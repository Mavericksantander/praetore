//! Rewrites MCP client configs so each stdio server runs behind
//! `praetore-mcp wrap`, and restores them.
//!
//! Formats handled (all strict JSON; files with comments or trailing commas
//! are refused, never rewritten):
//! * Claude Desktop `claude_desktop_config.json`: `{"mcpServers": {name: {command, args, env}}}`
//! * Cursor `~/.cursor/mcp.json` / `.cursor/mcp.json`: `{"mcpServers": {...}}`,
//!   stdio entries may carry `"type": "stdio"`, remote ones have `url`.
//! * VS Code `mcp.json` (user profile or `.vscode/mcp.json`): `{"servers": {...}}`,
//!   entries with `"type": "stdio" | "http" | "sse"`.

use crate::json::JsonValue;
use std::path::{Path, PathBuf};

pub const WRAP_SUBCOMMAND: &str = "wrap";
/// Marker recorded in the wrapped args when the original entry had no
/// `args` member, so `uninstall` restores the entry exactly.
pub const ORIGINAL_ARGS_ABSENT: &str = "--orig-args-absent";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    ClaudeDesktop,
    Cursor,
    VsCode,
}

impl Client {
    pub const ALL: [Client; 3] = [Client::ClaudeDesktop, Client::Cursor, Client::VsCode];

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "claude-desktop" | "claude" => Some(Client::ClaudeDesktop),
            "cursor" => Some(Client::Cursor),
            "vscode" | "vs-code" | "code" => Some(Client::VsCode),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Client::ClaudeDesktop => "claude-desktop",
            Client::Cursor => "cursor",
            Client::VsCode => "vscode",
        }
    }

    pub fn servers_key(self) -> &'static str {
        match self {
            Client::ClaudeDesktop | Client::Cursor => "mcpServers",
            Client::VsCode => "servers",
        }
    }

    /// Candidate config files for this client on this platform.
    pub fn default_paths(self) -> Vec<PathBuf> {
        let home = crate::store::user_home();
        let appdata = std::env::var_os("APPDATA").map(PathBuf::from);
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|home| home.join(".config")));
        let app_config = |app: &str| -> Option<PathBuf> {
            if cfg!(target_os = "macos") {
                home.as_ref()
                    .map(|h| h.join("Library").join("Application Support").join(app))
            } else if cfg!(windows) {
                appdata.as_ref().map(|a| a.join(app))
            } else {
                xdg.as_ref().map(|x| x.join(app))
            }
        };
        let mut paths = Vec::new();
        match self {
            Client::ClaudeDesktop => {
                paths.extend(app_config("Claude").map(|d| d.join("claude_desktop_config.json")));
            }
            Client::Cursor => {
                paths.extend(home.as_ref().map(|h| h.join(".cursor").join("mcp.json")));
                if let Ok(cwd) = std::env::current_dir() {
                    paths.push(cwd.join(".cursor").join("mcp.json"));
                }
            }
            Client::VsCode => {
                paths.extend(app_config("Code").map(|d| d.join("User").join("mcp.json")));
                if let Ok(cwd) = std::env::current_dir() {
                    paths.push(cwd.join(".vscode").join("mcp.json"));
                }
            }
        }
        paths
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeKind {
    Wrapped { before: String, after: String },
    Unwrapped { before: String, after: String },
    Skipped(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub server: String,
    pub kind: ChangeKind,
}

impl Change {
    pub fn is_modification(&self) -> bool {
        !matches!(self.kind, ChangeKind::Skipped(_))
    }
}

/// How `wrap` should be invoked from the rewritten entry.
#[derive(Debug, Clone)]
pub struct WrapTarget {
    pub exe: String,
    pub dir: String,
    pub mode: crate::gate::Mode,
}

fn command_line(entry: &JsonValue) -> String {
    let mut parts = vec![
        entry
            .get("command")
            .and_then(JsonValue::as_str)
            .unwrap_or("?")
            .to_owned(),
    ];
    if let Some(args) = entry.get("args").and_then(JsonValue::as_array) {
        parts.extend(args.iter().map(|a| a.as_str().unwrap_or("?").to_owned()));
    }
    parts
        .iter()
        .map(|p| {
            if p.is_empty() || p.contains(char::is_whitespace) {
                format!("{p:?}")
            } else {
                p.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn string_args(entry: &JsonValue) -> Option<Vec<String>> {
    match entry.get("args") {
        None => Some(Vec::new()),
        Some(JsonValue::Array(values)) => values
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect(),
        Some(_) => None,
    }
}

fn is_praetore_command(command: &str) -> bool {
    let file = command.rsplit(['/', '\\']).next().unwrap_or(command);
    let stem = file.strip_suffix(".exe").unwrap_or(file);
    stem == "praetore-mcp"
}

pub fn is_wrapped(entry: &JsonValue) -> bool {
    entry
        .get("command")
        .and_then(JsonValue::as_str)
        .is_some_and(is_praetore_command)
        && string_args(entry)
            .and_then(|args| args.first().cloned())
            .as_deref()
            == Some(WRAP_SUBCOMMAND)
}

/// Why an entry cannot be wrapped, or `None` if it is a plain stdio entry.
fn unsupported_reason(entry: &JsonValue) -> Option<String> {
    if !matches!(entry, JsonValue::Object(_)) {
        return Some("entry is not an object".into());
    }
    if entry.contains_key("url") || entry.contains_key("serverUrl") {
        return Some("remote (url) server: only stdio is supported".into());
    }
    if let Some(kind) = entry.get("type")
        && kind.as_str() != Some("stdio")
    {
        return Some(format!("transport type {} is not stdio", kind.to_compact()));
    }
    if entry.get("command").and_then(JsonValue::as_str).is_none() {
        return Some("no string \"command\"".into());
    }
    if string_args(entry).is_none() {
        return Some("\"args\" is not an array of strings".into());
    }
    if is_wrapped(entry) {
        return Some("already wrapped by praetore-mcp".into());
    }
    None
}

fn servers_mut(doc: &mut JsonValue, client: Client) -> Option<&mut Vec<(String, JsonValue)>> {
    match doc.get_mut(client.servers_key()) {
        Some(JsonValue::Object(entries)) => Some(entries),
        _ => None,
    }
}

/// Wraps every plain stdio server. Returns per-server changes.
pub fn wrap_config(doc: &mut JsonValue, client: Client, target: &WrapTarget) -> Vec<Change> {
    let Some(servers) = servers_mut(doc, client) else {
        return Vec::new();
    };
    let mut changes = Vec::new();
    for (name, entry) in servers.iter_mut() {
        if let Some(reason) = unsupported_reason(entry) {
            changes.push(Change {
                server: name.clone(),
                kind: ChangeKind::Skipped(reason),
            });
            continue;
        }
        let before = command_line(entry);
        let command = entry
            .get("command")
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .to_owned();
        let args_absent = !entry.contains_key("args");
        let original_args = string_args(entry).unwrap_or_default();
        let mut args = vec![
            WRAP_SUBCOMMAND.to_owned(),
            "--dir".into(),
            target.dir.clone(),
            "--name".into(),
            name.clone(),
            "--mode".into(),
            target.mode.as_str().into(),
        ];
        if args_absent {
            args.push(ORIGINAL_ARGS_ABSENT.into());
        }
        args.push("--".into());
        args.push(command);
        args.extend(original_args);
        entry.set("command", JsonValue::string(target.exe.clone()), None);
        entry.set(
            "args",
            JsonValue::Array(args.into_iter().map(JsonValue::String).collect()),
            Some("command"),
        );
        changes.push(Change {
            server: name.clone(),
            kind: ChangeKind::Wrapped {
                before,
                after: command_line(entry),
            },
        });
    }
    changes
}

/// Parsed `praetore-mcp wrap ... -- command args...` argument list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedArgs {
    pub options: Vec<String>,
    pub original_args_absent: bool,
    pub command: String,
    pub args: Vec<String>,
}

pub fn parse_wrapped_args(args: &[String]) -> Option<WrappedArgs> {
    if args.first().map(String::as_str) != Some(WRAP_SUBCOMMAND) {
        return None;
    }
    let separator = args.iter().position(|a| a == "--")?;
    let options = args[1..separator].to_vec();
    let command = args.get(separator + 1)?.clone();
    Some(WrappedArgs {
        original_args_absent: options.iter().any(|o| o == ORIGINAL_ARGS_ABSENT),
        options,
        command,
        args: args[separator + 2..].to_vec(),
    })
}

/// Restores every wrapped entry to its original command/args.
pub fn unwrap_config(doc: &mut JsonValue, client: Client) -> Vec<Change> {
    let Some(servers) = servers_mut(doc, client) else {
        return Vec::new();
    };
    let mut changes = Vec::new();
    for (name, entry) in servers.iter_mut() {
        if !is_wrapped(entry) {
            continue;
        }
        let Some(parsed) = string_args(entry).and_then(|args| parse_wrapped_args(&args)) else {
            changes.push(Change {
                server: name.clone(),
                kind: ChangeKind::Skipped("wrapped entry has no `-- command`; left as is".into()),
            });
            continue;
        };
        let before = command_line(entry);
        entry.set("command", JsonValue::string(parsed.command), None);
        if parsed.original_args_absent && parsed.args.is_empty() {
            entry.remove("args");
        } else {
            entry.set(
                "args",
                JsonValue::Array(parsed.args.into_iter().map(JsonValue::String).collect()),
                Some("command"),
            );
        }
        changes.push(Change {
            server: name.clone(),
            kind: ChangeKind::Unwrapped {
                before,
                after: command_line(entry),
            },
        });
    }
    changes
}

pub fn render_changes(path: &Path, changes: &[Change]) -> String {
    let mut out = format!("{}\n", path.display());
    if changes.is_empty() {
        out.push_str("  (no MCP servers found)\n");
    }
    for change in changes {
        match &change.kind {
            ChangeKind::Wrapped { before, after } | ChangeKind::Unwrapped { before, after } => {
                out.push_str(&format!(
                    "  ~ {}\n    - {before}\n    + {after}\n",
                    change.server
                ));
            }
            ChangeKind::Skipped(reason) => {
                out.push_str(&format!("  = {} (skipped: {reason})\n", change.server));
            }
        }
    }
    out
}

/// Serializes like the input: 2-space pretty JSON, keeping a trailing newline
/// if the original had one.
pub fn render_document(doc: &JsonValue, original: &str) -> String {
    let mut text = doc.to_pretty();
    if original.ends_with('\n') {
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::Mode;

    fn target() -> WrapTarget {
        WrapTarget {
            exe: "/opt/bin/praetore-mcp".into(),
            dir: "/home/u/.praetore/mcp".into(),
            mode: Mode::Observe,
        }
    }

    const CLAUDE: &str = include_str!("../tests/fixtures/claude_desktop_config.json");
    const CURSOR: &str = include_str!("../tests/fixtures/cursor_mcp.json");
    const VSCODE: &str = include_str!("../tests/fixtures/vscode_mcp.json");

    fn round_trip(text: &str, client: Client, expected_wrapped: usize) {
        let original = JsonValue::parse(text).unwrap();
        let mut doc = original.clone();
        let changes = wrap_config(&mut doc, client, &target());
        assert_eq!(
            changes.iter().filter(|c| c.is_modification()).count(),
            expected_wrapped,
            "{changes:?}"
        );
        // Re-wrapping is a no-op.
        let mut twice = doc.clone();
        assert!(
            wrap_config(&mut twice, client, &target())
                .iter()
                .all(|c| !c.is_modification())
        );
        assert_eq!(twice, doc);
        // Serialize + reparse, then unwrap: identical to the original,
        // including key order.
        let reparsed = JsonValue::parse(&render_document(&doc, text)).unwrap();
        let mut restored = reparsed;
        let undone = unwrap_config(&mut restored, client);
        assert_eq!(undone.len(), expected_wrapped);
        assert_eq!(restored, original);
        assert_eq!(restored.to_compact(), original.to_compact());
    }

    #[test]
    fn claude_desktop_round_trip() {
        round_trip(CLAUDE, Client::ClaudeDesktop, 2);
    }

    #[test]
    fn cursor_round_trip_skips_remote() {
        round_trip(CURSOR, Client::Cursor, 2);
    }

    #[test]
    fn vscode_round_trip_skips_http_and_sse() {
        round_trip(VSCODE, Client::VsCode, 1);
    }

    #[test]
    fn wrapped_entry_shape() {
        let mut doc = JsonValue::parse(CLAUDE).unwrap();
        wrap_config(&mut doc, Client::ClaudeDesktop, &target());
        let entry = doc.get("mcpServers").unwrap().get("filesystem").unwrap();
        assert_eq!(
            entry.to_compact(),
            r#"{"command":"/opt/bin/praetore-mcp","args":["wrap","--dir","/home/u/.praetore/mcp","--name","filesystem","--mode","observe","--","npx","-y","@modelcontextprotocol/server-filesystem","/Users/me/Desktop"],"env":{"DEBUG":"1"}}"#
        );
        let noargs = doc.get("mcpServers").unwrap().get("no-args").unwrap();
        let args = string_args(noargs).unwrap();
        assert!(args.contains(&ORIGINAL_ARGS_ABSENT.to_owned()));
        assert_eq!(args.last().unwrap(), "/usr/local/bin/my-server");
    }

    #[test]
    fn unknown_fields_and_top_level_keys_preserved() {
        let mut doc = JsonValue::parse(CLAUDE).unwrap();
        wrap_config(&mut doc, Client::ClaudeDesktop, &target());
        assert!(doc.get("globalShortcut").is_some());
        let keys: Vec<_> = match &doc {
            JsonValue::Object(entries) => entries.iter().map(|(k, _)| k.clone()).collect(),
            _ => unreachable!(),
        };
        assert_eq!(keys, ["globalShortcut", "mcpServers", "zzz"]);
    }

    #[test]
    fn detects_wrapped_commands() {
        let entry =
            JsonValue::parse(r#"{"command":"C:\\bin\\praetore-mcp.exe","args":["wrap","--","x"]}"#)
                .unwrap();
        assert!(is_wrapped(&entry));
        let entry = JsonValue::parse(r#"{"command":"praetore-mcp","args":["receipts"]}"#).unwrap();
        assert!(!is_wrapped(&entry));
    }

    #[test]
    fn already_wrapped_is_skipped_and_uninstall_unwraps_it() {
        let text = r#"{"mcpServers":{"git":{"command":"/x/praetore-mcp","args":["wrap","--name","git","--","uvx","mcp-server-git"]}}}"#;
        let mut doc = JsonValue::parse(text).unwrap();
        let changes = wrap_config(&mut doc, Client::ClaudeDesktop, &target());
        assert_eq!(
            changes[0].kind,
            ChangeKind::Skipped("already wrapped by praetore-mcp".into())
        );
        assert_eq!(doc.to_compact(), text);
        unwrap_config(&mut doc, Client::ClaudeDesktop);
        assert_eq!(
            doc.to_compact(),
            r#"{"mcpServers":{"git":{"command":"uvx","args":["mcp-server-git"]}}}"#
        );
    }

    #[test]
    fn missing_servers_key_is_noop() {
        let mut doc = JsonValue::parse(r#"{"other":1}"#).unwrap();
        assert!(wrap_config(&mut doc, Client::ClaudeDesktop, &target()).is_empty());
    }
}
