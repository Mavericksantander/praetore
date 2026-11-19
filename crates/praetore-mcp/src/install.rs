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
//! * Claude Code `~/.claude.json` (user scope, top-level `mcpServers`) and a
//!   project's `.mcp.json` (project scope, `mcpServers`). An entry with no
//!   `type` is stdio; `http`, `sse`, `ws`, `streamable-http` and `sdk` are
//!   not. Local scope (`projects["<path>"].mcpServers` in `~/.claude.json`)
//!   is listed, never wrapped. Only the `mcpServers` value is rewritten:
//!   every byte outside it stays as it was.

use crate::json::JsonValue;
use crate::shown::Show;
use std::path::{Path, PathBuf};

pub const WRAP_SUBCOMMAND: &str = "wrap";
/// Install skip when an entry parses as `wrap` but its command, `--dir` or
/// `--mode` is not this install's canonical binary and home.
pub const NOT_GOVERNED: &str = "NOT governed by this home; run uninstall, then install";
/// Marker recorded in the wrapped args when the original entry had no
/// `args` member, so `uninstall` restores the entry exactly.
pub const ORIGINAL_ARGS_ABSENT: &str = "--orig-args-absent";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    ClaudeDesktop,
    Cursor,
    VsCode,
    ClaudeCode,
}

impl Client {
    pub const ALL: [Client; 4] = [
        Client::ClaudeDesktop,
        Client::Cursor,
        Client::VsCode,
        Client::ClaudeCode,
    ];

    /// Names accepted by `--client`, for help and error messages.
    pub const NAMES: &'static str = "claude-desktop, cursor, vscode, claude-code";

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "claude-desktop" | "claude" => Some(Client::ClaudeDesktop),
            "cursor" => Some(Client::Cursor),
            "vscode" | "vs-code" | "code" => Some(Client::VsCode),
            // Not `claude`: that one is Claude Desktop.
            "claude-code" | "cc" => Some(Client::ClaudeCode),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Client::ClaudeDesktop => "claude-desktop",
            Client::Cursor => "cursor",
            Client::VsCode => "vscode",
            Client::ClaudeCode => "claude-code",
        }
    }

    pub fn servers_key(self) -> &'static str {
        match self {
            Client::ClaudeDesktop | Client::Cursor | Client::ClaudeCode => "mcpServers",
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
            Client::ClaudeCode => {
                paths.extend(home.as_ref().map(|h| h.join(".claude.json")));
                // Project scope, only when the current directory has one.
                if let Ok(cwd) = std::env::current_dir()
                    && cwd.join(".mcp.json").is_file()
                {
                    paths.push(cwd.join(".mcp.json"));
                }
            }
        }
        paths
    }

    /// The user-scope file `install --client claude-code` creates when it is
    /// missing: `~/.claude.json`. `CLAUDE_CONFIG_DIR` is not followed.
    pub fn creatable_path(self) -> Option<PathBuf> {
        match self {
            Client::ClaudeCode => crate::store::user_home().map(|h| h.join(".claude.json")),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeKind {
    Wrapped {
        before: String,
        after: String,
    },
    Unwrapped {
        before: String,
        after: String,
    },
    Skipped(String),
    /// Left as is and not governed, said louder than `Skipped`: a remote
    /// Claude Code server.
    NotWrapped(String),
    /// `install` added an empty `mcpServers` key to a document without one.
    CreatedKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub server: String,
    pub kind: ChangeKind,
}

impl Change {
    pub fn is_modification(&self) -> bool {
        !matches!(
            self.kind,
            ChangeKind::Skipped(_) | ChangeKind::NotWrapped(_)
        )
    }
}

/// True when install must exit 1, including `--dry-run`: a parsed wrap is
/// not this home's canonical binary with the same `--dir` and `--mode`.
pub fn refuses_success(changes: &[Change]) -> bool {
    changes
        .iter()
        .any(|change| matches!(&change.kind, ChangeKind::Skipped(reason) if reason == NOT_GOVERNED))
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

/// A `praetore-mcp wrap -- <command>` entry, before checking which binary
/// and home it points at.
fn parsed_wrap(entry: &JsonValue) -> Option<WrappedArgs> {
    let command = entry.get("command").and_then(JsonValue::as_str)?;
    if !is_praetore_command(command) {
        return None;
    }
    let args = string_args(entry)?;
    parse_wrapped_args(&args)
}

/// The single value of `flag` in `options`, or `None` when it is absent or
/// repeated.
fn flag_once<'a>(options: &'a [String], flag: &str) -> Option<&'a str> {
    let mut value = None;
    let mut index = 0;
    while index < options.len() {
        if options[index] == flag {
            if value.is_some() {
                return None;
            }
            value = Some(options.get(index + 1)?.as_str());
            index += 2;
            continue;
        }
        index += 1;
    }
    value
}

/// True only when `entry` is a wrap of this install: the command string is
/// `target.exe` (the canonical binary) and `--dir` / `--mode` equal `target`.
pub fn is_wrapped(entry: &JsonValue, target: &WrapTarget) -> bool {
    let Some(command) = entry.get("command").and_then(JsonValue::as_str) else {
        return false;
    };
    let Some(parsed) = parsed_wrap(entry) else {
        return false;
    };
    command == target.exe
        && flag_once(&parsed.options, "--dir") == Some(target.dir.as_str())
        && flag_once(&parsed.options, "--mode") == Some(target.mode.as_str())
}

/// Claude Code reads an entry with no `type` as stdio. Any other `type`
/// (`http`, `sse`, `ws`, `streamable-http`, `sdk`, or one this version does
/// not know), or any `url`, is not a stdio server and is not wrapped.
pub fn is_claude_code_remote(entry: &JsonValue) -> bool {
    entry.contains_key("url")
        || entry
            .get("type")
            .is_some_and(|kind| kind.as_str() != Some("stdio"))
}

/// Why an entry cannot be wrapped, or `None` if it is a plain stdio entry.
fn unsupported_reason(entry: &JsonValue, client: Client) -> Option<ChangeKind> {
    if !matches!(entry, JsonValue::Object(_)) {
        return Some(ChangeKind::Skipped("entry is not an object".into()));
    }
    if client == Client::ClaudeCode && is_claude_code_remote(entry) {
        return Some(ChangeKind::NotWrapped("remote server".into()));
    }
    generic_unsupported_reason(entry).map(ChangeKind::Skipped)
}

fn generic_unsupported_reason(entry: &JsonValue) -> Option<String> {
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
        // Claude Code connects to a remote entry (`type` other than stdio,
        // or `url`) and never runs its `command`, so a remote entry is
        // reported as remote even if its `command` parses as a wrap.
        let claude_code_remote = client == Client::ClaudeCode && is_claude_code_remote(entry);
        if !claude_code_remote && parsed_wrap(entry).is_some() {
            let kind = if is_wrapped(entry, target) {
                ChangeKind::Skipped("already wrapped by praetore-mcp".into())
            } else {
                ChangeKind::Skipped(NOT_GOVERNED.into())
            };
            changes.push(Change {
                server: name.clone(),
                kind,
            });
            continue;
        }
        let reason = unsupported_reason(entry, client).or_else(|| {
            (!crate::cli::valid_server_name(name)).then(|| {
                ChangeKind::Skipped(
                    "server name is empty, too long, has control characters or starts with '-'"
                        .to_owned(),
                )
            })
        });
        if let Some(kind) = reason {
            changes.push(Change {
                server: name.clone(),
                kind,
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

/// Removes Windows verbatim prefixes that `canonicalize` adds
/// (`\\?\C:\x` -> `C:\x`, `\\?\UNC\srv\share` -> `\\srv\share`), so
/// client configs get ordinary paths. Other strings are returned unchanged.
pub fn strip_verbatim_prefix(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = path.strip_prefix(r"\\?\") {
        let bytes = rest.as_bytes();
        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\'
        {
            return rest.to_owned();
        }
    }
    path.to_owned()
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
        let Some(parsed) = parsed_wrap(entry) else {
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
    let mut out = format!("{}\n", path.shown());
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
            ChangeKind::NotWrapped(reason) => {
                out.push_str(&format!("  ! {}: not wrapped ({reason})\n", change.server));
            }
            ChangeKind::CreatedKey => {
                out.push_str(&format!("  + {} (key created, empty)\n", change.server));
            }
        }
    }
    out
}

/// Serializes like the input: 2-space pretty JSON, keeping a trailing newline
/// if the original had one.
/// Drops targets that name the same file as an earlier one, e.g. Cursor's
/// `~/.cursor/mcp.json` and `./.cursor/mcp.json` when run from `~`, or a
/// symlink to a file already listed. Paths that cannot be resolved are
/// compared as given.
pub fn dedup_targets(targets: Vec<(Client, PathBuf)>) -> Vec<(Client, PathBuf)> {
    let mut seen = std::collections::HashSet::new();
    targets
        .into_iter()
        .filter(|(_, path)| {
            seen.insert(std::fs::canonicalize(path).unwrap_or_else(|_| path.clone()))
        })
        .collect()
}

pub fn render_document(doc: &JsonValue, original: &str) -> String {
    let mut text = doc.to_pretty();
    if original.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// Adds an empty `mcpServers` object at the end of a document that has no
/// such key, so `install --client claude-code` leaves the key in place.
pub fn ensure_servers_key(doc: &mut JsonValue, client: Client) -> Option<Change> {
    let key = client.servers_key();
    if !matches!(doc, JsonValue::Object(_)) || doc.contains_key(key) {
        return None;
    }
    doc.set(key, JsonValue::Object(Vec::new()), None);
    Some(Change {
        server: key.to_owned(),
        kind: ChangeKind::CreatedKey,
    })
}

/// One Claude Code local-scope server (`projects["<path>"].mcpServers`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalScopeEntry {
    pub project: String,
    pub server: String,
    /// The user-scope entry of the same name is wrapped, and this one
    /// overrides it in that project (local scope has precedence).
    pub overrides_wrapped_user_entry: bool,
}

/// Lists every local-scope server of a `~/.claude.json` document. This
/// version never wraps them.
pub fn local_scope_entries(doc: &JsonValue) -> Vec<LocalScopeEntry> {
    let wrapped_user: std::collections::HashSet<&str> = match doc.get("mcpServers") {
        Some(JsonValue::Object(entries)) => entries
            .iter()
            .filter(|(_, entry)| parsed_wrap(entry).is_some())
            .map(|(name, _)| name.as_str())
            .collect(),
        _ => Default::default(),
    };
    let Some(JsonValue::Object(projects)) = doc.get("projects") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (project, state) in projects {
        let Some(JsonValue::Object(servers)) = state.get("mcpServers") else {
            continue;
        };
        for (server, _) in servers {
            out.push(LocalScopeEntry {
                project: project.clone(),
                server: server.clone(),
                overrides_wrapped_user_entry: wrapped_user.contains(server.as_str()),
            });
        }
    }
    out
}

pub fn render_local_scope(entries: &[LocalScopeEntry]) -> String {
    let mut out = String::new();
    for entry in entries {
        out.push_str(&format!(
            "  ! {}: not wrapped (local scope, project {})\n",
            entry.server,
            entry.project.shown()
        ));
        if entry.overrides_wrapped_user_entry {
            out.push_str(&format!(
                "    a local-scope entry named {0} overrides the wrapped user-scope {0}; that server is NOT governed\n",
                entry.server
            ));
        }
    }
    out
}

/// Renders `doc` by replacing, in `original`, only the text of the
/// top-level `key` value (or adding the key before the closing brace).
/// Every byte outside that value is kept, including text a full
/// re-serialization would change (`\u00e9` escapes, compact or 4-space
/// spacing). The result is parsed again and must equal `doc`.
pub fn render_member(original: &str, doc: &JsonValue, key: &str) -> Result<String, String> {
    let value = doc
        .get(key)
        .ok_or_else(|| format!("internal error: no {key:?} to write"))?;
    let rendered = if original.trim().is_empty() {
        format!(
            "{{\n  {}: {}\n}}\n",
            JsonValue::string(key).to_compact(),
            pretty_with(value, "  ")
        )
    } else {
        let top = scan_top_level(original)?;
        match top.members.iter().find(|m| m.key == key) {
            Some(member) => {
                let text = match &member.indent {
                    Some(indent) => pretty_with(value, indent),
                    None => value.to_compact(),
                };
                format!(
                    "{}{}{}",
                    &original[..member.value_start],
                    text,
                    &original[member.value_end..]
                )
            }
            None => match top.members.last() {
                Some(last) => {
                    let key_text = JsonValue::string(key).to_compact();
                    let insert = match &last.indent {
                        Some(indent) => {
                            format!(",\n{indent}{key_text}: {}", pretty_with(value, indent))
                        }
                        None => format!(",{key_text}:{}", value.to_compact()),
                    };
                    format!(
                        "{}{}{}",
                        &original[..last.value_end],
                        insert,
                        &original[last.value_end..]
                    )
                }
                None => format!(
                    "{}{{\n  {}: {}\n}}{}",
                    &original[..top.start],
                    JsonValue::string(key).to_compact(),
                    pretty_with(value, "  "),
                    &original[top.end..]
                ),
            },
        }
    };
    match JsonValue::parse(&rendered) {
        Ok(reparsed) if &reparsed == doc => Ok(rendered),
        _ => Err(format!(
            "internal error: rewriting only {key:?} would change other content; nothing was written"
        )),
    }
}

/// Pretty JSON with `indent` as the unit, for a value that sits one level
/// deep (its inner lines are indented once more).
fn pretty_with(value: &JsonValue, indent: &str) -> String {
    use serde::Serialize;
    let mut out = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(indent.as_bytes());
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, formatter);
    if value.serialize(&mut serializer).is_err() {
        return value.to_compact();
    }
    String::from_utf8_lossy(&out).replace('\n', &format!("\n{indent}"))
}

struct Member {
    key: String,
    value_start: usize,
    value_end: usize,
    /// Whitespace before the key on its own line, or `None` when the key
    /// does not start a line (a compact document).
    indent: Option<String>,
}

struct TopLevel {
    start: usize,
    end: usize,
    members: Vec<Member>,
}

/// Finds the members of the top-level object of a document that
/// `JsonValue::parse` already accepted.
fn scan_top_level(text: &str) -> Result<TopLevel, String> {
    let bytes = text.as_bytes();
    let bad = || "internal error: cannot locate the top-level object".to_owned();
    let skip_ws = |mut i: usize| {
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        i
    };
    let string_end = |mut i: usize| -> Option<usize> {
        // `i` is at the opening quote.
        i += 1;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => i += 2,
                b'"' => return Some(i + 1),
                _ => i += 1,
            }
        }
        None
    };
    let value_end = |i: usize| -> Option<usize> {
        match bytes.get(i)? {
            b'"' => string_end(i),
            b'{' | b'[' => {
                let mut depth = 0usize;
                let mut j = i;
                while j < bytes.len() {
                    match bytes[j] {
                        b'"' => {
                            j = string_end(j)?;
                            continue;
                        }
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => {
                            depth -= 1;
                            if depth == 0 {
                                return Some(j + 1);
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                None
            }
            _ => {
                let mut j = i;
                while j < bytes.len()
                    && !matches!(bytes[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
                {
                    j += 1;
                }
                Some(j)
            }
        }
    };
    let start = skip_ws(0);
    if bytes.get(start) != Some(&b'{') {
        return Err(bad());
    }
    let mut members = Vec::new();
    let mut i = skip_ws(start + 1);
    if bytes.get(i) == Some(&b'}') {
        return Ok(TopLevel {
            start,
            end: i + 1,
            members,
        });
    }
    loop {
        if bytes.get(i) != Some(&b'"') {
            return Err(bad());
        }
        let key_start = i;
        let key_end = string_end(i).ok_or_else(bad)?;
        let key: String = serde_json::from_str(&text[key_start..key_end]).map_err(|_| bad())?;
        let line_start = text[..key_start].rfind('\n').map(|n| n + 1);
        let indent = line_start
            .map(|n| &text[n..key_start])
            .filter(|ws| ws.bytes().all(|b| b == b' ' || b == b'\t') && !ws.is_empty())
            .map(str::to_owned);
        i = skip_ws(key_end);
        if bytes.get(i) != Some(&b':') {
            return Err(bad());
        }
        let value_start = skip_ws(i + 1);
        let end = value_end(value_start).ok_or_else(bad)?;
        members.push(Member {
            key,
            value_start,
            value_end: end,
            indent,
        });
        i = skip_ws(end);
        match bytes.get(i) {
            Some(b',') => i = skip_ws(i + 1),
            Some(b'}') => {
                return Ok(TopLevel {
                    start,
                    end: i + 1,
                    members,
                });
            }
            _ => return Err(bad()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::Mode;

    #[test]
    fn duplicate_and_symlinked_targets_are_processed_once() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("mcp.json");
        std::fs::write(&file, "{}").unwrap();
        let other = temp.path().join("other.json");
        std::fs::write(&other, "{}").unwrap();
        let link = temp.path().join("link.json");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&file, &link).unwrap();
        #[cfg(not(unix))]
        std::fs::copy(&file, &link).unwrap();
        let dotted = temp.path().join(".").join("mcp.json");
        let targets = dedup_targets(vec![
            (Client::Cursor, file.clone()),
            (Client::Cursor, dotted),
            (Client::Cursor, other.clone()),
            (Client::Cursor, file.clone()),
            (Client::Cursor, link.clone()),
        ]);
        let paths: Vec<_> = targets.into_iter().map(|(_, p)| p).collect();
        if cfg!(unix) {
            assert_eq!(paths, vec![file, other]);
        } else {
            assert_eq!(paths, vec![file, other, link]);
        }
    }

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
        assert!(parsed_wrap(&entry).is_some());
        assert!(!is_wrapped(&entry, &target()));
        let entry = JsonValue::parse(r#"{"command":"praetore-mcp","args":["receipts"]}"#).unwrap();
        assert!(parsed_wrap(&entry).is_none());
        assert!(!is_wrapped(&entry, &target()));
    }

    fn git_entry(command: &str, args: &str) -> String {
        format!(r#"{{"mcpServers":{{"git":{{"command":"{command}","args":{args}}}}}}}"#)
    }

    fn kind_for(text: &str) -> ChangeKind {
        let mut doc = JsonValue::parse(text).unwrap();
        let before = doc.to_compact();
        let changes = wrap_config(&mut doc, Client::ClaudeDesktop, &target());
        assert_eq!(
            doc.to_compact(),
            before,
            "a classified wrap is not rewritten"
        );
        changes.into_iter().next().unwrap().kind
    }

    #[test]
    fn already_wrapped_is_skipped_and_uninstall_unwraps_it() {
        let text = git_entry(
            "/opt/bin/praetore-mcp",
            r#"["wrap","--dir","/home/u/.praetore/mcp","--name","git","--mode","observe","--","uvx","mcp-server-git"]"#,
        );
        let mut doc = JsonValue::parse(&text).unwrap();
        let changes = wrap_config(&mut doc, Client::ClaudeDesktop, &target());
        assert_eq!(
            changes[0].kind,
            ChangeKind::Skipped("already wrapped by praetore-mcp".into())
        );
        assert!(!refuses_success(&changes));
        assert_eq!(doc.to_compact(), text);
        unwrap_config(&mut doc, Client::ClaudeDesktop);
        assert_eq!(
            doc.to_compact(),
            r#"{"mcpServers":{"git":{"command":"uvx","args":["mcp-server-git"]}}}"#
        );
    }

    #[test]
    fn governance_requires_canonical_exe_and_matching_dir_and_mode() {
        let args = |dir: &str, mode: &str| {
            format!(
                r#"["wrap","--dir","{dir}","--name","git","--mode","{mode}","--","uvx","mcp-server-git"]"#
            )
        };
        let same = git_entry(
            "/opt/bin/praetore-mcp",
            &args("/home/u/.praetore/mcp", "observe"),
        );
        assert_eq!(
            kind_for(&same),
            ChangeKind::Skipped("already wrapped by praetore-mcp".into())
        );
        assert!(!refuses_success(&[Change {
            server: "git".into(),
            kind: kind_for(&same),
        }]));

        let other_exe = git_entry(
            "/other/praetore-mcp",
            &args("/home/u/.praetore/mcp", "observe"),
        );
        let other_dir = git_entry("/opt/bin/praetore-mcp", &args("/other/home", "observe"));
        let other_mode = git_entry(
            "/opt/bin/praetore-mcp",
            &args("/home/u/.praetore/mcp", "enforce"),
        );
        let repeated_dir = git_entry(
            "/opt/bin/praetore-mcp",
            r#"["wrap","--dir","/home/u/.praetore/mcp","--dir","/home/u/.praetore/mcp","--mode","observe","--","uvx","mcp-server-git"]"#,
        );
        for text in [other_exe, other_dir, other_mode, repeated_dir] {
            let kind = kind_for(&text);
            assert_eq!(kind, ChangeKind::Skipped(NOT_GOVERNED.into()), "{text}");
            assert!(refuses_success(&[Change {
                server: "git".into(),
                kind,
            }]));
        }
    }

    #[test]
    fn uninstall_restores_a_parsed_wrap_that_this_home_refuses() {
        let text = git_entry(
            "/other/praetore-mcp",
            r#"["wrap","--dir","/other/home","--mode","enforce","--","uvx","mcp-server-git"]"#,
        );
        let mut doc = JsonValue::parse(&text).unwrap();
        let changes = wrap_config(&mut doc, Client::ClaudeDesktop, &target());
        assert_eq!(changes[0].kind, ChangeKind::Skipped(NOT_GOVERNED.into()));
        assert_eq!(doc.to_compact(), text);
        unwrap_config(&mut doc, Client::ClaudeDesktop);
        assert_eq!(
            doc.to_compact(),
            r#"{"mcpServers":{"git":{"command":"uvx","args":["mcp-server-git"]}}}"#
        );
    }

    #[test]
    fn strips_windows_verbatim_prefixes() {
        assert_eq!(
            strip_verbatim_prefix(r"\\?\C:\bin\praetore-mcp.exe"),
            r"C:\bin\praetore-mcp.exe"
        );
        assert_eq!(
            strip_verbatim_prefix(r"\\?\UNC\srv\share\x"),
            r"\\srv\share\x"
        );
        assert_eq!(
            strip_verbatim_prefix(r"\\?\GLOBALROOT\x"),
            r"\\?\GLOBALROOT\x"
        );
        assert_eq!(strip_verbatim_prefix("/usr/bin/x"), "/usr/bin/x");
    }

    #[test]
    fn dash_server_names_are_skipped() {
        let mut doc = JsonValue::parse(r#"{"mcpServers":{"--dir":{"command":"x"}}}"#).unwrap();
        let changes = wrap_config(&mut doc, Client::ClaudeDesktop, &target());
        assert!(matches!(changes[0].kind, ChangeKind::Skipped(_)));
    }

    #[test]
    fn missing_servers_key_is_noop() {
        let mut doc = JsonValue::parse(r#"{"other":1}"#).unwrap();
        assert!(wrap_config(&mut doc, Client::ClaudeDesktop, &target()).is_empty());
    }

    /// The text of `original` outside the top-level `mcpServers` value.
    fn outside_servers(original: &str) -> (String, String) {
        let top = scan_top_level(original).unwrap();
        match top.members.iter().find(|m| m.key == "mcpServers") {
            Some(m) => (
                original[..m.value_start].to_owned(),
                original[m.value_end..].to_owned(),
            ),
            None => (original.to_owned(), String::new()),
        }
    }

    const CLAUDE_CODE: &str = include_str!("../tests/fixtures/claude_code_claude.json");

    #[test]
    fn claude_code_wraps_only_stdio_entries_with_a_command_and_no_url() {
        let cases = [
            ("no type", r#"{"command":"srv"}"#, true),
            (
                "stdio",
                r#"{"type":"stdio","command":"srv","args":["-x"]}"#,
                true,
            ),
            ("http", r#"{"type":"http","url":"https://x/mcp"}"#, false),
            ("sse", r#"{"type":"sse","url":"https://x/sse"}"#, false),
            ("ws", r#"{"type":"ws","url":"wss://x/socket"}"#, false),
            (
                "streamable-http",
                r#"{"type":"streamable-http","url":"https://x/mcp"}"#,
                false,
            ),
            ("sdk", r#"{"type":"sdk","name":"in-process"}"#, false),
            ("url without type", r#"{"url":"https://x/mcp"}"#, false),
            (
                "unknown type",
                r#"{"type":"carrier-pigeon","command":"srv"}"#,
                false,
            ),
            (
                "stdio with url",
                r#"{"type":"stdio","command":"srv","url":"https://x"}"#,
                false,
            ),
            ("non-string type", r#"{"type":1,"command":"srv"}"#, false),
        ];
        for (label, entry, wrapped) in cases {
            let text = format!(r#"{{"mcpServers":{{"s":{entry}}}}}"#);
            let mut doc = JsonValue::parse(&text).unwrap();
            let changes = wrap_config(&mut doc, Client::ClaudeCode, &target());
            assert_eq!(changes.len(), 1, "{label}");
            if wrapped {
                assert!(
                    matches!(changes[0].kind, ChangeKind::Wrapped { .. }),
                    "{label}: {changes:?}"
                );
            } else {
                assert_eq!(
                    changes[0].kind,
                    ChangeKind::NotWrapped("remote server".into()),
                    "{label}"
                );
                assert_eq!(doc.to_compact(), text, "{label}: entry left as is");
                assert!(
                    render_changes(Path::new("c.json"), &changes)
                        .contains("  ! s: not wrapped (remote server)\n"),
                    "{label}"
                );
            }
        }
    }

    #[test]
    fn claude_code_keeps_type_env_key_order_and_var_references() {
        let mut doc = JsonValue::parse(CLAUDE_CODE).unwrap();
        wrap_config(&mut doc, Client::ClaudeCode, &target());
        let entry = doc.get("mcpServers").unwrap().get("filesystem").unwrap();
        assert_eq!(
            entry.to_compact(),
            r#"{"type":"stdio","command":"/opt/bin/praetore-mcp","args":["wrap","--dir","/home/u/.praetore/mcp","--name","filesystem","--mode","observe","--","npx","-y","@modelcontextprotocol/server-filesystem","${HOME}/projects"],"env":{"LOG_LEVEL":"${LOG_LEVEL:-info}"}}"#
        );
    }

    #[test]
    fn claude_code_rewrites_only_the_servers_value() {
        let original = JsonValue::parse(CLAUDE_CODE).unwrap();
        let mut doc = original.clone();
        let changes = wrap_config(&mut doc, Client::ClaudeCode, &target());
        assert_eq!(changes.iter().filter(|c| c.is_modification()).count(), 2);
        let installed = render_member(CLAUDE_CODE, &doc, "mcpServers").unwrap();
        assert_eq!(outside_servers(&installed), outside_servers(CLAUDE_CODE));
        // Uninstall gives back the original bytes.
        let mut restored = JsonValue::parse(&installed).unwrap();
        unwrap_config(&mut restored, Client::ClaudeCode);
        assert_eq!(restored, original);
        assert_eq!(
            render_member(&installed, &restored, "mcpServers").unwrap(),
            CLAUDE_CODE
        );
    }

    #[test]
    fn text_a_full_reserialization_would_change_is_kept_outside_the_servers() {
        let original = "{\n    \"name\": \"caf\\u00e9\",\n    \"compact\": {\"a\":1},\n    \"mcpServers\": {\"s\": {\"command\": \"srv\"}}\n}\n";
        let mut doc = JsonValue::parse(original).unwrap();
        wrap_config(&mut doc, Client::ClaudeCode, &target());
        let installed = render_member(original, &doc, "mcpServers").unwrap();
        assert_eq!(outside_servers(&installed), outside_servers(original));
        assert!(installed.contains("\"caf\\u00e9\""), "{installed}");
        assert!(installed.contains("{\"a\":1}"), "{installed}");
        assert_ne!(render_document(&doc, original), installed);
    }

    #[test]
    fn a_missing_servers_key_is_added_without_touching_the_rest() {
        for text in [
            "{\n  \"numStartups\": 3,\n  \"lastCost\": 0.0000123\n}",
            "{\"numStartups\":3,\"lastCost\":0.0000123}\n",
            "{}",
            "",
        ] {
            let mut doc = if text.is_empty() {
                JsonValue::Object(Vec::new())
            } else {
                JsonValue::parse(text).unwrap()
            };
            let created = ensure_servers_key(&mut doc, Client::ClaudeCode).unwrap();
            assert_eq!(created.kind, ChangeKind::CreatedKey);
            assert!(ensure_servers_key(&mut doc, Client::ClaudeCode).is_none());
            let written = render_member(text, &doc, "mcpServers").unwrap();
            assert_eq!(JsonValue::parse(&written).unwrap(), doc, "{text:?}");
            if text.contains("numStartups") {
                // Everything before the last value's end and from the closing
                // brace on is the original text.
                let close = text.rfind('}').unwrap();
                let last_value_end = text[..close].trim_end().len();
                assert!(written.starts_with(&text[..last_value_end]), "{written}");
                assert!(written.ends_with(&text[last_value_end..]), "{written}");
            }
        }
    }

    #[test]
    fn local_scope_entries_are_listed_with_the_override_case() {
        let text = r#"{"projects":{"/p/a":{"mcpServers":{"db":{"command":"x"},"filesystem":{"command":"y"}}},"/p/b":{"mcpServers":{}}},"mcpServers":{"filesystem":{"command":"npx"}}}"#;
        let mut doc = JsonValue::parse(text).unwrap();
        wrap_config(&mut doc, Client::ClaudeCode, &target());
        let entries = local_scope_entries(&doc);
        assert_eq!(entries.len(), 2);
        let report = render_local_scope(&entries);
        assert!(report.contains("  ! db: not wrapped (local scope, project /p/a)\n"));
        assert!(report.contains("  ! filesystem: not wrapped (local scope, project /p/a)\n"));
        assert!(report.contains(
            "a local-scope entry named filesystem overrides the wrapped user-scope filesystem; that server is NOT governed"
        ));
        assert!(!report.contains("named db overrides"));
    }
}
