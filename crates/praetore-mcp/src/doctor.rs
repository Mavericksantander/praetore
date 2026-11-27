//! `doctor`: for each server the policy governs, which definition Claude
//! Code runs in a project, and whether it is a `wrap` for this home.
//!
//! Claude Code keeps one server name in up to four places and runs the
//! whole entry from the one with the highest precedence (nothing is merged):
//! `managed-mcp.json` (exclusive: when it exists no other scope loads),
//! local scope (`projects["<project>"].mcpServers` in `~/.claude.json`),
//! project scope (`<project>/.mcp.json`, once the user approved the server:
//! `enabledMcpjsonServers` or `enableAllProjectMcpServers` in the project's
//! state in `~/.claude.json` or in a settings file; `disabledMcpjsonServers`
//! rejects it), then user scope (`mcpServers` in `~/.claude.json`).
//! `install` wraps user and project scope only, so a raw entry above a
//! wrapped one runs the server with no policy and no receipt while `verify`
//! still passes. `doctor` resolves the winner and says so.

use crate::gate::Mode;
use crate::install;
use crate::json::JsonValue;
use crate::shown::Show;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Where a server definition lives, highest precedence first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    Managed,
    Local,
    Project,
    User,
}

impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Scope::Managed => "managed",
            Scope::Local => "local",
            Scope::Project => "project",
            Scope::User => "user",
        }
    }
}

/// How a project-scope entry stands with the user's approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Approval {
    /// `enableAllProjectMcpServers: true` in the named file.
    All(PathBuf),
    /// Named in `enabledMcpjsonServers` of that file.
    Named(PathBuf),
    /// Named in `disabledMcpjsonServers` of that file: never loads.
    Rejected(PathBuf),
    /// Not decided yet: Claude Code asks before the first use.
    Pending,
}

impl Approval {
    pub fn is_approved(&self) -> bool {
        matches!(self, Approval::All(_) | Approval::Named(_))
    }

    fn describe(&self) -> String {
        match self {
            Approval::All(path) => {
                format!("approved by enableAllProjectMcpServers in {}", path.shown())
            }
            Approval::Named(path) => {
                format!("approved by enabledMcpjsonServers in {}", path.shown())
            }
            Approval::Rejected(path) => {
                format!("rejected by disabledMcpjsonServers in {}", path.shown())
            }
            Approval::Pending => "not approved yet".to_owned(),
        }
    }
}

/// One definition of a server in one scope.
#[derive(Debug, Clone, PartialEq)]
pub struct Definition {
    pub scope: Scope,
    pub source: PathBuf,
    pub entry: JsonValue,
    /// Project scope only.
    pub approval: Option<Approval>,
}

impl Definition {
    /// Whether Claude Code loads this definition when nothing above it
    /// defines the name.
    fn is_active(&self) -> bool {
        self.approval.as_ref().is_none_or(Approval::is_approved)
    }

    fn describe(&self) -> String {
        let where_ = match &self.approval {
            Some(approval) => format!(
                "{} scope ({}, {})",
                self.scope.label(),
                self.source.shown(),
                approval.describe()
            ),
            None => format!("{} scope ({})", self.scope.label(), self.source.shown()),
        };
        format!("{where_} runs {}", install::command_line(&self.entry))
    }
}

/// The Claude Code files read for one project. Every document is already
/// parsed; a file that does not exist is `None`.
#[derive(Debug, Clone, Default)]
pub struct ClaudeCodeConfig {
    /// `managed-mcp.json`, when deployed.
    pub managed: Option<(PathBuf, JsonValue)>,
    /// `~/.claude.json`.
    pub user: Option<(PathBuf, JsonValue)>,
    /// `<project>/.mcp.json`.
    pub project_file: Option<(PathBuf, JsonValue)>,
    /// The project directory, absolute (the key of `projects` in
    /// `~/.claude.json`).
    pub project: PathBuf,
    /// Settings files that exist, lowest precedence first: user
    /// `settings.json`, project `.claude/settings.json`,
    /// `.claude/settings.local.json`.
    pub settings: Vec<(PathBuf, JsonValue)>,
}

/// The documented locations of `managed-mcp.json` for this platform.
pub fn managed_mcp_paths() -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        vec![PathBuf::from(
            "/Library/Application Support/ClaudeCode/managed-mcp.json",
        )]
    } else if cfg!(windows) {
        vec![PathBuf::from(
            r"C:\Program Files\ClaudeCode\managed-mcp.json",
        )]
    } else {
        vec![PathBuf::from("/etc/claude-code/managed-mcp.json")]
    }
}

/// The settings files Claude Code reads for `project`, lowest precedence
/// first (existing or not).
pub fn settings_paths(user_home: Option<&Path>, project: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = user_home {
        paths.push(home.join(".claude").join("settings.json"));
    }
    paths.push(project.join(".claude").join("settings.json"));
    paths.push(project.join(".claude").join("settings.local.json"));
    paths
}

fn same_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn servers_of(doc: &JsonValue) -> std::slice::Iter<'_, (String, JsonValue)> {
    match doc.get("mcpServers") {
        Some(JsonValue::Object(entries)) => entries.as_slice(),
        _ => &[],
    }
    .iter()
}

fn string_list<'a>(doc: &'a JsonValue, key: &str) -> impl Iterator<Item = &'a str> {
    doc.get(key)
        .and_then(JsonValue::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .filter_map(JsonValue::as_str)
}

impl ClaudeCodeConfig {
    /// `projects["<project>"]` of `~/.claude.json`, matched by path.
    fn project_state(&self) -> Option<&JsonValue> {
        let (_, doc) = self.user.as_ref()?;
        let JsonValue::Object(projects) = doc.get("projects")? else {
            return None;
        };
        projects
            .iter()
            .find(|(key, _)| same_path(Path::new(key), &self.project))
            .map(|(_, state)| state)
    }

    /// Every document that can hold the `.mcp.json` approval keys, with
    /// the file it comes from: the project's state in `~/.claude.json`
    /// first, then the settings files.
    fn approval_documents(&self) -> Vec<(&Path, &JsonValue)> {
        let mut docs = Vec::new();
        if let (Some((path, _)), Some(state)) = (&self.user, self.project_state()) {
            docs.push((path.as_path(), state));
        }
        docs.extend(
            self.settings
                .iter()
                .map(|(path, doc)| (path.as_path(), doc)),
        );
        docs
    }

    /// Files that approve every `.mcp.json` server without a prompt.
    pub fn enable_all_sources(&self) -> Vec<PathBuf> {
        self.approval_documents()
            .into_iter()
            .filter(|(_, doc)| {
                doc.get("enableAllProjectMcpServers") == Some(&JsonValue::Bool(true))
            })
            .map(|(path, _)| path.to_path_buf())
            .collect()
    }

    /// The approval of one `.mcp.json` server. A rejection in any file
    /// wins; then a name in `enabledMcpjsonServers`; then
    /// `enableAllProjectMcpServers`.
    pub fn approval(&self, name: &str) -> Approval {
        let docs = self.approval_documents();
        if let Some((path, _)) = docs
            .iter()
            .find(|(_, doc)| string_list(doc, "disabledMcpjsonServers").any(|n| n == name))
        {
            return Approval::Rejected(path.to_path_buf());
        }
        if let Some((path, _)) = docs
            .iter()
            .find(|(_, doc)| string_list(doc, "enabledMcpjsonServers").any(|n| n == name))
        {
            return Approval::Named(path.to_path_buf());
        }
        if let Some(path) = self.enable_all_sources().into_iter().next() {
            return Approval::All(path);
        }
        Approval::Pending
    }

    /// Every definition of `name`, highest precedence first.
    pub fn definitions(&self, name: &str) -> Vec<Definition> {
        let mut out = Vec::new();
        let find = |doc: &JsonValue| {
            servers_of(doc)
                .find(|(key, _)| key.as_str() == name)
                .map(|(_, entry)| entry.clone())
        };
        if let Some((path, doc)) = &self.managed
            && let Some(entry) = find(doc)
        {
            out.push(Definition {
                scope: Scope::Managed,
                source: path.clone(),
                entry,
                approval: None,
            });
        }
        if let (Some((path, _)), Some(state)) = (&self.user, self.project_state())
            && let Some(entry) = find(state)
        {
            out.push(Definition {
                scope: Scope::Local,
                source: path.clone(),
                entry,
                approval: None,
            });
        }
        if let Some((path, doc)) = &self.project_file
            && let Some(entry) = find(doc)
        {
            out.push(Definition {
                scope: Scope::Project,
                source: path.clone(),
                entry,
                approval: Some(self.approval(name)),
            });
        }
        if let Some((path, doc)) = &self.user
            && let Some(entry) = find(doc)
        {
            out.push(Definition {
                scope: Scope::User,
                source: path.clone(),
                entry,
                approval: None,
            });
        }
        out
    }

    /// The definition Claude Code runs for `name` in this project. With a
    /// `managed-mcp.json` deployed, only its entries load.
    pub fn winner<'a>(&self, definitions: &'a [Definition]) -> Option<&'a Definition> {
        if self.managed.is_some() {
            return definitions.iter().find(|d| d.scope == Scope::Managed);
        }
        definitions.iter().find(|d| d.is_active())
    }

    /// Names of every entry, in any scope of this project, that is a wrap
    /// with `--dir` equal to `dir`, whatever its mode.
    pub fn wrapped_for(&self, dir: &str) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        let mut collect = |doc: &JsonValue| {
            for (name, entry) in servers_of(doc) {
                if let Some(parsed) = install::parsed_wrap(entry)
                    && install::flag_once(&parsed.options, "--dir")
                        .is_some_and(|d| same_dir(d, dir))
                {
                    names.insert(name.clone());
                }
            }
        };
        if let Some((_, doc)) = &self.managed {
            collect(doc);
        }
        if let Some(state) = self.project_state() {
            collect(state);
        }
        if let Some((_, doc)) = &self.project_file {
            collect(doc);
        }
        if let Some((_, doc)) = &self.user {
            collect(doc);
        }
        names
    }
}

fn same_dir(a: &str, b: &str) -> bool {
    a == b || same_path(Path::new(a), Path::new(b))
}

/// What a definition is, for the policy of this home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A wrap for this home and mode, under this name.
    Governed,
    /// A wrap for another home, mode or name: the receipts, if any, land
    /// elsewhere or under another server name.
    OtherWrap(String),
    /// A plain (or remote) definition: no policy, no receipt.
    Raw,
}

/// The target a wrap must match to be governed: this home and mode.
#[derive(Debug, Clone)]
pub struct Expected {
    pub dir: String,
    pub mode: Mode,
}

/// Classifies one entry. The binary is any `praetore-mcp`; what matters
/// is the home, the mode and the name the receipts carry.
pub fn classify(name: &str, entry: &JsonValue, expected: &Expected) -> Verdict {
    if install::is_claude_code_remote(entry) {
        return Verdict::Raw;
    }
    let Some(parsed) = install::parsed_wrap(entry) else {
        return Verdict::Raw;
    };
    let dir = install::flag_once(&parsed.options, "--dir");
    if !dir.is_some_and(|d| same_dir(d, &expected.dir)) {
        return Verdict::OtherWrap(format!(
            "wrapped for home {}, not {}",
            dir.unwrap_or("(none)").shown(),
            expected.dir.shown()
        ));
    }
    let mode = match install::flag_once(&parsed.options, "--mode") {
        None => Some(Mode::Observe),
        Some(value) => Mode::parse(value),
    };
    if mode != Some(expected.mode) {
        return Verdict::OtherWrap(format!(
            "wrapped in mode {}, not {}",
            install::flag_once(&parsed.options, "--mode")
                .unwrap_or("(none)")
                .shown(),
            expected.mode.as_str()
        ));
    }
    let wrapped_name = install::flag_once(&parsed.options, "--name");
    if wrapped_name.is_some_and(|n| n != name) {
        return Verdict::OtherWrap(format!(
            "wrapped under the name {}, so the rules and receipts of {} do not apply to it",
            wrapped_name.unwrap_or_default().shown(),
            name.shown()
        ));
    }
    Verdict::Governed
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerReport {
    pub name: String,
    /// The definition Claude Code runs and what it is; `None` when no
    /// definition loads for this project.
    pub winner: Option<(Definition, Verdict)>,
    /// Definitions below the winner, and a pending project entry, that
    /// would run the server raw if the winner went away or got approved.
    pub warnings: Vec<String>,
    /// Commands that make the winner a wrap for this home, on FAIL.
    pub fixes: Vec<String>,
}

impl ServerReport {
    pub fn is_failure(&self) -> bool {
        !matches!(self.winner, Some((_, Verdict::Governed)))
    }

    pub fn verdict(&self) -> Option<&Verdict> {
        self.winner.as_ref().map(|(_, verdict)| verdict)
    }

    pub fn scope(&self) -> Option<Scope> {
        self.winner.as_ref().map(|(def, _)| def.scope)
    }
}

/// The commands a fix line names: `install`, `uninstall` and the home.
pub struct Commands {
    /// `commands::program()`: the running binary, as a shell word.
    pub program: String,
    /// ` --dir <home>`, as `cli::dir_suffix` writes it.
    pub dir_suffix: String,
    pub mode: Mode,
}

impl Commands {
    fn install(&self, config: &Path) -> String {
        format!(
            "{} install --client claude-code --config {}{} --mode {}",
            self.program,
            crate::commands::dir(config),
            self.dir_suffix,
            self.mode.as_str()
        )
    }

    fn uninstall(&self, config: &Path) -> String {
        format!(
            "{} uninstall --client claude-code --config {}",
            self.program,
            crate::commands::dir(config)
        )
    }
}

fn remove_command(name: &str, scope: Scope) -> String {
    format!(
        "claude mcp remove {} -s {}",
        crate::commands::quote(name),
        scope.label()
    )
}

/// `claude mcp add -s user NAME -- <command> [args]` for a raw entry.
fn add_user_command(name: &str, entry: &JsonValue) -> Option<String> {
    let command = entry.get("command").and_then(JsonValue::as_str)?;
    let original = install::parsed_wrap(entry);
    let (command, args): (&str, Vec<String>) = match &original {
        Some(parsed) => (parsed.command.as_str(), parsed.args.clone()),
        None => (
            command,
            entry
                .get("args")
                .and_then(JsonValue::as_array)
                .map(|args| {
                    args.iter()
                        .filter_map(JsonValue::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        ),
    };
    let mut words = vec![
        "claude".to_owned(),
        "mcp".to_owned(),
        "add".to_owned(),
        "-s".to_owned(),
        "user".to_owned(),
        crate::commands::quote(name),
        "--".to_owned(),
        crate::commands::quote(command),
    ];
    words.extend(args.iter().map(|a| crate::commands::quote(a)));
    Some(words.join(" "))
}

/// Resolves and classifies every name in `targets`.
pub fn diagnose(
    config: &ClaudeCodeConfig,
    targets: &BTreeSet<String>,
    expected: &Expected,
    commands: &Commands,
) -> Vec<ServerReport> {
    targets
        .iter()
        .map(|name| diagnose_one(config, name, expected, commands))
        .collect()
}

fn diagnose_one(
    config: &ClaudeCodeConfig,
    name: &str,
    expected: &Expected,
    commands: &Commands,
) -> ServerReport {
    let definitions = config.definitions(name);
    let winner = config.winner(&definitions);
    let mut warnings = Vec::new();
    let mut fixes = Vec::new();

    // A governed definition below the winner: removing the winner is enough.
    let governed_below = definitions.iter().find(|def| {
        winner != Some(def)
            && def.is_active()
            && classify(name, &def.entry, expected) == Verdict::Governed
    });

    for def in &definitions {
        if winner == Some(def) {
            continue;
        }
        let shadow = classify(name, &def.entry, expected);
        if shadow == Verdict::Governed {
            continue;
        }
        match &def.approval {
            Some(Approval::Pending) if config.managed.is_none() => warnings.push(format!(
                "{}: a raw definition; it wins over the wrapped one the moment the project's servers are approved",
                def.describe()
            )),
            Some(Approval::Rejected(_)) => warnings.push(format!(
                "{}: a raw definition, inactive while it stays rejected",
                def.describe()
            )),
            _ => warnings.push(format!(
                "{}: a raw definition, inactive while {} defines the server",
                def.describe(),
                winner.map_or("managed-mcp.json", |w| w.scope.label())
            )),
        }
    }

    let winner = winner.map(|def| (def.clone(), classify(name, &def.entry, expected)));
    match &winner {
        Some((_, Verdict::Governed)) => {}
        None => {
            if let Some((path, _)) = &config.managed {
                fixes.push(format!(
                    "{} has exclusive control and does not define {}; ask the administrator who deploys it",
                    path.shown(),
                    name.shown()
                ));
            } else {
                fixes.push(format!(
                    "define it (claude mcp add -s user {} -- <command> [args]), then run {}",
                    crate::commands::quote(name),
                    commands.install(&user_config_path(config))
                ));
                fixes.push(format!(
                    "or remove the rules whose target is {} ({} policy list{})",
                    name.shown(),
                    commands.program,
                    commands.dir_suffix
                ));
            }
        }
        Some((def, verdict)) => match def.scope {
            Scope::Managed => fixes.push(format!(
                "{} is deployed by an administrator and loads before every other scope; it must run {} wrap{} --name {} --mode {} -- <command> [args] for this home to govern it",
                def.source.shown(),
                commands.program,
                commands.dir_suffix,
                crate::commands::quote(name),
                commands.mode.as_str()
            )),
            Scope::Local => {
                fixes.push(remove_command(name, Scope::Local));
                if governed_below.is_none() {
                    if let Some(add) = add_user_command(name, &def.entry) {
                        fixes.push(add);
                    }
                    fixes.push(commands.install(&user_config_path(config)));
                }
            }
            Scope::Project | Scope::User => {
                if let Some(below) = governed_below {
                    fixes.push(format!(
                        "{} (the wrap in {} scope then runs)",
                        remove_command(name, def.scope),
                        below.scope.label()
                    ));
                } else {
                    if matches!(verdict, Verdict::OtherWrap(_)) {
                        fixes.push(commands.uninstall(&def.source));
                    }
                    fixes.push(commands.install(&def.source));
                }
            }
        },
    }

    ServerReport {
        name: name.to_owned(),
        winner,
        warnings,
        fixes,
    }
}

fn user_config_path(config: &ClaudeCodeConfig) -> PathBuf {
    config
        .user
        .as_ref()
        .map(|(path, _)| path.clone())
        .unwrap_or_else(|| PathBuf::from("~/.claude.json"))
}

/// The lines `doctor` prints for the servers, then the summary.
pub fn render(reports: &[ServerReport], enable_all: &[PathBuf]) -> String {
    let mut out = String::new();
    for path in enable_all {
        out.push_str(&format!(
            "WARN enableAllProjectMcpServers is true in {}: every server of a .mcp.json is approved without a prompt\n",
            path.shown()
        ));
    }
    let mut governed = 0usize;
    let mut not_governed = 0usize;
    let mut undefined = 0usize;
    let mut warnings = enable_all.len();
    for report in reports {
        let name = report.name.shown();
        match &report.winner {
            Some((def, Verdict::Governed)) => {
                governed += 1;
                out.push_str(&format!("OK   {name}: {}\n", def.describe()));
            }
            Some((def, Verdict::Raw)) => {
                not_governed += 1;
                out.push_str(&format!(
                    "FAIL {name}: {}: NOT governed (raw definition from {} scope)\n",
                    def.describe(),
                    def.scope.label()
                ));
            }
            Some((def, Verdict::OtherWrap(why))) => {
                not_governed += 1;
                out.push_str(&format!(
                    "FAIL {name}: {}: NOT governed by this home ({why})\n",
                    def.describe()
                ));
            }
            None => {
                undefined += 1;
                out.push_str(&format!(
                    "FAIL {name}: not defined in any scope that loads for this project\n"
                ));
            }
        }
        for warning in &report.warnings {
            warnings += 1;
            out.push_str(&format!("WARN {name}: {warning}\n"));
        }
        for fix in &report.fixes {
            out.push_str(&format!("     fix: {fix}\n"));
        }
    }
    out.push_str(&format!(
        "summary: {} server(s): {governed} governed, {not_governed} not governed, {undefined} not defined, {warnings} warning(s)\n",
        reports.len()
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(text: &str) -> JsonValue {
        JsonValue::parse(text).unwrap()
    }

    const HOME: &str = "/home/u/.praetore/mcp";

    fn wrapped(name: &str, dir: &str, mode: &str) -> String {
        format!(
            r#"{{"command":"/opt/bin/praetore-mcp","args":["wrap","--dir","{dir}","--name","{name}","--mode","{mode}","--","npx","-y","srv"]}}"#
        )
    }

    fn expected() -> Expected {
        Expected {
            dir: HOME.to_owned(),
            mode: Mode::Observe,
        }
    }

    fn commands() -> Commands {
        Commands {
            program: "/opt/bin/praetore-mcp".to_owned(),
            dir_suffix: format!(" --dir {HOME}"),
            mode: Mode::Observe,
        }
    }

    fn config(user: &str, project_file: Option<&str>) -> ClaudeCodeConfig {
        ClaudeCodeConfig {
            managed: None,
            user: Some((PathBuf::from("/home/u/.claude.json"), doc(user))),
            project_file: project_file.map(|t| (PathBuf::from("/p/a/.mcp.json"), doc(t))),
            project: PathBuf::from("/p/a"),
            settings: Vec::new(),
        }
    }

    fn one(config: &ClaudeCodeConfig, name: &str) -> ServerReport {
        diagnose_one(config, name, &expected(), &commands())
    }

    #[test]
    fn classify_needs_this_home_mode_and_name() {
        let ok = doc(&wrapped("fs", HOME, "observe"));
        assert_eq!(classify("fs", &ok, &expected()), Verdict::Governed);
        let other_home = doc(&wrapped("fs", "/elsewhere", "observe"));
        assert!(matches!(
            classify("fs", &other_home, &expected()),
            Verdict::OtherWrap(why) if why.contains("home")
        ));
        let other_mode = doc(&wrapped("fs", HOME, "enforce"));
        assert!(matches!(
            classify("fs", &other_mode, &expected()),
            Verdict::OtherWrap(why) if why.contains("mode")
        ));
        let other_name = doc(&wrapped("git", HOME, "observe"));
        assert!(matches!(
            classify("fs", &other_name, &expected()),
            Verdict::OtherWrap(why) if why.contains("name")
        ));
        // No --mode means observe, the default of wrap.
        let no_mode = doc(&format!(
            r#"{{"command":"praetore-mcp","args":["wrap","--dir","{HOME}","--","srv"]}}"#
        ));
        assert_eq!(classify("fs", &no_mode, &expected()), Verdict::Governed);
        assert_eq!(
            classify("fs", &doc(r#"{"command":"npx"}"#), &expected()),
            Verdict::Raw
        );
        // A remote entry never runs its command, wrap or not.
        let remote = doc(&format!(
            r#"{{"type":"http","url":"https://x/mcp","command":"praetore-mcp","args":["wrap","--dir","{HOME}","--","srv"]}}"#
        ));
        assert_eq!(classify("fs", &remote, &expected()), Verdict::Raw);
    }

    #[test]
    fn local_scope_wins_over_a_wrapped_user_entry() {
        let user = format!(
            r#"{{"projects":{{"/p/a":{{"mcpServers":{{"fs":{{"command":"npx"}}}}}}}},"mcpServers":{{"fs":{}}}}}"#,
            wrapped("fs", HOME, "observe")
        );
        let report = one(&config(&user, None), "fs");
        assert_eq!(report.verdict(), Some(&Verdict::Raw));
        assert_eq!(report.scope(), Some(Scope::Local));
        assert_eq!(
            report.fixes,
            vec!["claude mcp remove fs -s local".to_owned()]
        );
        // The same local entry in another project does not count.
        let mut other = config(&user, None);
        other.project = PathBuf::from("/p/other");
        let report = one(&other, "fs");
        assert_eq!(report.verdict(), Some(&Verdict::Governed));
    }

    #[test]
    fn a_project_entry_counts_only_once_approved() {
        let user_wrapped = |state: &str| {
            format!(
                r#"{{"projects":{{"/p/a":{state}}},"mcpServers":{{"fs":{}}}}}"#,
                wrapped("fs", HOME, "observe")
            )
        };
        let project = r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","srv"]}}}"#;

        let pending = one(&config(&user_wrapped("{}"), Some(project)), "fs");
        assert_eq!(pending.verdict(), Some(&Verdict::Governed));
        assert_eq!(pending.warnings.len(), 1, "{pending:?}");
        assert!(pending.warnings[0].contains("the moment the project's servers are approved"));

        let named = one(
            &config(
                &user_wrapped(r#"{"enabledMcpjsonServers":["fs"]}"#),
                Some(project),
            ),
            "fs",
        );
        assert_eq!(named.verdict(), Some(&Verdict::Raw));
        assert_eq!(named.scope(), Some(Scope::Project));
        assert_eq!(
            named.fixes,
            vec!["claude mcp remove fs -s project (the wrap in user scope then runs)".to_owned()]
        );

        let all = one(
            &config(
                &user_wrapped(r#"{"enableAllProjectMcpServers":true}"#),
                Some(project),
            ),
            "fs",
        );
        assert_eq!(all.verdict(), Some(&Verdict::Raw));

        let rejected = one(
            &config(
                &user_wrapped(
                    r#"{"enableAllProjectMcpServers":true,"disabledMcpjsonServers":["fs"]}"#,
                ),
                Some(project),
            ),
            "fs",
        );
        assert_eq!(rejected.verdict(), Some(&Verdict::Governed));
        assert!(rejected.warnings[0].contains("rejected"), "{rejected:?}");
    }

    #[test]
    fn settings_files_approve_too() {
        let user = format!(
            r#"{{"mcpServers":{{"fs":{}}}}}"#,
            wrapped("fs", HOME, "observe")
        );
        let project = r#"{"mcpServers":{"fs":{"command":"npx"}}}"#;
        let mut cfg = config(&user, Some(project));
        cfg.settings.push((
            PathBuf::from("/p/a/.claude/settings.json"),
            doc(r#"{"enableAllProjectMcpServers":true}"#),
        ));
        assert_eq!(
            cfg.enable_all_sources(),
            vec![PathBuf::from("/p/a/.claude/settings.json")]
        );
        let report = one(&cfg, "fs");
        assert_eq!(report.verdict(), Some(&Verdict::Raw));
        assert!(
            render(&[report], &cfg.enable_all_sources()).starts_with(
                "WARN enableAllProjectMcpServers is true in /p/a/.claude/settings.json"
            )
        );
    }

    #[test]
    fn managed_mcp_json_has_exclusive_control() {
        let user = format!(
            r#"{{"mcpServers":{{"fs":{},"git":{{"command":"uvx"}}}}}}"#,
            wrapped("fs", HOME, "observe")
        );
        let mut cfg = config(&user, None);
        cfg.managed = Some((
            PathBuf::from("/Library/Application Support/ClaudeCode/managed-mcp.json"),
            doc(r#"{"mcpServers":{"git":{"command":"uvx","args":["mcp-server-git"]}}}"#),
        ));
        let fs = one(&cfg, "fs");
        assert_eq!(fs.winner, None);
        assert!(fs.fixes[0].contains("exclusive control"), "{fs:?}");
        let git = one(&cfg, "git");
        assert_eq!(git.verdict(), Some(&Verdict::Raw));
        assert_eq!(git.scope(), Some(Scope::Managed));
        assert!(git.fixes[0].contains("administrator"), "{git:?}");
    }

    #[test]
    fn an_undefined_target_and_a_raw_user_entry_get_install_lines() {
        let cfg = config(
            r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","srv"]}}}"#,
            None,
        );
        let fs = one(&cfg, "fs");
        assert_eq!(fs.verdict(), Some(&Verdict::Raw));
        assert_eq!(
            fs.fixes,
            vec![format!(
                "/opt/bin/praetore-mcp install --client claude-code --config /home/u/.claude.json --dir {HOME} --mode observe"
            )]
        );
        let db = one(&cfg, "db");
        assert_eq!(db.winner, None);
        assert!(db.fixes[0].starts_with("define it (claude mcp add -s user db -- "));
        assert!(db.fixes[1].contains("policy list"));
    }

    #[test]
    fn a_wrap_for_another_home_gets_uninstall_then_install() {
        let cfg = config(
            &format!(
                r#"{{"mcpServers":{{"fs":{}}}}}"#,
                wrapped("fs", "/other", "observe")
            ),
            None,
        );
        let fs = one(&cfg, "fs");
        assert!(matches!(fs.verdict(), Some(Verdict::OtherWrap(_))));
        assert_eq!(fs.fixes.len(), 2);
        assert!(
            fs.fixes[0].contains(" uninstall --client claude-code --config /home/u/.claude.json")
        );
        assert!(
            fs.fixes[1].contains(" install --client claude-code --config /home/u/.claude.json")
        );
    }

    #[test]
    fn wrapped_for_lists_every_scope_of_this_project() {
        let user = format!(
            r#"{{"projects":{{"/p/a":{{"mcpServers":{{"loc":{}}}}},"/p/b":{{"mcpServers":{{"other":{}}}}}}},"mcpServers":{{"usr":{},"raw":{{"command":"x"}},"elsewhere":{}}}}}"#,
            wrapped("loc", HOME, "enforce"),
            wrapped("other", HOME, "observe"),
            wrapped("usr", HOME, "observe"),
            wrapped("elsewhere", "/other", "observe"),
        );
        let project = format!(
            r#"{{"mcpServers":{{"prj":{}}}}}"#,
            wrapped("prj", HOME, "observe")
        );
        let cfg = config(&user, Some(&project));
        let names: Vec<_> = cfg.wrapped_for(HOME).into_iter().collect();
        assert_eq!(names, ["loc", "prj", "usr"]);
    }

    #[test]
    fn render_escapes_names_and_counts() {
        let cfg = config(
            &format!(
                r#"{{"mcpServers":{{"s\u001b[2K":{},"raw":{{"command":"x"}}}}}}"#,
                wrapped("s\\u001b[2K", HOME, "observe")
            ),
            None,
        );
        let targets: BTreeSet<String> =
            ["s\x1b[2K".to_owned(), "raw".to_owned(), "none".to_owned()]
                .into_iter()
                .collect();
        let reports = diagnose(&cfg, &targets, &expected(), &commands());
        let text = render(&reports, &[]);
        assert!(!text.contains('\x1b'), "{text:?}");
        assert!(text.contains("OK   s\\u{1b}[2K:"), "{text}");
        assert!(text.contains("FAIL raw:"), "{text}");
        assert!(text.contains("FAIL none: not defined"), "{text}");
        assert!(text.ends_with(
            "summary: 3 server(s): 1 governed, 1 not governed, 1 not defined, 0 warning(s)\n"
        ));
        assert_eq!(reports.iter().filter(|r| r.is_failure()).count(), 2);
    }
}
