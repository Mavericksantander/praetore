//! `Bash` under the default profiles (GHSA-wg33-3h8v-xvqw).
//!
//! Each test feeds the hook the `PreToolUse` JSON Claude Code sends and reads
//! the decision `authorize` returns. They call the hook directly on purpose:
//! an end-to-end run through Claude Code only exercises the tools an agent
//! definition's `tools:` list exposes, so a case that list hides would never
//! reach the hook there.
//!
//! What they pin:
//! - no subagent profile holds `process:execute`, so a subagent's `Bash`
//!   call is denied for lack of the capability, whatever the command;
//! - for the main session, an analyzable command whose words name
//!   `<root>/.claude` or `<root>/.git`, a path outside the root, or a common
//!   network tool requires approval under its own rule, while an ordinary
//!   command is still allowed.
//!
//! The scan behind the second point is best effort, not a boundary (see
//! `shell`).

use std::path::PathBuf;

use super::*;

struct Project {
    root: PathBuf,
    state: PathBuf,
}

impl Project {
    fn new(name: &str) -> Self {
        Self::with_profiles(name, &PROFILES)
    }

    fn with_profiles(name: &str, profiles: &[(&str, &[&str])]) -> Self {
        let base = std::env::temp_dir().join(format!(
            "praetore-claude-hook-bash-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join(".claude")).unwrap();
        fs::create_dir_all(base.join(".git")).unwrap();
        fs::create_dir_all(base.join("src")).unwrap();
        fs::write(base.join(".git/config"), "").unwrap();
        let root = fs::canonicalize(&base).unwrap();
        let state = root.join(".claude/praetore");
        initialize_with(&state, &root, AUTHORITY_LIFETIME_DAYS, profiles).unwrap();
        Self { root, state }
    }

    fn root(&self) -> String {
        self.root.display().to_string()
    }

    /// Sends one `PreToolUse` event for `Bash`, as Claude Code does: no
    /// `agent_type` for the main session.
    fn bash(&self, agent: Option<&str>, command: &str) -> Verdict {
        self.tool(
            agent,
            "Bash",
            json!({ "command": command, "description": "test" }),
        )
    }

    fn tool(&self, agent: Option<&str>, tool: &str, tool_input: Value) -> Verdict {
        authorize(&self.state, &self.event(agent, tool, tool_input)).unwrap()
    }

    fn event(&self, agent: Option<&str>, tool: &str, tool_input: Value) -> HookInput {
        let mut event = json!({
            "session_id": "s-bash",
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": tool_input,
            "tool_use_id": "toolu_bash",
            "cwd": self.root(),
        });
        if let Some(agent) = agent {
            event["agent_type"] = json!(agent);
        }
        serde_json::from_value(event).unwrap()
    }

    fn path(&self, relative: &str) -> String {
        format!("{}/{relative}", self.root())
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The commands under test, each with the rule that holds it for the main
/// session.
fn cases(p: &Project) -> Vec<(String, &'static str)> {
    let root = p.root();
    let name = p.root.file_name().unwrap().to_str().unwrap().to_string();
    vec![
        // A write to the hook registration.
        (
            "echo '{}' > .claude/settings.local.json".into(),
            "approval-command-touches-protected-path",
        ),
        (
            format!("echo '{{}}' > ../{name}/.claude/settings.local.json"),
            "approval-command-touches-protected-path",
        ),
        (
            format!("cp x {root}/.claude/settings.local.json"),
            "approval-command-touches-protected-path",
        ),
        (
            "cd .claude && echo '{}' > settings.local.json".into(),
            "approval-command-touches-protected-path",
        ),
        // An append to the repository configuration.
        (
            "echo x >> .git/config".into(),
            "approval-command-touches-protected-path",
        ),
        (
            "echo x >> src/../.git/config".into(),
            "approval-command-touches-protected-path",
        ),
        // A read outside the project root.
        ("cat /etc/hosts".into(), "approval-command-leaves-root"),
        ("cat ../outside.txt".into(), "approval-command-leaves-root"),
        (
            "cat src/../../outside.txt".into(),
            "approval-command-leaves-root",
        ),
        ("cat ~/.profile".into(), "approval-command-leaves-root"),
        ("cat $HOME/.profile".into(), "approval-command-leaves-root"),
        // The network without `network:invoke`.
        (
            "curl https://example.test".into(),
            "approval-command-uses-network",
        ),
        (
            "cargo test && wget -q https://example.test".into(),
            "approval-command-uses-network",
        ),
        ("ssh host true".into(), "approval-command-uses-network"),
    ]
}

#[test]
fn no_subagent_profile_holds_process_execute() {
    let p = Project::new("profiles");
    for (name, capabilities) in PROFILES {
        if name != MAIN_AGENT {
            assert!(
                !capabilities.contains(&"process:execute"),
                "{name} must not get process:execute by default"
            );
        }
        let profile: AgentProfile = serde_json::from_slice(
            &fs::read(p.state.join(AGENTS_DIR).join(format!("{name}.json"))).unwrap(),
        )
        .unwrap();
        let issued = profile.authority["capabilities"].to_string();
        assert_eq!(
            issued.contains("process:execute"),
            name == MAIN_AGENT,
            "{name}: {issued}"
        );
    }
}

#[test]
fn subagents_are_denied_bash_for_lack_of_capability() {
    let p = Project::new("subagents");
    let mut commands: Vec<String> = cases(&p).into_iter().map(|(c, _)| c).collect();
    commands.push("cargo test".into());
    for agent in ["coder", "planner", "explorer", "web-fetch"] {
        for command in &commands {
            let verdict = p.bash(Some(agent), command);
            assert_eq!(verdict.outcome, DecisionOutcome::Deny, "{agent}: {command}");
            assert!(
                verdict.reason.contains("process:execute"),
                "{agent}: {command}: {}",
                verdict.reason
            );
        }
    }
}

#[test]
fn main_session_needs_approval_for_protected_paths_outside_paths_and_network() {
    let p = Project::new("main");
    for (command, rule) in cases(&p) {
        let verdict = p.bash(None, &command);
        assert_eq!(
            verdict.outcome,
            DecisionOutcome::RequireApproval,
            "{command}: {verdict:?}"
        );
        assert!(
            verdict.rule.as_deref().unwrap_or_default().contains(rule),
            "{command}: expected {rule}, got {:?}",
            verdict.rule
        );
        assert_eq!(
            hook_output(&verdict).unwrap()["hookSpecificOutput"]["permissionDecision"],
            "ask"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_symlink_out_of_the_root_counts_as_leaving_it() {
    let p = Project::new("symlink");
    std::os::unix::fs::symlink("/etc", p.root.join("out")).unwrap();
    let verdict = p.bash(None, "cat out/hosts");
    assert_eq!(verdict.outcome, DecisionOutcome::RequireApproval);
    assert_eq!(
        verdict.rule.as_deref(),
        Some("approval-command-leaves-root")
    );
}

#[test]
fn ordinary_commands_are_still_allowed_for_the_main_session() {
    let p = Project::new("ordinary");
    for command in [
        "ls src",
        "cargo test --workspace --locked 2>/dev/null",
        "git status && git log --oneline -3",
        "/usr/bin/env cargo fmt --all -- --check",
        "grep -rn 'fn main' src | head -5",
        "git commit -m 'use curl_parsing in ../docs'",
    ] {
        let verdict = p.bash(None, command);
        assert_eq!(
            verdict.outcome,
            DecisionOutcome::Allow,
            "{command}: {verdict:?}"
        );
        assert!(hook_output(&verdict).is_none(), "{command}");
    }
}

#[test]
fn init_records_the_project_root() {
    let p = Project::new("root-file");
    assert_eq!(
        fs::read_to_string(p.state.join(PROJECT_ROOT_FILE))
            .unwrap()
            .trim_end(),
        p.root()
    );
}

/// Writes that make the client, git, a shell or an IDE run something
/// (`CLIENT_CONFIG_PATHS`), outside `.claude/` and `.git/`.
const CLIENT_CONFIG_WRITES: [&str; 8] = [
    ".mcp.json",
    "sub/.MCP.json",
    ".vscode/tasks.json",
    ".cargo/config.toml",
    ".envrc",
    ".husky/pre-commit",
    ".devcontainer/devcontainer.json",
    ".gitmodules",
];

#[test]
fn subagents_cannot_write_client_configuration_and_main_must_ask() {
    let p = Project::new("client-config");
    for relative in CLIENT_CONFIG_WRITES {
        let path = p.path(relative);
        for (tool, input) in [
            ("Write", json!({ "file_path": path, "content": "{}" })),
            ("Edit", json!({ "file_path": path })),
            ("MultiEdit", json!({ "file_path": path })),
            ("NotebookEdit", json!({ "notebook_path": path })),
        ] {
            let verdict = p.tool(Some("coder"), tool, input.clone());
            assert_eq!(
                verdict.outcome,
                DecisionOutcome::Deny,
                "coder {tool} {relative}"
            );
            assert_eq!(
                verdict.rule.as_deref(),
                Some("deny-subagent-client-config-writes"),
                "coder {tool} {relative}"
            );
            let verdict = p.tool(None, tool, input);
            assert_eq!(
                verdict.outcome,
                DecisionOutcome::RequireApproval,
                "main {tool} {relative}"
            );
            assert_eq!(
                verdict.rule.as_deref(),
                Some("approval-main-client-config-writes"),
                "main {tool} {relative}"
            );
        }
    }
    // Ordinary project files are still the coder's to write, including
    // build scripts (see the README on indirect execution).
    for relative in [
        "src/lib.rs",
        "build.rs",
        "docs/mcp.json.md",
        "config/app.toml",
    ] {
        let verdict = p.tool(
            Some("coder"),
            "Write",
            json!({ "file_path": p.path(relative) }),
        );
        assert_eq!(
            verdict.outcome,
            DecisionOutcome::Allow,
            "coder writes {relative}"
        );
    }
    // `.claude/` and `.git/` keep their own rules.
    let verdict = p.tool(
        Some("coder"),
        "Write",
        json!({ "file_path": p.path(".claude/settings.json") }),
    );
    assert_eq!(
        verdict.rule.as_deref(),
        Some("deny-subagent-governance-writes")
    );
}

#[test]
fn a_command_naming_client_configuration_needs_approval() {
    let p = Project::new("client-config-bash");
    for command in [
        "echo '{}' > .mcp.json",
        "cp x .vscode/tasks.json",
        "echo x >> .envrc",
        "cat .cargo/config.toml",
    ] {
        let verdict = p.bash(None, command);
        assert_eq!(
            verdict.outcome,
            DecisionOutcome::RequireApproval,
            "{command}"
        );
        assert_eq!(
            verdict.rule.as_deref(),
            Some("approval-command-touches-protected-path"),
            "{command}"
        );
        assert_eq!(
            p.bash(Some("coder"), command).outcome,
            DecisionOutcome::Deny,
            "{command}"
        );
    }
}

/// `PROFILES` as `init` issued them before GHSA-wg33-3h8v-xvqw.
const EARLIER_PROFILES: [(&str, &[&str]); 6] = [
    (
        MAIN_AGENT,
        &[
            "fs:read",
            "fs:write",
            "process:execute",
            "network:invoke",
            "agent:delegate",
            "tool:invoke",
        ],
    ),
    ("planner", &["fs:read"]),
    ("explorer", &["fs:read"]),
    ("coder", &["fs:read", "fs:write", "process:execute"]),
    ("web-fetch", &["network:invoke"]),
    (UNREGISTERED, &[]),
];

#[test]
fn commands_are_reserved_to_main_whatever_the_authority_grants() {
    let p = Project::with_profiles("exec-guard", &EARLIER_PROFILES);
    let verdict = p.bash(Some("coder"), "cargo test");
    assert_eq!(verdict.outcome, DecisionOutcome::Deny, "{verdict:?}");
    assert!(
        verdict.reason.contains("reserved to the main session"),
        "{}",
        verdict.reason
    );
    // Signed, as `unregistered`.
    let receipts = fs::read_to_string(p.state.join(RECEIPTS_FILE)).unwrap();
    let last: Value = serde_json::from_str(receipts.lines().last().unwrap()).unwrap();
    assert_eq!(last["agent"], "coder");
    assert_eq!(last["profile"], UNREGISTERED);
    // The coder's other capabilities are untouched, and main still runs
    // commands.
    let verdict = p.tool(
        Some("coder"),
        "Write",
        json!({ "file_path": p.path("src/a.rs") }),
    );
    assert_eq!(verdict.outcome, DecisionOutcome::Allow);
    assert_eq!(p.bash(None, "cargo test").outcome, DecisionOutcome::Allow);
}

#[test]
fn earlier_state_is_reported_on_stderr() {
    let p = Project::with_profiles("warnings", &EARLIER_PROFILES);
    let warnings = state_warnings(&p.state);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("profile 'coder' holds process:execute"));

    fs::remove_file(p.state.join(PROJECT_ROOT_FILE)).unwrap();
    let warnings = state_warnings(&p.state);
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(warnings[0].contains("has no project-root"));

    assert!(state_warnings(&Project::new("no-warnings").state).is_empty());
}

#[test]
fn without_a_recorded_root_every_analyzable_command_needs_approval() {
    let p = Project::new("no-root");
    fs::remove_file(p.state.join(PROJECT_ROOT_FILE)).unwrap();
    let verdict = p.bash(None, "ls src");
    assert_eq!(verdict.outcome, DecisionOutcome::RequireApproval);
    assert_eq!(
        verdict.rule.as_deref(),
        Some("approval-command-leaves-root")
    );
}

#[test]
fn an_invalid_project_root_fails_closed() {
    let p = Project::new("bad-root");
    let file = p.state.join(PROJECT_ROOT_FILE);
    let missing = p.path("missing");
    let not_canonical = p.path("src/..");
    for content in ["", "/", "relative/path", &missing, &not_canonical] {
        fs::remove_file(&file).unwrap();
        fs::write(&file, content).unwrap();
        let input = p.event(None, "Bash", json!({ "command": "cat /etc/hosts" }));
        let error = authorize(&p.state, &input).unwrap_err();
        assert!(
            error.to_string().contains("project root"),
            "{content:?}: {error}"
        );
        assert_eq!(fail_closed(error).outcome, DecisionOutcome::Deny);
    }
}

#[test]
fn monitor_and_powershell_are_commands() {
    let p = Project::new("other-shells");
    for tool in ["Monitor", "PowerShell"] {
        let (action_type, capability, ..) = classify(tool, &json!({ "command": "ls" }), None, None);
        assert_eq!(action_type, action_type_of(tool));
        assert_eq!(
            (action_type.as_str(), capability),
            ("claude:exec", "process:execute")
        );
        let verdict = p.tool(Some("coder"), tool, json!({ "command": "ls" }));
        assert_eq!(verdict.outcome, DecisionOutcome::Deny, "{tool}");
    }
    let verdict = p.tool(None, "Monitor", json!({ "command": "curl https://x.test" }));
    assert_eq!(
        verdict.rule.as_deref(),
        Some("approval-command-uses-network")
    );
    assert_eq!(
        p.tool(None, "Monitor", json!({ "command": "tail -f log.txt" }))
            .outcome,
        DecisionOutcome::Allow
    );
    for (tool, input) in [
        ("PowerShell", json!({ "command": "Get-ChildItem" })),
        ("Monitor", json!({ "ws": { "url": "wss://x.test" } })),
    ] {
        let verdict = p.tool(None, tool, input);
        assert_eq!(verdict.outcome, DecisionOutcome::RequireApproval, "{tool}");
        assert_eq!(
            verdict.rule.as_deref(),
            Some("approval-unanalyzable-command"),
            "{tool}"
        );
    }
}
