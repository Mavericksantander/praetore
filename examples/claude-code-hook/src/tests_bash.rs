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
        initialize(&state, &root, AUTHORITY_LIFETIME_DAYS).unwrap();
        Self { root, state }
    }

    fn root(&self) -> String {
        self.root.display().to_string()
    }

    /// Sends one `PreToolUse` event for `Bash`, as Claude Code does: no
    /// `agent_type` for the main session.
    fn bash(&self, agent: Option<&str>, command: &str) -> Verdict {
        let mut event = json!({
            "session_id": "s-bash",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command, "description": "test" },
            "tool_use_id": "toolu_bash",
            "cwd": self.root(),
        });
        if let Some(agent) = agent {
            event["agent_type"] = json!(agent);
        }
        let input: HookInput = serde_json::from_value(event).unwrap();
        authorize(&self.state, &input).unwrap()
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
