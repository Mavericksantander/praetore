//! `doctor` against fixture `.claude.json`, `.mcp.json` and settings files
//! written into a temp dir, through the real binary. HOME and
//! `--claude-config` point into that dir, so the real `~/.claude.json` is
//! never read.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const BIN: &str = env!("CARGO_BIN_EXE_praetore-mcp");

struct Fixture {
    _temp: tempfile::TempDir,
    /// HOME: holds `.claude.json` and `.claude/settings.json`.
    home: PathBuf,
    /// The praetore home (`--dir`), initialized, with one rule for
    /// `filesystem`.
    dir: PathBuf,
    /// The project directory, canonical.
    project: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let home = root.join("home");
        let dir = root.join("praetore");
        let project = root.join("project");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&project).unwrap();
        let dir_str = dir.to_str().unwrap();
        let init = run_plain(&["init", "--dir", dir_str]);
        assert_eq!(init.status.code(), Some(0), "{init:?}");
        let allow = run_plain(&[
            "policy",
            "allow",
            "--id",
            "allow-fs-read",
            "--server",
            "filesystem",
            "--tool",
            "read_text_file",
            "--dir",
            dir_str,
        ]);
        assert_eq!(allow.status.code(), Some(0), "{allow:?}");
        Fixture {
            _temp: temp,
            home,
            dir,
            project,
        }
    }

    fn claude_json(&self) -> PathBuf {
        self.home.join(".claude.json")
    }

    fn dir_str(&self) -> &str {
        self.dir.to_str().unwrap()
    }

    fn project_str(&self) -> &str {
        self.project.to_str().unwrap()
    }

    /// A `filesystem` entry wrapped for `dir` in `mode` by a binary named
    /// praetore-mcp (the one under test).
    fn wrapped(&self, dir: &str, mode: &str) -> String {
        format!(
            r#"{{"command":{},"args":["wrap","--dir",{},"--name","filesystem","--mode","{mode}","--","npx","-y","@modelcontextprotocol/server-filesystem","/tmp"]}}"#,
            serde_json::to_string(BIN).unwrap(),
            serde_json::to_string(dir).unwrap()
        )
    }

    fn write_claude_json(&self, projects: &str, servers: &str) {
        fs::write(
            self.claude_json(),
            format!(r#"{{"numStartups": 3, "projects": {projects}, "mcpServers": {servers}}}"#),
        )
        .unwrap();
    }

    fn write_project_mcp(&self, text: &str) {
        fs::write(self.project.join(".mcp.json"), text).unwrap();
    }

    fn doctor(&self, extra: &[&str]) -> Output {
        let claude_json = self.claude_json();
        let mut args = vec![
            "doctor",
            "--dir",
            self.dir_str(),
            "--project",
            self.project_str(),
            "--claude-config",
            claude_json.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        Command::new(BIN)
            .args(&args)
            .env("HOME", &self.home)
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("PRAETORE_MCP_HOME")
            .current_dir(&self.home)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
}

fn run_plain(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn project_state(project: &Path, state: &str) -> String {
    format!(
        "{{{}: {state}}}",
        serde_json::to_string(project.to_str().unwrap()).unwrap()
    )
}

const RAW_FS: &str =
    r#"{"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}"#;

/// (1) The wrapped user entry is the only definition.
#[test]
fn wrapped_user_entry_alone_is_ok() {
    let fx = Fixture::new();
    fx.write_claude_json(
        "{}",
        &format!(
            r#"{{"filesystem": {}}}"#,
            fx.wrapped(fx.dir_str(), "observe")
        ),
    );
    let out = fx.doctor(&[]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(
        stdout.contains(&format!(
            "OK   filesystem: user scope ({})",
            fx.claude_json().display()
        )),
        "{stdout}"
    );
    assert!(stdout.contains("wrap --dir"), "{stdout}");
    assert!(
        stdout.contains(
            "summary: 1 server(s): 1 governed, 0 not governed, 0 not defined, 0 warning(s)"
        ),
        "{stdout}"
    );
    assert!(!stdout.contains("FAIL"), "{stdout}");
    assert!(!stdout.contains("WARN"), "{stdout}");
}

/// (2) A raw `.mcp.json` entry that the user has not approved: OK with a
/// WARN naming the shadow.
#[test]
fn unapproved_project_entry_is_a_warning() {
    let fx = Fixture::new();
    fx.write_claude_json(
        &project_state(&fx.project, "{}"),
        &format!(
            r#"{{"filesystem": {}}}"#,
            fx.wrapped(fx.dir_str(), "observe")
        ),
    );
    fx.write_project_mcp(&format!(r#"{{"mcpServers": {{"filesystem": {RAW_FS}}}}}"#));
    let out = fx.doctor(&[]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(stdout.contains("OK   filesystem: user scope"), "{stdout}");
    let warn = stdout
        .lines()
        .find(|line| line.starts_with("WARN filesystem:"))
        .unwrap_or_else(|| panic!("{stdout}"));
    assert!(
        warn.contains(&format!(
            "project scope ({}, not approved yet) runs npx -y @modelcontextprotocol/server-filesystem /tmp",
            fx.project.join(".mcp.json").display()
        )),
        "{warn}"
    );
    assert!(
        warn.contains("the moment the project's servers are approved"),
        "{warn}"
    );
    assert!(
        stdout.contains("1 governed, 0 not governed, 0 not defined, 1 warning(s)"),
        "{stdout}"
    );
}

/// (3) The same entry, approved through `enabledMcpjsonServers`: it is the
/// winner, raw, and the fix is to remove it from project scope.
#[test]
fn approved_project_entry_shadows_the_wrapped_user_entry() {
    let fx = Fixture::new();
    fx.write_claude_json(
        &project_state(
            &fx.project,
            r#"{"enabledMcpjsonServers": ["filesystem"], "disabledMcpjsonServers": []}"#,
        ),
        &format!(
            r#"{{"filesystem": {}}}"#,
            fx.wrapped(fx.dir_str(), "observe")
        ),
    );
    fx.write_project_mcp(&format!(r#"{{"mcpServers": {{"filesystem": {RAW_FS}}}}}"#));
    let out = fx.doctor(&[]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let fail = stdout
        .lines()
        .find(|line| line.starts_with("FAIL filesystem:"))
        .unwrap_or_else(|| panic!("{stdout}"));
    assert!(
        fail.contains(&format!(
            "project scope ({}, approved by enabledMcpjsonServers in {})",
            fx.project.join(".mcp.json").display(),
            fx.claude_json().display()
        )),
        "{fail}"
    );
    assert!(
        fail.ends_with("NOT governed (raw definition from project scope)"),
        "{fail}"
    );
    assert!(
        stdout.contains(
            "     fix: claude mcp remove filesystem -s project (the wrap in user scope then runs)\n"
        ),
        "{stdout}"
    );
    assert!(stdout.contains("0 governed, 1 not governed"), "{stdout}");
}

/// (3b) `enableAllProjectMcpServers` in the project's settings approves
/// it too, and is reported on its own WARN line.
#[test]
fn enable_all_in_project_settings_approves_and_warns() {
    let fx = Fixture::new();
    fx.write_claude_json(
        "{}",
        &format!(
            r#"{{"filesystem": {}}}"#,
            fx.wrapped(fx.dir_str(), "observe")
        ),
    );
    fx.write_project_mcp(&format!(r#"{{"mcpServers": {{"filesystem": {RAW_FS}}}}}"#));
    let settings = fx.project.join(".claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, r#"{"enableAllProjectMcpServers": true}"#).unwrap();
    let out = fx.doctor(&[]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        stdout.contains(&format!(
            "WARN enableAllProjectMcpServers is true in {}",
            settings.display()
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "approved by enableAllProjectMcpServers in {})",
            settings.display()
        )),
        "{stdout}"
    );
    assert!(stdout.contains("FAIL filesystem:"), "{stdout}");
}

/// (4) A raw local-scope entry wins over the wrapped user entry.
#[test]
fn raw_local_scope_entry_fails() {
    let fx = Fixture::new();
    fx.write_claude_json(
        &project_state(
            &fx.project,
            &format!(r#"{{"mcpServers": {{"filesystem": {RAW_FS}}}}}"#),
        ),
        &format!(
            r#"{{"filesystem": {}}}"#,
            fx.wrapped(fx.dir_str(), "observe")
        ),
    );
    let out = fx.doctor(&[]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        stdout.contains(&format!(
            "FAIL filesystem: local scope ({}) runs npx -y @modelcontextprotocol/server-filesystem /tmp: NOT governed (raw definition from local scope)",
            fx.claude_json().display()
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains("     fix: claude mcp remove filesystem -s local\n"),
        "{stdout}"
    );
}

/// (5) A user entry wrapped for another home, or another mode, is not
/// governed by this one.
#[test]
fn wrap_for_another_home_or_mode_fails() {
    let fx = Fixture::new();
    fx.write_claude_json(
        "{}",
        &format!(
            r#"{{"filesystem": {}}}"#,
            fx.wrapped("/elsewhere/mcp", "observe")
        ),
    );
    let out = fx.doctor(&[]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        stdout.contains("NOT governed by this home (wrapped for home /elsewhere/mcp, not "),
        "{stdout}"
    );
    assert!(
        stdout.contains(" uninstall --client claude-code --config "),
        "{stdout}"
    );
    assert!(
        stdout.contains(" install --client claude-code --config "),
        "{stdout}"
    );

    fx.write_claude_json(
        "{}",
        &format!(
            r#"{{"filesystem": {}}}"#,
            fx.wrapped(fx.dir_str(), "enforce")
        ),
    );
    let out = fx.doctor(&[]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        text(&out.stdout).contains("wrapped in mode enforce, not observe"),
        "{out:?}"
    );
    // With --mode enforce the same entry is governed.
    let out = fx.doctor(&["--mode", "enforce"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}

/// (6) A policy target with no definition in any scope.
#[test]
fn policy_target_without_a_definition_fails() {
    let fx = Fixture::new();
    fx.write_claude_json("{}", r#"{"other": {"command": "x"}}"#);
    let out = fx.doctor(&[]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        stdout.contains("FAIL filesystem: not defined in any scope that loads for this project"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "     fix: define it (claude mcp add -s user filesystem -- <command> [args]), then run "
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("0 governed, 0 not governed, 1 not defined"),
        "{stdout}"
    );
    // A missing ~/.claude.json is not an error: the server is undefined.
    fs::remove_file(fx.claude_json()).unwrap();
    let out = fx.doctor(&[]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        text(&out.stdout).contains("FAIL filesystem: not defined"),
        "{out:?}"
    );
}

/// (7) A file that is not strict JSON stops doctor with exit 2.
#[test]
fn malformed_json_exits_two() {
    let fx = Fixture::new();
    fs::write(fx.claude_json(), "{\"mcpServers\": {}, }").unwrap();
    let out = fx.doctor(&[]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(text(&out.stderr).contains("is not strict JSON"), "{out:?}");

    fx.write_claude_json("{}", "{}");
    fx.write_project_mcp("// comment\n{}");
    let out = fx.doctor(&[]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(
        text(&out.stderr).contains(".mcp.json is not strict JSON"),
        "{out:?}"
    );
}

#[test]
fn other_clients_are_a_usage_error() {
    let fx = Fixture::new();
    fx.write_claude_json("{}", "{}");
    let out = fx.doctor(&["--client", "cursor"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(text(&out.stderr).contains("claude-code only"), "{out:?}");
    let out = fx.doctor(&["--client", "cc"]);
    assert_ne!(out.status.code(), Some(2), "{out:?}");
}

/// Wrapped entries for this home count even without a policy rule: a
/// wrap for the home in local scope is governed, a user entry wrapped under
/// another name is not.
#[test]
fn wrapped_entries_without_rules_are_checked_too() {
    let fx = Fixture::new();
    let git = format!(
        r#"{{"command":{},"args":["wrap","--dir",{},"--name","git-renamed","--mode","observe","--","uvx","mcp-server-git"]}}"#,
        serde_json::to_string(BIN).unwrap(),
        serde_json::to_string(fx.dir_str()).unwrap()
    );
    fx.write_claude_json(
        &project_state(
            &fx.project,
            &format!(
                r#"{{"mcpServers": {{"filesystem": {}}}}}"#,
                fx.wrapped(fx.dir_str(), "observe")
            ),
        ),
        &format!(r#"{{"git": {git}}}"#),
    );
    let out = fx.doctor(&[]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(stdout.contains("OK   filesystem: local scope"), "{stdout}");
    assert!(
        stdout.contains("FAIL git: user scope")
            && stdout.contains("wrapped under the name git-renamed"),
        "{stdout}"
    );
}
