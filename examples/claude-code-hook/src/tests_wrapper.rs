//! Hallazgo 13: `hook/praetore-hook.sh` fails closed. Whatever happens to
//! the binary (it cannot start, panics, is killed by a signal, prints
//! something that is not a decision), the wrapper prints a deny decision and
//! exits 0. The binary is replaced by test doubles; the wrapper runs under
//! `/bin/sh` and, if present, `/bin/bash`.

use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use serde_json::Value;

const EVENT: &str = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/","tool_use_id":"toolu_wrapper"}"#;

fn wrapper() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("hook/praetore-hook.sh")
}

fn shells() -> Vec<&'static str> {
    ["/bin/sh", "/bin/bash"]
        .into_iter()
        .filter(|shell| Path::new(shell).exists())
        .collect()
}

/// A project directory with `.claude/praetore/policy.json` and the binary
/// double at `.claude/bin/praetore-claude-hook`.
struct Project {
    root: PathBuf,
}

impl Project {
    fn new(name: &str, binary: &[u8]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "praetore-claude-hook-wrapper-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join(".claude/praetore")).unwrap();
        fs::create_dir_all(root.join(".claude/bin")).unwrap();
        fs::write(root.join(".claude/praetore/policy.json"), "{}").unwrap();
        let bin = root.join(".claude/bin/praetore-claude-hook");
        fs::write(&bin, binary).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
        Self { root }
    }

    /// Runs the wrapper with `shell`; returns (exit code, stdout).
    fn run(&self, shell: &str, project_dir: bool) -> (Option<i32>, String) {
        let mut command = Command::new(shell);
        command
            .arg(wrapper())
            .env_remove("PRAETORE_HOOK_BIN")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if project_dir {
            command.env("CLAUDE_PROJECT_DIR", &self.root);
        } else {
            command.env_remove("CLAUDE_PROJECT_DIR");
        }
        let mut child = command.spawn().unwrap();
        // The double may exit without reading stdin.
        let _ = child.stdin.take().unwrap().write_all(EVENT.as_bytes());
        let out = child.wait_with_output().unwrap();
        (out.status.code(), String::from_utf8(out.stdout).unwrap())
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assert_deny(label: &str, (code, stdout): (Option<i32>, String), reason: &str) {
    assert_eq!(code, Some(0), "{label}: {stdout}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{label}: {stdout:?}");
    let decision: Value = serde_json::from_str(lines[0]).unwrap();
    let output = &decision["hookSpecificOutput"];
    assert_eq!(output["hookEventName"], "PreToolUse", "{label}");
    assert_eq!(output["permissionDecision"], "deny", "{label}");
    let text = output["permissionDecisionReason"].as_str().unwrap();
    assert!(text.contains(reason), "{label}: {text}");
}

/// Exit statuses 101 (Rust panic), 137 (SIGKILL), 126 (cannot execute:
/// corrupt binary) and 127 (command not found: an executable text file the
/// shell runs as a script) all become a deny that names the status.
#[test]
fn wrapper_denies_when_the_binary_fails() {
    let mut elf = b"\x7fELF\x02\x01\x01\x00".to_vec();
    elf.extend_from_slice(&[0xff; 64]);
    let cases: [(&str, Vec<u8>, i32); 4] = [
        (
            "panic",
            b"#!/bin/sh\necho 'thread main panicked' >&2\nprintf '{\"partial\":'\nexit 101\n"
                .to_vec(),
            101,
        ),
        ("sigkill", b"#!/bin/sh\nkill -9 $$\n".to_vec(), 137),
        ("corrupt-elf", elf, 126),
        (
            "text-not-a-binary",
            b"praetore-no-such-command-for-this-test\n".to_vec(),
            127,
        ),
    ];
    for (name, binary, status) in cases {
        let project = Project::new(name, &binary);
        for shell in shells() {
            let label = format!("{name} under {shell}");
            assert_deny(
                &label,
                project.run(shell, true),
                &format!("exit status {status}"),
            );
        }
    }
    // A missing interpreter is 126 or 127 depending on the shell: a deny
    // either way.
    let project = Project::new(
        "missing-interpreter",
        b"#!/nonexistent/praetore-interpreter\n",
    );
    for shell in shells() {
        assert_deny(
            &format!("missing interpreter under {shell}"),
            project.run(shell, true),
            "PRÆTORE hook binary failed (exit status 12",
        );
    }
}

#[test]
fn wrapper_denies_without_project_dir_binary_or_state() {
    let project = Project::new("setup", b"#!/bin/sh\nexit 0\n");
    for shell in shells() {
        assert_deny(
            &format!("no CLAUDE_PROJECT_DIR under {shell}"),
            project.run(shell, false),
            "CLAUDE_PROJECT_DIR is not set",
        );
    }
    fs::remove_file(project.root.join(".claude/praetore/policy.json")).unwrap();
    for shell in shells() {
        assert_deny(
            &format!("no state under {shell}"),
            project.run(shell, true),
            "not set up",
        );
    }
}

#[test]
fn wrapper_denies_output_that_is_not_a_json_object() {
    let project = Project::new("garbage", b"#!/bin/sh\ncat >/dev/null\necho allow\n");
    for shell in shells() {
        assert_deny(
            &format!("garbage under {shell}"),
            project.run(shell, true),
            "other than a JSON object",
        );
    }
}

/// A binary that exits 0 is passed through unchanged: its decision, or no
/// output (no decision). The event reaches the binary on stdin.
#[test]
fn wrapper_passes_a_successful_decision_through() {
    let decision = r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"r"}}"#;
    let script = format!(
        "#!/bin/sh\ninput=$(cat)\ncase \"$input\" in *toolu_wrapper*) printf '%s\\n' '{decision}' ;; *) exit 3 ;; esac\n"
    );
    let project = Project::new("ok", script.as_bytes());
    for shell in shells() {
        let (code, stdout) = project.run(shell, true);
        assert_eq!(code, Some(0), "{shell}");
        assert_eq!(stdout, format!("{decision}\n"), "{shell}");
    }
    let silent = Project::new("silent", b"#!/bin/sh\ncat >/dev/null\n");
    for shell in shells() {
        assert_eq!(silent.run(shell, true), (Some(0), String::new()), "{shell}");
    }
}
