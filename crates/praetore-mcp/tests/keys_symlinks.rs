//! Keys are read only from a real `DIR/keys` with real files.
//!
//! A scratch home that reaches another home's keys through a symlink (the
//! `keys` directory, a key file, or a directory above them) or through a
//! hard link used to load: `wrap` signed receipts with the other home's
//! keys under the scratch home's policy. Each layout here must refuse
//! every `tools/call` in both modes, and `policy check`, `verify` and
//! `init` must exit non-zero on it.
#![cfg(unix)]

use praetore_core::{PolicyCondition, PolicyEffect, PolicyRule};
use praetore_mcp::store::{self, ACTION_TYPE, CAPABILITY, Home};
use serde_json::json;
use std::{
    fs,
    io::Write,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_praetore-mcp")
}

fn fake_server() -> PathBuf {
    let path = Path::new(bin())
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("fake_server{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.exists(),
        "{} missing: run via `cargo test` so examples are built",
        path.display()
    );
    path
}

fn run(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Allows `echo` and `delete_file`: only the keys can stop a call.
fn write_allow_policy(home: &Home) {
    let mut policy = store::default_policy();
    for tool in ["echo", "delete_file"] {
        policy.rules.push(
            PolicyRule::new(format!("allow-{tool}"), ACTION_TYPE, PolicyEffect::Allow)
                .with_capability(CAPABILITY)
                .with_parameter_condition(PolicyCondition::exact("tool", json!(tool))),
        );
    }
    fs::write(home.policy(), serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
}

/// The victim: an initialized home with the default (deny everything)
/// policy.
fn real_home(root: &Path) -> Home {
    let init = run(&["init", "--dir", root.to_str().unwrap()], "");
    assert!(init.status.success(), "{init:?}");
    Home::new(root.to_path_buf())
}

/// A scratch home with the victim's public files and a policy that allows
/// the calls, but no `keys` yet.
fn scratch_home(root: &Path, real: &Home) -> Home {
    fs::create_dir_all(root).unwrap();
    let home = Home::new(root.to_path_buf());
    for (from, to) in [
        (real.agent(), home.agent()),
        (real.authority(), home.authority()),
        (real.issuer_pins(), home.issuer_pins()),
        (real.attester_pin(), home.attester_pin()),
        (real.approver_pin(), home.approver_pin()),
    ] {
        fs::copy(from, to).unwrap();
    }
    write_allow_policy(&home);
    home
}

const CALLS: &str = concat!(
    "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"0\"}}}\n",
    "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"n\":1}}}\n",
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_file\",\"arguments\":{\"path\":\"/x\"}}}\n",
);

/// `fake_server: EXECUTED` lines of one `wrap` session in `mode`.
fn executed(root: &Path, mode: &str) -> (usize, String) {
    let server = fake_server();
    let out = run(
        &[
            "wrap",
            "--dir",
            root.to_str().unwrap(),
            "--name",
            "fake",
            "--mode",
            mode,
            "--no-report",
            "--",
            server.to_str().unwrap(),
        ],
        CALLS,
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let count = stderr
        .lines()
        .filter(|line| line.starts_with("fake_server: EXECUTED "))
        .count();
    (count, stderr)
}

fn receipt_lines(root: &Path) -> usize {
    let Ok(entries) = fs::read_dir(root.join("receipts")) else {
        return 0;
    };
    entries
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .map(|path| fs::read_to_string(path).unwrap().lines().count())
        .sum()
}

/// Everything the task requires of a refused layout at `root`: `wrap`
/// forwards no `tools/call` in either mode and signs nothing, and
/// `policy check`, `verify` and `init` exit non-zero naming `reason`.
fn assert_refused(root: &Path, reason: &str) {
    for mode in ["enforce", "observe"] {
        let (count, stderr) = executed(root, mode);
        assert_eq!(count, 0, "{mode}: a call ran\n{stderr}");
        assert!(
            stderr.contains(reason),
            "{mode}: {reason:?} not in\n{stderr}"
        );
    }
    assert_eq!(receipt_lines(root), 0, "a receipt was signed");
    let dir = root.to_str().unwrap();
    for command in [
        vec!["policy", "check", "--dir", dir],
        vec!["verify", "--dir", dir],
        vec!["init", "--dir", dir],
    ] {
        let out = run(&command, "");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !out.status.success(),
            "{command:?} exited 0 on a refused layout\n{text}"
        );
        assert!(
            text.contains(reason),
            "{command:?}: {reason:?} not in\n{text}"
        );
    }
}

/// Control: the same scratch home with its own real keys works, so the
/// refusals below come from the links and nothing else.
#[test]
fn a_home_with_its_own_keys_runs_the_calls() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let home = real_home(&root);
    write_allow_policy(&home);
    let (count, stderr) = executed(&root, "enforce");
    assert_eq!(count, 2, "{stderr}");
    assert_eq!(receipt_lines(&root), 2);
    let dir = root.to_str().unwrap();
    for command in [
        vec!["policy", "check", "--dir", dir],
        vec!["verify", "--dir", dir],
        vec!["init", "--dir", dir],
    ] {
        let out = run(&command, "");
        assert!(out.status.success(), "{command:?}: {out:?}");
    }
}

#[test]
fn keys_dir_as_a_symlink_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let real = real_home(&temp.path().join("real"));
    let root = temp.path().join("scratch");
    scratch_home(&root, &real);
    symlink(real.keys_dir(), root.join("keys")).unwrap();
    assert_refused(&root, "keys is a symlink");
    // The victim signed nothing.
    assert_eq!(receipt_lines(&real.root), 0);
}

#[test]
fn a_key_file_as_a_symlink_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let real = real_home(&temp.path().join("real"));
    let root = temp.path().join("scratch");
    let home = scratch_home(&root, &real);
    fs::create_dir(home.keys_dir()).unwrap();
    for key in real.key_files() {
        symlink(&key, home.keys_dir().join(key.file_name().unwrap())).unwrap();
    }
    assert_refused(&root, ".key is a symlink");
}

#[test]
fn a_key_file_as_a_hard_link_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let real = real_home(&temp.path().join("real"));
    let root = temp.path().join("scratch");
    let home = scratch_home(&root, &real);
    fs::create_dir(home.keys_dir()).unwrap();
    for key in real.key_files() {
        fs::hard_link(&key, home.keys_dir().join(key.file_name().unwrap())).unwrap();
    }
    assert_refused(&root, "has 2 hard links");
}

#[test]
fn a_parent_directory_as_a_symlink_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let real = real_home(&temp.path().join("real").join("home"));
    write_allow_policy(&real);
    // The same home, reached through a symlinked directory above it.
    let link = temp.path().join("link");
    symlink(temp.path().join("real"), &link).unwrap();
    let through_link = link.join("home");
    assert_refused(&through_link, "link is a symlink");
    // `init` of a new home below the symlink is refused too.
    let fresh = link.join("fresh");
    let out = run(&["init", "--dir", fresh.to_str().unwrap()], "");
    assert!(!out.status.success(), "{out:?}");
    assert!(!temp.path().join("real").join("fresh").exists());
    // The home itself, by its real path, still works.
    let (count, stderr) = executed(&real.root, "enforce");
    assert_eq!(count, 2, "{stderr}");
}
