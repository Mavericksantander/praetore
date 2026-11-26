//! Observe refuses a call it cannot record.
//!
//! Observe mode records decisions. A `tools/call` whose receipt the journal
//! cannot take was forwarded anyway, with a stderr warning, and `verify`
//! with the heads kept earlier still said OK: the journal it reads was
//! intact, only shorter than the calls that ran. Each test here puts the
//! journal in a state that stops the next append while every read of it
//! still works, runs an observe session, and checks that the call did not
//! run and that the client was told why. The seeded head still verifies:
//! these tests pin what the proxy does, not what `verify` sees.

use praetore_mcp::store::Home;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
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

fn run(program: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(program)
        .args(args)
        .env_remove("PRAETORE_MCP_APPROVAL_TTL_SECONDS")
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

fn cli(args: &[&str]) -> Output {
    run(Path::new(bin()), args, "")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A home where `echo` is allowed; everything else is default deny.
fn init_home() -> (tempfile::TempDir, Home) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let dir = root.to_str().unwrap();
    let out = cli(&["init", "--dir", dir]);
    assert!(out.status.success(), "{out:?}");
    let out = cli(&[
        "policy",
        "allow",
        "--dir",
        dir,
        "--id",
        "allow-echo",
        "--server",
        "fake",
        "--tool",
        "echo",
    ]);
    assert!(out.status.success(), "{out:?}");
    (temp, Home::new(root))
}

fn call(id: i64, tool: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}
    })
}

fn session(calls: &[Value]) -> String {
    let mut lines = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ];
    lines.extend_from_slice(calls);
    lines.iter().map(|line| format!("{line}\n")).collect()
}

/// One observe session through `wrap`: the client replies by id, and the
/// server's stderr, where `fake_server` logs `EXECUTED <tool>`.
fn wrap_observe(home: &Home, calls: &[Value]) -> (Vec<Value>, String) {
    let server = fake_server();
    let out = run(
        Path::new(bin()),
        &[
            "wrap",
            "--dir",
            home.root.to_str().unwrap(),
            "--name",
            "fake",
            "--mode",
            "observe",
            "--no-report",
            "--",
            server.to_str().unwrap(),
        ],
        &session(calls),
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "{stderr}");
    let replies = stdout(&out)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (replies, stderr)
}

fn by_id(replies: &[Value], id: i64) -> &Value {
    replies
        .iter()
        .find(|reply| reply["id"] == json!(id))
        .unwrap_or_else(|| panic!("no reply with id {id}: {replies:?}"))
}

fn executed(stderr: &str, tool: &str) -> usize {
    stderr
        .lines()
        .filter(|line| *line == format!("fake_server: EXECUTED {tool}"))
        .count()
}

/// The daily receipts file of a home with one day of receipts.
fn daily_file(home: &Home) -> PathBuf {
    let mut files: Vec<PathBuf> = fs::read_dir(home.receipts_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    files.sort();
    assert_eq!(files.len(), 1, "{files:?}");
    files.remove(0)
}

fn printed_head(out: &Output) -> String {
    let text = stdout(out);
    let at = text.find(" head ").expect("verify prints the journal head") + " head ".len();
    let head = &text[at..at + 64];
    assert!(head.chars().all(|c| c.is_ascii_hexdigit()), "{text}");
    head.to_owned()
}

/// One allowed call in observe, so the journal has a receipt and a head.
fn seed(home: &Home) -> String {
    let (replies, stderr) = wrap_observe(home, &[call(2, "echo", json!({"seed": 1}))]);
    assert_eq!(executed(&stderr, "echo"), 1, "{stderr}");
    assert_eq!(by_id(&replies, 2)["result"]["isError"], false);
    let out = cli(&["verify", "--dir", home.root.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3), "{}", stdout(&out));
    printed_head(&out)
}

/// `verify` against the head kept after the seed, for a home with no
/// approval journal.
fn verify_anchored(home: &Home, head: &str) -> Output {
    cli(&[
        "verify",
        "--dir",
        home.root.to_str().unwrap(),
        "--expected-head",
        head,
        "--expected-approval-head",
        "none",
    ])
}

/// After `damage` put the journal in a state that stops the next append:
/// the call is refused, not run, the client is told that no receipt could
/// be recorded, stderr says REFUSED in observe, and the journal still ends
/// at the seeded head.
fn observe_refuses_after(damage: impl FnOnce(&Home)) {
    let (_temp, home) = init_home();
    let head = seed(&home);
    damage(&home);

    let (replies, stderr) = wrap_observe(
        &home,
        &[
            call(3, "echo", json!({"after": "damage"})),
            call(4, "delete_file", json!({"path": "/etc/passwd"})),
        ],
    );
    assert_eq!(executed(&stderr, "echo"), 0, "forwarded: {stderr}");
    assert_eq!(executed(&stderr, "delete_file"), 0, "forwarded: {stderr}");
    for id in [3, 4] {
        let reply = by_id(&replies, id);
        assert_eq!(reply["result"]["isError"], true, "{reply}");
        let text = reply["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("could not record a receipt") && text.contains("Evidence id: "),
            "{text}"
        );
    }
    let refused: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("could not be written") && line.contains("REFUSED"))
        .collect();
    assert_eq!(refused.len(), 2, "{stderr}");
    assert!(
        refused.iter().all(|line| line.contains("(observe")),
        "{stderr}"
    );
    assert!(
        !stderr.contains("forwarded anyway"),
        "the old warning is back: {stderr}"
    );

    // The gap is closed at the proxy. The journal as read is still the one
    // the seed left, so verify against its head passes: that is what makes
    // forwarding without the receipt invisible, and why the proxy refuses.
    let out = verify_anchored(&home, &head);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
}

/// (a) One blank line after the last receipt. `verify` skips blank lines;
/// the writer reads the last line back and finds nothing to chain from.
#[test]
fn a_blank_last_line_refuses_calls_in_observe() {
    observe_refuses_after(|home| {
        let path = daily_file(home);
        let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(b"\n").unwrap();
    });
}

/// (b) `receipts/` moved aside and replaced by a symlink to it. Reads
/// follow the link; the writer refuses to follow it.
#[cfg(unix)]
#[test]
fn a_symlinked_receipts_dir_refuses_calls_in_observe() {
    observe_refuses_after(|home| {
        let dir = home.receipts_dir();
        let real = home.root.join("receipts.real");
        fs::rename(&dir, &real).unwrap();
        std::os::unix::fs::symlink("receipts.real", &dir).unwrap();
    });
}

/// (c) The daily file made read-only. Reads work; the append fails. Root
/// ignores file modes, so the case is skipped there.
#[cfg(unix)]
#[test]
fn a_read_only_daily_file_refuses_calls_in_observe() {
    // SAFETY: `geteuid` takes no arguments and reads process state.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: running as root, file modes are not enforced");
        return;
    }
    observe_refuses_after(|home| {
        use std::os::unix::fs::PermissionsExt;
        let path = daily_file(home);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    });
}
