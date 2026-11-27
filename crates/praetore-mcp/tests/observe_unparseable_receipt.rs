//! Observe and client lines the proxy cannot parse.
//!
//! A line with a duplicate object key is unparseable for the proxy, but a
//! lenient server (here the `fake_server` example, `serde_json`, last key
//! wins) still reads it as a `tools/call` and runs it. This test pins the
//! property observe is meant to keep: a `tools/call` the server runs has a
//! receipt in the journal, or it does not run. It does not choose how
//! (refuse the line, or write a receipt for it first); either one passes.
//!
//! The test does not approve or reject anything: it only runs `init`,
//! `wrap --mode observe` and reads the receipts journal.

use praetore_mcp::{receipts, store::Home};
use serde_json::json;
use std::{
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
        "{} missing: build the examples (`cargo build -p praetore-mcp --examples`)",
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

/// Runs one observe session with `call` (a raw line) after the handshake;
/// returns how many times the server ran `delete_file` and the receipts
/// journal length afterwards.
fn observe_once(home: &Home, call: &str) -> (usize, usize, String) {
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}});
    let initialized = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
    let input = format!("{init}\n{initialized}\n{call}\n");
    let server = fake_server();
    let out = run(
        &[
            "wrap",
            "--dir",
            home.root.to_str().unwrap(),
            "--name",
            "fake",
            "--mode",
            "observe",
            "--",
            server.to_str().unwrap(),
        ],
        &input,
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let executed = stderr.matches("fake_server: EXECUTED delete_file").count();
    let receipts = receipts::read_journal(home).unwrap().len();
    (executed, receipts, stderr)
}

#[test]
fn observe_never_runs_an_unparseable_tools_call_without_a_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let home = Home::new(temp.path().join("home"));
    let out = run(&["init", "--dir", home.root.to_str().unwrap()], "");
    assert!(out.status.success(), "{out:?}");

    // Control: the same call, parseable, runs in observe with its receipt.
    let (executed, receipts, stderr) = observe_once(
        &home,
        r#"{"jsonrpc":"2.0","id":"p","method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/a"}}}"#,
    );
    assert_eq!((executed, receipts), (1, 1), "{stderr}");

    // A duplicate key: unparseable for the proxy, a tools/call for the server.
    let (executed, after, stderr) = observe_once(
        &home,
        r#"{"jsonrpc":"2.0","id":"u","method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/a","path":"/b"}}}"#,
    );
    assert!(
        executed == 0 || after > receipts,
        "observe ran a tools/call that left no receipt (executed {executed}, receipts {receipts} -> {after}):\n{stderr}"
    );
}
