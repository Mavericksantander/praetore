//! A symlink at `keys/` or at a key file is not a key. `wrap` refuses every
//! `tools/call`, and `policy check`, `verify` and `init` exit non-zero.

use praetore_mcp::{receipts, store::Home};
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
    assert!(path.exists(), "{}", path.display());
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

fn init_home() -> (tempfile::TempDir, Home) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let out = run(&["init", "--dir", root.to_str().unwrap()], "");
    assert!(
        out.status.success(),
        "stdout {}\nstderr {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (temp, Home::new(root))
}

/// Renames `path` to a sibling ending in `.real` and leaves a symlink behind.
fn replace_with_symlink(path: &Path) -> PathBuf {
    let real = path.with_file_name(format!(
        "{}.real",
        path.file_name().unwrap().to_str().unwrap()
    ));
    fs::rename(path, &real).unwrap();
    std::os::unix::fs::symlink(&real, path).unwrap();
    real
}

fn wrap_calls(home: &Home) -> (Vec<Value>, String, Output) {
    let server = fake_server();
    let lines = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo","arguments":{"n":1}}}),
        json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/tmp/x"}}}),
    ];
    let input: String = lines.iter().map(|line| format!("{line}\n")).collect();
    let out = run(
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
        &input,
    );
    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    let responses = stdout
        .lines()
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|error| panic!("bad line {line:?}: {error}"))
        })
        .collect();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (responses, stderr, out)
}

fn by_id(responses: &[Value], id: i64) -> &Value {
    responses
        .iter()
        .find(|response| response["id"] == id)
        .unwrap_or_else(|| panic!("no response for {id} in {responses:?}"))
}

fn assert_refused(home: &Home, label: &str) {
    let (responses, stderr, out) = wrap_calls(home);
    assert!(
        out.status.success(),
        "{label}: wrap exit {:?}\n{stderr}",
        out.status.code()
    );
    assert!(
        stderr.contains("symlink"),
        "{label}: stderr did not name the symlink\n{stderr}"
    );
    assert_eq!(
        by_id(&responses, 2)["result"]["tools"][0]["name"],
        "echo",
        "{label}: tools/list was not forwarded"
    );
    for id in [9, 10] {
        let refused = by_id(&responses, id);
        assert_eq!(refused["result"]["isError"], true, "{label}: {refused}");
        let text = refused["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("not ready"),
            "{label}: id {id} was not refused: {text}"
        );
    }
    assert!(!stderr.contains("EXECUTED"), "{label}: {stderr}");
    assert!(
        receipts::read_journal(home).unwrap().is_empty(),
        "{label}: a receipt was written"
    );

    let dir = home.root.to_str().unwrap();
    for args in [
        &["policy", "check", "--dir", dir][..],
        &["verify", "--dir", dir][..],
        &["init", "--dir", dir][..],
    ] {
        let out = run(args, "");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "{label}: {:?} exit {:?}\n{stdout}\n{stderr}",
            args,
            out.status.code()
        );
        let combined = format!("{stdout}\n{stderr}");
        assert!(
            combined.contains("symlink"),
            "{label}: {:?} did not name the symlink\n{combined}",
            args
        );
        assert!(
            !stdout.contains("already initialized"),
            "{label}: init treated the symlink as a home\n{stdout}"
        );
    }
}

#[cfg(unix)]
#[test]
fn keys_directory_symlink_refuses_wrap_and_the_other_commands() {
    let (_temp, home) = init_home();
    let issuer = fs::read(home.issuer_key()).unwrap();
    let real = replace_with_symlink(&home.keys_dir());
    assert_refused(&home, "keys directory");
    assert_eq!(fs::read(real.join("issuer.local-dev.key")).unwrap(), issuer);
}

#[cfg(unix)]
#[test]
fn key_file_symlink_refuses_wrap_and_the_other_commands() {
    let (_temp, home) = init_home();
    // The issuer key is not what `wrap` signs tool calls with. Refusing it
    // means every key file is opened, not only the agent and attester keys.
    let issuer = fs::read(home.issuer_key()).unwrap();
    let real = replace_with_symlink(&home.issuer_key());
    assert_refused(&home, "issuer key file");
    assert_eq!(fs::read(&real).unwrap(), issuer);
}
