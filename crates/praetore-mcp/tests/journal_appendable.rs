//! `verify` fails when `wrap` could not append the next receipt.
//!
//! `wrap` finds where the next receipt goes with `journal::next_entry`.
//! When that fails (a blank line at the end of the daily file, a
//! whitespace-only later `*.jsonl` file, a symlink in place of `receipts/`
//! or of the daily file), every call is refused, in both modes, until the
//! journal is repaired. Before this check, `verify` with both heads said OK
//! on such a home: the chain was intact and the head unchanged, while no call
//! could be recorded. Now `verify` runs the same function and reports FAIL.
//! A daily file that exists but cannot be opened for append is a WARNING:
//! permissions can change before the next call. `verify` sees either state
//! only while the journal stays in it; once repaired, it says OK again.

use praetore_mcp::store::Home;
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

fn run(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(bin())
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

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A home with `echo` allowed for the server `fake`.
fn init_home() -> (tempfile::TempDir, Home) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let dir = root.to_str().unwrap();
    let out = run(&["init", "--dir", dir], "");
    assert!(out.status.success(), "{out:?}");
    let out = run(
        &[
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
        ],
        "",
    );
    assert!(out.status.success(), "{out:?}");
    (temp, Home::new(root))
}

/// One observe session calling `echo` once; returns the server's stderr.
fn observe_echo(home: &Home, id: u32) -> String {
    let stdin = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"t\",\"version\":\"0\"}}}}}}\n{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"echo\",\"arguments\":{{\"n\":{id}}}}}}}\n"
    );
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
            "--no-report",
            "--",
            server.to_str().unwrap(),
        ],
        &stdin,
    );
    assert!(out.status.success(), "{out:?}");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn verify(home: &Home, extra: &[&str]) -> Output {
    let mut args = vec!["verify", "--dir", home.root.to_str().unwrap()];
    args.extend_from_slice(extra);
    run(&args, "")
}

/// The receipts head `verify` prints.
fn head_of(home: &Home) -> String {
    let text = stdout(&verify(home, &[]));
    let line = text
        .lines()
        .find(|line| line.starts_with("journal head: "))
        .expect("verify prints the journal head");
    let at = line.find(" head ").unwrap() + " head ".len();
    line[at..at + 64].to_owned()
}

fn anchored(home: &Home, head: &str) -> Output {
    verify(
        home,
        &["--expected-head", head, "--expected-approval-head", "none"],
    )
}

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

/// A seeded home whose saved head verifies OK with both anchors.
fn seeded() -> (tempfile::TempDir, Home, String) {
    let (temp, home) = init_home();
    let stderr = observe_echo(&home, 1);
    assert!(stderr.contains("fake_server: EXECUTED echo"), "{stderr}");
    let head = head_of(&home);
    let out = anchored(&home, &head);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(stdout(&out).starts_with("OK "), "{}", stdout(&out));
    (temp, home, head)
}

/// The state `wrap` refuses fails `verify`, with and without the heads,
/// naming the writer's error; and an observe call on that home is refused,
/// not run (the head did not move): every call is refused, in both modes,
/// until the journal is repaired.
fn assert_fails_as_unappendable(home: &Home, head: &str, cause: &str) {
    let stderr = observe_echo(home, 2);
    assert!(
        stderr.contains("could not be written")
            && stderr.contains("REFUSED (observe")
            && !stderr.contains("fake_server: EXECUTED echo"),
        "every call is refused, in both modes, until the journal is repaired: {stderr}"
    );
    for out in [anchored(home, head), verify(home, &[])] {
        let text = stdout(&out);
        assert_eq!(out.status.code(), Some(1), "{text}");
        assert!(text.starts_with("FAIL "), "{text}");
        assert!(
            text.contains("FAIL journal: wrap cannot append the next receipt"),
            "{text}"
        );
        assert!(text.contains(cause), "{text}");
    }
}

#[test]
fn a_blank_line_at_the_end_of_the_daily_file_fails_verify() {
    let (_temp, home, head) = seeded();
    let file = daily_file(&home);
    let mut handle = fs::OpenOptions::new().append(true).open(&file).unwrap();
    handle.write_all(b"\n").unwrap();
    assert_fails_as_unappendable(&home, &head, "is unreadable");
}

#[test]
fn a_whitespace_only_later_daily_file_fails_verify() {
    let (_temp, home, head) = seeded();
    fs::write(home.receipts_dir().join("9999-12-31.jsonl"), " \n").unwrap();
    assert_fails_as_unappendable(&home, &head, "9999-12-31.jsonl is unreadable");
}

#[cfg(unix)]
#[test]
fn a_symlink_in_place_of_the_receipts_dir_fails_verify() {
    let (_temp, home, head) = seeded();
    let real = home.root.join("receipts.real");
    fs::rename(home.receipts_dir(), &real).unwrap();
    std::os::unix::fs::symlink("receipts.real", home.receipts_dir()).unwrap();
    assert_fails_as_unappendable(&home, &head, "is a symlink; refusing to follow it");
}

#[cfg(unix)]
#[test]
fn a_symlink_in_place_of_the_daily_file_fails_verify() {
    let (_temp, home, head) = seeded();
    let file = daily_file(&home);
    let real = file.with_extension("jsonl.real");
    fs::rename(&file, &real).unwrap();
    std::os::unix::fs::symlink(real.file_name().unwrap(), &file).unwrap();
    assert_fails_as_unappendable(&home, &head, "is a symlink; refusing to append");
}

/// A daily file that exists but does not open for append is a warning, not
/// a failure: permissions can change before the next call. Meanwhile the
/// call is refused, in both modes, so `verify` says so.
#[cfg(unix)]
#[test]
fn a_read_only_daily_file_is_a_warning() {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: `geteuid` takes no arguments and reads process state.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root can append to a read-only file");
        return;
    }
    let (_temp, home, head) = seeded();
    let file = daily_file(&home);
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    let stderr = observe_echo(&home, 2);
    assert!(
        stderr.contains("could not be written")
            && stderr.contains("REFUSED (observe")
            && !stderr.contains("fake_server: EXECUTED echo"),
        "{stderr}"
    );
    let out = anchored(&home, &head);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.starts_with("OK "), "{text}");
    assert!(
        text.contains("WARNING journal: the next receipt cannot be appended right now")
            && text.contains("cannot open")
            && text.contains("for append"),
        "{text}"
    );
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let out = anchored(&home, &head);
    assert!(
        !stdout(&out).contains("WARNING journal"),
        "{}",
        stdout(&out)
    );
}

/// A home with no receipts yet, and one whose last daily file is empty (0
/// bytes), both verify: the writer appends to them.
#[test]
fn an_empty_home_and_an_empty_daily_file_verify() {
    let (_temp, home) = init_home();
    let out = verify(
        &home,
        &[
            "--expected-head",
            "none",
            "--expected-approval-head",
            "none",
        ],
    );
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(
        !text.contains("WARNING journal") && !text.contains("FAIL journal"),
        "{text}"
    );
    let (_temp, home, head) = seeded();
    fs::write(home.receipts_dir().join("9999-12-31.jsonl"), "").unwrap();
    let out = anchored(&home, &head);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(
        !text.contains("WARNING journal") && !text.contains("FAIL journal"),
        "{text}"
    );
    // And the writer does append after it.
    let stderr = observe_echo(&home, 2);
    assert!(
        !stderr.contains("could not be written") && stderr.contains("fake_server: EXECUTED echo"),
        "{stderr}"
    );
}
