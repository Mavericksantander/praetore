//! Session reports: `praetore-mcp wrap` writes `DIR/reports/session-*.json`
//! and `.pdf` when a session ends, and `praetore-mcp report` writes them
//! again. Uses the `fake_server` example, like `tests/wrap.rs`.

use praetore_mcp::{
    approvals::{self, HumanOutcome},
    receipts,
    report::STATEMENT,
    store::Home,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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

fn dir(home: &Home) -> &str {
    home.root.to_str().unwrap()
}

/// A home whose policy allows `echo`, asks for approval for `append` and
/// denies everything else (default deny), for the server name `fake`.
fn init_home() -> (tempfile::TempDir, Home) {
    let temp = tempfile::tempdir().unwrap();
    let home = Home::new(temp.path().join("home"));
    for args in [
        vec!["init"],
        vec![
            "policy",
            "allow",
            "--id",
            "allow-echo",
            "--server",
            "fake",
            "--tool",
            "echo",
        ],
        vec![
            "policy",
            "require-approval",
            "--id",
            "ask-append",
            "--server",
            "fake",
            "--tool",
            "append",
        ],
    ] {
        let mut args = args;
        args.extend(["--dir", dir(&home)]);
        let out = run(&args, "");
        assert!(out.status.success(), "{args:?}: {out:?}");
    }
    (temp, home)
}

fn call(id: i64, tool: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}
    })
}

fn input(calls: &[Value]) -> String {
    let mut lines = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ];
    lines.extend_from_slice(calls);
    lines.iter().map(|line| format!("{line}\n")).collect()
}

/// One enforce session; `extra` goes before `--`.
fn wrap(home: &Home, extra: &[&str], calls: &[Value]) -> Output {
    let server = fake_server();
    let mut args = vec![
        "wrap",
        "--dir",
        dir(home),
        "--name",
        "fake",
        "--mode",
        "enforce",
    ];
    args.extend_from_slice(extra);
    args.extend(["--", server.to_str().unwrap()]);
    run(&args, &input(calls))
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn reports_dir(home: &Home) -> PathBuf {
    home.root.join("reports")
}

/// The session JSON files, in name order.
fn json_reports(home: &Home) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(reports_dir(home))
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

fn document(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// The report whose session has `count` receipts.
fn report_with(home: &Home, count: usize) -> (PathBuf, Value) {
    json_reports(home)
        .into_iter()
        .map(|path| {
            let document = document(&path);
            (path, document)
        })
        .find(|(_, document)| document["receipts"].as_array().unwrap().len() == count)
        .unwrap_or_else(|| panic!("no report with {count} receipts"))
}

fn has(bytes: &[u8], needle: &str) -> bool {
    bytes
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

fn journal_lines(home: &Home) -> Vec<String> {
    receipts::read_journal(home)
        .unwrap()
        .into_iter()
        .map(|line| line.text)
        .collect()
}

#[test]
fn a_session_with_allow_deny_and_an_approval_writes_both_files() {
    let (temp, home) = init_home();
    let target = temp.path().join("notes.txt");
    let append = json!({"path": target.to_str().unwrap(), "text": "hi\n"});

    // First session: the call is held, and a person approves it.
    let held = wrap(&home, &[], &[call(10, "append", append.clone())]);
    assert!(held.status.success(), "{held:?}");
    let pending = approvals::list_pending(&home).unwrap();
    assert_eq!(pending.len(), 1);
    approvals::decide(&home, &pending[0].approval_id, HumanOutcome::Approve, None).unwrap();

    // Second session: ALLOW, DENY and the approved call.
    let out = wrap(
        &home,
        &[],
        &[
            call(20, "echo", json!({"text": "hello"})),
            call(21, "delete_file", json!({"path": "/tmp/x"})),
            call(22, "append", append),
        ],
    );
    assert!(out.status.success(), "{out:?}");
    assert!(stderr(&out).contains("session report:"), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(&target).unwrap(), "hi\n");

    let (json_path, document) = report_with(&home, 3);
    let pdf_path = json_path.with_extension("pdf");
    let name = json_path.file_name().unwrap().to_str().unwrap();
    assert!(
        name.starts_with("session-")
            && name.len() == "session-20260101T000000Z-0123abcd.json".len()
    );

    let header = &document["header"];
    assert_eq!(document["schema"], "praetore-mcp.session-report/1");
    assert_eq!(header["praetore_mcp_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(header["server"], "fake");
    assert_eq!(header["mode"], "enforce");
    let agent: Value = serde_json::from_str(&fs::read_to_string(home.agent()).unwrap()).unwrap();
    assert_eq!(header["agent"], agent["id"]);
    assert_eq!(header["seq"], json!({"first": 1, "last": 3, "count": 3}));
    assert_eq!(
        header["summary"],
        json!({
            "allow": 1, "deny": 1, "held": 0, "forwarded_with_approval": 1,
            "observe_would_ask": 0, "unreadable": 0,
            "approved": 1, "rejected": 0, "pending": 0, "expired": 0
        })
    );
    assert_eq!(header["statement"], STATEMENT);

    // Both heads are the ones `verify` reports for the journal at close.
    let verified = receipts::verify_journal(&home, None).unwrap();
    assert!(verified.failures.is_empty(), "{:?}", verified.failures);
    let head = verified.head.unwrap();
    assert_eq!(
        header["receipt_journal_head"],
        json!({"next_seq": head.seq, "head": head.prev.to_string()})
    );
    assert_eq!(
        header["approval_journal_head"],
        json!(verified.approval_head)
    );
    assert_eq!(header["verify"]["result"], "passed");
    assert_eq!(header["verify"]["journal_receipts"], 4);
    assert_eq!(header["verify"]["session_verified"], 3);

    // Who approved and when: the signed decision and the execution.
    let records = document["approvals"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["kind"], "decision");
    assert_eq!(records[0]["outcome"], "approve");
    assert!(records[0]["approver_key_id"].is_string());
    assert!(records[0]["decided_at"].is_string());
    assert_eq!(records[1]["kind"], "execution");

    let pdf = fs::read(&pdf_path).unwrap();
    assert!(pdf.starts_with(b"%PDF-"));
    for text in [
        "SESSION REPORT",
        "ALLOW",
        "DENY",
        "APPROVED",
        "CALL LOG",
        "HUMAN APPROVALS",
    ] {
        assert!(has(&pdf, text), "PDF has no {text:?}");
    }
    assert!(has(&pdf, STATEMENT));
    assert!(!has(&pdf, "VERIFY FAILED"));
    let sha256 = hex::encode(Sha256::digest(fs::read(&json_path).unwrap()));
    assert!(has(&pdf, &sha256), "PDF does not show the JSON SHA-256");
    assert!(has(&pdf, &head.prev.to_string()));
    assert!(has(&pdf, verified.approval_head.as_deref().unwrap()));
    // The embedded wordmark.
    assert!(has(&pdf, "/DCTDecode"));

    let lower = String::from_utf8_lossy(&pdf).to_lowercase();
    for claim in [
        "tamper-proof",
        "tamperproof",
        "no bypass",
        "certified",
        "guarantee",
    ] {
        assert!(!lower.contains(claim), "PDF claims {claim:?}");
    }
}

#[test]
fn the_json_receipts_are_the_journal_lines_byte_for_byte() {
    let (_temp, home) = init_home();
    let out = wrap(
        &home,
        &[],
        &[
            call(
                20,
                "echo",
                json!({"text": "caf\u{e9} \u{1f600}", "n": 1.50}),
            ),
            call(21, "delete_file", json!({"path": "/tmp/x"})),
            call(22, "echo", json!({"b": 2, "a": 1})),
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let reports = json_reports(&home);
    assert_eq!(reports.len(), 1);
    let text = fs::read_to_string(&reports[0]).unwrap();

    // Header line, one line per receipt, closing line.
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].ends_with("\"receipts\":["), "{}", lines[0]);
    assert_eq!(*lines.last().unwrap(), "]}");
    let copied: Vec<&str> = lines[1..lines.len() - 1]
        .iter()
        .map(|line| line.strip_suffix(',').unwrap_or(line))
        .collect();
    let journal = journal_lines(&home);
    assert_eq!(journal.len(), 3);
    assert_eq!(copied, journal);

    // The same bytes are in the daily file.
    let daily =
        fs::read(praetore_mcp::journal::journal_files(&home.receipts_dir()).unwrap()[0].clone())
            .unwrap();
    for line in &copied {
        assert!(has(&daily, &format!("{line}\n")));
    }
    // And the file as a whole is one JSON document with those receipts.
    let document: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(document["receipts"].as_array().unwrap().len(), 3);
    assert_eq!(document["receipts"][0]["seq"], 0);
}

#[test]
fn an_altered_journal_gives_a_pdf_that_says_verify_failed() {
    let (_temp, home) = init_home();
    let out = wrap(
        &home,
        &[],
        &[
            call(20, "echo", json!({"text": "one"})),
            call(21, "delete_file", json!({"path": "/tmp/x"})),
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let json_path = json_reports(&home).remove(0);
    let pdf_path = json_path.with_extension("pdf");
    assert!(!has(&fs::read(&pdf_path).unwrap(), "VERIFY FAILED"));
    let journal_before = journal_lines(&home);

    // Someone turns the DENY into an ALLOW-looking tool name.
    let daily = praetore_mcp::journal::journal_files(&home.receipts_dir()).unwrap()[0].clone();
    let altered = fs::read_to_string(&daily)
        .unwrap()
        .replace("\"tool\":\"delete_file\"", "\"tool\":\"read_file\"");
    fs::write(&daily, &altered).unwrap();

    let out = run(&["report", "--dir", dir(&home), "--last"], "");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("verify FAILED"));

    // Both files are written again, and the PDF says it on its cover.
    let pdf = fs::read(&pdf_path).unwrap();
    assert!(pdf.starts_with(b"%PDF-"));
    assert!(has(&pdf, "VERIFY FAILED"));
    assert!(has(&pdf, "INTEGRITY ALERT"));
    assert!(has(&pdf, STATEMENT));
    let document = document(&json_path);
    assert_eq!(document["header"]["verify"]["result"], "failed");
    assert_eq!(document["header"]["regenerated"], true);
    assert_eq!(document["header"]["verify"]["session_verified"], 1);
    assert!(
        !document["header"]["verify"]["failures"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // The altered line is copied as it now is in the journal.
    let text = fs::read_to_string(&json_path).unwrap();
    assert!(text.contains("\"tool\":\"read_file\""));
    assert!(has(&pdf, &hex::encode(Sha256::digest(text.as_bytes()))));

    // The report is a view: the journal was not touched by it.
    assert_eq!(fs::read_to_string(&daily).unwrap(), altered);
    assert_eq!(journal_before.len(), journal_lines(&home).len());
}

#[test]
fn a_removed_receipt_is_reported_as_missing() {
    let (_temp, home) = init_home();
    let out = wrap(
        &home,
        &[],
        &[
            call(20, "echo", json!({"text": "one"})),
            call(21, "echo", json!({"text": "two"})),
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let daily = praetore_mcp::journal::journal_files(&home.receipts_dir()).unwrap()[0].clone();
    let text = fs::read_to_string(&daily).unwrap();
    let first = text.lines().next().unwrap();
    fs::write(&daily, format!("{first}\n")).unwrap();

    let out = run(&["report", "--dir", dir(&home)], "");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let json_path = json_reports(&home).remove(0);
    let document = document(&json_path);
    assert_eq!(document["header"]["verify"]["result"], "failed");
    assert_eq!(
        document["header"]["verify"]["missing_evidence_ids"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(has(
        &fs::read(json_path.with_extension("pdf")).unwrap(),
        "VERIFY FAILED"
    ));
}

#[test]
fn no_report_and_the_config_switch_write_nothing() {
    let calls = [call(20, "echo", json!({"text": "one"}))];

    let (_temp, home) = init_home();
    let out = wrap(&home, &["--no-report"], &calls);
    assert!(out.status.success(), "{out:?}");
    assert!(!stderr(&out).contains("session report"), "{}", stderr(&out));
    assert!(!reports_dir(&home).exists());
    assert_eq!(journal_lines(&home).len(), 1);

    fs::write(home.root.join("config.toml"), "# quiet\nreport = false\n").unwrap();
    let out = wrap(&home, &[], &calls);
    assert!(out.status.success(), "{out:?}");
    assert!(!reports_dir(&home).exists());
    assert_eq!(journal_lines(&home).len(), 2);

    // Nothing to regenerate: no session wrote a report.
    let out = run(&["report", "--dir", dir(&home)], "");
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(stderr(&out).contains("no session report found"));

    // `report = true` (or no file) turns it back on; a bad line only warns.
    fs::write(home.root.join("config.toml"), "report = maybe\n").unwrap();
    let out = wrap(&home, &[], &calls);
    assert!(out.status.success(), "{out:?}");
    assert!(stderr(&out).contains("report must be true or false"));
    assert_eq!(json_reports(&home).len(), 1);
}

#[test]
fn a_session_without_receipts_writes_no_report() {
    let (_temp, home) = init_home();
    let out = wrap(&home, &[], &[]);
    assert!(out.status.success(), "{out:?}");
    assert!(!reports_dir(&home).exists());
}

#[test]
fn a_write_failure_in_reports_changes_neither_the_exit_code_nor_the_decisions() {
    let calls = [
        call(20, "echo", json!({"text": "one"})),
        call(21, "delete_file", json!({"path": "/tmp/x"})),
    ];
    let (_temp, plain) = init_home();
    let expected = wrap(&plain, &["--no-report"], &calls);

    let (_temp, home) = init_home();
    // `reports` cannot be created: a file is in its place.
    fs::write(reports_dir(&home), "not a directory").unwrap();
    let out = wrap(&home, &[], &calls);

    assert_eq!(out.status.code(), expected.status.code());
    assert_eq!(out.status.code(), Some(0));
    assert!(
        stderr(&out).contains("praetore-mcp: session report not written:"),
        "{}",
        stderr(&out)
    );
    // Same replies to the client.
    let replies = |out: &Output| -> Vec<(i64, Value)> {
        // Blocked replies and server replies are written by two threads,
        // so their order is not fixed: compare them by id.
        let mut replies: Vec<(i64, Value)> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|line| {
                let reply: Value = serde_json::from_str(line).unwrap();
                (
                    reply["id"].as_i64().unwrap(),
                    json!([reply["result"]["isError"], reply["error"]]),
                )
            })
            .collect();
        replies.sort_by_key(|(id, _)| *id);
        replies
    };
    assert_eq!(replies(&out), replies(&expected));
    assert!(stderr(&out).contains("fake_server: EXECUTED echo"));
    assert!(!stderr(&out).contains("fake_server: EXECUTED delete_file"));
    assert_eq!(journal_lines(&home).len(), 2);
    assert!(
        receipts::verify_journal(&home, None)
            .unwrap()
            .failures
            .is_empty()
    );
    assert_eq!(
        fs::read_to_string(reports_dir(&home)).unwrap(),
        "not a directory"
    );
}

#[test]
fn report_regenerates_a_session_by_id_and_rejects_unknown_ones() {
    let (_temp, home) = init_home();
    for text in ["one", "two"] {
        let out = wrap(&home, &[], &[call(20, "echo", json!({"text": text}))]);
        assert!(out.status.success(), "{out:?}");
    }
    let reports = json_reports(&home);
    assert_eq!(reports.len(), 2);
    let first = document(&reports[0]);
    let id = first["header"]["session_id"].as_str().unwrap();
    let pdf = reports[0].with_extension("pdf");
    fs::remove_file(&pdf).unwrap();

    let out = run(&["report", "--dir", dir(&home), "--session", id], "");
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(pdf.exists());
    let again = document(&reports[0]);
    assert_eq!(again["receipts"], first["receipts"]);
    assert_eq!(again["header"]["regenerated"], true);
    // The heads recorded at close are kept; verify sees the journal as it is.
    assert_eq!(
        again["header"]["receipt_journal_head"],
        first["header"]["receipt_journal_head"]
    );
    assert_eq!(again["header"]["started_at"], first["header"]["started_at"]);
    assert_eq!(again["header"]["verify"]["journal_receipts"], 2);
    assert_eq!(json_reports(&home).len(), 2);

    for (args, message) in [
        (vec!["--session", "00000000"], "no session report found"),
        (vec!["--session", "../../etc"], "--session must be"),
        (vec!["--session", id, "--last"], "cannot be used together"),
    ] {
        let mut full = vec!["report", "--dir", dir(&home)];
        full.extend(args);
        let out = run(&full, "");
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        assert!(stderr(&out).contains(message), "{}", stderr(&out));
    }
}

/// SIGTERM while the client is still connected: the session ends in order
/// and its report is written.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn sigterm_and_sigint_still_write_the_report() {
    use std::io::{BufRead, BufReader};

    for signal in [libc::SIGTERM, libc::SIGINT] {
        let (_temp, home) = init_home();
        let server = fake_server();
        let mut child = Command::new(bin())
            .args([
                "wrap",
                "--dir",
                dir(&home),
                "--name",
                "fake",
                "--mode",
                "enforce",
                "--",
            ])
            .arg(&server)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin
            .write_all(input(&[call(20, "echo", json!({"text": "one"}))]).as_bytes())
            .unwrap();
        stdin.flush().unwrap();
        // Wait for the reply to the call, with stdin still open.
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(
                stdout.read_line(&mut line).unwrap(),
                0,
                "server closed early"
            );
            if serde_json::from_str::<Value>(&line).unwrap()["id"] == 20 {
                break;
            }
        }
        // SAFETY: `kill` takes no pointers; the pid is this test's child.
        assert_eq!(unsafe { libc::kill(child.id() as libc::pid_t, signal) }, 0);
        let out = child.wait_with_output().unwrap();
        drop(stdin);
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("session report:"),
            "signal {signal}: {out:?}"
        );
        let reports = json_reports(&home);
        assert_eq!(reports.len(), 1, "signal {signal}");
        assert!(reports[0].with_extension("pdf").exists());
        assert_eq!(
            document(&reports[0])["header"]["verify"]["result"],
            "passed"
        );
    }
}
