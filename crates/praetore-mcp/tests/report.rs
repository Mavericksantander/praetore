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

/// The JSON files written at close (no `.regen-`), in name order.
fn json_reports(home: &Home) -> Vec<PathBuf> {
    all_json(home)
        .into_iter()
        .filter(|path| !name(path).contains(".regen-"))
        .collect()
}

/// The JSON files `report` wrote (`.regen-`), in name order.
fn regen_reports(home: &Home) -> Vec<PathBuf> {
    all_json(home)
        .into_iter()
        .filter(|path| name(path).contains(".regen-"))
        .collect()
}

fn name(path: &Path) -> &str {
    path.file_name().unwrap().to_str().unwrap()
}

fn sha256(path: &Path) -> String {
    hex::encode(Sha256::digest(fs::read(path).unwrap()))
}

fn all_json(home: &Home) -> Vec<PathBuf> {
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
    // The crate version, plus `-dev+<commit>` (or `-dev`) when this is not
    // a release build.
    let version = header["praetore_mcp_version"].as_str().unwrap();
    assert_eq!(version, praetore_mcp::report::BUILD_VERSION);
    let rest = version.strip_prefix(env!("CARGO_PKG_VERSION")).unwrap();
    assert!(
        rest.is_empty()
            || rest == "-dev"
            || rest.strip_prefix("-dev+").is_some_and(
                |commit| commit.len() >= 7 && commit.bytes().all(|b| b.is_ascii_hexdigit())
            ),
        "{version}"
    );
    assert!(
        has(&fs::read(&pdf_path).unwrap(), version),
        "PDF has no {version}"
    );
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
    // The command to check both heads later, as printed, with DIR for the
    // home: it passes on the journal as it is at close.
    let command = header["verify_command"].as_str().unwrap();
    assert_eq!(
        command,
        format!(
            "praetore-mcp verify --dir DIR --expected-head {} --expected-approval-head {}",
            head.prev,
            verified.approval_head.as_deref().unwrap()
        )
    );
    let args: Vec<&str> = command.split(' ').skip(1).collect();
    let home_dir = home.root.to_str().unwrap();
    let args: Vec<&str> = args
        .iter()
        .map(|arg| if *arg == "DIR" { home_dir } else { arg })
        .collect();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_praetore-mcp"))
        .args(&args)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(header["verify"]["result"], "passed");
    assert_eq!(header["verify"]["journal_receipts"], 4);
    assert_eq!(header["verify"]["session_verified"], 3);

    // Who approved and when: the signed decision and the execution, as
    // the journal lines themselves.
    let records = document["approvals"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["record"]["kind"], "decision");
    assert_eq!(records[0]["record"]["outcome"], "approve");
    assert!(records[0]["record"]["approver_key_id"].is_string());
    assert!(records[0]["record"]["decided_at"].is_string());
    assert_eq!(records[1]["record"]["kind"], "execution");
    assert!(header["approval_journal_error"].is_null());
    let approval_journal =
        fs::read_to_string(home.root.join("approvals").join("journal.jsonl")).unwrap();
    let text = fs::read_to_string(&json_path).unwrap();
    let start = text.find("\"approvals\":[").unwrap() + "\"approvals\":[".len();
    let copied = &text[start..start + text[start..].find("],\"receipts\":[").unwrap()];
    let journal_approvals: Vec<&str> = approval_journal
        .lines()
        .filter(|line| copied.contains(line))
        .collect();
    assert_eq!(journal_approvals.len(), 2, "{copied}");
    assert_eq!(copied, journal_approvals.join(","));

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
fn report_never_replaces_the_report_written_at_close() {
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
    let (json_sha, pdf_sha) = (sha256(&json_path), sha256(&pdf_path));
    let close_text = fs::read_to_string(&json_path).unwrap();
    let original = close_text
        .lines()
        .find(|line| line.contains("\"tool\":\"delete_file\""))
        .unwrap()
        .to_owned();
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

    // The report written at close is untouched, with its original line.
    assert_eq!(sha256(&json_path), json_sha);
    assert_eq!(sha256(&pdf_path), pdf_sha);
    assert!(fs::read_to_string(&json_path).unwrap().contains(&original));
    assert_eq!(json_reports(&home), vec![json_path.clone()]);

    // A new pair sits next to it and says verify failed.
    let regen = regen_reports(&home);
    assert_eq!(regen.len(), 1, "{regen:?}");
    let regen_json = &regen[0];
    let stem = name(&json_path).strip_suffix(".json").unwrap();
    let regen_name = name(regen_json);
    let stamp = regen_name
        .strip_prefix(&format!("{stem}.regen-"))
        .and_then(|rest| rest.strip_suffix(".json"))
        .unwrap_or_else(|| panic!("{regen_name}"));
    assert_eq!(stamp.len(), "20260101T000000Z".len(), "{stamp}");
    assert!(
        stamp.ends_with('Z') && stamp.as_bytes()[8] == b'T',
        "{stamp}"
    );
    let pdf = fs::read(regen_json.with_extension("pdf")).unwrap();
    assert!(pdf.starts_with(b"%PDF-"));
    assert!(has(&pdf, "VERIFY FAILED"));
    assert!(has(&pdf, "INTEGRITY ALERT"));
    assert!(has(&pdf, "THIS SESSION"));
    assert!(has(&pdf, STATEMENT));
    assert!(has(&pdf, name(&json_path)));
    let document = document(regen_json);
    assert_eq!(document["header"]["verify"]["result"], "failed");
    assert_eq!(document["header"]["regenerated"], true);
    assert_eq!(document["header"]["regenerated_from"], name(&json_path));
    assert_eq!(document["header"]["verify"]["session_verified"], 1);
    assert!(
        !document["header"]["verify"]["failures"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // The altered line is copied as it now is in the journal.
    let text = fs::read_to_string(regen_json).unwrap();
    assert!(text.contains("\"tool\":\"read_file\""));
    assert!(has(&pdf, &hex::encode(Sha256::digest(text.as_bytes()))));

    // `--last` still means the session's close report: a second run writes
    // another pair (a second later) and still leaves the first ones alone.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let out = run(&["report", "--dir", dir(&home), "--last"], "");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(regen_reports(&home).len(), 2);
    assert_eq!(sha256(&json_path), json_sha);
    assert_eq!(sha256(&pdf_path), pdf_sha);

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
    let json_path = regen_reports(&home).remove(0);
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
    // A missing close PDF is not written again: the new pair is beside it.
    assert!(!pdf.exists());
    let regen = regen_reports(&home);
    assert_eq!(regen.len(), 1);
    let stem = name(&reports[0]).strip_suffix(".json").unwrap();
    assert!(name(&regen[0]).starts_with(&format!("{stem}.regen-")));
    assert!(regen[0].with_extension("pdf").exists());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(name(&regen[0])), "{stdout}");
    let again = document(&regen[0]);
    assert_eq!(again["receipts"], first["receipts"]);
    assert_eq!(again["header"]["regenerated"], true);
    assert_eq!(again["header"]["regenerated_from"], name(&reports[0]));
    assert_eq!(document(&reports[0]), first);
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

/// `wrap` for the server `server` (program and arguments), with piped
/// stdio. SIGINT and SIGTERM are set back to their default action before
/// the exec: `wrap` keeps an ignored signal ignored, and `cargo test` may
/// have been started with one ignored.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn spawn_wrap(home: &Home, extra: &[&str], server: &[&str]) -> std::process::Child {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(bin());
    command
        .args([
            "wrap",
            "--dir",
            dir(home),
            "--name",
            "fake",
            "--mode",
            "enforce",
        ])
        .args(extra)
        .arg("--")
        .args(server)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the closure runs in the child between fork and exec and only
    // calls `signal`, `sigemptyset`, `sigaddset` and `sigprocmask`, which
    // are async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&raw mut set);
            for signal in [libc::SIGINT, libc::SIGTERM] {
                libc::signal(signal, libc::SIG_DFL);
                libc::sigaddset(&raw mut set, signal);
            }
            libc::sigprocmask(libc::SIG_UNBLOCK, &raw const set, std::ptr::null_mut());
            Ok(())
        });
    }
    command.spawn().unwrap()
}

/// Waits for `child` at most `limit`; past it, kills it and fails.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn wait_within(
    child: &mut std::process::Child,
    limit: std::time::Duration,
    what: &str,
) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what}: wrap still running after {limit:?}");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Reads all of `child`'s stderr on a thread, so it never fills.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stderr_text(child: &mut std::process::Child) -> std::thread::JoinHandle<String> {
    let mut stderr = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = std::io::Read::read_to_string(&mut stderr, &mut text);
        text
    })
}

/// The pid of `wrap`'s one child process, its server.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn server_pid(child: &std::process::Child) -> i32 {
    let pgrep = Command::new("pgrep")
        .args(["-P", &child.id().to_string()])
        .output()
        .unwrap();
    let pids: Vec<i32> = String::from_utf8_lossy(&pgrep.stdout)
        .split_whitespace()
        .map(|pid| pid.parse().unwrap())
        .collect();
    assert_eq!(pids.len(), 1, "server pid: {pgrep:?}");
    pids[0]
}

/// Sends one `echo` call and waits until its receipt is in the journal,
/// so `wrap` is past installing its handlers. Returns stdin, still open.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn one_receipt(home: &Home, child: &mut std::process::Child) -> std::process::ChildStdin {
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(input(&[call(20, "echo", json!({"text": "one"}))]).as_bytes())
        .unwrap();
    stdin.flush().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while receipts::read_journal(home).map_or(0, |lines| lines.len()) == 0 {
        assert!(std::time::Instant::now() < deadline, "no receipt");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    stdin
}

/// A `wrap` child of the fake server with one answered call and stdin
/// still open, its stderr reader, and the pid of its server.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn wrap_in_session(
    home: &Home,
    extra: &[&str],
) -> (
    std::process::Child,
    std::process::ChildStdin,
    std::thread::JoinHandle<String>,
    i32,
) {
    use std::io::{BufRead, BufReader};
    let server = fake_server();
    let mut child = spawn_wrap(home, extra, &[server.to_str().unwrap()]);
    let err = stderr_text(&mut child);
    let stdin = one_receipt(home, &mut child);
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
    // Keep draining stdout so wrap never blocks on a full pipe.
    std::thread::spawn(move || std::io::copy(&mut stdout, &mut std::io::sink()));
    let server = server_pid(&child);
    (child, stdin, err, server)
}

/// `kill(pid, 0)` fails with ESRCH within 10 s.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_gone(pid: i32, what: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        // SAFETY: `kill` with signal 0 sends nothing and takes no pointers.
        let result = unsafe { libc::kill(pid, 0) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        if result == -1 && errno == Some(libc::ESRCH) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{what}: server {pid} still exists ({result}, {errno:?})"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// SIGTERM or SIGINT while the client is still connected: wrap ends by
/// that same signal, its server is gone and, unless `--no-report`, the
/// report was written first.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn sigterm_and_sigint_end_wrap_by_the_signal_with_and_without_a_report() {
    use std::os::unix::process::ExitStatusExt;

    for signal in [libc::SIGTERM, libc::SIGINT] {
        for report in [true, false] {
            let what = format!("signal {signal}, report {report}");
            let (_temp, home) = init_home();
            let extra: &[&str] = if report { &[] } else { &["--no-report"] };
            let (mut child, stdin, err, server) = wrap_in_session(&home, extra);
            // SAFETY: `kill` takes no pointers; the pid is this test's child.
            assert_eq!(unsafe { libc::kill(child.id() as libc::pid_t, signal) }, 0);
            let status = wait_within(&mut child, std::time::Duration::from_secs(10), &what);
            drop(stdin);
            assert_eq!(status.signal(), Some(signal), "{what}: {status:?}");
            assert_eq!(status.code(), None, "{what}");
            assert_gone(server, &what);
            let err = err.join().unwrap();
            let reports = json_reports(&home);
            if report {
                assert!(err.contains("session report:"), "{what}: {err}");
                assert_eq!(reports.len(), 1, "{what}");
                assert!(reports[0].with_extension("pdf").exists(), "{what}");
                assert_eq!(
                    document(&reports[0])["header"]["verify"]["result"],
                    "passed",
                    "{what}"
                );
            } else {
                assert!(!err.contains("session report"), "{what}: {err}");
                assert!(!reports_dir(&home).exists(), "{what}");
            }
            assert_eq!(journal_lines(&home).len(), 1, "{what}");
        }
    }
}

/// A second signal while the first is being handled ends wrap at once by
/// that signal, without the report.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_second_signal_ends_wrap_without_the_report() {
    use std::os::unix::process::ExitStatusExt;

    for signal in [libc::SIGTERM, libc::SIGINT] {
        let what = format!("signal {signal}, second");
        let (_temp, home) = init_home();
        let (mut child, stdin, _err, server) = wrap_in_session(&home, &[]);
        let pid = child.id() as libc::pid_t;
        // SAFETY: `kill` takes no pointers; the pid is this test's child.
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
        let status = wait_within(&mut child, std::time::Duration::from_secs(10), &what);
        drop(stdin);
        assert_eq!(status.signal(), Some(signal), "{what}: {status:?}");
        assert!(!reports_dir(&home).exists(), "{what}");
        // The server loses its stdin with wrap and exits too.
        assert_gone(server, &what);
    }
}

/// A server that closes its stdout and keeps running: a SIGTERM to wrap
/// while it waits for that server still ends the server and then wrap,
/// by SIGTERM, after the report.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_signal_after_the_server_closed_stdout_still_ends_wrap_by_it() {
    use std::os::unix::process::ExitStatusExt;

    let (_temp, home) = init_home();
    let mut child = spawn_wrap(&home, &[], &["/bin/sh", "-c", "exec >&-; exec sleep 6"]);
    let err = stderr_text(&mut child);
    let stdin = one_receipt(&home, &mut child);
    let server = server_pid(&child);
    let sent = std::time::Instant::now();
    // SAFETY: `kill` takes no pointers; the pid is this test's child.
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let status = wait_within(
        &mut child,
        std::time::Duration::from_secs(3),
        "closed stdout",
    );
    let elapsed = sent.elapsed();
    drop(stdin);
    let err = err.join().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?} {err}");
    assert!(elapsed < std::time::Duration::from_secs(3), "{elapsed:?}");
    assert_gone(server, "closed stdout");
    assert!(err.contains("session report:"), "{err}");
    let reports = json_reports(&home);
    assert_eq!(reports.len(), 1);
    assert_eq!(
        document(&reports[0])["header"]["verify"]["result"],
        "passed"
    );
}

/// With `--no-report` no handler is installed: SIGTERM ends wrap at once,
/// with no grace period, even when the server ignores SIGTERM.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn without_the_report_sigterm_ends_wrap_at_once() {
    use std::os::unix::process::ExitStatusExt;

    let (_temp, home) = init_home();
    let mut child = spawn_wrap(
        &home,
        &["--no-report"],
        &["/bin/sh", "-c", "trap '' TERM INT; exec sleep 30"],
    );
    let _err = stderr_text(&mut child);
    let stdin = one_receipt(&home, &mut child);
    let server = server_pid(&child);
    let sent = std::time::Instant::now();
    // SAFETY: `kill` takes no pointers; the pid is this test's child.
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let status = wait_within(&mut child, std::time::Duration::from_secs(5), "no report");
    let elapsed = sent.elapsed();
    drop(stdin);
    // The server ignores SIGTERM and outlives wrap: end it here.
    // SAFETY: `kill` takes no pointers; the pid is this test's grandchild.
    unsafe { libc::kill(server, libc::SIGKILL) };
    assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
    assert!(
        elapsed < std::time::Duration::from_millis(200),
        "wrap took {elapsed:?}"
    );
    assert!(!reports_dir(&home).exists());
}

/// SIGTERM while `wrap` writes the report (its server already gone, the
/// `.json` not yet published): the report is finished and `wrap` then ends
/// by SIGTERM. A first session of `seed` receipts journaled with
/// `--no-report` makes `verify`, and so the report, take a while. If the
/// report is already there when the signal would be sent, the round says
/// so and the next one seeds more; if every round is too fast, the test
/// says it was skipped.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_sigterm_while_the_report_is_written_ends_wrap_by_it_after_the_report() {
    use std::os::unix::process::ExitStatusExt;

    for seed in [150_usize, 300] {
        let what = format!("seed {seed}");
        let (_temp, home) = init_home();
        let calls: Vec<Value> = (0..seed)
            .map(|i| call(100 + i as i64, "echo", json!({"text": format!("seed {i}")})))
            .collect();
        let first = wrap(&home, &["--no-report"], &calls);
        assert_eq!(first.status.code(), Some(0), "{what}: {first:?}");
        assert_eq!(journal_lines(&home).len(), seed, "{what}");
        assert!(!reports_dir(&home).exists(), "{what}");

        let server = fake_server();
        let mut child = spawn_wrap(&home, &[], &[server.to_str().unwrap()]);
        let err = stderr_text(&mut child);
        let mut stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || std::io::copy(&mut stdout, &mut std::io::sink()));
        let mut stdin = child.stdin.take().unwrap();
        stdin
            .write_all(input(&[call(20, "echo", json!({"text": "one"}))]).as_bytes())
            .unwrap();
        stdin.flush().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while journal_lines(&home).len() == seed {
            assert!(std::time::Instant::now() < deadline, "{what}: no receipt");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let server = server_pid(&child);
        // Close the session from the client side and wait for the server
        // to be gone (reaped by wrap, which then writes the report).
        drop(stdin);
        loop {
            // SAFETY: `kill` with signal 0 sends nothing and takes no pointers.
            let result = unsafe { libc::kill(server, 0) };
            if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{what}: server {server} still exists"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        if !json_reports(&home).is_empty() {
            eprintln!("{what}: the report was written before the signal; seeding more");
            let _ = wait_within(&mut child, std::time::Duration::from_secs(10), &what);
            continue;
        }
        // SAFETY: `kill` takes no pointers; the pid is this test's child.
        assert_eq!(
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
            0
        );
        let status = wait_within(&mut child, std::time::Duration::from_secs(10), &what);
        let err = err.join().unwrap();
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "{what}: {status:?} {err}"
        );
        assert!(err.contains("session report:"), "{what}: {err}");
        let reports = json_reports(&home);
        assert_eq!(reports.len(), 1, "{what}: {err}");
        assert!(reports[0].with_extension("pdf").exists(), "{what}");
        assert_eq!(
            document(&reports[0])["receipts"].as_array().unwrap().len(),
            1,
            "{what}"
        );
        return;
    }
    skip_or_fail_in_ci(
        "a_sigterm_while_the_report_is_written_ends_wrap_by_it_after_the_report",
        "the report was written before the signal in every round (seeds 150 and 300)",
    );
}

/// A test that could not reach the case it checks. On a developer's
/// machine it says so on stderr; in CI (the `CI` variable is set), where
/// stderr of a passing test is not shown, it fails with the cause, so a
/// case that never ran is never reported as passed.
fn skip_or_fail_in_ci(test: &str, cause: &str) {
    if std::env::var_os("CI").is_some() {
        panic!(
            "{test} did not reach its case: {cause}. In CI a skip fails instead of passing \
             unseen; raise the seed or make the window reachable on this runner"
        );
    }
    eprintln!("SKIPPED {test}: {cause}");
}

#[test]
fn a_backslash_in_a_tool_name_is_escaped_once_in_the_pdf() {
    let (_temp, home) = init_home();
    let out = wrap(&home, &[], &[call(20, "a\\b", json!({}))]);
    assert!(out.status.success(), "{out:?}");
    let pdf = fs::read(json_reports(&home)[0].with_extension("pdf")).unwrap();
    // Shown as `a\\b` (the display escape), which the PDF string writes as
    // four backslashes; eight would be the escape done twice.
    assert!(has(&pdf, "a\\\\\\\\b"));
    assert!(!has(&pdf, "a\\\\\\\\\\\\\\\\b"));
}

#[test]
fn the_call_log_shows_utc_under_local_time() {
    let (_temp, home) = init_home();
    let out = wrap(&home, &[], &[call(20, "echo", json!({"text": "one"}))]);
    assert!(out.status.success(), "{out:?}");
    let path = json_reports(&home).remove(0);
    let decided = document(&path)["receipts"][0]["evidence"]["decided_at"]
        .as_str()
        .unwrap()
        .to_owned();
    // `2026-11-15T23:34:40.123Z` -> `23:34:40 UTC`.
    let clock = &decided[11..19];
    let pdf = fs::read(path.with_extension("pdf")).unwrap();
    assert!(has(&pdf, &format!("{clock} UTC")), "{clock}");
}

#[cfg(unix)]
#[test]
fn an_existing_reports_directory_is_made_private() {
    use std::os::unix::fs::PermissionsExt;
    let (_temp, home) = init_home();
    fs::create_dir(reports_dir(&home)).unwrap();
    fs::set_permissions(reports_dir(&home), fs::Permissions::from_mode(0o755)).unwrap();
    let out = wrap(&home, &[], &[call(20, "echo", json!({"text": "one"}))]);
    assert!(out.status.success(), "{out:?}");
    let mode = fs::metadata(reports_dir(&home))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700, "{mode:o}");
    for file in [
        json_reports(&home)[0].clone(),
        json_reports(&home)[0].with_extension("pdf"),
    ] {
        let mode = fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{}: {mode:o}", file.display());
    }
}

#[test]
fn an_unreadable_approval_journal_is_said_in_the_header_and_the_pdf() {
    let (_temp, home) = init_home();
    let approvals = home.root.join("approvals");
    fs::create_dir_all(&approvals).unwrap();
    fs::write(approvals.join("journal.jsonl"), "not json\n").unwrap();
    let out = wrap(&home, &[], &[call(20, "echo", json!({"text": "one"}))]);
    assert!(out.status.success(), "{out:?}");
    let path = json_reports(&home).remove(0);
    let document = document(&path);
    let error = document["header"]["approval_journal_error"]
        .as_str()
        .unwrap_or_else(|| panic!("{}", document["header"]));
    assert!(error.contains("journal.jsonl:1:"), "{error}");
    assert!(!error.contains(home.root.to_str().unwrap()), "{error}");
    assert_eq!(document["approvals"], json!([]));
    let pdf = fs::read(path.with_extension("pdf")).unwrap();
    assert!(has(&pdf, "The approval journal could not be read"));
    assert!(!has(&pdf, "No approval record"));
}

/// After "session report: <pdf>", wrap names the command that starts the
/// dashboard on this home (absolute, quoted for sh) and the page of the
/// session there.
#[test]
fn the_close_line_names_the_dashboard_command_and_the_session_link() {
    let (_temp, home) = init_home();
    let out = wrap(&home, &[], &[call(20, "echo", json!({"text": "one"}))]);
    assert!(out.status.success(), "{out:?}");
    let err = stderr(&out);
    let id = document(&json_reports(&home)[0])["header"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let exe = Path::new(bin()).canonicalize().unwrap();
    let root = home.root.canonicalize().unwrap();
    let expected = format!(
        "praetore-mcp: to see and download it, run '{}' dashboard --dir '{}' --port 8787 and open http://127.0.0.1:8787/#/sessions/{id} (a dashboard on another port: #/sessions/{id} there)",
        exe.display(),
        root.display()
    );
    let lines: Vec<&str> = err.lines().collect();
    let report = lines
        .iter()
        .position(|line| line.starts_with("praetore-mcp: session report: "))
        .unwrap_or_else(|| panic!("{err}"));
    assert_eq!(
        lines.get(report + 1).copied(),
        Some(expected.as_str()),
        "{err}"
    );

    // The command works as printed: through sh, it names this binary and
    // this home.
    let words = expected
        .split_once(" run ")
        .unwrap()
        .1
        .split_once(" and open ")
        .unwrap()
        .0;
    let echoed = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "for word in {words}; do printf '%s\\n' \"$word\"; done"
        ))
        .output()
        .unwrap();
    let echoed = String::from_utf8(echoed.stdout).unwrap();
    assert_eq!(
        echoed.lines().collect::<Vec<_>>(),
        vec![
            exe.to_str().unwrap(),
            "dashboard",
            "--dir",
            root.to_str().unwrap(),
            "--port",
            "8787"
        ]
    );

    // Without a report there is nothing to point at.
    let out = wrap(
        &home,
        &["--no-report"],
        &[call(21, "echo", json!({"text": "two"}))],
    );
    assert!(!stderr(&out).contains("#/sessions/"), "{}", stderr(&out));
}

/// A held call whose pending `expires_at` cannot be read: the session
/// report and the dashboard, over the same home, both say expired, by the
/// one rule (`approvals::Expiry::is_expired_at`).
#[test]
fn an_unreadable_expiry_is_expired_in_the_report_and_the_dashboard() {
    let (_temp, home) = init_home();
    let out = wrap(&home, &[], &[call(2, "append", json!({"text": "x"}))]);
    assert!(out.status.success(), "{out:?}");
    let (_, closed) = report_with(&home, 1);
    assert_eq!(closed["header"]["summary"]["pending"], 1);
    assert_eq!(closed["header"]["summary"]["expired"], 0);
    let pending = approvals::list_pending(&home).unwrap();
    assert_eq!(pending.len(), 1);
    let path = home
        .root
        .join("approvals")
        .join("pending")
        .join(format!("{}.json", pending[0].approval_id));
    let mut file: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    file["expires_at"] = json!("not a time");
    fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

    let out = run(&["report", "--dir", dir(&home), "--last"], "");
    assert!(out.status.success(), "{out:?}");
    let regen = document(regen_reports(&home).last().unwrap());
    assert_eq!(
        regen["header"]["summary"]["pending"], 0,
        "{}",
        regen["header"]["summary"]
    );
    assert_eq!(
        regen["header"]["summary"]["expired"], 1,
        "{}",
        regen["header"]["summary"]
    );

    let state = praetore_mcp::dashboard::state(&home, None);
    let held = state["receipts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["evidence_id"] == pending[0].evidence_id.as_str())
        .unwrap();
    assert_eq!(held["approval"], "expired");
}

fn journal_len(home: &Home) -> usize {
    receipts::read_journal(home).map_or(0, |lines| lines.len())
}

fn empty_receipts_journal(home: &Home) {
    let files = praetore_mcp::journal::journal_files(&home.receipts_dir()).unwrap();
    assert!(!files.is_empty(), "no receipts journal files to empty");
    for path in &files {
        fs::write(path, "").unwrap();
    }
    assert!(
        journal_lines(home).is_empty(),
        "journal was not empty after wipe"
    );
}

fn missing_ids(document: &Value) -> Vec<String> {
    document["header"]["verify"]["missing_evidence_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_owned())
        .collect()
}

/// Sends one `echo` call on an already initialized wrap stdin and waits
/// until the receipts journal has `expect` lines.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn send_echo(
    home: &Home,
    stdin: &mut std::process::ChildStdin,
    id: i64,
    text: &str,
    expect: usize,
) {
    stdin
        .write_all(format!("{}\n", call(id, "echo", json!({"text": text}))).as_bytes())
        .unwrap();
    stdin.flush().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while journal_len(home) != expect {
        assert!(
            std::time::Instant::now() < deadline,
            "journal length {}, expected {expect} after echo id={id}",
            journal_len(home)
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Closes the client stdin so wrap ends itself and writes the session
/// report. Returns stderr.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn close_wrap(
    mut child: std::process::Child,
    stdin: std::process::ChildStdin,
    err: std::thread::JoinHandle<String>,
    what: &str,
) -> String {
    drop(stdin);
    let status = wait_within(&mut child, std::time::Duration::from_secs(20), what);
    let err = err.join().unwrap();
    assert!(
        status.success(),
        "{what}: wrap exit {status:?}, stderr={err}"
    );
    assert!(
        err.contains("session report:"),
        "{what}: no close report in stderr: {err}"
    );
    err
}

/// If the receipts journal is emptied while wrap is still open, the close
/// report records the session's evidence ids as missing (they lived only
/// in memory). `praetore-mcp report` must keep those ids when it
/// regenerates, so verify stays failed and the command exits 1. Taking
/// ids only from the close report's `receipts` array would drop them and
/// report a pass.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regenerating_after_a_mid_session_journal_wipe_still_reports_the_missing_receipts() {
    let (_temp, home) = init_home();
    let (child, mut stdin, err, _server) = wrap_in_session(&home, &[]);
    send_echo(&home, &mut stdin, 21, "two", 2);
    assert_eq!(journal_len(&home), 2);

    empty_receipts_journal(&home);
    close_wrap(child, stdin, err, "mid-session wipe close");

    let close_path = json_reports(&home);
    assert_eq!(close_path.len(), 1, "{close_path:?}");
    let close = document(&close_path[0]);
    assert_eq!(close["header"]["verify"]["result"], "failed");
    let missing = missing_ids(&close);
    assert_eq!(missing.len(), 2, "{missing:?}");
    assert_eq!(close["receipts"].as_array().unwrap().len(), 0);
    assert_eq!(close["header"]["verify"]["journal_receipts"], 0);
    assert!(close["header"]["receipt_journal_head"].is_null());

    let out = run(&["report", "--dir", dir(&home), "--last"], "");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "report must exit 1 on verify failed; stdout={stdout}; stderr={stderr}"
    );
    assert!(stdout.contains("verify FAILED"), "stdout={stdout}");

    let regen = regen_reports(&home);
    assert_eq!(regen.len(), 1, "{regen:?}");
    let regen_doc = document(&regen[0]);
    assert_eq!(regen_doc["header"]["verify"]["result"], "failed");
    assert_eq!(regen_doc["header"]["verify"]["journal_receipts"], 0);
    assert_eq!(missing_ids(&regen_doc), missing);
    assert_eq!(regen_doc["receipts"].as_array().unwrap().len(), 0);
}

/// Same wipe, then one more receipt before close: the new receipt is in
/// the close report, the earlier ones are only in `missing_evidence_ids`.
/// Regenerating must still fail verify for those earlier ids and exit 1.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regenerating_after_a_mid_session_wipe_and_a_later_receipt_keeps_the_earlier_missing_ids() {
    let (_temp, home) = init_home();
    let (child, mut stdin, err, _server) = wrap_in_session(&home, &[]);
    send_echo(&home, &mut stdin, 21, "two", 2);
    assert_eq!(journal_len(&home), 2);

    empty_receipts_journal(&home);
    send_echo(&home, &mut stdin, 30, "after-wipe", 1);
    assert_eq!(journal_len(&home), 1);

    close_wrap(child, stdin, err, "mid-session wipe then later receipt");

    let close_path = json_reports(&home);
    assert_eq!(close_path.len(), 1, "{close_path:?}");
    let close = document(&close_path[0]);
    assert_eq!(close["header"]["verify"]["result"], "failed");
    let missing = missing_ids(&close);
    assert_eq!(missing.len(), 2, "{missing:?}");
    assert_eq!(close["receipts"].as_array().unwrap().len(), 1);
    assert_eq!(close["header"]["verify"]["journal_receipts"], 1);
    assert_eq!(close["header"]["verify"]["session_receipts"], 1);

    let out = run(&["report", "--dir", dir(&home), "--last"], "");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "report must exit 1 on verify failed; stdout={stdout}; stderr={stderr}"
    );
    assert!(stdout.contains("verify FAILED"), "stdout={stdout}");

    let regen = regen_reports(&home);
    assert_eq!(regen.len(), 1, "{regen:?}");
    let regen_doc = document(&regen[0]);
    assert_eq!(regen_doc["header"]["verify"]["result"], "failed");
    assert_eq!(regen_doc["header"]["verify"]["journal_receipts"], 1);
    assert_eq!(regen_doc["header"]["verify"]["session_receipts"], 1);
    assert_eq!(missing_ids(&regen_doc), missing);
    assert_eq!(regen_doc["receipts"].as_array().unwrap().len(), 1);
}
