//! `praetore-mcp dashboard`: receipt parsing, loopback-only listening, the
//! verification status matching `praetore-mcp verify`, and read-only access.

use praetore_mcp::{
    dashboard,
    receipts::{self, Check},
    store::Home,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::SystemTime,
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
        "{} missing: run via `cargo test`",
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

/// A home with an ALLOW, a DENY and a REQUIRE_APPROVAL receipt in enforce
/// mode, and one path_check record.
fn home_with_receipts() -> (tempfile::TempDir, Home) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let dir = root.to_str().unwrap();
    assert!(run(&["init", "--dir", dir], "").status.success());
    let allowed = temp.path().join("allowed");
    fs::create_dir(&allowed).unwrap();
    let allowed = fs::canonicalize(&allowed).unwrap();
    for args in [
        vec![
            "policy",
            "deny",
            "--id",
            "deny-delete",
            "--tool",
            "delete_file",
        ],
        vec![
            "policy",
            "require-approval",
            "--id",
            "ask-move",
            "--tool",
            "move_file",
        ],
        vec![
            "policy",
            "deny",
            "--id",
            "deny-outside",
            "--tool",
            "read_file",
            "--arg-path-prefix",
        ],
    ] {
        let mut args = args;
        let prefix = format!("path={}", allowed.join("secret").display());
        if args.last() == Some(&"--arg-path-prefix") {
            args.push(&prefix);
        }
        args.extend(["--dir", dir]);
        let out = run(&args, "");
        assert!(out.status.success(), "{args:?}: {out:?}");
    }
    let calls = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"<b>hi</b>"}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/x"}}}),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"move_file","arguments":{"from":"/a","to":"/b"}}}),
        json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"read_file","arguments":{"path": allowed.join("ok.txt")}}}),
    ];
    let input: String = calls.iter().map(|c| format!("{c}\n")).collect();
    let server = fake_server();
    let out = run(
        &[
            "wrap",
            "--dir",
            dir,
            "--name",
            "fake",
            "--mode",
            "enforce",
            "--",
            server.to_str().unwrap(),
        ],
        &input,
    );
    assert!(out.status.success(), "{out:?}");
    (temp, Home::new(root))
}

fn verify_cli(home: &Home) -> (i32, String) {
    let out = run(&["verify", "--dir", home.root.to_str().unwrap()], "");
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// Asserts the dashboard state reports exactly what `verify` printed.
fn assert_state_matches_verify(home: &Home) -> Value {
    let (code, report) = verify_cli(home);
    let state = dashboard::state(home, None);
    let v = &state["verify"];
    assert_eq!(v["status"] == "ok", code == 0, "{report}\n{v}");
    let cli_failures: Vec<&str> = report
        .lines()
        .filter(|l| l.starts_with("FAIL") && !l.contains(" receipts: "))
        .collect();
    let state_failures: Vec<&str> = v["failures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert_eq!(cli_failures, state_failures);
    let summary = format!(
        "{} {} receipts: {} verified, {} failed",
        if code == 0 { "OK" } else { "FAIL" },
        v["total"],
        v["verified"],
        v["failed"]
    );
    assert!(report.contains(&summary), "{summary:?} not in\n{report}");
    match v["head"].as_object() {
        Some(head) => assert!(
            report.contains(&format!(
                "next seq {}, head {}",
                head["next_seq"],
                head["prev"].as_str().unwrap()
            )),
            "{report}"
        ),
        None => assert!(report.contains("journal head: none"), "{report}"),
    }
    // Per receipt: verified rows are exactly the `verified` count, and every
    // failing row's location and first failure appear in verify's output.
    let rows = state["receipts"].as_array().unwrap();
    let verified = rows.iter().filter(|r| r["verified"] == true).count();
    assert_eq!(json!(verified), v["verified"]);
    for row in rows.iter().filter(|r| r["verified"] == false) {
        let at = format!(
            "FAIL {}:{}: ",
            row["location"]["file"].as_str().unwrap(),
            row["location"]["line"]
        );
        let line = report
            .lines()
            .find(|l| l.starts_with(&at))
            .unwrap_or_else(|| panic!("{at} not in\n{report}"));
        let first_failure = ["agent", "attester", "authority"]
            .iter()
            .map(|s| &row["signatures"][s]["check"])
            .chain(
                row["checks"]
                    .as_object()
                    .into_iter()
                    .flat_map(|c| c.values()),
            )
            .find_map(|c| c["error"].as_str());
        if let Some(error) = first_failure {
            assert!(
                report.contains(&format!("{at}{error}")) || line.contains("journal order"),
                "{error} for {at} not in\n{report}"
            );
        }
    }
    state
}

#[test]
fn receipt_rows_carry_the_table_columns_signatures_and_path_check() {
    let (_temp, home) = home_with_receipts();
    let state = dashboard::state(&home, None);
    let rows = state["receipts"].as_array().unwrap();
    assert_eq!(rows.len(), 4, "{state}");
    let by_tool = |tool: &str| rows.iter().find(|r| r["tool"] == tool).unwrap();

    let echo = by_tool("echo");
    assert_eq!(echo["decision"], "ALLOW");
    assert_eq!(echo["rule"], "allow-all-mcp-tool-calls");
    assert_eq!(echo["server"], "fake");
    assert_eq!(echo["mode"], "enforce");
    assert_eq!(echo["arguments"], json!({"msg": "<b>hi</b>"}));
    assert_eq!(echo["seq"], 0);
    assert!(echo["decided_at"].as_str().unwrap().ends_with('Z'));
    assert!(echo["evidence_id"].as_str().unwrap().len() == 36);
    for sig in ["agent", "attester", "authority"] {
        assert_eq!(echo["signatures"][sig]["check"]["status"], "ok", "{sig}");
    }
    assert_eq!(
        echo["signatures"]["attester"]["key_id"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert!(echo["signatures"]["authority"]["key_id"].is_string());
    assert_eq!(
        echo["signatures"]["authority"]["issuer"],
        "praetore-mcp-local-issuer"
    );
    assert!(echo["signatures"]["agent"]["agent_id"].is_string());
    // The full line is there, chained.
    assert_eq!(echo["raw"]["seq"], 0);
    assert_eq!(echo["raw"]["evidence"]["evidence_id"], echo["evidence_id"]);

    assert_eq!(by_tool("delete_file")["decision"], "DENY");
    assert_eq!(by_tool("delete_file")["rule"], "deny-delete");
    assert_eq!(by_tool("move_file")["decision"], "REQUIRE_APPROVAL");
    assert_eq!(by_tool("move_file")["rule"], "ask-move");
    assert!(by_tool("move_file")["approval"].is_string());

    let read = by_tool("read_file");
    let check = read["path_check"]["arguments.path"].as_object().unwrap();
    assert!(check["lexical"].as_str().unwrap().ends_with("ok.txt"));
    assert!(check.contains_key("resolved"));
    assert!(check["status"].is_string());

    let summary = &state["summary"];
    assert_eq!(summary["total"], 4);
    assert_eq!(summary["allow"], 2);
    assert_eq!(summary["deny"], 1);
    assert_eq!(summary["require_approval"], 1);

    let policy = &state["policy"];
    assert_eq!(policy["status"], "ok");
    assert_eq!(policy["id"], "praetore-mcp-default");
    assert_eq!(policy["digest"].as_str().unwrap().len(), 64);
    assert_eq!(
        policy["allow_all_rules"],
        json!(["allow-all-mcp-tool-calls"])
    );
    assert_eq!(policy["warn_allow_all_enforce"], true);
    // The digest shown is the one the receipts were decided under.
    assert_eq!(echo["policy_digest"], policy["digest"]);
}

#[test]
fn unreadable_lines_are_listed_not_dropped() {
    let (_temp, home) = home_with_receipts();
    let file = receipts::read_journal(&home).unwrap()[0].file.clone();
    let mut text = fs::read_to_string(&file).unwrap();
    text.push_str("{not json\n");
    fs::write(&file, text).unwrap();
    let state = assert_state_matches_verify(&home);
    let rows = state["receipts"].as_array().unwrap();
    assert_eq!(rows.len(), 5);
    let bad = rows.last().unwrap();
    assert!(bad["parse_error"].as_str().unwrap().contains("not JSON"));
    assert_eq!(bad["verified"], false);
    assert_eq!(state["summary"]["unreadable"], 1);
}

#[test]
fn allow_all_warning_needs_an_enforce_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    assert!(
        run(&["init", "--dir", root.to_str().unwrap()], "")
            .status
            .success()
    );
    let home = Home::new(root);
    let state = dashboard::state(&home, None);
    assert_eq!(
        state["policy"]["allow_all_rules"].as_array().unwrap().len(),
        1
    );
    assert_eq!(state["policy"]["warn_allow_all_enforce"], false);
    assert_eq!(state["summary"]["total"], 0);
    assert_eq!(state["verify"]["status"], "ok");
}

#[test]
fn verification_status_matches_verify_on_a_good_journal() {
    let (_temp, home) = home_with_receipts();
    let state = assert_state_matches_verify(&home);
    assert_eq!(state["verify"]["status"], "ok");
    assert_eq!(state["verify"]["verified"], 4);
}

#[test]
fn verification_status_matches_verify_on_a_tampered_receipt() {
    let (_temp, home) = home_with_receipts();
    let file = receipts::read_journal(&home).unwrap()[0].file.clone();
    let original = fs::read_to_string(&file).unwrap();
    let mut lines: Vec<String> = original.lines().map(str::to_owned).collect();
    // The integrity hash no longer matches: the line is not a readable receipt.
    lines[1] = lines[1].replace(
        r#""praetore.mode":"enforce""#,
        r#""praetore.mode":"observe""#,
    );
    fs::write(&file, lines.join("\n") + "\n").unwrap();
    let state = assert_state_matches_verify(&home);
    assert_eq!(state["verify"]["status"], "fail");
    let row = &state["receipts"][1];
    assert_eq!(row["verified"], false);
    assert!(
        row["parse_error"].as_str().unwrap().contains("integrity"),
        "{row}"
    );
    assert_eq!(state["receipts"][0]["verified"], true);
}

#[test]
fn a_wrong_attester_pin_fails_only_the_attester_signature() {
    let (_temp, home) = home_with_receipts();
    // Pin another valid key (the approver's) as the attester.
    fs::copy(home.approver_pin(), home.attester_pin()).unwrap();
    let state = assert_state_matches_verify(&home);
    assert_eq!(state["verify"]["status"], "fail");
    assert_eq!(state["verify"]["verified"], 0);
    for row in state["receipts"].as_array().unwrap() {
        let sig = &row["signatures"];
        assert_eq!(sig["attester"]["check"]["status"], "fail", "{row}");
        assert!(
            sig["attester"]["check"]["error"]
                .as_str()
                .unwrap()
                .starts_with("attester signature: ")
        );
        assert_eq!(sig["agent"]["check"]["status"], "ok");
        assert_eq!(sig["authority"]["check"]["status"], "ok");
    }
}

#[test]
fn verification_status_matches_verify_when_an_entry_is_removed() {
    let (_temp, home) = home_with_receipts();
    let file = receipts::read_journal(&home).unwrap()[0].file.clone();
    let original = fs::read_to_string(&file).unwrap();
    let mut lines: Vec<&str> = original.lines().collect();
    lines.remove(1);
    fs::write(&file, lines.join("\n") + "\n").unwrap();
    let state = assert_state_matches_verify(&home);
    assert_eq!(state["verify"]["status"], "fail");
    let row = &state["receipts"][1];
    assert!(row["order"].as_str().unwrap().contains("seq"), "{row}");
    // Every signature of that receipt is still valid; only the order fails.
    for sig in ["agent", "attester", "authority"] {
        assert_eq!(row["signatures"][sig]["check"]["status"], "ok");
    }
}

#[test]
fn verification_status_matches_verify_with_an_expected_head() {
    let (_temp, home) = home_with_receipts();
    let wrong = "0".repeat(64);
    let state = dashboard::state(&home, Some(&wrong));
    let out = run(
        &[
            "verify",
            "--dir",
            home.root.to_str().unwrap(),
            "--expected-head",
            &wrong,
        ],
        "",
    );
    let report = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(state["verify"]["status"], "fail");
    let failures = state["verify"]["failures"].as_array().unwrap();
    assert_eq!(failures.len(), 1);
    assert!(report.contains(failures[0].as_str().unwrap()), "{report}");
}

#[test]
fn checks_report_each_signature_and_first_failure_is_what_verify_prints() {
    let (_temp, home) = home_with_receipts();
    let report = receipts::verify_journal(&home, None).unwrap();
    assert_eq!(report.lines.len(), 4);
    for line in &report.lines {
        let checks = line.checks.as_ref().unwrap();
        assert!(checks.named().iter().all(|(_, c)| **c == Check::Ok));
        assert_eq!(checks.first_failure(), None);
        assert!(line.verified);
    }
}

#[test]
fn listener_refuses_every_address_but_127_0_0_1() {
    for addr in [
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
        SocketAddr::from((Ipv4Addr::new(192, 168, 1, 10), 0)),
        SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), 0)),
    ] {
        let error = dashboard::bind_addr(addr).unwrap_err();
        assert!(
            error.contains("only listens on 127.0.0.1"),
            "{addr}: {error}"
        );
    }
    let listener = dashboard::bind(0).unwrap();
    assert_eq!(
        listener.local_addr().unwrap().ip(),
        std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
}

#[test]
fn cli_has_no_way_to_pick_another_address() {
    for args in [
        vec!["dashboard", "--host", "0.0.0.0"],
        vec!["dashboard", "--bind", "0.0.0.0:8787"],
        vec!["dashboard", "--port", "0.0.0.0:80"],
        vec!["dashboard", "--port", "70000"],
        vec!["dashboard", "--expected-head", "zz"],
    ] {
        let out = run(&args, "");
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
    }
}

fn http(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn snapshot(dir: &Path) -> BTreeMap<PathBuf, (u64, SystemTime)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let meta = fs::symlink_metadata(entry.path()).unwrap();
            if meta.is_dir() {
                stack.push(entry.path());
            }
            out.insert(entry.path(), (meta.len(), meta.modified().unwrap()));
        }
    }
    out
}

#[test]
fn server_answers_get_on_loopback_only_and_writes_nothing() {
    let (_temp, home) = home_with_receipts();
    let before = snapshot(&home.root);
    let listener = dashboard::bind(0).unwrap();
    let port = listener.local_addr().unwrap().port();
    let served_home = home.clone();
    let server = std::thread::spawn(move || {
        dashboard::serve(&listener, &served_home, None, Some(7)).unwrap();
    });
    let host = format!("Host: 127.0.0.1:{port}");

    let page = http(port, &format!("GET / HTTP/1.1\r\n{host}\r\n\r\n"));
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert!(page.contains("Content-Security-Policy: default-src 'none'"));
    // No network origin anywhere in the embedded page.
    for asset in ["/", "/app.js", "/app.css"] {
        let body = http(port, &format!("GET {asset} HTTP/1.1\r\n{host}\r\n\r\n"));
        assert!(body.starts_with("HTTP/1.1 200"), "{asset}");
        assert!(
            !body.contains("http://") && !body.contains("https://"),
            "{asset}"
        );
    }

    let api = http(
        port,
        &format!("GET /api/state HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"),
    );
    let body = api.split_once("\r\n\r\n").unwrap().1;
    let state: Value = serde_json::from_str(body).unwrap();
    assert_eq!(state["summary"]["total"], 4);

    let foreign = http(
        port,
        "GET /api/state HTTP/1.1\r\nHost: attacker.example\r\n\r\n",
    );
    assert!(foreign.starts_with("HTTP/1.1 403"), "{foreign}");
    let post = http(port, &format!("POST /api/state HTTP/1.1\r\n{host}\r\n\r\n"));
    assert!(post.starts_with("HTTP/1.1 405"), "{post}");
    server.join().unwrap();

    assert_eq!(
        before,
        snapshot(&home.root),
        "the dashboard wrote under DIR"
    );
}

#[test]
fn page_never_writes_journal_values_as_html() {
    let (_temp, home) = home_with_receipts();
    let listener = dashboard::bind(0).unwrap();
    let port = listener.local_addr().unwrap().port();
    let served_home = home.clone();
    let server = std::thread::spawn(move || {
        dashboard::serve(&listener, &served_home, None, Some(1)).unwrap();
    });
    let js = http(
        port,
        &format!("GET /app.js HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    );
    server.join().unwrap();
    for sink in [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
    ] {
        assert!(!js.contains(sink), "app.js uses {sink}");
    }
}
