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
        // A home from before default deny: `init` no longer writes this rule.
        vec![
            "policy",
            "allow",
            "--id",
            "allow-all-mcp-tool-calls",
            "--any-tool",
        ],
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
    // `init` writes a default-deny policy: no allow-all rule.
    let state = dashboard::state(&home, None);
    assert_eq!(state["policy"]["allow_all_rules"], json!([]));
    assert_eq!(state["policy"]["warn_allow_all_enforce"], false);

    // A server-scoped allow-all counts, as in `policy check`.
    let out = run(
        &[
            "policy",
            "allow",
            "--id",
            "allow-fake",
            "--server",
            "fake",
            "--any-tool",
            "--dir",
            home.root.to_str().unwrap(),
        ],
        "",
    );
    assert!(out.status.success(), "{out:?}");
    let state = dashboard::state(&home, None);
    assert_eq!(state["policy"]["allow_all_rules"], json!(["allow-fake"]));
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

/// The whole policy, so any added source (`'unsafe-inline'`, a host, a
/// scheme) or removed directive fails the comparison.
const EXPECTED_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// The value of the only `Content-Security-Policy` header of `response`.
fn csp_of(response: &str) -> &str {
    let head = response.split_once("\r\n\r\n").unwrap().0;
    let values: Vec<&str> = head
        .split("\r\n")
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-security-policy")
                .then(|| value.trim())
        })
        .collect();
    assert_eq!(values.len(), 1, "{head}");
    values[0]
}

#[test]
fn host_header_matrix() {
    let (_temp, home) = home_with_receipts();
    let listener = dashboard::bind(0).unwrap();
    let port = listener.local_addr().unwrap().port();
    let good = format!("Host: 127.0.0.1:{port}");
    let other_port = format!("Host: 127.0.0.1:{}", port.wrapping_add(1));
    let cases: Vec<(String, u16)> = vec![
        (format!("GET / HTTP/1.1\r\n{good}\r\n\r\n"), 200),
        (
            format!("GET / HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"),
            200,
        ),
        (
            "GET / HTTP/1.1\r\nHost: attacker.example\r\n\r\n".into(),
            403,
        ),
        (format!("GET / HTTP/1.1\r\n{other_port}\r\n\r\n"), 403),
        ("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".into(), 403),
        ("GET / HTTP/1.0\r\n\r\n".into(), 403),
        (
            format!("GET / HTTP/1.1\r\n{good}\r\nHost: attacker.example\r\n\r\n"),
            400,
        ),
        (
            format!("GET / HTTP/1.1\r\nHost: attacker.example\r\n{good}\r\n\r\n"),
            400,
        ),
        (
            format!("GET /api/state HTTP/1.1\r\n{good}\r\n{good}\r\n\r\n"),
            400,
        ),
        (
            format!("GET /app.js HTTP/1.1\r\n{good}\r\nhost: 127.0.0.1:{port}\r\n\r\n"),
            400,
        ),
    ];
    let served_home = home.clone();
    let count = cases.len();
    let server = std::thread::spawn(move || {
        dashboard::serve(&listener, &served_home, None, Some(count)).unwrap();
    });
    for (request, status) in &cases {
        let response = http(port, request);
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status} ")),
            "{request:?} gave\n{response}"
        );
        if *status != 200 {
            // Nothing served: only the short plain-text refusal.
            let (head, body) = response.split_once("\r\n\r\n").unwrap();
            assert!(
                head.contains("Content-Type: text/plain"),
                "{request:?}: {head}"
            );
            assert!(body.len() < 64, "{request:?}: {body}");
            assert!(
                !body.contains('<') && !body.contains('{') && !body.contains("function"),
                "{request:?}: {body}"
            );
        }
    }
    server.join().unwrap();
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
    assert_eq!(csp_of(&page), EXPECTED_CSP);
    // No network origin anywhere in the embedded page.
    for asset in ["/", "/app.js", "/app.css"] {
        let body = http(port, &format!("GET {asset} HTTP/1.1\r\n{host}\r\n\r\n"));
        assert!(body.starts_with("HTTP/1.1 200"), "{asset}");
        assert_eq!(csp_of(&body), EXPECTED_CSP, "{asset}");
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
fn favicon_is_answered_empty_and_stays_get_only_on_loopback() {
    let (_temp, home) = home_with_receipts();
    let before = snapshot(&home.root);
    let listener = dashboard::bind(0).unwrap();
    let port = listener.local_addr().unwrap().port();
    let host = format!("Host: 127.0.0.1:{port}");
    let cases: Vec<(String, u16)> = vec![
        (format!("GET /favicon.ico HTTP/1.1\r\n{host}\r\n\r\n"), 204),
        (
            format!("GET /favicon.ico HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"),
            204,
        ),
        (format!("POST /favicon.ico HTTP/1.1\r\n{host}\r\n\r\n"), 405),
        (format!("PUT /favicon.ico HTTP/1.1\r\n{host}\r\n\r\n"), 405),
        (
            format!("DELETE /favicon.ico HTTP/1.1\r\n{host}\r\n\r\n"),
            405,
        ),
        (
            "GET /favicon.ico HTTP/1.1\r\nHost: attacker.example\r\n\r\n".into(),
            403,
        ),
        ("GET /favicon.ico HTTP/1.0\r\n\r\n".into(), 403),
        (
            format!("GET /favicon.ico HTTP/1.1\r\n{host}\r\nHost: attacker.example\r\n\r\n"),
            400,
        ),
        // Only that path: anything else unknown is still a 404.
        (format!("GET /favicon.png HTTP/1.1\r\n{host}\r\n\r\n"), 404),
    ];
    let served_home = home.clone();
    let count = cases.len();
    let server = std::thread::spawn(move || {
        dashboard::serve(&listener, &served_home, None, Some(count)).unwrap();
    });
    for (request, status) in &cases {
        let response = http(port, request);
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status} ")),
            "{request:?} gave\n{response}"
        );
        assert_eq!(csp_of(&response), EXPECTED_CSP, "{request:?}");
        if *status == 204 {
            let (head, body) = response.split_once("\r\n\r\n").unwrap();
            assert!(head.starts_with("HTTP/1.1 204 No Content"), "{head}");
            assert!(head.contains("Content-Length: 0"), "{head}");
            assert_eq!(body, "");
        }
    }
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
    let js = js.split_once("\r\n\r\n").unwrap().1;
    for sink in [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "createContextualFragment",
        "DOMParser",
        "srcdoc",
        "eval(",
        "Function(",
        "setHTML",
        "javascript:",
    ] {
        assert!(!js.contains(sink), "app.js uses {sink}");
    }
    assert_no_string_timers(js);
    assert_no_event_handler_attributes(js);
}

/// Fails when `js` passes a string to `setTimeout` or `setInterval`, which
/// the browser would run as code.
fn assert_no_string_timers(js: &str) {
    for timer in ["setTimeout", "setInterval"] {
        for (at, _) in js.match_indices(timer) {
            let rest = js[at + timer.len()..].trim_start();
            let Some(argument) = rest.strip_prefix('(') else {
                continue;
            };
            let first = argument.trim_start().chars().next();
            assert!(
                !matches!(first, Some('"' | '\'' | '`')),
                "app.js passes a string to {timer}: {}",
                &js[at..(at + 60).min(js.len())]
            );
        }
    }
}

/// HTML event handler content attributes (GlobalEventHandlers and the
/// document and window ones).
const EVENT_HANDLER_ATTRIBUTES: &[&str] = &[
    "onabort",
    "onafterprint",
    "onanimationend",
    "onanimationiteration",
    "onanimationstart",
    "onauxclick",
    "onbeforeinput",
    "onbeforeprint",
    "onbeforetoggle",
    "onbeforeunload",
    "onblur",
    "oncancel",
    "oncanplay",
    "oncanplaythrough",
    "onchange",
    "onclick",
    "onclose",
    "oncontextlost",
    "oncontextmenu",
    "oncontextrestored",
    "oncopy",
    "oncuechange",
    "oncut",
    "ondblclick",
    "ondrag",
    "ondragend",
    "ondragenter",
    "ondragleave",
    "ondragover",
    "ondragstart",
    "ondrop",
    "ondurationchange",
    "onemptied",
    "onended",
    "onerror",
    "onfocus",
    "onfocusin",
    "onfocusout",
    "onformdata",
    "onhashchange",
    "oninput",
    "oninvalid",
    "onkeydown",
    "onkeypress",
    "onkeyup",
    "onlanguagechange",
    "onload",
    "onloadeddata",
    "onloadedmetadata",
    "onloadstart",
    "onmessage",
    "onmessageerror",
    "onmousedown",
    "onmouseenter",
    "onmouseleave",
    "onmousemove",
    "onmouseout",
    "onmouseover",
    "onmouseup",
    "onoffline",
    "ononline",
    "onpagehide",
    "onpagereveal",
    "onpageshow",
    "onpageswap",
    "onpaste",
    "onpause",
    "onplay",
    "onplaying",
    "onpointercancel",
    "onpointerdown",
    "onpointerenter",
    "onpointerleave",
    "onpointermove",
    "onpointerout",
    "onpointerover",
    "onpointerup",
    "onpopstate",
    "onprogress",
    "onratechange",
    "onrejectionhandled",
    "onreset",
    "onresize",
    "onscroll",
    "onscrollend",
    "onsecuritypolicyviolation",
    "onseeked",
    "onseeking",
    "onselect",
    "onselectionchange",
    "onselectstart",
    "onslotchange",
    "onstalled",
    "onstorage",
    "onsubmit",
    "onsuspend",
    "ontimeupdate",
    "ontoggle",
    "ontouchcancel",
    "ontouchend",
    "ontouchmove",
    "ontouchstart",
    "ontransitioncancel",
    "ontransitionend",
    "ontransitionrun",
    "ontransitionstart",
    "onunhandledrejection",
    "onunload",
    "onvolumechange",
    "onwaiting",
    "onwheel",
];

/// Fails when `js` sets an event handler attribute: a literal
/// `setAttribute("on...")`, or an `on...:` key in the attributes passed to
/// `el()`, which hands every key other than `class`, `style` and `onclick`
/// to `setAttribute`. `el()` turns `onclick` into `addEventListener`.
fn assert_no_event_handler_attributes(js: &str) {
    let lower = js.to_ascii_lowercase();
    let word_at = |at: usize| -> &str {
        let rest = &lower[at..];
        let len = rest.bytes().take_while(u8::is_ascii_alphanumeric).count();
        &rest[..len]
    };
    for (at, _) in lower.match_indices("setattribute(") {
        let argument = lower[at + "setattribute(".len()..].trim_start();
        let Some(name) = argument.strip_prefix(['"', '\'', '`']) else {
            continue;
        };
        let start = lower.len() - name.len();
        assert!(
            !EVENT_HANDLER_ATTRIBUTES.contains(&word_at(start)),
            "app.js sets an event handler attribute: {}",
            &js[at..(at + 60).min(js.len())]
        );
    }
    let bytes = lower.as_bytes();
    for (at, _) in lower.match_indices("on") {
        if at > 0
            && (bytes[at - 1].is_ascii_alphanumeric()
                || matches!(bytes[at - 1], b'_' | b'$' | b'.'))
        {
            continue;
        }
        let word = word_at(at);
        let after = lower[at + word.len()..]
            .trim_start_matches(['"', '\''])
            .trim_start();
        if word != "onclick" && EVENT_HANDLER_ATTRIBUTES.contains(&word) && after.starts_with(':') {
            panic!(
                "app.js passes an event handler attribute to el(): {}",
                &js[at..(at + 60).min(js.len())]
            );
        }
    }
}

/// `/api/state` with `query`, through [`dashboard::respond_with`].
fn api(home: &Home, cache: &mut dashboard::Cache, query: &str) -> (u16, Value) {
    let request = format!("GET /api/state{query} HTTP/1.1\r\nHost: 127.0.0.1:8787\r\n\r\n");
    let response = dashboard::respond_with(&request, home, None, 8787, cache);
    let body = if response.status == 200 {
        serde_json::from_slice(&response.body).unwrap()
    } else {
        Value::String(String::from_utf8(response.body).unwrap())
    };
    (response.status, body)
}

fn page_tools(state: &Value) -> Vec<&str> {
    state["page"]["receipts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["tool"].as_str().unwrap())
        .collect()
}

#[test]
fn api_state_sends_one_page_newest_first_with_full_counts() {
    let (_temp, home) = home_with_receipts();
    let mut cache = dashboard::Cache::default();
    let (status, state) = api(&home, &mut cache, "?limit=2");
    assert_eq!(status, 200, "{state}");
    assert_eq!(
        page_tools(&state),
        ["read_file", "move_file"],
        "newest first"
    );
    assert_eq!(state["page"]["matching"], 4);
    assert!(state.get("receipts").is_none(), "no whole journal");
    let (_, next) = api(&home, &mut cache, "?limit=2&offset=2");
    assert_eq!(page_tools(&next), ["delete_file", "echo"]);
    // The counts cover the whole journal, whatever the page.
    assert_eq!(state["summary"]["total"], 4);
    assert_eq!(state["summary"]["allow"], 2);
    assert_eq!(
        state["tools"].as_array().unwrap().len(),
        4,
        "{}",
        state["tools"]
    );
    let buckets = state["activity"]["buckets"].as_array().unwrap();
    let decisions: u64 = buckets
        .iter()
        .map(|b| {
            b["ALLOW"].as_u64().unwrap()
                + b["DENY"].as_u64().unwrap()
                + b["REQUIRE_APPROVAL"].as_u64().unwrap()
        })
        .sum();
    assert_eq!(decisions, 4);
    assert_eq!(state["activity"]["bucket_seconds"], 900);
    assert_eq!(state["recent"].as_array().unwrap().len(), 4);
    assert_eq!(state["approval_history"][0]["tool"], "move_file");
    // A parsed receipt is sent once, as JSON, not again as text.
    let first = &state["page"]["receipts"][0];
    assert!(first["raw"].is_object() && first.get("raw_text").is_none());
    // One verification for the three requests.
    assert_eq!(cache.verifications(), 1);
}

#[test]
fn api_state_filters_by_decision_tool_time_and_text() {
    let (_temp, home) = home_with_receipts();
    let mut cache = dashboard::Cache::default();
    let tools = |query: &str, cache: &mut dashboard::Cache| -> Vec<String> {
        let (status, state) = api(&home, cache, query);
        assert_eq!(status, 200, "{query}: {state}");
        page_tools(&state).into_iter().map(str::to_owned).collect()
    };
    assert_eq!(tools("?decision=DENY", &mut cache), ["delete_file"]);
    assert_eq!(tools("?decision=ALLOW", &mut cache), ["read_file", "echo"]);
    assert_eq!(
        tools("?decision=REQUIRE_APPROVAL", &mut cache),
        ["move_file"]
    );
    assert_eq!(tools("?tool=echo", &mut cache), ["echo"]);
    assert_eq!(
        tools("?decision=ALLOW&tool=delete_file", &mut cache),
        Vec::<String>::new()
    );
    // Text search over the receipt, case-insensitive, form-encoded.
    assert_eq!(tools("?q=%3CB%3Ehi", &mut cache), ["echo"]);
    assert_eq!(tools("?q=ok.txt", &mut cache), ["read_file"]);
    // Time range on decided_at, inclusive, any UTC offset.
    let (_, all) = api(&home, &mut cache, "");
    let times: Vec<&str> = all["recent"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["decided_at"].as_str().unwrap())
        .collect();
    let (newest, oldest) = (times[0], times[times.len() - 1]);
    let enc = |t: &str| t.replace('+', "%2B");
    assert_eq!(
        tools(
            &format!("?from={}&to={}", enc(oldest), enc(newest)),
            &mut cache
        )
        .len(),
        4
    );
    assert_eq!(
        tools("?from=2999-01-01T00:00:00Z", &mut cache),
        Vec::<String>::new()
    );
    assert_eq!(
        tools("?to=2000-01-01T00:00:00%2B03:00", &mut cache),
        Vec::<String>::new()
    );
    assert_eq!(
        tools(&format!("?from={}", enc(newest)), &mut cache).len(),
        times.iter().filter(|t| **t == newest).count()
    );
    for bad in [
        "?decision=allow",
        "?decision=UNREADABLE",
        "?limit=0",
        "?limit=501",
        "?offset=-1",
        "?from=yesterday",
        "?to=2026-01-01",
        "?q=%ZZ",
        "?q=%FF",
        "?sort=asc",
    ] {
        let (status, body) = api(&home, &mut cache, bad);
        assert_eq!(status, 400, "{bad}: {body}");
    }
    assert_eq!(cache.verifications(), 1);
}

/// Rewrites `file` with `edit` applied, keeping its length and its
/// modification time.
fn rewrite_keeping_mtime(file: &Path, edit: impl Fn(&str) -> String) {
    let before = fs::metadata(file).unwrap();
    let text = edit(&fs::read_to_string(file).unwrap());
    assert_eq!(text.len() as u64, before.len(), "same length");
    fs::write(file, text).unwrap();
    fs::File::options()
        .write(true)
        .open(file)
        .unwrap()
        .set_modified(before.modified().unwrap())
        .unwrap();
    assert_eq!(
        fs::metadata(file).unwrap().modified().unwrap(),
        before.modified().unwrap()
    );
}

#[test]
fn cached_verification_is_redone_when_a_file_verify_reads_changes() {
    let (_temp, home) = home_with_receipts();
    let mut cache = dashboard::Cache::default();
    let (_, state) = api(&home, &mut cache, "");
    assert_eq!(state["verify"]["status"], "ok");
    let (_, _) = api(&home, &mut cache, "?decision=DENY");
    assert_eq!(cache.verifications(), 1, "nothing changed");

    // Same length, same modification time: still verified again.
    let file = receipts::read_journal(&home).unwrap()[0].file.clone();
    rewrite_keeping_mtime(&file, |text| {
        text.replacen(
            r#""praetore.mode":"enforce""#,
            r#""praetore.mode":"observe""#,
            1,
        )
    });
    let (_, state) = api(&home, &mut cache, "");
    assert_eq!(cache.verifications(), 2);
    assert_eq!(state["verify"]["status"], "fail", "{}", state["verify"]);
    assert_eq!(
        state["verify"]["status"],
        dashboard::state(&home, None)["verify"]["status"]
    );

    // A changed pin is verified again too.
    let (_temp, home) = home_with_receipts();
    let mut cache = dashboard::Cache::default();
    assert_eq!(api(&home, &mut cache, "").1["verify"]["status"], "ok");
    let approver = fs::read_to_string(home.approver_pin()).unwrap();
    rewrite_keeping_mtime(&home.attester_pin(), |_| approver.clone());
    let (_, state) = api(&home, &mut cache, "");
    assert_eq!(cache.verifications(), 2);
    assert_eq!(state["verify"]["status"], "fail");

    // An appended line.
    let file = receipts::read_journal(&home).unwrap()[0].file.clone();
    let mut journal = fs::OpenOptions::new().append(true).open(&file).unwrap();
    journal.write_all(b"{not json\n").unwrap();
    let (_, state) = api(&home, &mut cache, "");
    assert_eq!(cache.verifications(), 3);
    assert_eq!(state["summary"]["unreadable"], 1);
    assert_eq!(state["summary"]["total"], 5);
}

/// Changes the hex digit right after `marker`, keeping the length.
fn flip_hex_after(text: &str, marker: &str) -> String {
    let at = text
        .find(marker)
        .unwrap_or_else(|| panic!("no {marker} in {text}"))
        + marker.len();
    let old = text.as_bytes()[at] as char;
    assert!(old.is_ascii_hexdigit(), "{marker} is not followed by hex");
    let new = if old == '0' { '1' } else { '0' };
    format!("{}{new}{}", &text[..at], &text[at + 1..])
}

/// A file verify reads: its name, where it is and a same-length edit.
type StampedFile = (&'static str, fn(&Home) -> PathBuf, fn(&str) -> String);

#[test]
fn cached_verification_is_redone_for_each_approval_and_issuer_file() {
    // Each of these files is read by verify and stamped by the cache. A home
    // with a signed approval decision, so the approval journal and the
    // approver pin are both checked.
    let files: [StampedFile; 3] = [
        (
            "approvals/journal.jsonl",
            |home| home.root.join("approvals").join("journal.jsonl"),
            |text| flip_hex_after(text, r#""signature":""#),
        ),
        (
            "approver-public-key.hex",
            |home| home.approver_pin(),
            |text| flip_hex_after(text, ""),
        ),
        (
            "issuer-pins.jsonl",
            |home| home.issuer_pins(),
            |text| flip_hex_after(text, r#""public_key":""#),
        ),
    ];
    for (name, path, edit) in files {
        let (_temp, home) = home_with_receipts();
        let pending = praetore_mcp::approvals::list_pending(&home).unwrap();
        assert_eq!(pending.len(), 1);
        praetore_mcp::approvals::decide(
            &home,
            &pending[0].approval_id,
            praetore_mcp::approvals::HumanOutcome::Approve,
            None,
        )
        .unwrap();
        let mut cache = dashboard::Cache::default();
        let (_, state) = api(&home, &mut cache, "");
        assert_eq!(
            state["verify"]["status"], "ok",
            "{name}: {}",
            state["verify"]
        );
        api(&home, &mut cache, "?decision=DENY");
        assert_eq!(cache.verifications(), 1, "{name}: nothing changed");

        // Same length, same modification time.
        rewrite_keeping_mtime(&path(&home), edit);
        let (_, state) = api(&home, &mut cache, "");
        assert_eq!(
            cache.verifications(),
            2,
            "{name} changed but was not verified again"
        );
        // verify fails (approval files) or cannot run (issuer pin): not OK.
        assert_ne!(
            state["verify"]["status"], "ok",
            "{name}: {}",
            state["verify"]
        );
        assert_eq!(
            state["verify"],
            dashboard::state(&home, None)["verify"],
            "{name}: the cached result is what a fresh read gives"
        );
    }
}

#[test]
fn pending_calls_are_marked_unsigned_and_carry_their_receipt() {
    let (_temp, home) = home_with_receipts();
    let (_, state) = api(&home, &mut dashboard::Cache::default(), "");
    let pending = state["pending"].as_array().unwrap();
    assert_eq!(pending.len(), 1, "{}", state["pending"]);
    // A pending file is not signed and verify does not check it.
    assert_eq!(pending[0]["signed"], false);
    assert_eq!(state["summary"]["pending_unsigned"], 1);
    assert_eq!(dashboard::state(&home, None)["pending"][0]["signed"], false);
    // The page labels it, from that field.
    let js = include_str!("../src/dashboard/app.js");
    assert!(
        js.contains("p.signed === false"),
        "app.js does not read signed"
    );
    assert!(js.contains("unsigned_tag") && js.contains("unsigned_note"));
    let receipt = &pending[0]["receipt"];
    assert_eq!(receipt["evidence_id"], pending[0]["evidence_id"]);
    assert_eq!(receipt["decision"], "REQUIRE_APPROVAL");
    assert_eq!(receipt["verified"], true);
}

#[test]
fn api_receipt_returns_one_receipt_by_evidence_id() {
    let (_temp, home) = home_with_receipts();
    let state = dashboard::state(&home, None);
    let id = state["receipts"][2]["evidence_id"].as_str().unwrap();
    let get = |target: &str| {
        dashboard::respond(
            &format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:8787\r\n\r\n"),
            &home,
            None,
            8787,
        )
    };
    let found = get(&format!("/api/receipt?id={id}"));
    assert_eq!(found.status, 200);
    let receipt: Value = serde_json::from_slice(&found.body).unwrap();
    assert_eq!(receipt["evidence_id"], id);
    assert_eq!(receipt["tool"], "move_file");
    for missing in [
        "/api/receipt?id=nope",
        "/api/receipt",
        "/api/receipt?id=%ZZ",
    ] {
        assert_eq!(get(missing).status, 404, "{missing}");
    }
}

#[test]
fn receipts_say_what_decided_them() {
    let (_temp, home) = home_with_receipts();
    let state = dashboard::state(&home, None);
    let by_tool = |tool: &str| {
        state["receipts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["tool"] == tool)
            .unwrap()
            .clone()
    };
    assert_eq!(
        by_tool("echo")["decided_by"],
        json!({"kind": "rule", "rule_id": "allow-all-mcp-tool-calls"})
    );
    assert_eq!(
        by_tool("delete_file")["decided_by"],
        json!({"kind": "rule", "rule_id": "deny-delete"})
    );
    assert!(
        by_tool("delete_file")["reason"]
            .as_str()
            .unwrap()
            .contains("deny-delete")
    );

    // `init` writes a default-deny policy: a call no rule covers.
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let dir = root.to_str().unwrap();
    assert!(run(&["init", "--dir", dir], "").status.success());
    let calls = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}),
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
    let state = dashboard::state(&Home::new(root), None);
    let receipt = &state["receipts"][0];
    assert_eq!(receipt["decision"], "DENY");
    assert_eq!(receipt["rule"], Value::Null);
    assert_eq!(receipt["decided_by"], json!({"kind": "default_deny"}));

    // The page explains each kind from that field.
    let js = include_str!("../src/dashboard/app.js");
    for kind in [
        "\"rule\"",
        "\"unbound_rule\"",
        "\"default_deny\"",
        "\"engine_guard\"",
    ] {
        assert!(
            js.contains(&format!("by.kind === {kind}")),
            "app.js: {kind}"
        );
    }
}

/// WCAG relative luminance of `#rrggbb`.
fn luminance(hex: &str) -> f64 {
    let channel = |i: usize| {
        let c = f64::from(u8::from_str_radix(&hex[1 + 2 * i..3 + 2 * i], 16).unwrap()) / 255.0;
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(0) + 0.7152 * channel(1) + 0.0722 * channel(2)
}

/// `--name: #hex;` tokens of the first block after `marker` in `css`.
fn color_tokens(css: &str, marker: &str) -> BTreeMap<String, String> {
    let block = &css[css.find(marker).unwrap()..];
    let block = &block[..block.find('}').unwrap()];
    let block = &block[block.rfind('{').unwrap() + 1..];
    // Without comments.
    let mut text = String::new();
    let mut rest = block;
    while let Some(start) = rest.find("/*") {
        text.push_str(&rest[..start]);
        rest = rest[start..]
            .split_once("*/")
            .map_or("", |(_, after)| after);
    }
    text.push_str(rest);
    text.split(';')
        .filter_map(|decl| {
            let (name, value) = decl.trim().split_once(':')?;
            let value = value.trim();
            (name.starts_with("--") && value.starts_with('#') && value.len() == 7)
                .then(|| (name.to_owned(), value.to_owned()))
        })
        .collect()
}

#[test]
fn page_meets_basic_accessibility() {
    let html = include_str!("../src/dashboard/index.html");
    let js = include_str!("../src/dashboard/app.js");
    let css = include_str!("../src/dashboard/app.css");

    // Table headers say what they head, in the page and in tables built by
    // app.js.
    assert_eq!(
        html.matches("<th ").count(),
        html.matches("<th scope=\"col\"").count(),
        "a <th> without scope in index.html"
    );
    assert!(html.contains("<th scope=\"col\""));
    assert!(
        !js.contains("el(\"th\", {}"),
        "a <th> without scope in app.js"
    );

    // Every form control has a name: a <label for>, a wrapping <label> or
    // an aria-label set by app.js.
    for id in ["f-text", "f-tool", "f-from", "f-to"] {
        let labelled = html.contains(&format!("for=\"{id}\""))
            || html.split("<label").skip(1).any(|label| {
                label
                    .split("</label>")
                    .next()
                    .unwrap()
                    .contains(&format!("id=\"{id}\""))
            });
        assert!(labelled, "#{id} has no label");
    }
    for id in ["lang", "reload", "drawer-close", "f-decision"] {
        assert!(
            js.contains(&format!(
                "getElementById(\"{id}\").setAttribute(\"aria-label\""
            )),
            "#{id} has no aria-label"
        );
    }
    assert!(html.contains("id=\"load-error\" class=\"alert bad\" role=\"alert\""));
    assert!(html.contains("role=\"dialog\" aria-modal=\"true\""));

    // Rows and feed items that open a receipt are reached and opened by
    // keyboard; the drawer moves focus in and back out.
    assert!(js.contains("node.setAttribute(\"tabindex\", \"0\")"));
    assert!(js.contains("event.key !== \"Enter\" && event.key !== \" \""));
    assert_eq!(
        js.matches("activatable(el(\"tr\"").count(),
        2,
        "log and history rows"
    );
    assert!(js.contains("activatable(el(\"li\""), "feed items");
    assert!(js.contains("document.getElementById(\"drawer-close\").focus()"));
    assert!(js.contains("if (back) back.focus();"));
    assert!(js.contains("node.setAttribute(\"data-evidence-id\", evidenceId)"));
    assert!(js.contains("drawer.inert = true"));
    assert!(js.contains("\"aria-pressed\""));

    // Focus is visible: nothing removes the outline, rows have their own.
    assert!(!css.contains("outline: none"), "app.css hides a focus ring");
    assert!(css.contains("tr[tabindex]:focus-visible"));

    // One dark scheme; text colors reach 4.5:1 on both backgrounds.
    let tokens = color_tokens(css, ":root {");
    assert!(luminance(&tokens["--paper"]) < 0.01, "the page is dark");
    assert!(!css.contains("prefers-color-scheme"), "one scheme only");
    for (scheme, tokens) in [("dark", tokens)] {
        for fg in [
            "--ink", "--ink-2", "--quiet", "--accent", "--ok", "--hud", "--wall",
        ] {
            for bg in ["--paper", "--sheet"] {
                let (a, b) = (luminance(&tokens[fg]), luminance(&tokens[bg]));
                let ratio = (a.max(b) + 0.05) / (a.min(b) + 0.05);
                assert!(
                    ratio >= 4.5,
                    "{scheme}: {fg} {} on {bg} {} is {ratio:.2}:1",
                    tokens[fg],
                    tokens[bg]
                );
            }
        }
    }
}

#[test]
fn a_corrupt_or_truncated_journal_shows_an_error_and_the_server_keeps_serving() {
    let (_temp, home) = home_with_receipts();
    let file = receipts::read_journal(&home).unwrap()[0].file.clone();
    let listener = dashboard::bind(0).unwrap();
    let port = listener.local_addr().unwrap().port();
    let served_home = home.clone();
    let server = std::thread::spawn(move || {
        dashboard::serve(&listener, &served_home, None, Some(4)).unwrap();
    });
    let get = |target: &str| {
        let response = http(
            port,
            &format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        (head.to_owned(), body.to_owned())
    };

    // A last line cut in the middle of a write: listed, verify fails.
    let mut journal = fs::OpenOptions::new().append(true).open(&file).unwrap();
    journal.write_all(br#"{"seq":4,"prev":"ab"#).unwrap();
    let (head, body) = get("/api/state");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let state: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(state["verify"]["status"], "fail");
    assert_eq!(state["summary"]["unreadable"], 1);
    assert!(state["page"]["receipts"][0]["parse_error"].is_string());

    // Bytes that are not UTF-8: the journal cannot be read at all.
    journal.write_all(b"\n\xff\xfe\x00garbage\n").unwrap();
    let (head, body) = get("/api/state");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let state: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(state["verify"]["status"], "error");
    let error = state["verify"]["error"].as_str().unwrap();
    assert!(
        error.contains(file.to_str().unwrap()) && error.contains("UTF-8"),
        "{error}"
    );

    // The page says the journal could not be read, not that it is empty.
    let js = include_str!("../src/dashboard/app.js");
    assert!(js.contains("if (none && state.verify.status === \"error\")"));

    // Still serving.
    assert!(get("/api/state").0.starts_with("HTTP/1.1 200"));
    assert!(get("/").0.starts_with("HTTP/1.1 200"));
    server.join().unwrap();
}

#[test]
fn api_state_sends_the_40_most_recent_receipts_for_the_live_view() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let dir = root.to_str().unwrap();
    assert!(run(&["init", "--dir", dir], "").status.success());
    let mut input = json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}).to_string() + "\n";
    for id in 1..=45 {
        input += &format!(
            "{}\n",
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"echo","arguments":{"n": id}}})
        );
    }
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
    let (_, state) = api(&Home::new(root), &mut dashboard::Cache::default(), "");
    assert_eq!(state["summary"]["total"], 45);
    let recent = state["recent"].as_array().unwrap();
    assert_eq!(recent.len(), 40);
    assert_eq!(recent[0]["arguments"]["n"], 45, "newest first");
    assert_eq!(recent[39]["arguments"]["n"], 6);
}

/// Identifiers and punctuation of app.js, with comments, strings and
/// template literals left out. Enough to see calls and definitions.
fn js_tokens(js: &str) -> Vec<String> {
    let chars: Vec<char> = js.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else if c == '"' || c == '\'' || c == '`' {
            i += 1;
            while i < chars.len() && chars[i] != c {
                i += if chars[i] == '\\' { 2 } else { 1 };
            }
            i += 1;
            tokens.push("\"\"".to_owned());
        } else if c.is_alphabetic() || c == '_' || c == '$' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '$')
            {
                i += 1;
            }
            tokens.push(chars[start..i].iter().collect());
        } else if c == '=' && next == Some('>') {
            tokens.push("=>".to_owned());
            i += 2;
        } else {
            if !c.is_whitespace() {
                tokens.push(c.to_string());
            }
            i += 1;
        }
    }
    tokens
}

/// Names app.js calls as plain functions but never defines. A function
/// left out by an edit only fails when the page runs it, so look here.
fn undefined_calls(js: &str) -> Vec<String> {
    let tokens = js_tokens(js);
    let is_ident = |t: &str| {
        t.chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
    };
    let closing = |open: usize, step: isize| {
        let (a, b) = if step > 0 { ("(", ")") } else { (")", "(") };
        let mut depth = 0;
        let mut j = open as isize;
        while j >= 0 && (j as usize) < tokens.len() {
            let t = tokens[j as usize].as_str();
            if t == a {
                depth += 1;
            } else if t == b {
                depth -= 1;
                if depth == 0 {
                    return j as usize;
                }
            }
            j += step;
        }
        open
    };
    let mut defined = std::collections::BTreeSet::new();
    for (i, t) in tokens.iter().enumerate() {
        let t = t.as_str();
        if matches!(t, "function" | "const" | "let" | "var") {
            match tokens.get(i + 1).map(String::as_str) {
                Some("{" | "[") => {
                    for name in tokens[i + 2..]
                        .iter()
                        .take_while(|x| !matches!(x.as_str(), "}" | "]"))
                    {
                        defined.insert(name.clone());
                    }
                }
                Some(name) if is_ident(name) => {
                    defined.insert(name.to_owned());
                }
                _ => {}
            }
            if t == "function"
                && let Some(open) = (i + 1..tokens.len()).find(|&j| tokens[j] == "(")
            {
                for name in &tokens[open..closing(open, 1)] {
                    defined.insert(name.clone());
                }
            }
        } else if t == "=>" && i > 0 {
            if tokens[i - 1] == ")" {
                for name in &tokens[closing(i - 1, -1)..i] {
                    defined.insert(name.clone());
                }
            } else {
                defined.insert(tokens[i - 1].clone());
            }
        }
    }
    let builtin = [
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "typeof",
        "new",
        "function",
        "async",
        "await",
        "String",
        "Number",
        "Boolean",
        "Array",
        "Object",
        "JSON",
        "Math",
        "Date",
        "Set",
        "Map",
        "Promise",
        "Error",
        "RegExp",
        "parseInt",
        "parseFloat",
        "isNaN",
        "setTimeout",
        "clearTimeout",
        "setInterval",
        "clearInterval",
        "requestAnimationFrame",
        "cancelAnimationFrame",
        "fetch",
        "encodeURIComponent",
        "decodeURIComponent",
        "getComputedStyle",
        "URLSearchParams",
    ];
    let mut missing: Vec<String> = tokens
        .windows(3)
        .filter(|w| w[0] != "." && w[0] != "function" && is_ident(&w[1]) && w[2] == "(")
        .map(|w| w[1].clone())
        .filter(|name| !defined.contains(name) && !builtin.contains(&name.as_str()))
        .collect();
    missing.sort();
    missing.dedup();
    missing
}

#[test]
fn every_function_the_page_calls_is_defined() {
    let js = include_str!("../src/dashboard/app.js");
    assert_eq!(undefined_calls(js), Vec::<String>::new());
    // The check sees a function that is called but gone.
    let gone = js.replacen("function renderStats(", "function renderStatsGone(", 1);
    assert_eq!(undefined_calls(&gone), vec!["renderStats".to_owned()]);
}

#[test]
fn views_have_routes_and_old_links_still_land() {
    let html = include_str!("../src/dashboard/index.html");
    let js = include_str!("../src/dashboard/app.js");
    assert!(js.contains("const VIEWS = [\"home\", \"live\", \"chain\", \"info\"];"));
    assert!(
        js.contains("const INFO_TABS = [\"approvals\", \"policy\", \"integrity\", \"stats\"];")
    );
    for view in ["home", "live", "chain", "info"] {
        assert!(html.contains(&format!("<a href=\"#/{view}\" data-view=\"{view}\">")));
        assert!(html.contains(&format!("id=\"view-{view}\"")));
    }
    // Links from earlier versions of the page land on the view that took
    // their place.
    assert!(js.contains(
        "operation: [\"home\"], overview: [\"home\"], approvals: [\"live\"], activity: [\"chain\"],"
    ));
    for function in ["renderHome", "renderLive", "renderChain", "renderStats"] {
        assert!(
            js.split("function renderAll() {")
                .nth(1)
                .unwrap()
                .split("\n}\n")
                .next()
                .unwrap()
                .contains(&format!("{function}();")),
            "renderAll does not call {function}"
        );
    }
}

#[test]
fn hud_draws_only_what_the_journal_and_verify_say() {
    let js = include_str!("../src/dashboard/app.js");
    // Nothing made up: no randomness, no measure PRÆTORE does not take.
    assert!(!js.contains("Math.random"), "random values in the page");
    let lower = js.to_lowercase();
    for word in [
        "confianza",
        "salud",
        "health",
        "trust",
        "confidence",
        "inestab",
        "instab",
        "pensando",
        "thinking",
        "stress",
        "estrés",
    ] {
        assert!(
            !lower
                .lines()
                .any(|line| line.contains(word) && !line.trim_start().starts_with("//")),
            "app.js shows `{word}`"
        );
    }
    // The wall says what decided the call, from the receipt.
    assert!(js.contains("if (by && by.kind === \"default_deny\") return t(\"l_default_deny\");"));
    assert!(
        js.contains("if (by && by.kind === \"engine_guard\") return t(\"l_guard\", by.guard);")
    );
    assert!(js.contains(
        "if (by && (by.kind === \"rule\" || by.kind === \"unbound_rule\")) return t(\"l_rule\", by.rule_id);"
    ));
    assert!(js.contains("l_default_deny: \"default deny: ninguna regla lo permite\""));
    assert!(js.contains(
        "let text = r.decision === \"DENY\" ? wallText(r) : row.pending ? t(\"l_pending\")"
    ));
    // A pending call is said to be unsigned and not checked by verify, in
    // the drawing and in the list.
    assert!(js.contains("l_pending: \"pendiente · aviso sin firma · verify no lo comprueba\""));
    assert!(js.contains("waiting ? el(\"div\", { class: \"unsigned\" }, t(\"l_pending\")) : null"));
}

#[test]
fn motion_stops_when_the_system_asks_for_less() {
    let js = include_str!("../src/dashboard/app.js");
    let css = include_str!("../src/dashboard/app.css");
    assert!(js.contains("window.matchMedia(\"(prefers-reduced-motion: reduce)\")"));
    // The animation loop only asks for another frame when motion is wanted.
    let loops: Vec<&str> = js
        .lines()
        .filter(|l| l.contains("requestAnimationFrame(hudLoop)"))
        .collect();
    assert!(
        loops
            .iter()
            .any(|l| l.contains("!reducedMotion() && !document.hidden && hudBusy(now)"))
    );
    // New receipts are scanned and the read sweep runs only with motion.
    assert!(js.contains("if (!known.has(r.evidence_id) && fresh && !reducedMotion())"));
    assert!(js.contains("if (hud.readAt !== null && !reducedMotion())"));
    let reduce = css
        .split("@media (prefers-reduced-motion: reduce) {")
        .nth(1)
        .expect("no reduced-motion rule in app.css")
        .split('}')
        .next()
        .unwrap();
    assert!(reduce.contains("animation: none !important"), "{reduce}");
    assert!(reduce.contains("transition: none !important"), "{reduce}");
}

#[test]
fn drawings_have_a_text_alternative_and_a_list_view() {
    let html = include_str!("../src/dashboard/index.html");
    let js = include_str!("../src/dashboard/app.js");
    for canvas in ["hud", "chain"] {
        assert!(html.contains(&format!("<canvas id=\"{canvas}\" role=\"img\">")));
    }
    assert!(js.contains("canvas.setAttribute(\"aria-label\", t(\"l_label\""));
    assert!(
        js.contains(
            "document.getElementById(\"chain\").setAttribute(\"aria-label\", t(\"c_label\""
        )
    );
    // Visual and list switches say which one is on.
    assert!(js.contains(
        "button.setAttribute(\"aria-pressed\", liveMode === mode ? \"true\" : \"false\");"
    ));
    assert!(js.contains(
        "button.setAttribute(\"aria-pressed\", chainMode === mode ? \"true\" : \"false\");"
    ));
    for id in [
        "live-visual",
        "live-list",
        "chain-visual",
        "chain-list",
        "hud-list",
        "chain-table",
    ] {
        assert!(html.contains(&format!("id=\"{id}\"")), "#{id}");
    }
    // The list view is text: rows reached by keyboard, no canvas.
    let list = js
        .split("function hudList() {")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    assert!(list.contains("activatable("));
    assert!(!list.contains("getContext"));
}

#[test]
fn the_chain_is_cut_where_verify_fails_and_the_receipt_is_rebuilt() {
    let (_temp, home) = home_with_receipts();
    let file = receipts::read_journal(&home).unwrap()[0].file.clone();
    let original = fs::read_to_string(&file).unwrap();
    let mut lines: Vec<&str> = original.lines().collect();
    lines.remove(1);
    fs::write(&file, lines.join("\n") + "\n").unwrap();

    // What the diagram draws comes from the page sent to the browser: seq,
    // the prev hash link and, where verify fails, why.
    let (status, state) = api(&home, &mut dashboard::Cache::default(), "");
    assert_eq!(status, 200);
    let receipts = state["page"]["receipts"].as_array().unwrap();
    let cut: Vec<&Value> = receipts.iter().filter(|r| r["order"].is_string()).collect();
    assert_eq!(cut.len(), 1, "{receipts:?}");
    assert_eq!(cut[0]["verified"], false);
    for r in receipts {
        assert!(r["seq"].is_u64(), "{r}");
        assert!(r["prev"].is_string(), "{r}");
    }

    let js = include_str!("../src/dashboard/app.js");
    // The diagram cuts the link at that receipt and says why.
    assert!(js.contains("if (r.order) return r.order;"));
    assert!(js.contains("const cut = entry.kind === \"receipt\" ? breakReason(entry.r) : null;"));
    assert!(js.contains("ctx.fillText(clipText(ctx, `${t(\"c_cut\")}: ${cut}`"));
    // The drawer rebuilds the receipt with seq, prev and verify's result.
    let drawer = js
        .split("function drawerSummary(")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    assert!(drawer.contains("const cut = breakReason(r);"));
    for field in [
        "t(\"f_tool\")",
        "t(\"why\"), whyBlock(r)",
        "t(\"f_mode\")",
        "t(\"f_local\")",
        "t(\"f_utc\")",
        "t(\"f_evidence\")",
        "t(\"f_seq\")",
        "t(\"f_prev\"), r.prev",
        "t(\"f_verified\")",
    ] {
        assert!(drawer.contains(field), "drawer has no {field}");
    }
    assert!(drawer.contains("el(\"pre\", { class: \"json\" }, argsText(r.arguments))"));
}
