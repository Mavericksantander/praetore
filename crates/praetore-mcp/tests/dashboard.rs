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
