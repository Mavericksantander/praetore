//! Approvals from the dashboard page (`dashboard --approvals`): what a
//! request needs before anything is signed, and that a decision from the
//! page is the same signed decision as `approve` / `reject`.

use praetore_core::{PolicyCondition, PolicyEffect, PolicyRule};
use praetore_mcp::{
    approvals, dashboard,
    store::{self, ACTION_TYPE, CAPABILITY, Home},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

const PORT: u16 = 8787;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_praetore-mcp")
}

fn fake_server() -> PathBuf {
    let path = PathBuf::from(bin())
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("fake_server{}", std::env::consts::EXE_SUFFIX));
    assert!(path.exists(), "{}", path.display());
    path
}

fn run(args: &[&str], stdin: &str) -> Output {
    run_env(args, stdin, &[])
}

fn run_env(args: &[&str], stdin: &str, env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(bin());
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    match input.write_all(stdin.as_bytes()) {
        Ok(()) => {}
        // `approve` exits before reading stdin when there is no terminal.
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(error) => panic!("write stdin: {error}"),
    }
    drop(input);
    child.wait_with_output().unwrap()
}

fn init_home() -> (tempfile::TempDir, Home) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let out = run(&["init", "--dir", root.to_str().unwrap()], "");
    assert!(out.status.success(), "{out:?}");
    (temp, Home::new(root))
}

fn require_echo(home: &Home) {
    let mut policy = store::default_policy();
    policy.rules.push(
        PolicyRule::new("approve-echo", ACTION_TYPE, PolicyEffect::RequireApproval)
            .with_capability(CAPABILITY)
            .with_parameter_condition(PolicyCondition::exact("tool", json!("echo"))),
    );
    fs::write(home.policy(), serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
}

fn session(call: Value) -> String {
    [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        call,
    ]
    .iter()
    .map(|line| format!("{line}\n"))
    .collect()
}

fn echo(id: i64, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": arguments}
    })
}

fn wrap(
    home: &Home,
    mode: &str,
    input: &str,
    env: &[(&str, &str)],
) -> (Vec<Value>, String, Output) {
    let server = fake_server();
    let args = [
        "wrap",
        "--dir",
        home.root.to_str().unwrap(),
        "--name",
        "fake",
        "--mode",
        mode,
        "--",
        server.to_str().unwrap(),
    ];
    let out = run_env(&args, input, env);
    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    let responses = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("bad line {line:?}: {e}")))
        .collect();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (responses, stderr, out)
}

fn by_id(responses: &[Value], id: i64) -> &Value {
    responses
        .iter()
        .find(|response| response["id"] == id)
        .unwrap_or_else(|| panic!("no response {id} in {responses:?}"))
}

fn tool_text(response: &Value) -> &str {
    response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no tool text in {response}"))
}

fn approval_id_from(text: &str) -> String {
    let rest = text
        .split("Approval id: ")
        .nth(1)
        .unwrap_or_else(|| panic!("no approval id in {text}"));
    let id = rest.split_whitespace().next().unwrap().to_owned();
    assert_eq!(id.len(), 64, "{id}");
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    id
}

fn verify(home: &Home) -> Output {
    run(&["verify", "--dir", home.root.to_str().unwrap()], "")
}

/// A held `echo` call; returns its approval id.
fn held(home: &Home, arguments: Value) -> String {
    require_echo(home);
    let (responses, stderr, _) = wrap(home, "enforce", &session(echo(7, arguments)), &[]);
    assert!(!stderr.contains("EXECUTED echo"), "{stderr}");
    approval_id_from(tool_text(by_id(&responses, 7)))
}

fn pending_entry(home: &Home, id: &str) -> Value {
    let state = dashboard::state(home, None);
    state["pending"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["approval_id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("{id} not pending in {}", state["pending"]))
}

fn body_for(pending: &Value) -> String {
    json!({
        "approval_id": pending["approval_id"],
        "server": pending["server"],
        "tool": pending["tool"],
        "evidence_id": pending["evidence_id"],
        "arguments_canonical": pending["arguments_canonical"],
    })
    .to_string()
}

fn post(path: &str, headers: &[(&str, &str)], body: &str) -> String {
    let mut request = format!("POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    request
}

fn good_headers(token: &str) -> Vec<(&'static str, String)> {
    vec![
        ("Origin", format!("http://127.0.0.1:{PORT}")),
        ("Content-Type", "application/json".to_owned()),
        ("Authorization", format!("Bearer {token}")),
    ]
}

fn send(
    home: &Home,
    session: Option<&dashboard::Session>,
    path: &str,
    headers: &[(&str, String)],
    body: &str,
) -> dashboard::Response {
    let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
    dashboard::respond_with(&post(path, &headers, body), home, None, session, PORT)
}

#[test]
fn read_only_server_refuses_post_even_with_a_token() {
    let (_temp, home) = init_home();
    let id = held(&home, json!({"a": 1}));
    let body = body_for(&pending_entry(&home, &id));
    let token = dashboard::Session::random().token_hex();
    let response = send(&home, None, "/api/approve", &good_headers(&token), &body);
    assert_eq!(response.status, 405);
    assert!(home.approvals_pending(&id));
    let state = dashboard::state(&home, None);
    assert!(state.get("approvals_from_page").is_none());
}

#[test]
fn each_missing_guard_is_refused_and_nothing_is_signed() {
    let (_temp, home) = init_home();
    let id = held(&home, json!({"a": 1}));
    let body = body_for(&pending_entry(&home, &id));
    let session = dashboard::Session::random();
    let token = session.token_hex();
    let good = good_headers(&token);
    let without = |name: &str| -> Vec<(&str, String)> {
        good.iter().filter(|(n, _)| *n != name).cloned().collect()
    };
    let replaced = |name: &'static str, value: &str| -> Vec<(&str, String)> {
        good.iter()
            .map(|(n, v)| {
                if *n == name {
                    (*n, value.to_owned())
                } else {
                    (*n, v.clone())
                }
            })
            .collect()
    };
    let other_token = dashboard::Session::random().token_hex();
    let cases: Vec<(Vec<(&str, String)>, u16)> = vec![
        (without("Origin"), 403),
        (replaced("Origin", "http://evil.example"), 403),
        (replaced("Origin", "http://127.0.0.1:9999"), 403),
        (without("Content-Type"), 415),
        (replaced("Content-Type", "text/plain"), 415),
        (without("Authorization"), 401),
        (
            replaced("Authorization", &format!("Bearer {other_token}")),
            401,
        ),
        (replaced("Authorization", "Bearer abc"), 401),
        (replaced("Authorization", &token), 401),
    ];
    for (headers, status) in cases {
        for path in ["/api/approve", "/api/reject"] {
            let response = send(&home, Some(&session), path, &headers, &body);
            assert_eq!(response.status, status, "{path} {headers:?}");
        }
    }
    // A foreign Host is refused before anything else.
    let headers: Vec<(&str, &str)> = good.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let request = post("/api/approve", &headers, &body)
        .replace(&format!("Host: 127.0.0.1:{PORT}"), "Host: evil.example");
    let response = dashboard::respond_with(&request, &home, None, Some(&session), PORT);
    assert_eq!(response.status, 403);

    assert!(home.approvals_pending(&id));
    let out = verify(&home);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("approval journal: none"),
        "{out:?}"
    );
}

#[test]
fn a_call_other_than_the_one_shown_is_not_signed() {
    let (_temp, home) = init_home();
    let id = held(&home, json!({"a": 1}));
    let session = dashboard::Session::random();
    let mut shown = pending_entry(&home, &id);
    shown["arguments_canonical"] = json!("{\"a\":2}");
    let response = send(
        &home,
        Some(&session),
        "/api/approve",
        &good_headers(&session.token_hex()),
        &body_for(&shown),
    );
    assert_eq!(response.status, 409);
    let text = String::from_utf8_lossy(&response.body);
    assert!(text.contains("changed after it was shown"), "{text}");
    assert!(home.approvals_pending(&id));
}

#[test]
fn approve_from_the_page_forwards_the_exact_call_once() {
    let (_temp, home) = init_home();
    let id = held(&home, json!({"b": 1, "a": 2}));
    let pending = pending_entry(&home, &id);
    assert_eq!(pending["arguments_canonical"], "{\"a\":2,\"b\":1}");
    let session = dashboard::Session::random();
    let response = send(
        &home,
        Some(&session),
        "/api/approve",
        &good_headers(&session.token_hex()),
        &body_for(&pending),
    );
    let text = String::from_utf8_lossy(&response.body).into_owned();
    assert_eq!(response.status, 200, "{text}");
    let reply: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(reply["outcome"], "approve");
    assert!(!home.approvals_pending(&id));
    assert!(approvals::list_pending(&home).unwrap().is_empty());

    // Deciding again is refused.
    let again = send(
        &home,
        Some(&session),
        "/api/approve",
        &good_headers(&session.token_hex()),
        &body_for(&pending),
    );
    assert_eq!(again.status, 409);

    let (responses, stderr, _) = wrap(
        &home,
        "enforce",
        &session_input(8, json!({"a": 2, "b": 1})),
        &[],
    );
    assert_eq!(stderr.matches("EXECUTED echo").count(), 1, "{stderr}");
    assert_eq!(
        by_id(&responses, 8)["result"]["isError"],
        false,
        "{responses:?}"
    );
    let (_, stderr, _) = wrap(
        &home,
        "enforce",
        &session_input(9, json!({"a": 2, "b": 1})),
        &[],
    );
    assert!(!stderr.contains("EXECUTED echo"), "{stderr}");

    let out = verify(&home);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("approval journal: 1 decision"), "{stdout}");
}

#[test]
fn reject_from_the_page_is_signed_and_not_forwarded() {
    let (_temp, home) = init_home();
    let id = held(&home, json!({"a": 1}));
    let pending = pending_entry(&home, &id);
    let session = dashboard::Session::random();
    let response = send(
        &home,
        Some(&session),
        "/api/reject",
        &good_headers(&session.token_hex()),
        &body_for(&pending),
    );
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    assert!(!home.approvals_pending(&id));
    let (_, stderr, _) = wrap(&home, "enforce", &session_input(8, json!({"a": 1})), &[]);
    assert!(!stderr.contains("EXECUTED echo"), "{stderr}");
    let out = verify(&home);
    assert!(out.status.success(), "{out:?}");
}

#[test]
fn state_lists_pending_and_says_whether_the_page_can_decide() {
    let (_temp, home) = init_home();
    let id = held(&home, json!({"a": 1}));
    let get = format!("GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n\r\n");
    let session = dashboard::Session::random();
    for (session, expected) in [(None, false), (Some(&session), true)] {
        let response = dashboard::respond_with(&get, &home, None, session, PORT);
        assert_eq!(response.status, 200);
        let state: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(state["approvals_from_page"], expected);
        assert_eq!(state["pending"][0]["approval_id"], id.as_str());
        assert_eq!(state["pending"][0]["tool"], "echo");
        assert!(
            state["policy"]["rules_detail"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["id"] == "approve-echo")
        );
    }
}

fn session_input(id: i64, arguments: Value) -> String {
    session(echo(id, arguments))
}

trait PendingPath {
    fn approvals_pending(&self, id: &str) -> bool;
}

impl PendingPath for Home {
    fn approvals_pending(&self, id: &str) -> bool {
        self.root
            .join("approvals")
            .join("pending")
            .join(format!("{id}.json"))
            .is_file()
    }
}
