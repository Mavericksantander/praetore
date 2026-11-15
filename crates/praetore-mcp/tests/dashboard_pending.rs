//! The dashboard lists calls waiting for approval and the policy rules,
//! read only: deciding stays with `approve` / `reject` in a terminal.

use praetore_core::{PolicyCondition, PolicyEffect, PolicyRule};
use praetore_mcp::{
    dashboard,
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

#[test]
fn state_lists_pending_calls_and_policy_rules() {
    let (_temp, home) = init_home();
    let id = held(&home, json!({"b": 1, "a": 2}));
    let get = format!("GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n\r\n");
    let response = dashboard::respond(&get, &home, None, PORT);
    assert_eq!(response.status, 200);
    let state: Value = serde_json::from_slice(&response.body).unwrap();
    let pending = &state["pending"][0];
    assert_eq!(pending["approval_id"], id.as_str());
    assert_eq!(pending["tool"], "echo");
    assert_eq!(pending["arguments_canonical"], "{\"a\":2,\"b\":1}");
    assert!(
        state["policy"]["rules_detail"]
            .as_array()
            .unwrap()
            .iter()
            .any(|rule| rule["id"] == "approve-echo")
    );
}

#[test]
fn post_is_refused_and_nothing_is_signed() {
    let (_temp, home) = init_home();
    let id = held(&home, json!({"a": 1}));
    let body = json!({"approval_id": id, "server": "fake", "tool": "echo"}).to_string();
    for path in ["/api/approve", "/api/reject", "/api/state", "/"] {
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nOrigin: http://127.0.0.1:{PORT}\r\nContent-Type: application/json\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n{body}",
            "ab".repeat(32),
            body.len()
        );
        let response = dashboard::respond(&request, &home, None, PORT);
        assert_eq!(response.status, 405, "{path}");
    }
    assert!(home.approvals_pending(&id));
    let out = verify(&home);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("approval journal: none"),
        "{out:?}"
    );
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
