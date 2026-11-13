//! Local approval: hold, terminal approve/reject, one use, verify.

use praetore_core::{DecisionOutcome, Evidence, PolicyCondition, PolicyEffect, PolicyRule};
use praetore_mcp::{
    journal, receipts,
    store::{self, ACTION_TYPE, CAPABILITY, Home},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
    thread,
    time::Duration,
};

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

fn evidence(home: &Home) -> Vec<Evidence> {
    receipts::read_journal(home)
        .unwrap()
        .iter()
        .map(|line| journal::parse_line(&line.text).unwrap().evidence)
        .collect()
}

fn verify(home: &Home) -> Output {
    run(&["verify", "--dir", home.root.to_str().unwrap()], "")
}

/// Drives `approve` on a pseudo-terminal and types the code the command prints.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn approve_on_tty(home: &Home, id: &str) -> Output {
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let mut master_raw = -1;
    let mut slave_raw = -1;
    let rc = unsafe {
        libc::openpty(
            &mut master_raw,
            &mut slave_raw,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    let master = unsafe { OwnedFd::from_raw_fd(master_raw) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave_raw) };
    let slave_in = slave.try_clone().unwrap();
    let slave_out = slave.try_clone().unwrap();
    let mut child = Command::new(bin())
        .args(["approve", id, "--dir", home.root.to_str().unwrap()])
        .stdin(Stdio::from(slave_in))
        .stdout(Stdio::from(slave_out))
        .stderr(Stdio::from(slave))
        .spawn()
        .unwrap();
    let mut master = std::fs::File::from(master);
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0, "{}", std::io::Error::last_os_error());
    assert_eq!(
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0,
        "{}",
        std::io::Error::last_os_error()
    );

    let mut buf = Vec::new();
    let started = std::time::Instant::now();
    let code = loop {
        let mut chunk = [0u8; 1024];
        match master.read(&mut chunk) {
            Ok(0) => break None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.raw_os_error() == Some(libc::EIO) => break None,
            Err(error) => panic!("read pty: {error}"),
        }
        let text = String::from_utf8_lossy(&buf);
        if text.contains("confirmation:")
            && let Some(code) = text
                .split("Type ")
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
            && code.len() == 6
        {
            break Some(code.to_owned());
        }
        if started.elapsed() > Duration::from_secs(10) {
            panic!(
                "timed out waiting for the confirmation code:\n{}",
                String::from_utf8_lossy(&buf)
            );
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!(
                "approve exited {status} before prompting:\n{}",
                String::from_utf8_lossy(&buf)
            );
        }
        thread::sleep(Duration::from_millis(20));
    };
    let Some(code) = code else {
        panic!(
            "pty closed before the confirmation code:\n{}",
            String::from_utf8_lossy(&buf)
        );
    };
    master.write_all(format!("{code}\n").as_bytes()).unwrap();
    let started = std::time::Instant::now();
    loop {
        let mut chunk = [0u8; 1024];
        match master.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if child.try_wait().unwrap().is_some()
                    && started.elapsed() > Duration::from_millis(200)
                {
                    break;
                }
                if started.elapsed() > Duration::from_secs(10) {
                    panic!(
                        "timed out after typing the code:\n{}",
                        String::from_utf8_lossy(&buf)
                    );
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
            Err(error) => panic!("read pty: {error}"),
        }
    }
    let status = child.wait().unwrap();
    Output {
        status,
        stdout: buf,
        stderr: Vec::new(),
    }
}

#[test]
fn enforce_holds_the_call_and_names_the_exact_command() {
    let (_temp, home) = init_home();
    require_echo(&home);
    let (responses, stderr, out) = wrap(
        &home,
        "enforce",
        &session(echo(7, json!({"path": "/secret/a", "n": 1}))),
        &[],
    );
    assert!(out.status.success(), "{stderr}");
    assert!(!stderr.contains("EXECUTED echo"), "{stderr}");
    let text = tool_text(by_id(&responses, 7));
    assert!(text.contains("waiting for local human approval"), "{text}");
    assert_eq!(by_id(&responses, 7)["result"]["isError"], true);
    let id = approval_id_from(text);
    let dir = home.root.display().to_string();
    assert!(
        text.contains(&format!("praetore-mcp approve {id} --dir {dir}")),
        "{text}"
    );
    assert!(
        text.contains(&format!("praetore-mcp reject {id} --dir {dir}")),
        "{text}"
    );
    let listed = run(&["approvals", "--dir", home.root.to_str().unwrap()], "");
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(listed.contains(&id), "{listed}");
    assert!(listed.contains("fake"), "{listed}");
    assert!(listed.contains("echo"), "{listed}");
    assert!(listed.contains("expires"), "{listed}");
    let recorded = evidence(&home);
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0].decision.outcome,
        DecisionOutcome::RequireApproval
    );
    assert_eq!(recorded[0].context["praetore.mode"], "enforce");
    let verify = verify(&home);
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stdout)
    );
}

#[test]
fn init_adds_an_approver_key_without_replacing_an_existing_home() {
    let (_temp, home) = init_home();
    let receipt = home.receipts_dir().join("kept.jsonl");
    fs::write(&receipt, b"not a receipt, left untouched\n").unwrap();
    let agent_before = fs::read(home.agent_key()).unwrap();
    let issuer_before = fs::read(home.issuer_key()).unwrap();
    let attester_before = fs::read(home.attester_key()).unwrap();
    let approver_before = fs::read(home.approver_key()).unwrap();
    let secret = |bytes: &[u8]| {
        serde_json::from_slice::<Value>(bytes).unwrap()["secret_key_hex"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let approver_secret = secret(&approver_before);
    assert_ne!(approver_secret, secret(&agent_before));
    assert_ne!(approver_secret, secret(&issuer_before));
    assert_ne!(approver_secret, secret(&attester_before));
    assert_ne!(
        fs::read_to_string(home.approver_pin()).unwrap().trim(),
        fs::read_to_string(home.attester_pin()).unwrap().trim()
    );

    fs::remove_file(home.approver_key()).unwrap();
    fs::remove_file(home.approver_pin()).unwrap();
    let out = run(&["init", "--dir", home.root.to_str().unwrap()], "");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("added a local approver key"), "{text}");
    assert_eq!(fs::read(home.agent_key()).unwrap(), agent_before);
    assert_eq!(fs::read(home.issuer_key()).unwrap(), issuer_before);
    assert_eq!(fs::read(home.attester_key()).unwrap(), attester_before);
    assert_eq!(
        fs::read(&receipt).unwrap(),
        b"not a receipt, left untouched\n"
    );
    let added = fs::read(home.approver_key()).unwrap();
    assert_ne!(secret(&added), approver_secret);
    assert_ne!(secret(&added), secret(&agent_before));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(home.approver_key())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let again = run(&["init", "--dir", home.root.to_str().unwrap()], "");
    assert!(again.status.success(), "{again:?}");
    assert!(String::from_utf8_lossy(&again.stdout).contains("nothing was changed"));
    assert_eq!(fs::read(home.approver_key()).unwrap(), added);
    assert_eq!(
        fs::read(&receipt).unwrap(),
        b"not a receipt, left untouched\n"
    );
}

#[test]
fn approve_without_a_terminal_signs_nothing() {
    let (_temp, home) = init_home();
    require_echo(&home);
    let (responses, stderr, _) = wrap(&home, "enforce", &session(echo(7, json!({"n": 1}))), &[]);
    assert!(!stderr.contains("EXECUTED"), "{stderr}");
    let id = approval_id_from(tool_text(by_id(&responses, 7)));
    let out = run(
        &["approve", &id, "--dir", home.root.to_str().unwrap()],
        "ignored\n",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("interactive terminal"), "{stderr}");
    assert!(stderr.contains("cooperative"), "{stderr}");
    assert!(home.approvals_pending(&id), "pending file removed");
    let journal = home.root.join("approvals").join("journal.jsonl");
    assert!(
        !journal.exists(),
        "a decision was signed without a terminal"
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn approved_call_forwards_once_and_a_second_retry_asks_again() {
    let (_temp, home) = init_home();
    require_echo(&home);
    let first_args = json!({"b": 1, "a": 2});
    let (responses, stderr, _) = wrap(&home, "enforce", &session(echo(7, first_args)), &[]);
    assert!(!stderr.contains("EXECUTED echo"), "{stderr}");
    let id = approval_id_from(tool_text(by_id(&responses, 7)));

    let approved = approve_on_tty(&home, &id);
    let approved_text = String::from_utf8_lossy(&approved.stdout);
    assert!(approved.status.success(), "{approved_text}");
    assert!(
        approved_text.contains(&format!("approve {id}")),
        "{approved_text}"
    );
    assert!(!home.approvals_pending(&id));

    // Same arguments, different key order: one canonical call.
    let (responses, stderr, _) = wrap(
        &home,
        "enforce",
        &session(echo(8, json!({"a": 2, "b": 1}))),
        &[],
    );
    assert_eq!(stderr.matches("EXECUTED echo").count(), 1, "{stderr}");
    assert_eq!(
        by_id(&responses, 8)["result"]["isError"],
        false,
        "{responses:?}"
    );
    assert!(stderr.contains(&id), "{stderr}");

    let (responses, stderr, _) = wrap(
        &home,
        "enforce",
        &session(echo(9, json!({"a": 2, "b": 1}))),
        &[],
    );
    assert_eq!(stderr.matches("EXECUTED echo").count(), 0, "{stderr}");
    let again = approval_id_from(tool_text(by_id(&responses, 9)));
    assert_ne!(again, id);

    let table = run(&["receipts", "--dir", home.root.to_str().unwrap()], "");
    let table = String::from_utf8_lossy(&table.stdout);
    assert!(table.contains("approve by "), "{table}");
    assert!(table.contains("executed once"), "{table}");
    assert!(
        table.contains("pending") || table.contains("held"),
        "{table}"
    );

    let verify = verify(&home);
    let report = String::from_utf8_lossy(&verify.stdout);
    assert!(verify.status.success(), "{report}");
    assert!(report.contains("1 decision(s), 1 execution(s)"), "{report}");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn different_arguments_do_not_use_the_approval() {
    let (_temp, home) = init_home();
    require_echo(&home);
    let (responses, _, _) = wrap(
        &home,
        "enforce",
        &session(echo(7, json!({"path": "/secret/a"}))),
        &[],
    );
    let id = approval_id_from(tool_text(by_id(&responses, 7)));
    let approved = approve_on_tty(&home, &id);
    assert!(
        approved.status.success(),
        "{}",
        String::from_utf8_lossy(&approved.stdout)
    );

    let (responses, stderr, _) = wrap(
        &home,
        "enforce",
        &session(echo(8, json!({"path": "/secret/b"}))),
        &[],
    );
    assert_eq!(stderr.matches("EXECUTED echo").count(), 0, "{stderr}");
    assert_eq!(by_id(&responses, 8)["result"]["isError"], true);
    let other = approval_id_from(tool_text(by_id(&responses, 8)));
    assert_ne!(other, id);
    let verify = verify(&home);
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stdout)
    );
    assert!(
        String::from_utf8_lossy(&verify.stdout).contains("1 decision(s), 0 execution(s)"),
        "{}",
        String::from_utf8_lossy(&verify.stdout)
    );
}

#[test]
fn unknown_approval_id_is_rejected() {
    let (_temp, home) = init_home();
    let id = "ab".repeat(32);
    let out = run(&["approve", &id, "--dir", home.root.to_str().unwrap()], "");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // No pending call, so this fails before the terminal check only when the
    // id is malformed. A well-formed unknown id still needs a terminal for
    // `approve`, and then reports that nothing is pending.
    assert!(!out.status.success(), "{stderr}");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn unknown_id_on_a_terminal_is_not_signed() {
    let (_temp, home) = init_home();
    let id = "ab".repeat(32);
    let out = approve_on_tty(&home, &id);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("no pending approval"), "{text}");
    assert!(!home.root.join("approvals").join("journal.jsonl").exists());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn rejected_call_is_not_forwarded() {
    let (_temp, home) = init_home();
    require_echo(&home);
    let (responses, stderr, _) = wrap(&home, "enforce", &session(echo(7, json!({"n": 1}))), &[]);
    assert!(!stderr.contains("EXECUTED"), "{stderr}");
    let id = approval_id_from(tool_text(by_id(&responses, 7)));
    let out = run(&["reject", &id, "--dir", home.root.to_str().unwrap()], "");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains(&format!("reject {id}")), "{text}");

    let (responses, stderr, _) = wrap(&home, "enforce", &session(echo(8, json!({"n": 1}))), &[]);
    assert_eq!(stderr.matches("EXECUTED echo").count(), 0, "{stderr}");
    assert_eq!(by_id(&responses, 8)["result"]["isError"], true);
    let verify = verify(&home);
    let report = String::from_utf8_lossy(&verify.stdout);
    assert!(verify.status.success(), "{report}");
    assert!(report.contains("1 decision(s), 0 execution(s)"), "{report}");
    let table = run(&["receipts", "--dir", home.root.to_str().unwrap()], "");
    let table = String::from_utf8_lossy(&table.stdout);
    assert!(table.contains("reject by "), "{table}");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn expired_pending_and_expired_approval_do_not_pass() {
    let (_temp, home) = init_home();
    require_echo(&home);
    let env = [("PRAETORE_MCP_APPROVAL_TTL_SECONDS", "1")];
    let (responses, _, _) = wrap(&home, "enforce", &session(echo(7, json!({"n": 1}))), &env);
    let id = approval_id_from(tool_text(by_id(&responses, 7)));
    thread::sleep(Duration::from_secs(2));
    let expired = approve_on_tty(&home, &id);
    let text = String::from_utf8_lossy(&expired.stdout);
    assert!(!expired.status.success(), "{text}");
    assert!(text.contains("expired"), "{text}");
    assert!(!home.root.join("approvals").join("journal.jsonl").exists());

    let (_temp, home) = init_home();
    require_echo(&home);
    let env = [("PRAETORE_MCP_APPROVAL_TTL_SECONDS", "4")];
    let (responses, _, _) = wrap(&home, "enforce", &session(echo(7, json!({"n": 1}))), &env);
    let id = approval_id_from(tool_text(by_id(&responses, 7)));
    let approved = approve_on_tty(&home, &id);
    assert!(
        approved.status.success(),
        "{}",
        String::from_utf8_lossy(&approved.stdout)
    );
    thread::sleep(Duration::from_secs(5));
    let (responses, stderr, _) = wrap(&home, "enforce", &session(echo(8, json!({"n": 1}))), &[]);
    assert_eq!(stderr.matches("EXECUTED echo").count(), 0, "{stderr}");
    assert_eq!(by_id(&responses, 8)["result"]["isError"], true);
    let verify = verify(&home);
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stdout)
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn verify_rejects_a_bad_signature_and_a_reused_approval() {
    let (_temp, home) = init_home();
    require_echo(&home);
    let (responses, _, _) = wrap(&home, "enforce", &session(echo(7, json!({"n": 1}))), &[]);
    let id = approval_id_from(tool_text(by_id(&responses, 7)));
    assert!(approve_on_tty(&home, &id).status.success());
    let (_, stderr, _) = wrap(&home, "enforce", &session(echo(8, json!({"n": 1}))), &[]);
    assert_eq!(stderr.matches("EXECUTED echo").count(), 1, "{stderr}");
    assert!(verify(&home).status.success());

    let path = home.root.join("approvals").join("journal.jsonl");
    let original = fs::read(&path).unwrap();
    let mut tampered = original.clone();
    let marker = b"\"signature\":\"";
    let at = tampered
        .windows(marker.len())
        .rposition(|window| window == marker)
        .unwrap()
        + marker.len();
    tampered[at] = if tampered[at] == b'a' { b'b' } else { b'a' };
    fs::write(&path, &tampered).unwrap();
    let bad_signature = verify(&home);
    let report = String::from_utf8_lossy(&bad_signature.stdout);
    assert_eq!(bad_signature.status.code(), Some(1), "{report}");
    assert!(report.contains("signature"), "{report}");

    fs::write(&path, &original).unwrap();
    assert!(verify(&home).status.success());
    let executed = evidence(&home)
        .into_iter()
        .rfind(|item| item.decision.outcome == DecisionOutcome::RequireApproval)
        .unwrap();
    praetore_mcp::approvals::record_duplicate_execution(&home, &id, &executed).unwrap();
    let reused = verify(&home);
    let report = String::from_utf8_lossy(&reused.stdout);
    assert_eq!(reused.status.code(), Some(1), "{report}");
    assert!(report.contains("reused"), "{report}");
}

#[test]
fn observe_does_not_hold_and_the_receipt_says_enforce_would_ask() {
    let (_temp, home) = init_home();
    require_echo(&home);
    let (responses, stderr, _) = wrap(&home, "observe", &session(echo(7, json!({"n": 1}))), &[]);
    assert_eq!(stderr.matches("EXECUTED echo").count(), 1, "{stderr}");
    assert_eq!(by_id(&responses, 7)["result"]["isError"], false);
    assert!(!home.root.join("approvals").join("pending").exists() || dir_empty(&home));
    let recorded = evidence(&home);
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0].decision.outcome,
        DecisionOutcome::RequireApproval
    );
    assert_eq!(recorded[0].context["praetore.mode"], "observe");
    let table = run(&["receipts", "--dir", home.root.to_str().unwrap()], "");
    let table = String::from_utf8_lossy(&table.stdout);
    assert!(table.contains("enforce would ask"), "{table}");
    let verify = verify(&home);
    let report = String::from_utf8_lossy(&verify.stdout);
    assert!(verify.status.success(), "{report}");
    assert!(report.contains("approval journal: none"), "{report}");
}

fn dir_empty(home: &Home) -> bool {
    let pending = home.root.join("approvals").join("pending");
    !pending.exists() || fs::read_dir(&pending).unwrap().next().is_none()
}

#[test]
fn an_evidence_only_journal_still_verifies() {
    let (_temp, home) = init_home();
    let (_, stderr, _) = wrap(&home, "enforce", &session(echo(4, json!({"n": 1}))), &[]);
    assert!(stderr.contains("EXECUTED echo"), "{stderr}");
    assert!(!home.root.join("approvals").join("journal.jsonl").exists());
    let line = &receipts::read_journal(&home).unwrap()[0].text;
    let value: Value = serde_json::from_str(line).unwrap();
    assert!(value.get("evidence").is_some(), "{line}");
    assert!(value.get("record").is_none(), "{line}");
    let verify = verify(&home);
    let report = String::from_utf8_lossy(&verify.stdout);
    assert!(verify.status.success(), "{report}");
    assert!(
        report.contains("1 receipts: 1 verified, 0 failed"),
        "{report}"
    );
    assert!(report.contains("approval journal: none"), "{report}");
}
