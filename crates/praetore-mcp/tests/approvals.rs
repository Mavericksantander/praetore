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

/// `value` quoted for a POSIX shell, as praetore-mcp prints paths.
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// How printed commands start: the binary's canonical path, quoted.
fn program() -> String {
    quote(fs::canonicalize(bin()).unwrap().to_str().unwrap())
}

/// The `--dir` value of printed commands: the canonical home, quoted.
fn quoted_dir(home: &Home) -> String {
    quote(fs::canonicalize(&home.root).unwrap().to_str().unwrap())
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
    approve_on_tty_with(home, id, &|| {})
}

/// Like [`approve_on_tty`], and runs `before_code` after the call is printed
/// and before the confirmation code is typed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn approve_on_tty_with(home: &Home, id: &str, before_code: &dyn Fn()) -> Output {
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
            before_code();
            break Some(code.to_owned());
        }
        if started.elapsed() > Duration::from_secs(10) {
            panic!(
                "timed out waiting for the confirmation code:\n{}",
                String::from_utf8_lossy(&buf)
            );
        }
        if let Some(status) = child.try_wait().unwrap() {
            return Output {
                status,
                stdout: buf,
                stderr: Vec::new(),
            };
        }
        thread::sleep(Duration::from_millis(20));
    };
    let Some(code) = code else {
        // `approve` exited before asking for the code (an unknown or expired
        // id): what it wrote is in `buf`.
        let status = child.wait().unwrap();
        return Output {
            status,
            stdout: buf,
            stderr: Vec::new(),
        };
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
    // The commands name the running binary and the home by absolute paths,
    // quoted for a POSIX shell, so they run as printed off PATH.
    let approve = format!("{} approve {id} --dir {}", program(), quoted_dir(&home));
    let reject = format!("{} reject {id} --dir {}", program(), quoted_dir(&home));
    assert!(text.contains(&format!("\n{approve}\n")), "{text}");
    assert!(text.contains(&format!("\n{reject}\n")), "{text}");
    assert!(text.contains("Expires (UTC): "), "{text}");
    assert!(text.contains(" local time (UTC"), "{text}");
    assert!(text.contains(" UTC (in "), "{text}");
    let listed = run(&["approvals", "--dir", home.root.to_str().unwrap()], "");
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(
        listed.contains(&format!("approve    {approve}\n")),
        "{listed}"
    );
    assert!(
        listed.contains(&format!("reject     {reject}\n")),
        "{listed}"
    );
    // The dashboard sends the same commands for the binary that serves it
    // (here the test binary); the page shows and copies them unchanged.
    let state = praetore_mcp::dashboard::state(&home, None);
    let served = praetore_mcp::commands::program();
    assert!(served.starts_with("'/"), "{served}");
    assert_eq!(
        state["pending"][0]["commands"]["approve"],
        format!("{served} approve {id} --dir {}", quoted_dir(&home)).as_str()
    );
    assert_eq!(
        state["pending"][0]["commands"]["reject"],
        format!("{served} reject {id} --dir {}", quoted_dir(&home)).as_str()
    );
    // As printed, through sh with an empty PATH, the reject command runs.
    let ran = Command::new("/bin/sh")
        .arg("-c")
        .arg(&reject)
        .env("PATH", "")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(ran.status.success(), "{reject}\n{ran:?}");
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains(&format!("reject {id}")),
        "{ran:?}"
    );
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
        approved_text.contains("Now run the agent again before ")
            && approved_text.contains(" (local time) / ")
            && approved_text.contains(" UTC so the call runs once."),
        "{approved_text}"
    );
    let before_code = approved_text.split("confirmation:").next().unwrap();
    assert!(
        before_code.contains("tool") && before_code.contains("echo"),
        "{before_code}"
    );
    assert!(before_code.contains("\"a\":2"), "{before_code}");
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
    // The exit code of a refused approve is 2, as before.
    assert_eq!(expired.status.code(), Some(2), "{text}");
    assert!(text.contains("this approval expired at "), "{text}");
    assert!(text.contains(" (local time) / "), "{text}");
    assert!(
        text.contains("run the agent again so the call is held again"),
        "{text}"
    );
    assert!(text.contains("nothing was signed"), "{text}");
    assert!(!text.contains("confirmation:"), "asked for a code: {text}");
    assert!(!home.root.join("approvals").join("journal.jsonl").exists());
    assert!(home.approvals_pending(&id), "the pending file is kept");

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
    // `init` writes a default-deny policy; allow the tool this test calls.
    let out = run(
        &[
            "policy",
            "allow",
            "--id",
            "allow-echo",
            "--tool",
            "echo",
            "--dir",
            home.root.to_str().unwrap(),
        ],
        "",
    );
    assert!(out.status.success(), "{out:?}");
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn pending_changed_after_it_was_shown_is_not_signed() {
    let (_temp, home) = init_home();
    require_echo(&home);
    let (responses, stderr, _) = wrap(
        &home,
        "enforce",
        &session(echo(7, json!({"note": "shown"}))),
        &[],
    );
    assert!(!stderr.contains("EXECUTED echo"), "{stderr}");
    let id = approval_id_from(tool_text(by_id(&responses, 7)));
    let path = home
        .root
        .join("approvals")
        .join("pending")
        .join(format!("{id}.json"));
    let approved = approve_on_tty_with(&home, &id, &|| {
        let text = fs::read_to_string(&path).unwrap();
        let edited = text.replace("\"shown\"", "\"changed\"");
        assert_ne!(edited, text);
        fs::write(&path, edited).unwrap();
    });
    let text = String::from_utf8_lossy(&approved.stdout);
    let before = text.split("confirmation:").next().unwrap();
    assert!(
        before.contains("echo") && before.contains("shown"),
        "{before}"
    );
    assert!(!approved.status.success(), "{text}");
    assert!(text.contains("changed after it was shown"), "{text}");
    assert!(path.is_file(), "pending file was removed");
    assert!(!home.root.join("approvals").join("journal.jsonl").exists());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn edited_pending_is_not_signed_and_the_edited_call_is_not_forwarded() {
    let (_temp, home) = init_home();
    require_echo(&home);
    let (responses, stderr, _) = wrap(
        &home,
        "enforce",
        &session(echo(7, json!({"note": "benign"}))),
        &[],
    );
    assert!(!stderr.contains("EXECUTED echo"), "{stderr}");
    let id = approval_id_from(tool_text(by_id(&responses, 7)));
    let path = home
        .root
        .join("approvals")
        .join("pending")
        .join(format!("{id}.json"));
    let original = fs::read_to_string(&path).unwrap();
    let edited = original.replace("\"benign\"", "\"EVIL\"");
    assert_ne!(edited, original);
    fs::write(&path, &edited).unwrap();

    let approved = approve_on_tty(&home, &id);
    let text = String::from_utf8_lossy(&approved.stdout);
    assert!(!approved.status.success(), "{text}");
    assert!(
        text.contains("nothing was signed") && text.contains("kept"),
        "{text}"
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), edited);

    let (responses, stderr, _) = wrap(
        &home,
        "enforce",
        &session(echo(8, json!({"note": "EVIL"}))),
        &[],
    );
    assert_eq!(stderr.matches("EXECUTED echo").count(), 0, "{stderr}");
    assert_eq!(by_id(&responses, 8)["result"]["isError"], true);
    assert!(!home.root.join("approvals").join("journal.jsonl").exists());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn verify_rejects_an_execution_after_the_approval_window() {
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
    let held = evidence(&home)
        .into_iter()
        .find(|item| item.decision.outcome == DecisionOutcome::RequireApproval)
        .unwrap();
    praetore_mcp::approvals::record_duplicate_execution(&home, &id, &held).unwrap();
    let checked = verify(&home);
    let report = String::from_utf8_lossy(&checked.stdout);
    assert_eq!(checked.status.code(), Some(1), "{report}");
    assert!(report.contains("outside the approval window"), "{report}");
}

#[test]
fn approvals_show_the_expiry_in_local_time_with_utc_and_what_is_left() {
    let (_temp, home) = init_home();
    require_echo(&home);
    let (responses, _, _) = wrap(&home, "enforce", &session(echo(7, json!({"n": 1}))), &[]);
    let id = approval_id_from(tool_text(by_id(&responses, 7)));
    let file: Value = serde_json::from_str(
        &fs::read_to_string(
            home.root
                .join("approvals")
                .join("pending")
                .join(format!("{id}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    let utc = file["expires_at"].as_str().unwrap();
    // 2026-11-15T23:34:40Z -> "2026-11-15 23:34:40"
    let utc_text = utc.trim_end_matches('Z').replace('T', " ");
    let listed = run_env(
        &["approvals", "--dir", home.root.to_str().unwrap()],
        "",
        &[("TZ", "Asia/Kolkata")],
    );
    let text = String::from_utf8_lossy(&listed.stdout);
    let line = text
        .lines()
        .find(|line| line.starts_with("expires    "))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(line.contains(" local time (UTC+05:30) / "), "{line}");
    assert!(line.contains(&format!(" / {utc_text} UTC (in ")), "{line}");
    assert!(line.contains(" min ") && line.ends_with(" s)"), "{line}");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn the_status_tells_an_expired_unused_approval_from_an_executed_one() {
    // Approved, then expired before any retry ran.
    let (_temp, home) = init_home();
    require_echo(&home);
    let env = [("PRAETORE_MCP_APPROVAL_TTL_SECONDS", "3")];
    let (responses, _, _) = wrap(&home, "enforce", &session(echo(7, json!({"n": 1}))), &env);
    let id = approval_id_from(tool_text(by_id(&responses, 7)));
    assert!(approve_on_tty(&home, &id).status.success());
    let held = held_evidence_id(&home);
    let status = praetore_mcp::approvals::status_by_evidence(&home).unwrap();
    assert!(status[&held].starts_with("approve by "), "{status:?}");
    assert!(!status[&held].contains(','), "still usable: {status:?}");
    thread::sleep(Duration::from_secs(4));
    let status = praetore_mcp::approvals::status_by_evidence(&home).unwrap();
    assert!(status[&held].ends_with(", expired unused"), "{status:?}");
    let state = praetore_mcp::dashboard::state(&home, None);
    let row = state["receipts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["evidence_id"] == held.as_str())
        .unwrap();
    assert!(
        row["approval"]
            .as_str()
            .unwrap()
            .ends_with(", expired unused"),
        "{row}"
    );

    // Approved and retried in time: executed, not expired.
    let (_temp, home) = init_home();
    require_echo(&home);
    let env = [("PRAETORE_MCP_APPROVAL_TTL_SECONDS", "3")];
    let (responses, _, _) = wrap(&home, "enforce", &session(echo(7, json!({"n": 1}))), &env);
    let id = approval_id_from(tool_text(by_id(&responses, 7)));
    assert!(approve_on_tty(&home, &id).status.success());
    let (_, stderr, _) = wrap(&home, "enforce", &session(echo(8, json!({"n": 1}))), &[]);
    assert_eq!(stderr.matches("EXECUTED echo").count(), 1, "{stderr}");
    thread::sleep(Duration::from_secs(4));
    let held = held_evidence_id(&home);
    let status = praetore_mcp::approvals::status_by_evidence(&home).unwrap();
    assert!(status[&held].ends_with(", executed once"), "{status:?}");
    assert!(status.values().any(|v| v == "executed once"), "{status:?}");
    assert!(
        !status.values().any(|v| v.contains("expired")),
        "{status:?}"
    );
}

/// The evidence id of the held (REQUIRE_APPROVAL) receipt.
fn held_evidence_id(home: &Home) -> String {
    evidence(home)
        .into_iter()
        .find(|item| item.decision.outcome == DecisionOutcome::RequireApproval)
        .unwrap()
        .evidence_id
        .to_string()
}

/// `reject` of a call that expired undecided signs nothing: exit 2, the
/// reason, and no approval journal. The CLI checks nothing before
/// `approvals::decide` for a rejection, so this is the guard in `decide`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn reject_of_an_expired_pending_call_signs_nothing() {
    let (_temp, home) = init_home();
    require_echo(&home);
    let env = [("PRAETORE_MCP_APPROVAL_TTL_SECONDS", "1")];
    let (responses, _, _) = wrap(&home, "enforce", &session(echo(7, json!({"n": 1}))), &env);
    let id = approval_id_from(tool_text(by_id(&responses, 7)));
    // Past the one second the call was held for.
    thread::sleep(Duration::from_secs(2));
    let out = run(&["reject", &id, "--dir", home.root.to_str().unwrap()], "");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("nothing left to reject"), "{stderr}");
    assert!(stderr.contains("nothing was signed"), "{stderr}");
    assert!(!home.root.join("approvals").join("journal.jsonl").exists());
}

/// `approvals::decide` itself refuses an expired pending call, for approve
/// as for reject, without the CLI's check before the confirmation code.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn decide_refuses_an_expired_pending_call_without_the_cli_check() {
    use praetore_mcp::approvals::{self, HumanOutcome};
    let (_temp, home) = init_home();
    require_echo(&home);
    let (responses, _, _) = wrap(&home, "enforce", &session(echo(7, json!({"n": 1}))), &[]);
    let id = approval_id_from(tool_text(by_id(&responses, 7)));
    let path = home
        .root
        .join("approvals")
        .join("pending")
        .join(format!("{id}.json"));
    let mut pending: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    pending["expires_at"] = json!("2000-01-01T00:00:00Z");
    fs::write(&path, serde_json::to_vec(&pending).unwrap()).unwrap();
    for outcome in [HumanOutcome::Approve, HumanOutcome::Reject] {
        let error = approvals::decide(&home, &id, outcome, None).unwrap_err();
        assert!(
            error.contains("expired") && error.contains("nothing was signed"),
            "{error}"
        );
    }
    assert!(!home.root.join("approvals").join("journal.jsonl").exists());
    assert!(path.is_file(), "the pending file is kept");
}

/// The boundary of the one expiry rule: at `expires_at` exactly the call
/// can still be decided, one nanosecond later it cannot. The offset of
/// `expires_at` does not change the instant. An `expires_at` that is not
/// RFC 3339 (no offset, empty, not a date) counts as expired.
#[test]
#[expect(clippy::disallowed_methods, reason = "checks the time at() reads")]
fn expiry_is_strictly_after_expires_at_whatever_the_offset() {
    use praetore_mcp::approvals::Expiry;
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
    let now = OffsetDateTime::now_utc();
    for text in [
        "2026-11-16T05:00:00Z",
        "2026-11-16T02:00:00-03:00",
        "2026-11-16T10:30:00+05:30",
    ] {
        let expiry = Expiry::parse(text);
        let at = OffsetDateTime::parse(text, &Rfc3339).unwrap();
        assert_eq!(expiry.at(), Some(at));
        assert!(!expiry.is_expired_at(at), "{text}: at expires_at");
        assert!(
            expiry.is_expired_at(at + time::Duration::nanoseconds(1)),
            "{text}: 1 ns later"
        );
        assert!(
            !expiry.is_expired_at(at - time::Duration::seconds(1)),
            "{text}: 1 s before"
        );
        // The same instant in UTC.
        let utc = at.to_offset(time::UtcOffset::UTC);
        assert!(!expiry.is_expired_at(utc));
        assert!(expiry.is_expired_at(utc + time::Duration::nanoseconds(1)));
    }
    for text in ["2026-11-16T05:00:00", "", "not a date"] {
        let expiry = Expiry::parse(text);
        assert_eq!(expiry.at(), None, "{text:?}");
        assert!(expiry.is_expired_at(now), "{text:?}");
        assert_eq!(expiry.text(), text);
    }
}

/// The same call held again after its pending call expired gets a new
/// approval id: an expired pending call is not reused, whether its
/// `expires_at` is a past time or cannot be read.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn the_same_call_after_its_pending_call_expired_is_held_with_a_new_id() {
    let (_temp, home) = init_home();
    require_echo(&home);
    let (responses, _, _) = wrap(&home, "enforce", &session(echo(7, json!({"n": 1}))), &[]);
    let mut current = approval_id_from(tool_text(by_id(&responses, 7)));
    // Held again while it is still open: the same id.
    let (responses, _, _) = wrap(&home, "enforce", &session(echo(8, json!({"n": 1}))), &[]);
    assert_eq!(approval_id_from(tool_text(by_id(&responses, 8))), current);
    for (id, expires_at) in [(9, "2000-01-01T00:00:00Z"), (10, "not a time")] {
        let path = home
            .root
            .join("approvals")
            .join("pending")
            .join(format!("{current}.json"));
        let mut pending: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        pending["expires_at"] = json!(expires_at);
        fs::write(&path, serde_json::to_vec(&pending).unwrap()).unwrap();
        let (responses, _, _) = wrap(&home, "enforce", &session(echo(id, json!({"n": 1}))), &[]);
        let next = approval_id_from(tool_text(by_id(&responses, id)));
        assert_ne!(
            next, current,
            "{expires_at}: an expired pending call was reused"
        );
        assert!(home.approvals_pending(&next), "{expires_at}");
        current = next;
    }
}

/// `approve` on a terminal for a pending call whose `expires_at` cannot be
/// read: refused before the confirmation code, as an expired call, by the
/// same rule as `decide` (`Expiry::is_expired_at`).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn approve_of_a_pending_call_with_an_unreadable_expiry_asks_for_no_code() {
    let (_temp, home) = init_home();
    require_echo(&home);
    let (responses, _, _) = wrap(&home, "enforce", &session(echo(7, json!({"n": 1}))), &[]);
    let id = approval_id_from(tool_text(by_id(&responses, 7)));
    let path = home
        .root
        .join("approvals")
        .join("pending")
        .join(format!("{id}.json"));
    let mut pending: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    pending["expires_at"] = json!("not a time");
    fs::write(&path, serde_json::to_vec(&pending).unwrap()).unwrap();
    let out = approve_on_tty(&home, &id);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("expired at an unreadable time"), "{text}");
    assert!(text.contains("nothing was signed"), "{text}");
    assert!(!text.contains("confirmation:"), "asked for a code: {text}");
    assert!(!home.root.join("approvals").join("journal.jsonl").exists());
    assert!(home.approvals_pending(&id), "the pending file is kept");
}

/// A `decide` cut between appending the decision and removing the pending
/// file leaves both. Seeded here with the real `decide` and the pending
/// file written back. The same call held again must not get the decided
/// id (it could never be decided again, so the call would be stuck until
/// it expired), and the rejected id is never executed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_decided_id_whose_pending_file_was_left_is_not_reused() {
    use praetore_mcp::approvals::{self, HumanOutcome};
    for outcome in [HumanOutcome::Reject, HumanOutcome::Approve] {
        let (_temp, home) = init_home();
        require_echo(&home);
        let (responses, _, _) = wrap(&home, "enforce", &session(echo(7, json!({"n": 1}))), &[]);
        let decided = approval_id_from(tool_text(by_id(&responses, 7)));
        let path = home
            .root
            .join("approvals")
            .join("pending")
            .join(format!("{decided}.json"));
        let pending = fs::read(&path).unwrap();
        approvals::decide(&home, &decided, outcome, None).unwrap();
        assert!(!path.exists());
        fs::write(&path, &pending).unwrap();

        // An approval is used once: the first retry runs, then the call is
        // held again. A rejection runs nothing.
        let mut next_id = 8;
        if outcome == HumanOutcome::Approve {
            let (_, stderr, _) = wrap(&home, "enforce", &session(echo(8, json!({"n": 1}))), &[]);
            assert_eq!(stderr.matches("EXECUTED echo").count(), 1, "{stderr}");
            next_id = 9;
        }
        let (responses, stderr, _) = wrap(
            &home,
            "enforce",
            &session(echo(next_id, json!({"n": 1}))),
            &[],
        );
        assert_eq!(stderr.matches("EXECUTED echo").count(), 0, "{stderr}");
        let text = tool_text(by_id(&responses, next_id));
        let held = approval_id_from(text);
        assert_ne!(
            held, decided,
            "{outcome:?}: the decided id was handed out again: {text}"
        );
        assert!(home.approvals_pending(&held));
        assert!(
            !path.exists(),
            "{outcome:?}: the decided id's pending file is left"
        );
        // The new id can be decided.
        approvals::decide(&home, &held, HumanOutcome::Reject, None).unwrap();
        let journal =
            fs::read_to_string(home.root.join("approvals").join("journal.jsonl")).unwrap();
        let executions_of_decided = journal
            .lines()
            .filter(|line| line.contains("\"execution\"") && line.contains(&decided))
            .count();
        let expected = usize::from(outcome == HumanOutcome::Approve);
        assert_eq!(executions_of_decided, expected, "{outcome:?}");
        let verify = verify(&home);
        assert!(
            verify.status.success(),
            "{}",
            String::from_utf8_lossy(&verify.stdout)
        );
    }
}
