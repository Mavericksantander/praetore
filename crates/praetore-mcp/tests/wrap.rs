//! End-to-end tests: `praetore-mcp wrap` in front of the `fake_server`
//! example (built by `cargo test` alongside the integration tests).

use praetore_core::{DecisionOutcome, Evidence, Policy, PolicyCondition, PolicyEffect, PolicyRule};
use praetore_mcp::{
    receipts,
    store::{self, ACTION_TYPE, CAPABILITY, DEFAULT_ALLOW_RULE, Home},
};
use serde_json::{Value, json};
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

fn init_home() -> (tempfile::TempDir, Home) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let out = run(&["init", "--dir", root.to_str().unwrap()], "");
    assert!(out.status.success(), "{out:?}");
    (temp, Home::new(root))
}

fn write_policy(home: &Home, extra: Vec<PolicyRule>) {
    let mut rules = vec![
        PolicyRule::new(DEFAULT_ALLOW_RULE, ACTION_TYPE, PolicyEffect::Allow)
            .with_capability(CAPABILITY),
    ];
    rules.extend(extra);
    let policy = mission_policy(Policy::new_v2("test-policy", 1, rules));
    fs::write(
        home.policy(),
        serde_json::to_string_pretty(&policy).unwrap(),
    )
    .unwrap();
}

fn deny_delete_file() -> PolicyRule {
    PolicyRule::new("deny-delete-file", ACTION_TYPE, PolicyEffect::Deny)
        .with_parameter_condition(PolicyCondition::exact("tool", json!("delete_file")))
}

fn wrap(home: &Home, mode: &str, lines: &[Value]) -> (Vec<Value>, String, Output) {
    let input: String = lines.iter().map(|l| format!("{l}\n")).collect();
    wrap_raw(home, mode, &input)
}

fn wrap_raw(home: &Home, mode: &str, input: &str) -> (Vec<Value>, String, Output) {
    let server = fake_server();
    wrap_command(home, mode, input, &[server.to_str().unwrap()])
}

/// `wrap` with an arbitrary server command line.
fn wrap_command(
    home: &Home,
    mode: &str,
    input: &str,
    command: &[&str],
) -> (Vec<Value>, String, Output) {
    let mut args = vec![
        "wrap",
        "--dir",
        home.root.to_str().unwrap(),
        "--name",
        "fake",
        "--mode",
        mode,
        "--",
    ];
    args.extend_from_slice(command);
    let out = run(&args, input);
    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    let responses = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad line {l:?}: {e}")))
        .collect();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (responses, stderr, out)
}

fn by_id<'a>(responses: &'a [Value], id: &Value) -> &'a Value {
    responses
        .iter()
        .find(|r| &r["id"] == id)
        .unwrap_or_else(|| panic!("no response for id {id} in {responses:?}"))
}

fn journal(home: &Home) -> Vec<Evidence> {
    receipts::read_journal(home)
        .unwrap()
        .iter()
        .map(|l| praetore_mcp::journal::parse_line(&l.text).unwrap().evidence)
        .collect()
}

fn verify_cli(home: &Home) -> Output {
    run(&["verify", "--dir", home.root.to_str().unwrap()], "")
}

fn session(calls: Vec<Value>) -> Vec<Value> {
    let mut lines = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    ];
    lines.extend(calls);
    lines
}

#[test]
fn observe_forwards_and_records_verifiable_observe_receipt() {
    let (_temp, home) = init_home();
    write_policy(&home, vec![deny_delete_file()]);
    let (responses, stderr, out) = wrap(
        &home,
        "observe",
        &session(vec![
            json!({"jsonrpc":"2.0","id":"c3","method":"tools/call",
            "params":{"name":"delete_file","arguments":{"path":"/etc/hosts"}}}),
        ]),
    );
    assert!(out.status.success(), "{stderr}");
    assert_eq!(responses.len(), 3, "{responses:?}");
    assert_eq!(
        by_id(&responses, &json!(1))["result"]["serverInfo"]["name"],
        "fake_server"
    );
    assert_eq!(
        by_id(&responses, &json!(2))["result"]["tools"][0]["name"],
        "echo"
    );
    assert_eq!(by_id(&responses, &json!("c3"))["result"]["isError"], false);
    assert!(
        stderr.contains("fake_server: EXECUTED delete_file"),
        "{stderr}"
    );
    assert!(stderr.contains("would be DENIED"), "{stderr}");

    let evidence = journal(&home);
    assert_eq!(evidence.len(), 1);
    let receipt = &evidence[0];
    assert_eq!(receipt.context["praetore.mode"], "observe");
    assert_eq!(receipt.decision.outcome, DecisionOutcome::Deny);
    assert_eq!(receipt.action.target.as_deref(), Some("fake"));
    assert_eq!(receipt.action.parameters["tool"], "delete_file");
    assert_eq!(receipt.action.parameters["arguments.path"], "/etc/hosts");
    assert_eq!(receipt.evaluation_mode.as_deref(), Some("high_assurance"));

    let attester = store::read_attester_pin(&home.attester_pin()).unwrap();
    let pins = store::read_issuer_pins(&home.issuer_pins()).unwrap();
    let line = &receipts::read_journal(&home).unwrap()[0].text;
    receipts::verify_line(line, &attester, &pins).unwrap();

    let verify = verify_cli(&home);
    let text = String::from_utf8_lossy(&verify.stdout);
    assert!(verify.status.success(), "{text}");
    assert!(text.contains("1 verified, 0 failed"), "{text}");
    assert!(text.contains("observe=1"), "{text}");

    let table = run(&["receipts", "--dir", home.root.to_str().unwrap()], "");
    let table = String::from_utf8_lossy(&table.stdout);
    assert!(table.contains("observe") && table.contains("delete_file") && table.contains("DENY"));
}

#[test]
fn enforce_blocks_deny_and_approval_and_allows_the_rest() {
    let (temp, home) = init_home();
    // A path that resolves to itself: `/tmp` is a symlink on macOS, and
    // paths covered by a PathPrefix rule are resolved first (T-014).
    let ok_path = fs::canonicalize(temp.path()).unwrap().join("ok");
    let ok_path = ok_path.to_str().unwrap();
    write_policy(
        &home,
        vec![
            deny_delete_file(),
            PolicyRule::new("approve-secret", ACTION_TYPE, PolicyEffect::RequireApproval)
                .with_capability(CAPABILITY)
                .with_parameter_condition(PolicyCondition::exact("tool", json!("echo")))
                .with_parameter_condition(PolicyCondition::path_prefix(
                    "arguments.path",
                    "/secret",
                )),
        ],
    );
    let (responses, stderr, out) = wrap(
        &home,
        "enforce",
        &session(vec![
            json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/tmp/x"}}}),
            json!({"jsonrpc":"2.0","id":"e","method":"tools/call","params":{"name":"echo","arguments":{"path":ok_path}}}),
            json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":{"path":"/secret/keys"}}}),
        ]),
    );
    assert!(out.status.success(), "{stderr}");
    assert_eq!(responses.len(), 5, "{responses:?}");

    let denied = by_id(&responses, &json!(5));
    assert_eq!(denied["result"]["isError"], true);
    let text = denied["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.starts_with("Denied by PRÆTORE. Evidence id: "),
        "{text}"
    );
    // The rule is reported on stderr, not to the client (G7).
    assert!(!text.contains("deny-delete-file"), "{text}");
    assert!(stderr.contains("deny-delete-file"), "{stderr}");

    assert_eq!(by_id(&responses, &json!("e"))["result"]["isError"], false);

    let held = by_id(&responses, &json!(7));
    assert_eq!(held["result"]["isError"], true);
    assert!(
        held["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("requires human approval (not supported by praetore-mcp yet)")
    );

    assert!(!stderr.contains("EXECUTED delete_file"), "{stderr}");
    assert_eq!(stderr.matches("EXECUTED echo").count(), 1, "{stderr}");

    let evidence = journal(&home);
    assert_eq!(evidence.len(), 3);
    assert!(
        evidence
            .iter()
            .all(|e| e.context["praetore.mode"] == "enforce")
    );
    let outcomes: Vec<_> = evidence.iter().map(|e| e.decision.outcome).collect();
    assert_eq!(
        outcomes,
        [
            DecisionOutcome::Deny,
            DecisionOutcome::Allow,
            DecisionOutcome::RequireApproval
        ]
    );
    // The reply names the evidence of the denied call.
    assert!(text.contains(&evidence[0].evidence_id.to_string()));

    let verify = verify_cli(&home);
    let report = String::from_utf8_lossy(&verify.stdout);
    assert!(verify.status.success(), "{report}");
    assert!(report.contains("3 verified, 0 failed"), "{report}");
}

#[test]
fn tampered_journal_line_fails_verify() {
    let (_temp, home) = init_home();
    let (_, stderr, out) = wrap(
        &home,
        "observe",
        &session(vec![
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{}}}),
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"n":1}}}),
        ]),
    );
    assert!(out.status.success(), "{stderr}");
    assert!(verify_cli(&home).status.success());

    // Re-label an observe receipt as enforce: the mode is signed, so this
    // must not verify.
    let file = receipts::read_journal(&home).unwrap()[0].file.clone();
    let original = fs::read_to_string(&file).unwrap();
    let mut lines: Vec<String> = original.lines().map(str::to_owned).collect();
    assert!(lines[1].contains(r#""praetore.mode":"observe""#));
    lines[1] = lines[1].replace(
        r#""praetore.mode":"observe""#,
        r#""praetore.mode":"enforce""#,
    );
    fs::write(&file, lines.join("\n") + "\n").unwrap();

    let verify = verify_cli(&home);
    let report = String::from_utf8_lossy(&verify.stdout);
    assert_eq!(verify.status.code(), Some(1), "{report}");
    assert!(report.contains("1 verified, 1 failed"), "{report}");
    assert!(report.contains(":2:"), "{report}");
}

#[test]
fn enforce_refuses_unparseable_lines_but_relays_other_traffic() {
    let (_temp, home) = init_home();
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo"},"method":"ping"}"#,
        "\n",
        "this is not json\n",
    );
    let (responses, stderr, out) = wrap_raw(&home, "enforce", input);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(
        by_id(&responses, &json!(1))["result"]["tools"][1]["name"],
        "delete_file"
    );
    let parse_errors: Vec<_> = responses
        .iter()
        .filter(|r| r["error"]["code"] == -32700)
        .collect();
    assert_eq!(parse_errors.len(), 2, "{responses:?}");
    assert!(parse_errors.iter().all(|r| {
        r["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("praetore-mcp")
    }));
    assert!(!stderr.contains("EXECUTED"), "{stderr}");
}

fn assert_refused_without_receipts(home: &Home, mode: &str) {
    let call = json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo","arguments":{}}});
    let (responses, stderr, _) = wrap(home, mode, &session(vec![call]));
    // Non-tools traffic still reaches the server and comes back.
    assert_eq!(
        by_id(&responses, &json!(2))["result"]["tools"][0]["name"],
        "echo"
    );
    let refused = by_id(&responses, &json!(9));
    assert_eq!(refused["result"]["isError"], true, "{mode}: {refused}");
    assert!(
        refused["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("not ready"),
        "{mode}: {refused}"
    );
    assert!(!stderr.contains("EXECUTED"), "{mode}: {stderr}");
    assert!(stderr.contains("REFUSED"), "{mode}: {stderr}");
    assert!(!stderr.contains("WITHOUT"), "{mode}: {stderr}");
}

#[test]
fn broken_home_fails_closed_in_enforce_and_observe() {
    let (_temp, home) = init_home();
    fs::write(home.policy(), "{not a policy").unwrap();
    for mode in ["enforce", "observe"] {
        assert_refused_without_receipts(&home, mode);
    }
    assert!(receipts::read_journal(&home).unwrap().is_empty());
}

#[test]
fn uninitialized_home_fails_closed_in_enforce_and_observe() {
    let temp = tempfile::tempdir().unwrap();
    let home = Home::new(temp.path().join("never-initialized"));
    for mode in ["enforce", "observe"] {
        assert_refused_without_receipts(&home, mode);
    }
    // wrap must not create a home (or keys) on its own.
    assert!(!home.root.exists());
}

#[test]
fn init_is_idempotent_and_keys_are_private() {
    let (_temp, home) = init_home();
    let before = fs::read(home.agent_key()).unwrap();
    let out = run(&["init", "--dir", home.root.to_str().unwrap()], "");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("already initialized"));
    assert_eq!(fs::read(home.agent_key()).unwrap(), before);
    let key_hex = serde_json::from_slice::<Value>(&before).unwrap()["secret_key_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&key_hex));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for key in [home.agent_key(), home.issuer_key(), home.attester_key()] {
            assert_eq!(
                fs::metadata(key).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    // Partial homes are refused rather than overwritten.
    fs::remove_file(home.policy()).unwrap();
    let out = run(&["init", "--dir", home.root.to_str().unwrap()], "");
    assert!(!out.status.success());
    assert_eq!(fs::read(home.agent_key()).unwrap(), before);
}

#[test]
fn rules_generated_by_policy_commands_enforce_end_to_end() {
    let (temp, home) = init_home();
    let dir = home.root.to_str().unwrap();
    // Resolves to itself (not `/tmp`, a symlink on macOS): see T-014.
    let ok_path = fs::canonicalize(temp.path()).unwrap().join("ok");
    let ok_path = ok_path.to_str().unwrap();
    for args in [
        vec![
            "policy",
            "deny",
            "--id",
            "deny-delete",
            "--server",
            "fake",
            "--tool",
            "delete_file",
        ],
        vec![
            "policy",
            "require-approval",
            "--id",
            "approve-secret",
            "--tool",
            "echo",
            "--arg-path-prefix",
            "path=/secret",
        ],
    ] {
        let mut args = args;
        args.extend(["--dir", dir]);
        let out = run(&args, "");
        assert!(out.status.success(), "{out:?}");
        assert!(String::from_utf8_lossy(&out.stdout).contains("restart your MCP client"));
    }
    let check = run(&["policy", "check", "--dir", dir], "");
    let report = String::from_utf8_lossy(&check.stdout);
    assert!(check.status.success(), "{report}");
    assert!(report.contains("0 warning(s)"), "{report}");

    let (responses, stderr, out) = wrap(
        &home,
        "enforce",
        &session(vec![
            json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/tmp/x"}}}),
            json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"echo","arguments":{"path":ok_path}}}),
            json!({"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"echo","arguments":{"path":"/secret/key"}}}),
        ]),
    );
    assert!(out.status.success(), "{stderr}");
    let denied = by_id(&responses, &json!(10))["result"].clone();
    assert_eq!(denied["isError"], true);
    assert!(stderr.contains("deny-delete"), "{stderr}");
    assert!(
        denied["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("Denied by PRÆTORE")
    );
    assert_eq!(by_id(&responses, &json!(11))["result"]["isError"], false);
    let held = by_id(&responses, &json!(12))["result"].clone();
    assert_eq!(held["isError"], true);
    assert!(
        held["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("requires human approval")
    );
    assert_eq!(stderr.matches("EXECUTED").count(), 1, "{stderr}");

    // The approval rule is bound (capability granted, target present), so the
    // receipt says REQUIRE_APPROVAL rather than an unbound DENY.
    let outcomes: Vec<_> = journal(&home).iter().map(|e| e.decision.outcome).collect();
    assert_eq!(
        outcomes,
        [
            DecisionOutcome::Deny,
            DecisionOutcome::Allow,
            DecisionOutcome::RequireApproval
        ]
    );
    assert!(verify_cli(&home).status.success());
}

/// Security review regressions: bare-CR line splitting (Python/Node
/// universal newlines) and case-insensitive keys (Go encoding/json).
#[test]
fn enforce_refuses_line_split_and_case_fold_differentials() {
    let (_temp, home) = init_home();
    let input = concat!(
        "{\"a\":1,\"x\":\r{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_file\"}}\r}\n",
        r#"{"jsonrpc":"2.0","id":8,"method":"tools/list","Method":"tools/call","params":{"name":"delete_file"}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":9,"method":"tools/list"}"#,
        "\r\n",
    );
    let (responses, stderr, out) = wrap_raw(&home, "enforce", input);
    assert!(out.status.success(), "{stderr}");
    let refused: Vec<_> = responses
        .iter()
        .filter(|r| r["error"]["code"] == -32700)
        .collect();
    assert_eq!(refused.len(), 2, "{responses:?}");
    assert!(responses.iter().all(|r| r["id"] != 8), "{responses:?}");
    // The CRLF-terminated line is still relayed normally.
    assert_eq!(
        by_id(&responses, &json!(9))["result"]["tools"][0]["name"],
        "echo"
    );
    assert!(
        stderr.contains("carriage return") && stderr.contains("case"),
        "{stderr}"
    );
    assert!(receipts::read_journal(&home).unwrap().is_empty());

    // Observe forwards both lines unchanged but records each tools/call reading.
    let (_, stderr, out) = wrap_raw(&home, "observe", input);
    assert!(out.status.success(), "{stderr}");
    let evidence = journal(&home);
    assert_eq!(evidence.len(), 2, "{stderr}");
    assert!(
        evidence
            .iter()
            .all(|e| e.action.parameters["tool"] == "delete_file")
    );
    assert!(verify_cli(&home).status.success());
}

fn write_rules(home: &Home, rules: Vec<PolicyRule>) {
    let policy = mission_policy(Policy::new_v2("test-policy", 1, rules));
    fs::write(
        home.policy(),
        serde_json::to_string_pretty(&policy).unwrap(),
    )
    .unwrap();
}

fn echo_path(id: u32, path: &Path) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"echo","arguments":{"path":path.to_str().unwrap()}}})
}

/// `<canonical tmp>/sandbox/{file, link -> outside/secret, dirlink -> outside}`.
#[cfg(unix)]
fn symlink_tree(temp: &tempfile::TempDir) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::symlink;
    let root = fs::canonicalize(temp.path()).unwrap();
    let sandbox = root.join("sandbox");
    let outside = root.join("outside");
    fs::create_dir_all(&sandbox).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(sandbox.join("file"), b"x").unwrap();
    fs::write(outside.join("secret"), b"s").unwrap();
    symlink(outside.join("secret"), sandbox.join("link")).unwrap();
    symlink(&outside, sandbox.join("dirlink")).unwrap();
    (sandbox, outside)
}

/// T-014, the case `praetore-core/tests/path_escape_gaps.rs` documents as a
/// core limitation: a symlink inside an ALLOW PathPrefix whose target is
/// outside. praetore-mcp resolves it before evaluation, so it is not allowed.
#[cfg(unix)]
#[test]
fn allow_path_prefix_does_not_allow_a_symlink_that_leaves_it() {
    let (temp, home) = init_home();
    let (sandbox, outside) = symlink_tree(&temp);
    write_rules(
        &home,
        vec![
            PolicyRule::new("sandbox-only", ACTION_TYPE, PolicyEffect::Allow)
                .with_capability(CAPABILITY)
                .with_parameter_condition(PolicyCondition::path_prefix(
                    "arguments.path",
                    sandbox.to_str().unwrap(),
                )),
        ],
    );
    let (responses, stderr, _) = wrap(
        &home,
        "enforce",
        &session(vec![
            echo_path(10, &sandbox.join("file")),
            echo_path(11, &sandbox.join("link")),
            echo_path(12, &sandbox.join("dirlink").join("new")),
            echo_path(13, &sandbox.join("missing-dir").join("new")),
            echo_path(14, &sandbox.join("new-file")),
        ]),
    );
    for (id, refused) in [(10, false), (11, true), (12, true), (13, true), (14, false)] {
        assert_eq!(
            by_id(&responses, &json!(id))["result"]["isError"],
            refused,
            "id {id}: {stderr}"
        );
    }
    assert_eq!(stderr.matches("EXECUTED echo").count(), 2, "{stderr}");

    let evidence = journal(&home);
    let outcomes: Vec<_> = evidence.iter().map(|e| e.decision.outcome).collect();
    use DecisionOutcome::{Allow, Deny};
    assert_eq!(outcomes, [Allow, Deny, Deny, Deny, Allow]);
    let check = |i: usize| &evidence[i].context["praetore.path_check"]["arguments.path"];
    assert_eq!(check(0)["status"], "same");
    assert_eq!(check(1)["status"], "differs");
    assert_eq!(check(1)["lexical"], sandbox.join("link").to_str().unwrap());
    assert_eq!(
        check(1)["resolved"],
        outside.join("secret").to_str().unwrap()
    );
    assert_eq!(check(2)["resolved"], outside.join("new").to_str().unwrap());
    assert_eq!(check(3)["status"], "unresolved");
    assert_eq!(check(3)["resolved"], Value::Null);
    // The engine saw the placeholder; the server got the client's bytes.
    assert_eq!(
        evidence[1].action.parameters["arguments.path"],
        "praetore-mcp:path-check-failed"
    );
    assert_eq!(
        evidence[1].action.parameters["arguments"]["path"],
        sandbox.join("link").to_str().unwrap()
    );

    let verify = verify_cli(&home);
    let report = String::from_utf8_lossy(&verify.stdout);
    assert!(verify.status.success(), "{report}");
    assert!(report.contains("5 verified, 0 failed"), "{report}");
}

/// The default policy shape (allow everything, deny one directory): a path
/// that only reaches the denied directory through a symlink is denied, and
/// so is one whose parent does not exist yet.
#[cfg(unix)]
#[test]
fn deny_path_prefix_catches_symlinks_into_it_and_unresolvable_paths() {
    let (temp, home) = init_home();
    let (sandbox, outside) = symlink_tree(&temp);
    write_policy(
        &home,
        vec![
            PolicyRule::new("deny-outside", ACTION_TYPE, PolicyEffect::Deny)
                .with_parameter_condition(PolicyCondition::path_prefix(
                    "arguments.path",
                    outside.to_str().unwrap(),
                )),
        ],
    );
    let (responses, stderr, _) = wrap(
        &home,
        "enforce",
        &session(vec![
            echo_path(20, &sandbox.join("file")),
            echo_path(21, &sandbox.join("link")),
            echo_path(22, &sandbox.join("dirlink").join("secret")),
            echo_path(23, &sandbox.join("missing-dir").join("x")),
            echo_path(24, &outside.join("secret")),
        ]),
    );
    for (id, refused) in [(20, false), (21, true), (22, true), (23, true), (24, true)] {
        let reply = by_id(&responses, &json!(id));
        assert_eq!(reply["result"]["isError"], refused, "id {id}: {stderr}");
        if refused {
            let text = reply["result"]["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with("Denied by PRÆTORE"), "id {id}: {text}");
            assert!(stderr.contains("deny-outside"), "id {id}: {stderr}");
        }
    }
    assert_eq!(stderr.matches("EXECUTED echo").count(), 1, "{stderr}");
    assert!(verify_cli(&home).status.success());
}

/// Observe still forwards everything, and its receipts record the check.
#[cfg(unix)]
#[test]
fn observe_records_the_path_check_and_forwards() {
    let (temp, home) = init_home();
    let (sandbox, outside) = symlink_tree(&temp);
    write_policy(
        &home,
        vec![
            PolicyRule::new("deny-outside", ACTION_TYPE, PolicyEffect::Deny)
                .with_parameter_condition(PolicyCondition::path_prefix(
                    "arguments.path",
                    outside.to_str().unwrap(),
                )),
        ],
    );
    let (responses, stderr, _) = wrap(
        &home,
        "observe",
        &session(vec![echo_path(30, &sandbox.join("link"))]),
    );
    assert_eq!(by_id(&responses, &json!(30))["result"]["isError"], false);
    assert_eq!(stderr.matches("EXECUTED echo").count(), 1, "{stderr}");
    let evidence = journal(&home);
    assert_eq!(evidence[0].decision.outcome, DecisionOutcome::Deny);
    assert_eq!(
        evidence[0].context["praetore.path_check"]["arguments.path"]["status"],
        "differs"
    );
}

/// T-014, adversarial finding on `ccea7be`: on APFS a case or NFD variant of
/// a denied name that does not exist yet is the same entry; enforce refuses
/// it although core's `PathPrefix` is lexical, and still allows the rest.
#[cfg(target_os = "macos")]
#[test]
fn deny_path_prefix_catches_case_and_nfd_variants_of_a_missing_name_on_apfs() {
    let (temp, home) = init_home();
    let root = fs::canonicalize(temp.path()).unwrap();
    let deny = |id: &str, path: PathBuf| {
        PolicyRule::new(id, ACTION_TYPE, PolicyEffect::Deny).with_parameter_condition(
            PolicyCondition::path_prefix("arguments.path", path.to_str().unwrap()),
        )
    };
    write_policy(
        &home,
        vec![
            deny("deny-vault", root.join("vault")),
            deny("deny-cafe", root.join("caf\u{e9}")),
        ],
    );
    let (responses, stderr, _) = wrap(
        &home,
        "enforce",
        &session(vec![
            echo_path(40, &root.join("notes.txt")),
            echo_path(41, &root.join("vault")),
            echo_path(42, &root.join("VAULT")),
            echo_path(43, &root.join("Vault").join("x")),
            echo_path(44, &root.join("cafe\u{301}")),
            echo_path(45, &root.join("CAF\u{c9}")),
        ]),
    );
    for (id, refused) in [
        (40, false),
        (41, true),
        (42, true),
        (43, true),
        (44, true),
        (45, true),
    ] {
        let reply = by_id(&responses, &json!(id));
        assert_eq!(reply["result"]["isError"], refused, "id {id}: {stderr}");
    }
    assert_eq!(stderr.matches("EXECUTED echo").count(), 1, "{stderr}");
    let statuses: Vec<String> = journal(&home)
        .iter()
        .filter_map(|evidence| {
            evidence.context.get("praetore.path_check")?["arguments.path"]["status"]
                .as_str()
                .map(str::to_owned)
        })
        .collect();
    assert_eq!(
        statuses,
        [
            "same",
            "same",
            "ambiguous",
            "unresolved",
            "ambiguous",
            "ambiguous"
        ]
    );
    assert!(verify_cli(&home).status.success());
}

/// Independent review of `a9dbbdf`, Alta 1, as the reviewer ran it: DENY on
/// a `.ssh` that does not exist yet (a stand-in for `~/.ssh` in a temp dir).
/// `.ẞh` is the same entry on APFS; it must be refused before it exists
/// (step 1) and after the server created it under that spelling (step 2).
#[cfg(target_os = "macos")]
#[test]
fn deny_path_prefix_catches_sharp_s_variants_of_dot_ssh_on_apfs() {
    let (temp, home) = init_home();
    let root = fs::canonicalize(temp.path()).unwrap();
    let ssh = root.join(".ssh");
    write_policy(
        &home,
        vec![
            PolicyRule::new("deny-ssh", ACTION_TYPE, PolicyEffect::Deny).with_parameter_condition(
                PolicyCondition::path_prefix("arguments.path", ssh.to_str().unwrap()),
            ),
        ],
    );
    let variant = root.join(".\u{1e9e}h");
    let refused = |responses: &[Value], id: u32| {
        by_id(responses, &json!(id))["result"]["isError"] == json!(true)
    };
    let (step1, stderr, _) = wrap(
        &home,
        "enforce",
        &session(vec![
            echo_path(60, &variant),
            echo_path(61, &root.join(".\u{df}h")),
            echo_path(62, &root.join(".SSH")),
            echo_path(63, &root.join(".sh")),
        ]),
    );
    for id in [60, 61, 62] {
        assert!(refused(&step1, id), "id {id}: {stderr}");
    }
    assert!(!refused(&step1, 63), "{stderr}");

    // What the server would have done had step 1 been allowed.
    fs::create_dir(&variant).unwrap();
    assert!(ssh.exists(), "APFS: .ẞh is .ssh");
    let (step2, stderr, _) = wrap(
        &home,
        "enforce",
        &session(vec![echo_path(64, &variant.join("authorized_keys"))]),
    );
    assert!(refused(&step2, 64), "{stderr}");
    assert_eq!(stderr.matches("EXECUTED echo").count(), 0, "{stderr}");
    assert!(verify_cli(&home).status.success());
}

/// Independent review of `a9dbbdf`, Alta 2: `realpath` keeps the
/// `/System/Volumes/Data` spelling of firmlinked directories. Includes the
/// real `~/.ssh` (only `stat`; `echo` touches nothing).
#[cfg(target_os = "macos")]
#[test]
fn deny_path_prefix_catches_firmlink_spellings_on_macos() {
    let (temp, home) = init_home();
    let root = fs::canonicalize(temp.path()).unwrap();
    fs::create_dir_all(root.join("vault")).unwrap();
    let user_home = PathBuf::from(std::env::var("HOME").unwrap());
    let data = |path: &Path| PathBuf::from(format!("/System/Volumes/Data{}", path.display()));
    let deny = |id: &str, path: &Path| {
        PolicyRule::new(id, ACTION_TYPE, PolicyEffect::Deny).with_parameter_condition(
            PolicyCondition::path_prefix("arguments.path", path.to_str().unwrap()),
        )
    };
    write_policy(
        &home,
        vec![
            deny("deny-vault", &root.join("vault")),
            deny("deny-ssh", &user_home.join(".ssh")),
        ],
    );
    let (responses, stderr, _) = wrap(
        &home,
        "enforce",
        &session(vec![
            echo_path(70, &root.join("vault").join("k")),
            echo_path(71, &data(&root.join("vault").join("k"))),
            echo_path(72, &data(&user_home.join(".ssh"))),
            echo_path(73, &data(&user_home.join(".ssh").join("authorized_keys"))),
            echo_path(74, &data(&root.join("notes.txt"))),
        ]),
    );
    for (id, refused) in [(70, true), (71, true), (72, true), (73, true), (74, false)] {
        let reply = by_id(&responses, &json!(id));
        assert_eq!(reply["result"]["isError"], refused, "id {id}: {stderr}");
    }
    assert_eq!(stderr.matches("EXECUTED echo").count(), 1, "{stderr}");
    assert!(verify_cli(&home).status.success());
}

/// Independent review of `c5dc165`, Media 1, as the reviewer ran it: DENY on
/// `/System/Volumes/Data` also covers `/private/var/...` and `~/.ssh`, which
/// live on the data volume behind firmlinks.
#[cfg(target_os = "macos")]
#[test]
fn deny_on_the_macos_data_volume_covers_firmlinked_spellings() {
    let (temp, home) = init_home();
    let root = fs::canonicalize(temp.path()).unwrap();
    fs::write(root.join("notes.txt"), b"x").unwrap();
    let user_home = PathBuf::from(std::env::var("HOME").unwrap());
    write_policy(
        &home,
        vec![
            PolicyRule::new("deny-data", ACTION_TYPE, PolicyEffect::Deny).with_parameter_condition(
                PolicyCondition::path_prefix("arguments.path", "/System/Volumes/Data"),
            ),
        ],
    );
    let (responses, stderr, _) = wrap(
        &home,
        "enforce",
        &session(vec![
            echo_path(
                80,
                &PathBuf::from(format!(
                    "/System/Volumes/Data{}",
                    root.join("notes.txt").display()
                )),
            ),
            echo_path(81, &root.join("notes.txt")),
            echo_path(82, &user_home.join(".ssh").join("authorized_keys")),
            echo_path(83, Path::new("/bin/ls")),
        ]),
    );
    for (id, refused) in [(80, true), (81, true), (82, true), (83, false)] {
        let reply = by_id(&responses, &json!(id));
        assert_eq!(reply["result"]["isError"], refused, "id {id}: {stderr}");
    }
    assert_eq!(stderr.matches("EXECUTED echo").count(), 1, "{stderr}");
    assert!(verify_cli(&home).status.success());
}

/// Independent review of `d300e25`, Media 1, as the reviewer ran it:
/// `/.nofollow/<path>` resolves to itself on macOS and is the same entry; a
/// DENY on `/System/Volumes/Data` must still refuse it.
#[cfg(target_os = "macos")]
#[test]
fn deny_on_the_macos_data_volume_covers_dot_root_aliases() {
    let (temp, home) = init_home();
    let root = fs::canonicalize(temp.path()).unwrap();
    fs::write(root.join("notes.txt"), b"x").unwrap();
    let user_home = PathBuf::from(std::env::var("HOME").unwrap());
    write_policy(
        &home,
        vec![
            PolicyRule::new("deny-data", ACTION_TYPE, PolicyEffect::Deny).with_parameter_condition(
                PolicyCondition::path_prefix("arguments.path", "/System/Volumes/Data"),
            ),
        ],
    );
    let nofollow = |path: &Path| PathBuf::from(format!("/.nofollow{}", path.display()));
    let (responses, stderr, _) = wrap(
        &home,
        "enforce",
        &session(vec![
            echo_path(90, &root.join("notes.txt")),
            echo_path(91, &nofollow(&root.join("notes.txt"))),
            echo_path(
                92,
                &nofollow(&user_home.join(".ssh").join("authorized_keys")),
            ),
            echo_path(
                93,
                &PathBuf::from(format!("/.NOFOLLOW{}", root.join("notes.txt").display())),
            ),
            echo_path(94, Path::new("/bin/ls")),
        ]),
    );
    for (id, refused) in [(90, true), (91, true), (92, true), (93, true), (94, false)] {
        let reply = by_id(&responses, &json!(id));
        assert_eq!(reply["result"]["isError"], refused, "id {id}: {stderr}");
    }
    assert_eq!(stderr.matches("EXECUTED echo").count(), 1, "{stderr}");
    assert!(verify_cli(&home).status.success());
}

/// Independent review of `f9ae433`, Media 1, as the reviewer ran it: the
/// server holds a file inside the DENY prefix on its fd 4, and `/dev/fd/4`
/// (a pipe in the gate's own fd table, so `realpath` kept it) would reach
/// that file. Every path under `/dev` or `/proc` is now `unresolved`.
#[cfg(unix)]
#[test]
fn deny_path_prefix_catches_dev_fd_aliases_of_server_descriptors() {
    let (temp, home) = init_home();
    let root = fs::canonicalize(temp.path()).unwrap();
    let vault = root.join("vault");
    fs::create_dir_all(&vault).unwrap();
    let secret = vault.join("secret");
    fs::write(&secret, "orig\n").unwrap();
    fs::write(root.join("notes.txt"), "").unwrap();
    write_policy(
        &home,
        vec![
            PolicyRule::new("deny-vault", ACTION_TYPE, PolicyEffect::Deny)
                .with_parameter_condition(PolicyCondition::path_prefix(
                    "arguments.path",
                    vault.to_str().unwrap(),
                )),
        ],
    );
    let append = |id: u32, path: &str| {
        json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"append",
            "arguments":{"path":path,"text":"PWNED\n"}}})
    };
    let server = fake_server();
    let input: String = session(vec![
        append(10, secret.to_str().unwrap()),
        append(12, "/dev/fd/4"),
        append(13, "/DEV/fd/4"),
        append(14, root.join("notes.txt").to_str().unwrap()),
    ])
    .iter()
    .map(|line| format!("{line}\n"))
    .collect();
    let (responses, stderr, _) = wrap_command(
        &home,
        "enforce",
        &input,
        &[
            "/bin/sh",
            "-c",
            "exec 4>>\"$0\" && exec \"$1\"",
            secret.to_str().unwrap(),
            server.to_str().unwrap(),
        ],
    );
    for (id, refused) in [(10, true), (12, true), (13, true), (14, false)] {
        let reply = by_id(&responses, &json!(id));
        assert_eq!(reply["result"]["isError"], refused, "id {id}: {stderr}");
    }
    assert_eq!(fs::read_to_string(&secret).unwrap(), "orig\n", "{stderr}");
    assert_eq!(
        fs::read_to_string(root.join("notes.txt")).unwrap(),
        "PWNED\n"
    );
    assert!(verify_cli(&home).status.success());
}

/// Independent review of `419e66f`, Media 1, as the reviewer ran it, on a
/// real HFS+ volume: HFS+ ignores U+200C (and other invisible code points)
/// in names, so `va\u{200C}ult` would create the `vault` a DENY names
/// before it exists. Set `PRAETORE_TEST_HFS_ROOT` to a writable directory
/// on an HFS+ volume (`hdiutil create -fs HFS+ ...`).
#[cfg(target_os = "macos")]
#[test]
#[ignore = "needs an HFS+ volume: set PRAETORE_TEST_HFS_ROOT"]
fn deny_path_prefix_catches_hfs_ignorable_aliases_of_a_missing_name() {
    let hfs = fs::canonicalize(std::env::var("PRAETORE_TEST_HFS_ROOT").unwrap()).unwrap();
    let vault = hfs.join("vault");
    let _ = fs::remove_file(&vault);
    let (_temp, home) = init_home();
    write_policy(
        &home,
        vec![
            PolicyRule::new("deny-vault", ACTION_TYPE, PolicyEffect::Deny)
                .with_parameter_condition(PolicyCondition::path_prefix(
                    "arguments.path",
                    vault.to_str().unwrap(),
                )),
        ],
    );
    let append = |id: u32, name: &str| {
        json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"append",
            "arguments":{"path":hfs.join(name).to_str().unwrap(),"text":"PLANTED\n"}}})
    };
    let (responses, stderr, _) = wrap(
        &home,
        "enforce",
        &session(vec![
            append(10, "vault"),
            append(11, "VAULT"),
            append(12, "vault."),
            append(13, "va\u{200C}ult"),
            append(14, "\u{FEFF}vault"),
            append(15, "vault\u{206F}"),
            append(16, "notes.txt"),
        ]),
    );
    for (id, refused) in [
        (10, true),
        (11, true),
        (12, true),
        (13, true),
        (14, true),
        (15, true),
        (16, false),
    ] {
        let reply = by_id(&responses, &json!(id));
        eprintln!("HFS+ e2e id {id}: isError={}", reply["result"]["isError"]);
        assert_eq!(reply["result"]["isError"], refused, "id {id}: {stderr}");
    }
    assert!(
        !vault.exists(),
        "the agent created the denied entry: {stderr}"
    );
    fs::remove_file(hfs.join("notes.txt")).unwrap();
    assert!(verify_cli(&home).status.success());
}

/// G7: the default policy plus `safety:halt` declared Safety.
fn write_policy_with_safety(home: &Home) {
    let policy = store::default_policy()
        .with_action_class("safety:halt", praetore_core::ActionClass::Safety);
    fs::write(
        home.policy(),
        serde_json::to_string_pretty(&policy).unwrap(),
    )
    .unwrap();
}

/// G7: a `safety:*` tool that the policy declares Safety is
/// forwarded to the wrapped server without a receipt, in enforce and in
/// observe. Every evaluation in praetore-mcp writes a receipt, so "no
/// receipt for the safety call" means the engine was not called for it; the
/// mission call in the same session shows the journal works.
#[test]
fn g7_declared_safety_call_is_forwarded_without_a_receipt_in_both_modes() {
    for mode in ["enforce", "observe"] {
        let (_temp, home) = init_home();
        write_policy_with_safety(&home);
        let (responses, stderr, out) = wrap(
            &home,
            mode,
            &session(vec![
                json!({"jsonrpc":"2.0","id":"s","method":"tools/call","params":{"name":"safety:halt","arguments":{}}}),
                json!({"jsonrpc":"2.0","id":"m","method":"tools/call","params":{"name":"echo","arguments":{}}}),
            ]),
        );
        assert!(out.status.success(), "{mode}: {stderr}");
        let safety = by_id(&responses, &json!("s"));
        assert_eq!(safety["result"]["isError"], false, "{mode}: {safety}");
        assert!(stderr.contains("EXECUTED safety:halt"), "{mode}: {stderr}");
        assert!(
            stderr.contains("SAFETY_ACTION_NOT_GOVERNED"),
            "{mode}: {stderr}"
        );
        assert!(
            stderr.contains("forwarded WITHOUT a receipt"),
            "{mode}: {stderr}"
        );
        let evidence = journal(&home);
        assert_eq!(
            evidence.len(),
            1,
            "{mode}: only the mission call has a receipt"
        );
        assert_eq!(evidence[0].action.parameters["tool"], "echo");
        assert!(
            evidence
                .iter()
                .all(|e| !e.action.action_type.starts_with("safety:"))
        );
    }
}

/// G7: a `safety:*` tool that the policy does not declare is refused in both
/// modes, nothing reaches the server, and the engine leaves a signed DENY
/// receipt (reason `unclassified`) that `praetore-mcp verify` accepts. The
/// client sees the same text as for any DENY.
#[test]
fn g7_undeclared_safety_call_is_refused_in_both_modes() {
    for mode in ["enforce", "observe"] {
        let (_temp, home) = init_home();
        write_policy_with_safety(&home);
        let (responses, stderr, out) = wrap(
            &home,
            mode,
            &session(vec![
                json!({"jsonrpc":"2.0","id":"u","method":"tools/call","params":{"name":"safety:hold","arguments":{}}}),
            ]),
        );
        assert!(out.status.success(), "{mode}: {stderr}");
        let refused = by_id(&responses, &json!("u"));
        assert_eq!(refused["result"]["isError"], true, "{mode}: {refused}");
        let text = refused["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.starts_with("Denied by PRÆTORE. Evidence id: "),
            "{mode}: {text}"
        );
        assert!(!stderr.contains("EXECUTED safety:hold"), "{mode}: {stderr}");
        let evidence = journal(&home);
        assert_eq!(evidence.len(), 1, "{mode}");
        assert_eq!(evidence[0].action.action_type, "safety:hold");
        assert_eq!(evidence[0].decision.outcome, DecisionOutcome::Deny);
        assert_eq!(
            evidence[0].decision.reason,
            praetore_core::UNCLASSIFIED_DENY_REASON
        );
        assert!(text.contains(&evidence[0].evidence_id.to_string()));
        let verify = verify_cli(&home);
        let report = String::from_utf8_lossy(&verify.stdout);
        assert!(verify.status.success(), "{mode}: {report}");
        assert!(report.contains("1 verified, 0 failed"), "{mode}: {report}");
    }
}

/// G7: a tool name that starts with `safety` (any ASCII case) and is not
/// exactly a declared Safety action is refused in both modes and never
/// forwarded, including names that would fail validation (trailing space or
/// tab) and an ambiguous line (bare carriage return).
#[test]
fn g7_safety_named_calls_that_are_not_declared_are_never_forwarded() {
    let calls = [
        ("space", json!({"jsonrpc":"2.0","id":"space","method":"tools/call","params":{"name":"safety:halt ","arguments":{}}}).to_string()),
        ("tab", json!({"jsonrpc":"2.0","id":"tab","method":"tools/call","params":{"name":"safety:halt\t","arguments":{}}}).to_string()),
        ("upper", json!({"jsonrpc":"2.0","id":"upper","method":"tools/call","params":{"name":"SAFETY:halt","arguments":{}}}).to_string()),
        ("cr", "{\"a\":1,\"x\":\r{\"jsonrpc\":\"2.0\",\"id\":\"cr\",\"method\":\"tools/call\",\"params\":{\"name\":\"safety:hold\"}}\r}".to_string()),
    ];
    for mode in ["enforce", "observe"] {
        for (id, call) in &calls {
            let (_temp, home) = init_home();
            write_policy_with_safety(&home);
            let mut input: String = session(vec![]).iter().map(|l| format!("{l}\n")).collect();
            input.push_str(call);
            input.push('\n');
            let (responses, stderr, out) = wrap_raw(&home, mode, &input);
            assert!(out.status.success(), "{mode}/{id}: {stderr}");
            assert!(
                !stderr.contains("EXECUTED"),
                "{mode}/{id}: forwarded: {stderr}"
            );
            let refused = responses
                .iter()
                .find(|r| r["id"] == json!(id) || (r["id"].is_null() && r.get("error").is_some()))
                .unwrap_or_else(|| panic!("{mode}/{id}: no refusal in {responses:?}"));
            let text = refused.to_string();
            assert!(
                text.contains("Denied by PRÆTORE") || text.contains("not forwarded"),
                "{mode}/{id}: {text}"
            );
            // Any receipt is the engine's signed unclassified DENY.
            assert!(
                journal(&home)
                    .iter()
                    .all(|e| e.decision.reason == praetore_core::UNCLASSIFIED_DENY_REASON),
                "{mode}/{id}"
            );
        }
    }
}

/// G7 limit: without a readable policy nothing can be classified, so every
/// tool is refused, `safety:*` included, in both modes (fail closed).
#[test]
fn g7_unreadable_policy_refuses_safety_calls_in_both_modes() {
    for broken in ["not json", "directory"] {
        let (_temp, home) = init_home();
        write_policy_with_safety(&home);
        if broken == "directory" {
            fs::remove_file(home.policy()).unwrap();
            fs::create_dir(home.policy()).unwrap();
        } else {
            fs::write(home.policy(), "{not a policy").unwrap();
        }
        for mode in ["enforce", "observe"] {
            let (responses, stderr, _) = wrap(
                &home,
                mode,
                &session(vec![
                    json!({"jsonrpc":"2.0","id":"s","method":"tools/call","params":{"name":"safety:halt","arguments":{}}}),
                ]),
            );
            let refused = by_id(&responses, &json!("s"));
            assert_eq!(
                refused["result"]["isError"], true,
                "{broken}/{mode}: {refused}"
            );
            assert!(
                refused["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("not ready"),
                "{broken}/{mode}: {refused}"
            );
            assert!(!stderr.contains("EXECUTED"), "{broken}/{mode}: {stderr}");
        }
        assert!(receipts::read_journal(&home).unwrap().is_empty());
    }
}

/// G7 test helper: declares every action type a rule names as Mission.
#[allow(dead_code)]
fn mission_policy(mut policy: praetore_core::Policy) -> praetore_core::Policy {
    for rule in &policy.rules {
        policy
            .action_classes
            .entry(rule.action_type.clone())
            .or_insert(praetore_core::ActionClass::Mission);
    }
    policy
}

/// G7 test helper: classifies `action` as a Mission action. The engine still
/// checks it against its own policy's `action_classes`.
#[allow(dead_code)]
fn mission(action: praetore_core::Action) -> praetore_core::MissionAction {
    praetore_core::Policy::new("classify", 1, vec![])
        .with_mission_actions([action.action_type.clone()])
        .classify(action)
        .expect("classify")
        .into_mission()
        .expect("mission action")
}

/// Hallazgo 11, end to end in observe: lines the proxy cannot parse are
/// never forwarded silently. An ordinary tool call with a duplicate key is
/// forwarded with a warning; an undeclared `safety:halt` with a duplicate
/// key is refused and never reaches the server.
#[test]
fn observe_warns_on_unparseable_lines_and_refuses_unparseable_safety_calls() {
    let (_temp, home) = init_home();
    write_policy_with_safety(&home);
    let deep = format!(
        r#"{{"jsonrpc":"2.0","id":"deep","method":"tools/call","params":{{"name":"echo","arguments":{{"a":{}1{}}}}}}}"#,
        "[".repeat(200),
        "]".repeat(200)
    );
    let input = [
        r#"{"jsonrpc":"2.0","id":"dup","method":"tools/call","params":{"name":"echo","arguments":{"x":1,"x":2}}}"#,
        r#"{"jsonrpc":"2.0","id":"sur","method":"tools/call","params":{"name":"echo","arguments":{"p":"\ud800"}}}"#,
        deep.as_str(),
        r#"{"jsonrpc":"2.0","id":"halt","method":"tools/call","params":{"name":"safety:halt","arguments":{"x":1,"x":2}}}"#,
        r#"{"jsonrpc":"2.0","id":"hold","method":"tools/call","params":{"name":"safety:hold","arguments":{"x":1,"x":2}}}"#,
    ]
    .map(|line| format!("{line}\n"))
    .concat();
    let (responses, stderr, out) = wrap_raw(&home, "observe", &input);
    assert!(out.status.success(), "{stderr}");
    // The duplicate-key echo reaches the server (it accepts the line).
    assert_eq!(by_id(&responses, &json!("dup"))["result"]["isError"], false);
    assert_eq!(
        stderr.matches("WARNING unparseable client line").count(),
        3,
        "{stderr}"
    );
    // Neither safety line reaches the server, declared or not.
    assert!(!stderr.contains("EXECUTED safety"), "{stderr}");
    assert_eq!(
        stderr.matches("may name a safety* tool").count(),
        2,
        "{stderr}"
    );
    let refusals = responses
        .iter()
        .filter(|r| {
            r["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("may name a safety* tool"))
        })
        .count();
    assert_eq!(refusals, 2, "{responses:?}");
    // No reading was evaluated, so no receipt.
    assert!(journal(&home).is_empty());
}

/// Three observe calls: a journal of three chained entries in one file.
fn journal_of_three() -> (tempfile::TempDir, Home, PathBuf, Vec<String>) {
    let (temp, home) = init_home();
    let calls = (0..3)
        .map(|n| json!({"jsonrpc":"2.0","id":n + 10,"method":"tools/call","params":{"name":"echo","arguments":{"n":n}}}))
        .collect();
    let (_, stderr, out) = wrap(&home, "observe", &session(calls));
    assert!(out.status.success(), "{stderr}");
    let lines = receipts::read_journal(&home).unwrap();
    assert_eq!(lines.len(), 3);
    let file = lines[0].file.clone();
    let text = lines.iter().map(|l| l.text.clone()).collect();
    (temp, home, file, text)
}

fn verify_output(home: &Home, extra: &[&str]) -> (Option<i32>, String) {
    let mut args = vec!["verify", "--dir", home.root.to_str().unwrap()];
    args.extend_from_slice(extra);
    let out = run(&args, "");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn head_of(report: &str) -> String {
    let start = report.find(" head ").unwrap() + " head ".len();
    report[start..start + 64].to_owned()
}

/// Hallazgo 12: the journal is a hash chain. Every entry carries `seq` and
/// `prev`, and `verify` reports a removed, duplicated or reordered entry,
/// and (against a head kept elsewhere) entries removed at the end.
#[test]
fn verify_detects_removed_duplicated_reordered_and_truncated_entries() {
    let (_temp, home, file, lines) = journal_of_three();
    for (index, line) in lines.iter().enumerate() {
        let value: Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["seq"], index as u64, "{line}");
        assert_eq!(value["prev"].as_str().unwrap().len(), 64);
    }
    let (code, report) = verify_output(&home, &[]);
    assert_eq!(code, Some(0), "{report}");
    assert!(report.contains("3 verified, 0 failed"), "{report}");
    assert!(
        report.contains("journal head: 3 chained entries"),
        "{report}"
    );
    let head = head_of(&report);
    let (code, report) = verify_output(&home, &["--expected-head", &head]);
    assert_eq!(code, Some(0), "{report}");

    let write = |kept: &[&String]| {
        let text: String = kept.iter().map(|l| format!("{l}\n")).collect();
        fs::write(&file, text).unwrap();
    };
    let cases: [(&str, Vec<&String>); 4] = [
        ("removed", vec![&lines[0], &lines[2]]),
        (
            "duplicated",
            vec![&lines[0], &lines[1], &lines[1], &lines[2]],
        ),
        ("reordered", vec![&lines[0], &lines[2], &lines[1]]),
        ("first removed", vec![&lines[1], &lines[2]]),
    ];
    for (label, kept) in cases {
        write(&kept);
        let (code, report) = verify_output(&home, &[]);
        assert_eq!(code, Some(1), "{label}: {report}");
        assert!(report.contains("journal order"), "{label}: {report}");
    }
    let (code, report) = {
        write(&[&lines[0], &lines[1], &lines[1], &lines[2]]);
        verify_output(&home, &[])
    };
    assert_eq!(code, Some(1));
    assert!(report.contains("duplicate evidence_id"), "{report}");

    // Removing the last entry leaves a valid shorter chain: only the head
    // kept elsewhere shows it.
    write(&[&lines[0], &lines[1]]);
    let (code, report) = verify_output(&home, &[]);
    assert_eq!(code, Some(0), "{report}");
    let (code, report) = verify_output(&home, &["--expected-head", &head]);
    assert_eq!(code, Some(1), "{report}");
    assert!(
        report.contains("does not match the expected head"),
        "{report}"
    );

    // An expected head that is not 64 lowercase hex is a usage error.
    let (code, _) = verify_output(&home, &["--expected-head", &head.to_uppercase()]);
    assert_ne!(code, Some(0));
}

/// A whole daily file removed from the middle of the journal breaks the
/// chain, and new entries continue the chain from the newest file.
#[test]
fn chain_continues_across_daily_files_and_a_removed_file_is_detected() {
    let (_temp, home, file, lines) = journal_of_three();
    let dir = home.receipts_dir();
    // Move the entries into three earlier daily files, one per file.
    fs::remove_file(&file).unwrap();
    for (index, line) in lines.iter().enumerate() {
        fs::write(
            dir.join(format!("2001-01-0{}.jsonl", index + 1)),
            format!("{line}\n"),
        )
        .unwrap();
    }
    // A new entry goes after the last one (today's file), not at seq 0.
    let call = json!({"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"echo","arguments":{}}});
    let (_, stderr, out) = wrap(&home, "observe", &session(vec![call]));
    assert!(out.status.success(), "{stderr}");
    let all = receipts::read_journal(&home).unwrap();
    let last: Value = serde_json::from_str(&all.last().unwrap().text).unwrap();
    assert_eq!(last["seq"], 3, "{last}");
    let (code, report) = verify_output(&home, &[]);
    assert_eq!(code, Some(0), "{report}");
    assert!(
        report.contains("journal head: 4 chained entries"),
        "{report}"
    );

    fs::remove_file(dir.join("2001-01-02.jsonl")).unwrap();
    let (code, report) = verify_output(&home, &[]);
    assert_eq!(code, Some(1), "{report}");
    assert!(report.contains("journal order"), "{report}");
}

/// Receipts written before the chain existed (bare evidence lines) still
/// verify, are counted apart, and the chain starts after them.
#[test]
fn unchained_entries_from_earlier_versions_still_verify_before_the_chain() {
    let (_temp, home, file, lines) = journal_of_three();
    // Rewrite the first two entries in the earlier format.
    let bare = |line: &String| {
        let value: Value = serde_json::from_str(line).unwrap();
        praetore_mcp::journal::parse_line(line).unwrap();
        value["evidence"].to_string()
    };
    let legacy = format!("{}\n{}\n", bare(&lines[0]), bare(&lines[1]));
    fs::remove_file(&file).unwrap();
    fs::write(home.receipts_dir().join("2001-01-01.jsonl"), &legacy).unwrap();
    let call = json!({"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"echo","arguments":{}}});
    let (_, stderr, out) = wrap(&home, "observe", &session(vec![call]));
    assert!(out.status.success(), "{stderr}");
    let (code, report) = verify_output(&home, &[]);
    assert_eq!(code, Some(0), "{report}");
    assert!(report.contains("3 verified, 0 failed"), "{report}");
    assert!(
        report.contains("1 chained entries") && report.contains("2 unchained"),
        "{report}"
    );

    // An unchained line after the chain started is reported.
    let today = receipts::read_journal(&home)
        .unwrap()
        .last()
        .unwrap()
        .file
        .clone();
    let mut text = fs::read_to_string(&today).unwrap();
    text.push_str(&format!("{}\n", bare(&lines[2])));
    fs::write(&today, text).unwrap();
    let (code, report) = verify_output(&home, &[]);
    assert_eq!(code, Some(1), "{report}");
    assert!(
        report.contains("unchained line after the chain started"),
        "{report}"
    );
}

/// An interrupted write (last line without a newline) stops further
/// appends: enforce refuses the call instead of writing after a torn entry.
#[test]
fn torn_journal_tail_refuses_in_enforce() {
    let (_temp, home, file, _) = journal_of_three();
    let mut text = fs::read_to_string(&file).unwrap();
    text.push_str("{\"seq\":3,\"prev\":");
    fs::write(&file, text).unwrap();
    let call = json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo","arguments":{}}});
    let (responses, stderr, _) = wrap(&home, "enforce", &session(vec![call]));
    assert_eq!(
        by_id(&responses, &json!(9))["result"]["isError"],
        true,
        "{stderr}"
    );
    assert!(stderr.contains("does not end with a newline"), "{stderr}");
    assert!(!stderr.contains("EXECUTED"), "{stderr}");
}

/// Hallazgo 11: a client line over 32 MiB is not parsed, so it cannot be
/// checked for a `safety*` tool; it is refused in observe too, and the
/// traffic after it still flows.
#[test]
fn oversized_lines_are_refused_in_observe_too() {
    let (_temp, home) = init_home();
    let filler = "x".repeat(praetore_mcp::relay::MAX_CLIENT_LINE_BYTES);
    let big = format!(
        r#"{{"jsonrpc":"2.0","id":"big","method":"tools/call","params":{{"arguments":{{"f":"{filler}"}},"name":"safety:halt"}}}}"#
    );
    let after = r#"{"jsonrpc":"2.0","id":"after","method":"tools/call","params":{"name":"echo","arguments":{}}}"#;
    let (responses, stderr, out) = wrap_raw(&home, "observe", &format!("{big}\n{after}\n"));
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("REFUSED client message over"), "{stderr}");
    assert!(!stderr.contains("EXECUTED safety"), "{stderr}");
    assert!(stderr.contains("EXECUTED echo"), "{stderr}");
    assert_eq!(
        by_id(&responses, &json!("after"))["result"]["isError"],
        false
    );
    assert!(responses.iter().all(|r| r["id"] != "big"));
}
