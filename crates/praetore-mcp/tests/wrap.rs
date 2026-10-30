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
    let policy = Policy::new_v2("test-policy", 1, rules);
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
    let out = run(
        &[
            "wrap",
            "--dir",
            home.root.to_str().unwrap(),
            "--name",
            "fake",
            "--mode",
            mode,
            "--",
            server.to_str().unwrap(),
        ],
        input,
    );
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
        .map(|l| Evidence::from_json(&l.text).unwrap())
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
    let (_temp, home) = init_home();
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
            json!({"jsonrpc":"2.0","id":"e","method":"tools/call","params":{"name":"echo","arguments":{"path":"/tmp/ok"}}}),
            json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":{"path":"/secret/keys"}}}),
        ]),
    );
    assert!(out.status.success(), "{stderr}");
    assert_eq!(responses.len(), 5, "{responses:?}");

    let denied = by_id(&responses, &json!(5));
    assert_eq!(denied["result"]["isError"], true);
    let text = denied["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("Denied by PRÆTORE"), "{text}");
    assert!(text.contains("deny-delete-file"), "{text}");

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

#[test]
fn broken_home_fails_closed_in_enforce_and_open_in_observe() {
    let (_temp, home) = init_home();
    fs::write(home.policy(), "{not a policy").unwrap();
    let call = json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo","arguments":{}}});

    let (responses, stderr, _) = wrap(&home, "enforce", &session(vec![call.clone()]));
    assert_eq!(
        by_id(&responses, &json!(2))["result"]["tools"][0]["name"],
        "echo"
    );
    assert_eq!(by_id(&responses, &json!(9))["result"]["isError"], true);
    assert!(!stderr.contains("EXECUTED"), "{stderr}");

    let (responses, stderr, _) = wrap(&home, "observe", &session(vec![call]));
    assert_eq!(by_id(&responses, &json!(9))["result"]["isError"], false);
    assert!(stderr.contains("WITHOUT"), "{stderr}");
    assert!(receipts::read_journal(&home).unwrap().is_empty());
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
    let (_temp, home) = init_home();
    let dir = home.root.to_str().unwrap();
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
            json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"echo","arguments":{"path":"/tmp/ok"}}}),
            json!({"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"echo","arguments":{"path":"/secret/key"}}}),
        ]),
    );
    assert!(out.status.success(), "{stderr}");
    let denied = by_id(&responses, &json!(10))["result"].clone();
    assert_eq!(denied["isError"], true);
    assert!(
        denied["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("deny-delete")
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
