//! Evasion battery: what an agent, or a process running as the same user,
//! can try in order to get a call through praetore-mcp or to erase its
//! trace. Each test pins today's behaviour, whether praetore-mcp blocks it,
//! detects it afterwards, or does neither (a known limitation). The table in
//! docs/security/evasion-matrix.md names each test.
//!
//! Approvals are decided here with `approvals::decide` on a throwaway home,
//! as tests/report.rs does; the terminal check of `approve` is covered in
//! tests/approvals.rs.

use praetore_core::{PolicyCondition, PolicyEffect, PolicyRule};
use praetore_mcp::{
    approvals::{self, HumanOutcome},
    store::{self, ACTION_TYPE, CAPABILITY, Home},
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

fn run(program: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(program)
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

fn cli(args: &[&str]) -> Output {
    run(Path::new(bin()), args, "")
}

fn rule(id: &str, tool: &str, effect: PolicyEffect) -> PolicyRule {
    PolicyRule::new(id, ACTION_TYPE, effect)
        .with_capability(CAPABILITY)
        .with_parameter_condition(PolicyCondition::exact("tool", json!(tool)))
}

/// `echo` allowed, `append` held for approval, the rest denied (default
/// deny), plus `extra` rules.
fn write_policy(home: &Home, extra: Vec<PolicyRule>) {
    let mut policy = store::default_policy();
    policy
        .rules
        .push(rule("allow-echo", "echo", PolicyEffect::Allow));
    policy.rules.push(rule(
        "approve-append",
        "append",
        PolicyEffect::RequireApproval,
    ));
    policy.rules.extend(extra);
    fs::write(home.policy(), serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
}

fn init_home() -> (tempfile::TempDir, Home) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let out = cli(&["init", "--dir", root.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    let home = Home::new(root);
    write_policy(&home, Vec::new());
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

fn session(calls: &[Value]) -> String {
    let mut lines = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ];
    lines.extend_from_slice(calls);
    lines.iter().map(|line| format!("{line}\n")).collect()
}

/// One enforce session through `wrap`; returns the server's stderr too,
/// where `fake_server` logs `EXECUTED <tool>` for each forwarded call.
fn wrap(home: &Home, calls: &[Value]) -> (Output, String) {
    let server = fake_server();
    let out = run(
        Path::new(bin()),
        &[
            "wrap",
            "--dir",
            home.root.to_str().unwrap(),
            "--name",
            "fake",
            "--mode",
            "enforce",
            "--no-report",
            "--",
            server.to_str().unwrap(),
        ],
        &session(calls),
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (out, stderr)
}

fn executed(stderr: &str, tool: &str) -> usize {
    stderr
        .lines()
        .filter(|line| *line == format!("fake_server: EXECUTED {tool}"))
        .count()
}

fn verify(home: &Home) -> Output {
    cli(&["verify", "--dir", home.root.to_str().unwrap()])
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The receipts journal files of `home` (`*.jsonl`), in name order.
fn receipt_files(home: &Home) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(home.receipts_dir())
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

fn receipts(home: &Home) -> Vec<Value> {
    receipt_files(home)
        .iter()
        .flat_map(|file| {
            fs::read_to_string(file)
                .unwrap()
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).unwrap())
                .collect::<Vec<Value>>()
        })
        .collect()
}

fn approval_journal(home: &Home) -> PathBuf {
    home.root.join("approvals").join("journal.jsonl")
}

/// Holds `append(arguments)` once and approves it, as a person would.
fn hold_and_approve(home: &Home, arguments: &Value) {
    let (out, stderr) = wrap(home, &[call(10, "append", arguments.clone())]);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(executed(&stderr, "append"), 0, "held, not forwarded");
    let pending = approvals::list_pending(home).unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    approvals::decide(home, &pending[0].approval_id, HumanOutcome::Approve, None).unwrap();
}

// ---------- (a) the server without wrap ----------

/// (a) Limitación conocida. A client configured to start the server itself,
/// not through `wrap`, reaches it directly: the call runs and praetore-mcp
/// writes nothing, so `verify` still passes with the same count. Closing it
/// needs the server reachable only through `wrap` (OS sandbox or a separate
/// user for the server) and a check of the client config.
#[test]
fn a_server_started_without_wrap_runs_the_call_and_leaves_no_receipt() {
    let (temp, home) = init_home();
    let target = temp.path().join("target.txt");
    let (out, _) = wrap(&home, &[call(2, "echo", json!({"n": 1}))]);
    assert!(out.status.success());
    let before = receipts(&home).len();
    assert_eq!(before, 1);

    // Same call the policy holds for approval, sent straight to the server.
    let arguments = json!({"path": target.to_str().unwrap(), "text": "direct"});
    let out = run(
        &fake_server(),
        &[],
        &session(&[call(3, "append", arguments)]),
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(fs::read_to_string(&target).unwrap(), "direct");
    assert_eq!(receipts(&home).len(), before, "praetore-mcp saw nothing");
    let out = verify(&home);
    assert!(out.status.success(), "{out:?}");
    assert!(
        stdout(&out).starts_with("OK 1 receipts"),
        "{}",
        stdout(&out)
    );
}

// ---------- (b) editing the policy or the config ----------

/// (b) Limitación conocida, con rastro. A process that can write
/// `policy.json` can allow what was denied: the next `wrap` reads the new
/// policy and forwards the call. `verify` passes (editing the policy is
/// also how a person changes it). What is left is the trace: every receipt
/// carries the digest of the policy that decided it, so the change shows as
/// a new `policy_digest` between two receipts. Closing it needs a policy
/// signed by a key the agent cannot use, checked by `wrap` at start.
#[test]
fn an_edited_policy_allows_a_denied_call_and_shows_only_as_a_new_policy_digest() {
    let (_temp, home) = init_home();
    let (_, stderr) = wrap(&home, &[call(2, "delete_file", json!({"path": "/x"}))]);
    assert_eq!(executed(&stderr, "delete_file"), 0, "denied by default");

    write_policy(
        &home,
        vec![rule("sneaky", "delete_file", PolicyEffect::Allow)],
    );
    let (_, stderr) = wrap(&home, &[call(3, "delete_file", json!({"path": "/x"}))]);
    assert_eq!(executed(&stderr, "delete_file"), 1, "{stderr}");

    let out = verify(&home);
    assert!(out.status.success(), "{out:?}");
    let digests: Vec<String> = receipts(&home)
        .iter()
        .map(|r| r["evidence"]["policy_digest"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(digests.len(), 2);
    assert_ne!(digests[0], digests[1], "the edit shows as a new digest");
}

/// (b) Limitación conocida. `report = false` in `config.toml` stops the
/// session reports; the receipts are still written and verified. The
/// config never changes a decision. Closing it is not needed for
/// decisions; a home that must keep reports would need the config signed
/// like the policy.
#[test]
fn an_edited_config_turns_reports_off_but_not_the_receipts() {
    let (_temp, home) = init_home();
    fs::write(home.root.join("config.toml"), "report = false\n").unwrap();
    let server = fake_server();
    let out = run(
        Path::new(bin()),
        &[
            "wrap",
            "--dir",
            home.root.to_str().unwrap(),
            "--name",
            "fake",
            "--mode",
            "enforce",
            "--",
            server.to_str().unwrap(),
        ],
        &session(&[call(2, "echo", json!({"n": 1}))]),
    );
    assert!(out.status.success(), "{out:?}");
    assert!(!home.root.join("reports").exists(), "no report written");
    assert_eq!(receipts(&home).len(), 1);
    assert!(verify(&home).status.success());
}

// ---------- (c) deleting or truncating a journal ----------

/// Three allowed calls in one session: three chained receipts.
fn three_receipts() -> (tempfile::TempDir, Home) {
    let (temp, home) = init_home();
    let calls: Vec<Value> = (0..3)
        .map(|n| call(2 + n, "echo", json!({ "n": n })))
        .collect();
    let (out, stderr) = wrap(&home, &calls);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(receipts(&home).len(), 3);
    assert!(verify(&home).status.success());
    (temp, home)
}

fn rewrite_receipts(home: &Home, keep: impl Fn(usize, &str) -> Option<String>) {
    let files = receipt_files(home);
    assert_eq!(files.len(), 1, "one journal file for one day");
    let text = fs::read_to_string(&files[0]).unwrap();
    let kept: String = text
        .lines()
        .enumerate()
        .filter_map(|(index, line)| keep(index, line))
        .map(|line| format!("{line}\n"))
        .collect();
    fs::write(&files[0], kept).unwrap();
}

/// (c) Detectado después. Removing a receipt from the middle of the
/// journal breaks the hash chain: `verify` fails and names the gap.
#[test]
fn a_receipt_removed_from_the_middle_fails_verify() {
    let (_temp, home) = three_receipts();
    rewrite_receipts(&home, |index, line| (index != 1).then(|| line.to_owned()));
    let out = verify(&home);
    assert!(!out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("FAIL"), "{}", stdout(&out));
}

/// (c) Detectado después. A journal cut in the middle of a line is not
/// JSON any more: `verify` fails on it.
#[test]
fn a_receipts_journal_cut_mid_line_fails_verify() {
    let (_temp, home) = three_receipts();
    rewrite_receipts(&home, |index, line| {
        Some(if index == 2 {
            line[..line.len() / 2].to_owned()
        } else {
            line.to_owned()
        })
    });
    let out = verify(&home);
    assert!(!out.status.success(), "{}", stdout(&out));
}

/// (c) Limitación conocida. Dropping the last receipts whole, or deleting
/// the journal, leaves a valid shorter chain (or none): `verify` passes.
/// Only a head kept outside the home shows it (`verify` prints the head;
/// the session report records it at close). Closing it needs `verify` to
/// check against an external head, or the head sent off the machine.
#[test]
fn dropping_the_last_receipts_or_the_whole_journal_passes_verify() {
    let (_temp, home) = three_receipts();
    let head_before = stdout(&verify(&home));
    rewrite_receipts(&home, |index, line| (index < 2).then(|| line.to_owned()));
    let out = verify(&home);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(
        stdout(&out).starts_with("OK 2 receipts"),
        "{}",
        stdout(&out)
    );
    assert_ne!(stdout(&out), head_before, "only the printed head differs");

    for file in receipt_files(&home) {
        fs::remove_file(file).unwrap();
    }
    let out = verify(&home);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(
        stdout(&out).starts_with("OK 0 receipts"),
        "{}",
        stdout(&out)
    );
}

/// (c) and (d) Limitación conocida. Dropping the execution record from the
/// end of `approvals/journal.jsonl` makes a used approval unused again: the
/// same call is forwarded a second time. `verify` does not flag it. Closing
/// it needs the approval head kept outside the home, or the execution
/// bound into the receipts chain so `verify` sees two executions.
#[test]
fn truncating_the_approval_journal_lets_a_used_approval_run_again() {
    let (temp, home) = init_home();
    let target = temp.path().join("target.txt");
    let arguments = json!({"path": target.to_str().unwrap(), "text": "a"});
    hold_and_approve(&home, &arguments);
    let (_, stderr) = wrap(&home, &[call(11, "append", arguments.clone())]);
    assert_eq!(executed(&stderr, "append"), 1, "{stderr}");

    let journal = approval_journal(&home);
    let text = fs::read_to_string(&journal).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "decision and execution");
    assert!(lines[1].contains("\"execution\""), "{}", lines[1]);
    fs::write(&journal, format!("{}\n", lines[0])).unwrap();

    let (_, stderr) = wrap(&home, &[call(12, "append", arguments.clone())]);
    assert_eq!(executed(&stderr, "append"), 1, "forwarded again: {stderr}");
    assert_eq!(fs::read_to_string(&target).unwrap(), "aa");
    let out = verify(&home);
    assert!(out.status.success(), "{}", stdout(&out));
}

/// (c) Bloqueado for the call, limitación conocida for the trace. Deleting
/// `approvals/journal.jsonl` before the approved call ran erases the
/// decision with it: the call is held again. Deleting it after the call ran
/// erases the decision and the execution; `verify` reads only the receipts
/// journal and still passes. Closing it needs `verify` to require, for
/// each receipt forwarded on an approval, the signed decision it names.
#[test]
fn deleting_the_approval_journal_holds_the_call_and_verify_still_passes() {
    let (temp, home) = init_home();
    let target = temp.path().join("target.txt");
    let arguments = json!({"path": target.to_str().unwrap(), "text": "a"});
    hold_and_approve(&home, &arguments);
    fs::remove_file(approval_journal(&home)).unwrap();
    let (_, stderr) = wrap(&home, &[call(11, "append", arguments.clone())]);
    assert_eq!(executed(&stderr, "append"), 0, "{stderr}");
    assert!(!target.exists());

    // Approved and executed, then the approval journal deleted.
    let pending = approvals::list_pending(&home).unwrap();
    approvals::decide(&home, &pending[0].approval_id, HumanOutcome::Approve, None).unwrap();
    let (_, stderr) = wrap(&home, &[call(12, "append", arguments)]);
    assert_eq!(executed(&stderr, "append"), 1, "{stderr}");
    assert!(verify(&home).status.success());
    fs::remove_file(approval_journal(&home)).unwrap();
    let out = verify(&home);
    assert!(out.status.success(), "{}", stdout(&out));
}

// ---------- (d) reusing an approval ----------

/// (d) Bloqueado. An approval is used by one call: the same call again is
/// held, not forwarded.
#[test]
fn an_approval_is_used_once() {
    let (temp, home) = init_home();
    let target = temp.path().join("target.txt");
    let arguments = json!({"path": target.to_str().unwrap(), "text": "a"});
    hold_and_approve(&home, &arguments);
    let (_, stderr) = wrap(
        &home,
        &[
            call(11, "append", arguments.clone()),
            call(12, "append", arguments.clone()),
        ],
    );
    assert_eq!(executed(&stderr, "append"), 1, "{stderr}");
    let (_, stderr) = wrap(&home, &[call(13, "append", arguments)]);
    assert_eq!(executed(&stderr, "append"), 0, "{stderr}");
    assert_eq!(fs::read_to_string(&target).unwrap(), "a");
    assert!(verify(&home).status.success());
}

// ---------- (e) other arguments after approval ----------

/// (e) Bloqueado. The approval binds the server, the tool and the canonical
/// arguments: a call with any other argument is held, and the approved one
/// still passes once.
#[test]
fn an_approval_does_not_cover_other_arguments() {
    let (temp, home) = init_home();
    let target = temp.path().join("target.txt");
    let other = temp.path().join("other.txt");
    let arguments = json!({"path": target.to_str().unwrap(), "text": "a"});
    hold_and_approve(&home, &arguments);
    for changed in [
        json!({"path": other.to_str().unwrap(), "text": "a"}),
        json!({"path": target.to_str().unwrap(), "text": "b"}),
        json!({"path": target.to_str().unwrap(), "text": "a", "mode": "x"}),
    ] {
        let (_, stderr) = wrap(&home, &[call(11, "append", changed.clone())]);
        assert_eq!(executed(&stderr, "append"), 0, "{changed}: {stderr}");
    }
    assert!(!other.exists());
    let (_, stderr) = wrap(&home, &[call(12, "append", arguments)]);
    assert_eq!(executed(&stderr, "append"), 1, "{stderr}");
}

// ---------- (f) another allowed tool for the same effect ----------

/// (f) Limitación conocida. The policy decides by tool name and arguments,
/// not by effect: with `append` held for approval and `write_text` allowed,
/// `write_text` writes the same file at once. The receipt records the
/// call as allowed by the rule that matched. Closing it needs rules over
/// the effect (paths, resources) for every tool of the server, and
/// `policy coverage` to show the tools a rule leaves open.
#[test]
fn another_allowed_tool_with_the_same_effect_is_forwarded() {
    let (temp, home) = init_home();
    write_policy(
        &home,
        vec![rule("allow-write-text", "write_text", PolicyEffect::Allow)],
    );
    let target = temp.path().join("target.txt");
    let arguments = json!({"path": target.to_str().unwrap(), "text": "a"});
    let (_, stderr) = wrap(&home, &[call(2, "append", arguments.clone())]);
    assert_eq!(executed(&stderr, "append"), 0, "append is held");
    let (_, stderr) = wrap(&home, &[call(3, "write_text", arguments)]);
    assert_eq!(executed(&stderr, "write_text"), 1, "{stderr}");
    assert_eq!(fs::read_to_string(&target).unwrap(), "a");
    let last = receipts(&home).pop().unwrap();
    assert_eq!(
        last["evidence"]["decision"]["decided_by"]["rule_id"],
        "allow-write-text"
    );
    assert!(verify(&home).status.success());
}
