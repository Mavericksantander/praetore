//! A receipts journal line is accepted only in the byte form `wrap` writes:
//! `{"seq":N,"prev":"<hex>","evidence":<canonical evidence>}`. The approval
//! journal already requires that of its lines. Before, a line rewritten in
//! another byte form (whitespace, key order, a JSON escape such as `_`
//! for `_`) still verified, even against the saved head: integrity and the
//! chain link are computed over the canonical form, not the bytes. That let
//! a forwarded receipt hide its `praetore.approval_id` from the substring
//! test `wrap` used to find used approvals, so, with the execution record
//! cut from the end of the approval journal, the same approval ran again
//! while the receipts chain and its head stayed intact.
//!
//! Approvals are decided here with `approvals::decide` on a throwaway home,
//! as tests/evasion.rs does; the terminal check of `approve` is covered in
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

const TTL_ENV: &str = "PRAETORE_MCP_APPROVAL_TTL_SECONDS";
const APPROVAL_KEY: &str = "praetore.approval_id";
/// The same key with its `_` as a JSON escape: equal JSON, other bytes.
const ESCAPED_APPROVAL_KEY: &str = "praetore.approval\\u005fid";

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
        .env_remove(TTL_ENV)
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

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn rule(id: &str, tool: &str, effect: PolicyEffect) -> PolicyRule {
    PolicyRule::new(id, ACTION_TYPE, effect)
        .with_capability(CAPABILITY)
        .with_parameter_condition(PolicyCondition::exact("tool", json!(tool)))
}

/// `echo` allowed, `append` held for approval, the rest denied.
fn init_home() -> (tempfile::TempDir, Home) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let out = cli(&["init", "--dir", root.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    let home = Home::new(root);
    let mut policy = store::default_policy();
    policy
        .rules
        .push(rule("allow-echo", "echo", PolicyEffect::Allow));
    policy.rules.push(rule(
        "approve-append",
        "append",
        PolicyEffect::RequireApproval,
    ));
    fs::write(home.policy(), serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
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

fn verify_anchored(home: &Home, head: &str, approval_head: &str) -> Output {
    cli(&[
        "verify",
        "--dir",
        home.root.to_str().unwrap(),
        "--expected-head",
        head,
        "--expected-approval-head",
        approval_head,
    ])
}

fn printed_head(out: &Output) -> String {
    let text = stdout(out);
    let line = text
        .lines()
        .find(|line| line.starts_with("journal head: "))
        .expect("verify prints the journal head");
    let head = line
        .split_once(" head ")
        .and_then(|(_, rest)| rest.get(..64))
        .unwrap()
        .to_owned();
    assert!(head.chars().all(|c| c.is_ascii_hexdigit()), "{line}");
    head
}

fn printed_approval_head(out: &Output) -> String {
    let text = stdout(out);
    let line = text
        .lines()
        .find(|line| line.starts_with("approval journal: "))
        .expect("verify prints the approval journal line");
    line.split_once(" head ")
        .and_then(|(_, rest)| rest.get(..64))
        .unwrap()
        .to_owned()
}

/// The one receipts journal file of a one-day home.
fn journal_file(home: &Home) -> PathBuf {
    let mut files: Vec<PathBuf> = fs::read_dir(home.receipts_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    files.sort();
    assert_eq!(files.len(), 1, "one journal file for one day: {files:?}");
    files.remove(0)
}

/// Rewrites line `index` (0-based) of the receipts journal with `rewrite`,
/// which must keep the JSON value equal, and checks that it did.
fn rewrite_line(home: &Home, index: usize, rewrite: impl Fn(&str) -> String) -> String {
    let file = journal_file(home);
    let text = fs::read_to_string(&file).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let original = lines[index].clone();
    let rewritten = rewrite(&original);
    assert_ne!(rewritten, original, "the rewrite changed nothing");
    let before: Value = serde_json::from_str(&original).unwrap();
    let after: Value = serde_json::from_str(&rewritten).unwrap();
    assert_eq!(before, after, "the rewrite must keep the JSON value");
    lines[index] = rewritten.clone();
    let joined: String = lines.iter().map(|line| format!("{line}\n")).collect();
    fs::write(&file, joined).unwrap();
    rewritten
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

/// The forwarded receipt is written again with its approval key as a JSON
/// escape (`praetore.approval_id`): same JSON, other bytes. The
/// execution record is cut from the end of the approval journal. The retry
/// is held: `wrap` cannot read that line as a receipt, so it does not know
/// which approvals were used and does not forward. `verify` fails on the
/// line with and without the saved heads: integrity and the chain link are
/// unchanged by the rewrite, so only the byte check names it. A later
/// receipt (`echo`) keeps the rewritten line off the end of the journal, so
/// the hold comes from reading the used approvals, not from the writer
/// refusing an unreadable last line.
#[test]
fn a_receipt_rewritten_to_hide_its_approval_id_holds_the_retry_and_fails_verify() {
    let (temp, home) = init_home();
    let target = temp.path().join("target.txt");
    let arguments = json!({"path": target.to_str().unwrap(), "text": "a"});
    hold_and_approve(&home, &arguments);
    let (_, stderr) = wrap(
        &home,
        &[
            call(11, "append", arguments.clone()),
            call(12, "echo", json!({"text": "after"})),
        ],
    );
    assert_eq!(executed(&stderr, "append"), 1, "{stderr}");
    assert_eq!(executed(&stderr, "echo"), 1, "{stderr}");
    assert_eq!(fs::read_to_string(&target).unwrap(), "a");
    let out = verify(&home);
    let receipts_head = printed_head(&out);
    let approval_head = printed_approval_head(&out);

    let rewritten = rewrite_line(&home, 1, |line| {
        assert!(line.contains(APPROVAL_KEY), "{line}");
        line.replacen(APPROVAL_KEY, ESCAPED_APPROVAL_KEY, 1)
    });
    assert!(!rewritten.contains(APPROVAL_KEY), "{rewritten}");
    let journal = approval_journal(&home);
    let text = fs::read_to_string(&journal).unwrap();
    assert_eq!(text.lines().count(), 2, "one decision and one execution");
    let decision = text.lines().next().unwrap().to_owned();
    fs::write(&journal, format!("{decision}\n")).unwrap();

    // Before the retry, against the heads saved after the forwarded call:
    // the rewritten line is named. It is no longer a readable entry, so the
    // chain cannot be rebuilt up to the saved head either.
    let out = verify_anchored(&home, &receipts_head, &approval_head);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(
        text.contains(":2: not in canonical form"),
        "verify must name the rewritten line: {text}"
    );

    let (out, stderr) = wrap(&home, &[call(13, "append", arguments)]);
    assert_eq!(
        executed(&stderr, "append"),
        0,
        "held, not run again: {stderr}"
    );
    let reply = stdout(&out);
    assert!(
        reply.contains("Local approval could not be recorded")
            && reply.contains("not in canonical form"),
        "the client reply names the line that could not be read: {reply}"
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), "a");
    let out = verify(&home);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("not in canonical form"),
        "{}",
        stdout(&out)
    );
}

/// A receipt line written again with spaces after the separators and its
/// keys in another order (same JSON) fails `verify`, also against the head
/// saved before the rewrite: the chain is intact, the bytes are not the
/// ones `wrap` writes.
#[test]
fn a_receipt_line_in_another_byte_form_fails_verify_against_the_saved_head() {
    let (_temp, home) = init_home();
    let (_, stderr) = wrap(
        &home,
        &[
            call(2, "echo", json!({"n": 1})),
            call(3, "echo", json!({"n": 2})),
            call(4, "echo", json!({"n": 3})),
        ],
    );
    assert_eq!(executed(&stderr, "echo"), 3, "{stderr}");
    let out = verify(&home);
    let head = printed_head(&out);
    let out = verify_anchored(&home, &head, "none");
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));

    rewrite_line(&home, 1, |line| {
        // Keys reversed and a space after every separator: another byte form
        // of the same object.
        let value: Value = serde_json::from_str(line).unwrap();
        let object = value.as_object().unwrap();
        let members: Vec<String> = object
            .iter()
            .rev()
            .map(|(key, value)| format!("{key:?} : {value}"))
            .collect();
        format!("{{ {} }}", members.join(" , "))
    });

    let out = verify_anchored(&home, &head, "none");
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains(":2: not in canonical form"), "{text}");
    assert!(
        text.contains("FAIL 3 receipts: 2 verified, 1 failed"),
        "{text}"
    );
}

/// `receipts` marks a line in another byte form INVALID and names the
/// cause, instead of rendering it as a receipt.
#[test]
fn receipts_marks_a_line_in_another_byte_form_invalid() {
    let (_temp, home) = init_home();
    let (_, stderr) = wrap(
        &home,
        &[
            call(2, "echo", json!({"n": 1})),
            call(3, "echo", json!({"n": 2})),
        ],
    );
    assert_eq!(executed(&stderr, "echo"), 2, "{stderr}");
    rewrite_line(&home, 0, |line| format!(" {line}"));
    let out = cli(&["receipts", "--dir", home.root.to_str().unwrap()]);
    let text = stdout(&out);
    assert!(out.status.success(), "{out:?}");
    let invalid: Vec<&str> = text.lines().filter(|l| l.starts_with("INVALID ")).collect();
    assert_eq!(invalid.len(), 1, "{text}");
    assert!(invalid[0].contains(":1: not in canonical form"), "{text}");
    assert_eq!(
        text.lines().filter(|l| l.contains(" ALLOW ")).count(),
        1,
        "{text}"
    );
}
