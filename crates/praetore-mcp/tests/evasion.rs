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

const TTL_ENV: &str = "PRAETORE_MCP_APPROVAL_TTL_SECONDS";

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
    run_env(program, args, stdin, &[])
}

/// [`run`] with `env` set on top of the test's environment, minus any
/// approval TTL the test runner may have exported.
fn run_env(program: &Path, args: &[&str], stdin: &str, env: &[(&str, &str)]) -> Output {
    let mut child = Command::new(program)
        .args(args)
        .env_remove(TTL_ENV)
        .envs(env.iter().copied())
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
    wrap_as(home, "fake", calls)
}

/// [`wrap`] with the server registered under `name` (`--name`).
fn wrap_as(home: &Home, name: &str, calls: &[Value]) -> (Output, String) {
    wrap_full(home, name, calls, &[])
}

/// [`wrap_as`] with `env` set for `wrap`, as an MCP client config's `env`
/// block sets it.
fn wrap_full(home: &Home, name: &str, calls: &[Value], env: &[(&str, &str)]) -> (Output, String) {
    let server = fake_server();
    let out = run_env(
        Path::new(bin()),
        &[
            "wrap",
            "--dir",
            home.root.to_str().unwrap(),
            "--name",
            name,
            "--mode",
            "enforce",
            "--no-report",
            "--",
            server.to_str().unwrap(),
        ],
        &session(calls),
        env,
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
/// approval window that `config.toml` can also set has its own test,
/// [`the_ttl_in_config_toml_stretches_new_approvals`]. A home that must
/// keep reports would need the config signed like the policy.
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

/// The receipts journal head that `verify` prints.
fn printed_head(out: &Output) -> String {
    let text = stdout(out);
    let at = text.find(" head ").expect("verify prints the journal head") + " head ".len();
    let head = &text[at..at + 64];
    assert!(head.chars().all(|c| c.is_ascii_hexdigit()), "{text}");
    head.to_owned()
}

fn verify_with_head(home: &Home, head: &str) -> Output {
    cli(&[
        "verify",
        "--dir",
        home.root.to_str().unwrap(),
        "--expected-head",
        head,
    ])
}

/// (c) Detectado después con `--expected-head` (head guardado fuera de la
/// máquina); limitación conocida sin él. Dropping the last receipts whole,
/// or deleting the journal, leaves a valid shorter chain (or none): plain
/// `verify` passes. `verify --expected-head` with the head printed before
/// fails in both cases. It detects only if that head was kept where the
/// agent cannot write.
#[test]
fn dropping_the_last_receipts_or_the_journal_fails_only_verify_with_the_expected_head() {
    let (_temp, home) = three_receipts();
    let before = verify(&home);
    let head = printed_head(&before);
    assert!(
        verify_with_head(&home, &head).status.success(),
        "{}",
        stdout(&before)
    );

    rewrite_receipts(&home, |index, line| (index < 2).then(|| line.to_owned()));
    let out = verify(&home);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(
        stdout(&out).starts_with("OK 2 receipts"),
        "{}",
        stdout(&out)
    );
    let out = verify_with_head(&home, &head);
    assert!(!out.status.success(), "trimmed: {}", stdout(&out));

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
    let out = verify_with_head(&home, &head);
    assert!(!out.status.success(), "deleted: {}", stdout(&out));
}

/// (c) and (d) Limitación conocida. Dropping the execution record from the
/// end of `approvals/journal.jsonl` makes a used approval unused again: the
/// same call is forwarded a second time and `verify` passes. The receipts
/// do not show it: the held call and each forwarded call all record
/// REQUIRE_APPROVAL and none carries the approval id, and `--expected-head`
/// covers only the receipts journal. Closing it needs a head for the
/// approval journal kept outside the home, or the execution bound into the
/// receipts chain so `verify` sees two executions of one approval.
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

    // Why nothing else shows the second run: the receipts of the held call
    // and of both forwarded calls look the same. All three record
    // REQUIRE_APPROVAL, and none carries the approval id or any key naming
    // an approval.
    let decision: Value = serde_json::from_str(lines[0]).unwrap();
    let approval_id = string_under(&decision, "approval_id").expect("approval_id in the journal");
    let all = receipts(&home);
    assert_eq!(all.len(), 3, "held, forwarded, forwarded again");
    for receipt in &all {
        assert_eq!(
            receipt["evidence"]["decision"]["outcome"], "RequireApproval",
            "{receipt}"
        );
        assert!(
            keys_of(receipt).iter().all(|key| !key.contains("approval")),
            "{receipt}"
        );
        assert!(!receipt.to_string().contains(&approval_id), "{receipt}");
    }
}

/// The head on the `approval journal: ... head HEX` line of `verify`.
fn printed_approval_head(out: &Output) -> String {
    let text = stdout(out);
    let line = text
        .lines()
        .find(|line| line.starts_with("approval journal: "))
        .expect("verify prints the approval journal line");
    let head = line.rsplit(" head ").next().unwrap().to_owned();
    assert!(
        head.len() == 64 && head.chars().all(|c| c.is_ascii_hexdigit()),
        "{line}"
    );
    head
}

fn verify_with_approval_head(home: &Home, head: &str) -> Output {
    cli(&[
        "verify",
        "--dir",
        home.root.to_str().unwrap(),
        "--expected-approval-head",
        head,
    ])
}

/// (c) `verify --expected-approval-head`: the approval journal must end at
/// the head printed earlier. It passes at that head, and fails once the
/// last record is cut or the file is deleted, while plain `verify` passes.
/// A malformed head is a usage error.
#[test]
fn verify_with_the_expected_approval_head_fails_after_a_cut_or_a_deletion() {
    let (temp, home) = init_home();
    let arguments = json!({"path": temp.path().join("t.txt").to_str().unwrap(), "text": "a"});
    hold_and_approve(&home, &arguments);
    let (_, stderr) = wrap(&home, &[call(11, "append", arguments.clone())]);
    assert_eq!(executed(&stderr, "append"), 1, "{stderr}");
    let head = printed_approval_head(&verify(&home));
    let out = verify_with_approval_head(&home, &head);
    assert!(out.status.success(), "{}", stdout(&out));
    let both = cli(&[
        "verify",
        "--dir",
        home.root.to_str().unwrap(),
        "--expected-head",
        &printed_head(&verify(&home)),
        "--expected-approval-head",
        &head,
    ]);
    assert!(both.status.success(), "{}", stdout(&both));

    let journal = approval_journal(&home);
    let text = fs::read_to_string(&journal).unwrap();
    let first = text.lines().next().unwrap().to_owned();
    fs::write(&journal, format!("{first}\n")).unwrap();
    assert!(
        verify(&home).status.success(),
        "plain verify passes after the cut"
    );
    let out = verify_with_approval_head(&home, &head);
    assert_eq!(out.status.code(), Some(1), "cut: {}", stdout(&out));
    assert!(
        stdout(&out).contains("does not match the expected approval head"),
        "{}",
        stdout(&out)
    );

    fs::remove_file(&journal).unwrap();
    let out = verify_with_approval_head(&home, &head);
    assert_eq!(out.status.code(), Some(1), "deleted: {}", stdout(&out));
    assert!(
        stdout(&out).contains("approval journal has no head"),
        "{}",
        stdout(&out)
    );

    let out = verify_with_approval_head(&home, "abc");
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--expected-approval-head must be 64"),
        "{out:?}"
    );
}

/// The `sh` block of README.md (Local approval) that saves and checks the
/// approval head, run as written, with `SAVED` from the environment instead
/// of its placeholder line.
fn readme_approval_head_check(home: &Home, saved: &str) -> (String, String) {
    let readme =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md")).unwrap();
    let block = readme
        .split("```sh\n")
        .skip(1)
        .filter_map(|rest| rest.split_once("```").map(|(block, _)| block))
        .find(|block| block.contains("approval journal still ends at"))
        .expect("README.md has the approval head check");
    assert!(
        block.contains("--expected-approval-head"),
        "the README check no longer uses --expected-approval-head"
    );
    let script: String = block
        .lines()
        .filter(|line| !line.starts_with("SAVED="))
        .map(|line| format!("{line}\n"))
        .collect();
    let bin_dir = Path::new(bin()).parent().unwrap();
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = Command::new("sh")
        .args(["-c", &script])
        .env("PATH", path)
        .env("DIR", &home.root)
        .env("SAVED", saved)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    // The save command prints the head, or nothing when there is none; the
    // check always prints one verdict line, last.
    let lines: Vec<&str> = text.lines().collect();
    let (verdict, printed) = lines.split_last().expect("a verdict line");
    (printed.join("\n"), (*verdict).to_owned())
}

/// The README command that checks a saved approval head with
/// `verify --expected-approval-head`: the head printed after a run passes,
/// a later approval moves it, and cutting or deleting the journal fails.
#[cfg(unix)]
#[test]
fn the_readme_approval_head_check_finds_a_cut_or_deleted_journal() {
    let (temp, home) = init_home();
    let first = json!({"path": temp.path().join("a.txt").to_str().unwrap(), "text": "a"});
    hold_and_approve(&home, &first);
    let (_, stderr) = wrap(&home, &[call(11, "append", first.clone())]);
    assert_eq!(executed(&stderr, "append"), 1, "{stderr}");

    let (saved, verdict) = readme_approval_head_check(&home, &"0".repeat(64));
    assert!(
        saved.len() == 64 && saved.chars().all(|c| c.is_ascii_hexdigit()),
        "printed head: {saved:?}"
    );
    assert_eq!(verdict, "approval journal changed or verify failed");
    let (_, verdict) = readme_approval_head_check(&home, &saved);
    assert_eq!(verdict, format!("approval journal still ends at {saved}"));

    // A later approval, decided and used, moves the head: the old one no
    // longer passes, the new one does.
    let second = json!({"path": temp.path().join("b.txt").to_str().unwrap(), "text": "b"});
    hold_and_approve(&home, &second);
    let (_, stderr) = wrap(&home, &[call(12, "append", second.clone())]);
    assert_eq!(executed(&stderr, "append"), 1, "{stderr}");
    let (now, verdict) = readme_approval_head_check(&home, &saved);
    assert_ne!(now, saved, "the head moved");
    assert_eq!(verdict, "approval journal changed or verify failed");
    let (_, verdict) = readme_approval_head_check(&home, &now);
    assert_eq!(verdict, format!("approval journal still ends at {now}"));

    // The last execution record dropped: the check with the saved head fails.
    let journal = approval_journal(&home);
    let text = fs::read_to_string(&journal).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4, "two decisions, two executions");
    fs::write(&journal, format!("{}\n", lines[..3].join("\n"))).unwrap();
    let (_, verdict) = readme_approval_head_check(&home, &now);
    assert_eq!(verdict, "approval journal changed or verify failed");

    fs::remove_file(&journal).unwrap();
    let (printed, verdict) = readme_approval_head_check(&home, &now);
    assert_eq!(printed, "", "no head to print");
    assert_eq!(verdict, "approval journal changed or verify failed");
}

/// Every object key in `value`, at any depth.
fn keys_of(value: &Value) -> Vec<String> {
    match value {
        Value::Object(map) => map
            .iter()
            .flat_map(|(key, inner)| std::iter::once(key.clone()).chain(keys_of(inner)))
            .collect(),
        Value::Array(items) => items.iter().flat_map(keys_of).collect(),
        _ => Vec::new(),
    }
}

/// The first string found under `key` in `value`, at any depth.
fn string_under(value: &Value, key: &str) -> Option<String> {
    match value {
        Value::Object(map) => map
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| map.values().find_map(|inner| string_under(inner, key))),
        Value::Array(items) => items.iter().find_map(|inner| string_under(inner, key)),
        _ => None,
    }
}

/// (c) Bloqueado for the call, limitación conocida for the trace. Deleting
/// `approvals/journal.jsonl` before the approved call ran erases the
/// decision with it: the call is held again. Deleting it after the call ran
/// erases the decision and the execution. `verify` reads
/// `approvals/journal.jsonl` when it is there (approver signature, binding
/// to the held receipt, expiry, single use), but with the file gone there is
/// no record to check, and no receipt names the approval, so it passes.
/// Closing it needs `verify` to require, for each receipt forwarded on an
/// approval, the signed decision it names.
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

/// (e) Bloqueado. The approval also binds the server name and the tool:
/// the same arguments sent to the same tool under another `--name`, or to
/// another held tool, are held and not run, and the approved call still
/// passes once afterwards.
#[test]
fn an_approval_does_not_cover_another_server_or_another_held_tool() {
    let (temp, home) = init_home();
    write_policy(
        &home,
        vec![rule(
            "approve-write-text",
            "write_text",
            PolicyEffect::RequireApproval,
        )],
    );
    let target = temp.path().join("target.txt");
    let arguments = json!({"path": target.to_str().unwrap(), "text": "a"});
    hold_and_approve(&home, &arguments);

    // Same tool and arguments, server registered as `other`; the
    // approve-append rule has no server condition, so it holds there too.
    let (out, stderr) = wrap_as(&home, "other", &[call(11, "append", arguments.clone())]);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(executed(&stderr, "append"), 0, "other server: {stderr}");
    assert!(
        stderr.contains("other/append waiting for local approval"),
        "{stderr}"
    );

    // Another held tool, same arguments.
    let (_, stderr) = wrap(&home, &[call(12, "write_text", arguments.clone())]);
    assert_eq!(executed(&stderr, "write_text"), 0, "other tool: {stderr}");
    assert!(
        stderr.contains("fake/write_text waiting for local approval"),
        "{stderr}"
    );
    assert!(!target.exists(), "nothing was written");

    // The approval is still unused: the approved call passes once.
    let (_, stderr) = wrap(&home, &[call(13, "append", arguments)]);
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

// ---------- (b) the approval window ----------

/// Holds `append` once through `wrap` with `env`, approves it, and returns
/// the window (`expires_at - created_at`, in seconds) of the pending file
/// and of the signed decision in `approvals/journal.jsonl`.
fn approval_window(home: &Home, env: &[(&str, &str)]) -> (i64, i64) {
    let arguments = json!({"path": home.root.join("w.txt").to_str().unwrap(), "text": "w"});
    let (out, stderr) = wrap_full(home, "fake", &[call(10, "append", arguments)], env);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(executed(&stderr, "append"), 0, "held, not forwarded");
    let pending = approvals::list_pending(home).unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    let id = &pending[0].approval_id;
    let file = home
        .root
        .join("approvals")
        .join("pending")
        .join(format!("{id}.json"));
    let file: Value = serde_json::from_str(&fs::read_to_string(file).unwrap()).unwrap();
    approvals::decide(home, id, HumanOutcome::Approve, None).unwrap();
    let line = fs::read_to_string(approval_journal(home)).unwrap();
    let decision: Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();
    (window_of(&file), window_of(&decision))
}

fn window_of(value: &Value) -> i64 {
    let at = |key: &str| {
        time::OffsetDateTime::parse(
            &string_under(value, key).unwrap_or_else(|| panic!("{key} in {value}")),
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
    };
    (at("expires_at") - at("created_at")).whole_seconds()
}

/// (b) Limitación conocida, con rastro. `PRAETORE_MCP_APPROVAL_TTL_SECONDS`
/// in the `env` block of the MCP client config reaches `wrap`, so a process
/// that can edit that config can stretch the window of every new approval
/// up to 24 h. The window is signed into each decision (`created_at`,
/// `expires_at` in `approvals/journal.jsonl`), and `verify` passes: it
/// checks that an execution is inside the window, not how long the window
/// is. Closing it needs the TTL set where the agent cannot write, or
/// `verify` checking each window against a maximum kept outside the home.
#[test]
fn the_ttl_env_var_in_the_client_config_stretches_new_approvals() {
    let (_temp, home) = init_home();
    assert_eq!(approval_window(&home, &[]), (600, 600), "default");
    let (_temp, home) = init_home();
    assert_eq!(
        approval_window(&home, &[(TTL_ENV, "86400")]),
        (86400, 86400)
    );
    let out = verify(&home);
    assert!(out.status.success(), "{}", stdout(&out));
}

/// (b) Limitación conocida, con rastro. `DIR/approvals/ttl-seconds` is read
/// from the home, so a process that can write the home can stretch the
/// window of every new approval up to 24 h, whatever the client config
/// says. Same trace and same `verify` result as the env var.
#[test]
fn the_ttl_seconds_file_in_the_home_stretches_new_approvals() {
    let (_temp, home) = init_home();
    fs::create_dir_all(home.root.join("approvals")).unwrap();
    fs::write(home.root.join("approvals").join("ttl-seconds"), "86400\n").unwrap();
    assert_eq!(approval_window(&home, &[]), (86400, 86400));
    let out = verify(&home);
    assert!(out.status.success(), "{}", stdout(&out));
}

/// (b) Limitación conocida, con rastro. `approval_ttl_seconds` in
/// `DIR/config.toml` is read from the home, whatever environment the client
/// passes, so a process that can write the home can stretch the window of
/// every new approval up to 24 h. Same trace and same `verify` result as
/// the env var and `approvals/ttl-seconds`.
#[test]
fn the_ttl_in_config_toml_stretches_new_approvals() {
    let (_temp, home) = init_home();
    fs::write(
        home.root.join("config.toml"),
        "approval_ttl_seconds = 86400\n",
    )
    .unwrap();
    assert_eq!(approval_window(&home, &[]), (86400, 86400));
    let out = verify(&home);
    assert!(out.status.success(), "{}", stdout(&out));
}

/// What `config.toml` can and cannot change (the module doc of
/// `src/config.rs`): the same calls get the same rule outcomes under the
/// same policy digest with and without a config, and only the approval
/// window differs.
#[test]
fn config_toml_changes_no_rule_outcome_only_the_approval_window() {
    let outcomes = |home: &Home| -> Vec<(String, String)> {
        let (out, stderr) = wrap(
            home,
            &[
                call(2, "echo", json!({"n": 1})),
                call(
                    3,
                    "append",
                    json!({"path": home.root.join("o.txt").to_str().unwrap(), "text": "o"}),
                ),
                call(4, "other", json!({})),
            ],
        );
        assert!(out.status.success(), "{stderr}");
        receipts(home)
            .iter()
            .map(|r| {
                (
                    r["evidence"]["decision"]["outcome"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                    r["evidence"]["policy_digest"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    };
    let (_plain_temp, plain) = init_home();
    let (_config_temp, configured) = init_home();
    fs::write(
        configured.root.join("config.toml"),
        "report = false\napproval_ttl_seconds = 86400\n",
    )
    .unwrap();
    let without = outcomes(&plain);
    let with = outcomes(&configured);
    let kinds: Vec<&str> = without
        .iter()
        .map(|(outcome, _)| outcome.as_str())
        .collect();
    assert_eq!(kinds, ["Allow", "RequireApproval", "Deny"]);
    assert_eq!(without, with, "same outcomes and policy digest");

    let window = |home: &Home| {
        let id = &approvals::list_pending(home).unwrap()[0].approval_id;
        let file = home
            .root
            .join("approvals")
            .join("pending")
            .join(format!("{id}.json"));
        window_of(&serde_json::from_str(&fs::read_to_string(file).unwrap()).unwrap())
    };
    assert_eq!((window(&plain), window(&configured)), (600, 86400));
}
