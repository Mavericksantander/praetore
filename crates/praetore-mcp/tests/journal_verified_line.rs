//! The journal writer reads a line back before it writes it.
//!
//! A receipt whose JSON does not read back as the receipt that was signed
//! (a float printed as text that parses to another float) used to be
//! appended anyway. The next append then failed on that line: enforce
//! refused every later call, in new sessions too, and observe ran every
//! later call with no receipt. Now such a line is never written and its
//! call is refused in both modes, so every home these tests leave behind
//! passes `verify`.

use praetore_core::{PolicyCondition, PolicyEffect, PolicyRule};
use praetore_mcp::store::{self, ACTION_TYPE, CAPABILITY, Home};
use proptest::prelude::*;
use serde_json::json;
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

/// A fresh home whose policy allows `echo` with any arguments; every other
/// tool is denied by default.
fn home_allowing_echo(root: &Path) -> Home {
    let init = run(&["init", "--dir", root.to_str().unwrap()], "");
    assert!(init.status.success(), "{init:?}");
    let home = Home::new(root.to_path_buf());
    let mut policy = store::default_policy();
    policy.rules.push(
        PolicyRule::new("allow-echo", ACTION_TYPE, PolicyEffect::Allow)
            .with_capability(CAPABILITY)
            .with_parameter_condition(PolicyCondition::exact("tool", json!("echo"))),
    );
    fs::write(home.policy(), serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
    home
}

/// One `tools/call` line with `literal` spliced in as text (`json!` would
/// re-serialize the number).
fn call(id: usize, tool: &str, literal: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{{"x":{literal}}}}}}}"#
    )
}

struct Session {
    stderr: String,
    /// `fake_server: EXECUTED <tool>` lines.
    executed: usize,
}

fn wrap(root: &Path, mode: &str, lines: &[String]) -> Session {
    let mut stdin = String::from(
        "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"0\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
    );
    for line in lines {
        stdin.push_str(line);
        stdin.push('\n');
    }
    let server = fake_server();
    let out = run(
        &[
            "wrap",
            "--dir",
            root.to_str().unwrap(),
            "--name",
            "fake",
            "--mode",
            mode,
            "--no-report",
            "--",
            server.to_str().unwrap(),
        ],
        &stdin,
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let executed = stderr
        .lines()
        .filter(|line| line.starts_with("fake_server: EXECUTED "))
        .count();
    Session { stderr, executed }
}

/// Receipt lines in the home's journal.
fn receipts(root: &Path) -> usize {
    let Ok(entries) = fs::read_dir(root.join("receipts")) else {
        return 0;
    };
    entries
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .map(|path| fs::read_to_string(path).unwrap().lines().count())
        .sum()
}

fn verify(root: &Path) -> Output {
    run(&["verify", "--dir", root.to_str().unwrap()], "")
}

fn assert_verifies(root: &Path, context: &str) {
    let out = verify(root);
    assert!(
        out.status.success(),
        "{context}: verify exited {:?}\n{}{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The literal of the report. Without `float_roundtrip`, `serde_json` reads
/// it as an f64 that prints as text which parses to another f64.
const POISON: &str = "99.9999999999999929";

/// Whether `literal` is one of those numbers in this build, read from the
/// refusal on stderr. With a correctly rounding parser none is.
fn was_refused_as_unverifiable(session: &Session) -> bool {
    session.stderr.contains("was not written")
}

#[test]
fn the_poison_literal_never_reaches_the_journal_in_enforce() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    home_allowing_echo(&root);
    let session = wrap(
        &root,
        "enforce",
        &[call(1, "echo", POISON), call(2, "echo", "1")],
    );
    // The control call always runs and is journaled.
    if was_refused_as_unverifiable(&session) {
        assert_eq!(session.executed, 1, "{}", session.stderr);
        assert_eq!(receipts(&root), 1, "{}", session.stderr);
        assert!(
            session.stderr.contains("call REFUSED (enforce)"),
            "{}",
            session.stderr
        );
    } else {
        assert_eq!(session.executed, 2, "{}", session.stderr);
        assert_eq!(receipts(&root), 2, "{}", session.stderr);
    }
    assert_verifies(&root, "after the poison literal");
    // A new session on the same home still records.
    let before = receipts(&root);
    let session = wrap(&root, "enforce", &[call(3, "echo", "2")]);
    assert_eq!(session.executed, 1, "{}", session.stderr);
    assert_eq!(receipts(&root), before + 1, "{}", session.stderr);
    assert_verifies(&root, "after a new session");
}

/// A denied call carries the literal: its receipt is the one that cannot be
/// written. It must not stop later calls either.
#[test]
fn the_poison_literal_in_a_denied_call_does_not_stop_later_calls() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    home_allowing_echo(&root);
    let session = wrap(
        &root,
        "enforce",
        &[call(1, "delete_file", POISON), call(2, "echo", "1")],
    );
    assert_eq!(session.executed, 1, "{}", session.stderr);
    assert!(
        session.stderr.contains("fake_server: EXECUTED echo"),
        "{}",
        session.stderr
    );
    assert_verifies(&root, "after a denied poison call");
}

#[test]
fn observe_never_runs_a_call_without_a_receipt_because_of_a_number() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    home_allowing_echo(&root);
    let session = wrap(
        &root,
        "observe",
        &[
            call(1, "echo", POISON),
            call(2, "delete_file", "1"),
            call(3, "echo", "2"),
        ],
    );
    // Observe forwards the denied delete_file and the control echo; each
    // has a receipt. The poison call runs only if its receipt was written.
    assert_eq!(session.executed, receipts(&root), "{}", session.stderr);
    assert!(session.executed >= 2, "{}", session.stderr);
    if was_refused_as_unverifiable(&session) {
        assert_eq!(session.executed, 2, "{}", session.stderr);
        assert!(
            session
                .stderr
                .contains("call REFUSED (observe: this call cannot have a receipt)"),
            "{}",
            session.stderr
        );
    }
    assert!(
        !session.stderr.contains("could NOT be written"),
        "{}",
        session.stderr
    );
    assert_verifies(&root, "after the poison literal in observe");
}

/// A JSON number: a finite f64 as Rust prints it, or a decimal literal with
/// more digits than an f64 holds, with or without an exponent.
fn number_literal() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<f64>()
            .prop_filter("finite", |value| value.is_finite())
            .prop_map(|value| format!("{value:?}")),
        (1.0f64..1024.0).prop_map(|value| format!("{value:?}")),
        "-?(0|[1-9][0-9]{0,3})\\.[0-9]{1,25}",
        "-?[1-9]\\.[0-9]{1,20}[eE][-+]?[0-9]{1,2}",
    ]
}

proptest! {
    // Each case spawns four processes; the fixed literal above is the
    // regression case, so no failure file is kept in the source tree.
    #![proptest_config(ProptestConfig {
        cases: 48,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Whatever numbers a client sends, in either mode: every call the
    /// server ran has a receipt, a last ordinary call still runs, and
    /// `verify` passes.
    #[test]
    fn appended_receipts_always_verify(
        literals in proptest::collection::vec(number_literal(), 1..6),
        observe in any::<bool>(),
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("home");
        home_allowing_echo(&root);
        let mode = if observe { "observe" } else { "enforce" };
        let mut lines: Vec<String> = literals
            .iter()
            .enumerate()
            .map(|(index, literal)| call(index + 1, "echo", literal))
            .collect();
        lines.push(call(literals.len() + 1, "echo", "7"));
        let session = wrap(&root, mode, &lines);
        // Observe forwards every call it records. Enforce also records the
        // calls it denies (a float the policy treats as unsafe, for one),
        // so there it can only have more receipts than executions.
        let recorded = receipts(&root);
        prop_assert!(
            if observe { session.executed == recorded } else { session.executed <= recorded },
            "{} {:?}: {} executed, {} receipts\n{}",
            mode,
            literals,
            session.executed,
            recorded,
            session.stderr
        );
        prop_assert!(session.executed >= 1, "{} {:?}: the last call did not run\n{}", mode, literals, session.stderr);
        prop_assert!(
            !session.stderr.contains("is unreadable") && !session.stderr.contains("could NOT be written"),
            "{} {:?}\n{}",
            mode,
            literals,
            session.stderr
        );
        let out = verify(&root);
        prop_assert!(
            out.status.success(),
            "{} {:?}: verify exited {:?}\n{}",
            mode,
            literals,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
