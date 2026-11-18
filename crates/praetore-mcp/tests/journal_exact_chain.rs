//! `verify` accepts a journal only when its lines are exactly the chain
//! that ends at the head, in chain order (`journal::Chain::rebuild`).
//!
//! Before, bare evidence lines placed before the first chained entry were
//! counted as "unchained earlier entries" and verified: a signed receipt
//! could be added to a journal without changing its head, so `verify
//! --expected-head` with a head saved elsewhere still passed.

use praetore_core::{PolicyCondition, PolicyEffect, PolicyRule};
use praetore_mcp::store::{self, ACTION_TYPE, CAPABILITY, Home};
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

/// One enforce session of `calls` allowed `echo` calls.
fn session(root: &Path, calls: usize) {
    let mut stdin = String::from(
        "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"0\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
    );
    for id in 1..=calls {
        stdin.push_str(&format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"echo\",\"arguments\":{{\"n\":{id}}}}}}}\n"
        ));
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
            "enforce",
            "--no-report",
            "--",
            server.to_str().unwrap(),
        ],
        &stdin,
    );
    assert!(out.status.success(), "{out:?}");
}

const N: usize = 4;

struct Journal {
    _temp: tempfile::TempDir,
    root: PathBuf,
    /// The daily file holding the N chained entries.
    file: PathBuf,
    lines: Vec<String>,
    /// The head `verify` printed for the clean journal.
    head: String,
    /// A receipt signed by the same keys that is not in the journal: a
    /// chained line (at seq N) and the same evidence as a bare line.
    extra_chained: String,
    extra_bare: String,
}

/// A home with N receipts, its head, and one more validly signed receipt
/// taken from a copy of the home.
fn journal() -> Journal {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let init = run(&["init", "--dir", root.to_str().unwrap()], "");
    assert!(init.status.success(), "{init:?}");
    let home = Home::new(root.clone());
    let mut policy = store::default_policy();
    policy.rules.push(
        PolicyRule::new("allow-echo", ACTION_TYPE, PolicyEffect::Allow)
            .with_capability(CAPABILITY)
            .with_parameter_condition(PolicyCondition::exact("tool", json!("echo"))),
    );
    fs::write(home.policy(), serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
    session(&root, N);
    let file = fs::read_dir(home.receipts_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .unwrap();
    let lines: Vec<String> = fs::read_to_string(&file)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(lines.len(), N);
    let (code, report) = verify(&root, None);
    assert_eq!(code, 3, "{report}");
    assert!(report.starts_with("UNANCHORED "), "{report}");
    let head = report
        .split(", head ")
        .nth(1)
        .and_then(|rest| rest.get(..64))
        .unwrap()
        .to_owned();
    let (code, report) = verify_anchored(&root, &head);
    assert_eq!(code, 0, "{report}");

    // The same keys sign one more receipt in a copy of the home.
    let copy = temp.path().join("copy");
    copy_dir(&root, &copy);
    session(&copy, 1);
    let copy_file = copy.join("receipts").join(file.file_name().unwrap());
    let extra_chained = fs::read_to_string(copy_file)
        .unwrap()
        .lines()
        .last()
        .unwrap()
        .to_owned();
    let value: Value = serde_json::from_str(&extra_chained).unwrap();
    assert_eq!(value["seq"], N as u64);
    let extra_bare = value["evidence"].to_string();
    Journal {
        _temp: temp,
        root,
        file,
        lines,
        head,
        extra_chained,
        extra_bare,
    }
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn write_lines(path: &Path, lines: &[&str]) {
    let mut text = lines.join("\n");
    text.push('\n');
    fs::write(path, text).unwrap();
}

/// Exit code and stdout of `verify`, with `--expected-head` when given.
fn verify(root: &Path, expected_head: Option<&str>) -> (i32, String) {
    verify_with(root, expected_head, None)
}

/// `verify` against both anchors: the receipts head and `none` for approvals.
fn verify_anchored(root: &Path, expected_head: &str) -> (i32, String) {
    verify_with(root, Some(expected_head), Some("none"))
}

fn verify_with(
    root: &Path,
    expected_head: Option<&str>,
    expected_approval_head: Option<&str>,
) -> (i32, String) {
    let mut args = vec!["verify", "--dir", root.to_str().unwrap()];
    if let Some(head) = expected_head {
        args.extend(["--expected-head", head]);
    }
    if let Some(head) = expected_approval_head {
        args.extend(["--expected-approval-head", head]);
    }
    let out = run(&args, "");
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// `verify` fails with and without the saved head, and names `cause` at
/// `at` (`<file name>:<line>`).
fn assert_fails(journal: &Journal, cause: &str, at: &str) {
    for expected in [Some(journal.head.as_str()), None] {
        let (code, report) = verify(&journal.root, expected);
        assert_eq!(code, 1, "expected head {expected:?}\n{report}");
        let named = report
            .lines()
            .any(|line| line.starts_with("FAIL ") && line.contains(at) && line.contains(cause));
        assert!(
            named,
            "expected head {expected:?}: no FAIL line with {at:?} and {cause:?}\n{report}"
        );
    }
}

#[test]
fn a_clean_journal_verifies_with_and_without_its_head() {
    let journal = journal();
    // Without anchors: not a pass.
    let (code, report) = verify(&journal.root, None);
    assert_eq!(code, 3, "{report}");
    assert!(
        report.contains(&format!("UNANCHORED {N} receipts: {N} verified, 0 failed")),
        "{report}"
    );
    assert!(report.contains("(0 unchained"), "{report}");
    // One anchor alone is not OK either.
    let (code, report) = verify(&journal.root, Some(&journal.head));
    assert_eq!(code, 3, "{report}");
    assert!(report.starts_with("UNANCHORED "), "{report}");
    // Both anchors: OK.
    let (code, report) = verify_anchored(&journal.root, &journal.head);
    assert_eq!(code, 0, "{report}");
    assert!(
        report.contains(&format!("OK {N} receipts: {N} verified, 0 failed")),
        "{report}"
    );
    assert!(report.contains("(0 unchained"), "{report}");
}

/// The reported case: a validly signed bare line before the chain, in the
/// daily file and in a file that sorts first.
#[test]
fn a_signed_line_before_the_chain_fails_verify() {
    let journal = journal();
    let name = journal.file.file_name().unwrap().to_str().unwrap();
    let mut lines: Vec<&str> = vec![&journal.extra_bare];
    lines.extend(journal.lines.iter().map(String::as_str));
    write_lines(&journal.file, &lines);
    assert_fails(&journal, "unchained line", &format!("{name}:1"));
    assert_fails(
        &journal,
        "is outside the chain that ends at head",
        &format!("{name}:1"),
    );

    let journal = self::journal();
    let earlier = journal.file.with_file_name("0000-00-00.jsonl");
    write_lines(&earlier, &[&journal.extra_bare, &journal.extra_bare]);
    assert_fails(&journal, "unchained line", "0000-00-00.jsonl:1");
    assert_fails(&journal, "unchained line", "0000-00-00.jsonl:2");
}

/// The same receipt as a chained line (it claims seq N and the head as its
/// `prev`), placed before the chain.
#[test]
fn a_chained_line_before_the_chain_fails_verify() {
    let journal = journal();
    let name = journal.file.file_name().unwrap().to_str().unwrap();
    let mut lines: Vec<&str> = vec![&journal.extra_chained];
    lines.extend(journal.lines.iter().map(String::as_str));
    write_lines(&journal.file, &lines);
    // With the saved head, and without it (the journal's own head is its
    // last line), the added line is outside the chain.
    assert_fails(
        &journal,
        &format!("seq {N} is outside the chain that ends at head"),
        &format!("{name}:1"),
    );
}

#[test]
fn a_line_after_the_head_fails_verify() {
    // A bare line after the chain: outside any chain.
    let journal = journal();
    let name = journal.file.file_name().unwrap().to_str().unwrap();
    let mut lines: Vec<&str> = journal.lines.iter().map(String::as_str).collect();
    lines.push(&journal.extra_bare);
    write_lines(&journal.file, &lines);
    assert_fails(&journal, "unchained line", &format!("{name}:{}", N + 1));

    // A chained line after the saved head: a real entry, but not covered by
    // that head. Without the head it is simply the journal's last entry.
    let journal = self::journal();
    let mut lines: Vec<&str> = journal.lines.iter().map(String::as_str).collect();
    lines.push(&journal.extra_chained);
    write_lines(&journal.file, &lines);
    let (code, report) = verify(&journal.root, Some(&journal.head));
    assert_eq!(code, 1, "{report}");
    assert!(
        report.contains(&format!(
            "{name}:{}: journal order: seq {N} is outside the chain",
            N + 1
        )),
        "{report}"
    );
    // Without the saved head it is simply the journal's last entry: a
    // clean longer chain, so without anchors that is UNANCHORED, and
    // with both anchors (the new head) it is OK.
    let (code, report) = verify(&journal.root, None);
    assert_eq!(code, 3, "{report}");
    assert!(report.starts_with("UNANCHORED "), "{report}");
    let new_head = report
        .split(", head ")
        .nth(1)
        .and_then(|rest| rest.get(..64))
        .unwrap();
    let (code, report) = verify_anchored(&journal.root, new_head);
    assert_eq!(code, 0, "{report}");
}

#[test]
fn a_reordered_journal_fails_verify() {
    let journal = journal();
    let name = journal.file.file_name().unwrap().to_str().unwrap();
    let mut lines: Vec<&str> = journal.lines.iter().map(String::as_str).collect();
    lines.swap(1, 2);
    write_lines(&journal.file, &lines);
    assert_fails(&journal, "entries were reordered", name);
}

/// Missing entries: one removed from the middle, and one copied twice.
#[test]
fn a_missing_or_duplicated_entry_fails_verify() {
    let journal = journal();
    let name = journal.file.file_name().unwrap().to_str().unwrap();
    let mut lines: Vec<&str> = journal.lines.iter().map(String::as_str).collect();
    lines.remove(1);
    write_lines(&journal.file, &lines);
    // The entry after the gap names it; the entry before is not reached.
    assert_fails(
        &journal,
        "is missing: an entry was removed",
        &format!("{name}:2"),
    );
    assert_fails(&journal, "is outside the chain", &format!("{name}:1"));

    let journal = self::journal();
    let mut lines: Vec<&str> = journal.lines.iter().map(String::as_str).collect();
    lines.insert(2, &journal.lines[1]);
    write_lines(&journal.file, &lines);
    assert_fails(&journal, "duplicate evidence_id", &format!("{name}:3"));
}

/// The chain link is not keyed, so a line's `seq` and `prev` can be
/// rewritten. Removing an entry and pointing its successor at the entry
/// before it leaves links that follow, but the `seq` numbers do not; and a
/// first entry must start from 64 zeros.
#[test]
fn a_gap_hidden_by_relinking_fails_verify() {
    let journal = journal();
    let name = journal.file.file_name().unwrap().to_str().unwrap();
    // Drop seq 2 and point seq 3 at the link that seq 1 produces.
    let second = praetore_mcp::journal::parse_line(&journal.lines[1]).unwrap();
    let link = second
        .position
        .unwrap()
        .after(&second.evidence)
        .unwrap()
        .prev;
    let last: Value = serde_json::from_str(&journal.lines[3]).unwrap();
    let relinked = format!(
        r#"{{"seq":3,"prev":"{link}","evidence":{}}}"#,
        last["evidence"]
    );
    write_lines(
        &journal.file,
        &[&journal.lines[0], &journal.lines[1], &relinked],
    );
    let (code, report) = verify(&journal.root, None);
    assert_eq!(code, 1, "{report}");
    assert!(
        report.contains(&format!(
            "{name}:2: journal order: seq 1 does not come right before seq 3"
        )),
        "{report}"
    );

    // A journal whose only entry is seq 0 with a `prev` that is not zeros.
    let journal = self::journal();
    let first: Value = serde_json::from_str(&journal.lines[0]).unwrap();
    let rooted = format!(
        r#"{{"seq":0,"prev":"{}","evidence":{}}}"#,
        "ab".repeat(32),
        first["evidence"]
    );
    write_lines(&journal.file, &[&rooted]);
    let (code, report) = verify(&journal.root, None);
    assert_eq!(code, 1, "{report}");
    assert!(report.contains("instead of 64 zeros"), "{report}");
}

/// What `verify` cannot see without a head kept elsewhere: entries removed
/// at the end leave a shorter journal that is exactly one chain. With the
/// saved head the same journal fails.
#[test]
fn entries_removed_at_the_end_need_the_saved_head() {
    let journal = journal();
    let lines: Vec<&str> = journal.lines[..N - 1].iter().map(String::as_str).collect();
    write_lines(&journal.file, &lines);
    // A shorter journal is still exactly one chain: without anchors that
    // is UNANCHORED, and with both anchors at its own new head it is OK.
    let (code, report) = verify(&journal.root, None);
    assert_eq!(code, 3, "{report}");
    assert!(report.starts_with("UNANCHORED "), "{report}");
    let new_head = report
        .split(", head ")
        .nth(1)
        .and_then(|rest| rest.get(..64))
        .unwrap()
        .to_owned();
    let (code, report) = verify_anchored(&journal.root, &new_head);
    assert_eq!(code, 0, "{report}");
    // The head saved earlier still finds the removed entries. Failed
    // beats Unanchored, even with only --expected-head.
    let (code, report) = verify(&journal.root, Some(&journal.head));
    assert_eq!(code, 1, "{report}");
    assert!(
        report.contains("does not match the expected head") && report.contains(&journal.head),
        "{report}"
    );
}
