//! What a `verify` result is worth (`receipts::Assurance`).
//!
//! The keys that sign receipts are files in the home. A process that reads
//! them can write another journal, consistent from the first entry to a
//! new head, and every check that reads only the home passes on it. So
//! `verify` exits 0 only when both journals end at states the caller kept
//! elsewhere; without them a clean result is UNANCHORED, exit 3.

use praetore_core::{PolicyCondition, PolicyEffect, PolicyRule};
use praetore_mcp::store::{self, ACTION_TYPE, CAPABILITY, Home};
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

/// One enforce session calling the allowed `echo` once per value.
fn session(root: &Path, values: &[u32]) {
    let mut stdin = String::from(
        "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"0\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
    );
    for (id, value) in values.iter().enumerate() {
        stdin.push_str(&format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"tools/call\",\"params\":{{\"name\":\"echo\",\"arguments\":{{\"n\":{value}}}}}}}\n",
            id + 1
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

fn init(root: &Path) -> Output {
    let out = run(&["init", "--dir", root.to_str().unwrap()], "");
    assert!(out.status.success(), "{out:?}");
    let home = Home::new(root.to_path_buf());
    let mut policy = store::default_policy();
    policy.rules.push(
        PolicyRule::new("allow-echo", ACTION_TYPE, PolicyEffect::Allow)
            .with_capability(CAPABILITY)
            .with_parameter_condition(PolicyCondition::exact("tool", json!("echo"))),
    );
    fs::write(home.policy(), serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
    out
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

/// Exit code and stdout of `verify` with `extra` arguments.
fn verify(root: &Path, extra: &[&str]) -> (i32, String) {
    let mut args = vec!["verify", "--dir", root.to_str().unwrap()];
    args.extend_from_slice(extra);
    let out = run(&args, "");
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn head_of(report: &str) -> String {
    report
        .split(", head ")
        .nth(1)
        .and_then(|rest| rest.get(..64))
        .expect("verify prints the journal head")
        .to_owned()
}

struct Homes {
    _temp: tempfile::TempDir,
    /// The home as its owner left it: three receipts.
    legitimate: PathBuf,
    /// The head of `legitimate`, as kept off the machine.
    saved_head: String,
    /// The same home after someone with its keys wrote another journal:
    /// every receipt is signed by the home's keys and the chain is
    /// consistent from seq 0 to a different head.
    rewritten: PathBuf,
}

/// `rewritten` is made the way an attacker holding the keys would make it:
/// a copy of the home taken before any receipt (same keys, same policy)
/// runs its own sessions, and its journal replaces the original one.
fn homes() -> Homes {
    let temp = tempfile::tempdir().unwrap();
    let legitimate = temp.path().join("legitimate");
    init(&legitimate);
    let keys_copy = temp.path().join("keys-copy");
    copy_dir(&legitimate, &keys_copy);

    session(&legitimate, &[1, 2, 3]);
    let (_, report) = verify(&legitimate, &[]);
    let saved_head = head_of(&report);

    // Another history, signed with the copied keys: the call with 2 never
    // happened and a call with 9 did.
    session(&keys_copy, &[1, 9]);
    let rewritten = temp.path().join("rewritten");
    copy_dir(&legitimate, &rewritten);
    fs::remove_dir_all(rewritten.join("receipts")).unwrap();
    copy_dir(&keys_copy.join("receipts"), &rewritten.join("receipts"));
    Homes {
        _temp: temp,
        legitimate,
        saved_head,
        rewritten,
    }
}

const WARNING: &str = "WARNING: NOT ANCHORED (exit 3).";
const CANNOT_DETECT: &str = "cannot detect a journal rewritten with those keys";

#[test]
fn a_legitimate_journal_with_its_anchors_is_ok_exit_0() {
    let homes = homes();
    let (code, report) = verify(
        &homes.legitimate,
        &[
            "--expected-head",
            &homes.saved_head,
            "--expected-approval-head",
            "none",
        ],
    );
    assert_eq!(code, 0, "{report}");
    assert!(
        report.starts_with("OK 3 receipts: 3 verified, 0 failed"),
        "{report}"
    );
    assert!(
        report.contains("\nanchored: both journals end exactly"),
        "{report}"
    );
    assert!(!report.contains("NOT ANCHORED"), "{report}");
}

#[test]
fn a_journal_rewritten_with_the_keys_fails_against_the_saved_anchor() {
    let homes = homes();
    let (code, report) = verify(
        &homes.rewritten,
        &[
            "--expected-head",
            &homes.saved_head,
            "--expected-approval-head",
            "none",
        ],
    );
    assert_eq!(code, 1, "{report}");
    // Every receipt is validly signed; only the head tells, on its own
    // FAIL line: no receipt failed.
    assert!(
        report.contains("FAIL 2 receipts: 2 verified, 0 failed"),
        "{report}"
    );
    assert!(
        report.contains(&format!(
            "does not match the expected head {}: entries were removed or added",
            homes.saved_head
        )),
        "{report}"
    );
    assert!(!report.contains("\nanchored:"), "{report}");
}

/// The rewritten journal passes every check that reads only the home, as
/// the legitimate one does. Neither is reported as OK.
#[test]
fn without_an_anchor_no_journal_is_ok() {
    let homes = homes();
    for (home, receipts) in [(&homes.rewritten, 2), (&homes.legitimate, 3)] {
        let (code, report) = verify(home, &[]);
        assert_eq!(code, 3, "{report}");
        assert!(
            report.starts_with(&format!(
                "UNANCHORED {receipts} receipts: {receipts} verified, 0 failed"
            )),
            "{report}"
        );
        assert!(
            !report.lines().any(|line| line.starts_with("OK ")),
            "{report}"
        );
        assert!(report.contains(WARNING), "{report}");
        assert!(report.contains(CANNOT_DETECT), "{report}");
        assert!(
            report.contains("--expected-head and --expected-approval-head not given"),
            "{report}"
        );
        assert!(report.contains("This result is not a pass."), "{report}");
    }
}

/// One anchor is not enough: the other journal can still be rewritten or
/// removed. The warning names the option that is missing.
#[test]
fn one_anchor_alone_is_not_ok() {
    let homes = homes();
    let (code, report) = verify(&homes.legitimate, &["--expected-head", &homes.saved_head]);
    assert_eq!(code, 3, "{report}");
    assert!(report.starts_with("UNANCHORED 3 receipts"), "{report}");
    assert!(
        report.contains("--expected-approval-head not given"),
        "{report}"
    );
    let (code, report) = verify(&homes.legitimate, &["--expected-approval-head", "none"]);
    assert_eq!(code, 3, "{report}");
    assert!(report.contains("--expected-head not given"), "{report}");

    // A failed check is exit 1 whatever was given.
    let (code, report) = verify(&homes.rewritten, &["--expected-head", &homes.saved_head]);
    assert_eq!(code, 1, "{report}");
    assert!(report.starts_with("FAIL "), "{report}");
}

/// `none` anchors a journal that does not exist yet: a new home passes with
/// it, and the first receipt written afterwards fails it.
#[test]
fn none_anchors_an_empty_journal() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    init(&root);
    let none = [
        "--expected-head",
        "none",
        "--expected-approval-head",
        "none",
    ];
    let (code, report) = verify(&root, &none);
    assert_eq!(code, 0, "{report}");
    assert!(report.starts_with("OK 0 receipts"), "{report}");

    session(&root, &[1]);
    let (code, report) = verify(&root, &none);
    assert_eq!(code, 1, "{report}");
    assert!(
        report.contains("--expected-head none says it was empty: entries were added"),
        "{report}"
    );
    let (code, report) = verify(&root, &["--expected-head", "zzz"]);
    assert_eq!(
        code, 2,
        "a head that is neither hex nor none is a usage error: {report}"
    );
}

/// `init` tells where the anchors come from and what verify is without them.
#[test]
fn init_says_to_keep_the_heads_outside_the_machine() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let out = init(&root);
    let text = String::from_utf8_lossy(&out.stdout);
    for expected in [
        "`verify` passes (exit 0) only against two heads kept outside this",
        "--expected-head HEX --expected-approval-head HEX",
        "Without them verify exits 3 (not anchored)",
    ] {
        assert!(text.contains(expected), "{expected:?} not in\n{text}");
    }
}
