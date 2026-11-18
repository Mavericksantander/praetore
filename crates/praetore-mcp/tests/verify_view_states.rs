//! Fixtures for the signature and journal states `verify_view` shows.
//!
//! `verify_view` is private. These tests read it through `dashboard::state`,
//! which is the object the page gets. They do not move or rewrite that
//! function. Each test builds one home, applies one mutation, and checks
//! the state the code already distinguishes.

use praetore_core::AgentKeyPair;
use praetore_mcp::{
    dashboard,
    receipts::{self},
    store::Home,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
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
        "{} missing: run via cargo test",
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

fn home_with_receipts(count: usize) -> (tempfile::TempDir, Home) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let dir = root.to_str().unwrap();
    assert!(run(&["init", "--dir", dir], "").status.success());
    let out = run(
        &[
            "policy",
            "allow",
            "--id",
            "allow-echo",
            "--tool",
            "echo",
            "--dir",
            dir,
        ],
        "",
    );
    assert!(out.status.success(), "{out:?}");
    let mut lines = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ];
    for index in 0..count {
        lines.push(json!({"jsonrpc":"2.0","id":10 + index,"method":"tools/call","params":{"name":"echo","arguments":{"n": index}}}));
    }
    let input: String = lines.iter().map(|line| format!("{line}\n")).collect();
    let server = fake_server();
    let out = run(
        &[
            "wrap",
            "--dir",
            dir,
            "--name",
            "fake",
            "--mode",
            "enforce",
            "--no-report",
            "--",
            server.to_str().unwrap(),
        ],
        &input,
    );
    assert!(out.status.success(), "{out:?}");
    let home = Home::new(root);
    assert_eq!(receipts::read_journal(&home).unwrap().len(), count);
    (temp, home)
}

fn journal_file(home: &Home) -> PathBuf {
    receipts::read_journal(home).unwrap()[0].file.clone()
}

fn state(home: &Home) -> Value {
    dashboard::state(home, None)
}

fn verify(home: &Home) -> Value {
    state(home)["verify"].clone()
}

fn keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

fn assert_check(check: &Value, status: &str, error: Option<&str>) {
    assert_eq!(check["status"], status, "{check}");
    match error {
        None => assert!(check["error"].is_null(), "{check}"),
        Some(expected) => assert_eq!(check["error"], expected, "{check}"),
    }
}

const VERIFY_KEYS: &[&str] = &[
    "approval",
    "assurance",
    "attester_pin",
    "chained",
    "expected_head",
    "failed",
    "failures",
    "head",
    "issuer_pins",
    "status",
    "total",
    "unchained",
    "verified",
];

const RECEIPT_KEYS: &[&str] = &[
    "approval",
    "arguments",
    "checks",
    "decided_at",
    "decided_by",
    "decision",
    "evidence_id",
    "location",
    "mode",
    "order",
    "parse_error",
    "path_check",
    "policy_digest",
    "prev",
    "raw",
    "reason",
    "rule",
    "seq",
    "server",
    "signatures",
    "tool",
    "verified",
];

#[test]
fn a_valid_receipt_is_ok_and_exposes_the_view_fields() {
    let (_temp, home) = home_with_receipts(1);
    let state = state(&home);
    let view = &state["verify"];
    assert_eq!(keys(view), keys(&json_keys(VERIFY_KEYS)));
    assert_eq!(view["status"], "ok");
    // No heads were given, so verify would exit 3. The dashboard view still
    // reports status ok; assurance is the field that names that gap.
    assert_eq!(view["assurance"], "unanchored");
    assert_eq!(view["total"], 1);
    assert_eq!(view["verified"], 1);
    assert_eq!(view["failed"], 0);
    assert_eq!(view["failures"], json!([]));
    assert_eq!(view["chained"], 1);
    assert_eq!(view["unchained"], 0);
    assert!(view["expected_head"].is_null());
    assert_eq!(keys(&view["head"]), keys(&json_keys(&["next_seq", "prev"])));
    assert_eq!(view["head"]["next_seq"], 1);
    assert_eq!(view["head"]["prev"].as_str().unwrap().len(), 64);
    assert_eq!(
        keys(&view["approval"]),
        keys(&json_keys(&[
            "decisions",
            "executions",
            "expected_head",
            "head"
        ]))
    );
    assert_eq!(view["approval"]["decisions"], 0);
    assert_eq!(view["approval"]["executions"], 0);
    assert!(view["approval"]["head"].is_null());
    assert!(view["approval"]["expected_head"].is_null());

    let row = &state["receipts"][0];
    assert_eq!(keys(row), keys(&json_keys(RECEIPT_KEYS)));
    assert!(row["parse_error"].is_null());
    assert_eq!(row["verified"], true);
    assert!(row["order"].is_null());
    for name in ["agent", "attester", "authority"] {
        assert_check(&row["signatures"][name]["check"], "ok", None);
    }
    for name in ["shape", "authority_subject", "audience", "mode"] {
        assert_check(&row["checks"][name], "ok", None);
    }
    assert_eq!(
        keys(&row["signatures"]["agent"]),
        keys(&json_keys(&["agent_id", "check", "subject_key_hash"]))
    );
    assert_eq!(
        keys(&row["signatures"]["attester"]),
        keys(&json_keys(&["check", "key_id"]))
    );
    assert_eq!(
        keys(&row["signatures"]["authority"]),
        keys(&json_keys(&["authority_id", "check", "issuer", "key_id"]))
    );
    assert_eq!(
        keys(&row["signatures"]["agent"]["check"]),
        keys(&json_keys(&["error", "status"]))
    );
}

fn json_keys(names: &[&str]) -> Value {
    let mut object = serde_json::Map::new();
    for name in names {
        object.insert((*name).to_owned(), Value::Null);
    }
    Value::Object(object)
}

fn rewrite_first_line(home: &Home, edit: impl FnOnce(&mut Value)) {
    let file = journal_file(home);
    let text = fs::read_to_string(&file).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let mut value: Value = serde_json::from_str(&lines[0]).unwrap();
    edit(&mut value);
    lines[0] = serde_json::to_string(&value).unwrap();
    fs::write(&file, lines.join("\n") + "\n").unwrap();
}

#[test]
fn a_flipped_attester_signature_fails_only_that_check() {
    let (_temp, home) = home_with_receipts(1);
    rewrite_first_line(&home, |value| {
        let signature = value["evidence"]["attester_signature"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut bytes = signature.into_bytes();
        bytes[0] = if bytes[0] == b'a' { b'b' } else { b'a' };
        value["evidence"]["attester_signature"] = Value::String(String::from_utf8(bytes).unwrap());
    });
    let state = state(&home);
    assert_eq!(state["verify"]["status"], "fail");
    let row = &state["receipts"][0];
    assert_eq!(row["verified"], false);
    assert!(row["parse_error"].is_null(), "{row}");
    assert_check(
        &row["signatures"]["attester"]["check"],
        "fail",
        Some("attester signature: AUTH_FAIL"),
    );
    assert_check(&row["signatures"]["agent"]["check"], "ok", None);
    assert_check(&row["signatures"]["authority"]["check"], "ok", None);
}

/// The code uses the same `AUTH_FAIL` when the pinned attester key is a
/// different key. It does not have a separate unknown-key state for the
/// attester.
#[test]
fn a_different_attester_pin_is_the_same_auth_fail() {
    let (_temp, home) = home_with_receipts(1);
    fs::copy(home.approver_pin(), home.attester_pin()).unwrap();
    let row = &state(&home)["receipts"][0];
    assert_check(
        &row["signatures"]["attester"]["check"],
        "fail",
        Some("attester signature: AUTH_FAIL"),
    );
    assert_check(&row["signatures"]["agent"]["check"], "ok", None);
    assert_eq!(state(&home)["verify"]["status"], "fail");
}

#[test]
fn an_unpinned_authority_issuer_is_not_a_bad_signature() {
    let (_temp, home) = home_with_receipts(1);
    let pin = praetore_core::engine::TrustedAuthorityIssuer::new(
        "other-issuer",
        AgentKeyPair::from_secret_bytes(&[9; 32]).public_key(),
    )
    .unwrap()
    .export_pin_json()
    .unwrap();
    fs::write(home.issuer_pins(), format!("{pin}\n")).unwrap();
    let state = state(&home);
    assert_eq!(state["verify"]["status"], "fail");
    let row = &state["receipts"][0];
    assert_check(&row["signatures"]["attester"]["check"], "ok", None);
    assert_check(&row["signatures"]["agent"]["check"], "ok", None);
    assert_check(
        &row["signatures"]["authority"]["check"],
        "fail",
        Some("authority issuer is not pinned"),
    );
}

#[test]
fn an_issuer_pin_outside_its_validity_fails_the_authority_check() {
    let (_temp, home) = home_with_receipts(1);
    let path = home.issuer_pins();
    let text = fs::read_to_string(&path).unwrap();
    let mut pin: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    pin["validity"]["not_before"] = json!("2099-01-01T00:00:00Z");
    pin["validity"]["not_after"] = json!("2099-12-31T00:00:00Z");
    fs::write(&path, format!("{pin}\n")).unwrap();
    let row = &state(&home)["receipts"][0];
    assert_check(
        &row["signatures"]["authority"]["check"],
        "fail",
        Some("authority: TRUST_STORE_FAIL"),
    );
    assert_check(&row["signatures"]["attester"]["check"], "ok", None);
    assert_eq!(state(&home)["verify"]["status"], "fail");
}

#[test]
fn a_line_that_is_not_json_is_a_parse_error() {
    let (_temp, home) = home_with_receipts(1);
    let file = journal_file(&home);
    let mut text = fs::read_to_string(&file).unwrap();
    text.push_str("{not json\n");
    fs::write(&file, text).unwrap();
    let state = state(&home);
    assert_eq!(state["verify"]["status"], "fail");
    let row = state["receipts"].as_array().unwrap().last().unwrap();
    assert_eq!(
        keys(row),
        keys(&json_keys(&[
            "location",
            "parse_error",
            "raw",
            "raw_text",
            "verified"
        ]))
    );
    assert_eq!(row["verified"], false);
    assert!(row["parse_error"].as_str().unwrap().contains("not JSON"));
    assert!(row["raw"].is_null());
    assert!(row.get("signatures").is_none());
}

#[test]
fn a_prev_that_is_not_hex_is_a_parse_error() {
    let (_temp, home) = home_with_receipts(1);
    rewrite_first_line(&home, |value| {
        value["prev"] = Value::String("Z".repeat(64));
    });
    let state = state(&home);
    assert_eq!(state["verify"]["status"], "fail");
    let row = &state["receipts"][0];
    assert!(
        row["parse_error"]
            .as_str()
            .unwrap()
            .contains("prev is not 64 lowercase hex"),
        "{row}"
    );
    assert!(row.get("signatures").is_none());
}

#[test]
fn a_tampered_body_fails_integrity_before_the_signature_checks() {
    let (_temp, home) = home_with_receipts(1);
    let file = journal_file(&home);
    let text = fs::read_to_string(&file).unwrap();
    let edited = text.replace(
        r#""praetore.mode":"enforce""#,
        r#""praetore.mode":"observe""#,
    );
    assert_ne!(edited, text);
    fs::write(&file, edited).unwrap();
    let row = &state(&home)["receipts"][0];
    let error = row["parse_error"].as_str().unwrap();
    assert!(error.contains("EVIDENCE_FAIL"), "{error}");
    assert!(error.contains("integrity"), "{error}");
    assert!(row.get("signatures").is_none());
    assert_eq!(state(&home)["verify"]["status"], "fail");
}

#[test]
fn removing_a_middle_receipt_breaks_the_chain_and_keeps_the_signatures() {
    let (_temp, home) = home_with_receipts(3);
    let file = journal_file(&home);
    let text = fs::read_to_string(&file).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3);
    lines.remove(1);
    fs::write(&file, lines.join("\n") + "\n").unwrap();
    let state = state(&home);
    assert_eq!(state["verify"]["status"], "fail");
    let row = &state["receipts"][1];
    assert!(row["order"].as_str().unwrap().contains("seq"), "{row}");
    assert_eq!(row["verified"], false);
    for name in ["agent", "attester", "authority"] {
        assert_check(&row["signatures"][name]["check"], "ok", None);
    }
}

#[test]
fn a_duplicated_receipt_is_an_order_failure() {
    let (_temp, home) = home_with_receipts(1);
    let file = journal_file(&home);
    let text = fs::read_to_string(&file).unwrap();
    let first = text.lines().next().unwrap();
    fs::write(&file, format!("{text}{first}\n")).unwrap();
    let state = state(&home);
    assert_eq!(state["verify"]["status"], "fail");
    assert_eq!(state["verify"]["total"], 2);
    let row = &state["receipts"][1];
    assert!(
        row["order"]
            .as_str()
            .unwrap()
            .contains("duplicate evidence_id"),
        "{row}"
    );
    assert_check(&row["signatures"]["attester"]["check"], "ok", None);
}

#[test]
fn a_wrong_expected_head_fails_the_view_without_unverifying_the_line() {
    let (_temp, home) = home_with_receipts(1);
    let wrong = "ab".repeat(32);
    let state = dashboard::state(&home, Some(&wrong));
    let view = &state["verify"];
    assert_eq!(view["status"], "fail");
    assert_eq!(view["expected_head"], wrong);
    assert_eq!(view["total"], 1);
    assert_eq!(view["verified"], 1);
    assert_eq!(view["failed"], 1);
    let failure = view["failures"][0].as_str().unwrap();
    assert!(
        failure.contains("does not match the expected head"),
        "{failure}"
    );
    assert_eq!(state["receipts"][0]["verified"], true);
}

#[test]
fn an_unreadable_attester_pin_is_an_error_and_checks_are_not_run() {
    let (_temp, home) = home_with_receipts(1);
    fs::write(home.attester_pin(), "zz\n").unwrap();
    let state = state(&home);
    let view = &state["verify"];
    assert_eq!(keys(view), keys(&json_keys(&["error", "status"])));
    assert_eq!(view["status"], "error");
    assert!(view["error"].as_str().unwrap().contains("hex"), "{view}");
    let row = &state["receipts"][0];
    assert_eq!(row["verified"], false);
    assert_check(&row["signatures"]["attester"]["check"], "not_run", None);
    assert_check(&row["signatures"]["agent"]["check"], "not_run", None);
    assert_check(&row["signatures"]["authority"]["check"], "not_run", None);
}

#[test]
fn an_unreadable_approval_journal_is_an_error_and_checks_are_not_run() {
    let (_temp, home) = home_with_receipts(1);
    let path = home.root.join("approvals").join("journal.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "not-json\n").unwrap();
    let state = state(&home);
    let view = &state["verify"];
    assert_eq!(view["status"], "error");
    assert!(
        view["error"].as_str().unwrap().contains("not JSON"),
        "{view}"
    );
    assert_check(
        &state["receipts"][0]["signatures"]["attester"]["check"],
        "not_run",
        None,
    );
}

fn approval_line(seq: u64, prev: &str, record: &str) -> String {
    let canonical = praetore_core::canonical::canonicalize_json(record).unwrap();
    let record = std::str::from_utf8(&canonical).unwrap();
    format!("{{\"seq\":{seq},\"prev\":\"{prev}\",\"record\":{record}}}\n")
}

#[test]
fn an_unknown_approval_kind_fails_verify_and_leaves_the_receipt_valid() {
    let (_temp, home) = home_with_receipts(1);
    let path = home.root.join("approvals").join("journal.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        approval_line(0, &"0".repeat(64), r#"{"kind":"note"}"#),
    )
    .unwrap();
    let state = state(&home);
    let view = &state["verify"];
    assert_eq!(view["status"], "fail");
    assert_eq!(view["verified"], 1);
    assert_eq!(state["receipts"][0]["verified"], true);
    let failure = view["failures"][0].as_str().unwrap();
    assert!(
        failure.contains("unknown approval record kind note"),
        "{failure}"
    );
}

#[test]
fn an_approval_chain_that_does_not_follow_is_a_failure() {
    let (_temp, home) = home_with_receipts(1);
    let path = home.root.join("approvals").join("journal.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let zeros = "0".repeat(64);
    let text = format!(
        "{}{}",
        approval_line(0, &zeros, r#"{"kind":"note"}"#),
        approval_line(1, &zeros, r#"{"kind":"note"}"#)
    );
    fs::write(&path, text).unwrap();
    let view = verify(&home);
    assert_eq!(view["status"], "fail");
    let joined = view["failures"].to_string();
    assert!(
        joined.contains("does not follow the previous record"),
        "{joined}"
    );
}
