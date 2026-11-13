//! CLI tests for `praetore-verify outcomes` (P-002 D3.1), over files from a
//! real compliance package (`fixtures/outcomes`, see its README).

use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/outcomes")
}

/// A scratch copy of the fixture, to alter files in.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "praetore-verify-outcomes-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).unwrap();
        for entry in fs::read_dir(fixture()).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), path.join(entry.file_name())).unwrap();
        }
        Self(path)
    }

    fn write(&self, name: &str, text: &str) {
        fs::write(self.0.join(name), text).unwrap();
    }

    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.0.join(name)).unwrap()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const FULL: [&str; 13] = [
    "outcomes",
    "--outcomes",
    "approvals.jsonl",
    "--journal",
    "journal.jsonl",
    "--attester-pin",
    "attester-pin-1.hex",
    "--execution-pin",
    "execution-pin-1.json",
    "--approver-pin",
    "approver-pin-1.json",
    "--format",
    "json",
];

fn verify(dir: &Path, args: &[&str]) -> (bool, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "not JSON: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(output.status.success(), summary["ok"] == true, "{summary}");
    (output.status.success(), summary)
}

fn outcome_list(summary: &Value) -> Vec<String> {
    summary["details"]["held"]
        .as_array()
        .unwrap()
        .iter()
        .map(|held| held["outcome"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_real_package_reports_how_each_held_request_ended() {
    let (ok, summary) = verify(&fixture(), &FULL);
    assert!(ok, "{summary}");
    let details = &summary["details"];
    // Journal order: approved and executed, rejected, approved and not
    // executed, pending.
    assert_eq!(
        outcome_list(&summary),
        [
            "approved_executed",
            "rejected",
            "approved_pending_dispatch",
            "pending"
        ]
    );
    assert_eq!(
        details["held"][1]["not_dispatched_reason"],
        "approval_rejected"
    );
    assert_eq!(details["held"][0]["execution"], "confirmed");
    assert_eq!(details["counts"]["approvals"], 2);
    assert_eq!(details["counts"]["rejections"], 1);
    assert_eq!(details["counts"]["expirations"], 0);
    assert_eq!(details["counts"]["execution_receipts"], 6);
    assert_eq!(
        details["counts"]["execution_receipts_by_state"],
        serde_json::json!({"awaiting_approval": 4, "confirmed": 1, "not_dispatched": 1})
    );
    assert_eq!(details["journal_entries"], 4);
    assert!(details["tenant_id"].is_string());
    assert_eq!(details["unused_execution_pins"], serde_json::json!([]));
    assert_eq!(details["current_authorization"], false);
    // Each held row names a request of the journal, by evidence_id.
    let journal = fs::read_to_string(fixture().join("journal.jsonl")).unwrap();
    for held in details["held"].as_array().unwrap() {
        let evidence_id = held["evidence_id"].as_str().unwrap();
        assert!(journal.contains(&format!("\"evidence_id\":\"{evidence_id}\"")));
    }
    // Not anchored without --expected-head; with it, no warning.
    assert!(
        details["warnings"][0]
            .as_str()
            .unwrap()
            .starts_with("head_not_anchored")
    );
    let head = verify(
        &fixture(),
        &[
            "journal",
            "--journal",
            "journal.jsonl",
            "--attester-pin",
            "attester-pin-1.hex",
            "--format",
            "json",
        ],
    )
    .1["details"]["head"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut anchored = FULL.to_vec();
    anchored.extend(["--expected-head", &head]);
    let (ok, summary) = verify(&fixture(), &anchored);
    assert!(ok, "{summary}");
    assert_eq!(summary["details"]["expected_head_verified"], true);
    assert_eq!(summary["details"]["warnings"], serde_json::json!([]));
    let mut wrong = FULL.to_vec();
    let other = "ab".repeat(32);
    wrong.extend(["--expected-head", &other]);
    assert!(!verify(&fixture(), &wrong).0);
}

#[test]
fn a_changed_or_missing_record_or_key_fails_the_whole_file() {
    let dir = Dir::new();
    let approvals = dir.read("approvals.jsonl");
    let code = |args: &[&str]| verify(&dir.0, args).1["code"].as_str().unwrap().to_owned();
    fn with(file: &'static str) -> Vec<&'static str> {
        let mut args = FULL.to_vec();
        args[2] = file;
        args
    }

    // A decision flipped after signing.
    dir.write(
        "flipped.jsonl",
        &approvals.replacen("\"outcome\":\"reject\"", "\"outcome\":\"approve\"", 1),
    );
    assert_eq!(code(&with("flipped.jsonl")), "OUTCOME_SIGNATURE_INVALID");
    // The adapter output changed after signing.
    let output = "\"output\":{\"key\":\"aprobar\",\"value\":\"v\"}";
    assert!(approvals.contains(output));
    dir.write(
        "output.jsonl",
        &approvals.replacen(
            output,
            "\"output\":{\"key\":\"aprobar\",\"value\":\"w\"}",
            1,
        ),
    );
    assert_eq!(code(&with("output.jsonl")), "OUTCOME_SIGNATURE_INVALID");
    // The evidence inside an execution receipt is not the journal's.
    dir.write(
        "evidence.jsonl",
        &approvals.replacen("\"value\":\"v\"", "\"value\":\"w\"", 1),
    );
    assert_eq!(code(&with("evidence.jsonl")), "OUTCOME_EVIDENCE_MISMATCH");
    // An execution without the approval it needs.
    let without_approval: String = approvals
        .lines()
        .enumerate()
        .filter(|(index, _)| *index != 1)
        .map(|(_, line)| format!("{line}\n"))
        .collect();
    dir.write("unapproved.jsonl", &without_approval);
    assert_eq!(code(&with("unapproved.jsonl")), "OUTCOME_INCONSISTENT");
    // A decision twice.
    let first = approvals.lines().nth(1).unwrap();
    dir.write("twice.jsonl", &format!("{approvals}{first}\n"));
    assert_eq!(code(&with("twice.jsonl")), "OUTCOME_DUPLICATE");
    // Not one record per line.
    dir.write(
        "bad.jsonl",
        &approvals.replacen("\"schema_version\":1", "\"schema_version\":9", 1),
    );
    assert_eq!(code(&with("bad.jsonl")), "OUTCOME_MALFORMED");
    dir.write("cut.jsonl", approvals.trim_end());
    assert_eq!(code(&with("cut.jsonl")), "OUTCOME_MALFORMED");

    // The journal cut before the last request: its records have no request.
    let journal = dir.read("journal.jsonl");
    let lines: Vec<&str> = journal.lines().collect();
    dir.write(
        "short.jsonl",
        &lines[..lines.len() - 1]
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>(),
    );
    let mut short = FULL.to_vec();
    short[4] = "short.jsonl";
    assert_eq!(code(&short), "OUTCOME_UNKNOWN_REQUEST");

    // No approver pin, or another key under its key id.
    assert_eq!(
        code(&[&FULL[..9], &FULL[11..]].concat()),
        "OUTCOME_KEY_UNKNOWN"
    );
    let approver: Value = serde_json::from_str(&dir.read("approver-pin-1.json")).unwrap();
    let execution: Value = serde_json::from_str(&dir.read("execution-pin-1.json")).unwrap();
    dir.write(
        "other-approver.json",
        &serde_json::json!({
            "schema_version": 1,
            "key_id": approver["key_id"],
            "public_key_hex": execution["public_key_hex"],
        })
        .to_string(),
    );
    let mut other = FULL.to_vec();
    other[10] = "other-approver.json";
    assert_eq!(code(&other), "OUTCOME_SIGNATURE_INVALID");
    // A pin that is not a JSON pin.
    let mut bare = FULL.to_vec();
    bare[10] = "attester-pin-1.hex";
    assert_eq!(code(&bare), "TRUST_STORE_FAIL");
}

#[test]
fn an_empty_file_leaves_every_held_request_pending_and_reports_unused_pins() {
    let dir = Dir::new();
    dir.write("empty.jsonl", "");
    let mut args = FULL.to_vec();
    args[2] = "empty.jsonl";
    let (ok, summary) = verify(&dir.0, &args);
    assert!(ok, "{summary}");
    assert_eq!(outcome_list(&summary), ["pending"; 4]);
    assert_eq!(
        summary["details"]["unused_execution_pins"],
        serde_json::json!([1])
    );
    assert_eq!(
        summary["details"]["unused_approver_pins"],
        serde_json::json!([1])
    );
}

#[test]
fn outcomes_usage_errors() {
    for args in [
        // No --journal, no attester pin, an unknown flag, a flag of another
        // command, a repeated --outcomes.
        vec![
            "outcomes",
            "--outcomes",
            "approvals.jsonl",
            "--attester-pin",
            "attester-pin-1.hex",
        ],
        vec![
            "outcomes",
            "--outcomes",
            "approvals.jsonl",
            "--journal",
            "journal.jsonl",
        ],
        [&FULL[..11], &["--policy", "policy.json"]].concat(),
        [&FULL[..11], &["--require-anchored"]].concat(),
        [&FULL[..11], &["--outcomes", "approvals.jsonl"]].concat(),
        // --execution-pin belongs to outcomes and receipt only.
        vec![
            "journal",
            "--journal",
            "journal.jsonl",
            "--attester-pin",
            "attester-pin-1.hex",
            "--approver-pin",
            "approver-pin-1.json",
        ],
    ] {
        let mut args = args.clone();
        args.extend(["--format", "json"]);
        let (ok, summary) = verify(&fixture(), &args);
        assert!(!ok);
        assert_eq!(summary["code"], "USAGE", "{args:?}");
    }
}

/// The fixture's tenant, read from its summary.
fn fixture_tenant() -> String {
    verify(&fixture(), &FULL).1["details"]["tenant_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// A delegation document with one root for the fixture's tenant, its pin,
/// and a format 2 policy, written into `dir`.
fn write_delegation_files(dir: &Dir) {
    // A 32-byte Ed25519 public key that is not any key of the fixture.
    let root_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    dir.write(
        "delegations.json",
        &serde_json::json!({
            "schema_version": 1,
            "roots": [{"tenant_id": fixture_tenant(), "key_id": "tenant-root", "public_key_hex": root_hex}],
        })
        .to_string(),
    );
    dir.write(
        "root-pin.json",
        &serde_json::json!({"schema_version": 1, "key_id": "tenant-root", "public_key_hex": root_hex})
            .to_string(),
    );
    dir.write(
        "policy.json",
        include_str!("../../../docs/golden/canonical-policy-v2.json"),
    );
}

fn with_delegation_flags() -> Vec<&'static str> {
    let mut args = FULL.to_vec();
    args.extend([
        "--delegation-root-pin",
        "root-pin.json",
        "--delegations",
        "delegations.json",
        "--policy",
        "policy.json",
    ]);
    args
}

/// The fixture's first human decision, rewritten as a schema version 2
/// decision by the tenant's root (`delegation_chain: []`). Its signature
/// no longer verifies, but the verifier must stop before it.
fn with_a_delegated_decision(dir: &Dir) {
    let mut lines: Vec<String> = dir
        .read("approvals.jsonl")
        .lines()
        .map(str::to_owned)
        .collect();
    let index = lines
        .iter()
        .position(|line| line.contains("\"human_decision\""))
        .unwrap();
    let mut line: serde_json::Value = serde_json::from_str(&lines[index]).unwrap();
    line["human_decision"]["schema_version"] = 2.into();
    line["human_decision"]["approver_key_id"] = "tenant-root".into();
    line["human_decision"]["delegation_chain"] = serde_json::json!([]);
    lines[index] = line.to_string();
    dir.write("approvals.jsonl", &(lines.join("\n") + "\n"));
}

#[test]
fn version_1_decisions_verify_as_before_with_or_without_the_delegation_flags() {
    let dir = Dir::new();
    write_delegation_files(&dir);
    let (ok, without) = verify(&dir.0, &FULL);
    assert!(ok, "{without}");
    assert_eq!(without["details"]["delegation_checked"], false);
    let (ok, with) = verify(&dir.0, &with_delegation_flags());
    assert!(ok, "{with}");
    assert_eq!(with["details"]["delegation_checked"], true);
    assert_eq!(
        with["details"]["delegated_decisions"],
        serde_json::json!([])
    );
    assert_eq!(with["details"]["held"], without["details"]["held"]);
    assert_eq!(with["details"]["counts"], without["details"]["counts"]);
}

#[test]
fn a_delegated_decision_without_the_delegation_flags_fails_with_delegation_unverified() {
    let dir = Dir::new();
    with_a_delegated_decision(&dir);
    let (ok, summary) = verify(&dir.0, &FULL);
    assert!(!ok);
    assert_eq!(summary["code"], "DELEGATION_UNVERIFIED", "{summary}");
}

#[test]
fn a_delegated_decision_is_checked_against_the_given_policy() {
    let dir = Dir::new();
    write_delegation_files(&dir);
    with_a_delegated_decision(&dir);
    // The golden policy is not the policy the fixture's requests were
    // decided under: its digest is not the challenge's.
    let (ok, summary) = verify(&dir.0, &with_delegation_flags());
    assert!(!ok);
    assert_eq!(summary["code"], "DELEGATION_POLICY_MISMATCH", "{summary}");
}

#[test]
fn the_delegation_flags_go_together() {
    let dir = Dir::new();
    write_delegation_files(&dir);
    let full = with_delegation_flags();
    // Drop one of the three flags (and its value) at a time.
    for flag in ["--delegation-root-pin", "--delegations", "--policy"] {
        let position = full.iter().position(|arg| *arg == flag).unwrap();
        let mut args = full.clone();
        args.drain(position..position + 2);
        assert_eq!(verify(&dir.0, &args).1["code"], "USAGE", "{flag}");
    }
    // A malformed delegation document is reported with its own code.
    dir.write(
        "delegations.json",
        "{\"schema_version\":1,\"roots\":[],\"extra\":1}",
    );
    assert_eq!(
        verify(&dir.0, &full).1["code"],
        "DELEGATION_DOCUMENT_INVALID"
    );
}
