//! CLI tests for `praetore-verify journal` and `--policy`.

use praetore_core::{
    action::Action,
    authority::Authority,
    authorization::AuthorizationRequest,
    decision::Decision,
    evidence::{Evidence, EvidenceAttesterKey},
    identity::{AgentId, AgentKeyPair},
    policy::{Policy, PolicyEffect, PolicyRule},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const LEGACY: &str = include_str!("fixtures/legacy-evidence-no-policy-digest.json");

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "praetore-verify-journal-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> String {
        let path = self.0.join(name);
        fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn policy(effect: PolicyEffect) -> Policy {
    mission_policy(Policy::new(
        "journal-policy",
        1,
        vec![PolicyRule::new("read", "read_data", effect)],
    ))
}

fn attester() -> EvidenceAttesterKey {
    EvidenceAttesterKey::from_secret_bytes(&[3; 32])
}

fn pin(key: &EvidenceAttesterKey) -> String {
    format!("{}\n", hex::encode(key.public_key().unwrap().as_bytes()))
}

fn receipt(index: u8, policy: &Policy) -> Evidence {
    let agent_key = AgentKeyPair::from_secret_bytes(&[1; 32]);
    let issuer_key = AgentKeyPair::from_secret_bytes(&[2; 32]);
    let agent = agent_key.identity(AgentId::new());
    let mut authority = Authority::new(agent.id.clone(), "test-issuer", vec!["data:read".into()]);
    authority.sign_for_agent(&issuer_key, &agent).unwrap();
    let action = Action::new("read_data", Some("db".into()), json!({ "row": index }))
        .unwrap()
        .with_capability("data:read");
    let mut request = AuthorizationRequest::new(agent, authority, mission(action)).unwrap();
    request.sign_intent(&agent_key).unwrap();
    let mut evidence = request
        .attest(Decision::allow(
            "journal fixture",
            praetore_core::DecidedBy::rule("journal-fixture"),
        ))
        .unwrap();
    evidence
        .bind_policy_digest(policy.digest().unwrap())
        .unwrap();
    evidence.sign(&attester()).unwrap();
    evidence
}

/// Independent re-implementation of the documented link hash.
fn link(seq: u64, prev: &str, evidence: &Evidence) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"PRAETORE_JOURNAL_LINK_V1\0");
    hasher.update(seq.to_be_bytes());
    hasher.update(prev.as_bytes());
    hasher.update(evidence.context_hash.as_bytes());
    hasher.update(evidence.attester_signature.as_deref().unwrap().as_bytes());
    hex::encode(hasher.finalize())
}

fn entry(seq: u64, prev: &str, evidence: &Evidence) -> String {
    let evidence: Value = serde_json::from_str(&evidence.to_json().unwrap()).unwrap();
    json!({ "seq": seq, "prev": prev, "evidence": evidence }).to_string()
}

fn journal(receipts: &[Evidence]) -> Vec<String> {
    let mut prev = GENESIS.to_owned();
    receipts
        .iter()
        .enumerate()
        .map(|(seq, evidence)| {
            let line = entry(seq as u64, &prev, evidence);
            prev = link(seq as u64, &prev, evidence);
            line
        })
        .collect()
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .args(args)
        .output()
        .unwrap()
}

fn code(output: &Output) -> String {
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    summary["code"].as_str().unwrap().to_owned()
}

fn verify_journal(dir: &Dir, lines: &[String], pin_file: &str, policy: Option<&str>) -> Output {
    let text: String = lines.iter().map(|line| format!("{line}\n")).collect();
    let path = dir.write("journal.jsonl", text);
    let mut args = vec!["journal", "--journal", &path, "--attester-pin", pin_file];
    if let Some(policy) = policy {
        args.extend(["--policy", policy]);
    }
    args.extend(["--format", "json"]);
    run(&args)
}

fn assert_fails(output: &Output, expected: &str) {
    assert!(!output.status.success(), "expected failure {expected}");
    assert_ne!(output.status.code(), Some(0));
    assert_eq!(code(output), expected);
}

#[test]
fn valid_journal_verifies_with_pinned_key_and_policy() {
    let dir = Dir::new();
    let allow = policy(PolicyEffect::Allow);
    let receipts: Vec<_> = (0..3).map(|i| receipt(i, &allow)).collect();
    let pin_file = dir.write("pin.hex", pin(&attester()));
    let policy_file = dir.write("policy.json", serde_json::to_vec(&allow).unwrap());

    let output = verify_journal(&dir, &journal(&receipts), &pin_file, Some(&policy_file));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["ok"], true);
    assert_eq!(summary["details"]["entries"], 3);
    assert_eq!(summary["details"]["policy_verified"], true);
    let mut head = GENESIS.to_owned();
    for (seq, evidence) in receipts.iter().enumerate() {
        head = link(seq as u64, &head, evidence);
    }
    assert_eq!(summary["details"]["head"], head);
}

#[test]
fn altered_signature_fails() {
    let dir = Dir::new();
    let allow = policy(PolicyEffect::Allow);
    let mut receipts: Vec<_> = (0..2).map(|i| receipt(i, &allow)).collect();
    let pin_file = dir.write("pin.hex", pin(&attester()));
    receipts[1].attester_signature = Some("00".repeat(64));
    // The chain is rebuilt over the altered signature, so only the Ed25519
    // check can catch it.
    assert_fails(
        &verify_journal(&dir, &journal(&receipts), &pin_file, None),
        "AUTH_FAIL",
    );
}

#[test]
fn broken_reordered_dropped_or_duplicated_links_fail() {
    let dir = Dir::new();
    let allow = policy(PolicyEffect::Allow);
    let receipts: Vec<_> = (0..3).map(|i| receipt(i, &allow)).collect();
    let pin_file = dir.write("pin.hex", pin(&attester()));
    let lines = journal(&receipts);

    let mut reordered = lines.clone();
    reordered.swap(1, 2);
    assert_fails(
        &verify_journal(&dir, &reordered, &pin_file, None),
        "JOURNAL_CHAIN_FAIL",
    );

    let dropped = vec![lines[0].clone(), lines[2].clone()];
    assert_fails(
        &verify_journal(&dir, &dropped, &pin_file, None),
        "JOURNAL_CHAIN_FAIL",
    );

    let mut broken = lines.clone();
    broken[2] = entry(2, &"ab".repeat(32), &receipts[2]);
    assert_fails(
        &verify_journal(&dir, &broken, &pin_file, None),
        "JOURNAL_CHAIN_FAIL",
    );

    // A duplicated receipt, even correctly linked, is rejected.
    let duplicated = journal(&[receipts[0].clone(), receipts[0].clone()]);
    assert_fails(
        &verify_journal(&dir, &duplicated, &pin_file, None),
        "JOURNAL_CHAIN_FAIL",
    );

    assert_fails(
        &verify_journal(&dir, &[], &pin_file, None),
        "JOURNAL_CHAIN_FAIL",
    );
}

#[test]
fn wrong_attester_key_fails() {
    let dir = Dir::new();
    let allow = policy(PolicyEffect::Allow);
    let receipts = vec![receipt(0, &allow)];
    let wrong = dir.write(
        "wrong.hex",
        pin(&EvidenceAttesterKey::from_secret_bytes(&[4; 32])),
    );
    assert_fails(
        &verify_journal(&dir, &journal(&receipts), &wrong, None),
        "AUTH_FAIL",
    );
}

#[test]
fn other_policy_fails_for_journal_and_evidence() {
    let dir = Dir::new();
    let allow = policy(PolicyEffect::Allow);
    let deny = policy(PolicyEffect::Deny);
    let evidence = receipt(0, &allow);
    let pin_file = dir.write("pin.hex", pin(&attester()));
    let right = dir.write("right.json", serde_json::to_vec(&allow).unwrap());
    let other = dir.write("other.json", serde_json::to_vec(&deny).unwrap());
    let evidence_file = dir.write("evidence.json", evidence.to_json().unwrap());

    assert_fails(
        &verify_journal(&dir, &journal(&[evidence]), &pin_file, Some(&other)),
        "POLICY_MISMATCH",
    );

    let ok = run(&[
        "evidence",
        "--evidence",
        &evidence_file,
        "--attester-pin",
        &pin_file,
        "--policy",
        &right,
        "--format",
        "json",
    ]);
    assert!(ok.status.success());
    let summary: Value = serde_json::from_slice(&ok.stdout).unwrap();
    assert_eq!(summary["details"]["policy_verified"], true);

    let bad = run(&[
        "evidence",
        "--evidence",
        &evidence_file,
        "--attester-pin",
        &pin_file,
        "--policy",
        &other,
        "--format",
        "json",
    ]);
    assert_fails(&bad, "POLICY_MISMATCH");

    let invalid_policy = dir.write("invalid.json", "{\"id\":\"x\"}");
    let invalid = run(&[
        "evidence",
        "--evidence",
        &evidence_file,
        "--attester-pin",
        &pin_file,
        "--policy",
        &invalid_policy,
        "--format",
        "json",
    ]);
    assert!(!invalid.status.success());
}

#[test]
fn legacy_receipt_without_policy_digest_verifies_but_fails_with_policy() {
    // Fixture produced and signed by origin/main 3db7b5e, before the digest
    // was required (attester secret [3; 32]).
    let dir = Dir::new();
    let legacy = Evidence::from_json(LEGACY.trim()).unwrap();
    assert!(legacy.policy_digest.is_none());
    let pin_file = dir.write("pin.hex", pin(&attester()));
    let evidence_file = dir.write("legacy.json", LEGACY.trim());
    let policy_file = dir.write(
        "policy.json",
        serde_json::to_vec(&policy(PolicyEffect::Allow)).unwrap(),
    );

    let plain = run(&[
        "evidence",
        "--evidence",
        &evidence_file,
        "--attester-pin",
        &pin_file,
        "--format",
        "json",
    ]);
    assert!(
        plain.status.success(),
        "{}",
        String::from_utf8_lossy(&plain.stdout)
    );

    let with_policy = run(&[
        "evidence",
        "--evidence",
        &evidence_file,
        "--attester-pin",
        &pin_file,
        "--policy",
        &policy_file,
        "--format",
        "json",
    ]);
    assert_fails(&with_policy, "POLICY_MISMATCH");

    assert_fails(
        &verify_journal(&dir, &journal(&[legacy]), &pin_file, Some(&policy_file)),
        "POLICY_MISMATCH",
    );
}

#[test]
fn malformed_and_oversized_journals_fail_closed() {
    let dir = Dir::new();
    let pin_file = dir.write("pin.hex", pin(&attester()));
    assert_fails(
        &verify_journal(&dir, &["not json".into()], &pin_file, None),
        "INVALID_REQUEST",
    );
    let allow = policy(PolicyEffect::Allow);
    let mut lines = journal(&[receipt(0, &allow)]);
    lines[0] = lines[0].replacen('{', "{\"extra\":1,", 1);
    assert_fails(
        &verify_journal(&dir, &lines, &pin_file, None),
        "INVALID_REQUEST",
    );

    let big = dir.write("big.jsonl", vec![b' '; 8 * 1024 * 1024 + 1]);
    let output = run(&[
        "journal",
        "--journal",
        &big,
        "--attester-pin",
        &pin_file,
        "--format",
        "json",
    ]);
    assert_fails(&output, "INPUT_TOO_LARGE");
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
