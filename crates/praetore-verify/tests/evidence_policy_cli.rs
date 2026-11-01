//! CLI tests for `praetore-verify evidence --policy`.

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
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

/// Regenerate with scripts/regen-legacy-evidence-fixture.sh (signed by
/// praetore-core 3db7b5e, attester secret [3; 32], no policy_digest).
const LEGACY: &str = include_str!("fixtures/legacy-evidence-no-policy-digest.json");

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "praetore-verify-policy-{}-{}",
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
        "receipt-policy",
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

fn receipt(policy: &Policy) -> Evidence {
    let agent_key = AgentKeyPair::from_secret_bytes(&[1; 32]);
    let issuer_key = AgentKeyPair::from_secret_bytes(&[2; 32]);
    let agent = agent_key.identity(AgentId::new());
    let mut authority = Authority::new(agent.id.clone(), "test-issuer", vec!["data:read".into()]);
    authority.sign_for_agent(&issuer_key, &agent).unwrap();
    let action = Action::new("read_data", Some("db".into()), json!({}))
        .unwrap()
        .with_capability("data:read");
    let mut request = AuthorizationRequest::new(agent, authority, mission(action)).unwrap();
    request.sign_intent(&agent_key).unwrap();
    let mut evidence = request
        .attest(Decision::allow(
            "policy fixture",
            praetore_core::DecidedBy::rule("policy-fixture"),
        ))
        .unwrap();
    evidence
        .bind_policy_digest(policy.digest().unwrap())
        .unwrap();
    evidence.sign(&attester()).unwrap();
    evidence
}

fn verify(evidence: &str, pin_file: &str, policy: Option<&str>) -> Output {
    let mut args = vec![
        "evidence",
        "--evidence",
        evidence,
        "--attester-pin",
        pin_file,
    ];
    if let Some(policy) = policy {
        args.extend(["--policy", policy]);
    }
    args.extend(["--format", "json"]);
    Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .args(&args)
        .output()
        .unwrap()
}

fn summary(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_fails(output: &Output, expected: &str) {
    assert!(!output.status.success(), "expected failure {expected}");
    assert_eq!(summary(output)["code"], expected);
}

#[test]
fn matching_policy_verifies() {
    let dir = Dir::new();
    let allow = policy(PolicyEffect::Allow);
    let evidence = dir.write("e.json", receipt(&allow).to_json().unwrap());
    let pin_file = dir.write("pin.hex", pin(&attester()));
    let policy_file = dir.write("p.json", serde_json::to_vec(&allow).unwrap());

    let output = verify(&evidence, &pin_file, Some(&policy_file));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(summary(&output)["details"]["policy_verified"], true);
}

#[test]
fn other_or_invalid_policy_fails() {
    let dir = Dir::new();
    let evidence = dir.write(
        "e.json",
        receipt(&policy(PolicyEffect::Allow)).to_json().unwrap(),
    );
    let pin_file = dir.write("pin.hex", pin(&attester()));
    let other = dir.write(
        "other.json",
        serde_json::to_vec(&policy(PolicyEffect::Deny)).unwrap(),
    );
    assert_fails(
        &verify(&evidence, &pin_file, Some(&other)),
        "POLICY_MISMATCH",
    );

    let invalid = dir.write("invalid.json", "{\"id\":\"x\"}");
    assert!(
        !verify(&evidence, &pin_file, Some(&invalid))
            .status
            .success()
    );
}

#[test]
fn wrong_key_still_fails_before_policy_check() {
    let dir = Dir::new();
    let allow = policy(PolicyEffect::Allow);
    let evidence = dir.write("e.json", receipt(&allow).to_json().unwrap());
    let wrong = dir.write(
        "w.hex",
        pin(&EvidenceAttesterKey::from_secret_bytes(&[4; 32])),
    );
    let policy_file = dir.write("p.json", serde_json::to_vec(&allow).unwrap());
    assert_fails(&verify(&evidence, &wrong, Some(&policy_file)), "AUTH_FAIL");
}

#[test]
fn legacy_receipt_without_policy_digest_verifies_but_fails_with_policy() {
    let dir = Dir::new();
    let legacy = Evidence::from_json(LEGACY.trim()).unwrap();
    assert!(legacy.policy_digest.is_none());
    let evidence = dir.write("legacy.json", LEGACY.trim());
    let pin_file = dir.write("pin.hex", pin(&attester()));
    let policy_file = dir.write(
        "p.json",
        serde_json::to_vec(&policy(PolicyEffect::Allow)).unwrap(),
    );

    let plain = verify(&evidence, &pin_file, None);
    assert!(
        plain.status.success(),
        "{}",
        String::from_utf8_lossy(&plain.stdout)
    );
    assert_fails(
        &verify(&evidence, &pin_file, Some(&policy_file)),
        "POLICY_MISMATCH",
    );
}

#[test]
fn swapping_the_recorded_digest_to_the_audited_policy_fails_signature() {
    let dir = Dir::new();
    let allow = policy(PolicyEffect::Allow);
    let deny = policy(PolicyEffect::Deny);
    // Signed under `allow`; a forger rewrites the digest to `deny` and
    // recomputes the (unkeyed) integrity hash so the receipt still parses.
    let mut forged = receipt(&allow);
    forged.bind_policy_digest(deny.digest().unwrap()).unwrap();
    assert!(forged.attester_signature.is_some());
    let evidence = dir.write("forged.json", forged.to_json().unwrap());
    let pin_file = dir.write("pin.hex", pin(&attester()));
    let deny_file = dir.write("deny.json", serde_json::to_vec(&deny).unwrap());
    assert_fails(&verify(&evidence, &pin_file, Some(&deny_file)), "AUTH_FAIL");
    assert_fails(&verify(&evidence, &pin_file, None), "AUTH_FAIL");
}

#[test]
fn oversized_or_missing_policy_file_fails_without_success() {
    let dir = Dir::new();
    let allow = policy(PolicyEffect::Allow);
    let evidence = dir.write("e.json", receipt(&allow).to_json().unwrap());
    let pin_file = dir.write("pin.hex", pin(&attester()));
    let mut big = serde_json::to_value(&allow).unwrap();
    big["id"] = Value::String("x".repeat(70 * 1024));
    let big_file = dir.write("big.json", serde_json::to_vec(&big).unwrap());
    let output = verify(&evidence, &pin_file, Some(&big_file));
    assert!(!output.status.success());
    assert_eq!(summary(&output)["ok"], false);
    let missing = dir.0.join("missing.json").to_string_lossy().into_owned();
    let output = verify(&evidence, &pin_file, Some(&missing));
    assert!(!output.status.success());
    assert_eq!(summary(&output)["ok"], false);
}

/// G7: evidence that bound a policy format 1 digest (committed before G7)
/// still verifies against its recorded format 1 document. The migrated
/// format 2 document has another digest, so it does not match that evidence.
#[test]
fn historical_format_1_evidence_verifies_against_its_recorded_document() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/verify");
    let path = |name: &str| fixtures.join(name).to_string_lossy().into_owned();
    let recorded = fs::read_to_string(fixtures.join("policy.json")).unwrap();
    assert!(!recorded.contains("format_version"), "fixture is format 1");

    let output = verify(
        &path("evidence.json"),
        &path("attester-public-key.hex"),
        Some(&path("policy.json")),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(summary(&output)["details"]["policy_verified"], true);

    let digest = Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .args(["policy-digest", "--policy", &path("policy.json")])
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(digest.status.success());
    assert_eq!(summary(&digest)["details"]["policy_format_version"], 1);

    // The same rules migrated to format 2 (with action_classes).
    let mut migrated: Value = serde_json::from_str(&recorded).unwrap();
    migrated["format_version"] = json!(2);
    migrated["action_classes"] = json!({"read_data": "Mission"});
    let dir = Dir::new();
    let migrated = dir.write("migrated.json", migrated.to_string());
    let output = verify(
        &path("evidence.json"),
        &path("attester-public-key.hex"),
        Some(&migrated),
    );
    assert_fails(&output, "POLICY_MISMATCH");
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
