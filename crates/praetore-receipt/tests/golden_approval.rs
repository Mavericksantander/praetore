//! Golden vectors of human decisions, approval delegations and revocations
//! (`docs/golden/`), recomputed from fixed keys. The version 1 decision
//! vector was produced before delegated approval existed: a version 1
//! decision signs and serializes exactly as it did.

use ed25519_dalek::{Signer, SigningKey};
use praetore_core::{
    AgentKeyPair,
    approval_delegation::{
        ApprovalDelegation, ApprovalRevocation, DelegationRole, DelegationScope,
    },
};
use praetore_receipt::{ApprovalChallenge, HumanApprovalDecision, HumanApprovalOutcome};
use serde_json::Value;
use uuid::Uuid;

fn golden(name: &str) -> Value {
    let path = format!("{}/../../docs/golden/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{path}"));
    serde_json::from_str(&text).unwrap()
}

/// Writes the vector when `PRAETORE_WRITE_GOLDEN` is set (to create a new
/// one); otherwise compares.
fn check(name: &str, computed: Value) {
    if std::env::var_os("PRAETORE_WRITE_GOLDEN").is_some() {
        let path = format!("{}/../../docs/golden/{name}", env!("CARGO_MANIFEST_DIR"));
        if !std::path::Path::new(&path).exists() {
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&computed).unwrap() + "\n",
            )
            .unwrap();
        }
    }
    assert_eq!(golden(name), computed, "{name}");
}

fn challenge() -> ApprovalChallenge {
    ApprovalChallenge {
        schema_version: 1,
        tenant_id: Uuid::from_u128(0x10),
        agent_id: Uuid::from_u128(0x20),
        request_id: Uuid::from_u128(0x30),
        evidence_id: Uuid::from_u128(0x40),
        evidence_hash: "11".repeat(32),
        action_digest: "22".repeat(32),
        policy_digest: "33".repeat(32),
        expires_at: "2026-12-01T00:05:00Z".into(),
    }
}

fn signed(mut decision: HumanApprovalDecision, key: &SigningKey) -> HumanApprovalDecision {
    decision.signature = hex::encode(key.sign(&decision.signing_message().unwrap()).to_bytes());
    decision
}

fn decision_vector(decision: &HumanApprovalDecision, key: &SigningKey) -> Value {
    serde_json::json!({
        "approver_public_key_hex": hex::encode(key.verifying_key().to_bytes()),
        "decision_json": serde_json::to_string(decision).unwrap(),
        "signature_hex": decision.signature,
        "signing_payload": String::from_utf8(decision.signing_payload().unwrap()).unwrap(),
    })
}

#[test]
fn a_version_1_decision_is_unchanged() {
    let key = SigningKey::from_bytes(&[0x21; 32]);
    let decision = signed(
        HumanApprovalDecision {
            schema_version: 1,
            approval_id: Uuid::parse_str("4a4f7b2e-9d1c-4f6a-8b3e-5c2d1e0f9a8b").unwrap(),
            approver_key_id: "golden-approver".into(),
            challenge: challenge(),
            outcome: HumanApprovalOutcome::Approve,
            delegation_chain: None,
            signature: String::new(),
        },
        &key,
    );
    let vector = golden("human-approval-decision-v1.json");
    assert_eq!(decision_vector(&decision, &key), vector);
    // The stored form parses back and verifies with the pinned key.
    let parsed =
        HumanApprovalDecision::from_json(vector["decision_json"].as_str().unwrap()).unwrap();
    let public =
        praetore_core::VerifiedPublicKey::from_bytes(&key.verifying_key().to_bytes()).unwrap();
    parsed.verify_signature("golden-approver", &public).unwrap();
    assert!(
        !vector["decision_json"]
            .as_str()
            .unwrap()
            .contains("delegation_chain")
    );
}

fn root_delegation() -> ApprovalDelegation {
    let mut delegation = ApprovalDelegation {
        schema_version: 1,
        delegation_id: Uuid::parse_str("6d1f3c2a-8b4e-4f7a-9c0d-1e2f3a4b5c6d").unwrap(),
        tenant_id: Uuid::from_u128(0x10),
        issuer_key_id: "golden-root".into(),
        parent_delegation_hash: None,
        subject_key_id: "golden-delegator".into(),
        subject_public_key_hex: hex::encode(
            AgentKeyPair::from_secret_bytes(&[0x42; 32])
                .public_key()
                .as_bytes(),
        ),
        role: DelegationRole::Delegator,
        scope: DelegationScope {
            action_types: vec!["local:set_value".into(), "local:delete_value".into()],
        },
        not_before: "2026-11-01T00:00:00Z".into(),
        not_after: "2026-12-31T00:00:00Z".into(),
        max_depth: 1,
        signature: String::new(),
    };
    delegation
        .sign(&AgentKeyPair::from_secret_bytes(&[0x41; 32]))
        .unwrap();
    delegation
}

fn approver_delegation(parent: &ApprovalDelegation) -> ApprovalDelegation {
    let mut delegation = ApprovalDelegation {
        schema_version: 1,
        delegation_id: Uuid::parse_str("7e2a4d3b-9c5f-4a8b-8d1e-2f3a4b5c6d7e").unwrap(),
        tenant_id: Uuid::from_u128(0x10),
        issuer_key_id: "golden-delegator".into(),
        parent_delegation_hash: Some(parent.hash().unwrap()),
        subject_key_id: "golden-approver".into(),
        subject_public_key_hex: hex::encode(
            AgentKeyPair::from_secret_bytes(&[0x43; 32])
                .public_key()
                .as_bytes(),
        ),
        role: DelegationRole::Approver,
        scope: DelegationScope {
            action_types: vec!["local:set_value".into()],
        },
        not_before: "2026-11-15T00:00:00Z".into(),
        not_after: "2026-12-15T00:00:00Z".into(),
        max_depth: 0,
        signature: String::new(),
    };
    delegation
        .sign(&AgentKeyPair::from_secret_bytes(&[0x42; 32]))
        .unwrap();
    delegation
}

fn delegation_vector(delegation: &ApprovalDelegation, issuer_seed: u8) -> Value {
    serde_json::json!({
        "issuer_public_key_hex": hex::encode(
            AgentKeyPair::from_secret_bytes(&[issuer_seed; 32]).public_key().as_bytes()
        ),
        "delegation_json": serde_json::to_string(delegation).unwrap(),
        "signing_payload": String::from_utf8(delegation.signing_payload().unwrap()).unwrap(),
        "signature_hex": delegation.signature,
        "delegation_hash": delegation.hash().unwrap(),
    })
}

#[test]
fn approval_delegations_match_their_vector() {
    let root = root_delegation();
    let approver = approver_delegation(&root);
    check(
        "approval-delegation-v1.json",
        serde_json::json!({
            "domain": "PRAETORE_APPROVAL_DELEGATION_V1\\0",
            "hash_domain": "PRAETORE_APPROVAL_DELEGATION_HASH_V1\\0",
            "root_signed": delegation_vector(&root, 0x41),
            "delegator_signed": delegation_vector(&approver, 0x42),
        }),
    );
}

#[test]
fn approval_revocations_match_their_vector() {
    let root = root_delegation();
    let approver = approver_delegation(&root);
    let mut revocation = ApprovalRevocation {
        schema_version: 1,
        tenant_id: Uuid::from_u128(0x10),
        delegation_hash: approver.hash().unwrap(),
        issuer_key_id: "golden-delegator".into(),
        effective_at: "2026-12-01T00:00:00Z".into(),
        signature: String::new(),
    };
    revocation
        .sign(&AgentKeyPair::from_secret_bytes(&[0x42; 32]))
        .unwrap();
    check(
        "approval-revocation-v1.json",
        serde_json::json!({
            "domain": "PRAETORE_APPROVAL_REVOCATION_V1\\0",
            "issuer_public_key_hex": hex::encode(
                AgentKeyPair::from_secret_bytes(&[0x42; 32]).public_key().as_bytes()
            ),
            "revocation_json": serde_json::to_string(&revocation).unwrap(),
            "signing_payload": String::from_utf8(revocation.signing_payload().unwrap()).unwrap(),
            "signature_hex": revocation.signature,
        }),
    );
}

#[test]
fn a_version_2_decision_matches_its_vector() {
    let root = root_delegation();
    let approver = approver_delegation(&root);
    let key = SigningKey::from_bytes(&[0x43; 32]);
    let delegated = signed(
        HumanApprovalDecision {
            schema_version: 2,
            approval_id: Uuid::parse_str("8f3b5e4c-0d6a-4b9c-9e2f-3a4b5c6d7e8f").unwrap(),
            approver_key_id: "golden-approver".into(),
            challenge: challenge(),
            outcome: HumanApprovalOutcome::Approve,
            delegation_chain: Some(vec![root.hash().unwrap(), approver.hash().unwrap()]),
            signature: String::new(),
        },
        &key,
    );
    let root_key = SigningKey::from_bytes(&[0x41; 32]);
    let by_root = signed(
        HumanApprovalDecision {
            schema_version: 2,
            approval_id: Uuid::parse_str("9a4c6f5d-1e7b-4c0d-8f3a-4b5c6d7e8f9a").unwrap(),
            approver_key_id: "golden-root".into(),
            challenge: challenge(),
            outcome: HumanApprovalOutcome::Approve,
            delegation_chain: Some(vec![]),
            signature: String::new(),
        },
        &root_key,
    );
    check(
        "human-approval-decision-v2.json",
        serde_json::json!({
            "delegated": decision_vector(&delegated, &key),
            "root_approves": decision_vector(&by_root, &root_key),
        }),
    );
}
