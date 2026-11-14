//! The policy's `approval_delegation` option and the delegation document's
//! format checks. The chain rules are tested where the gateway and the
//! offline verifier use them (praetore-gateway `tests/enforcement.rs`,
//! module `delegated_approval`).

use praetore_core::{
    AgentKeyPair, ApprovalDelegationPolicy, Policy, PolicyDocumentError, PraetoreError,
    approval_delegation::{
        ApprovalDelegation, DelegationConfig, DelegationError, DelegationRole, DelegationScope,
    },
};
use serde_json::{Value, json};
use uuid::Uuid;

const TENANT: Uuid = Uuid::from_u128(1);

fn golden_policy() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/golden/canonical-policy-v2.json"
    ))
    .unwrap()
}

#[test]
fn without_the_option_a_policy_digest_is_unchanged() {
    let policy = Policy::from_json(&golden_policy().to_string()).unwrap();
    assert_eq!(policy.approval_delegation, None);
    assert!(!policy.root_may_approve());
    assert!(
        !serde_json::to_string(&policy)
            .unwrap()
            .contains("approval_delegation")
    );
}

#[test]
fn an_explicit_false_loads_behaves_as_absent_and_has_another_digest() {
    let absent = Policy::from_json(&golden_policy().to_string()).unwrap();
    let mut document = golden_policy();
    document["approval_delegation"] = json!({"root_may_approve": false});
    let explicit_false = Policy::from_json(&document.to_string()).unwrap();
    assert_eq!(
        explicit_false.approval_delegation,
        Some(ApprovalDelegationPolicy {
            root_may_approve: false
        })
    );
    assert!(!explicit_false.root_may_approve());
    assert_ne!(explicit_false.digest().unwrap(), absent.digest().unwrap());
    document["approval_delegation"] = json!({"root_may_approve": true});
    let allowed = Policy::from_json(&document.to_string()).unwrap();
    assert!(allowed.root_may_approve());
    assert_ne!(allowed.digest().unwrap(), explicit_false.digest().unwrap());
}

#[test]
fn the_option_rejects_unknown_fields_and_a_missing_value() {
    let mut document = golden_policy();
    document["approval_delegation"] = json!({"root_may_approve": true, "tenants": ["a"]});
    assert!(matches!(
        Policy::from_json(&document.to_string()),
        Err(PraetoreError::PolicyDocumentInvalid(
            PolicyDocumentError::UnknownField { .. }
        ))
    ));
    document["approval_delegation"] = json!({});
    assert!(Policy::from_json(&document.to_string()).is_err());
    document["approval_delegation"] = json!({"root_may_approve": "yes"});
    assert!(Policy::from_json(&document.to_string()).is_err());
}

fn pair(seed: u8) -> AgentKeyPair {
    AgentKeyPair::from_secret_bytes(&[seed; 32])
}

fn delegation() -> ApprovalDelegation {
    ApprovalDelegation {
        schema_version: 1,
        delegation_id: Uuid::new_v4(),
        tenant_id: TENANT,
        issuer_key_id: "root".into(),
        parent_delegation_hash: None,
        subject_key_id: "alice".into(),
        subject_public_key_hex: hex::encode(pair(2).public_key().as_bytes()),
        role: DelegationRole::Approver,
        scope: DelegationScope {
            action_types: vec!["local:set_value".into()],
        },
        not_before: "2026-06-01T00:00:00Z".into(),
        not_after: "2026-06-02T00:00:00Z".into(),
        max_depth: 0,
        signature: String::new(),
    }
}

fn load(delegation: &ApprovalDelegation) -> Result<DelegationConfig, DelegationError> {
    let mut delegation = delegation.clone();
    delegation.sign(&pair(1)).unwrap();
    DelegationConfig::from_json(
        &json!({
            "schema_version": 1,
            "roots": [{"tenant_id": TENANT, "key_id": "root",
                       "public_key_hex": hex::encode(pair(1).public_key().as_bytes())}],
            "delegations": [delegation],
        })
        .to_string(),
    )
}

#[test]
fn a_well_formed_delegation_loads() {
    assert!(load(&delegation()).is_ok());
}

type Edit = Box<dyn Fn(&mut ApprovalDelegation)>;

#[test]
fn malformed_delegations_are_refused_when_the_document_is_read() {
    let cases: Vec<(&str, Edit)> = vec![
        (
            "wildcard",
            Box::new(|d| d.scope.action_types = vec!["local:*".into()]),
        ),
        ("no action", Box::new(|d| d.scope.action_types.clear())),
        (
            "repeated action",
            Box::new(|d| d.scope.action_types = vec!["a".into(), "a".into()]),
        ),
        ("depth over the maximum", Box::new(|d| d.max_depth = 4)),
        (
            "not version 4",
            Box::new(|d| d.delegation_id = Uuid::from_u128(7)),
        ),
        ("nil tenant", Box::new(|d| d.tenant_id = Uuid::nil())),
        (
            "empty window",
            Box::new(|d| d.not_after = d.not_before.clone()),
        ),
        (
            "offset time",
            Box::new(|d| d.not_before = "2026-06-01T02:00:00+02:00".into()),
        ),
        ("schema 2", Box::new(|d| d.schema_version = 2)),
        (
            "empty parent hash",
            Box::new(|d| d.parent_delegation_hash = Some(String::new())),
        ),
        (
            "uppercase key",
            Box::new(|d| d.subject_public_key_hex = d.subject_public_key_hex.to_uppercase()),
        ),
        (
            "padded key id",
            Box::new(|d| d.subject_key_id = " alice".into()),
        ),
    ];
    for (name, edit) in cases {
        let mut bad = delegation();
        edit(&mut bad);
        assert_eq!(
            load(&bad).unwrap_err(),
            DelegationError::InvalidDocument,
            "{name}"
        );
    }
}

#[test]
fn a_delegation_with_an_unknown_field_is_refused() {
    let mut value = serde_json::to_value(delegation()).unwrap();
    value["scope"]["parameters"] = json!({});
    let document = json!({
        "schema_version": 1,
        "roots": [{"tenant_id": TENANT, "key_id": "root",
                   "public_key_hex": hex::encode(pair(1).public_key().as_bytes())}],
        "delegations": [value],
    });
    assert_eq!(
        DelegationConfig::from_json(&document.to_string()).unwrap_err(),
        DelegationError::InvalidDocument
    );
}
