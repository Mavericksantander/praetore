//! The gateway's delegated-approval document
//! (`PRAETORE_GATEWAY_DELEGATION_FILE`): one delegation root per tenant, the
//! signed delegations and the signed revocations. The file is optional;
//! without it the gateway accepts only its pinned approvers, as before.
//!
//! The format and its checks are [`DelegationConfig::from_json`]'s. Here the
//! gateway adds what only it knows: every root tenant has an issuer binding,
//! and no root key is also a pinned approver key, an authority issuer key or
//! an attester key. A root that was also a pinned approver could sign a
//! version 1 decision and so approve whatever the policy's
//! `root_may_approve` says.
//!
//! The document is read once, at startup: a new revocation takes effect when
//! the gateway restarts with it.

use praetore_core::{
    VerifiedPublicKey,
    approval_delegation::{DelegationConfig, DelegationError},
};
use praetore_gateway::HumanApprovalVerifier;
use std::collections::HashSet;
use uuid::Uuid;

/// The keys of the gateway's other roles, which a delegation root must not
/// reuse.
pub struct OtherRoleKeys<'a> {
    pub approvers: &'a [HumanApprovalVerifier],
    pub issuers: &'a [VerifiedPublicKey],
    pub attesters: &'a [VerifiedPublicKey],
}

/// Parses the delegation document for this gateway. `issuer_tenants` is
/// `None` only for the single-tenant local demo.
pub fn parse_delegation_config(
    document: &str,
    issuer_tenants: Option<&HashSet<Uuid>>,
    others: &OtherRoleKeys<'_>,
) -> Result<DelegationConfig, Box<dyn std::error::Error>> {
    let config = DelegationConfig::from_json(document).map_err(describe)?;
    for root in config.roots() {
        if issuer_tenants.is_some_and(|tenants| !tenants.contains(&root.tenant_id)) {
            return Err("delegation file names a tenant without an issuer binding".into());
        }
        let shared_approver = others.approvers.iter().any(|approver| {
            approver.public_key() == &root.public_key || approver.key_id() == root.key_id
        });
        if shared_approver {
            return Err(
                "a delegation root key or key id is also a pinned approver; the root would approve without the policy's root_may_approve"
                    .into(),
            );
        }
        if others.issuers.contains(&root.public_key) {
            return Err("a delegation root key is also an authority issuer key".into());
        }
        if others.attesters.contains(&root.public_key) {
            return Err("a delegation root key is also an attester key".into());
        }
    }
    Ok(config)
}

fn describe(error: DelegationError) -> Box<dyn std::error::Error> {
    format!("delegation file: {error} ({})", error.code()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use praetore_core::AgentKeyPair;
    use serde_json::{Value, json};

    const TENANT_A: Uuid = Uuid::from_u128(1);
    const TENANT_B: Uuid = Uuid::from_u128(2);

    fn public(seed: u8) -> VerifiedPublicKey {
        AgentKeyPair::from_secret_bytes(&[seed; 32]).public_key()
    }

    fn public_hex(seed: u8) -> String {
        hex::encode(public(seed).as_bytes())
    }

    fn roots(roots: Value) -> String {
        json!({"schema_version": 1, "roots": roots}).to_string()
    }

    fn one_root(key_id: &str, seed: u8) -> String {
        roots(
            json!([{"tenant_id": TENANT_A, "key_id": key_id, "public_key_hex": public_hex(seed)}]),
        )
    }

    fn approver(key_id: &str, seed: u8) -> HumanApprovalVerifier {
        HumanApprovalVerifier::for_tenant(TENANT_A, key_id, public(seed)).unwrap()
    }

    /// Starts like the gateway: issuer pins seed 2, attesters seeds 3 and
    /// 4, the pinned approver seed 5 (`tenant-a-approver`).
    fn start(document: &str) -> Result<DelegationConfig, String> {
        let approvers = [approver("tenant-a-approver", 5)];
        parse_delegation_config(
            document,
            Some(&HashSet::from([TENANT_A, TENANT_B])),
            &OtherRoleKeys {
                approvers: &approvers,
                issuers: &[public(2)],
                attesters: &[public(3), public(4)],
            },
        )
        .map_err(|error| error.to_string())
    }

    #[test]
    fn a_root_per_tenant_with_its_own_key_starts() {
        let config = start(&roots(json!([
            {"tenant_id": TENANT_A, "key_id": "a-root", "public_key_hex": public_hex(10)},
            {"tenant_id": TENANT_B, "key_id": "b-root", "public_key_hex": public_hex(11)}
        ])))
        .unwrap();
        assert_eq!(config.root(TENANT_A).unwrap().key_id, "a-root");
        assert_eq!(config.root(TENANT_B).unwrap().key_id, "b-root");
    }

    #[test]
    fn the_root_cannot_be_a_pinned_approver() {
        let error = start(&one_root("a-root", 5)).unwrap_err();
        assert!(error.contains("pinned approver"), "{error}");
        // Nor share its key id.
        let error = start(&one_root("tenant-a-approver", 10)).unwrap_err();
        assert!(error.contains("pinned approver"), "{error}");
    }

    #[test]
    fn the_root_cannot_be_another_tenants_root() {
        let shared_key = roots(json!([
            {"tenant_id": TENANT_A, "key_id": "a-root", "public_key_hex": public_hex(10)},
            {"tenant_id": TENANT_B, "key_id": "b-root", "public_key_hex": public_hex(10)}
        ]));
        assert!(
            start(&shared_key)
                .unwrap_err()
                .contains("DELEGATION_ROOT_SHARED")
        );
        let shared_id = roots(json!([
            {"tenant_id": TENANT_A, "key_id": "root", "public_key_hex": public_hex(10)},
            {"tenant_id": TENANT_B, "key_id": "root", "public_key_hex": public_hex(11)}
        ]));
        assert!(
            start(&shared_id)
                .unwrap_err()
                .contains("DELEGATION_ROOT_SHARED")
        );
    }

    #[test]
    fn the_root_cannot_be_an_issuer_or_an_attester() {
        assert!(
            start(&one_root("a-root", 2))
                .unwrap_err()
                .contains("issuer")
        );
        assert!(
            start(&one_root("a-root", 3))
                .unwrap_err()
                .contains("attester")
        );
        assert!(
            start(&one_root("a-root", 4))
                .unwrap_err()
                .contains("attester")
        );
    }

    #[test]
    fn every_root_tenant_needs_an_issuer_binding_and_a_non_nil_id() {
        let unknown = roots(json!([
            {"tenant_id": Uuid::from_u128(3), "key_id": "c-root", "public_key_hex": public_hex(10)}
        ]));
        assert!(start(&unknown).unwrap_err().contains("issuer binding"));
        let nil = roots(json!([
            {"tenant_id": Uuid::nil(), "key_id": "root", "public_key_hex": public_hex(10)}
        ]));
        assert!(
            start(&nil)
                .unwrap_err()
                .contains("DELEGATION_DOCUMENT_INVALID")
        );
    }

    #[test]
    fn a_malformed_document_does_not_start() {
        let invalid = |document: &str| {
            let error = start(document).unwrap_err();
            assert!(
                error.contains("DELEGATION_DOCUMENT_INVALID"),
                "{error}: {document}"
            );
        };
        // Duplicate key.
        invalid(&format!(
            r#"{{"schema_version":1,"schema_version":1,"roots":[{{"tenant_id":"{TENANT_A}","key_id":"a-root","public_key_hex":"{}"}}]}}"#,
            public_hex(10)
        ));
        // Unknown fields, at the top and in a root.
        invalid(
            &json!({"schema_version": 1, "extra": true, "roots": [
                {"tenant_id": TENANT_A, "key_id": "a-root", "public_key_hex": public_hex(10)}
            ]})
            .to_string(),
        );
        invalid(&roots(json!([
            {"tenant_id": TENANT_A, "key_id": "a-root", "public_key_hex": public_hex(10), "role": "root"}
        ])));
        // Uppercase hex, wrong version, no roots.
        invalid(&roots(json!([
            {"tenant_id": TENANT_A, "key_id": "a-root", "public_key_hex": public_hex(10).to_uppercase()}
        ])));
        invalid(&json!({"schema_version": 2, "roots": [{"tenant_id": TENANT_A, "key_id": "a", "public_key_hex": public_hex(10)}]}).to_string());
        invalid(&roots(json!([])));
        // Over the size limit.
        let mut oversized = one_root("a-root", 10);
        oversized.push_str(
            &" ".repeat(praetore_core::approval_delegation::MAX_DELEGATION_DOCUMENT_BYTES),
        );
        invalid(&oversized);
    }
}
