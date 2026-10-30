//! Per-tenant human-approver key bindings.
//!
//! Mirrors the tenant issuer binding file: an approver key verifies
//! decisions only for the tenant it is bound to, and a public key or key id
//! is assigned to exactly one tenant.
//!
//! ```json
//! {"schema_version":1,"tenants":[
//!   {"tenant_id":"<uuid>","approvers":[{"key_id":"tenant-a-alice","public_key_hex":"<64 hex>"}]}
//! ]}
//! ```

use praetore_core::{VerifiedPublicKey, canonical::parse_json_rejecting_duplicates};
use praetore_gateway::HumanApprovalVerifier;
use serde::Deserialize;
use std::collections::HashSet;
use uuid::Uuid;

const MAX_DOCUMENT_BYTES: usize = 1_048_576;
const MAX_TENANTS: usize = 4096;
const MAX_APPROVERS_PER_TENANT: usize = 16;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproverBindingsFile {
    schema_version: u8,
    tenants: Vec<TenantApprovers>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantApprovers {
    tenant_id: Uuid,
    approvers: Vec<ApproverKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproverKey {
    key_id: String,
    public_key_hex: String,
}

/// Parses the binding file into tenant-scoped verifiers. When
/// `issuer_tenants` is given, every approver tenant must also be an
/// issuer-bound tenant of this gateway.
pub fn parse_approver_bindings(
    document: &str,
    issuer_tenants: Option<&HashSet<Uuid>>,
) -> Result<Vec<HumanApprovalVerifier>, Box<dyn std::error::Error>> {
    if document.len() > MAX_DOCUMENT_BYTES {
        return Err("approver binding configuration exceeds the size limit".into());
    }
    let value = parse_json_rejecting_duplicates(document)?;
    let bindings: ApproverBindingsFile = serde_json::from_value(value)?;
    if bindings.schema_version != 1
        || bindings.tenants.is_empty()
        || bindings.tenants.len() > MAX_TENANTS
    {
        return Err("approver binding configuration has an unsupported version or size".into());
    }

    let mut tenants = HashSet::with_capacity(bindings.tenants.len());
    let mut key_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    let mut verifiers = Vec::new();
    for binding in bindings.tenants {
        if binding.tenant_id.is_nil()
            || binding.approvers.is_empty()
            || binding.approvers.len() > MAX_APPROVERS_PER_TENANT
        {
            return Err("approver binding contains an invalid tenant or approver list".into());
        }
        if !tenants.insert(binding.tenant_id) {
            return Err("approver binding contains a duplicate tenant id".into());
        }
        if issuer_tenants.is_some_and(|issuer_tenants| !issuer_tenants.contains(&binding.tenant_id))
        {
            return Err("approver binding names a tenant without an issuer binding".into());
        }
        for approver in binding.approvers {
            let canonical_hex = hex::decode(&approver.public_key_hex)
                .ok()
                .filter(|bytes| bytes.len() == 32 && hex::encode(bytes) == approver.public_key_hex)
                .ok_or("approver public keys must be 32-byte canonical lowercase hex")?;
            if !key_ids.insert(approver.key_id.clone())
                || !public_keys.insert(approver.public_key_hex.clone())
            {
                return Err(
                    "approver key ids and public keys must be assigned to exactly one tenant"
                        .into(),
                );
            }
            let public_key = VerifiedPublicKey::from_bytes(&canonical_hex)?;
            verifiers.push(HumanApprovalVerifier::for_tenant(
                binding.tenant_id,
                approver.key_id,
                public_key,
            )?);
        }
    }
    Ok(verifiers)
}

/// A single approver key configured through environment variables. It is
/// unscoped only for the single-tenant local demo; a production adapter
/// accepts it only when exactly one tenant is issuer-bound, and then binds
/// it to that tenant.
pub fn single_approver(
    key_id: &str,
    public_key_hex: &str,
    issuer_tenants: Option<&HashSet<Uuid>>,
) -> Result<HumanApprovalVerifier, Box<dyn std::error::Error>> {
    let public_key = VerifiedPublicKey::from_bytes(&hex::decode(public_key_hex)?)?;
    match issuer_tenants {
        None => Ok(HumanApprovalVerifier::new(key_id, public_key)?),
        Some(tenants) if tenants.len() == 1 => {
            let tenant = *tenants.iter().next().expect("one tenant");
            Ok(HumanApprovalVerifier::for_tenant(
                tenant, key_id, public_key,
            )?)
        }
        Some(_) => Err(
            "a multi-tenant gateway requires PRAETORE_GATEWAY_APPROVER_BINDINGS_FILE; a single approver key would approve for every tenant"
                .into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn public_hex(seed: u8) -> String {
        hex::encode(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    fn document(tenants: serde_json::Value) -> String {
        serde_json::json!({"schema_version": 1, "tenants": tenants}).to_string()
    }

    #[test]
    fn bindings_produce_tenant_scoped_verifiers() {
        let tenant_a = Uuid::from_u128(1);
        let tenant_b = Uuid::from_u128(2);
        let verifiers = parse_approver_bindings(
            &document(serde_json::json!([
                {"tenant_id": tenant_a, "approvers": [{"key_id": "a-alice", "public_key_hex": public_hex(1)}]},
                {"tenant_id": tenant_b, "approvers": [{"key_id": "b-bob", "public_key_hex": public_hex(2)}]}
            ])),
            Some(&HashSet::from([tenant_a, tenant_b])),
        )
        .unwrap();
        assert_eq!(verifiers.len(), 2);
        assert_eq!(verifiers[0].tenant_id(), Some(tenant_a));
        assert_eq!(verifiers[1].tenant_id(), Some(tenant_b));
    }

    #[test]
    fn bindings_reject_shared_keys_duplicate_tenants_and_unknown_tenants() {
        let tenant_a = Uuid::from_u128(1);
        let tenant_b = Uuid::from_u128(2);
        let both = HashSet::from([tenant_a, tenant_b]);
        let shared_key = document(serde_json::json!([
            {"tenant_id": tenant_a, "approvers": [{"key_id": "a", "public_key_hex": public_hex(1)}]},
            {"tenant_id": tenant_b, "approvers": [{"key_id": "b", "public_key_hex": public_hex(1)}]}
        ]));
        assert!(parse_approver_bindings(&shared_key, Some(&both)).is_err());
        let shared_id = document(serde_json::json!([
            {"tenant_id": tenant_a, "approvers": [{"key_id": "a", "public_key_hex": public_hex(1)}]},
            {"tenant_id": tenant_b, "approvers": [{"key_id": "a", "public_key_hex": public_hex(2)}]}
        ]));
        assert!(parse_approver_bindings(&shared_id, Some(&both)).is_err());
        let duplicate_tenant = document(serde_json::json!([
            {"tenant_id": tenant_a, "approvers": [{"key_id": "a", "public_key_hex": public_hex(1)}]},
            {"tenant_id": tenant_a, "approvers": [{"key_id": "b", "public_key_hex": public_hex(2)}]}
        ]));
        assert!(parse_approver_bindings(&duplicate_tenant, Some(&both)).is_err());
        let unknown_tenant = document(serde_json::json!([
            {"tenant_id": Uuid::from_u128(3), "approvers": [{"key_id": "a", "public_key_hex": public_hex(1)}]}
        ]));
        assert!(parse_approver_bindings(&unknown_tenant, Some(&both)).is_err());
        let nil_tenant = document(serde_json::json!([
            {"tenant_id": Uuid::nil(), "approvers": [{"key_id": "a", "public_key_hex": public_hex(1)}]}
        ]));
        assert!(parse_approver_bindings(&nil_tenant, None).is_err());
        let uppercase = document(serde_json::json!([
            {"tenant_id": tenant_a, "approvers": [{"key_id": "a", "public_key_hex": public_hex(1).to_uppercase()}]}
        ]));
        assert!(parse_approver_bindings(&uppercase, None).is_err());
        let empty = document(serde_json::json!([{"tenant_id": tenant_a, "approvers": []}]));
        assert!(parse_approver_bindings(&empty, None).is_err());
    }

    #[test]
    fn single_approver_key_is_unscoped_only_without_tenant_bindings() {
        let tenant_a = Uuid::from_u128(1);
        let unscoped = single_approver("demo", &public_hex(1), None).unwrap();
        assert_eq!(unscoped.tenant_id(), None);
        let scoped =
            single_approver("demo", &public_hex(1), Some(&HashSet::from([tenant_a]))).unwrap();
        assert_eq!(scoped.tenant_id(), Some(tenant_a));
        assert!(
            single_approver(
                "demo",
                &public_hex(1),
                Some(&HashSet::from([tenant_a, Uuid::from_u128(2)]))
            )
            .is_err()
        );
    }
}
