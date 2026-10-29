use praetore_core::{evidence::Evidence, identity::VerifiedPublicKey};
use pyo3::prelude::*;

#[pyfunction]
fn verify_evidence_integrity(evidence_json: &str) -> bool {
    Evidence::from_json(evidence_json).is_ok_and(|evidence| evidence.verify_integrity())
}

#[pyfunction]
fn verify_evidence_attester_signature(evidence_json: &str, attester_public_key_hex: &str) -> bool {
    let Ok(evidence) = Evidence::from_json(evidence_json) else {
        return false;
    };
    if attester_public_key_hex.len() != 64
        || attester_public_key_hex
            .bytes()
            .any(|byte| byte.is_ascii_uppercase())
    {
        return false;
    }
    let Ok(public_key_bytes) = hex::decode(attester_public_key_hex) else {
        return false;
    };
    let Ok(public_key) = VerifiedPublicKey::from_bytes(&public_key_bytes) else {
        return false;
    };
    evidence.verify_attester_signature(&public_key).is_ok()
}

/// Verifies a serialized gateway receipt's execution attestation (schema v1,
/// v2 or v3) against a pinned key. Unknown `not_dispatched_reason` values,
/// unknown fields and bad signatures return `false`. Historical only.
#[pyfunction]
fn verify_gateway_receipt(
    receipt_json: &str,
    execution_public_key_hex: &str,
    key_id: &str,
) -> bool {
    let Some(public_key) = parse_public_key(execution_public_key_hex) else {
        return false;
    };
    praetore_gateway::verify_gateway_receipt_json(receipt_json, &public_key, key_id).is_ok()
}

fn parse_public_key(hex_value: &str) -> Option<VerifiedPublicKey> {
    if hex_value.len() != 64 || hex_value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    VerifiedPublicKey::from_bytes(&hex::decode(hex_value).ok()?).ok()
}

#[pymodule]
fn _core(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(verify_evidence_integrity, module)?)?;
    module.add_function(wrap_pyfunction!(verify_gateway_receipt, module)?)?;
    module.add_function(wrap_pyfunction!(
        verify_evidence_attester_signature,
        module
    )?)?;
    Ok(())
}
