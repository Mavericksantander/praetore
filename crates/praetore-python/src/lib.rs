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

#[pymodule]
fn _core(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(verify_evidence_integrity, module)?)?;
    module.add_function(wrap_pyfunction!(
        verify_evidence_attester_signature,
        module
    )?)?;
    Ok(())
}
