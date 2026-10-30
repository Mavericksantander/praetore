//! Parsing rules of `verify_gateway_receipt_json`, using the committed
//! fixtures shared with the external verifiers.

use praetore_core::VerifiedPublicKey;
use praetore_receipt::{ExecutionAttestationError, verify_gateway_receipt_json};
use std::path::Path;

const KEY_ID: &str = "test-execution-attester-v1";

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages/praetore-python/tests/fixtures")
            .join(name),
    )
    .unwrap()
}

fn key() -> VerifiedPublicKey {
    VerifiedPublicKey::from_bytes(
        &hex::decode(fixture("execution-attester-public-key.hex").trim()).unwrap(),
    )
    .unwrap()
}

fn verify(json: &str) -> Result<u8, ExecutionAttestationError> {
    verify_gateway_receipt_json(json, &key(), KEY_ID)
        .map(|receipt| receipt.execution_attestation.schema_version)
}

#[test]
fn accepts_v1_v2_and_v3() {
    assert_eq!(verify(&fixture("receipt-v1-confirmed.json")), Ok(1));
    assert_eq!(verify(&fixture("receipt-v2-confirmed.json")), Ok(2));
    assert_eq!(verify(&fixture("receipt-v3-crash-recovered.json")), Ok(3));
}

#[test]
fn rejects_duplicate_keys_unknown_fields_and_unknown_reasons() {
    let v3 = fixture("receipt-v3-crash-recovered.json");
    let duplicate = v3.replacen('{', "{\"output\":null,", 1);
    assert_ne!(duplicate, v3);
    assert_eq!(
        verify(&duplicate),
        Err(ExecutionAttestationError::InvalidPayload)
    );
    let unknown_field = v3.replacen('{', "{\"extra\":1,", 1);
    assert_eq!(
        verify(&unknown_field),
        Err(ExecutionAttestationError::InvalidPayload)
    );
    let unknown_reason = v3.replace("\"crash_recovered\"", "\"operator_override\"");
    assert_ne!(unknown_reason, v3);
    assert_eq!(
        verify(&unknown_reason),
        Err(ExecutionAttestationError::InvalidPayload)
    );
}
