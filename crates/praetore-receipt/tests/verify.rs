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

fn evidence_key() -> VerifiedPublicKey {
    VerifiedPublicKey::from_bytes(
        &hex::decode(fixture("receipt-evidence-attester-public-key.hex").trim()).unwrap(),
    )
    .unwrap()
}

fn verify(json: &str) -> Result<u8, ExecutionAttestationError> {
    verify_gateway_receipt_json(json, &key(), KEY_ID, &evidence_key())
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

const FIXTURES: [&str; 3] = [
    "receipt-v1-confirmed.json",
    "receipt-v2-confirmed.json",
    "receipt-v3-crash-recovered.json",
];

fn with_attestation(json: &str, edit: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
    edit(&mut value["execution_attestation"]);
    serde_json::to_string(&value).unwrap()
}

fn signature(json: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    value["execution_attestation"]["signature"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn with_signature(json: &str, signature: String) -> String {
    with_attestation(json, |attestation| {
        attestation["signature"] = signature.into();
    })
}

#[test]
fn rejects_every_single_bit_flip_in_the_signature() {
    for name in FIXTURES {
        let original = fixture(name);
        let bytes = hex::decode(signature(&original)).unwrap();
        for bit in 0..bytes.len() * 8 {
            let mut flipped = bytes.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                verify(&with_signature(&original, hex::encode(flipped))),
                Err(ExecutionAttestationError::InvalidSignature),
                "{name}: bit {bit}"
            );
        }
    }
}

#[test]
fn rejects_any_single_hex_char_change_in_the_signature() {
    for name in FIXTURES {
        let original = fixture(name);
        let sig = signature(&original);
        for index in 0..sig.len() {
            let mut chars: Vec<char> = sig.chars().collect();
            chars[index] = if chars[index] == '0' { '1' } else { '0' };
            let altered: String = chars.into_iter().collect();
            assert!(
                verify(&with_signature(&original, altered)).is_err(),
                "{name}: char {index}"
            );
        }
    }
}

#[test]
fn rejects_uppercase_and_mixed_case_signatures() {
    for name in FIXTURES {
        let original = fixture(name);
        let sig = signature(&original);
        assert!(
            sig.bytes().any(|b| b.is_ascii_lowercase()),
            "{name}: needs a-f"
        );
        let upper = sig.to_ascii_uppercase();
        assert_eq!(
            verify(&with_signature(&original, upper)),
            Err(ExecutionAttestationError::InvalidPayload),
            "{name}: uppercase"
        );
        let first_letter = sig.find(|c: char| c.is_ascii_lowercase()).unwrap();
        let mut mixed = sig.clone();
        mixed.replace_range(
            first_letter..=first_letter,
            &sig[first_letter..=first_letter].to_ascii_uppercase(),
        );
        assert_eq!(
            verify(&with_signature(&original, mixed)),
            Err(ExecutionAttestationError::InvalidPayload),
            "{name}: one uppercase char"
        );
        // Lowercase original still verifies after the same JSON round trip.
        assert!(verify(&with_signature(&original, sig)).is_ok(), "{name}");
    }
}

#[test]
fn rejects_truncated_extended_or_empty_signatures() {
    let original = fixture("receipt-v2-confirmed.json");
    let sig = signature(&original);
    for altered in [String::new(), sig[..126].to_owned(), format!("{sig}00")] {
        assert_eq!(
            verify(&with_signature(&original, altered)),
            Err(ExecutionAttestationError::InvalidPayload)
        );
    }
}

#[test]
fn rejects_a_different_public_key() {
    // A valid Ed25519 key that did not sign these receipts.
    let other = VerifiedPublicKey::from_bytes(
        &hex::decode(fixture("attester-public-key.hex").trim()).unwrap(),
    )
    .unwrap();
    assert_ne!(other.as_bytes(), key().as_bytes());
    for name in FIXTURES {
        assert_eq!(
            verify_gateway_receipt_json(&fixture(name), &other, KEY_ID, &evidence_key())
                .map(|_| ()),
            Err(ExecutionAttestationError::InvalidSignature),
            "{name}"
        );
        assert_eq!(
            verify_gateway_receipt_json(&fixture(name), &key(), "other-key-id", &evidence_key())
                .map(|_| ()),
            Err(ExecutionAttestationError::KeyMismatch),
            "{name}"
        );
    }
}

#[test]
fn rejects_a_relabelled_schema_version() {
    for name in FIXTURES {
        let original = fixture(name);
        let current = verify(&original).unwrap();
        for version in [0u8, 1, 2, 3, 4, 255] {
            if version == current {
                continue;
            }
            let relabelled = with_attestation(&original, |attestation| {
                attestation["schema_version"] = version.into();
            });
            assert!(verify(&relabelled).is_err(), "{name} as v{version}");
        }
    }
}

#[test]
fn rejects_v2_relabelled_as_v1_even_without_tenant() {
    // Strip the v2-only field so the shape matches v1: only the signature
    // can catch the downgrade.
    let downgraded = with_attestation(&fixture("receipt-v2-confirmed.json"), |attestation| {
        attestation["schema_version"] = 1.into();
        attestation.as_object_mut().unwrap().remove("tenant_id");
    });
    assert_eq!(
        verify(&downgraded),
        Err(ExecutionAttestationError::InvalidSignature)
    );
}

fn with_evidence_signature(json: &str, signature: serde_json::Value) -> String {
    let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
    value["evidence"]["attester_signature"] = signature;
    serde_json::to_string(&value).unwrap()
}

fn evidence_signature(json: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    value["evidence"]["attester_signature"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn rejects_an_altered_evidence_attester_signature() {
    for name in FIXTURES {
        let original = fixture(name);
        let bytes = hex::decode(evidence_signature(&original)).unwrap();
        for bit in [0, 7, 255, 511] {
            let mut flipped = bytes.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                verify(&with_evidence_signature(
                    &original,
                    hex::encode(flipped).into()
                )),
                Err(ExecutionAttestationError::InvalidEvidenceSignature),
                "{name}: bit {bit}"
            );
        }
        for forged in ["0".repeat(128), "not-hex".into(), String::new()] {
            assert_eq!(
                verify(&with_evidence_signature(&original, forged.clone().into())),
                Err(ExecutionAttestationError::InvalidEvidenceSignature),
                "{name}: {forged:?}"
            );
        }
    }
}

#[test]
fn rejects_a_missing_evidence_attester_signature() {
    for name in FIXTURES {
        let original = fixture(name);
        assert_eq!(
            verify(&with_evidence_signature(&original, serde_json::Value::Null)),
            Err(ExecutionAttestationError::InvalidEvidenceSignature),
            "{name}: null"
        );
        let mut value: serde_json::Value = serde_json::from_str(&original).unwrap();
        value["evidence"]
            .as_object_mut()
            .unwrap()
            .remove("attester_signature");
        assert!(
            verify(&serde_json::to_string(&value).unwrap()).is_err(),
            "{name}: field removed"
        );
    }
}

#[test]
fn rejects_evidence_signed_by_another_attester_key() {
    // A valid Ed25519 key that did not sign this evidence.
    let other = VerifiedPublicKey::from_bytes(
        &hex::decode(fixture("attester-public-key.hex").trim()).unwrap(),
    )
    .unwrap();
    assert_ne!(other.as_bytes(), evidence_key().as_bytes());
    for name in FIXTURES {
        assert_eq!(
            verify_gateway_receipt_json(&fixture(name), &key(), KEY_ID, &other).map(|_| ()),
            Err(ExecutionAttestationError::InvalidEvidenceSignature),
            "{name}"
        );
        // Nor does the execution key double as the evidence attester key.
        assert_eq!(
            verify_gateway_receipt_json(&fixture(name), &key(), KEY_ID, &key()).map(|_| ()),
            Err(ExecutionAttestationError::InvalidEvidenceSignature),
            "{name}"
        );
    }
}
