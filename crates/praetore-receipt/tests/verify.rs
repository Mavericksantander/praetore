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
            // Still 128 lowercase hex digits, so it passes the encoding
            // check and must be rejected by the signature itself.
            assert_eq!(
                verify(&with_signature(&original, altered)),
                Err(ExecutionAttestationError::InvalidSignature),
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
    for name in FIXTURES {
        let original = fixture(name);
        let sig = signature(&original);
        for altered in [
            String::new(),
            sig[..2].to_owned(),
            sig[..126].to_owned(),
            sig[..127].to_owned(),
            format!("{sig}00"),
        ] {
            let len = altered.len();
            assert_eq!(
                verify(&with_signature(&original, altered)),
                Err(ExecutionAttestationError::InvalidPayload),
                "{name}: length {len}"
            );
        }
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
            verify_gateway_receipt_json(&fixture(name), &other, KEY_ID).map(|_| ()),
            Err(ExecutionAttestationError::InvalidSignature),
            "{name}"
        );
        assert_eq!(
            verify_gateway_receipt_json(&fixture(name), &key(), "other-key-id").map(|_| ()),
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
            // The (schema_version, tenant_id, not_dispatched_reason) shape
            // no longer matches, so this fails before the signature check.
            assert_eq!(
                verify(&relabelled),
                Err(ExecutionAttestationError::InvalidPayload),
                "{name} as v{version}"
            );
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
