//! SAF-11: `praetore-verify evidence` accepts the `ed25519-sha256-envelope`
//! attester algorithm, using the committed golden vector, and never accepts
//! an envelope signature as a legacy one or the reverse.

use praetore_core::{Evidence, EvidenceAttesterKey, SignatureAlgorithm};
use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

const GOLDEN: &str = include_str!("../../../docs/golden/evidence-envelope-v1.json");
/// Signed with `"ed25519"` by an older praetore-core (attester `[3; 32]`).
const LEGACY: &str = include_str!("fixtures/legacy-evidence-no-policy-digest.json");

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "praetore-verify-envelope-{}-{}",
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

fn verify(evidence: &str, pin: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .args([
            "evidence",
            "--evidence",
            evidence,
            "--attester-pin",
            pin,
            "--format",
            "json",
        ])
        .output()
        .unwrap()
}

fn summary(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn golden() -> Value {
    serde_json::from_str(GOLDEN).unwrap()
}

/// Changes `attester_algorithm` and recomputes the unkeyed context hash, so
/// only the signature can catch the change.
fn relabel(json: &str, algorithm: &str) -> String {
    let mut evidence = Evidence::from_json(json).unwrap();
    evidence.attester_algorithm = Some(algorithm.into());
    let digest = evidence.policy_digest.clone().unwrap();
    evidence.bind_policy_digest(digest).unwrap();
    assert!(evidence.verify_integrity());
    evidence.to_json().unwrap()
}

#[test]
fn golden_envelope_receipt_verifies() {
    let golden = golden();
    let dir = Dir::new();
    let evidence = dir.write("e.json", golden["evidence_json"].as_str().unwrap());
    let pin = dir.write(
        "pin.hex",
        format!("{}\n", golden["attester_public_key_hex"].as_str().unwrap()),
    );
    let output = verify(&evidence, &pin);
    assert!(output.status.success(), "{}", summary(&output));
    let summary = summary(&output);
    assert_eq!(summary["code"], "OK");
    assert_eq!(
        summary["details"]["attester_algorithm"],
        "ed25519-sha256-envelope"
    );
}

#[test]
fn envelope_signature_relabelled_as_legacy_fails() {
    let golden = golden();
    let dir = Dir::new();
    let evidence = dir.write(
        "e.json",
        relabel(golden["evidence_json"].as_str().unwrap(), "ed25519"),
    );
    let pin = dir.write(
        "pin.hex",
        golden["attester_public_key_hex"].as_str().unwrap(),
    );
    let output = verify(&evidence, &pin);
    assert!(!output.status.success());
    assert_eq!(summary(&output)["code"], "AUTH_FAIL");
}

#[test]
fn legacy_receipt_still_verifies_and_fails_when_relabelled_as_envelope() {
    let dir = Dir::new();
    let key = EvidenceAttesterKey::from_secret_bytes(&[3; 32]);
    let pin = dir.write("pin.hex", hex::encode(key.public_key().unwrap().as_bytes()));
    let legacy = dir.write("legacy.json", LEGACY);
    let output = verify(&legacy, &pin);
    assert!(output.status.success(), "{}", summary(&output));
    assert_eq!(summary(&output)["details"]["attester_algorithm"], "ed25519");

    // A legacy signature from the golden envelope evidence's key, relabelled
    // as an envelope one.
    let mut fresh = Evidence::from_json(golden()["evidence_json"].as_str().unwrap()).unwrap();
    fresh.sign(&key).unwrap();
    assert_eq!(
        fresh.attester_algorithm.as_deref(),
        Some(SignatureAlgorithm::ED25519)
    );
    let fresh_json = fresh.to_json().unwrap();
    let output = verify(&dir.write("fresh.json", &fresh_json), &pin);
    assert!(output.status.success(), "{}", summary(&output));
    let relabelled = dir.write(
        "relabelled.json",
        relabel(&fresh_json, SignatureAlgorithm::ED25519_SHA256_ENVELOPE),
    );
    let output = verify(&relabelled, &pin);
    assert!(!output.status.success());
    assert_eq!(summary(&output)["code"], "AUTH_FAIL");
}
