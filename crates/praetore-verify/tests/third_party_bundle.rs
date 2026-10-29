//! Runs the committed DEMO bundle in `examples/third-party-verification/`
//! through the `praetore-verify` binary, like `verify.sh` does.

use serde_json::Value;
use std::{fs, path::PathBuf, process::Command};

fn bundle(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/third-party-verification/bundle")
        .join(name)
}

fn verify_evidence(evidence: &PathBuf) -> (bool, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .arg("evidence")
        .arg("--evidence")
        .arg(evidence)
        .arg("--attester-pin")
        .arg(bundle("attester-public-key.hex"))
        .arg("--issuer-pins")
        .arg(bundle("issuer-pins.jsonl"))
        .args(["--require-intent", "--format", "json"])
        .output()
        .unwrap();
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

#[test]
fn demo_bundle_verifies_and_one_byte_change_is_rejected() {
    let (ok, summary) = verify_evidence(&bundle("evidence.json"));
    assert!(ok, "{summary}");
    assert_eq!(summary["details"]["intent_verified"], true);
    assert_eq!(summary["details"]["authority_verified"], true);

    let mut bytes = fs::read(bundle("evidence.json")).unwrap();
    let offset = bytes
        .windows(b"DEMO allow".len())
        .position(|window| window == b"DEMO allow")
        .unwrap()
        + "DEMO ".len();
    bytes[offset] = b'A';
    let tampered = std::env::temp_dir().join(format!(
        "praetore-third-party-tampered-{}.json",
        std::process::id()
    ));
    fs::write(&tampered, bytes).unwrap();
    let (ok, summary) = verify_evidence(&tampered);
    let _ = fs::remove_file(&tampered);
    assert!(!ok);
    assert_eq!(summary["code"], "EVIDENCE_FAIL");
}

#[test]
fn demo_bundle_policy_digest_matches_the_bound_digest() {
    let output = Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .arg("policy-digest")
        .arg("--policy")
        .arg(bundle("policy.json"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    let evidence: Value =
        serde_json::from_str(&fs::read_to_string(bundle("evidence.json")).unwrap()).unwrap();
    assert_eq!(summary["details"]["digest"], evidence["policy_digest"]);
}
