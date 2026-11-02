//! G2: `praetore-verify safety-manifest` verifies a safety namespace
//! manifest against a pinned namespace key and, with `--policy`, against the
//! policy it was derived from.

use praetore_core::{
    ActionClass, EvidenceAttesterKey, Policy, SafetyNamespaceKey, SafetyNamespaceManifest,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};
use time::OffsetDateTime;

const GOLDEN: &str = include_str!("../../../docs/golden/safety-namespace-manifest-v1.json");
const GOLDEN_POLICY: &str = include_str!("../../../docs/golden/canonical-policy-v2.json");

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "praetore-verify-safety-manifest-{}-{}",
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

/// `value` as a manifest file: canonical JSON and one newline, so the check
/// under test, not the encoding, rejects it.
fn canonical_file(value: &Value) -> String {
    let bytes = praetore_core::canonical::canonicalize_json(&value.to_string()).unwrap();
    String::from_utf8(bytes).unwrap() + "\n"
}

fn golden() -> Value {
    serde_json::from_str(GOLDEN).unwrap()
}

/// The golden manifest, its pin and its policy, as files.
fn golden_files(dir: &Dir) -> (String, String, String) {
    let golden = golden();
    (
        dir.write(
            "manifest.json",
            format!("{}\n", golden["manifest"].as_str().unwrap()),
        ),
        dir.write(
            "namespace.pin",
            format!("{}\n", golden["namespace_public_key_hex"].as_str().unwrap()),
        ),
        dir.write("policy.json", GOLDEN_POLICY),
    )
}

fn verify(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .arg("safety-manifest")
        .args(args)
        .output()
        .unwrap()
}

fn verify_json(manifest: &str, pin: &str, policy: Option<&str>) -> Output {
    let mut args = vec!["--manifest", manifest, "--pin", pin];
    if let Some(policy) = policy {
        args.extend(["--policy", policy]);
    }
    args.extend(["--format", "json"]);
    verify(&args)
}

fn summary(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_fails(output: &Output, code: &str) {
    assert!(!output.status.success(), "expected {code}: {output:?}");
    assert_eq!(summary(output)["code"], code, "{output:?}");
}

#[test]
fn the_golden_manifest_verifies_with_and_without_its_policy() {
    let dir = Dir::new();
    let (manifest, pin, policy) = golden_files(&dir);

    let output = verify_json(&manifest, &pin, Some(&policy));
    assert!(output.status.success(), "{output:?}");
    let summary = summary(&output);
    assert_eq!(summary["command"], "safety-manifest");
    assert_eq!(summary["code"], "OK");
    let details = &summary["details"];
    assert_eq!(details["policy_id"], "golden");
    assert_eq!(details["policy_version"], 1);
    assert_eq!(
        details["policy_digest"],
        "77821c2735152448004f6780288dbb793bc1a78c204c5d0e460e859e89753cd0"
    );
    assert_eq!(details["safety_actions"], json!(["safety:halt"]));
    assert_eq!(details["signature_verified"], true);
    assert_eq!(details["policy_verified"], true);
    assert_eq!(details["current_authorization"], false);
    assert_eq!(
        details["verification_scope"],
        "safety_namespace_at_policy_digest"
    );

    let output = verify_json(&manifest, &pin, None);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(self::summary(&output)["details"]["policy_verified"], false);
}

#[test]
fn text_output_is_one_escaped_line() {
    let dir = Dir::new();
    let (manifest, pin, policy) = golden_files(&dir);
    let output = verify(&["--manifest", &manifest, "--pin", &pin, "--policy", &policy]);
    assert!(output.status.success(), "{output:?}");
    let line = String::from_utf8(output.stdout).unwrap();
    assert!(line.starts_with("OK safety-manifest OK "), "{line}");
    assert!(line.contains(" safety_actions=[\"safety:halt\"]"), "{line}");
    assert!(line.contains(" policy_verified=true"), "{line}");
    assert!(line.contains(" current_authorization=false"), "{line}");

    // A policy id with an invisible character is escaped in text output and
    // exact in JSON output.
    let key = SafetyNamespaceKey::from_secret_bytes(&[0x61; 32]);
    let policy = Policy::new_v2("ops\u{200b}", 1, vec![])
        .with_action_class("safety:hold", ActionClass::Safety);
    let built = SafetyNamespaceManifest::from_policy(
        &policy,
        OffsetDateTime::from_unix_timestamp(1_793_491_200).unwrap(),
        &key,
    )
    .unwrap();
    let manifest = dir.write("invisible.json", built.to_file().unwrap());
    let pin = dir.write(
        "invisible.pin",
        hex::encode(key.public_key().unwrap().as_bytes()),
    );
    let text = verify(&["--manifest", &manifest, "--pin", &pin]);
    assert!(text.status.success(), "{text:?}");
    let line = String::from_utf8(text.stdout).unwrap();
    assert!(line.contains("policy_id=\"ops\\u{200b}\""), "{line}");
    assert!(!line.contains('\u{200b}'));
    let json = verify_json(&manifest, &pin, None);
    assert_eq!(summary(&json)["details"]["policy_id"], "ops\u{200b}");
}

#[test]
fn a_wrong_pin_or_a_tampered_manifest_fails() {
    let dir = Dir::new();
    let (manifest, pin, policy) = golden_files(&dir);

    let other = dir.write(
        "other.pin",
        hex::encode(
            SafetyNamespaceKey::from_secret_bytes(&[0x62; 32])
                .public_key()
                .unwrap()
                .as_bytes(),
        ),
    );
    assert_fails(
        &verify_json(&manifest, &other, Some(&policy)),
        "SAFETY_MANIFEST_KEY_MISMATCH",
    );

    let original: Value = serde_json::from_str(golden()["manifest"].as_str().unwrap()).unwrap();
    let tampered = |name: &str, edit: &dyn Fn(&mut Value)| {
        let mut value = original.clone();
        edit(&mut value);
        dir.write(name, canonical_file(&value))
    };
    let added = tampered("added.json", &|v| {
        v["safety_actions"] = json!(["safety:halt", "safety:hold"])
    });
    assert_fails(
        &verify_json(&added, &pin, None),
        "SAFETY_MANIFEST_SIGNATURE_INVALID",
    );
    let digest = tampered("digest.json", &|v| {
        v["policy_digest"] = json!("ab".repeat(32))
    });
    assert_fails(
        &verify_json(&digest, &pin, None),
        "SAFETY_MANIFEST_SIGNATURE_INVALID",
    );
    let reordered = tampered("reordered.json", &|v| {
        v["safety_actions"] = json!(["safety:stop_all", "safety:halt"])
    });
    let output = verify_json(&reordered, &pin, None);
    assert_fails(&output, "SAFETY_MANIFEST_INVALID");
    assert!(String::from_utf8_lossy(&output.stderr).contains("sorted by byte value"));
    let version = tampered("version.json", &|v| v["schema_version"] = json!(2));
    assert_fails(
        &verify_json(&version, &pin, None),
        "SAFETY_MANIFEST_VERSION_UNSUPPORTED",
    );
    let unknown = tampered("unknown.json", &|v| v["extra"] = json!(true));
    assert_fails(
        &verify_json(&unknown, &pin, None),
        "SAFETY_MANIFEST_INVALID",
    );
}

#[test]
fn a_manifest_of_another_policy_version_fails_with_the_policy() {
    let dir = Dir::new();
    let (manifest, pin, _) = golden_files(&dir);
    let mut next: Value = serde_json::from_str(GOLDEN_POLICY).unwrap();
    next["version"] = json!(2);
    let next = dir.write("next.json", next.to_string());
    let output = verify_json(&manifest, &pin, Some(&next));
    assert_fails(&output, "POLICY_MISMATCH");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("policy_version differs"),
        "{output:?}"
    );

    let mut extra: Value = serde_json::from_str(GOLDEN_POLICY).unwrap();
    extra["action_classes"]["safety:hold"] = json!("Safety");
    let extra = dir.write("extra.json", extra.to_string());
    assert_fails(
        &verify_json(&manifest, &pin, Some(&extra)),
        "POLICY_MISMATCH",
    );

    // A format 1 policy cannot be matched.
    let v1 = dir.write(
        "v1.json",
        include_str!("../../../docs/golden/canonical-policy-v1.json"),
    );
    assert_fails(
        &verify_json(&manifest, &pin, Some(&v1)),
        "POLICY_EVALUATION_FAIL",
    );
}

/// A receipt pin is not a namespace pin: the same public key in the
/// attester role has another key id, and its signatures do not verify.
#[test]
fn the_attester_key_cannot_stand_in_for_the_namespace_key() {
    let dir = Dir::new();
    let secret = [0x47; 32]; // the golden namespace secret
    let attester = EvidenceAttesterKey::from_secret_bytes(&secret);
    let golden = golden();
    assert_eq!(
        hex::encode(attester.public_key().unwrap().as_bytes()),
        golden["namespace_public_key_hex"].as_str().unwrap()
    );
    assert_ne!(attester.key_id(), golden["key_id"].as_str().unwrap());
    let mut value: Value = serde_json::from_str(golden["manifest"].as_str().unwrap()).unwrap();
    value["key_id"] = json!(attester.key_id());
    let manifest = dir.write("attester-id.json", canonical_file(&value));
    let pin = dir.write("pin", golden["namespace_public_key_hex"].as_str().unwrap());
    assert_fails(
        &verify_json(&manifest, &pin, None),
        "SAFETY_MANIFEST_KEY_MISMATCH",
    );
}

/// One manifest, one file: the canonical document and exactly one newline.
#[test]
fn only_the_canonical_file_is_accepted() {
    let dir = Dir::new();
    let (_, pin, _) = golden_files(&dir);
    let document = golden()["manifest"].as_str().unwrap().to_owned();
    let value: Value = serde_json::from_str(&document).unwrap();
    for (name, text) in [
        ("no-newline.json", document.clone()),
        ("two-newlines.json", format!("{document}\n\n")),
        ("crlf.json", format!("{document}\r\n")),
        (
            "pretty.json",
            serde_json::to_string_pretty(&value).unwrap() + "\n",
        ),
        (
            "escaped.json",
            document.replacen("safety:halt", "\\u0073afety:halt", 1) + "\n",
        ),
    ] {
        let file = dir.write(name, text);
        let output = verify_json(&file, &pin, None);
        assert_fails(&output, "SAFETY_MANIFEST_INVALID");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("canonical encoding"),
            "{name}: {output:?}"
        );
    }
}

/// With `--attester-pin`, a namespace pin equal to the attester key is
/// refused before the signature is considered.
#[test]
fn the_namespace_pin_must_not_be_the_attester_key() {
    let dir = Dir::new();
    let (manifest, pin, _) = golden_files(&dir);
    let output = verify(&[
        "--manifest",
        &manifest,
        "--pin",
        &pin,
        "--attester-pin",
        &pin,
        "--format",
        "json",
    ]);
    assert_fails(&output, "SAFETY_MANIFEST_SAME_KEY");
    let other = dir.write(
        "attester.pin",
        hex::encode(
            EvidenceAttesterKey::from_secret_bytes(&[0x63; 32])
                .public_key()
                .unwrap()
                .as_bytes(),
        ),
    );
    let output = verify(&[
        "--manifest",
        &manifest,
        "--pin",
        &pin,
        "--attester-pin",
        &other,
        "--format",
        "json",
    ]);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn usage_errors_are_reported() {
    let dir = Dir::new();
    let (manifest, pin, _) = golden_files(&dir);
    for args in [
        vec!["--manifest", manifest.as_str(), "--format", "json"],
        vec!["--pin", pin.as_str(), "--format", "json"],
        vec![
            "--manifest",
            manifest.as_str(),
            "--pin",
            pin.as_str(),
            "--issuer-pins",
            pin.as_str(),
            "--format",
            "json",
        ],
    ] {
        assert_fails(&verify(&args), "USAGE");
    }
    let missing = dir.0.join("missing.json");
    assert_fails(
        &verify_json(missing.to_str().unwrap(), &pin, None),
        "INPUT_IO",
    );
}
