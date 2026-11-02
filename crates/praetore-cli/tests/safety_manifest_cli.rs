//! G2 end to end: `praetore policy safety-manifest` writes a signed safety
//! namespace manifest, never overwrites, and the manifest verifies with the
//! library and, when it is built in the same profile, with
//! `praetore-verify safety-manifest`.

use praetore_core::{
    ActionClass, Policy, PolicyEffect, PolicyRule, SafetyNamespaceKey, SafetyNamespaceManifest,
    VerifiedPublicKey,
};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const PRAETORE: &str = env!("CARGO_BIN_EXE_praetore");
const SECRET: [u8; 32] = [0x51; 32];

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "praetore-safety-manifest-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, contents).unwrap();
        path
    }

    fn write_private(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.write(name, contents);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn policy() -> Policy {
    Policy::new_v2(
        "operations",
        2,
        vec![PolicyRule::new(
            "allow-writes",
            "fs:write_file",
            PolicyEffect::Allow,
        )],
    )
    .with_mission_actions(["fs:write_file"])
    .with_action_class("safety:stop_all", ActionClass::Safety)
    .with_action_class("safety:halt", ActionClass::Safety)
}

fn pin() -> VerifiedPublicKey {
    SafetyNamespaceKey::from_secret_bytes(&SECRET)
        .public_key()
        .unwrap()
}

/// A directory with the policy and the owner-only key file.
fn fixture() -> (Dir, PathBuf, PathBuf) {
    let dir = Dir::new();
    let policy = dir.write("policy.json", serde_json::to_vec_pretty(&policy()).unwrap());
    let key = dir.write_private("namespace.key", &format!("{}\n", hex::encode(SECRET)));
    (dir, policy, key)
}

fn praetore(args: &[&str]) -> Output {
    Command::new(PRAETORE).args(args).output().unwrap()
}

fn manifest_args<'a>(policy: &'a Path, key: &'a Path, output: &'a Path) -> Vec<&'a str> {
    vec![
        "policy",
        "safety-manifest",
        "--policy",
        policy.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--issued-at",
        "2026-11-01T00:00:00Z",
    ]
}

#[test]
fn writes_a_manifest_that_verifies_against_the_policy() {
    let (dir, policy_path, key) = fixture();
    let output = dir.path("manifest.json");
    let mut args = manifest_args(&policy_path, &key, &output);
    args.extend(["--format", "json"]);
    let result = praetore(&args);
    assert!(result.status.success(), "{result:?}");

    let summary: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(summary["ok"], true);
    assert_eq!(summary["policy_id"], "operations");
    assert_eq!(summary["policy_version"], 2);
    assert_eq!(summary["policy_digest"], policy().digest().unwrap());
    assert_eq!(
        summary["safety_actions"],
        serde_json::json!(["safety:halt", "safety:stop_all"])
    );
    assert_eq!(summary["public_key"], hex::encode(pin().as_bytes()));

    let text = fs::read_to_string(&output).unwrap();
    assert!(text.ends_with("}\n"));
    let manifest = SafetyNamespaceManifest::from_file(&text).unwrap();
    manifest.verify(&pin()).unwrap();
    manifest.verify_matches_policy(&policy()).unwrap();
    assert_eq!(summary["key_id"], manifest.key_id());

    // Deterministic: the same inputs give the same file.
    let again = dir.path("again.json");
    assert!(
        praetore(&manifest_args(&policy_path, &key, &again))
            .status
            .success()
    );
    assert_eq!(fs::read(&again).unwrap(), text.as_bytes());
}

#[test]
fn never_overwrites_an_existing_file() {
    let (dir, policy, key) = fixture();
    let output = dir.write("manifest.json", "existing contents\n");
    let before = fs::metadata(&output).unwrap().modified().unwrap();
    let result = praetore(&manifest_args(&policy, &key, &output));
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("cannot create"),
        "{result:?}"
    );
    assert_eq!(fs::read_to_string(&output).unwrap(), "existing contents\n");
    assert_eq!(fs::metadata(&output).unwrap().modified().unwrap(), before);

    // Not even a manifest written by a previous run.
    let first = dir.path("first.json");
    assert!(
        praetore(&manifest_args(&policy, &key, &first))
            .status
            .success()
    );
    let contents = fs::read(&first).unwrap();
    let mut args = manifest_args(&policy, &key, &first);
    args[9] = "2026-12-01T00:00:00Z";
    assert!(!praetore(&args).status.success());
    assert_eq!(fs::read(&first).unwrap(), contents);
}

#[test]
fn writes_nothing_when_an_input_is_invalid() {
    let (dir, policy, key) = fixture();
    let output = dir.path("manifest.json");

    // A policy that does not load (a rule on a Safety action).
    let invalid = dir.write(
        "invalid.json",
        serde_json::to_vec(
            &Policy::new_v2(
                "p",
                1,
                vec![PolicyRule::new("r", "safety:halt", PolicyEffect::Deny)],
            )
            .with_action_class("safety:halt", ActionClass::Safety),
        )
        .unwrap(),
    );
    assert!(
        !praetore(&manifest_args(&invalid, &key, &output))
            .status
            .success()
    );

    // A format 1 policy.
    let format_1 = dir.write(
        "v1.json",
        include_str!("../../../docs/golden/canonical-policy-v1.json"),
    );
    assert!(
        !praetore(&manifest_args(&format_1, &key, &output))
            .status
            .success()
    );

    // A key that is not 64 lowercase hex characters.
    let bad_key = dir.write_private("bad.key", &"AB".repeat(32));
    assert!(
        !praetore(&manifest_args(&policy, &bad_key, &output))
            .status
            .success()
    );

    // A key readable by others.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let open_key = dir.write("open.key", hex::encode(SECRET));
        fs::set_permissions(&open_key, fs::Permissions::from_mode(0o644)).unwrap();
        let result = praetore(&manifest_args(&policy, &open_key, &output));
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("group or others"));

        // A symlink to an owner-only key, a FIFO and an oversized file.
        let link = dir.path("link.key");
        std::os::unix::fs::symlink(&key, &link).unwrap();
        let result = praetore(&manifest_args(&policy, &link, &output));
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("symbolic link"));

        let fifo = dir.path("fifo.key");
        assert!(
            Command::new("mkfifo")
                .args(["-m", "600"])
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let result = praetore(&manifest_args(&policy, &fifo, &output));
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("not a regular file"));

        let big = dir.write_private(
            "big.key",
            &format!("{}\n{}", hex::encode(SECRET), "a".repeat(100)),
        );
        let result = praetore(&manifest_args(&policy, &big, &output));
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("larger than 128 bytes"));
    }

    // An invalid time.
    let mut args = manifest_args(&policy, &key, &output);
    args[9] = "yesterday";
    assert!(!praetore(&args).status.success());

    assert!(!output.exists());
}

/// The namespace key is refused when it equals any `--other-pin` (the
/// attester or an issuer); `--attester-pin` is an alias.
#[test]
fn refuses_the_key_of_another_role_as_the_namespace_key() {
    let (dir, policy, key) = fixture();
    let output = dir.path("manifest.json");
    let same = dir.write("same.pin", hex::encode(pin().as_bytes()));
    let other = |name: &str, seed: u8| {
        dir.write(
            name,
            hex::encode(
                praetore_core::EvidenceAttesterKey::from_secret_bytes(&[seed; 32])
                    .public_key()
                    .unwrap()
                    .as_bytes(),
            ),
        )
    };
    let attester = other("attester.pin", 0x52);
    let issuer = other("issuer.pin", 0x53);
    for flags in [
        vec!["--other-pin", same.to_str().unwrap()],
        vec!["--attester-pin", same.to_str().unwrap()],
        vec![
            "--other-pin",
            attester.to_str().unwrap(),
            "--other-pin",
            issuer.to_str().unwrap(),
            "--other-pin",
            same.to_str().unwrap(),
        ],
    ] {
        let mut args = manifest_args(&policy, &key, &output);
        args.extend(flags.iter().copied());
        let result = praetore(&args);
        assert!(!result.status.success(), "{flags:?}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("key of another role"),
            "{result:?}"
        );
        assert!(!output.exists());
    }

    let mut args = manifest_args(&policy, &key, &output);
    args.extend([
        "--other-pin",
        attester.to_str().unwrap(),
        "--attester-pin",
        issuer.to_str().unwrap(),
    ]);
    assert!(praetore(&args).status.success());
}

/// The manifest is written through a temporary file that is always
/// removed; nothing else is left in the directory.
#[test]
fn leaves_no_temporary_file() {
    let (dir, policy, key) = fixture();
    let output = dir.path("manifest.json");
    assert!(
        praetore(&manifest_args(&policy, &key, &output))
            .status
            .success()
    );
    assert!(
        !praetore(&manifest_args(&policy, &key, &output))
            .status
            .success()
    );
    #[cfg(unix)]
    {
        let dangling = dir.path("dangling.json");
        std::os::unix::fs::symlink(dir.path("nowhere"), &dangling).unwrap();
        assert!(
            !praetore(&manifest_args(&policy, &key, &dangling))
                .status
                .success()
        );
        assert!(!dir.path("nowhere").exists());
    }
    let mut names: Vec<String> = fs::read_dir(&dir.0)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let mut expected = vec!["manifest.json", "namespace.key", "policy.json"];
    #[cfg(unix)]
    expected.insert(0, "dangling.json");
    assert_eq!(names, expected);
}

#[test]
fn text_output_names_every_field() {
    let (dir, policy, key) = fixture();
    let output = dir.path("manifest.json");
    let result = praetore(&manifest_args(&policy, &key, &output));
    assert!(result.status.success(), "{result:?}");
    let line = String::from_utf8(result.stdout).unwrap();
    assert!(line.starts_with("OK policy safety-manifest "), "{line}");
    for field in [
        "policy_id=\"operations\"",
        "policy_version=2",
        "safety_actions=[\"safety:halt\",\"safety:stop_all\"]",
        "issued_at=\"2026-11-01T00:00:00Z\"",
        "key_id=",
        "public_key=",
    ] {
        assert!(line.contains(field), "{field} missing from {line}");
    }
}

/// The full chain with the real verifier binary, when it is built in the
/// same profile (`cargo test --workspace` builds it).
#[test]
fn the_verifier_accepts_the_written_manifest() {
    let verifier = Path::new(PRAETORE)
        .with_file_name(format!("praetore-verify{}", std::env::consts::EXE_SUFFIX));
    if !verifier.is_file() {
        eprintln!(
            "skipped: {} is not built (cargo build -p praetore-verify --locked)",
            verifier.display()
        );
        return;
    }
    let (dir, policy, key) = fixture();
    let output = dir.path("manifest.json");
    assert!(
        praetore(&manifest_args(&policy, &key, &output))
            .status
            .success()
    );
    let pin_file = dir.write("namespace.pin", hex::encode(pin().as_bytes()));
    let result = Command::new(&verifier)
        .args([
            "safety-manifest",
            "--manifest",
            output.to_str().unwrap(),
            "--pin",
            pin_file.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    let summary: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(summary["ok"], true);
    assert_eq!(summary["details"]["policy_verified"], true);
}
