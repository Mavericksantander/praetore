//! SoftHSM2 integration tests. Ignored by default; run them with a SoftHSM2
//! module:
//!
//! ```text
//! PRAETORE_TEST_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
//!   cargo test -p praetore-signer-pkcs11 --features softhsm-testing \
//!   --test softhsm -- --ignored
//! ```
//!
//! Each run creates a fresh token in a temporary directory (through its own
//! `SOFTHSM2_CONF`), generates Ed25519 keys inside it and never touches the
//! user's tokens. With `PRAETORE_TEST_PKCS11_EXPORT_DIR` set, the signed
//! receipts and the public key are also written there, so CI can check them
//! with the `praetore-verify` binary.

use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, DecidedBy, Decision, Evidence, LocalSigner,
    SignatureAlgorithm, Signer, VerifiedPublicKey,
};
use praetore_signer_pkcs11::{
    AuthPin, Pkcs11Config, Pkcs11Signer, Pkcs11SignerError,
    softhsm_testing::{self, TestKey},
};
use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

const TOKEN_LABEL: &str = "praetore-test";
const SO_PIN: &str = "so-pin-0000";
const USER_PIN: &str = "user-pin-7391";
const KEY_LABEL: &str = "praetore-evidence";
const EXTRACTABLE_LABEL: &str = "praetore-extractable";
const IMPORTED_LABEL: &str = "praetore-imported";
const EXPORTED_LABEL: &str = "praetore-exported-then-locked";

struct Token {
    module: PathBuf,
}

fn module_path() -> PathBuf {
    std::env::var_os("PRAETORE_TEST_PKCS11_MODULE")
        .map(PathBuf::from)
        .expect("set PRAETORE_TEST_PKCS11_MODULE to the SoftHSM2 module path")
}

/// Creates the temporary token once per test binary.
fn token() -> &'static Token {
    static TOKEN: OnceLock<Token> = OnceLock::new();
    TOKEN.get_or_init(|| {
        let module = module_path();
        let root = std::env::temp_dir().join(format!(
            "praetore-softhsm-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let conf = softhsm_testing::write_config(&root);
        softhsm_testing::remove_at_exit(root.clone());
        // SAFETY: runs once, inside `OnceLock::get_or_init`, before any test
        // loads the module; the other test threads are blocked on this
        // initialization and do not read the environment meanwhile.
        unsafe { std::env::set_var("SOFTHSM2_CONF", &conf) };
        softhsm_testing::create_token(
            &module,
            TOKEN_LABEL,
            SO_PIN,
            USER_PIN,
            &[
                TestKey {
                    label: KEY_LABEL,
                    extractable: false,
                },
                TestKey {
                    label: EXTRACTABLE_LABEL,
                    extractable: true,
                },
                TestKey {
                    label: EXPORTED_LABEL,
                    extractable: true,
                },
            ],
        );
        softhsm_testing::lock_exported_key(&module, TOKEN_LABEL, USER_PIN, EXPORTED_LABEL);
        softhsm_testing::import_key(&module, TOKEN_LABEL, USER_PIN, IMPORTED_LABEL, [0x42; 32]);
        Token { module }
    })
}

/// The tests run one at a time: PKCS#11 login state is per process and
/// token, so a concurrent test could otherwise hide a wrong PIN.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn config(label: &str, pin: &str, algorithm: SignatureAlgorithm) -> Pkcs11Config {
    Pkcs11Config {
        module: token().module.clone(),
        token_label: TOKEN_LABEL.into(),
        key_label: label.into(),
        user_pin: AuthPin::new(pin.into()),
        algorithm,
        expected_public_key: None,
    }
}

fn signer(algorithm: SignatureAlgorithm) -> Pkcs11Signer {
    Pkcs11Signer::open(&config(KEY_LABEL, USER_PIN, algorithm)).unwrap()
}

fn receipt(signer: &dyn Signer) -> Evidence {
    let agent_key = AgentKeyPair::generate();
    let agent = agent_key.identity(AgentId::new());
    let authority = Authority::new(agent.id.clone(), "softhsm-test", vec!["data:read".into()]);
    let action = Action::new(
        "read_data",
        Some("dataset".into()),
        serde_json::json!({"rows": 10}),
    )
    .unwrap()
    .with_capability("data:read");
    let mut evidence = Evidence::new(
        uuid::Uuid::new_v4(),
        agent,
        authority,
        action,
        Decision::allow("softhsm test", DecidedBy::rule("read")),
        None,
    )
    .unwrap();
    evidence
        .bind_policy_digest(hex::encode([0x5a; 32]))
        .unwrap();
    evidence.sign(signer).unwrap();
    evidence
}

/// The pin a verifier would configure: the public key as lowercase hex,
/// parsed again independently of the signer object.
fn pinned_key(signer: &Pkcs11Signer) -> (String, VerifiedPublicKey) {
    let hex_pin = hex::encode(signer.verifying_key().as_bytes());
    let key = VerifiedPublicKey::from_bytes(&hex::decode(&hex_pin).unwrap()).unwrap();
    (hex_pin, key)
}

fn relabelled(evidence: &Evidence, algorithm: &str) -> Evidence {
    let mut relabelled = evidence.clone();
    relabelled.attester_algorithm = Some(algorithm.into());
    // Recomputes the unkeyed context hash.
    let digest = relabelled.policy_digest.clone().unwrap();
    relabelled.bind_policy_digest(digest).unwrap();
    assert!(relabelled.verify_integrity());
    relabelled
}

fn export(name: &str, contents: &str) {
    if let Some(dir) = std::env::var_os("PRAETORE_TEST_PKCS11_EXPORT_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(Path::new(&dir).join(name), contents).unwrap();
    }
}

#[test]
#[ignore = "requires SoftHSM2 (PRAETORE_TEST_PKCS11_MODULE)"]
fn softhsm_legacy_signature_verifies_with_the_existing_verifier() {
    let _serial = serial();
    let signer = signer(SignatureAlgorithm::Ed25519);
    let evidence = receipt(&signer);
    let (hex_pin, key) = pinned_key(&signer);
    assert_eq!(evidence.attester_algorithm.as_deref(), Some("ed25519"));
    assert_eq!(evidence.attester_key_id, Some(signer.key_id()));
    let json = evidence.to_json().unwrap();
    Evidence::from_json(&json)
        .unwrap()
        .verify_attester_signature(&key)
        .unwrap();
    // Tampering and a foreign key are still rejected.
    let mut tampered = evidence.clone();
    tampered.trace_id = Some("tampered".into());
    let digest = tampered.policy_digest.clone().unwrap();
    tampered.bind_policy_digest(digest).unwrap();
    assert!(tampered.verify_attester_signature(&key).is_err());
    assert!(
        evidence
            .verify_attester_signature(&LocalSigner::generate().public_key().unwrap())
            .is_err()
    );
    assert!(
        relabelled(&evidence, "ed25519-sha256-envelope")
            .verify_attester_signature(&key)
            .is_err()
    );
    export("attester-public-key.hex", &hex_pin);
    export("evidence-legacy.json", &json);
    println!(
        "softhsm legacy: key_id={} algorithm={} signature={}",
        signer.key_id(),
        evidence.attester_algorithm.as_deref().unwrap(),
        evidence.attester_signature.as_deref().unwrap()
    );
}

#[test]
#[ignore = "requires SoftHSM2 (PRAETORE_TEST_PKCS11_MODULE)"]
fn softhsm_envelope_signature_verifies_and_is_not_a_legacy_signature() {
    let _serial = serial();
    let signer = signer(SignatureAlgorithm::Ed25519Sha256Envelope);
    let evidence = receipt(&signer);
    let (_, key) = pinned_key(&signer);
    assert_eq!(
        evidence.attester_algorithm.as_deref(),
        Some("ed25519-sha256-envelope")
    );
    let json = evidence.to_json().unwrap();
    Evidence::from_json(&json)
        .unwrap()
        .verify_attester_signature(&key)
        .unwrap();
    assert!(
        relabelled(&evidence, "ed25519")
            .verify_attester_signature(&key)
            .is_err()
    );
    export("evidence-envelope.json", &json);
    export(
        "evidence-envelope-relabelled.json",
        &relabelled(&evidence, "ed25519").to_json().unwrap(),
    );
    println!(
        "softhsm envelope: key_id={} algorithm={} signature={}",
        signer.key_id(),
        evidence.attester_algorithm.as_deref().unwrap(),
        evidence.attester_signature.as_deref().unwrap()
    );
}

#[test]
#[ignore = "requires SoftHSM2 (PRAETORE_TEST_PKCS11_MODULE)"]
fn softhsm_signs_execution_attestation_messages_and_large_payloads() {
    let _serial = serial();
    let signer = signer(SignatureAlgorithm::Ed25519);
    let (_, key) = pinned_key(&signer);
    let domain = b"PRAETORE_EXECUTION_ATTESTATION_V1\0";
    let payload = br#"{"schema_version":2}"#;
    let mut message = domain.to_vec();
    message.extend_from_slice(payload);
    let signature = praetore_core::signer::sign_exact(&signer, &message).unwrap();
    key.verify_domain_message(domain, payload, &signature)
        .unwrap();
    // Pure Ed25519 over 64 KiB: the token has no 4 KiB limit.
    let large = vec![0x42; 64 * 1024];
    let signature = praetore_core::signer::sign_exact(&signer, &large).unwrap();
    key.verify_domain_message(b"", &large, &signature).unwrap();
}

#[test]
#[ignore = "requires SoftHSM2 (PRAETORE_TEST_PKCS11_MODULE)"]
fn softhsm_signers_share_the_module_and_sign_concurrently() {
    let _serial = serial();
    let first = std::sync::Arc::new(signer(SignatureAlgorithm::Ed25519));
    let second = signer(SignatureAlgorithm::Ed25519Sha256Envelope);
    assert_eq!(first.verifying_key(), second.verifying_key());
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let signer = first.clone();
            std::thread::spawn(move || {
                for _ in 0..10 {
                    let evidence = receipt(signer.as_ref());
                    evidence
                        .verify_attester_signature(signer.verifying_key())
                        .unwrap();
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
}

#[test]
#[ignore = "requires SoftHSM2 (PRAETORE_TEST_PKCS11_MODULE)"]
fn softhsm_refuses_wrong_pin_unknown_keys_and_exportable_keys() {
    let _serial = serial();
    let wrong = "wrong-pin-1234";
    let error =
        Pkcs11Signer::open(&config(KEY_LABEL, wrong, SignatureAlgorithm::Ed25519)).unwrap_err();
    assert_eq!(
        error,
        Pkcs11SignerError::Login {
            code: "PinIncorrect".into()
        }
    );
    assert!(!error.to_string().contains(wrong));
    assert!(!format!("{error:?}").contains(wrong));

    assert_eq!(
        Pkcs11Signer::open(&config(
            "no-such-key",
            USER_PIN,
            SignatureAlgorithm::Ed25519
        ))
        .unwrap_err(),
        Pkcs11SignerError::KeyNotFound
    );
    assert_eq!(
        Pkcs11Signer::open(&config(
            EXTRACTABLE_LABEL,
            USER_PIN,
            SignatureAlgorithm::Ed25519
        ))
        .unwrap_err(),
        Pkcs11SignerError::KeyExportable
    );
    let mut other_token = config(KEY_LABEL, USER_PIN, SignatureAlgorithm::Ed25519);
    other_token.token_label = "praetore-no-such-token".into();
    assert_eq!(
        Pkcs11Signer::open(&other_token).unwrap_err(),
        Pkcs11SignerError::TokenNotFound
    );
}

#[test]
#[ignore = "requires SoftHSM2 (PRAETORE_TEST_PKCS11_MODULE)"]
fn softhsm_enforces_the_pinned_public_key() {
    let _serial = serial();
    let actual = signer(SignatureAlgorithm::Ed25519).verifying_key().clone();
    let mut pinned = config(KEY_LABEL, USER_PIN, SignatureAlgorithm::Ed25519);
    pinned.expected_public_key = Some(actual);
    assert!(Pkcs11Signer::open(&pinned).is_ok());
    pinned.expected_public_key = Some(LocalSigner::generate().public_key().unwrap());
    assert_eq!(
        Pkcs11Signer::open(&pinned).unwrap_err(),
        Pkcs11SignerError::UnexpectedPublicKey
    );
}

#[test]
#[ignore = "requires SoftHSM2 (PRAETORE_TEST_PKCS11_MODULE)"]
fn softhsm_refuses_keys_imported_in_clear_or_once_extractable() {
    let _serial = serial();
    // Imported with C_CreateObject and CKA_VALUE, marked sensitive and not
    // extractable: the same key exists outside the token.
    assert_eq!(
        Pkcs11Signer::open(&config(
            IMPORTED_LABEL,
            USER_PIN,
            SignatureAlgorithm::Ed25519
        ))
        .unwrap_err(),
        Pkcs11SignerError::KeyNotGeneratedInToken
    );
    // Generated extractable, then locked: it may have been exported.
    assert_eq!(
        Pkcs11Signer::open(&config(
            EXPORTED_LABEL,
            USER_PIN,
            SignatureAlgorithm::Ed25519
        ))
        .unwrap_err(),
        Pkcs11SignerError::KeyNotGeneratedInToken
    );
}

#[test]
#[ignore = "requires SoftHSM2 (PRAETORE_TEST_PKCS11_MODULE)"]
fn softhsm_signer_recovers_after_the_process_is_logged_out() {
    let _serial = serial();
    let signer = signer(SignatureAlgorithm::Ed25519);
    let (_, key) = pinned_key(&signer);
    receipt(&signer).verify_attester_signature(&key).unwrap();
    // Another component (or an HSM session timeout) logs the process out:
    // the signer's key handle and login are gone.
    softhsm_testing::logout_process(&token().module, TOKEN_LABEL, USER_PIN);
    for _ in 0..3 {
        let evidence = receipt(&signer);
        evidence.verify_attester_signature(&key).unwrap();
    }
    let message = b"PRAETORE_TEST\0after logout";
    softhsm_testing::logout_process(&token().module, TOKEN_LABEL, USER_PIN);
    let signature = praetore_core::signer::sign_exact(&signer, message).unwrap();
    key.verify_domain_message(b"", message, &signature).unwrap();
}

#[test]
#[ignore = "requires SoftHSM2 (PRAETORE_TEST_PKCS11_MODULE)"]
fn softhsm_checks_the_pin_when_the_process_is_already_logged_in() {
    let _serial = serial();
    let first = signer(SignatureAlgorithm::Ed25519);
    // The token reports CKR_USER_ALREADY_LOGGED_IN and does not check it.
    assert_eq!(
        Pkcs11Signer::open(&config(
            KEY_LABEL,
            "wrong-pin-5678",
            SignatureAlgorithm::Ed25519
        ))
        .unwrap_err(),
        Pkcs11SignerError::Login {
            code: "PinIncorrect".into()
        }
    );
    // The right PIN is still accepted while logged in.
    let second = signer(SignatureAlgorithm::Ed25519);
    assert_eq!(first.verifying_key(), second.verifying_key());
}
