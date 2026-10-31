//! A [`praetore_core::Signer`] backed by an AWS KMS Ed25519 key
//! (SAF-11, decision 2: AWS KMS is the first KMS).
//!
//! * Key: `KeySpec` `ECC_NIST_EDWARDS25519`, `KeyUsage` `SIGN_VERIFY`.
//! * Signing: `SigningAlgorithm` `ED25519_SHA_512`, `MessageType` `RAW`,
//!   which is pure Ed25519 (RFC 8032), so signatures verify with the same
//!   offline verifiers. `RAW` accepts at most 4096 bytes, so evidence uses
//!   [`SignatureAlgorithm::Ed25519Sha256Envelope`] (a fixed 99-byte message)
//!   and longer messages are refused before calling KMS.
//!   `ED25519_PH_SHA_512` is not used (SAF-11 §4).
//! * The public key is read once with `GetPublicKey` and checked: key spec,
//!   usage, offered algorithm, the exact RFC 8410 SubjectPublicKeyInfo
//!   encoding, optionally a pinned public key, and a test signature.
//!   Every later signature is verified against it before use, so a key
//!   alias that is re-pointed to another key fails closed.
//!
//! The crate talks to KMS through the [`KmsClient`] trait. With the `sdk`
//! feature, [`sdk::AwsSdkKmsClient`] implements it over the official
//! `aws-sdk-kms` client; credentials, region and HTTP client are configured
//! by the caller. Errors never contain key material or credentials.

use praetore_core::{
    SignatureAlgorithm, Signer, SignerError, VerifiedPublicKey, signer::attester_key_id,
};
use std::sync::Arc;
use thiserror::Error;

#[cfg(feature = "sdk")]
pub mod sdk;

pub const KEY_SPEC: &str = "ECC_NIST_EDWARDS25519";
pub const KEY_USAGE: &str = "SIGN_VERIFY";
pub const SIGNING_ALGORITHM: &str = "ED25519_SHA_512";
/// `Sign` with `MessageType` `RAW` accepts 0 to 4096 bytes.
pub const MAX_RAW_MESSAGE_BYTES: usize = 4096;

/// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): SEQUENCE {
/// SEQUENCE { OID 1.3.101.112 }, BIT STRING (0 unused bits) }.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const SELF_TEST_MESSAGE: &[u8] = b"PRAETORE_AWS_KMS_SELF_TEST_V1\0";

/// What `GetPublicKey` returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsPublicKey {
    pub key_spec: Option<String>,
    pub key_usage: Option<String>,
    pub signing_algorithms: Vec<String>,
    /// DER SubjectPublicKeyInfo.
    pub public_key_der: Vec<u8>,
}

/// A failed KMS call, already classified. Implementations must not put
/// credentials or request contents in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KmsCallError {
    /// Network failure, timeout, throttling, `KMSInternalException`,
    /// `KeyUnavailableException`, `DependencyTimeoutException`.
    #[error("KMS is unavailable")]
    Unavailable,
    /// Access denied, disabled or pending-deletion key, wrong key usage,
    /// unknown key, invalid request.
    #[error("KMS refused the request")]
    Rejected,
}

/// The two KMS operations the signer needs.
pub trait KmsClient: Send + Sync {
    fn get_public_key(&self, key_id: &str) -> Result<KmsPublicKey, KmsCallError>;

    /// `Sign` with `SigningAlgorithm` `ED25519_SHA_512` and `MessageType`
    /// `RAW`. Returns the raw 64-byte signature.
    fn sign_ed25519_raw(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, KmsCallError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AwsKmsSignerError {
    #[error("KMS key id is empty or malformed")]
    InvalidKeyId,
    #[error("KMS is unavailable")]
    Unavailable,
    #[error("KMS refused GetPublicKey or Sign")]
    Rejected,
    #[error("KMS key is not an ECC_NIST_EDWARDS25519 SIGN_VERIFY key offering ED25519_SHA_512")]
    WrongKeyType,
    #[error("KMS public key is not a valid Ed25519 SubjectPublicKeyInfo")]
    InvalidPublicKey,
    #[error("KMS public key does not match the pinned public key")]
    UnexpectedPublicKey,
    #[error("KMS test signature does not verify under the key's public key")]
    SelfTestFailed,
}

impl From<KmsCallError> for AwsKmsSignerError {
    fn from(error: KmsCallError) -> Self {
        match error {
            KmsCallError::Unavailable => Self::Unavailable,
            KmsCallError::Rejected => Self::Rejected,
        }
    }
}

/// Extracts the 32-byte key from an Ed25519 SubjectPublicKeyInfo. Only the
/// exact 44-byte RFC 8410 encoding is accepted.
pub fn ed25519_key_from_spki(der: &[u8]) -> Option<[u8; 32]> {
    let key = der.strip_prefix(&ED25519_SPKI_PREFIX)?;
    key.try_into().ok()
}

/// An Ed25519 key in AWS KMS.
pub struct AwsKmsSigner {
    client: Arc<dyn KmsClient>,
    key_id: String,
    verifying_key: VerifiedPublicKey,
}

impl std::fmt::Debug for AwsKmsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsSigner")
            .field("kms_key_id", &self.key_id)
            .field("attester_key_id", &attester_key_id(&self.verifying_key))
            .finish_non_exhaustive()
    }
}

impl AwsKmsSigner {
    /// Reads and checks the public key of `key_id` (prefer a key ARN to an
    /// alias), compares it with `expected_public_key` when given, and makes
    /// one test signature. Fails closed on any mismatch.
    pub fn new(
        client: Arc<dyn KmsClient>,
        key_id: impl Into<String>,
        expected_public_key: Option<&VerifiedPublicKey>,
    ) -> Result<Self, AwsKmsSignerError> {
        let key_id = key_id.into();
        if key_id.is_empty()
            || key_id.len() > 2048
            || key_id.trim() != key_id
            || key_id.chars().any(char::is_control)
        {
            return Err(AwsKmsSignerError::InvalidKeyId);
        }
        let public = client.get_public_key(&key_id)?;
        if public.key_spec.as_deref() != Some(KEY_SPEC)
            || public.key_usage.as_deref() != Some(KEY_USAGE)
            || !public
                .signing_algorithms
                .iter()
                .any(|algorithm| algorithm == SIGNING_ALGORITHM)
        {
            return Err(AwsKmsSignerError::WrongKeyType);
        }
        let bytes = ed25519_key_from_spki(&public.public_key_der)
            .ok_or(AwsKmsSignerError::InvalidPublicKey)?;
        let verifying_key = VerifiedPublicKey::from_bytes(&bytes)
            .map_err(|_| AwsKmsSignerError::InvalidPublicKey)?;
        if expected_public_key.is_some_and(|expected| expected != &verifying_key) {
            return Err(AwsKmsSignerError::UnexpectedPublicKey);
        }
        let signer = Self {
            client,
            key_id,
            verifying_key,
        };
        praetore_core::signer::sign_exact(&signer, SELF_TEST_MESSAGE).map_err(
            |error| match error {
                SignerError::Unavailable => AwsKmsSignerError::Unavailable,
                SignerError::Rejected | SignerError::MessageTooLarge => AwsKmsSignerError::Rejected,
                SignerError::InvalidSignature => AwsKmsSignerError::SelfTestFailed,
            },
        )?;
        Ok(signer)
    }

    /// The KMS key id or ARN this signer calls.
    pub fn kms_key_id(&self) -> &str {
        &self.key_id
    }
}

impl Signer for AwsKmsSigner {
    /// Always the envelope: a full receipt may exceed the `RAW` limit.
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519Sha256Envelope
    }

    fn verifying_key(&self) -> &VerifiedPublicKey {
        &self.verifying_key
    }

    fn max_message_len(&self) -> Option<usize> {
        Some(MAX_RAW_MESSAGE_BYTES)
    }

    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        if message.len() > MAX_RAW_MESSAGE_BYTES {
            return Err(SignerError::MessageTooLarge);
        }
        self.client
            .sign_ed25519_raw(&self.key_id, message)
            .map_err(|error| match error {
                KmsCallError::Unavailable => SignerError::Unavailable,
                KmsCallError::Rejected => SignerError::Rejected,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use praetore_core::{
        Action, AgentId, AgentKeyPair, Authority, DecidedBy, Decision, Evidence, LocalSigner,
    };
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    /// A stub KMS: one Ed25519 key, the AWS answers configured per test.
    struct StubKms {
        key: LocalSigner,
        signing_key: LocalSigner,
        public: KmsPublicKey,
        available: AtomicBool,
        reject: AtomicBool,
        calls: AtomicUsize,
        last_message_len: Mutex<Option<usize>>,
    }

    fn spki(key: &LocalSigner) -> Vec<u8> {
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(&key.public_key().unwrap().as_bytes());
        der
    }

    impl StubKms {
        fn new() -> Self {
            let key = LocalSigner::from_secret_bytes(&[0x4b; 32]);
            Self {
                public: KmsPublicKey {
                    key_spec: Some(KEY_SPEC.into()),
                    key_usage: Some(KEY_USAGE.into()),
                    signing_algorithms: vec!["ED25519_PH_SHA_512".into(), SIGNING_ALGORITHM.into()],
                    public_key_der: spki(&key),
                },
                signing_key: key.clone(),
                key,
                available: AtomicBool::new(true),
                reject: AtomicBool::new(false),
                calls: AtomicUsize::new(0),
                last_message_len: Mutex::new(None),
            }
        }
    }

    impl KmsClient for StubKms {
        fn get_public_key(&self, key_id: &str) -> Result<KmsPublicKey, KmsCallError> {
            assert_eq!(key_id, KEY_ARN);
            Ok(self.public.clone())
        }

        fn sign_ed25519_raw(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, KmsCallError> {
            assert_eq!(key_id, KEY_ARN);
            // The real service refuses RAW messages over 4096 bytes.
            assert!(message.len() <= MAX_RAW_MESSAGE_BYTES);
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.last_message_len.lock().unwrap() = Some(message.len());
            if !self.available.load(Ordering::SeqCst) {
                return Err(KmsCallError::Unavailable);
            }
            if self.reject.load(Ordering::SeqCst) {
                return Err(KmsCallError::Rejected);
            }
            self.signing_key
                .sign_raw(message)
                .map_err(|_| KmsCallError::Rejected)
        }
    }

    const KEY_ARN: &str =
        "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    fn signer(stub: Arc<StubKms>) -> AwsKmsSigner {
        AwsKmsSigner::new(stub, KEY_ARN, None).unwrap()
    }

    fn large_evidence() -> Evidence {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let authority = Authority::new(agent.id.clone(), "kms-test", vec!["data:read".into()]);
        // Parameters large enough that the canonical payload exceeds 4 KiB.
        let action = Action::new(
            "read_data",
            Some("dataset".into()),
            serde_json::json!({"filter": "x".repeat(8 * 1024)}),
        )
        .unwrap()
        .with_capability("data:read");
        let mut evidence = Evidence::new(
            uuid::Uuid::new_v4(),
            agent,
            authority,
            action,
            Decision::allow("kms test", DecidedBy::rule("read")),
            None,
        )
        .unwrap();
        evidence
            .bind_policy_digest(hex::encode([0x6b; 32]))
            .unwrap();
        assert!(evidence.to_json().unwrap().len() > MAX_RAW_MESSAGE_BYTES);
        evidence
    }

    #[test]
    fn kms_signs_large_evidence_with_the_envelope_and_it_verifies_offline() {
        let stub = Arc::new(StubKms::new());
        let signer = signer(stub.clone());
        let mut evidence = large_evidence();
        evidence.sign(&signer).unwrap();
        assert_eq!(
            evidence.attester_algorithm.as_deref(),
            Some("ed25519-sha256-envelope")
        );
        // Only the fixed 99-byte envelope went to KMS.
        assert_eq!(*stub.last_message_len.lock().unwrap(), Some(99));
        let pinned = stub.key.public_key().unwrap();
        Evidence::from_json(&evidence.to_json().unwrap())
            .unwrap()
            .verify_attester_signature(&pinned)
            .unwrap();
        assert_eq!(evidence.attester_key_id, Some(stub.key.key_id()));
    }

    #[test]
    fn the_raw_limit_is_enforced_before_calling_kms() {
        let stub = Arc::new(StubKms::new());
        let signer = signer(stub.clone());
        let calls = stub.calls.load(Ordering::SeqCst);
        assert!(praetore_core::signer::sign_exact(&signer, &[0; MAX_RAW_MESSAGE_BYTES]).is_ok());
        assert_eq!(
            praetore_core::signer::sign_exact(&signer, &[0; MAX_RAW_MESSAGE_BYTES + 1]),
            Err(SignerError::MessageTooLarge)
        );
        assert_eq!(
            signer.sign_raw(&[0; MAX_RAW_MESSAGE_BYTES + 1]),
            Err(SignerError::MessageTooLarge)
        );
        assert_eq!(stub.calls.load(Ordering::SeqCst), calls + 1);
        // A legacy (non-envelope) signature of a large receipt is refused,
        // never truncated or silently switched.
        let mut evidence = large_evidence();
        let legacy_over_kms = LegacyOverKms(signer);
        assert_eq!(
            evidence.sign(&legacy_over_kms).unwrap_err().code(),
            "SIGNER_FAIL"
        );
        assert!(evidence.attester_signature.is_none());
    }

    /// The same KMS key asked to use the legacy algorithm.
    struct LegacyOverKms(AwsKmsSigner);

    impl Signer for LegacyOverKms {
        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::Ed25519
        }
        fn verifying_key(&self) -> &VerifiedPublicKey {
            self.0.verifying_key()
        }
        fn max_message_len(&self) -> Option<usize> {
            self.0.max_message_len()
        }
        fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
            self.0.sign_raw(message)
        }
    }

    #[test]
    fn kms_outages_are_transient_and_refusals_are_not() {
        let stub = Arc::new(StubKms::new());
        let signer = signer(stub.clone());
        let mut evidence = large_evidence();
        stub.available.store(false, Ordering::SeqCst);
        let error = evidence.sign(&signer).unwrap_err();
        assert!(matches!(
            error,
            praetore_core::PraetoreError::SignerUnavailable
        ));
        assert!(evidence.attester_signature.is_none());
        stub.available.store(true, Ordering::SeqCst);
        stub.reject.store(true, Ordering::SeqCst);
        assert!(matches!(
            evidence.sign(&signer).unwrap_err(),
            praetore_core::PraetoreError::SignerFailed
        ));
        stub.reject.store(false, Ordering::SeqCst);
        evidence.sign(&signer).unwrap();
    }

    #[test]
    fn a_kms_key_that_signs_with_another_key_fails_closed() {
        // As if an alias had been re-pointed after GetPublicKey.
        let mut stub = StubKms::new();
        stub.signing_key = LocalSigner::from_secret_bytes(&[0x4c; 32]);
        assert_eq!(
            AwsKmsSigner::new(Arc::new(stub), KEY_ARN, None).unwrap_err(),
            AwsKmsSignerError::SelfTestFailed
        );
    }

    #[test]
    fn wrong_key_types_and_encodings_are_refused() {
        type Mutation = fn(&mut KmsPublicKey);
        let cases: [(&str, Mutation); 4] = [
            ("P-256", |p| p.key_spec = Some("ECC_NIST_P256".into())),
            ("no spec", |p| p.key_spec = None),
            ("encrypt", |p| p.key_usage = Some("ENCRYPT_DECRYPT".into())),
            ("ph only", |p| {
                p.signing_algorithms = vec!["ED25519_PH_SHA_512".into()]
            }),
        ];
        for (name, mutate) in cases {
            let mut stub = StubKms::new();
            mutate(&mut stub.public);
            assert_eq!(
                AwsKmsSigner::new(Arc::new(stub), KEY_ARN, None).unwrap_err(),
                AwsKmsSignerError::WrongKeyType,
                "{name}"
            );
        }
        let encodings: [fn(&mut Vec<u8>); 5] = [
            |der| der.truncate(43),
            |der| der.push(0),
            |der| der[8] = 0x71,  // id-Ed448 OID
            |der| der[11] = 0x01, // unused bits in the BIT STRING
            |der| {
                // A small-order point (the identity).
                let mut identity = [0u8; 32];
                identity[0] = 1;
                der[12..].copy_from_slice(&identity);
            },
        ];
        for mutate in encodings {
            let mut stub = StubKms::new();
            mutate(&mut stub.public.public_key_der);
            assert_eq!(
                AwsKmsSigner::new(Arc::new(stub), KEY_ARN, None).unwrap_err(),
                AwsKmsSignerError::InvalidPublicKey
            );
        }
    }

    #[test]
    fn the_pinned_public_key_is_enforced() {
        let stub = Arc::new(StubKms::new());
        let expected = stub.key.public_key().unwrap();
        assert!(AwsKmsSigner::new(stub.clone(), KEY_ARN, Some(&expected)).is_ok());
        let other = LocalSigner::generate().public_key().unwrap();
        assert_eq!(
            AwsKmsSigner::new(stub, KEY_ARN, Some(&other)).unwrap_err(),
            AwsKmsSignerError::UnexpectedPublicKey
        );
    }

    #[test]
    fn key_ids_are_validated_and_debug_output_has_no_secrets() {
        for key_id in ["", " arn", "arn\n", "a\u{0}b"] {
            assert_eq!(
                AwsKmsSigner::new(Arc::new(StubKms::new()), key_id, None).unwrap_err(),
                AwsKmsSignerError::InvalidKeyId
            );
        }
        let signer = signer(Arc::new(StubKms::new()));
        let debug = format!("{signer:?}");
        assert!(debug.contains(KEY_ARN));
        assert!(!debug.contains(&hex::encode([0x4b; 32])));
    }

    #[test]
    fn spki_parsing_is_exact() {
        let key = LocalSigner::from_secret_bytes(&[1; 32]);
        let der = spki(&key);
        assert_eq!(der.len(), 44);
        assert_eq!(
            ed25519_key_from_spki(&der),
            Some(key.public_key().unwrap().as_bytes())
        );
        assert_eq!(ed25519_key_from_spki(&der[1..]), None);
        assert_eq!(ed25519_key_from_spki(&[]), None);
    }
}
