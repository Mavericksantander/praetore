//! Who signs receipts (SAF-11, decision 1).
//!
//! [`Signer`] separates *what* is signed (the receipt formats, which do not
//! change) from *who* holds the key: an in-process [`LocalSigner`], or a
//! backend that never exposes the private key (a PKCS#11 token or a cloud
//! KMS, in their own crates so `praetore-core` depends on no SDK).
//!
//! Every signer produces plain Ed25519 signatures. The
//! [`SignatureAlgorithm`] says which bytes an evidence attester signature
//! covers:
//!
//! * [`SignatureAlgorithm::Ed25519`] (`"ed25519"`): `domain || payload`, the
//!   format every receipt so far uses. Unchanged.
//! * [`SignatureAlgorithm::Ed25519Sha256Envelope`]
//!   (`"ed25519-sha256-envelope"`): `ENVELOPE_DOMAIN || domain ||
//!   SHA-256(payload)`. For signers that cannot sign arbitrarily long
//!   messages (AWS KMS signs `RAW` messages of at most 4096 bytes). For
//!   evidence the signed message is always 99 bytes long.
//!
//! The two messages can never be equal: every receipt domain starts with
//! `PRAETORE_` followed by its purpose and ends at its only NUL byte, and no
//! receipt domain is a prefix of [`ENVELOPE_DOMAIN`] or the other way
//! round. The evidence payload also records `attester_algorithm` itself, so
//! relabelling a receipt changes the signed bytes as well.
//!
//! [`sign_message`] checks every signature a signer returns against the
//! signer's public key before it is used, so a backend that answers with the
//! wrong key, or garbage, fails closed instead of producing a receipt that
//! would not verify.

use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;

use crate::identity::VerifiedPublicKey;

/// Prefix of every envelope message. Its NUL bytes end the prefix and the
/// algorithm name; no receipt domain starts with it.
pub const ENVELOPE_DOMAIN: &[u8] = b"PRAETORE_SIGNATURE_ENVELOPE_V1\0ed25519-sha256\0";

pub(crate) const ATTESTER_KEY_ID_DOMAIN: &[u8] = b"PRAETORE_ATTESTER_KEY_V1\0ed25519\0";

/// What an attester signature covers. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// `domain || payload`, signed with Ed25519 (`"ed25519"`).
    Ed25519,
    /// `ENVELOPE_DOMAIN || domain || SHA-256(payload)`, signed with Ed25519
    /// (`"ed25519-sha256-envelope"`).
    Ed25519Sha256Envelope,
}

impl SignatureAlgorithm {
    pub const ED25519: &'static str = "ed25519";
    pub const ED25519_SHA256_ENVELOPE: &'static str = "ed25519-sha256-envelope";

    /// The `attester_algorithm` value recorded in evidence.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => Self::ED25519,
            Self::Ed25519Sha256Envelope => Self::ED25519_SHA256_ENVELOPE,
        }
    }

    /// Parses an exact `attester_algorithm` value. Anything else, including
    /// other spellings or case, is unknown and fails closed.
    pub fn from_identifier(value: &str) -> Option<Self> {
        match value {
            Self::ED25519 => Some(Self::Ed25519),
            Self::ED25519_SHA256_ENVELOPE => Some(Self::Ed25519Sha256Envelope),
            _ => None,
        }
    }

    /// The exact bytes a signature under this algorithm covers.
    pub fn signing_message(self, domain: &[u8], payload: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519 => {
                let mut message = Vec::with_capacity(domain.len() + payload.len());
                message.extend_from_slice(domain);
                message.extend_from_slice(payload);
                message
            }
            Self::Ed25519Sha256Envelope => {
                let digest = Sha256::digest(payload);
                let mut message =
                    Vec::with_capacity(ENVELOPE_DOMAIN.len() + domain.len() + digest.len());
                message.extend_from_slice(ENVELOPE_DOMAIN);
                message.extend_from_slice(domain);
                message.extend_from_slice(&digest);
                message
            }
        }
    }

    /// Strict Ed25519 verification of `signature` over
    /// [`Self::signing_message`].
    pub fn verify(
        self,
        public_key: &VerifiedPublicKey,
        domain: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> crate::Result<()> {
        public_key.verify_domain_message(b"", &self.signing_message(domain, payload), signature)
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a signer could not sign. The messages are fixed strings: they never
/// contain key material, PINs, credentials or the message being signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SignerError {
    /// The backend (HSM, KMS) did not answer or answered with a transient
    /// error. Like an unavailable trusted clock, nothing is authorized; the
    /// same request can be retried. Never falls back to another key.
    #[error("signer is unavailable")]
    Unavailable,
    /// The backend refused (permissions, disabled key, wrong key type) or is
    /// misconfigured. Retrying does not help.
    #[error("signer refused the request or is misconfigured")]
    Rejected,
    /// The message is longer than the backend accepts.
    #[error("message exceeds the signer's size limit")]
    MessageTooLarge,
    /// The backend returned something that is not a valid Ed25519 signature
    /// by the signer's public key.
    #[error("signer returned an invalid signature")]
    InvalidSignature,
}

impl From<SignerError> for crate::PraetoreError {
    fn from(error: SignerError) -> Self {
        match error {
            SignerError::Unavailable => crate::PraetoreError::SignerUnavailable,
            SignerError::Rejected
            | SignerError::MessageTooLarge
            | SignerError::InvalidSignature => crate::PraetoreError::SignerFailed,
        }
    }
}

/// A holder of one Ed25519 signing key.
///
/// Implementations only sign exact bytes ([`Signer::sign_raw`]); callers
/// use [`sign_message`], which builds the message for the chosen
/// [`SignatureAlgorithm`] and checks the result. Implementations must not
/// log or return key material, PINs or credentials.
pub trait Signer: Send + Sync {
    /// The algorithm this signer uses for evidence attester signatures.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// The public key of the signing key. It is read once, when the signer
    /// is built, and must not change afterwards.
    fn verifying_key(&self) -> &VerifiedPublicKey;

    /// The evidence attester `key_id`: SHA-256 over
    /// `PRAETORE_ATTESTER_KEY_V1\0ed25519\0 || public_key`, as before.
    fn key_id(&self) -> String {
        attester_key_id(self.verifying_key())
    }

    /// The longest message [`Signer::sign_raw`] accepts, if limited.
    fn max_message_len(&self) -> Option<usize> {
        None
    }

    /// Signs exactly `message` with pure Ed25519 (RFC 8032, no prehash) and
    /// returns the 64-byte signature.
    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;
}

impl<S: Signer + ?Sized> Signer for Arc<S> {
    fn algorithm(&self) -> SignatureAlgorithm {
        (**self).algorithm()
    }
    fn verifying_key(&self) -> &VerifiedPublicKey {
        (**self).verifying_key()
    }
    fn key_id(&self) -> String {
        (**self).key_id()
    }
    fn max_message_len(&self) -> Option<usize> {
        (**self).max_message_len()
    }
    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        (**self).sign_raw(message)
    }
}

impl<S: Signer + ?Sized> Signer for Box<S> {
    fn algorithm(&self) -> SignatureAlgorithm {
        (**self).algorithm()
    }
    fn verifying_key(&self) -> &VerifiedPublicKey {
        (**self).verifying_key()
    }
    fn key_id(&self) -> String {
        (**self).key_id()
    }
    fn max_message_len(&self) -> Option<usize> {
        (**self).max_message_len()
    }
    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        (**self).sign_raw(message)
    }
}

/// Signs `domain || payload` under `algorithm` and verifies the signature
/// against `signer.verifying_key()` before returning it.
pub fn sign_message<S: Signer + ?Sized>(
    signer: &S,
    algorithm: SignatureAlgorithm,
    domain: &[u8],
    payload: &[u8],
) -> Result<[u8; 64], SignerError> {
    sign_exact(signer, &algorithm.signing_message(domain, payload))
}

/// Signs exactly `message` with pure Ed25519 and verifies the signature
/// against `signer.verifying_key()`. For formats that already include their
/// domain in `message` (execution attestations).
pub fn sign_exact<S: Signer + ?Sized>(signer: &S, message: &[u8]) -> Result<[u8; 64], SignerError> {
    if signer
        .max_message_len()
        .is_some_and(|limit| message.len() > limit)
    {
        return Err(SignerError::MessageTooLarge);
    }
    let signature: [u8; 64] = signer
        .sign_raw(message)?
        .try_into()
        .map_err(|_| SignerError::InvalidSignature)?;
    signer
        .verifying_key()
        .verify_domain_message(b"", message, &signature)
        .map_err(|_| SignerError::InvalidSignature)?;
    Ok(signature)
}

/// The evidence attester key identifier of `public_key`.
pub fn attester_key_id(public_key: &VerifiedPublicKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ATTESTER_KEY_ID_DOMAIN);
    hasher.update(public_key.as_bytes());
    hex::encode(hasher.finalize())
}

/// An Ed25519 key held in process memory (zeroized on drop).
///
/// This is the former `EvidenceAttesterKey` (still available under that
/// name) and the gateway's execution key. The key is only as protected as
/// the process: prefer a PKCS#11 or KMS signer outside development.
pub struct LocalSigner {
    signing_key: SigningKey,
    verifying_key: VerifiedPublicKey,
    algorithm: SignatureAlgorithm,
}

impl std::fmt::Debug for LocalSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSigner")
            .field("key_id", &Signer::key_id(self))
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl Clone for LocalSigner {
    fn clone(&self) -> Self {
        Self {
            signing_key: self.signing_key.clone(),
            verifying_key: self.verifying_key.clone(),
            algorithm: self.algorithm,
        }
    }
}

impl LocalSigner {
    pub fn generate() -> Self {
        Self::from_signing_key(SigningKey::generate(&mut OsRng))
    }

    /// Restores a key from its 32-byte secret. The input must already be a
    /// high-entropy secret.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self::from_signing_key(SigningKey::from_bytes(secret))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = VerifiedPublicKey::from_verifying_key(signing_key.verifying_key());
        Self {
            signing_key,
            verifying_key,
            algorithm: SignatureAlgorithm::Ed25519,
        }
    }

    /// Uses `algorithm` for evidence attester signatures (default
    /// [`SignatureAlgorithm::Ed25519`]).
    pub fn with_algorithm(mut self, algorithm: SignatureAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// The public key. Kept for compatibility with `EvidenceAttesterKey`;
    /// it cannot fail.
    pub fn public_key(&self) -> crate::Result<VerifiedPublicKey> {
        Ok(self.verifying_key.clone())
    }

    /// The evidence attester key identifier.
    pub fn key_id(&self) -> String {
        attester_key_id(&self.verifying_key)
    }
}

impl Signer for LocalSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn verifying_key(&self) -> &VerifiedPublicKey {
        &self.verifying_key
    }

    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.signing_key.sign(message).to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVIDENCE_V1: &[u8] = b"PRAETORE_EVIDENCE_V1\0";
    const EVIDENCE_V2: &[u8] = b"PRAETORE_EVIDENCE_V2\0";

    #[test]
    fn algorithm_identifiers_round_trip_exactly() {
        for algorithm in [
            SignatureAlgorithm::Ed25519,
            SignatureAlgorithm::Ed25519Sha256Envelope,
        ] {
            assert_eq!(
                SignatureAlgorithm::from_identifier(algorithm.as_str()),
                Some(algorithm)
            );
        }
        for unknown in [
            "",
            "Ed25519",
            "ed25519 ",
            "ed25519ph",
            "ED25519-SHA256-ENVELOPE",
            "ed25519-sha256",
        ] {
            assert_eq!(SignatureAlgorithm::from_identifier(unknown), None);
        }
    }

    #[test]
    fn envelope_message_has_fixed_layout_and_size() {
        let payload = vec![b'x'; 100_000];
        let message =
            SignatureAlgorithm::Ed25519Sha256Envelope.signing_message(EVIDENCE_V2, &payload);
        assert!(message.starts_with(ENVELOPE_DOMAIN));
        assert_eq!(
            &message[ENVELOPE_DOMAIN.len()..ENVELOPE_DOMAIN.len() + EVIDENCE_V2.len()],
            EVIDENCE_V2
        );
        assert_eq!(
            &message[ENVELOPE_DOMAIN.len() + EVIDENCE_V2.len()..],
            Sha256::digest(&payload).as_slice()
        );
        assert_eq!(
            message.len(),
            ENVELOPE_DOMAIN.len() + EVIDENCE_V2.len() + 32
        );
        assert_eq!(message.len(), 99);
        assert!(message.len() <= 4096);
    }

    #[test]
    fn envelope_domain_is_not_confusable_with_receipt_domains() {
        for domain in [
            &b"PRAETORE_EVIDENCE_V1\0"[..],
            b"PRAETORE_EVIDENCE_V2\0",
            b"PRAETORE_EXECUTION_ATTESTATION_V1\0",
            b"PRAETORE_AUTHORITY_V1\0",
            b"PRAETORE_INTENT_V1\0",
            b"PRAETORE_INTENT_V2\0",
            b"PRAETORE_HUMAN_APPROVAL_V1\0",
            b"PRAETORE_KEY_ROTATION_V1\0",
        ] {
            assert!(!ENVELOPE_DOMAIN.starts_with(domain));
            assert!(!domain.starts_with(ENVELOPE_DOMAIN));
        }
    }

    #[test]
    fn a_signature_verifies_only_under_the_algorithm_it_was_made_with() {
        let signer = LocalSigner::from_secret_bytes(&[5; 32]);
        let payload = br#"{"receipt":"payload"}"#;
        for domain in [EVIDENCE_V1, EVIDENCE_V2] {
            let legacy =
                sign_message(&signer, SignatureAlgorithm::Ed25519, domain, payload).unwrap();
            let envelope = sign_message(
                &signer,
                SignatureAlgorithm::Ed25519Sha256Envelope,
                domain,
                payload,
            )
            .unwrap();
            let key = signer.verifying_key();
            assert!(
                SignatureAlgorithm::Ed25519
                    .verify(key, domain, payload, &legacy)
                    .is_ok()
            );
            assert!(
                SignatureAlgorithm::Ed25519Sha256Envelope
                    .verify(key, domain, payload, &envelope)
                    .is_ok()
            );
            // Prehash signature presented as legacy, and the reverse.
            assert!(
                SignatureAlgorithm::Ed25519
                    .verify(key, domain, payload, &envelope)
                    .is_err()
            );
            assert!(
                SignatureAlgorithm::Ed25519Sha256Envelope
                    .verify(key, domain, payload, &legacy)
                    .is_err()
            );
            // A legacy signature over the envelope bytes themselves is not an
            // envelope signature for that payload either.
            let raw_envelope_bytes =
                SignatureAlgorithm::Ed25519Sha256Envelope.signing_message(domain, payload);
            let legacy_over_envelope_bytes = sign_message(
                &signer,
                SignatureAlgorithm::Ed25519,
                b"",
                &raw_envelope_bytes,
            )
            .unwrap();
            assert_eq!(legacy_over_envelope_bytes, envelope);
            assert!(
                SignatureAlgorithm::Ed25519
                    .verify(key, domain, &raw_envelope_bytes, &envelope)
                    .is_err()
            );
        }
    }

    #[test]
    fn envelope_binds_the_domain_and_the_payload() {
        let signer = LocalSigner::from_secret_bytes(&[6; 32]);
        let algorithm = SignatureAlgorithm::Ed25519Sha256Envelope;
        let signature = sign_message(&signer, algorithm, EVIDENCE_V1, b"payload").unwrap();
        let key = signer.verifying_key();
        assert!(
            algorithm
                .verify(key, EVIDENCE_V2, b"payload", &signature)
                .is_err()
        );
        assert!(
            algorithm
                .verify(key, EVIDENCE_V1, b"payloaD", &signature)
                .is_err()
        );
        let other = LocalSigner::from_secret_bytes(&[7; 32]);
        assert!(
            algorithm
                .verify(other.verifying_key(), EVIDENCE_V1, b"payload", &signature)
                .is_err()
        );
    }

    struct WrongKeySigner {
        claimed: LocalSigner,
        actual: LocalSigner,
        limit: Option<usize>,
    }

    impl Signer for WrongKeySigner {
        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::Ed25519
        }
        fn verifying_key(&self) -> &VerifiedPublicKey {
            self.claimed.verifying_key()
        }
        fn max_message_len(&self) -> Option<usize> {
            self.limit
        }
        fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
            self.actual.sign_raw(message)
        }
    }

    #[test]
    fn signatures_by_another_key_or_of_the_wrong_size_fail_closed() {
        let signer = WrongKeySigner {
            claimed: LocalSigner::from_secret_bytes(&[1; 32]),
            actual: LocalSigner::from_secret_bytes(&[2; 32]),
            limit: None,
        };
        assert_eq!(
            sign_message(&signer, SignatureAlgorithm::Ed25519, EVIDENCE_V1, b"x"),
            Err(SignerError::InvalidSignature)
        );

        struct Truncating(LocalSigner);
        impl Signer for Truncating {
            fn algorithm(&self) -> SignatureAlgorithm {
                SignatureAlgorithm::Ed25519
            }
            fn verifying_key(&self) -> &VerifiedPublicKey {
                self.0.verifying_key()
            }
            fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
                let mut signature = self.0.sign_raw(message)?;
                signature.pop();
                Ok(signature)
            }
        }
        assert_eq!(
            sign_exact(&Truncating(LocalSigner::from_secret_bytes(&[3; 32])), b"x"),
            Err(SignerError::InvalidSignature)
        );
    }

    #[test]
    fn the_size_limit_is_enforced_before_the_backend_is_called() {
        let signer = WrongKeySigner {
            claimed: LocalSigner::from_secret_bytes(&[1; 32]),
            actual: LocalSigner::from_secret_bytes(&[1; 32]),
            limit: Some(4096),
        };
        assert!(sign_exact(&signer, &[0; 4096]).is_ok());
        assert_eq!(
            sign_exact(&signer, &[0; 4097]),
            Err(SignerError::MessageTooLarge)
        );
        // The envelope keeps any payload under the limit.
        assert!(
            sign_message(
                &signer,
                SignatureAlgorithm::Ed25519Sha256Envelope,
                EVIDENCE_V2,
                &[0; 1 << 20]
            )
            .is_ok()
        );
    }

    #[test]
    fn local_signer_debug_does_not_print_the_secret() {
        let secret = [0xab; 32];
        let signer = LocalSigner::from_secret_bytes(&secret);
        let debug = format!("{signer:?}");
        assert!(!debug.contains(&hex::encode(secret)));
        assert!(!debug.contains("signing_key"));
        assert!(debug.contains(&signer.key_id()));
    }

    #[test]
    fn signer_errors_do_not_leak_and_map_to_stable_codes() {
        assert_eq!(
            crate::PraetoreError::from(SignerError::Unavailable).code(),
            "SIGNER_UNAVAILABLE"
        );
        for error in [
            SignerError::Rejected,
            SignerError::MessageTooLarge,
            SignerError::InvalidSignature,
        ] {
            assert_eq!(crate::PraetoreError::from(error).code(), "SIGNER_FAIL");
        }
    }
}
