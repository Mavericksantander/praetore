use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    canonical::parse_json_rejecting_duplicates,
    error::{PraetoreError, Result},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

const AGENT_KEY_FINGERPRINT_DOMAIN: &[u8] = b"PRAETORE_AGENT_KEY_V1\0ed25519\0";

pub(crate) const REQUEST_INTENT_DOMAIN: &[u8] = b"PRAETORE_INTENT_V1\0";
pub const PRAETORE_MOTTO: &str = "Be Bold. The Mighty Forces Will Come to Your Aid.";

/// Stable identifier for an agent.
///
/// This identifier is intentionally separate from cryptographic key material.
/// An AgentId identifies an agent; it does not, by itself, authenticate it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(Uuid);

impl AgentId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for AgentId {
    fn default() -> Self {
        Self::new()
    }
}

/// Public identity information associated with an agent.
///
/// The serialized key remains algorithm-tagged bytes for interoperability.
/// Call `verified_public_key` before using Ed25519 verification operations.
///
/// ```
/// use praetore_core::{AgentId, AgentKeyPair};
///
/// let key_pair = AgentKeyPair::generate();
/// let identity = key_pair.identity(AgentId::new());
/// assert!(identity.verified_public_key().is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentity {
    pub id: AgentId,
    pub public_key: Vec<u8>,
    pub key_algorithm: String,
}

impl AgentIdentity {
    pub fn from_json(json: &str) -> Result<Self> {
        let value =
            parse_json_rejecting_duplicates(json).map_err(PraetoreError::InvalidIdentity)?;
        let identity: Self = serde_json::from_value(value)
            .map_err(|error| PraetoreError::InvalidIdentity(error.to_string()))?;
        identity.validate()?;
        Ok(identity)
    }

    pub fn new(id: AgentId, public_key: Vec<u8>, key_algorithm: impl Into<String>) -> Result<Self> {
        let identity = Self {
            id,
            public_key,
            key_algorithm: key_algorithm.into(),
        };

        identity.validate()?;

        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        if self.public_key.is_empty() {
            return Err(PraetoreError::InvalidIdentity(
                "public key cannot be empty".into(),
            ));
        }
        if self.public_key.len() > 4096 {
            return Err(PraetoreError::InvalidIdentity(
                "public key exceeds maximum size".into(),
            ));
        }

        if self.key_algorithm.trim().is_empty() {
            return Err(PraetoreError::InvalidIdentity(
                "key algorithm cannot be empty".into(),
            ));
        }

        if self.key_algorithm != self.key_algorithm.trim() {
            return Err(PraetoreError::InvalidIdentity(
                "key algorithm cannot have leading or trailing whitespace".into(),
            ));
        }

        Ok(())
    }

    pub fn verified_public_key(&self) -> Result<VerifiedPublicKey> {
        if self.key_algorithm != "ed25519" {
            return Err(PraetoreError::IdentityVerificationFailed);
        }

        VerifiedPublicKey::from_bytes(&self.public_key)
    }

    pub fn key_fingerprint(&self) -> Result<AgentKeyFingerprint> {
        Ok(AgentKeyFingerprint::from_verified_key(
            &self.verified_public_key()?,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentKeyFingerprint([u8; 32]);

impl AgentKeyFingerprint {
    pub fn from_verified_key(key: &VerifiedPublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(AGENT_KEY_FINGERPRINT_DOMAIN);
        hasher.update(key.as_bytes());
        Self(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

pub struct AgentKeyPair {
    signing_key: SigningKey,
}

impl std::fmt::Debug for AgentKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKeyPair").finish_non_exhaustive()
    }
}

impl AgentKeyPair {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(secret),
        }
    }

    pub fn public_key(&self) -> VerifiedPublicKey {
        VerifiedPublicKey(self.signing_key.verifying_key())
    }

    pub fn identity(&self, id: AgentId) -> AgentIdentity {
        AgentIdentity {
            id,
            public_key: self.signing_key.verifying_key().to_bytes().to_vec(),
            key_algorithm: "ed25519".into(),
        }
    }

    pub(crate) fn sign_domain_message(&self, domain: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut message = Vec::with_capacity(domain.len() + payload.len());
        message.extend_from_slice(domain);
        message.extend_from_slice(payload);
        self.signing_key.sign(&message).to_bytes().to_vec()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPublicKey(VerifyingKey);

impl VerifiedPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| PraetoreError::IdentityVerificationFailed)?;

        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| PraetoreError::IdentityVerificationFailed)?;
        if key.is_weak() {
            return Err(PraetoreError::IdentityVerificationFailed);
        }
        Ok(Self(key))
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub(crate) fn as_verifying_key(&self) -> &VerifyingKey {
        &self.0
    }

    pub fn verify_domain_message(
        &self,
        domain: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let signature = Signature::from_slice(signature)
            .map_err(|_| PraetoreError::IdentityVerificationFailed)?;
        let mut message = Vec::with_capacity(domain.len() + payload.len());
        message.extend_from_slice(domain);
        message.extend_from_slice(payload);
        self.0
            .verify_strict(&message, &signature)
            .map_err(|_| PraetoreError::IdentityVerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_unique_agent_ids() {
        let first = AgentId::new();
        let second = AgentId::new();

        assert_ne!(first, second);
    }

    #[test]
    fn agent_id_exposes_underlying_uuid() {
        let id = AgentId::new();

        assert!(!id.as_uuid().is_nil());
    }

    #[test]
    fn key_fingerprint_is_derived_from_verified_public_key() {
        let key = AgentKeyPair::from_secret_bytes(&[7; 32]);
        let identity = key.identity(AgentId::new());
        let fingerprint = identity.key_fingerprint().unwrap();

        assert_eq!(
            fingerprint,
            AgentKeyFingerprint::from_verified_key(&key.public_key())
        );
        assert_eq!(
            fingerprint.to_hex(),
            "57caa81d5a974ba0d7f9c17ba230b54284fc656fd492df2f8bbe52eb8f23f67e"
        );
        assert_eq!(fingerprint.as_bytes().len(), 32);
        assert_eq!(fingerprint.to_hex().len(), 64);
        let second_alias = key.identity(AgentId::new());
        assert_ne!(identity.id, second_alias.id);
        assert_eq!(fingerprint, second_alias.key_fingerprint().unwrap());
    }

    #[test]
    fn rejects_empty_public_key() {
        let result = AgentIdentity::new(AgentId::new(), Vec::new(), "ed25519");

        assert!(matches!(result, Err(PraetoreError::InvalidIdentity(_))));
    }

    #[test]
    fn rejects_empty_algorithm() {
        let result = AgentIdentity::new(AgentId::new(), vec![1, 2, 3], "");

        assert!(matches!(result, Err(PraetoreError::InvalidIdentity(_))));
    }

    #[test]
    fn rejects_whitespace_algorithm() {
        let result = AgentIdentity::new(AgentId::new(), vec![1, 2, 3], "   ");

        assert!(matches!(result, Err(PraetoreError::InvalidIdentity(_))));
    }

    #[test]
    fn rejects_algorithm_with_surrounding_whitespace() {
        let result = AgentIdentity::new(AgentId::new(), vec![1, 2, 3], " ed25519 ");

        assert!(matches!(result, Err(PraetoreError::InvalidIdentity(_))));
    }

    #[test]
    fn accepts_valid_identity() {
        let identity = AgentKeyPair::generate().identity(AgentId::new());

        assert_eq!(identity.public_key.len(), 32);
        assert_eq!(identity.key_algorithm, "ed25519");
        assert!(identity.validate().is_ok());
        assert!(identity.verified_public_key().is_ok());
    }

    #[test]
    fn validate_rejects_tampered_identity() {
        let mut identity = AgentIdentity::new(AgentId::new(), vec![1, 2, 3], "ed25519").unwrap();

        identity.public_key.clear();

        assert!(matches!(
            identity.validate(),
            Err(PraetoreError::InvalidIdentity(_))
        ));
    }

    #[test]
    fn identity_json_parser_rejects_duplicate_fields() {
        assert!(
            AgentIdentity::from_json(
                r#"{"id":"00000000-0000-0000-0000-000000000000","id":"00000000-0000-0000-0000-000000000001","public_key":[1],"key_algorithm":"ed25519"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn generated_keypair_signatures_verify_only_for_matching_key_and_message() {
        let keypair = AgentKeyPair::generate();
        let public_key = keypair.public_key();
        let signature = keypair.sign_domain_message(REQUEST_INTENT_DOMAIN, b"request");

        assert!(
            public_key
                .verify_domain_message(REQUEST_INTENT_DOMAIN, b"request", &signature)
                .is_ok()
        );
        assert!(
            public_key
                .verify_domain_message(REQUEST_INTENT_DOMAIN, b"changed", &signature)
                .is_err()
        );
        assert!(
            AgentKeyPair::generate()
                .public_key()
                .verify_domain_message(REQUEST_INTENT_DOMAIN, b"request", &signature)
                .is_err()
        );
    }

    #[test]
    fn rejects_malformed_ed25519_public_key() {
        assert!(VerifiedPublicKey::from_bytes(&[0; 31]).is_err());
    }

    #[test]
    fn rejects_weak_ed25519_public_keys_before_they_are_fingerprinted() {
        assert!(VerifiedPublicKey::from_bytes(&[0; 32]).is_err());
    }
}
