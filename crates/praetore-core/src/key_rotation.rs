use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    Result,
    authority::{Authority, AuthorityId},
    canonical::canonical_json,
    error::PraetoreError,
    identity::{AgentIdentity, AgentKeyFingerprint, AgentKeyPair, VerifiedPublicKey},
};

const KEY_ROTATION_DOMAIN: &[u8] = b"PRAETORE_KEY_ROTATION_V1\0";

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRotationProof {
    pub previous_key_fingerprint: String,
    pub new_key_fingerprint: String,
    pub new_public_key: String,
    pub subject: crate::identity::AgentId,
    pub authority_id: AuthorityId,
    pub request_id: Uuid,
    pub signature: String,
}

impl KeyRotationProof {
    pub fn sign(
        new_key: &AgentKeyPair,
        previous_identity: &AgentIdentity,
        authority: &Authority,
        request_id: Uuid,
    ) -> Result<Self> {
        previous_identity.validate()?;
        authority.validate()?;
        if authority.subject != previous_identity.id {
            return Err(PraetoreError::AuthorityVerificationFailed);
        }

        let previous_key = previous_identity.verified_public_key()?;
        let new_public_key = new_key.public_key();
        let previous_fingerprint = AgentKeyFingerprint::from_verified_key(&previous_key);
        let new_fingerprint = AgentKeyFingerprint::from_verified_key(&new_public_key);
        if previous_fingerprint == new_fingerprint {
            return Err(PraetoreError::InvalidRequest(
                "key rotation requires a different public key".into(),
            ));
        }

        let mut proof = Self {
            previous_key_fingerprint: previous_fingerprint.to_hex(),
            new_key_fingerprint: new_fingerprint.to_hex(),
            new_public_key: hex::encode(new_public_key.as_bytes()),
            subject: previous_identity.id.clone(),
            authority_id: authority.id.clone(),
            request_id,
            signature: String::new(),
        };
        let payload = proof.signing_bytes()?;
        proof.signature = hex::encode(new_key.sign_domain_message(KEY_ROTATION_DOMAIN, &payload));
        Ok(proof)
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|error| PraetoreError::InvalidRequest(error.to_string()))
    }

    pub fn verify_new_key_possession(
        &self,
        previous_identity: &AgentIdentity,
        authority: &Authority,
        request_id: Uuid,
    ) -> Result<()> {
        if !is_lower_hex(&self.previous_key_fingerprint, 64)
            || !is_lower_hex(&self.new_key_fingerprint, 64)
            || !is_lower_hex(&self.new_public_key, 64)
            || !is_lower_hex(&self.signature, 128)
        {
            return Err(PraetoreError::IdentityVerificationFailed);
        }
        if authority.subject != previous_identity.id
            || self.subject != previous_identity.id
            || self.authority_id != authority.id
            || self.request_id != request_id
        {
            return Err(PraetoreError::IdentityVerificationFailed);
        }

        let previous_key = previous_identity.verified_public_key()?;
        let new_key_bytes = hex::decode(&self.new_public_key)
            .map_err(|_| PraetoreError::IdentityVerificationFailed)?;
        let new_key = VerifiedPublicKey::from_bytes(&new_key_bytes)?;
        let previous_fingerprint = AgentKeyFingerprint::from_verified_key(&previous_key);
        let new_fingerprint = AgentKeyFingerprint::from_verified_key(&new_key);
        if previous_fingerprint.to_hex() != self.previous_key_fingerprint
            || new_fingerprint.to_hex() != self.new_key_fingerprint
            || previous_fingerprint == new_fingerprint
        {
            return Err(PraetoreError::IdentityVerificationFailed);
        }

        let signature_bytes =
            hex::decode(&self.signature).map_err(|_| PraetoreError::IdentityVerificationFailed)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| PraetoreError::IdentityVerificationFailed)?;
        let payload = self.signing_bytes()?;
        let mut message = Vec::with_capacity(KEY_ROTATION_DOMAIN.len() + payload.len());
        message.extend_from_slice(KEY_ROTATION_DOMAIN);
        message.extend_from_slice(&payload);
        new_key
            .as_verifying_key()
            .verify_strict(&message, &signature)
            .map_err(|_| PraetoreError::IdentityVerificationFailed)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(&KeyRotationPayload {
            canonical_version: crate::canonical::CANONICAL_VERSION,
            schema_version: 1,
            previous_key_fingerprint: &self.previous_key_fingerprint,
            new_key_fingerprint: &self.new_key_fingerprint,
            new_public_key: &self.new_public_key,
            subject: &self.subject,
            authority_id: &self.authority_id,
            request_id: self.request_id,
        })
        .map_err(|error| PraetoreError::InvalidRequest(error.to_string()))
    }
}

#[derive(Serialize)]
struct KeyRotationPayload<'a> {
    canonical_version: u8,
    schema_version: u8,
    previous_key_fingerprint: &'a str,
    new_key_fingerprint: &'a str,
    new_public_key: &'a str,
    subject: &'a crate::identity::AgentId,
    authority_id: &'a AuthorityId,
    request_id: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::Action, authorization::AuthorizationRequest, decision::Decision, identity::AgentId,
    };

    fn make_rotation_evidence() -> crate::evidence::Evidence {
        let old_key = AgentKeyPair::from_secret_bytes(&[11; 32]);
        let new_key = AgentKeyPair::from_secret_bytes(&[12; 32]);
        let agent = old_key.identity(AgentId::new());
        let authority = Authority::new(agent.id.clone(), "issuer", vec!["identity:rotate".into()]);
        let action = Action::new("identity:rotate_key", None, serde_json::json!({}))
            .unwrap()
            .with_capability("identity:rotate");
        let mut request =
            AuthorizationRequest::new(agent.clone(), authority.clone(), action).unwrap();
        let proof =
            KeyRotationProof::sign(&new_key, &agent, &authority, request.request_id).unwrap();
        request.action.parameters = serde_json::json!({
            "key_rotation_proof": proof.to_value().unwrap()
        });
        request.sign_intent(&old_key).unwrap();
        request
            .attest(Decision::allow(
                "rotation permitted",
                crate::DecidedBy::rule("test-rule"),
            ))
            .unwrap()
    }

    #[test]
    fn rotation_evidence_verifies_new_key_possession() {
        let evidence = make_rotation_evidence();
        let proof = evidence.verify_key_rotation().unwrap();
        assert_eq!(proof.request_id, evidence.request_id);
        assert_eq!(proof.subject, evidence.agent.id);
        assert_eq!(proof.authority_id, evidence.authority.id);
    }

    #[test]
    fn rotation_proof_rejects_missing_or_wrong_signature_and_modified_payload() {
        let evidence = make_rotation_evidence();
        let mut proof = evidence.verify_key_rotation().unwrap();

        proof.signature.clear();
        assert!(
            proof
                .verify_new_key_possession(
                    &evidence.agent,
                    &evidence.authority,
                    evidence.request_id
                )
                .is_err()
        );

        let mut proof = evidence.verify_key_rotation().unwrap();
        proof.new_public_key = hex::encode(
            AgentKeyPair::from_secret_bytes(&[99; 32])
                .public_key()
                .as_bytes(),
        );
        assert!(
            proof
                .verify_new_key_possession(
                    &evidence.agent,
                    &evidence.authority,
                    evidence.request_id
                )
                .is_err()
        );

        let mut proof = evidence.verify_key_rotation().unwrap();
        proof.new_key_fingerprint = hex::encode([0x42; 32]);
        assert!(
            proof
                .verify_new_key_possession(
                    &evidence.agent,
                    &evidence.authority,
                    evidence.request_id
                )
                .is_err()
        );
    }

    #[test]
    fn rotation_proof_cannot_be_replayed_for_another_request() {
        let evidence = make_rotation_evidence();
        let proof = evidence.verify_key_rotation().unwrap();
        assert!(
            proof
                .verify_new_key_possession(&evidence.agent, &evidence.authority, Uuid::new_v4())
                .is_err()
        );
    }

    #[test]
    fn rotation_evidence_detects_action_tampering() {
        let mut evidence = make_rotation_evidence();
        evidence.action.parameters["key_rotation_proof"]["request_id"] =
            serde_json::json!(Uuid::new_v4());
        assert!(evidence.verify_key_rotation().is_err());
        assert!(!evidence.verify_integrity());
    }
}
