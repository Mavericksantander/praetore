use ed25519_dalek::{Signature, Signer, SigningKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    action::Action,
    authority::Authority,
    authorization::{AuthorizationIntentV2, AuthorizationRequest},
    canonical::{
        MAX_JSON_VALUE_BYTES, canonical_json, parse_json_rejecting_duplicates, validate_json_value,
    },
    decision::{Decision, DecisionOutcome},
    identity::{AgentIdentity, VerifiedPublicKey},
    key_rotation::KeyRotationProof,
};

const EVIDENCE_SIGNATURE_DOMAIN: &[u8] = b"PRAETORE_EVIDENCE_V1\0";
const EVIDENCE_V2_SIGNATURE_DOMAIN: &[u8] = b"PRAETORE_EVIDENCE_V2\0";
const ATTESTER_KEY_ID_DOMAIN: &[u8] = b"PRAETORE_ATTESTER_KEY_V1\0ed25519\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// A versioned receipt binding an authorization request to its decision.
///
/// `verify_integrity` detects payload changes but does not authenticate who
/// produced the evidence. Verify any available agent, issuer, and attester
/// signatures against externally pinned keys. The end-to-end `quickstart`
/// example demonstrates those checks.
pub struct Evidence {
    pub evidence_schema_version: u16,
    pub canonical_version: u8,
    pub evidence_id: Uuid,
    pub request_id: Uuid,
    pub agent: AgentIdentity,
    pub authority: Authority,
    pub action: Action,
    pub decision: Decision,
    pub trace_id: Option<String>,
    pub context: BTreeMap<String, Value>,
    pub agent_signature: Option<String>,
    pub policy_digest: Option<String>,
    pub attester_key_id: Option<String>,
    pub attester_algorithm: Option<String>,
    pub attester_signature: Option<String>,
    pub context_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_v2: Option<AuthorizationIntentV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_valid_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics_version: Option<u8>,
}

pub struct EvidenceAttesterKey {
    signing_key: SigningKey,
}

impl std::fmt::Debug for EvidenceAttesterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidenceAttesterKey")
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

impl Clone for EvidenceAttesterKey {
    fn clone(&self) -> Self {
        Self {
            signing_key: self.signing_key.clone(),
        }
    }
}

impl EvidenceAttesterKey {
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

    pub fn public_key(&self) -> crate::Result<VerifiedPublicKey> {
        VerifiedPublicKey::from_bytes(&self.signing_key.verifying_key().to_bytes())
    }

    pub fn key_id(&self) -> String {
        key_id(self.signing_key.verifying_key().as_bytes())
    }
}

fn key_id(public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ATTESTER_KEY_ID_DOMAIN);
    hasher.update(public_key);
    hex::encode(hasher.finalize())
}

impl Evidence {
    pub fn new(
        request_id: Uuid,
        agent: AgentIdentity,
        authority: Authority,
        action: Action,
        decision: Decision,
        trace_id: Option<String>,
    ) -> crate::Result<Self> {
        Self::new_with_context(
            request_id,
            agent,
            authority,
            action,
            decision,
            trace_id,
            BTreeMap::new(),
        )
    }

    pub fn new_with_context(
        request_id: Uuid,
        agent: AgentIdentity,
        authority: Authority,
        action: Action,
        decision: Decision,
        trace_id: Option<String>,
        context: BTreeMap<String, Value>,
    ) -> crate::Result<Self> {
        let evidence_schema_version = if decision.recovery.is_some() { 3 } else { 1 };
        let mut evidence = Self {
            evidence_schema_version,
            canonical_version: crate::canonical::CANONICAL_VERSION,
            evidence_id: Uuid::new_v4(),
            request_id,
            agent,
            authority,
            action,
            decision,
            trace_id,
            context,
            agent_signature: None,
            policy_digest: None,
            attester_key_id: None,
            attester_algorithm: None,
            attester_signature: None,
            context_hash: String::new(),
            intent_v2: None,
            decided_at: None,
            evaluation_mode: None,
            freshness_valid_until: None,
            authority_digest: None,
            semantics_version: None,
        };
        evidence.context_hash = evidence.compute_context_hash().ok_or_else(|| {
            crate::PraetoreError::EvidenceError("evidence exceeds integrity limits".into())
        })?;
        Ok(evidence)
    }

    pub fn outcome(&self) -> DecisionOutcome {
        self.decision.outcome
    }

    /// Verifies the integrity of the evidence payload.
    ///
    /// This verifies that the evidence contents still correspond to the
    /// recorded SHA-256 context hash. It does not authenticate the issuer
    /// cryptographically and does not provide non-repudiation.
    pub fn verify_integrity(&self) -> bool {
        let has_recovery = self.decision.recovery.is_some();
        let shape_ok = match self.evidence_schema_version {
            1 => !self.has_v2_fields() && !has_recovery,
            2 => self.has_complete_v2_fields() && !has_recovery,
            // SAF-10: v3 is the only version that may carry a recovery
            // obligation; it is either a complete HighAssurance record or a
            // record without any v2 field.
            3 => has_recovery && (self.has_complete_v2_fields() || !self.has_v2_fields()),
            _ => false,
        };
        if !shape_ok
            || self.canonical_version != crate::canonical::CANONICAL_VERSION
            || self.decision.validate_recovery().is_err()
        {
            return false;
        }
        let Some(expected) = self.compute_context_hash() else {
            return false;
        };

        self.context_hash.len() == expected.len()
            && bool::from(self.context_hash.as_bytes().ct_eq(expected.as_bytes()))
    }

    /// Backwards-compatible alias for `verify_integrity`.
    pub fn verify(&self) -> bool {
        self.verify_integrity()
    }

    pub fn verify_agent_intent(&self) -> crate::Result<()> {
        AuthorizationRequest {
            request_id: self.request_id,
            agent: self.agent.clone(),
            authority: self.authority.clone(),
            action: self.action.clone(),
            trace_id: self.trace_id.clone(),
            context: self.context.clone(),
            agent_signature: self.agent_signature.clone(),
            intent_v2: self.intent_v2.clone(),
        }
        .verify_intent_signature()
    }

    pub fn verify_key_rotation(&self) -> crate::Result<KeyRotationProof> {
        if !self.verify_integrity() {
            return Err(crate::PraetoreError::EvidenceError(
                "evidence integrity verification failed".into(),
            ));
        }
        if self.action.action_type != "identity:rotate_key" {
            return Err(crate::PraetoreError::EvidenceError(
                "evidence does not describe a key rotation action".into(),
            ));
        }
        if self.decision.outcome != DecisionOutcome::Allow {
            return Err(crate::PraetoreError::EvidenceError(
                "key rotation was not authorized".into(),
            ));
        }
        self.verify_agent_intent()?;
        let proof_value = self
            .action
            .parameters
            .get("key_rotation_proof")
            .cloned()
            .ok_or_else(|| {
                crate::PraetoreError::EvidenceError("key rotation proof is missing".into())
            })?;
        let proof: KeyRotationProof = serde_json::from_value(proof_value).map_err(|_| {
            crate::PraetoreError::EvidenceError("key rotation proof is invalid".into())
        })?;
        proof
            .verify_new_key_possession(&self.agent, &self.authority, self.request_id)
            .map_err(|_| {
                crate::PraetoreError::EvidenceError("key rotation proof verification failed".into())
            })?;
        Ok(proof)
    }

    pub(crate) fn with_agent_signature(mut self, signature: Option<String>) -> crate::Result<Self> {
        self.agent_signature = signature;
        self.context_hash = self.compute_context_hash().ok_or_else(|| {
            crate::PraetoreError::EvidenceError("evidence exceeds integrity limits".into())
        })?;
        Ok(self)
    }

    pub(crate) fn with_intent_v2(
        mut self,
        intent_v2: Option<AuthorizationIntentV2>,
    ) -> crate::Result<Self> {
        self.intent_v2 = intent_v2;
        self.context_hash = self.compute_context_hash().ok_or_else(|| {
            crate::PraetoreError::EvidenceError("evidence exceeds integrity limits".into())
        })?;
        Ok(self)
    }

    pub(crate) fn bind_high_assurance_metadata(
        &mut self,
        decided_at: String,
        freshness_valid_until: String,
        authority_digest: String,
    ) -> crate::Result<()> {
        if self.intent_v2.is_none()
            || self.policy_digest.is_none()
            || !Self::is_sha256_hex(&authority_digest)
        {
            return Err(crate::PraetoreError::EvidenceError(
                "HighAssurance evidence metadata is incomplete".into(),
            ));
        }
        self.evidence_schema_version = if self.decision.recovery.is_some() {
            3
        } else {
            2
        };
        self.decided_at = Some(decided_at);
        self.evaluation_mode = Some("high_assurance".into());
        self.freshness_valid_until = Some(freshness_valid_until);
        self.authority_digest = Some(authority_digest);
        self.semantics_version = Some(2);
        self.context_hash = self.compute_context_hash().ok_or_else(|| {
            crate::PraetoreError::EvidenceError("evidence exceeds integrity limits".into())
        })?;
        Ok(())
    }

    pub fn sign(&mut self, attester: &EvidenceAttesterKey) -> crate::Result<()> {
        if !self.verify_integrity() {
            return Err(crate::PraetoreError::EvidenceError(
                "cannot sign evidence with invalid integrity hash".into(),
            ));
        }

        self.attester_key_id = Some(attester.key_id());
        self.attester_algorithm = Some("ed25519".into());
        self.attester_signature = None;
        self.context_hash = self.compute_context_hash().ok_or_else(|| {
            crate::PraetoreError::EvidenceError("evidence exceeds integrity limits".into())
        })?;
        let payload = self.attestation_bytes()?;
        let domain = self.attestation_domain();
        let mut message = Vec::with_capacity(domain.len() + payload.len());
        message.extend_from_slice(domain);
        message.extend_from_slice(&payload);
        self.attester_signature = Some(hex::encode(attester.signing_key.sign(&message).to_bytes()));
        Ok(())
    }

    pub fn verify_attester_signature(&self, trusted_key: &VerifiedPublicKey) -> crate::Result<()> {
        if !self.verify_integrity() {
            return Err(crate::PraetoreError::EvidenceError(
                "evidence integrity verification failed".into(),
            ));
        }
        if self.attester_algorithm.as_deref() != Some("ed25519")
            || self.attester_key_id.as_deref() != Some(key_id(&trusted_key.as_bytes()).as_str())
        {
            return Err(crate::PraetoreError::IdentityVerificationFailed);
        }

        let signature = self
            .attester_signature
            .as_deref()
            .ok_or(crate::PraetoreError::IdentityVerificationFailed)
            .and_then(|signature| {
                hex::decode(signature).map_err(|_| crate::PraetoreError::IdentityVerificationFailed)
            })?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| crate::PraetoreError::IdentityVerificationFailed)?;
        let payload = self.attestation_bytes()?;
        let domain = self.attestation_domain();
        let mut message = Vec::with_capacity(domain.len() + payload.len());
        message.extend_from_slice(domain);
        message.extend_from_slice(&payload);
        trusted_key
            .as_verifying_key()
            .verify_strict(&message, &signature)
            .map_err(|_| crate::PraetoreError::IdentityVerificationFailed)
    }

    pub fn to_json(&self) -> crate::Result<String> {
        if !self.verify_integrity() {
            return Err(crate::PraetoreError::EvidenceError(
                "cannot export evidence with invalid integrity hash".into(),
            ));
        }

        String::from_utf8(
            canonical_json(self)
                .map_err(|error| crate::PraetoreError::EvidenceError(error.to_string()))?,
        )
        .map_err(|error| crate::PraetoreError::EvidenceError(error.to_string()))
    }

    pub fn from_json(json: &str) -> crate::Result<Self> {
        if json.len() > MAX_JSON_VALUE_BYTES {
            return Err(crate::PraetoreError::EvidenceError(
                "evidence document exceeds maximum size".into(),
            ));
        }
        let value =
            parse_json_rejecting_duplicates(json).map_err(crate::PraetoreError::EvidenceError)?;
        let evidence: Self = serde_json::from_value(value)
            .map_err(|error| crate::PraetoreError::EvidenceError(error.to_string()))?;
        if !evidence.verify_integrity() {
            return Err(crate::PraetoreError::EvidenceError(
                "evidence integrity verification failed".into(),
            ));
        }
        if evidence.is_high_assurance_shape()
            && (evidence.attester_signature.is_none()
                || evidence.attester_key_id.is_none()
                || evidence.attester_algorithm.as_deref() != Some("ed25519"))
        {
            return Err(crate::PraetoreError::EvidenceError(
                "v2 evidence requires an attester signature".into(),
            ));
        }
        Ok(evidence)
    }

    pub fn bind_policy_digest(&mut self, digest: String) -> crate::Result<()> {
        if digest.len() != 64 || hex::decode(&digest).is_err() {
            return Err(crate::PraetoreError::EvidenceError(
                "policy digest must be a 32-byte SHA-256 hex value".into(),
            ));
        }

        self.policy_digest = Some(digest);
        self.context_hash = self.compute_context_hash().ok_or_else(|| {
            crate::PraetoreError::EvidenceError("evidence exceeds integrity limits".into())
        })?;
        Ok(())
    }

    fn compute_context_hash(&self) -> Option<String> {
        self.validate_integrity_inputs().ok()?;
        let payload = EvidenceIntegrityPayload {
            evidence_schema_version: self.evidence_schema_version,
            canonical_version: self.canonical_version,
            evidence_id: &self.evidence_id,
            request_id: &self.request_id,
            agent: &self.agent,
            authority: &self.authority,
            action: &self.action,
            decision: &self.decision,
            trace_id: &self.trace_id,
            context: &self.context,
            agent_signature: &self.agent_signature,
            policy_digest: &self.policy_digest,
            attester_key_id: &self.attester_key_id,
            attester_algorithm: &self.attester_algorithm,
            intent_v2: &self.intent_v2,
            decided_at: &self.decided_at,
            evaluation_mode: &self.evaluation_mode,
            freshness_valid_until: &self.freshness_valid_until,
            authority_digest: &self.authority_digest,
            semantics_version: &self.semantics_version,
        };

        Self::compute_payload_hash(&payload)
    }

    fn validate_integrity_inputs(&self) -> crate::Result<()> {
        self.agent.validate()?;
        if self.agent.public_key.len() > 4096 {
            return Err(crate::PraetoreError::EvidenceError(
                "agent key exceeds maximum size".into(),
            ));
        }
        self.authority.validate()?;
        self.action.validate()?;
        if self.context.len() > 128
            || self
                .context
                .keys()
                .any(|key| key.is_empty() || key.len() > 256)
        {
            return Err(crate::PraetoreError::EvidenceError(
                "evidence context exceeds configured limits".into(),
            ));
        }
        let mut context_size = 0usize;
        for (key, value) in &self.context {
            context_size += key.len();
            context_size += validate_json_value(value)
                .map_err(|message| crate::PraetoreError::EvidenceError(message.into()))?;
            if context_size > MAX_JSON_VALUE_BYTES {
                return Err(crate::PraetoreError::EvidenceError(
                    "evidence context exceeds maximum size".into(),
                ));
            }
        }
        if self.decision.reason.len() > 4096
            || self.decision.contributions.len() > 1024
            || self.decision.contributions.iter().any(|contribution| {
                contribution.rule_id.len() > 1024 || contribution.reason.len() > 4096
            })
        {
            return Err(crate::PraetoreError::EvidenceError(
                "evidence decision exceeds configured limits".into(),
            ));
        }
        if self
            .agent_signature
            .as_deref()
            .is_some_and(|value| value.len() > 128)
            || self
                .attester_signature
                .as_deref()
                .is_some_and(|value| value.len() > 128)
            || self
                .attester_key_id
                .as_deref()
                .is_some_and(|value| value.len() != 64)
            || self
                .attester_algorithm
                .as_deref()
                .is_some_and(|value| value != "ed25519")
            || self
                .policy_digest
                .as_deref()
                .is_some_and(|value| value.len() != 64)
            || self
                .authority_digest
                .as_deref()
                .is_some_and(|value| !Self::is_sha256_hex(value))
        {
            return Err(crate::PraetoreError::EvidenceError(
                "evidence cryptographic metadata is malformed".into(),
            ));
        }
        // v3 records without HighAssurance metadata (and the intermediate
        // state during attestation) are checked by `verify_integrity`'s shape
        // rule instead.
        if self.evidence_schema_version == 2
            || (self.evidence_schema_version == 3 && self.has_complete_v2_fields())
        {
            let intent = self.intent_v2.as_ref().ok_or_else(|| {
                crate::PraetoreError::EvidenceError("v2 intent metadata is missing".into())
            })?;
            crate::authorization::validate_intent_v2(intent)?;
            let decided_at = self
                .decided_at
                .as_deref()
                .and_then(parse_canonical_timestamp);
            let freshness_valid_until = self
                .freshness_valid_until
                .as_deref()
                .and_then(parse_canonical_timestamp);
            let issued_at = OffsetDateTime::parse(&intent.issued_at, &Rfc3339).map_err(|_| {
                crate::PraetoreError::EvidenceError("v2 intent timestamp is invalid".into())
            })?;
            let expires_at = OffsetDateTime::parse(&intent.expires_at, &Rfc3339).map_err(|_| {
                crate::PraetoreError::EvidenceError("v2 intent timestamp is invalid".into())
            })?;
            let policy_digest = self.policy_digest.as_deref();
            let authority_digest = self.authority_digest.as_deref();
            let expected_authority_digest = self.authority.content_digest()?;
            if decided_at.is_none()
                || freshness_valid_until.is_none()
                || policy_digest.is_none_or(|value| !Self::is_sha256_hex(value))
                || policy_digest != Some(intent.policy_digest.as_str())
                || authority_digest != Some(expected_authority_digest.as_str())
                || self.evaluation_mode.as_deref() != Some("high_assurance")
                || self.semantics_version != Some(2)
                || decided_at.is_some_and(|value| value < issued_at || value > expires_at)
                || decided_at
                    .zip(freshness_valid_until)
                    .is_some_and(|(decided_at, valid_until)| valid_until < decided_at)
            {
                return Err(crate::PraetoreError::EvidenceError(
                    "v2 evidence metadata is invalid or inconsistent".into(),
                ));
            }
        }
        Ok(())
    }

    fn attestation_bytes(&self) -> crate::Result<Vec<u8>> {
        self.validate_integrity_inputs()?;
        if !self.verify_integrity() {
            return Err(crate::PraetoreError::EvidenceError(
                "evidence integrity verification failed".into(),
            ));
        }
        canonical_json(&EvidenceAttestationPayload {
            evidence: EvidenceIntegrityPayload {
                evidence_schema_version: self.evidence_schema_version,
                canonical_version: self.canonical_version,
                evidence_id: &self.evidence_id,
                request_id: &self.request_id,
                agent: &self.agent,
                authority: &self.authority,
                action: &self.action,
                decision: &self.decision,
                trace_id: &self.trace_id,
                context: &self.context,
                agent_signature: &self.agent_signature,
                policy_digest: &self.policy_digest,
                attester_key_id: &self.attester_key_id,
                attester_algorithm: &self.attester_algorithm,
                intent_v2: &self.intent_v2,
                decided_at: &self.decided_at,
                evaluation_mode: &self.evaluation_mode,
                freshness_valid_until: &self.freshness_valid_until,
                authority_digest: &self.authority_digest,
                semantics_version: &self.semantics_version,
            },
            evidence_id: &self.evidence_id,
            context_hash: &self.context_hash,
        })
        .map_err(|error| crate::PraetoreError::EvidenceError(error.to_string()))
    }

    fn has_v2_fields(&self) -> bool {
        self.intent_v2.is_some()
            || self.decided_at.is_some()
            || self.evaluation_mode.is_some()
            || self.freshness_valid_until.is_some()
            || self.authority_digest.is_some()
            || self.semantics_version.is_some()
    }

    fn has_complete_v2_fields(&self) -> bool {
        self.intent_v2.is_some()
            && self.decided_at.is_some()
            && self.evaluation_mode.as_deref() == Some("high_assurance")
            && self.freshness_valid_until.is_some()
            && self
                .authority_digest
                .as_deref()
                .is_some_and(Self::is_sha256_hex)
            && self.semantics_version == Some(2)
            && self.policy_digest.is_some()
            && self.agent_signature.is_some()
    }

    /// True for v2, or v3 with complete HighAssurance metadata. Use this
    /// instead of comparing `evidence_schema_version` to 2.
    pub fn is_high_assurance_shape(&self) -> bool {
        matches!(self.evidence_schema_version, 2 | 3) && self.has_complete_v2_fields()
    }

    fn attestation_domain(&self) -> &'static [u8] {
        if self.is_high_assurance_shape() {
            EVIDENCE_V2_SIGNATURE_DOMAIN
        } else {
            EVIDENCE_SIGNATURE_DOMAIN
        }
    }

    fn compute_payload_hash(payload: &EvidenceIntegrityPayload<'_>) -> Option<String> {
        let serialized = canonical_json(payload).ok()?;
        Some(hex::encode(Sha256::digest(serialized)))
    }

    fn is_sha256_hex(value: &str) -> bool {
        value.len() == 64
            && hex::decode(value)
                .is_ok_and(|decoded| decoded.len() == 32 && hex::encode(decoded) == value)
    }
}

fn parse_canonical_timestamp(value: &str) -> Option<OffsetDateTime> {
    let timestamp = OffsetDateTime::parse(value, &Rfc3339).ok()?;
    let canonical = timestamp
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .ok()?;
    (canonical == value).then_some(timestamp)
}

#[derive(Serialize)]
struct EvidenceIntegrityPayload<'a> {
    evidence_schema_version: u16,
    canonical_version: u8,
    evidence_id: &'a Uuid,
    request_id: &'a Uuid,
    agent: &'a AgentIdentity,
    authority: &'a Authority,
    action: &'a Action,
    decision: &'a Decision,
    trace_id: &'a Option<String>,
    context: &'a BTreeMap<String, Value>,
    agent_signature: &'a Option<String>,
    policy_digest: &'a Option<String>,
    attester_key_id: &'a Option<String>,
    attester_algorithm: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    intent_v2: &'a Option<AuthorizationIntentV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decided_at: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evaluation_mode: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    freshness_valid_until: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority_digest: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantics_version: &'a Option<u8>,
}

#[derive(Serialize)]
struct EvidenceAttestationPayload<'a> {
    evidence: EvidenceIntegrityPayload<'a>,
    evidence_id: &'a Uuid,
    context_hash: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::Action,
        authority::Authority,
        decision::{Decision, DecisionContribution, DecisionOutcome},
        identity::{AgentId, AgentIdentity, AgentKeyPair},
    };
    use serde_json::json;

    fn test_agent() -> AgentIdentity {
        AgentIdentity::new(AgentId::new(), b"test-public-key".to_vec(), "ed25519").unwrap()
    }

    fn test_authority(agent: &AgentIdentity) -> Authority {
        Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()])
    }

    fn test_action() -> Action {
        Action::new(
            "read_data",
            Some("database".into()),
            json!({"table": "users"}),
        )
        .unwrap()
    }

    fn test_decision() -> Decision {
        Decision::allow("policy permitted action")
    }

    fn test_evidence() -> Evidence {
        let agent = test_agent();
        let authority = test_authority(&agent);

        Evidence::new(
            Uuid::new_v4(),
            agent,
            authority,
            test_action(),
            test_decision(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn creates_evidence_with_unique_id() {
        let first = test_evidence();
        let second = test_evidence();

        assert_ne!(first.evidence_id, second.evidence_id);
    }

    #[test]
    fn evidence_verifies_after_creation() {
        let evidence = test_evidence();

        assert!(evidence.verify());
        assert!(evidence.verify_integrity());
    }

    #[test]
    fn evidence_exposes_decision_outcome() {
        let evidence = test_evidence();

        assert_eq!(evidence.outcome(), DecisionOutcome::Allow);
    }

    #[test]
    fn trace_id_is_preserved_in_evidence() {
        let agent = test_agent();
        let authority = test_authority(&agent);

        let evidence = Evidence::new(
            Uuid::new_v4(),
            agent,
            authority,
            test_action(),
            test_decision(),
            Some("trace-001".into()),
        )
        .unwrap();

        assert_eq!(evidence.trace_id.as_deref(), Some("trace-001"));
        assert!(evidence.verify_integrity());
    }

    #[test]
    fn context_is_bound_to_integrity_hash() {
        let agent = test_agent();
        let authority = test_authority(&agent);
        let mut context = BTreeMap::new();
        context.insert("region".into(), json!("santiago"));
        let mut evidence = Evidence::new_with_context(
            Uuid::new_v4(),
            agent,
            authority,
            test_action(),
            test_decision(),
            None,
            context,
        )
        .unwrap();

        assert!(evidence.verify_integrity());
        evidence.context.insert("region".into(), json!("north"));
        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn policy_digest_is_bound_to_integrity_hash() {
        let mut evidence = test_evidence();
        let digest = hex::encode([42; 32]);

        evidence.bind_policy_digest(digest.clone()).unwrap();

        assert_eq!(evidence.policy_digest.as_deref(), Some(digest.as_str()));
        assert!(evidence.verify_integrity());
        evidence.policy_digest = Some(hex::encode([43; 32]));
        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_agent_signature_invalidates_evidence() {
        let evidence = test_evidence()
            .with_agent_signature(Some("00".repeat(64)))
            .unwrap();

        assert!(evidence.verify_integrity());
        let mut tampered = evidence;
        tampered.agent_signature = Some("11".repeat(64));
        assert!(!tampered.verify_integrity());
    }

    #[test]
    fn rejects_malformed_policy_digest() {
        let mut evidence = test_evidence();

        assert!(evidence.bind_policy_digest("not-a-digest".into()).is_err());
    }

    #[test]
    fn evidence_attester_signature_verifies_and_fails_after_tampering() {
        let attester = EvidenceAttesterKey::from_secret_bytes(&[51; 32]);
        let wrong_attester = EvidenceAttesterKey::from_secret_bytes(&[52; 32]);
        let mut evidence = test_evidence();

        evidence.bind_policy_digest(hex::encode([53; 32])).unwrap();
        evidence.sign(&attester).unwrap();

        assert!(
            evidence
                .verify_attester_signature(&attester.public_key().unwrap())
                .is_ok()
        );
        assert!(
            evidence
                .verify_attester_signature(&wrong_attester.public_key().unwrap())
                .is_err()
        );

        evidence.attester_signature = Some("00".repeat(64));
        assert!(
            evidence
                .verify_attester_signature(&attester.public_key().unwrap())
                .is_err()
        );
    }

    #[test]
    fn evidence_round_trip_exports_versioned_stable_json() {
        let attester = EvidenceAttesterKey::generate();
        let mut evidence = test_evidence();
        evidence.sign(&attester).unwrap();

        let json = evidence.to_json().unwrap();
        let restored = Evidence::from_json(&json).unwrap();

        assert_eq!(restored.evidence_schema_version, 1);
        assert_eq!(
            restored.canonical_version,
            crate::canonical::CANONICAL_VERSION
        );
        assert!(restored.verify_integrity());
        assert!(
            restored
                .verify_attester_signature(&attester.public_key().unwrap())
                .is_ok()
        );
    }

    #[test]
    fn evidence_v2_attestation_detects_rehashed_payload_tampering() {
        let agent_key = AgentKeyPair::from_secret_bytes(&[21; 32]);
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::from_secret_bytes(&[22; 32]);
        let mut authority = Authority::new(agent.id.clone(), "v2-issuer", vec!["data:read".into()])
            .with_validity(crate::authority::Validity {
                not_before: Some("2026-01-01T00:00:00Z".into()),
                not_after: Some("2027-01-01T00:00:00Z".into()),
            });
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let now = OffsetDateTime::parse("2026-06-01T12:00:00Z", &Rfc3339).unwrap();
        let policy_digest = "a".repeat(64);
        let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
        request
            .sign_intent_v2(
                &agent_key,
                "test-gateway",
                now,
                now + time::Duration::minutes(1),
                policy_digest.clone(),
            )
            .unwrap();
        let mut evidence = request.attest(Decision::allow("v2 allow")).unwrap();
        evidence.bind_policy_digest(policy_digest).unwrap();
        evidence
            .bind_high_assurance_metadata(
                "2026-06-01T12:00:00Z".into(),
                "2026-06-01T12:01:00Z".into(),
                evidence.authority.content_digest().unwrap(),
            )
            .unwrap();
        let attester = EvidenceAttesterKey::from_secret_bytes(&[23; 32]);
        evidence.sign(&attester).unwrap();
        let pinned_attester = attester.public_key().unwrap();

        assert_eq!(evidence.evidence_schema_version, 2);
        assert!(evidence.verify_integrity());
        assert!(evidence.verify_attester_signature(&pinned_attester).is_ok());
        assert!(Evidence::from_json(&evidence.to_json().unwrap()).is_ok());
        let mut document: Value = serde_json::from_str(&evidence.to_json().unwrap()).unwrap();
        document["future_field"] = json!(true);
        assert!(Evidence::from_json(&document.to_string()).is_err());

        evidence.decision = Decision::deny("tampered decision");
        evidence.context_hash = evidence.compute_context_hash().unwrap();

        assert!(evidence.verify_integrity());
        assert!(
            evidence
                .verify_attester_signature(&pinned_attester)
                .is_err()
        );
    }

    #[test]
    fn evidence_v1_matches_committed_trust_chain_golden_vector() {
        let golden: Value =
            serde_json::from_str(include_str!("../../../docs/golden/trust-chain-v1.json")).unwrap();
        let agent_key = AgentKeyPair::from_secret_bytes(&[7; 32]);
        let agent_id: AgentId =
            serde_json::from_str("\"00000000-0000-0000-0000-000000000002\"").unwrap();
        let agent = agent_key.identity(agent_id);
        let mut authority =
            Authority::new(agent.id.clone(), "golden-issuer", vec!["data:read".into()])
                .with_validity(crate::authority::Validity {
                    not_before: Some("2026-01-01T00:00:00Z".into()),
                    not_after: Some("2027-01-01T00:00:00Z".into()),
                });
        authority.id = serde_json::from_str("\"00000000-0000-0000-0000-000000000001\"").unwrap();
        authority
            .sign_for_agent(&AgentKeyPair::from_secret_bytes(&[8; 32]), &agent)
            .unwrap();
        let action = Action::new("read_data", Some("dataset".into()), json!({}))
            .unwrap()
            .with_capability("data:read");
        let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
        request.request_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
        request.sign_intent(&agent_key).unwrap();
        let mut evidence = request.attest(Decision::allow("golden allow")).unwrap();
        evidence.evidence_id = Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap();
        evidence.context_hash = evidence.compute_context_hash().unwrap();

        assert_eq!(
            evidence.context_hash,
            golden["evidence_context_hash"].as_str().unwrap()
        );
        assert_eq!(
            evidence.to_json().unwrap(),
            golden["evidence_json"].as_str().unwrap()
        );
        assert!(Evidence::from_json(golden["evidence_json"].as_str().unwrap()).is_ok());
    }

    #[test]
    fn evidence_import_rejects_duplicate_json_fields() {
        assert!(
            Evidence::from_json(r#"{"evidence_schema_version":1,"evidence_schema_version":1}"#)
                .is_err()
        );
    }

    #[test]
    fn evidence_import_rejects_unknown_fields_and_versions() {
        let evidence = test_evidence();
        let mut document: Value = serde_json::from_str(&evidence.to_json().unwrap()).unwrap();

        document["future_field"] = json!(true);
        assert!(Evidence::from_json(&document.to_string()).is_err());

        let mut document: Value = serde_json::from_str(&evidence.to_json().unwrap()).unwrap();
        document["agent"]["unexpected"] = json!("ignored fields are forbidden");
        assert!(Evidence::from_json(&document.to_string()).is_err());

        let mut document: Value = serde_json::from_str(&evidence.to_json().unwrap()).unwrap();
        document["authority"]["unexpected"] = json!("ignored fields are forbidden");
        assert!(Evidence::from_json(&document.to_string()).is_err());

        let mut document: Value = serde_json::from_str(&evidence.to_json().unwrap()).unwrap();
        document["action"]["unexpected"] = json!("ignored fields are forbidden");
        assert!(Evidence::from_json(&document.to_string()).is_err());

        let mut document: Value = serde_json::from_str(&evidence.to_json().unwrap()).unwrap();
        document["decision"]["unexpected"] = json!("ignored fields are forbidden");
        assert!(Evidence::from_json(&document.to_string()).is_err());

        let mut document: Value = serde_json::from_str(&evidence.to_json().unwrap()).unwrap();
        document["evidence_schema_version"] = json!(2);
        assert!(Evidence::from_json(&document.to_string()).is_err());

        let mut document: Value = serde_json::from_str(&evidence.to_json().unwrap()).unwrap();
        document["canonical_version"] = json!(2);
        assert!(Evidence::from_json(&document.to_string()).is_err());
    }

    #[test]
    fn evidence_import_rejects_oversized_documents() {
        let oversized = format!("{{\"padding\":\"{}\"}}", "x".repeat(MAX_JSON_VALUE_BYTES));
        assert!(Evidence::from_json(&oversized).is_err());
    }

    #[test]
    fn evidence_constructor_rejects_oversized_context() {
        let mut nested = json!(null);
        for _ in 0..=crate::canonical::MAX_JSON_DEPTH {
            nested = json!([nested]);
        }

        let agent = test_agent();
        let authority = test_authority(&agent);
        let context = BTreeMap::from([("oversized".into(), nested)]);

        assert!(
            Evidence::new_with_context(
                Uuid::new_v4(),
                agent,
                authority,
                test_action(),
                test_decision(),
                None,
                context,
            )
            .is_err()
        );
    }

    #[test]
    fn evidence_verification_fails_closed_for_oversized_nested_input() {
        let mut value = json!(0);
        for _ in 0..=crate::canonical::MAX_JSON_DEPTH {
            value = json!([value]);
        }

        let mut evidence = test_evidence();
        evidence.action.parameters = json!({"nested": value});

        assert!(!evidence.verify_integrity());
        assert!(evidence.to_json().is_err());
    }

    #[test]
    fn tampering_with_trace_id_invalidates_evidence() {
        let agent = test_agent();
        let authority = test_authority(&agent);

        let mut evidence = Evidence::new(
            Uuid::new_v4(),
            agent,
            authority,
            test_action(),
            test_decision(),
            Some("trace-001".into()),
        )
        .unwrap();

        evidence.trace_id = Some("trace-999".into());

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_action_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.action = Action::new(
            "delete_data",
            Some("database".into()),
            json!({"table": "users"}),
        )
        .unwrap();

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_action_parameters_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.action.parameters = json!({
            "table": "secrets"
        });

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_request_id_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.request_id = Uuid::new_v4();

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_agent_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.agent.public_key = b"tampered-public-key".to_vec();

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_agent_algorithm_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.agent.key_algorithm = "rsa".into();

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_authority_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.authority.issuer = "tampered-issuer".into();

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_authority_constraints_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence
            .authority
            .constraints
            .push(crate::authority::AuthorityConstraint::new(
                "environment",
                "production",
            ));

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_authority_validity_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.authority.validity.not_after = Some("2027-01-01T00:00:00Z".into());

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_decision_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.decision = Decision::deny("policy rejected action");

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_decision_reason_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.decision.reason = "tampered reason".into();

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_decision_contributions_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence
            .decision
            .contributions
            .push(DecisionContribution::new(
                "tampered-rule",
                DecisionOutcome::Deny,
                "tampered contribution",
            ));

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_evidence_id_invalidates_integrity_hash() {
        let mut evidence = test_evidence();

        evidence.evidence_id = Uuid::new_v4();

        assert!(!evidence.verify_integrity());
    }
}
