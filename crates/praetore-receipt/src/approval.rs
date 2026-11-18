//! Human-approval decisions and approval-expiration receipts: what they
//! sign and how they verify. Moved from `praetore-gateway` (which re-exports
//! everything here) so offline verifiers can check them without server
//! dependencies.

#[cfg(feature = "signing")]
use crate::ExecutionAttestationSigner;
use crate::{ExecutionAttestationError, action_digest};
use praetore_core::{Authority, DecisionOutcome, Evidence, canonical::canonicalize_json};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

const HUMAN_APPROVAL_DOMAIN: &[u8] = b"PRAETORE_HUMAN_APPROVAL_V1\0";
const APPROVAL_EXPIRED_DOMAIN: &[u8] = b"PRAETORE_APPROVAL_EXPIRED_V1\0";

/// A stable key for one signed request and its single permitted execution
/// attempt within a tenant. The tenant comes from the issuer-signed authority;
/// the request ID is signed as part of the authorization intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecutionKey {
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub request_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalChallenge {
    pub schema_version: u8,
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub request_id: Uuid,
    pub evidence_id: Uuid,
    pub evidence_hash: String,
    pub action_digest: String,
    pub policy_digest: String,
    pub expires_at: String,
}

impl ApprovalChallenge {
    pub fn from_evidence(evidence: &Evidence, action_digest: &str) -> Result<Self, ApprovalError> {
        let intent = evidence
            .intent_v2
            .as_ref()
            .ok_or(ApprovalError::InvalidChallenge)?;
        let intent_expiry = OffsetDateTime::parse(&intent.expires_at, &Rfc3339)
            .map_err(|_| ApprovalError::InvalidChallenge)?;
        let freshness_expiry = evidence
            .freshness_valid_until
            .as_deref()
            .ok_or(ApprovalError::InvalidChallenge)
            .and_then(|value| {
                OffsetDateTime::parse(value, &Rfc3339).map_err(|_| ApprovalError::InvalidChallenge)
            })?;
        let expires_at = intent_expiry.min(freshness_expiry);
        let expires_at = expires_at
            .to_offset(time::UtcOffset::UTC)
            .format(&Rfc3339)
            .map_err(|_| ApprovalError::InvalidChallenge)?;
        Ok(Self {
            schema_version: 1,
            tenant_id: authority_tenant_id(&evidence.authority)
                .ok_or(ApprovalError::InvalidChallenge)?,
            agent_id: *evidence.agent.id.as_uuid(),
            request_id: evidence.request_id,
            evidence_id: evidence.evidence_id,
            evidence_hash: evidence.context_hash.clone(),
            action_digest: action_digest.to_owned(),
            policy_digest: evidence
                .policy_digest
                .clone()
                .ok_or(ApprovalError::InvalidChallenge)?,
            expires_at,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanApprovalOutcome {
    Approve,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanApprovalDecision {
    pub schema_version: u8,
    pub approval_id: Uuid,
    pub approver_key_id: String,
    pub challenge: ApprovalChallenge,
    pub outcome: HumanApprovalOutcome,
    pub signature: String,
}

#[derive(Serialize)]
struct HumanApprovalPayload<'a> {
    schema_version: u8,
    approval_id: Uuid,
    approver_key_id: &'a str,
    challenge: &'a ApprovalChallenge,
    outcome: HumanApprovalOutcome,
}

impl HumanApprovalDecision {
    pub fn from_json(json: &str) -> Result<Self, ApprovalError> {
        if json.len() > 16_384 {
            return Err(ApprovalError::InvalidChallenge);
        }
        let value = praetore_core::canonical::parse_json_rejecting_duplicates(json)
            .map_err(|_| ApprovalError::InvalidChallenge)?;
        let decision =
            serde_json::from_value(value).map_err(|_| ApprovalError::InvalidChallenge)?;
        Ok(decision)
    }

    /// Returns the canonical payload that the approver signs with Ed25519.
    pub fn signing_payload(&self) -> Result<Vec<u8>, ApprovalError> {
        let payload = HumanApprovalPayload {
            schema_version: self.schema_version,
            approval_id: self.approval_id,
            approver_key_id: &self.approver_key_id,
            challenge: &self.challenge,
            outcome: self.outcome,
        };
        let json = serde_json::to_string(&payload).map_err(|_| ApprovalError::InvalidChallenge)?;
        canonicalize_json(&json).map_err(|_| ApprovalError::InvalidChallenge)
    }

    /// Verifies the approver's signature against a pinned approver key with
    /// key id `expected_key_id`. It does not check the challenge against a
    /// request; see [`ApprovalChallenge::from_evidence`].
    pub fn verify_signature(
        &self,
        expected_key_id: &str,
        public_key: &praetore_core::VerifiedPublicKey,
    ) -> Result<(), ApprovalError> {
        if self.schema_version != 1
            || self.approver_key_id != expected_key_id
            || self.approval_id.is_nil()
        {
            return Err(ApprovalError::InvalidSignature);
        }
        if !is_lower_hex(&self.signature) {
            return Err(ApprovalError::InvalidSignature);
        }
        let signature =
            hex::decode(&self.signature).map_err(|_| ApprovalError::InvalidSignature)?;
        public_key
            .verify_domain_message(HUMAN_APPROVAL_DOMAIN, &self.signing_payload()?, &signature)
            .map_err(|_| ApprovalError::InvalidSignature)
    }

    /// Whether the approver of this decision is the requesting agent: the
    /// approver key is the agent's key, or the key id is the agent's id.
    pub fn is_self_approval(
        &self,
        approver_key: &praetore_core::VerifiedPublicKey,
        evidence: &Evidence,
    ) -> bool {
        approver_key.as_bytes().as_slice() == evidence.agent.public_key.as_slice()
            || self.approver_key_id == evidence.agent.id.as_uuid().to_string()
    }

    pub fn signing_message(&self) -> Result<Vec<u8>, ApprovalError> {
        let payload = self.signing_payload()?;
        let mut message = Vec::with_capacity(HUMAN_APPROVAL_DOMAIN.len() + payload.len());
        message.extend_from_slice(HUMAN_APPROVAL_DOMAIN);
        message.extend_from_slice(&payload);
        Ok(message)
    }
}

/// The only effective outcome an expired approval can have (SAF-10
/// decision 3): silence never approves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiredOutcome {
    Deny,
}

/// Signed, persisted record that a human-approval window closed without a
/// signed decision (SAF-10). Exactly one exists per execution key, and never
/// together with a [`HumanApprovalDecision`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalExpiredReceipt {
    pub schema_version: u8,
    /// Unique identifier of this receipt (UUID v4), reported on HTTP 410.
    pub receipt_id: Uuid,
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub request_id: Uuid,
    pub evidence_id: Uuid,
    pub evidence_hash: String,
    pub action_digest: String,
    pub policy_digest: String,
    /// Same value as the approval challenge.
    pub expires_at: String,
    /// Engine clock at first detection, not the gateway host clock.
    pub observed_at: String,
    pub effective_outcome: ExpiredOutcome,
    pub gateway_key_id: String,
    pub signature: String,
}

#[derive(Serialize)]
struct ApprovalExpiredPayload<'a> {
    schema_version: u8,
    receipt_id: Uuid,
    tenant_id: Uuid,
    agent_id: Uuid,
    request_id: Uuid,
    evidence_id: Uuid,
    evidence_hash: &'a str,
    action_digest: &'a str,
    policy_digest: &'a str,
    expires_at: &'a str,
    observed_at: &'a str,
    effective_outcome: ExpiredOutcome,
    gateway_key_id: &'a str,
}

impl ApprovalExpiredReceipt {
    pub fn key(&self) -> ExecutionKey {
        ExecutionKey {
            tenant_id: self.tenant_id,
            agent_id: self.agent_id,
            request_id: self.request_id,
        }
    }

    fn payload(&self) -> ApprovalExpiredPayload<'_> {
        ApprovalExpiredPayload {
            schema_version: self.schema_version,
            receipt_id: self.receipt_id,
            tenant_id: self.tenant_id,
            agent_id: self.agent_id,
            request_id: self.request_id,
            evidence_id: self.evidence_id,
            evidence_hash: &self.evidence_hash,
            action_digest: &self.action_digest,
            policy_digest: &self.policy_digest,
            expires_at: &self.expires_at,
            observed_at: &self.observed_at,
            effective_outcome: self.effective_outcome,
            gateway_key_id: &self.gateway_key_id,
        }
    }

    fn payload_bytes(&self) -> Result<Vec<u8>, ExecutionAttestationError> {
        let json = serde_json::to_string(&self.payload())
            .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
        canonicalize_json(&json).map_err(|_| ExecutionAttestationError::InvalidPayload)
    }

    /// Signs the expiration of a pending approval. Used by the gateway;
    /// verifiers only need [`Self::verify`]. Only available with the
    /// `signing` feature, like [`ExecutionAttestation::create`].
    #[cfg(feature = "signing")]
    pub fn create(
        evidence: &Evidence,
        action_digest: &str,
        observed_at: OffsetDateTime,
        signer: &dyn ExecutionAttestationSigner,
    ) -> Result<Self, ExecutionAttestationError> {
        let key_id = signer.key_id();
        if key_id.is_empty() || key_id.len() > 256 || key_id.trim() != key_id {
            return Err(ExecutionAttestationError::InvalidKeyId);
        }
        let challenge = ApprovalChallenge::from_evidence(evidence, action_digest)
            .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
        let observed_at = observed_at
            .to_offset(time::UtcOffset::UTC)
            .format(&Rfc3339)
            .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
        let mut receipt = Self {
            schema_version: 1,
            receipt_id: Uuid::new_v4(),
            tenant_id: challenge.tenant_id,
            agent_id: challenge.agent_id,
            request_id: challenge.request_id,
            evidence_id: challenge.evidence_id,
            evidence_hash: challenge.evidence_hash,
            action_digest: challenge.action_digest,
            policy_digest: challenge.policy_digest,
            expires_at: challenge.expires_at,
            observed_at,
            effective_outcome: ExpiredOutcome::Deny,
            gateway_key_id: key_id.to_owned(),
            signature: String::new(),
        };
        receipt.validate_binding(evidence)?;
        let canonical = receipt.payload_bytes()?;
        let mut message = Vec::with_capacity(APPROVAL_EXPIRED_DOMAIN.len() + canonical.len());
        message.extend_from_slice(APPROVAL_EXPIRED_DOMAIN);
        message.extend_from_slice(&canonical);
        let signature = signer
            .sign(&message)
            .map_err(|_| ExecutionAttestationError::SignerFailed)?;
        if signature.len() != 64 {
            return Err(ExecutionAttestationError::InvalidSignature);
        }
        receipt.signature = hex::encode(signature);
        Ok(receipt)
    }

    /// Checks that the receipt is bound to exactly this pending evidence and
    /// that it was observed at or after the challenge deadline.
    pub fn validate_binding(&self, evidence: &Evidence) -> Result<(), ExecutionAttestationError> {
        let expected = ApprovalChallenge::from_evidence(
            evidence,
            &action_digest(&evidence.action)
                .map_err(|_| ExecutionAttestationError::InvalidPayload)?,
        )
        .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
        let expires_at = OffsetDateTime::parse(&self.expires_at, &Rfc3339)
            .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
        let observed_at = OffsetDateTime::parse(&self.observed_at, &Rfc3339)
            .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
        if self.schema_version != 1
            || self.receipt_id.is_nil()
            || evidence.decision.outcome != DecisionOutcome::RequireApproval
            || self.tenant_id != expected.tenant_id
            || self.agent_id != expected.agent_id
            || self.request_id != expected.request_id
            || self.evidence_id != expected.evidence_id
            || self.evidence_hash != expected.evidence_hash
            || self.action_digest != expected.action_digest
            || self.policy_digest != expected.policy_digest
            || self.expires_at != expected.expires_at
            || observed_at < expires_at
            || self.gateway_key_id.is_empty()
            || self.gateway_key_id.len() > 256
            || self.gateway_key_id.trim() != self.gateway_key_id
        {
            return Err(ExecutionAttestationError::InvalidPayload);
        }
        Ok(())
    }

    /// Verifies binding and the gateway signature against a pinned key.
    pub fn verify(
        &self,
        evidence: &Evidence,
        public_key: &praetore_core::VerifiedPublicKey,
        expected_key_id: &str,
    ) -> Result<(), ExecutionAttestationError> {
        if self.gateway_key_id != expected_key_id {
            return Err(ExecutionAttestationError::KeyMismatch);
        }
        self.validate_binding(evidence)?;
        // Lowercase hex only, so a signature has a single valid encoding.
        if !is_lower_hex(&self.signature) {
            return Err(ExecutionAttestationError::InvalidSignature);
        }
        let signature = hex::decode(&self.signature)
            .map_err(|_| ExecutionAttestationError::InvalidSignature)?;
        if signature.len() != 64 {
            return Err(ExecutionAttestationError::InvalidSignature);
        }
        public_key
            .verify_domain_message(APPROVAL_EXPIRED_DOMAIN, &self.payload_bytes()?, &signature)
            .map_err(|_| ExecutionAttestationError::InvalidSignature)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ApprovalError {
    #[error("human approval is not configured")]
    NotConfigured,
    #[error("human approval verifier configuration is invalid")]
    InvalidVerifier,
    #[error("approval signature is invalid")]
    InvalidSignature,
    #[error("approval challenge does not match a pending request")]
    InvalidChallenge,
    #[error("approval request has expired")]
    Expired,
    #[error("execution is not awaiting human approval")]
    NotPending,
    #[error("the requesting agent cannot approve its own action")]
    SelfApproval,
}

fn authority_tenant_id(authority: &Authority) -> Option<Uuid> {
    authority.tenant_id()
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
