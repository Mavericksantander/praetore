//! Gateway receipts and their signed execution attestations (schema v1, v2
//! and v3), with the signing and verification logic they need.
//!
//! This crate has no server dependencies so offline verifiers
//! (`praetore-verify`, the Python bindings) can use it. `praetore-gateway`
//! re-exports everything here.

use praetore_core::{Action, Authority, Evidence, PraetoreError, canonical::canonicalize_json};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

const ACTION_DIGEST_DOMAIN: &[u8] = b"PRAETORE_EXECUTION_ACTION_V1\0";
const EXECUTION_ATTESTATION_DOMAIN: &[u8] = b"PRAETORE_EXECUTION_ATTESTATION_V1\0";
const OUTPUT_DIGEST_DOMAIN: &[u8] = b"PRAETORE_EXECUTION_OUTPUT_V1\0";

/// Computes the stable digest used to bind one normalized action to an
/// execution key. The canonical v1 encoding is domain separated from core
/// policy, request and evidence hashes.
pub fn action_digest(action: &Action) -> Result<String, PraetoreError> {
    let json = serde_json::to_string(action)
        .map_err(|error| PraetoreError::InvalidRequest(error.to_string()))?;
    let canonical = canonicalize_json(&json)?;
    let mut hash = Sha256::new();
    hash.update(ACTION_DIGEST_DOMAIN);
    hash.update(canonical);
    Ok(hex::encode(hash.finalize()))
}

fn authority_tenant_id(authority: &Authority) -> Option<Uuid> {
    authority.tenant_id()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Allowed,
    RequiresApproval,
    Denied,
}

/// Final gateway-side state. `Dispatched` means the gateway durably committed
/// to invoking the adapter; it does not prove a remote system received a call.
///
/// `ApprovedPendingDispatch` exists only for `RequiresApproval`: a human
/// approved, and no dispatch has been claimed yet. Like `Authorized`, it is
/// intermediate and never appears in a [`GatewayReceipt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    NotDispatched,
    Authorized,
    ApprovedPendingDispatch,
    Dispatched,
    Executed,
    Confirmed,
    OutcomeUnknown,
    Failed,
}

/// Why an approved execution was closed as `NotDispatched` without ever
/// reaching the adapter. Signed into the closing [`ExecutionAttestation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotDispatchedReason {
    /// The approval window closed before dispatch was claimed.
    ApprovalExpired,
    /// Revalidation before the claim failed for a reason other than expiry.
    DispatchFailed,
    /// Reconciliation found the approval unclaimed after a restart.
    CrashRecovered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ExecutionAttestationError {
    #[error("execution attestation signer failed")]
    SignerFailed,
    #[error("execution attestation key identifier is invalid")]
    InvalidKeyId,
    #[error("execution attestation payload is invalid")]
    InvalidPayload,
    #[error("execution attestation signature is invalid")]
    InvalidSignature,
    #[error("execution attestation key does not match the pinned identifier")]
    KeyMismatch,
}

/// Signs gateway execution observations using an externally managed key.
///
/// `message` contains the PRÆTORE execution-attestation domain separator and
/// canonical payload. Implementations may delegate signing to a KMS/HSM.
pub trait ExecutionAttestationSigner: Send + Sync {
    fn key_id(&self) -> &str;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ExecutionAttestationError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAttestation {
    pub schema_version: u8,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub key_id: String,
    pub evidence_id: Uuid,
    pub request_id: Uuid,
    pub agent_id: Uuid,
    pub authorization: AuthorizationStatus,
    pub execution: ExecutionStatus,
    pub policy_digest: String,
    pub evidence_hash: String,
    pub action_digest: String,
    pub output_digest: Option<String>,
    pub observed_at: String,
    /// Present only on schema version 3: the closing attestation of an
    /// approved execution that was never dispatched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_dispatched_reason: Option<NotDispatchedReason>,
    pub signature: String,
}

#[derive(Serialize)]
struct ExecutionAttestationPayload<'a> {
    schema_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    key_id: &'a str,
    evidence_id: Uuid,
    request_id: Uuid,
    agent_id: Uuid,
    authorization: AuthorizationStatus,
    execution: ExecutionStatus,
    policy_digest: &'a str,
    evidence_hash: &'a str,
    action_digest: &'a str,
    output_digest: Option<&'a str>,
    observed_at: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_dispatched_reason: Option<NotDispatchedReason>,
}

impl ExecutionAttestation {
    /// Signs an execution observation. Used by the gateway; verifiers only
    /// need [`GatewayReceipt::verify_execution_attestation`].
    ///
    /// Only available with the `signing` feature (off by default), so offline
    /// verifiers cannot mint attestations that bypass the gateway's state
    /// machine.
    #[cfg(feature = "signing")]
    pub fn create(
        evidence: &Evidence,
        authorization: AuthorizationStatus,
        execution: ExecutionStatus,
        output: Option<&Value>,
        not_dispatched_reason: Option<NotDispatchedReason>,
        signer: &dyn ExecutionAttestationSigner,
    ) -> Result<Self, ExecutionAttestationError> {
        let key_id = signer.key_id();
        if key_id.is_empty() || key_id.len() > 256 || key_id.trim() != key_id {
            return Err(ExecutionAttestationError::InvalidKeyId);
        }
        // Intermediate states are never attested, and a reason is only
        // meaningful when closing an approved execution without dispatch.
        if matches!(
            execution,
            ExecutionStatus::Authorized
                | ExecutionStatus::ApprovedPendingDispatch
                | ExecutionStatus::Dispatched
        ) || not_dispatched_reason.is_some()
            && (execution != ExecutionStatus::NotDispatched
                || authorization != AuthorizationStatus::RequiresApproval)
        {
            return Err(ExecutionAttestationError::InvalidPayload);
        }
        let schema_version = if not_dispatched_reason.is_some() {
            3
        } else {
            2
        };
        if !evidence.verify_integrity()
            || !evidence.is_high_assurance_shape()
            || evidence.evaluation_mode.as_deref() != Some("high_assurance")
        {
            return Err(ExecutionAttestationError::InvalidPayload);
        }

        let observed_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
        let policy_digest = evidence
            .policy_digest
            .as_deref()
            .ok_or(ExecutionAttestationError::InvalidPayload)?;
        let tenant_id = authority_tenant_id(&evidence.authority)
            .ok_or(ExecutionAttestationError::InvalidPayload)?;
        let action_digest = action_digest(&evidence.action)
            .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
        let output_digest = output.map(output_digest).transpose()?;
        let payload = ExecutionAttestationPayload {
            schema_version,
            tenant_id: Some(tenant_id),
            key_id,
            evidence_id: evidence.evidence_id,
            request_id: evidence.request_id,
            agent_id: *evidence.agent.id.as_uuid(),
            authorization,
            execution,
            policy_digest,
            evidence_hash: &evidence.context_hash,
            action_digest: &action_digest,
            output_digest: output_digest.as_deref(),
            observed_at: &observed_at,
            not_dispatched_reason,
        };
        let canonical = attestation_payload_bytes(&payload)?;
        let mut message = Vec::with_capacity(EXECUTION_ATTESTATION_DOMAIN.len() + canonical.len());
        message.extend_from_slice(EXECUTION_ATTESTATION_DOMAIN);
        message.extend_from_slice(&canonical);
        let signature = signer
            .sign(&message)
            .map_err(|_| ExecutionAttestationError::SignerFailed)?;
        if signature.len() != 64 {
            return Err(ExecutionAttestationError::InvalidSignature);
        }

        Ok(Self {
            schema_version,
            tenant_id: Some(tenant_id),
            key_id: key_id.to_owned(),
            evidence_id: evidence.evidence_id,
            request_id: evidence.request_id,
            agent_id: *evidence.agent.id.as_uuid(),
            authorization,
            execution,
            policy_digest: policy_digest.to_owned(),
            evidence_hash: evidence.context_hash.clone(),
            action_digest,
            output_digest,
            observed_at,
            not_dispatched_reason,
            signature: hex::encode(signature),
        })
    }

    fn verify(
        &self,
        evidence: &Evidence,
        authorization: AuthorizationStatus,
        execution: ExecutionStatus,
        output: Option<&Value>,
        public_key: &praetore_core::VerifiedPublicKey,
        expected_key_id: &str,
    ) -> Result<(), ExecutionAttestationError> {
        if self.key_id != expected_key_id {
            return Err(ExecutionAttestationError::KeyMismatch);
        }
        self.validate_binding(evidence, authorization, execution, output)?;

        let payload = ExecutionAttestationPayload {
            schema_version: self.schema_version,
            tenant_id: self.tenant_id,
            key_id: &self.key_id,
            evidence_id: self.evidence_id,
            request_id: self.request_id,
            agent_id: self.agent_id,
            authorization: self.authorization,
            execution: self.execution,
            policy_digest: &self.policy_digest,
            evidence_hash: &self.evidence_hash,
            action_digest: &self.action_digest,
            output_digest: self.output_digest.as_deref(),
            observed_at: &self.observed_at,
            not_dispatched_reason: self.not_dispatched_reason,
        };
        let canonical = attestation_payload_bytes(&payload)?;
        let signature = hex::decode(&self.signature)
            .map_err(|_| ExecutionAttestationError::InvalidSignature)?;
        public_key
            .verify_domain_message(EXECUTION_ATTESTATION_DOMAIN, &canonical, &signature)
            .map_err(|_| ExecutionAttestationError::InvalidSignature)
    }

    pub fn validate_binding(
        &self,
        evidence: &Evidence,
        authorization: AuthorizationStatus,
        execution: ExecutionStatus,
        output: Option<&Value>,
    ) -> Result<(), ExecutionAttestationError> {
        if !matches!(
            (
                self.schema_version,
                self.tenant_id,
                self.not_dispatched_reason
            ),
            (1, None, None) | (2, Some(_), None) | (3, Some(_), Some(_))
        ) || self.schema_version >= 2
            && self.tenant_id != authority_tenant_id(&evidence.authority)
            || self.not_dispatched_reason.is_some()
                && (authorization != AuthorizationStatus::RequiresApproval
                    || execution != ExecutionStatus::NotDispatched)
            || self.evidence_id != evidence.evidence_id
            || self.request_id != evidence.request_id
            || self.agent_id != *evidence.agent.id.as_uuid()
            || self.authorization != authorization
            || authorization_for_outcome(evidence.decision.outcome) != authorization
            || self.execution != execution
            || self.policy_digest != evidence.policy_digest.as_deref().unwrap_or_default()
            || self.evidence_hash != evidence.context_hash
            || !evidence.verify_integrity()
            || authorization == AuthorizationStatus::Denied
                && execution != ExecutionStatus::NotDispatched
            || authorization == AuthorizationStatus::RequiresApproval
                && !matches!(
                    execution,
                    ExecutionStatus::NotDispatched
                        | ExecutionStatus::Executed
                        | ExecutionStatus::Confirmed
                        | ExecutionStatus::OutcomeUnknown
                        | ExecutionStatus::Failed
                )
            || matches!(
                execution,
                ExecutionStatus::Authorized
                    | ExecutionStatus::ApprovedPendingDispatch
                    | ExecutionStatus::Dispatched
            )
            || output.is_some()
                != matches!(
                    execution,
                    ExecutionStatus::Executed | ExecutionStatus::Confirmed
                )
            || self.key_id.is_empty()
            || self.key_id.len() > 256
            || self.key_id.trim() != self.key_id
            || !is_canonical_signature_hex(&self.signature)
            || OffsetDateTime::parse(&self.observed_at, &Rfc3339).is_err()
        {
            return Err(ExecutionAttestationError::InvalidPayload);
        }

        let expected_action_digest = action_digest(&evidence.action)
            .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
        let expected_output_digest = output.map(output_digest).transpose()?;
        if self.action_digest != expected_action_digest
            || self.output_digest != expected_output_digest
        {
            return Err(ExecutionAttestationError::InvalidPayload);
        }
        Ok(())
    }
}

/// Accepts only the canonical encoding produced by `hex::encode`: exactly
/// 64 bytes as 128 lowercase hex digits. Uppercase or mixed case is rejected
/// so each receipt has a single valid encoding.
fn is_canonical_signature_hex(signature: &str) -> bool {
    signature.len() == 128
        && signature
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn authorization_for_outcome(outcome: praetore_core::DecisionOutcome) -> AuthorizationStatus {
    match outcome {
        praetore_core::DecisionOutcome::Allow => AuthorizationStatus::Allowed,
        praetore_core::DecisionOutcome::RequireApproval => AuthorizationStatus::RequiresApproval,
        praetore_core::DecisionOutcome::Deny => AuthorizationStatus::Denied,
    }
}

fn attestation_payload_bytes(
    payload: &ExecutionAttestationPayload<'_>,
) -> Result<Vec<u8>, ExecutionAttestationError> {
    let json =
        serde_json::to_string(payload).map_err(|_| ExecutionAttestationError::InvalidPayload)?;
    canonicalize_json(&json).map_err(|_| ExecutionAttestationError::InvalidPayload)
}

fn output_digest(output: &Value) -> Result<String, ExecutionAttestationError> {
    let json =
        serde_json::to_string(output).map_err(|_| ExecutionAttestationError::InvalidPayload)?;
    let bytes = canonicalize_json(&json).map_err(|_| ExecutionAttestationError::InvalidPayload)?;
    let mut hash = Sha256::new();
    hash.update(OUTPUT_DIGEST_DOMAIN);
    hash.update(&bytes);
    Ok(hex::encode(hash.finalize()))
}

/// A receipt keeps authorization evidence separate from the gateway's signed
/// observation of dispatch/execution. The attestation does not independently
/// prove an external effect beyond the adapter's documented contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayReceipt {
    pub evidence: Evidence,
    pub authorization: AuthorizationStatus,
    pub execution: ExecutionStatus,
    pub output: Option<Value>,
    pub execution_attestation: ExecutionAttestation,
}

impl GatewayReceipt {
    pub fn verify_execution_attestation(
        &self,
        public_key: &praetore_core::VerifiedPublicKey,
        expected_key_id: &str,
    ) -> Result<(), ExecutionAttestationError> {
        self.execution_attestation.verify(
            &self.evidence,
            self.authorization,
            self.execution,
            self.output.as_ref(),
            public_key,
            expected_key_id,
        )
    }
}

/// Parses a serialized [`GatewayReceipt`] and verifies its execution
/// attestation (schema v1, v2 or v3) against a pinned key.
///
/// Duplicate JSON keys, unknown fields and unknown `not_dispatched_reason`
/// values are rejected, as is a reason on anything but an approval closed
/// without dispatch. This proves historical integrity only; it never
/// authorizes an action.
pub fn verify_gateway_receipt_json(
    json: &str,
    public_key: &praetore_core::VerifiedPublicKey,
    expected_key_id: &str,
) -> Result<GatewayReceipt, ExecutionAttestationError> {
    let value = praetore_core::canonical::parse_json_rejecting_duplicates(json)
        .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
    let receipt: GatewayReceipt =
        serde_json::from_value(value).map_err(|_| ExecutionAttestationError::InvalidPayload)?;
    receipt.verify_execution_attestation(public_key, expected_key_id)?;
    Ok(receipt)
}
