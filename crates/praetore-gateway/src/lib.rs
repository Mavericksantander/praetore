//! A small synchronous reference boundary between PRÆTORE and a tool adapter.
//!
//! The gateway accepts only a signed [`AuthorizationRequest`], requires a
//! HighAssurance engine, and dispatches the exact [`Action`] carried by the
//! evidence produced by that evaluation. It never accepts historical
//! [`Evidence`] as an execution credential.
//!
//! [`ExecutionJournal`] implementations must atomically persist completed
//! HighAssurance evidence with the replay claim, then durably enforce
//! execution uniqueness and state transitions across all gateway instances.
//! This crate deliberately does not provide a network server. The test journal
//! is in-memory and is not suitable for deployment.
//!
//! ```compile_fail
//! use praetore_core::Evidence;
//! use praetore_gateway::{ActionDispatcher, ExecutionJournal, Gateway};
//!
//! fn historical_receipt_is_not_an_execution_request<D: ActionDispatcher, J: ExecutionJournal>(
//!     gateway: &Gateway,
//!     receipt: Evidence,
//! ) {
//!     let _ = gateway.execute(receipt);
//! }
//! ```
//!
//! ```compile_fail
//! use praetore_core::{AtomicAuthorizationCommit, Evidence, VerifiedPublicKey};
//!
//! fn historical_receipt_cannot_be_atomically_committed<C: AtomicAuthorizationCommit>(
//!     commit: &C,
//!     receipt: &Evidence,
//!     attester: &VerifiedPublicKey,
//! ) {
//!     let _ = commit.commit_authorization(receipt, attester);
//! }
//! ```
//!
//! ```compile_fail
//! use praetore_core::Action;
//! fn authorized_action_cannot_be_mutated_in_the_adapter(action: &Action) {
//!     action.parameters["value"] = serde_json::json!("changed");
//! }
//! ```
//!
//! Dispatching an approved action requires a [`DispatchPermit`], which only
//! [`Gateway::claim_dispatch`] can produce by consuming an
//! [`ApprovedPendingDispatch`]. Neither type is `Clone`, and neither can be
//! built outside this crate.
//!
//! ```
//! use praetore_gateway::{ApprovedPendingDispatch, Gateway, GatewayError, GatewayReceipt};
//!
//! fn approved_dispatch(
//!     gateway: &Gateway,
//!     pending: ApprovedPendingDispatch,
//! ) -> Result<GatewayReceipt, GatewayError> {
//!     let permit = gateway.claim_dispatch(pending)?;
//!     gateway.dispatch(permit)
//! }
//! ```
//!
//! Dispatching without a permit does not compile:
//!
//! ```compile_fail
//! use praetore_gateway::{ApprovedPendingDispatch, Gateway};
//!
//! fn dispatch_without_claim(gateway: &Gateway, pending: ApprovedPendingDispatch) {
//!     let _ = gateway.dispatch(pending);
//! }
//! ```
//!
//! A permit cannot be forged outside the crate:
//!
//! ```compile_fail
//! use praetore_gateway::{DispatchPermit, Gateway};
//!
//! fn forged_permit(gateway: &Gateway) {
//!     let _ = gateway.dispatch(DispatchPermit {});
//! }
//! ```
//!
//! A permit is consumed by its single dispatch:
//!
//! ```compile_fail
//! use praetore_gateway::{DispatchPermit, Gateway};
//!
//! fn dispatch_twice(gateway: &Gateway, permit: DispatchPermit) {
//!     let _ = gateway.dispatch(permit);
//!     let _ = gateway.dispatch(permit);
//! }
//! ```
//!
//! Neither typestate can be cloned:
//!
//! ```compile_fail
//! use praetore_gateway::DispatchPermit;
//!
//! fn clone_permit(permit: DispatchPermit) -> (DispatchPermit, DispatchPermit) {
//!     (permit.clone(), permit)
//! }
//! ```
//!
//! ```compile_fail
//! use praetore_gateway::ApprovedPendingDispatch;
//!
//! fn clone_pending(pending: ApprovedPendingDispatch) -> (ApprovedPendingDispatch, ApprovedPendingDispatch) {
//!     (pending.clone(), pending)
//! }
//! ```

use praetore_core::{
    Action, AtomicAuthorizationCommit, AtomicEvaluationError, Authority, AuthorizationCommitError,
    AuthorizationRequest, DecisionOutcome, EvaluationMode, Evidence, PraetoreError,
    canonical::canonicalize_json, engine::AuthorizationEngine, freshness::FreshnessError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

pub use praetore_receipt::{
    AuthorizationStatus, ExecutionAttestation, ExecutionAttestationError,
    ExecutionAttestationSigner, ExecutionStatus, GatewayReceipt, NotDispatchedReason,
    action_digest, verify_gateway_receipt_json,
};

pub mod http_api;
pub mod local_demo;

const HUMAN_APPROVAL_DOMAIN: &[u8] = b"PRAETORE_HUMAN_APPROVAL_V1\0";

/// Revalidation failures that say nothing about the approval itself and may
/// clear on their own: they must not permanently close an approved execution.
fn is_transient_authorization_error(error: &PraetoreError) -> bool {
    matches!(
        error,
        PraetoreError::TrustedClockUnavailable
            | PraetoreError::ReplayGuardUnavailable
            | PraetoreError::FreshnessCheckFailed(FreshnessError::Unavailable)
    )
}
const APPROVAL_EXPIRED_DOMAIN: &[u8] = b"PRAETORE_APPROVAL_EXPIRED_V1\0";

/// Returns the tenant UUID only when the authority contains exactly one
/// well-formed `tenant_id` constraint.
pub fn authority_tenant_id(authority: &Authority) -> Option<Uuid> {
    authority.tenant_id()
}

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

/// Externally visible state of a human-approval request, scoped to one
/// tenant/agent/request execution key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalResolution {
    Pending,
    /// Approved and either awaiting its single dispatch or dispatched.
    Approved,
    Rejected,
    /// The window closed without a signed decision.
    Expired,
    /// Approved, but the execution was closed without dispatch (expired
    /// before the claim, crash-recovered, or failed revalidation). The
    /// signed receipt carries the `not_dispatched_reason`.
    NotDispatched,
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

    fn create(
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

/// A pinned human-approver key.
///
/// A verifier built with [`HumanApprovalVerifier::for_tenant`] only verifies
/// decisions whose challenge belongs to that tenant. One built with
/// [`HumanApprovalVerifier::new`] is unscoped and approves for every tenant
/// the gateway serves; use it only for single-tenant deployments such as the
/// local demo.
#[derive(Debug, Clone)]
pub struct HumanApprovalVerifier {
    key_id: String,
    public_key: praetore_core::VerifiedPublicKey,
    tenant_id: Option<Uuid>,
}

impl HumanApprovalVerifier {
    /// Unscoped verifier: valid for every tenant. Single-tenant use only.
    pub fn new(
        key_id: impl Into<String>,
        public_key: praetore_core::VerifiedPublicKey,
    ) -> Result<Self, ApprovalError> {
        let key_id = key_id.into();
        if key_id.trim().is_empty() || key_id != key_id.trim() || key_id.len() > 256 {
            return Err(ApprovalError::InvalidVerifier);
        }
        Ok(Self {
            key_id,
            public_key,
            tenant_id: None,
        })
    }

    /// Verifier bound to exactly one tenant: it never verifies a decision
    /// for another tenant's execution.
    pub fn for_tenant(
        tenant_id: Uuid,
        key_id: impl Into<String>,
        public_key: praetore_core::VerifiedPublicKey,
    ) -> Result<Self, ApprovalError> {
        if tenant_id.is_nil() {
            return Err(ApprovalError::InvalidVerifier);
        }
        let mut verifier = Self::new(key_id, public_key)?;
        verifier.tenant_id = Some(tenant_id);
        Ok(verifier)
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// `None` for an unscoped (single-tenant) verifier.
    pub fn tenant_id(&self) -> Option<Uuid> {
        self.tenant_id
    }

    fn applies_to(&self, key_id: &str, tenant_id: Uuid) -> bool {
        self.key_id == key_id && self.tenant_id.is_none_or(|bound| bound == tenant_id)
    }

    fn verify(&self, decision: &HumanApprovalDecision) -> Result<(), ApprovalError> {
        if decision.schema_version != 1
            || decision.approver_key_id != self.key_id
            || decision.approval_id.is_nil()
        {
            return Err(ApprovalError::InvalidSignature);
        }
        let signature =
            hex::decode(&decision.signature).map_err(|_| ApprovalError::InvalidSignature)?;
        self.public_key
            .verify_domain_message(
                HUMAN_APPROVAL_DOMAIN,
                &decision.signing_payload()?,
                &signature,
            )
            .map_err(|_| ApprovalError::InvalidSignature)
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

/// Human-approval state of one execution key, with the execution state that
/// actually resulted from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalState {
    pub resolution: ApprovalResolution,
    pub execution: ExecutionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_dispatched_reason: Option<NotDispatchedReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum JournalError {
    #[error("execution key has already been recorded")]
    AlreadyRecorded,
    #[error("execution key conflicts with different signed request or action content")]
    ConflictingRequest,
    #[error("replay claim exists without its matching authorization record")]
    OrphanedReplayClaim,
    #[error("execution journal is unavailable")]
    Unavailable,
    #[error("execution journal state transition is invalid")]
    InvalidTransition,
    #[error("execution journal record is invalid")]
    InvalidRecord,
    #[error("human approval decision has already been recorded")]
    ApprovalAlreadyRecorded,
    #[error("approval window closed before dispatch was claimed")]
    ApprovalExpired,
}

#[derive(Debug, Clone)]
pub struct ExecutionRecord {
    pub key: ExecutionKey,
    pub evidence: Evidence,
    pub authorization: AuthorizationStatus,
    pub execution: ExecutionStatus,
    pub action_digest: String,
    pub output: Option<Value>,
    pub execution_attestation: Option<ExecutionAttestation>,
    pub human_approval: Option<HumanApprovalDecision>,
    /// SAF-10: present only when the approval window closed without a
    /// decision. Never together with `human_approval`.
    pub approval_expiration: Option<ApprovalExpiredReceipt>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReconciliationReport {
    Applied(Value),
    NotApplied,
    Unknown,
}

/// The journal is a security boundary, not merely a logging callback.
///
/// `AtomicAuthorizationCommit` must atomically persist the replay claim and
/// exact verified HighAssurance evidence before a tool can be invoked. It must
/// reject duplicate keys, distinguishing changed request/action content from
/// an exact duplicate. `mark_dispatched` must atomically transition only
/// Authorized to Dispatched. Terminal transitions are one-way. Implementations
/// must be durable and shared across instances in a production deployment.
pub trait ExecutionJournal: AtomicAuthorizationCommit + Send + Sync {
    fn mark_dispatched(&self, key: ExecutionKey) -> Result<(), JournalError>;

    fn record_terminal_attested(
        &self,
        key: ExecutionKey,
        execution: ExecutionStatus,
        output: Option<&Value>,
        attestation: &ExecutionAttestation,
    ) -> Result<(), JournalError>;

    fn record_attestation(
        &self,
        key: ExecutionKey,
        execution: ExecutionStatus,
        output: Option<&Value>,
        attestation: &ExecutionAttestation,
    ) -> Result<(), JournalError>;

    fn get(&self, key: ExecutionKey) -> Result<Option<ExecutionRecord>, JournalError>;

    /// Closes without dispatch: `Authorized` (allowed path) or
    /// `ApprovedPendingDispatch` (approval path, which requires an
    /// attestation carrying a [`NotDispatchedReason`]). Never dispatches.
    fn mark_not_dispatched_attested(
        &self,
        key: ExecutionKey,
        attestation: &ExecutionAttestation,
    ) -> Result<(), JournalError>;

    /// Stores the decision. `Approve` moves `NotDispatched` to
    /// `ApprovedPendingDispatch` in the same transaction and never to
    /// `Dispatched`. `now` is the engine's trusted clock; the decision is
    /// rejected when `expires_at <= now`. Must fail with
    /// `ApprovalAlreadyRecorded` when an approval expiration is already
    /// stored for the key.
    fn record_human_approval(
        &self,
        key: ExecutionKey,
        decision: &HumanApprovalDecision,
        now: OffsetDateTime,
    ) -> Result<(), JournalError>;

    /// The only transition to `Dispatched` for `RequiresApproval`: an atomic
    /// compare-and-set from `ApprovedPendingDispatch`, holding the row lock
    /// while the stored approval is revalidated against `now` (the engine's
    /// trusted clock). Fails with `ApprovalExpired` when the approval's
    /// `expires_at <= now`, and with `InvalidTransition` unless exactly one
    /// row changed. Of concurrent claims at most one succeeds.
    fn claim_dispatch(&self, key: ExecutionKey, now: OffsetDateTime) -> Result<(), JournalError>;

    /// SAF-10: persists the single expiration receipt for a pending approval
    /// (append-only). Idempotent: an existing receipt for the key is kept and
    /// `Ok` is returned. Fails with `ApprovalAlreadyRecorded` when a human
    /// decision exists, and must check this atomically with that write.
    fn record_approval_expiration(
        &self,
        key: ExecutionKey,
        receipt: &ApprovalExpiredReceipt,
    ) -> Result<(), JournalError>;
}

/// An adapter receives the verified issuer-signed authority and exact
/// normalized action evaluated by the engine. Implementations must derive
/// tenant routing only from that authority, never from agent-controlled
/// action parameters or context. They must not silently broaden the operation.
pub trait ActionDispatcher: Send + Sync {
    fn dispatch(
        &self,
        key: ExecutionKey,
        authority: &Authority,
        action: &Action,
        action_digest: &str,
    ) -> Result<DispatchReport, DispatchError>;

    /// Read-only reconciliation hook. `Applied` or `NotApplied` must only be
    /// returned when the adapter can establish that fact for this key and
    /// action digest. The default is deliberately inconclusive.
    fn reconcile(
        &self,
        _key: ExecutionKey,
        _authority: &Authority,
        _action: &Action,
        _action_digest: &str,
    ) -> ReconciliationReport {
        ReconciliationReport::Unknown
    }
}

/// The adapter may report that it performed an operation or that it performed
/// and independently confirmed it. The strength of `Confirmed` depends on
/// the adapter's documented confirmation mechanism.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "output")]
pub enum DispatchReport {
    Executed(Value),
    Confirmed(Value),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("tool adapter returned an ambiguous failure")]
pub struct DispatchError;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("production gateway requires a HighAssurance authorization engine")]
    HighAssuranceRequired,
    #[error("authorization failed: {0}")]
    Authorization(#[from] PraetoreError),
    #[error("authorization engine returned invalid HighAssurance evidence")]
    InvalidEvidence,
    #[error("authorization authority has no valid tenant identity")]
    TenantIdentityInvalid,
    #[error("execution journal failed: {0}")]
    Journal(#[from] JournalError),
    #[error("tool outcome may have occurred but could not be journaled for {0:?}")]
    OutcomeNotRecorded(ExecutionKey),
    #[error("execution outcome was recorded but its attestation could not be created: {0}")]
    ExecutionAttestation(#[from] ExecutionAttestationError),
    #[error("execution record does not exist for {0:?}")]
    ExecutionNotFound(ExecutionKey),
    #[error("human approval failed: {0}")]
    Approval(#[from] ApprovalError),
}

/// Result of a signed human decision. An approval only records intent: the
/// execution is `approved_pending_dispatch` and nothing has run yet. A
/// rejection is final and carries its signed `not_dispatched` receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanApprovalResult {
    ApprovedPendingDispatch {
        decision: HumanApprovalDecision,
    },
    Rejected {
        decision: HumanApprovalDecision,
        receipt: Box<GatewayReceipt>,
    },
}

/// An approved execution whose dispatch has not been claimed. Only
/// [`Gateway::pending_dispatch`] creates it; [`Gateway::claim_dispatch`]
/// consumes it. Not `Clone`.
#[derive(Debug)]
pub struct ApprovedPendingDispatch {
    record: ExecutionRecord,
}

impl ApprovedPendingDispatch {
    pub fn key(&self) -> ExecutionKey {
        self.record.key
    }
}

/// The single right to invoke the adapter for one execution key, obtained
/// after the journal durably moved it to `Dispatched`. Only the gateway
/// creates it; [`Gateway::dispatch`] consumes it. Not `Clone`.
#[derive(Debug)]
pub struct DispatchPermit {
    key: ExecutionKey,
    evidence: Evidence,
    authorization: AuthorizationStatus,
    action_digest: String,
}

impl DispatchPermit {
    pub fn key(&self) -> ExecutionKey {
        self.key
    }
}

/// A synchronous gateway that binds a current authorization result to one
/// adapter invocation.
#[derive(Clone)]
pub struct Gateway {
    engine: AuthorizationEngine,
    journal: Arc<dyn ExecutionJournal>,
    dispatcher: Arc<dyn ActionDispatcher>,
    execution_attester: Arc<dyn ExecutionAttestationSigner>,
    approval_verifiers: Vec<HumanApprovalVerifier>,
}

impl Gateway {
    pub fn new(
        engine: AuthorizationEngine,
        journal: Arc<dyn ExecutionJournal>,
        dispatcher: Arc<dyn ActionDispatcher>,
        execution_attester: Arc<dyn ExecutionAttestationSigner>,
    ) -> Result<Self, GatewayError> {
        if engine.mode() != EvaluationMode::HighAssurance {
            return Err(GatewayError::HighAssuranceRequired);
        }
        Ok(Self {
            engine,
            journal,
            dispatcher,
            execution_attester,
            approval_verifiers: Vec::new(),
        })
    }

    /// Adds a pinned approver key. May be called once per approver; a
    /// decision is verified only by the single verifier whose key id matches
    /// and whose tenant scope covers the execution's tenant.
    pub fn with_human_approval_verifier(mut self, verifier: HumanApprovalVerifier) -> Self {
        self.approval_verifiers.push(verifier);
        self
    }

    /// Verifies a decision against the stored execution: the challenge must
    /// be the one derived from the persisted evidence, the approver key must
    /// be pinned for the execution's tenant, the signature must verify, and
    /// the requesting agent must not be the approver.
    fn verify_decision_for_record(
        &self,
        record: &ExecutionRecord,
        decision: &HumanApprovalDecision,
    ) -> Result<(), GatewayError> {
        if self.approval_verifiers.is_empty() {
            return Err(ApprovalError::NotConfigured.into());
        }
        let expected = ApprovalChallenge::from_evidence(&record.evidence, &record.action_digest)?;
        if decision.challenge != expected {
            return Err(ApprovalError::InvalidChallenge.into());
        }
        let mut candidates = self.approval_verifiers.iter().filter(|verifier| {
            verifier.applies_to(&decision.approver_key_id, record.key.tenant_id)
        });
        let verifier = match (candidates.next(), candidates.next()) {
            (Some(verifier), None) => verifier,
            _ => return Err(ApprovalError::InvalidSignature.into()),
        };
        verifier.verify(decision)?;
        if verifier.public_key.as_bytes().as_slice() == record.evidence.agent.public_key.as_slice()
            || decision.approver_key_id == record.evidence.agent.id.as_uuid().to_string()
        {
            return Err(ApprovalError::SelfApproval.into());
        }
        Ok(())
    }

    /// Independently re-checks, at claim time, that a `RequireApproval`
    /// execution carries a recorded, valid approval for exactly this action.
    /// `validate_evidence_for_dispatch` accepts `RequireApproval` evidence,
    /// so it must never be the only gate before dispatch.
    fn verify_recorded_approval(&self, record: &ExecutionRecord) -> Result<(), GatewayError> {
        if record.authorization != AuthorizationStatus::RequiresApproval
            || record.evidence.decision.outcome != DecisionOutcome::RequireApproval
        {
            return Err(GatewayError::InvalidEvidence);
        }
        let decision = record
            .human_approval
            .as_ref()
            .filter(|decision| decision.outcome == HumanApprovalOutcome::Approve)
            .ok_or(ApprovalError::NotPending)?;
        if action_digest(&record.evidence.action)? != record.action_digest {
            return Err(GatewayError::Journal(JournalError::InvalidRecord));
        }
        self.verify_decision_for_record(record, decision)
    }

    fn create_execution_attestation(
        &self,
        evidence: &Evidence,
        authorization: AuthorizationStatus,
        execution: ExecutionStatus,
        output: Option<&Value>,
    ) -> Result<ExecutionAttestation, GatewayError> {
        Ok(ExecutionAttestation::create(
            evidence,
            authorization,
            execution,
            output,
            None,
            self.execution_attester.as_ref(),
        )?)
    }

    /// Closes `ApprovedPendingDispatch` as `NotDispatched` with a signed
    /// reason. Never invokes the adapter.
    fn close_not_dispatched(
        &self,
        mut record: ExecutionRecord,
        reason: NotDispatchedReason,
    ) -> Result<GatewayReceipt, GatewayError> {
        let attestation = ExecutionAttestation::create(
            &record.evidence,
            record.authorization,
            ExecutionStatus::NotDispatched,
            None,
            Some(reason),
            self.execution_attester.as_ref(),
        )?;
        self.journal
            .mark_not_dispatched_attested(record.key, &attestation)?;
        record.execution = ExecutionStatus::NotDispatched;
        Ok(Self::receipt(
            record.evidence,
            record.authorization,
            record.execution,
            None,
            attestation,
        ))
    }

    fn receipt(
        evidence: Evidence,
        authorization: AuthorizationStatus,
        execution: ExecutionStatus,
        output: Option<Value>,
        execution_attestation: ExecutionAttestation,
    ) -> GatewayReceipt {
        GatewayReceipt {
            evidence,
            authorization,
            execution,
            output,
            execution_attestation,
        }
    }

    /// Returns the persisted SAF-10 expiration receipt for a key, if any.
    pub fn approval_expiration(
        &self,
        key: ExecutionKey,
    ) -> Result<Option<ApprovalExpiredReceipt>, GatewayError> {
        Ok(self
            .journal
            .get(key)?
            .and_then(|record| record.approval_expiration))
    }

    pub fn approval_challenge(&self, key: ExecutionKey) -> Result<ApprovalChallenge, GatewayError> {
        let record = self
            .journal
            .get(key)?
            .ok_or(GatewayError::ExecutionNotFound(key))?;
        if record.authorization != AuthorizationStatus::RequiresApproval
            || record.execution != ExecutionStatus::NotDispatched
            || record.human_approval.is_some()
        {
            return Err(ApprovalError::NotPending.into());
        }
        self.check_pending_approval_window(&record)?;
        Ok(ApprovalChallenge::from_evidence(
            &record.evidence,
            &record.action_digest,
        )?)
    }

    /// Reports the human-approval state of exactly one execution key. It never
    /// dispatches. On the first detection of an expired window it persists the
    /// single signed [`ApprovalExpiredReceipt`] (SAF-10); otherwise it does not
    /// change journal state. Returns
    /// `ApprovalError::NotPending` for executions that never required
    /// approval, and `ExecutionNotFound` for unknown keys.
    pub fn approval_resolution(
        &self,
        key: ExecutionKey,
    ) -> Result<ApprovalResolution, GatewayError> {
        Ok(self.approval_state(key)?.resolution)
    }

    /// [`Gateway::approval_resolution`] together with the execution state
    /// that resulted from it. An approved execution that was later closed
    /// without dispatch reports [`ApprovalResolution::NotDispatched`] and the
    /// signed `not_dispatched_reason`, never `approved`.
    pub fn approval_state(&self, key: ExecutionKey) -> Result<ApprovalState, GatewayError> {
        let record = self
            .journal
            .get(key)?
            .ok_or(GatewayError::ExecutionNotFound(key))?;
        let resolution = self.resolution_of(&record)?;
        let not_dispatched_reason = match record.execution {
            ExecutionStatus::NotDispatched => record
                .execution_attestation
                .as_ref()
                .and_then(|attestation| attestation.not_dispatched_reason),
            _ => None,
        };
        Ok(ApprovalState {
            resolution,
            execution: record.execution,
            not_dispatched_reason,
        })
    }

    fn resolution_of(&self, record: &ExecutionRecord) -> Result<ApprovalResolution, GatewayError> {
        if record.authorization != AuthorizationStatus::RequiresApproval {
            return Err(ApprovalError::NotPending.into());
        }
        if record.human_approval.is_some() && record.approval_expiration.is_some() {
            return Err(GatewayError::Journal(JournalError::InvalidRecord));
        }
        if record.approval_expiration.is_some() {
            return Ok(ApprovalResolution::Expired);
        }
        match &record.human_approval {
            Some(decision) => Ok(match decision.outcome {
                HumanApprovalOutcome::Approve
                    if record.execution == ExecutionStatus::NotDispatched =>
                {
                    ApprovalResolution::NotDispatched
                }
                HumanApprovalOutcome::Approve => ApprovalResolution::Approved,
                HumanApprovalOutcome::Reject => ApprovalResolution::Rejected,
            }),
            None if record.execution != ExecutionStatus::NotDispatched => {
                // A dispatched requires_approval record without a stored
                // decision is inconsistent; never report it as pending.
                Err(GatewayError::Journal(JournalError::InvalidRecord))
            }
            None => match self.check_pending_approval_window(record) {
                Ok(()) => Ok(ApprovalResolution::Pending),
                Err(GatewayError::Approval(ApprovalError::Expired)) => {
                    Ok(ApprovalResolution::Expired)
                }
                Err(error) => Err(error),
            },
        }
    }

    /// Validates and consumes a signed human decision exactly once. It never
    /// dispatches: an approval moves the execution to
    /// `ApprovedPendingDispatch`, and only [`Gateway::claim_dispatch`] can
    /// move it to `Dispatched`.
    pub fn resolve_human_approval(
        &self,
        decision: HumanApprovalDecision,
    ) -> Result<HumanApprovalResult, GatewayError> {
        if self.approval_verifiers.is_empty() {
            return Err(ApprovalError::NotConfigured.into());
        }
        let key = ExecutionKey {
            tenant_id: decision.challenge.tenant_id,
            agent_id: decision.challenge.agent_id,
            request_id: decision.challenge.request_id,
        };
        let mut record = self
            .journal
            .get(key)?
            .ok_or(GatewayError::ExecutionNotFound(key))?;
        if record.authorization != AuthorizationStatus::RequiresApproval
            || record.execution != ExecutionStatus::NotDispatched
            || record.human_approval.is_some()
        {
            return Err(ApprovalError::NotPending.into());
        }

        let expected = ApprovalChallenge::from_evidence(&record.evidence, &record.action_digest)?;
        if decision.challenge != expected {
            return Err(ApprovalError::InvalidChallenge.into());
        }
        self.check_pending_approval_window(&record)?;
        self.verify_decision_for_record(&record, &decision)?;
        if decision.outcome == HumanApprovalOutcome::Approve {
            self.engine
                .validate_evidence_for_dispatch(&record.evidence)
                .map_err(GatewayError::Authorization)?;
        }
        self.check_pending_approval_window(&record)?;
        let now = self
            .engine
            .trusted_now()
            .map_err(GatewayError::Authorization)?;
        self.journal.record_human_approval(key, &decision, now)?;
        record.human_approval = Some(decision.clone());

        match decision.outcome {
            HumanApprovalOutcome::Approve => {
                Ok(HumanApprovalResult::ApprovedPendingDispatch { decision })
            }
            HumanApprovalOutcome::Reject => {
                let receipt = self.attest_record(&mut record)?;
                Ok(HumanApprovalResult::Rejected {
                    decision,
                    receipt: Box::new(receipt),
                })
            }
        }
    }

    /// Loads an approved execution that has not been claimed yet. Fails with
    /// `ApprovalError::NotPending` for any other state.
    pub fn pending_dispatch(
        &self,
        key: ExecutionKey,
    ) -> Result<ApprovedPendingDispatch, GatewayError> {
        let record = self
            .journal
            .get(key)?
            .ok_or(GatewayError::ExecutionNotFound(key))?;
        let approved = record
            .human_approval
            .as_ref()
            .is_some_and(|decision| decision.outcome == HumanApprovalOutcome::Approve);
        if record.authorization != AuthorizationStatus::RequiresApproval
            || record.execution != ExecutionStatus::ApprovedPendingDispatch
            || !approved
            || record.approval_expiration.is_some()
        {
            return Err(ApprovalError::NotPending.into());
        }
        Ok(ApprovedPendingDispatch { record })
    }

    /// Re-verifies the recorded approval, revalidates the evidence with the
    /// engine clock and claims the single dispatch in the journal. On an
    /// expired window or a terminal revalidation failure the execution is
    /// closed as `NotDispatched` with a signed reason, and the error is
    /// returned. Transient failures (trusted clock, freshness source or
    /// replay storage unavailable) leave it `ApprovedPendingDispatch` so the
    /// claim can be attempted again. Never retries by itself.
    pub fn claim_dispatch(
        &self,
        pending: ApprovedPendingDispatch,
    ) -> Result<DispatchPermit, GatewayError> {
        let record = pending.record;
        // Fail closed without changing state: a record whose stored approval
        // no longer verifies is not dispatched, and is left for an operator.
        self.verify_recorded_approval(&record)?;
        if let Err(error) = self.engine.validate_evidence_for_dispatch(&record.evidence) {
            if is_transient_authorization_error(&error) {
                return Err(GatewayError::Authorization(error));
            }
            let reason = match error {
                PraetoreError::IntentInvalid
                | PraetoreError::FreshnessCheckFailed(FreshnessError::Expired) => {
                    NotDispatchedReason::ApprovalExpired
                }
                _ => NotDispatchedReason::DispatchFailed,
            };
            self.close_not_dispatched(record, reason)?;
            return Err(match reason {
                NotDispatchedReason::ApprovalExpired => ApprovalError::Expired.into(),
                _ => GatewayError::Authorization(error),
            });
        }
        let now = self
            .engine
            .trusted_now()
            .map_err(GatewayError::Authorization)?;
        match self.journal.claim_dispatch(record.key, now) {
            Ok(()) => Ok(DispatchPermit {
                key: record.key,
                evidence: record.evidence,
                authorization: record.authorization,
                action_digest: record.action_digest,
            }),
            Err(JournalError::ApprovalExpired) => {
                self.close_not_dispatched(record, NotDispatchedReason::ApprovalExpired)?;
                Err(ApprovalError::Expired.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Invokes the adapter once for a claimed execution and records the
    /// attested outcome. Adapter errors become `OutcomeUnknown`; never
    /// retries.
    pub fn dispatch(&self, permit: DispatchPermit) -> Result<GatewayReceipt, GatewayError> {
        let DispatchPermit {
            key,
            evidence,
            authorization,
            action_digest,
        } = permit;
        let (execution, output) = match self.dispatcher.dispatch(
            key,
            &evidence.authority,
            &evidence.action,
            &action_digest,
        ) {
            Ok(DispatchReport::Executed(output)) => (ExecutionStatus::Executed, Some(output)),
            Ok(DispatchReport::Confirmed(output)) => (ExecutionStatus::Confirmed, Some(output)),
            Err(_) => (ExecutionStatus::OutcomeUnknown, None),
        };
        let execution_attestation = self.create_execution_attestation(
            &evidence,
            authorization,
            execution,
            output.as_ref(),
        )?;
        self.journal
            .record_terminal_attested(key, execution, output.as_ref(), &execution_attestation)
            .map_err(|_| GatewayError::OutcomeNotRecorded(key))?;
        Ok(Self::receipt(
            evidence,
            authorization,
            execution,
            output,
            execution_attestation,
        ))
    }

    /// `pending_dispatch`, `claim_dispatch` and `dispatch` in sequence.
    pub fn dispatch_approved(&self, key: ExecutionKey) -> Result<GatewayReceipt, GatewayError> {
        let pending = self.pending_dispatch(key)?;
        let permit = self.claim_dispatch(pending)?;
        self.dispatch(permit)
    }

    /// Fails with `ApprovalError::Expired` once the window is closed. The
    /// first detection persists the signed expiration receipt; a journal or
    /// signer failure is returned instead (fail closed, nothing dispatched).
    fn check_pending_approval_window(&self, record: &ExecutionRecord) -> Result<(), GatewayError> {
        if record.approval_expiration.is_some() {
            return Err(ApprovalError::Expired.into());
        }
        match self.validate_approval_time_bounds(&record.evidence) {
            Err(GatewayError::Approval(ApprovalError::Expired)) => {
                self.record_approval_expiration(record)?;
                Err(ApprovalError::Expired.into())
            }
            other => other,
        }
    }

    fn record_approval_expiration(&self, record: &ExecutionRecord) -> Result<(), GatewayError> {
        let observed_at = self
            .engine
            .trusted_now()
            .map_err(GatewayError::Authorization)?;
        let receipt = ApprovalExpiredReceipt::create(
            &record.evidence,
            &record.action_digest,
            observed_at,
            self.execution_attester.as_ref(),
        )?;
        self.journal
            .record_approval_expiration(record.key, &receipt)?;
        Ok(())
    }

    fn validate_approval_time_bounds(&self, evidence: &Evidence) -> Result<(), GatewayError> {
        self.engine
            .validate_evidence_time_bounds(evidence)
            .map_err(|error| match error {
                PraetoreError::IntentInvalid
                | PraetoreError::FreshnessCheckFailed(FreshnessError::Expired) => {
                    GatewayError::Approval(ApprovalError::Expired)
                }
                error => GatewayError::Authorization(error),
            })
    }

    fn attest_record(&self, record: &mut ExecutionRecord) -> Result<GatewayReceipt, GatewayError> {
        if let Some(attestation) = &record.execution_attestation
            && attestation.execution == record.execution
        {
            attestation
                .validate_binding(
                    &record.evidence,
                    record.authorization,
                    record.execution,
                    record.output.as_ref(),
                )
                .map_err(|_| GatewayError::Journal(JournalError::InvalidRecord))?;
            return Ok(Self::receipt(
                record.evidence.clone(),
                record.authorization,
                record.execution,
                record.output.clone(),
                attestation.clone(),
            ));
        }

        let attestation = self.create_execution_attestation(
            &record.evidence,
            record.authorization,
            record.execution,
            record.output.as_ref(),
        )?;
        self.journal.record_attestation(
            record.key,
            record.execution,
            record.output.as_ref(),
            &attestation,
        )?;
        record.execution_attestation = Some(attestation.clone());
        Ok(Self::receipt(
            record.evidence.clone(),
            record.authorization,
            record.execution,
            record.output.clone(),
            attestation,
        ))
    }

    fn record_terminal_attested(
        &self,
        record: &mut ExecutionRecord,
        execution: ExecutionStatus,
        output: Option<Value>,
    ) -> Result<GatewayReceipt, GatewayError> {
        let attestation = self.create_execution_attestation(
            &record.evidence,
            record.authorization,
            execution,
            output.as_ref(),
        )?;
        self.journal
            .record_terminal_attested(record.key, execution, output.as_ref(), &attestation)
            .map_err(|_| GatewayError::OutcomeNotRecorded(record.key))?;
        record.execution = execution;
        record.output = output.clone();
        record.execution_attestation = Some(attestation.clone());
        Ok(Self::receipt(
            record.evidence.clone(),
            record.authorization,
            execution,
            output,
            attestation,
        ))
    }

    /// Evaluates a new signed request and, only for an exact `ALLOW`, records
    /// and dispatches its evidence-bound action once.
    ///
    /// Any adapter error is treated as outcome-unknown. The gateway never
    /// retries an operation automatically.
    pub fn execute(&self, request: AuthorizationRequest) -> Result<GatewayReceipt, GatewayError> {
        let evidence = self
            .engine
            .evaluate_with_atomic_commit(request, self.journal.as_ref())
            .map_err(map_atomic_evaluation_error)?;
        if !evidence.is_high_assurance_shape()
            || evidence.evaluation_mode.as_deref() != Some("high_assurance")
            || evidence.policy_digest.is_none()
            || !evidence.verify_integrity()
        {
            return Err(GatewayError::InvalidEvidence);
        }

        fn map_atomic_evaluation_error(error: AtomicEvaluationError) -> GatewayError {
            match error {
                AtomicEvaluationError::Evaluation(error) => GatewayError::Authorization(error),
                AtomicEvaluationError::Commit(error) => GatewayError::Journal(match error {
                    AuthorizationCommitError::AlreadyCommitted => JournalError::AlreadyRecorded,
                    AuthorizationCommitError::ConflictingRequest => {
                        JournalError::ConflictingRequest
                    }
                    AuthorizationCommitError::OrphanedReplayClaim => {
                        JournalError::OrphanedReplayClaim
                    }
                    AuthorizationCommitError::Unavailable | AuthorizationCommitError::NotFound => {
                        JournalError::Unavailable
                    }
                    AuthorizationCommitError::InvalidRecord => JournalError::InvalidRecord,
                }),
            }
        }

        let key = ExecutionKey {
            tenant_id: authority_tenant_id(&evidence.authority)
                .ok_or(GatewayError::TenantIdentityInvalid)?,
            agent_id: *evidence.agent.id.as_uuid(),
            request_id: evidence.request_id,
        };
        let authorization = match evidence.decision.outcome {
            DecisionOutcome::Allow => AuthorizationStatus::Allowed,
            DecisionOutcome::RequireApproval => AuthorizationStatus::RequiresApproval,
            DecisionOutcome::Deny => AuthorizationStatus::Denied,
        };

        if authorization != AuthorizationStatus::Allowed {
            let execution = ExecutionStatus::NotDispatched;
            let attestation =
                self.create_execution_attestation(&evidence, authorization, execution, None)?;
            self.journal
                .record_attestation(key, execution, None, &attestation)?;
            return Ok(Self::receipt(
                evidence,
                authorization,
                execution,
                None,
                attestation,
            ));
        }

        self.journal.mark_dispatched(key)?;
        if let Err(error) = self.engine.validate_evidence_for_dispatch(&evidence) {
            let execution = ExecutionStatus::Failed;
            let attestation =
                self.create_execution_attestation(&evidence, authorization, execution, None)?;
            self.journal
                .record_terminal_attested(key, execution, None, &attestation)
                .map_err(|_| GatewayError::OutcomeNotRecorded(key))?;
            return Err(GatewayError::Authorization(error));
        }
        let action_digest = action_digest(&evidence.action)?;
        self.dispatch(DispatchPermit {
            key,
            evidence,
            authorization,
            action_digest,
        })
    }

    /// Resolves persisted execution state without dispatching an action.
    ///
    /// Authorized operations are closed as not dispatched after restart.
    /// In-flight operations are marked ambiguous and may become terminal only
    /// when the adapter's read-only reconciliation contract establishes an
    /// outcome. This method never retries an effect. Callers must first quiesce
    /// and fence every worker that could still dispatch this execution; the
    /// journal cannot determine whether a paused worker will resume.
    pub fn reconcile(&self, key: ExecutionKey) -> Result<GatewayReceipt, GatewayError> {
        let mut record = self
            .journal
            .get(key)?
            .ok_or(GatewayError::ExecutionNotFound(key))?;

        match record.execution {
            ExecutionStatus::Authorized => {
                let execution_attestation = self.create_execution_attestation(
                    &record.evidence,
                    record.authorization,
                    ExecutionStatus::NotDispatched,
                    None,
                )?;
                self.journal
                    .mark_not_dispatched_attested(key, &execution_attestation)?;
                record.execution = ExecutionStatus::NotDispatched;
                record.execution_attestation = Some(execution_attestation.clone());
                return Ok(Self::receipt(
                    record.evidence,
                    record.authorization,
                    record.execution,
                    None,
                    execution_attestation,
                ));
            }
            ExecutionStatus::ApprovedPendingDispatch => {
                // Approved but never claimed: provably not dispatched. Closed
                // without retrying; a new request is required to run it.
                return self.close_not_dispatched(record, NotDispatchedReason::CrashRecovered);
            }
            ExecutionStatus::Dispatched | ExecutionStatus::OutcomeUnknown => {
                match self.dispatcher.reconcile(
                    key,
                    &record.evidence.authority,
                    &record.evidence.action,
                    &record.action_digest,
                ) {
                    ReconciliationReport::Applied(output) => {
                        return self.record_terminal_attested(
                            &mut record,
                            ExecutionStatus::Confirmed,
                            Some(output),
                        );
                    }
                    ReconciliationReport::NotApplied => {
                        return self.record_terminal_attested(
                            &mut record,
                            ExecutionStatus::Failed,
                            None,
                        );
                    }
                    ReconciliationReport::Unknown => {
                        if record.execution == ExecutionStatus::Dispatched {
                            return self.record_terminal_attested(
                                &mut record,
                                ExecutionStatus::OutcomeUnknown,
                                None,
                            );
                        }
                    }
                }
            }
            ExecutionStatus::NotDispatched
            | ExecutionStatus::Executed
            | ExecutionStatus::Confirmed
            | ExecutionStatus::Failed => {}
        }

        self.attest_record(&mut record)
    }
}
