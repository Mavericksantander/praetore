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

use praetore_core::{
    Action, AtomicAuthorizationCommit, AtomicEvaluationError, Authority, AuthorizationCommitError,
    AuthorizationRequest, DecisionOutcome, EvaluationMode, Evidence, PraetoreError,
    canonical::canonicalize_json, engine::AuthorizationEngine, freshness::FreshnessError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

pub mod http_api;
pub mod local_demo;

const ACTION_DIGEST_DOMAIN: &[u8] = b"PRAETORE_EXECUTION_ACTION_V1\0";
const EXECUTION_ATTESTATION_DOMAIN: &[u8] = b"PRAETORE_EXECUTION_ATTESTATION_V1\0";
const OUTPUT_DIGEST_DOMAIN: &[u8] = b"PRAETORE_EXECUTION_OUTPUT_V1\0";
const HUMAN_APPROVAL_DOMAIN: &[u8] = b"PRAETORE_HUMAN_APPROVAL_V1\0";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Allowed,
    RequiresApproval,
    Denied,
}

/// Final gateway-side state. `Dispatched` means the gateway durably committed
/// to invoking the adapter; it does not prove a remote system received a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    NotDispatched,
    Authorized,
    Dispatched,
    Executed,
    Confirmed,
    OutcomeUnknown,
    Failed,
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
    Approved,
    Rejected,
    Expired,
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

#[derive(Debug, Clone)]
pub struct HumanApprovalVerifier {
    key_id: String,
    public_key: praetore_core::VerifiedPublicKey,
}

impl HumanApprovalVerifier {
    pub fn new(
        key_id: impl Into<String>,
        public_key: praetore_core::VerifiedPublicKey,
    ) -> Result<Self, ApprovalError> {
        let key_id = key_id.into();
        if key_id.trim().is_empty() || key_id != key_id.trim() || key_id.len() > 256 {
            return Err(ApprovalError::InvalidVerifier);
        }
        Ok(Self { key_id, public_key })
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
}

impl ExecutionAttestation {
    fn create(
        evidence: &Evidence,
        authorization: AuthorizationStatus,
        execution: ExecutionStatus,
        output: Option<&Value>,
        signer: &dyn ExecutionAttestationSigner,
    ) -> Result<Self, ExecutionAttestationError> {
        let key_id = signer.key_id();
        if key_id.is_empty() || key_id.len() > 256 || key_id.trim() != key_id {
            return Err(ExecutionAttestationError::InvalidKeyId);
        }
        if !evidence.verify_integrity()
            || evidence.evidence_schema_version != 2
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
            schema_version: 2,
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
            schema_version: 2,
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
            (self.schema_version, self.tenant_id),
            (1, None) | (2, Some(_))
        ) || self.schema_version == 2
            && self.tenant_id != authority_tenant_id(&evidence.authority)
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
                ExecutionStatus::Authorized | ExecutionStatus::Dispatched
            )
            || output.is_some()
                != matches!(
                    execution,
                    ExecutionStatus::Executed | ExecutionStatus::Confirmed
                )
            || self.key_id.is_empty()
            || self.key_id.len() > 256
            || self.key_id.trim() != self.key_id
            || hex::decode(&self.signature).map_or(true, |signature| signature.len() != 64)
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

    fn mark_not_dispatched_attested(
        &self,
        key: ExecutionKey,
        attestation: &ExecutionAttestation,
    ) -> Result<(), JournalError>;

    fn record_human_approval(
        &self,
        key: ExecutionKey,
        decision: &HumanApprovalDecision,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanApprovalReceipt {
    pub decision: HumanApprovalDecision,
    pub receipt: GatewayReceipt,
}

/// A synchronous gateway that binds a current authorization result to one
/// adapter invocation.
#[derive(Clone)]
pub struct Gateway {
    engine: AuthorizationEngine,
    journal: Arc<dyn ExecutionJournal>,
    dispatcher: Arc<dyn ActionDispatcher>,
    execution_attester: Arc<dyn ExecutionAttestationSigner>,
    approval_verifier: Option<HumanApprovalVerifier>,
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
            approval_verifier: None,
        })
    }

    pub fn with_human_approval_verifier(mut self, verifier: HumanApprovalVerifier) -> Self {
        self.approval_verifier = Some(verifier);
        self
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
            self.execution_attester.as_ref(),
        )?)
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
        self.validate_approval_time_bounds(&record.evidence)?;
        Ok(ApprovalChallenge::from_evidence(
            &record.evidence,
            &record.action_digest,
        )?)
    }

    /// Reports the human-approval state of exactly one execution key. Read
    /// only; it never changes journal state or dispatches. Returns
    /// `ApprovalError::NotPending` for executions that never required
    /// approval, and `ExecutionNotFound` for unknown keys.
    pub fn approval_resolution(
        &self,
        key: ExecutionKey,
    ) -> Result<ApprovalResolution, GatewayError> {
        let record = self
            .journal
            .get(key)?
            .ok_or(GatewayError::ExecutionNotFound(key))?;
        if record.authorization != AuthorizationStatus::RequiresApproval {
            return Err(ApprovalError::NotPending.into());
        }
        match &record.human_approval {
            Some(decision) => Ok(match decision.outcome {
                HumanApprovalOutcome::Approve => ApprovalResolution::Approved,
                HumanApprovalOutcome::Reject => ApprovalResolution::Rejected,
            }),
            None if record.execution != ExecutionStatus::NotDispatched => {
                // A dispatched requires_approval record without a stored
                // decision is inconsistent; never report it as pending.
                Err(GatewayError::Journal(JournalError::InvalidRecord))
            }
            None => match self.validate_approval_time_bounds(&record.evidence) {
                Ok(()) => Ok(ApprovalResolution::Pending),
                Err(GatewayError::Approval(ApprovalError::Expired)) => {
                    Ok(ApprovalResolution::Expired)
                }
                Err(error) => Err(error),
            },
        }
    }

    /// Validates and consumes a signed human decision exactly once. Approval
    /// and the transition to `Dispatched` are committed atomically before the
    /// exact persisted evidence action is passed to the dispatcher.
    pub fn resolve_human_approval(
        &self,
        decision: HumanApprovalDecision,
    ) -> Result<HumanApprovalReceipt, GatewayError> {
        let verifier = self
            .approval_verifier
            .as_ref()
            .ok_or(ApprovalError::NotConfigured)?;
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
        self.validate_approval_time_bounds(&record.evidence)?;
        verifier.verify(&decision)?;
        if verifier.public_key.as_bytes().as_slice() == record.evidence.agent.public_key.as_slice()
            || decision.approver_key_id == record.evidence.agent.id.as_uuid().to_string()
        {
            return Err(ApprovalError::SelfApproval.into());
        }
        if decision.outcome == HumanApprovalOutcome::Approve {
            self.engine
                .validate_evidence_for_dispatch(&record.evidence)
                .map_err(GatewayError::Authorization)?;
        }
        self.validate_approval_time_bounds(&record.evidence)?;
        self.journal.record_human_approval(key, &decision)?;
        record.human_approval = Some(decision.clone());

        if decision.outcome == HumanApprovalOutcome::Reject {
            let receipt = self.attest_record(&mut record)?;
            return Ok(HumanApprovalReceipt { decision, receipt });
        }

        record.execution = ExecutionStatus::Dispatched;
        if let Err(error) = self.engine.validate_evidence_for_dispatch(&record.evidence) {
            self.record_terminal_attested(&mut record, ExecutionStatus::Failed, None)?;
            return Err(GatewayError::Authorization(error));
        }
        let (execution, output) = match self.dispatcher.dispatch(
            key,
            &record.evidence.authority,
            &record.evidence.action,
            &record.action_digest,
        ) {
            Ok(DispatchReport::Executed(output)) => (ExecutionStatus::Executed, Some(output)),
            Ok(DispatchReport::Confirmed(output)) => (ExecutionStatus::Confirmed, Some(output)),
            Err(_) => (ExecutionStatus::OutcomeUnknown, None),
        };
        let execution_attestation = self.create_execution_attestation(
            &record.evidence,
            record.authorization,
            execution,
            output.as_ref(),
        )?;
        self.journal
            .record_terminal_attested(key, execution, output.as_ref(), &execution_attestation)
            .map_err(|_| GatewayError::OutcomeNotRecorded(key))?;
        let receipt = Self::receipt(
            record.evidence,
            record.authorization,
            execution,
            output,
            execution_attestation,
        );
        Ok(HumanApprovalReceipt { decision, receipt })
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
        if evidence.evidence_schema_version != 2
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
