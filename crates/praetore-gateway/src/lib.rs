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
    Action, AtomicAuthorizationCommit, AtomicEvaluationError, AuthorizationCommitError,
    AuthorizationRequest, DecisionOutcome, EvaluationMode, Evidence, PraetoreError,
    canonical::canonicalize_json, engine::AuthorizationEngine,
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

/// A stable key for one signed request and its single permitted execution
/// attempt. The request ID is signed as part of the authorization intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecutionKey {
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
        let action_digest = action_digest(&evidence.action)
            .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
        let output_digest = output.map(output_digest).transpose()?;
        let payload = ExecutionAttestationPayload {
            schema_version: 1,
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
            schema_version: 1,
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
        if self.schema_version != 1
            || self.evidence_id != evidence.evidence_id
            || self.request_id != evidence.request_id
            || self.agent_id != *evidence.agent.id.as_uuid()
            || self.authorization != authorization
            || authorization_for_outcome(evidence.decision.outcome) != authorization
            || self.execution != execution
            || self.policy_digest != evidence.policy_digest.as_deref().unwrap_or_default()
            || self.evidence_hash != evidence.context_hash
            || !evidence.verify_integrity()
            || authorization != AuthorizationStatus::Allowed
                && execution != ExecutionStatus::NotDispatched
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
}

/// An adapter receives the exact normalized action evaluated by the engine.
/// It must not re-parse a caller payload or silently broaden the operation.
pub trait ActionDispatcher: Send + Sync {
    fn dispatch(
        &self,
        key: ExecutionKey,
        action: &Action,
        action_digest: &str,
    ) -> Result<DispatchReport, DispatchError>;

    /// Read-only reconciliation hook. `Applied` or `NotApplied` must only be
    /// returned when the adapter can establish that fact for this key and
    /// action digest. The default is deliberately inconclusive.
    fn reconcile(
        &self,
        _key: ExecutionKey,
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
    #[error("execution journal failed: {0}")]
    Journal(#[from] JournalError),
    #[error("tool outcome may have occurred but could not be journaled for {0:?}")]
    OutcomeNotRecorded(ExecutionKey),
    #[error("execution outcome was recorded but its attestation could not be created: {0}")]
    ExecutionAttestation(#[from] ExecutionAttestationError),
    #[error("execution record does not exist for {0:?}")]
    ExecutionNotFound(ExecutionKey),
}

/// A synchronous gateway that binds a current authorization result to one
/// adapter invocation.
#[derive(Clone)]
pub struct Gateway {
    engine: AuthorizationEngine,
    journal: Arc<dyn ExecutionJournal>,
    dispatcher: Arc<dyn ActionDispatcher>,
    execution_attester: Arc<dyn ExecutionAttestationSigner>,
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
        })
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

    fn attest_record(&self, record: &mut ExecutionRecord) -> Result<GatewayReceipt, GatewayError> {
        if let Some(attestation) = &record.execution_attestation {
            if attestation.execution == record.execution {
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
        let action_digest = action_digest(&evidence.action)?;
        let (execution, output) =
            match self
                .dispatcher
                .dispatch(key, &evidence.action, &action_digest)
            {
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
                match self
                    .dispatcher
                    .reconcile(key, &record.evidence.action, &record.action_digest)
                {
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
