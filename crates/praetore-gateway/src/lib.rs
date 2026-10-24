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
use uuid::Uuid;

const ACTION_DIGEST_DOMAIN: &[u8] = b"PRAETORE_EXECUTION_ACTION_V1\0";

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

/// A transport/audit wrapper. The contained core evidence attests to the
/// authorization decision only; the execution fields are gateway records and
/// are not covered by the core evidence signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayReceipt {
    pub evidence: Evidence,
    pub authorization: AuthorizationStatus,
    pub execution: ExecutionStatus,
    pub output: Option<Value>,
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

    fn record_terminal(
        &self,
        key: ExecutionKey,
        execution: ExecutionStatus,
        output: Option<&Value>,
    ) -> Result<(), JournalError>;

    fn get(&self, key: ExecutionKey) -> Result<Option<ExecutionRecord>, JournalError>;

    fn mark_not_dispatched(&self, key: ExecutionKey) -> Result<(), JournalError>;

    fn mark_outcome_unknown(&self, key: ExecutionKey) -> Result<(), JournalError>;
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
}

impl Gateway {
    pub fn new(
        engine: AuthorizationEngine,
        journal: Arc<dyn ExecutionJournal>,
        dispatcher: Arc<dyn ActionDispatcher>,
    ) -> Result<Self, GatewayError> {
        if engine.mode() != EvaluationMode::HighAssurance {
            return Err(GatewayError::HighAssuranceRequired);
        }
        Ok(Self {
            engine,
            journal,
            dispatcher,
        })
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
            return Ok(GatewayReceipt {
                evidence,
                authorization,
                execution: ExecutionStatus::NotDispatched,
                output: None,
            });
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

        self.journal
            .record_terminal(key, execution, output.as_ref())
            .map_err(|_| GatewayError::OutcomeNotRecorded(key))?;

        Ok(GatewayReceipt {
            evidence,
            authorization,
            execution,
            output,
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
                self.journal.mark_not_dispatched(key)?;
                record.execution = ExecutionStatus::NotDispatched;
            }
            ExecutionStatus::Dispatched => {
                self.journal.mark_outcome_unknown(key)?;
                record.execution = ExecutionStatus::OutcomeUnknown;
                match self
                    .dispatcher
                    .reconcile(key, &record.evidence.action, &record.action_digest)
                {
                    ReconciliationReport::Applied(output) => {
                        self.journal.record_terminal(
                            key,
                            ExecutionStatus::Confirmed,
                            Some(&output),
                        )?;
                        record.execution = ExecutionStatus::Confirmed;
                        record.output = Some(output);
                    }
                    ReconciliationReport::NotApplied => {
                        self.journal
                            .record_terminal(key, ExecutionStatus::Failed, None)?;
                        record.execution = ExecutionStatus::Failed;
                        record.output = None;
                    }
                    ReconciliationReport::Unknown => {}
                }
            }
            ExecutionStatus::OutcomeUnknown => {
                match self
                    .dispatcher
                    .reconcile(key, &record.evidence.action, &record.action_digest)
                {
                    ReconciliationReport::Applied(output) => {
                        self.journal.record_terminal(
                            key,
                            ExecutionStatus::Confirmed,
                            Some(&output),
                        )?;
                        record.execution = ExecutionStatus::Confirmed;
                        record.output = Some(output);
                    }
                    ReconciliationReport::NotApplied => {
                        self.journal
                            .record_terminal(key, ExecutionStatus::Failed, None)?;
                        record.execution = ExecutionStatus::Failed;
                        record.output = None;
                    }
                    ReconciliationReport::Unknown => {}
                }
            }
            ExecutionStatus::NotDispatched
            | ExecutionStatus::Executed
            | ExecutionStatus::Confirmed
            | ExecutionStatus::Failed => {}
        }

        Ok(GatewayReceipt {
            evidence: record.evidence,
            authorization: record.authorization,
            execution: record.execution,
            output: record.output,
        })
    }
}
