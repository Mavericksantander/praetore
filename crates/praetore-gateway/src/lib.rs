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
    engine::AuthorizationEngine, freshness::FreshnessError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

pub use praetore_receipt::{
    ApprovalChallenge, ApprovalError, ApprovalExpiredReceipt, AttestedExecution, AttestedOutcome,
    AuthorizationStatus, ExecutionAttestation, ExecutionAttestationError,
    ExecutionAttestationSigner, ExecutionFailure, ExecutionKey, ExecutionStatus, ExpiredOutcome,
    GatewayReceipt, HumanApprovalDecision, HumanApprovalOutcome, NonFinalReason,
    NotDispatchedReason, RefusalCode, action_digest, verify_gateway_receipt_json,
};

pub mod http_api;
pub mod local_demo;
#[cfg(unix)]
pub mod sandbox;

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

/// Returns the tenant UUID only when the authority contains exactly one
/// well-formed `tenant_id` constraint.
pub fn authority_tenant_id(authority: &Authority) -> Option<Uuid> {
    authority.tenant_id()
}

/// What an approver is shown: the challenge to sign and the exact persisted
/// action whose digest it binds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalChallengeView {
    pub challenge: ApprovalChallenge,
    pub action: Action,
}

impl ApprovalChallengeView {
    pub fn from_json(json: &str) -> Result<Self, ApprovalError> {
        if json.len() > 131_072 {
            return Err(ApprovalError::InvalidChallenge);
        }
        let value = praetore_core::canonical::parse_json_rejecting_duplicates(json)
            .map_err(|_| ApprovalError::InvalidChallenge)?;
        serde_json::from_value(value).map_err(|_| ApprovalError::InvalidChallenge)
    }

    /// True only when the displayed action hashes to the digest that the
    /// challenge (and therefore the approver's signature) commits to.
    pub fn action_matches_challenge(&self) -> bool {
        self.action.validate().is_ok()
            && action_digest(&self.action)
                .is_ok_and(|digest| digest == self.challenge.action_digest)
    }
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
        decision.verify_signature(&self.key_id, &self.public_key)
    }
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

/// A human decision for [`ExecutionJournal::record_human_approval`], with
/// what must be written in the same transaction. Built only by
/// [`HumanDecisionRecord::approve`] and [`HumanDecisionRecord::reject`]: an
/// approval never carries a close, and a rejection always carries its signed
/// `approval_rejected` close for the same request.
#[derive(Debug, Clone, Copy)]
pub struct HumanDecisionRecord<'a> {
    decision: &'a HumanApprovalDecision,
    rejection_close: Option<&'a ExecutionAttestation>,
}

impl<'a> HumanDecisionRecord<'a> {
    /// `None` unless the decision approves.
    pub fn approve(decision: &'a HumanApprovalDecision) -> Option<Self> {
        (decision.outcome == HumanApprovalOutcome::Approve).then_some(Self {
            decision,
            rejection_close: None,
        })
    }

    /// `None` unless the decision rejects and `close` is a `not_dispatched`
    /// attestation with the reason `approval_rejected` for the decision's
    /// tenant, agent and request. The journal still checks the close against
    /// the stored evidence ([`ExecutionAttestation::validate_binding`]).
    pub fn reject(
        decision: &'a HumanApprovalDecision,
        close: &'a ExecutionAttestation,
    ) -> Option<Self> {
        let challenge = &decision.challenge;
        (decision.outcome == HumanApprovalOutcome::Reject
            && close.execution == AttestedExecution::NotDispatched
            && close.not_dispatched_reason == Some(NotDispatchedReason::ApprovalRejected)
            && close.tenant_id == Some(challenge.tenant_id)
            && close.agent_id == challenge.agent_id
            && close.request_id == challenge.request_id)
            .then_some(Self {
                decision,
                rejection_close: Some(close),
            })
    }

    pub fn decision(&self) -> &'a HumanApprovalDecision {
        self.decision
    }

    /// The signed close of a rejection; `None` for an approval.
    pub fn rejection_close(&self) -> Option<&'a ExecutionAttestation> {
        self.rejection_close
    }
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

    /// Closes without dispatch: `Authorized` (allowed path; no reason or
    /// `DispatchRefused`), `ApprovedPendingDispatch` (approval path, which
    /// requires an attestation carrying a [`NotDispatchedReason`]), or an
    /// undecided `NotDispatched` approval (only with `DispatchRefused`; no
    /// decision may be recorded afterwards). Never dispatches.
    fn mark_not_dispatched_attested(
        &self,
        key: ExecutionKey,
        attestation: &ExecutionAttestation,
    ) -> Result<(), JournalError>;

    /// Stores the decision. `Approve` moves `NotDispatched` to
    /// `ApprovedPendingDispatch` in the same transaction and never to
    /// `Dispatched`. `Reject` closes the held `NotDispatched` request with
    /// the signed `approval_rejected` attestation it carries, in the same
    /// transaction: the decision and the close are written together or not
    /// at all. `now` is the engine's trusted clock; the decision is
    /// rejected when `expires_at <= now`. Must fail with
    /// `ApprovalAlreadyRecorded` when an approval expiration is already
    /// stored for the key.
    fn record_human_approval(
        &self,
        key: ExecutionKey,
        record: HumanDecisionRecord<'_>,
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

    /// Side-effect-free admission check run by the gateway before an action
    /// is dispatched or offered for human approval, with the same verified
    /// authority that [`ActionDispatcher::dispatch`] would receive (an
    /// adapter that routes per tenant derives the tenant from it). An
    /// adapter that returns `Err` guarantees it would not perform the
    /// action now. A terminal
    /// refusal at submission or at the dispatch claim closes the execution
    /// as `not_dispatched` with the signed reason `dispatch_refused` (never
    /// `outcome_unknown`); a transient refusal at the dispatch claim leaves an
    /// approved execution `approved_pending_dispatch`. The default admits
    /// every action, which preserves the behaviour of existing adapters.
    fn preflight(&self, _authority: &Authority, _action: &Action) -> Result<(), DispatchRefused> {
        Ok(())
    }
}

/// An explicit, pre-dispatch refusal: the adapter did not perform the
/// action. The reason is a stable machine-readable code. A transient refusal
/// (for example a descriptor limit or an I/O error while inspecting the
/// target) may succeed later; a terminal one will not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("dispatcher refused the action before any effect: {reason}")]
pub struct DispatchRefused {
    reason: &'static str,
    transient: bool,
}

impl DispatchRefused {
    pub const fn terminal(reason: &'static str) -> Self {
        Self {
            reason,
            transient: false,
        }
    }

    pub const fn transient(reason: &'static str) -> Self {
        Self {
            reason,
            transient: true,
        }
    }

    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    pub const fn is_transient(&self) -> bool {
        self.transient
    }

    /// The signed `no_effect` classification of this refusal. A reason that
    /// is not a well-formed [`RefusalCode`] is signed as
    /// `invalid_refusal_code` (still `no_effect`: the adapter asserted it
    /// changed nothing; only its code is unusable).
    pub fn no_effect(&self) -> ExecutionFailure {
        ExecutionFailure::NoEffect {
            reason: RefusalCode::new(self.reason).unwrap_or_else(|| {
                RefusalCode::new("invalid_refusal_code").expect("valid refusal code")
            }),
        }
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

/// Why [`ActionDispatcher::dispatch`] returned no report. Each case leads to
/// a different signed journal state, so an adapter must not report
/// `NotApplied` unless it holds the guarantee below; when in doubt between
/// `NotApplied` and `EffectFailed` it must report `EffectFailed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DispatchError {
    /// The adapter cannot tell whether the effect happened. Recorded as
    /// `outcome_unknown`; only reconciliation can close it.
    #[error("tool adapter returned an ambiguous failure")]
    Ambiguous,
    /// Positive proof that nothing was touched: the adapter refused before
    /// any change at the target (for example the path changed between the
    /// preflight and the effect, and the effect was refused before opening
    /// or creating anything). Recorded as the signed terminal state
    /// `failed` with the class `no_effect` and the refusal code, never
    /// `outcome_unknown`, and never retried.
    #[error("adapter refused the action before any effect: {0}")]
    NotApplied(DispatchRefused),
    /// The effect was attempted and did not complete, and the adapter cannot
    /// prove that nothing was left behind (for example a temporary file was
    /// written, or the failure came after opening or writing). Recorded as
    /// the signed terminal state `failed` with the class `effect_failed`
    /// (fail closed), never retried. The code is diagnostic only: it is
    /// returned to the caller, not signed.
    #[error("adapter attempted the action and the effect failed: {0}")]
    EffectFailed(&'static str),
}

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
    /// The adapter refused before any effect. `receipt` is the signed
    /// `not_dispatched` / `dispatch_refused` receipt when the refusal closed
    /// the execution; `None` when nothing changed (a refused challenge or
    /// decision, or a transient refusal at the dispatch claim).
    #[error("dispatcher refused {key:?} before any effect: {reason}")]
    DispatchRefused {
        key: ExecutionKey,
        reason: &'static str,
        transient: bool,
        receipt: Option<Box<GatewayReceipt>>,
    },
    /// The adapter attempted the effect and it failed
    /// ([`DispatchError::EffectFailed`]). `receipt` is the signed `failed`
    /// receipt with the class `effect_failed`. Never retried.
    #[error("the effect for {key:?} was attempted and failed: {reason}")]
    EffectFailed {
        key: ExecutionKey,
        reason: &'static str,
        receipt: Box<GatewayReceipt>,
    },
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

fn map_atomic_evaluation_error(error: AtomicEvaluationError) -> GatewayError {
    match error {
        AtomicEvaluationError::Evaluation(error) => GatewayError::Authorization(error),
        AtomicEvaluationError::Commit(error) => GatewayError::Journal(match error {
            AuthorizationCommitError::AlreadyCommitted => JournalError::AlreadyRecorded,
            AuthorizationCommitError::ConflictingRequest => JournalError::ConflictingRequest,
            AuthorizationCommitError::OrphanedReplayClaim => JournalError::OrphanedReplayClaim,
            AuthorizationCommitError::Unavailable | AuthorizationCommitError::NotFound => {
                JournalError::Unavailable
            }
            AuthorizationCommitError::InvalidRecord => JournalError::InvalidRecord,
        }),
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

    /// The engine's policy. Entry points classify incoming actions against
    /// it (`Policy::classify`) before anything else.
    pub fn policy(&self) -> &praetore_core::Policy {
        self.engine.policy()
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
        if decision.is_self_approval(&verifier.public_key, &record.evidence) {
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
        outcome: &AttestedOutcome,
    ) -> Result<ExecutionAttestation, GatewayError> {
        // Signed with the engine's trusted clock, like approval expirations;
        // when it is unavailable nothing is signed (fail closed).
        let observed_at = self
            .engine
            .trusted_now()
            .map_err(GatewayError::Authorization)?;
        Ok(ExecutionAttestation::create(
            evidence,
            authorization,
            outcome,
            observed_at,
            self.execution_attester.as_ref(),
        )?)
    }

    /// Closes `ApprovedPendingDispatch`, or a held `NotDispatched` request,
    /// as `NotDispatched` with a signed reason. Never invokes the adapter.
    /// When a concurrent caller already closed it with the same reason, that
    /// first signed close is returned instead (idempotent).
    fn close_not_dispatched(
        &self,
        mut record: ExecutionRecord,
        reason: NotDispatchedReason,
    ) -> Result<GatewayReceipt, GatewayError> {
        let attestation = self.create_execution_attestation(
            &record.evidence,
            record.authorization,
            &AttestedOutcome::NotDispatched(Some(reason)),
        )?;
        if let Err(error) = self
            .journal
            .mark_not_dispatched_attested(record.key, &attestation)
        {
            let JournalError::InvalidTransition = error else {
                return Err(error.into());
            };
            let mut current = self
                .journal
                .get(record.key)?
                .ok_or(GatewayError::ExecutionNotFound(record.key))?;
            if Self::closed_reason(&current) != Some(reason) {
                return Err(error.into());
            }
            return self.attest_record(&mut current);
        }
        record.execution = ExecutionStatus::NotDispatched;
        Ok(Self::receipt(
            record.evidence,
            record.authorization,
            None,
            attestation,
        ))
    }

    /// The receipt states exactly what its attestation signs.
    fn receipt(
        evidence: Evidence,
        authorization: AuthorizationStatus,
        output: Option<Value>,
        execution_attestation: ExecutionAttestation,
    ) -> GatewayReceipt {
        GatewayReceipt {
            evidence,
            authorization,
            execution: execution_attestation.execution,
            output,
            execution_attestation,
        }
    }

    /// Adapter preflight for a held request that has no decision yet. A
    /// terminal refusal closes it for good as `NotDispatched` with the signed
    /// reason `dispatch_refused`: the approval can never proceed afterwards,
    /// even if the target later becomes admissible again (the agent must
    /// submit a new request). A transient refusal leaves it pending.
    fn preflight_held(&self, record: &ExecutionRecord) -> Result<(), GatewayError> {
        let Err(refusal) = self
            .dispatcher
            .preflight(&record.evidence.authority, &record.evidence.action)
        else {
            return Ok(());
        };
        let receipt = if refusal.is_transient() {
            None
        } else {
            Some(Box::new(self.close_not_dispatched(
                record.clone(),
                NotDispatchedReason::DispatchRefused,
            )?))
        };
        Err(GatewayError::DispatchRefused {
            key: record.key,
            reason: refusal.reason(),
            transient: refusal.is_transient(),
            receipt,
        })
    }

    /// The signed final reason a held request must carry once a human
    /// rejected it or its window expired, if it does not carry one yet.
    fn pending_close_reason(record: &ExecutionRecord) -> Option<NotDispatchedReason> {
        if record.authorization != AuthorizationStatus::RequiresApproval
            || record.execution != ExecutionStatus::NotDispatched
            || Self::closed_reason(record).is_some()
        {
            return None;
        }
        match (&record.human_approval, &record.approval_expiration) {
            (Some(decision), None) if decision.outcome == HumanApprovalOutcome::Reject => {
                Some(NotDispatchedReason::ApprovalRejected)
            }
            (None, Some(_)) => Some(NotDispatchedReason::ApprovalExpired),
            _ => None,
        }
    }

    /// Idempotent repair: closes a rejected or expired held request with its
    /// signed final reason when an earlier close did not complete (for
    /// example a crash between the expiration receipt and the close, a
    /// rejection recorded by an earlier release, which closed it in a
    /// second transaction, or a row written before migration 0020). Returns
    /// the closing receipt when it closed.
    fn close_decided_hold(
        &self,
        record: &ExecutionRecord,
    ) -> Result<Option<GatewayReceipt>, GatewayError> {
        match Self::pending_close_reason(record) {
            Some(reason) => Ok(Some(self.close_not_dispatched(record.clone(), reason)?)),
            None => Ok(None),
        }
    }

    /// The signed reason of an execution closed without dispatch, if any.
    fn closed_reason(record: &ExecutionRecord) -> Option<NotDispatchedReason> {
        match record.execution {
            ExecutionStatus::NotDispatched => record
                .execution_attestation
                .as_ref()
                .and_then(|attestation| attestation.not_dispatched_reason),
            _ => None,
        }
    }

    /// Read-only execution status of one key, for transports that must tell
    /// whether the gateway itself already performed the effect.
    pub fn execution_status(&self, key: ExecutionKey) -> Result<ExecutionStatus, GatewayError> {
        Ok(self
            .journal
            .get(key)?
            .ok_or(GatewayError::ExecutionNotFound(key))?
            .execution)
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
        self.close_decided_hold(&record)?;
        if record.authorization == AuthorizationStatus::RequiresApproval
            && record.human_approval.is_none()
            && record.approval_expiration.is_some()
        {
            return Err(ApprovalError::Expired.into());
        }
        if record.authorization != AuthorizationStatus::RequiresApproval
            || record.execution != ExecutionStatus::NotDispatched
            || record.human_approval.is_some()
            || Self::closed_reason(&record).is_some()
        {
            return Err(ApprovalError::NotPending.into());
        }
        self.check_pending_approval_window(&record)?;
        self.preflight_held(&record)?;
        Ok(ApprovalChallenge::from_evidence(
            &record.evidence,
            &record.action_digest,
        )?)
    }

    /// The pending challenge together with the persisted action it binds,
    /// so an approver can be shown exactly what it is about to sign.
    pub fn approval_challenge_view(
        &self,
        key: ExecutionKey,
    ) -> Result<ApprovalChallengeView, GatewayError> {
        let challenge = self.approval_challenge(key)?;
        let record = self
            .journal
            .get(key)?
            .ok_or(GatewayError::ExecutionNotFound(key))?;
        let view = ApprovalChallengeView {
            challenge,
            action: record.evidence.action,
        };
        if !view.action_matches_challenge() {
            return Err(GatewayError::Journal(JournalError::InvalidRecord));
        }
        Ok(view)
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
        self.close_decided_hold(record)?;
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
            // Closed before any decision (dispatch_refused): final.
            None if Self::closed_reason(record).is_some() => Ok(ApprovalResolution::NotDispatched),
            // Status never consults the adapter: it reports journal state
            // only, so it cannot reveal live filesystem state.
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
        self.close_decided_hold(&record)?;
        if record.authorization == AuthorizationStatus::RequiresApproval
            && record.human_approval.is_none()
            && record.approval_expiration.is_some()
        {
            return Err(ApprovalError::Expired.into());
        }
        if record.authorization != AuthorizationStatus::RequiresApproval
            || record.execution != ExecutionStatus::NotDispatched
            || record.human_approval.is_some()
            || Self::closed_reason(&record).is_some()
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
            // Refuse before the approval is consumed, so an action the
            // adapter cannot perform is never recorded as dispatched. A
            // terminal refusal closes the request for good.
            self.preflight_held(&record)?;
        }
        self.check_pending_approval_window(&record)?;
        let now = self
            .engine
            .trusted_now()
            .map_err(GatewayError::Authorization)?;

        match decision.outcome {
            HumanApprovalOutcome::Approve => {
                let write = HumanDecisionRecord::approve(&decision)
                    .ok_or(GatewayError::Journal(JournalError::InvalidRecord))?;
                self.journal.record_human_approval(key, write, now)?;
                Ok(HumanApprovalResult::ApprovedPendingDispatch { decision })
            }
            HumanApprovalOutcome::Reject => {
                // Final: the signed reason says a human rejected it. It is
                // signed first and written with the decision in one
                // transaction, so a recorded rejection is always closed.
                let close = self.create_execution_attestation(
                    &record.evidence,
                    record.authorization,
                    &AttestedOutcome::NotDispatched(Some(NotDispatchedReason::ApprovalRejected)),
                )?;
                let write = HumanDecisionRecord::reject(&decision, &close)
                    .ok_or(GatewayError::Journal(JournalError::InvalidRecord))?;
                self.journal.record_human_approval(key, write, now)?;
                record.execution = ExecutionStatus::NotDispatched;
                let receipt = Self::receipt(record.evidence, record.authorization, None, close);
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
            // Approved, claimed after the window: its own signed reason,
            // distinct from a window that closed without a decision.
            let reason = match error {
                PraetoreError::IntentInvalid
                | PraetoreError::FreshnessCheckFailed(FreshnessError::Expired) => {
                    NotDispatchedReason::ApprovedClaimExpired
                }
                _ => NotDispatchedReason::DispatchFailed,
            };
            self.close_not_dispatched(record, reason)?;
            return Err(match reason {
                NotDispatchedReason::ApprovedClaimExpired => ApprovalError::Expired.into(),
                _ => GatewayError::Authorization(error),
            });
        }
        // The adapter re-checks admission after the approval was re-verified
        // and before the single dispatch is claimed: an action it would refuse
        // (for example a target replaced by a symlink while the approval was
        // pending) is closed as `NotDispatched`, never claimed or dispatched.
        // A transient refusal leaves it approved_pending_dispatch, like the
        // other transient revalidation failures above.
        if let Err(refusal) = self
            .dispatcher
            .preflight(&record.evidence.authority, &record.evidence.action)
        {
            let key = record.key;
            let receipt = if refusal.is_transient() {
                None
            } else {
                Some(Box::new(self.close_not_dispatched(
                    record,
                    NotDispatchedReason::DispatchRefused,
                )?))
            };
            return Err(GatewayError::DispatchRefused {
                key,
                reason: refusal.reason(),
                transient: refusal.is_transient(),
                receipt,
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
                self.close_not_dispatched(record, NotDispatchedReason::ApprovedClaimExpired)?;
                Err(ApprovalError::Expired.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Invokes the adapter once for a claimed execution and records the
    /// attested outcome. An ambiguous adapter error becomes `OutcomeUnknown`.
    /// A refusal the adapter guarantees left the target untouched
    /// ([`DispatchError::NotApplied`]) is recorded as the signed terminal
    /// state `Failed` with the class `no_effect` and returned as
    /// [`GatewayError::DispatchRefused`] with that receipt. An attempted
    /// effect that failed ([`DispatchError::EffectFailed`]) is recorded as
    /// `Failed` with the class `effect_failed` and returned as
    /// [`GatewayError::EffectFailed`]. Never retries.
    pub fn dispatch(&self, permit: DispatchPermit) -> Result<GatewayReceipt, GatewayError> {
        let DispatchPermit {
            key,
            evidence,
            authorization,
            action_digest,
        } = permit;
        let (outcome, failed) = match self.dispatcher.dispatch(
            key,
            &evidence.authority,
            &evidence.action,
            &action_digest,
        ) {
            Ok(DispatchReport::Executed(output)) => (AttestedOutcome::Executed(output), None),
            Ok(DispatchReport::Confirmed(output)) => (AttestedOutcome::Confirmed(output), None),
            Err(error @ DispatchError::NotApplied(refusal)) => {
                (AttestedOutcome::Failed(refusal.no_effect()), Some(error))
            }
            Err(error @ DispatchError::EffectFailed(_)) => (
                AttestedOutcome::Failed(ExecutionFailure::EffectFailed),
                Some(error),
            ),
            Err(DispatchError::Ambiguous) => (AttestedOutcome::OutcomeUnknown, None),
        };
        let execution_attestation =
            self.create_execution_attestation(&evidence, authorization, &outcome)?;
        let execution = outcome.execution().journal_status();
        self.journal
            .record_terminal_attested(key, execution, outcome.output(), &execution_attestation)
            .map_err(|_| GatewayError::OutcomeNotRecorded(key))?;
        let receipt = Self::receipt(
            evidence,
            authorization,
            outcome.into_output(),
            execution_attestation,
        );
        match failed {
            // Closed for good: the claim was consumed, so a transient
            // adapter refusal is not offered again either.
            Some(DispatchError::NotApplied(refusal)) => Err(GatewayError::DispatchRefused {
                key,
                reason: refusal.reason(),
                transient: false,
                receipt: Some(Box::new(receipt)),
            }),
            Some(DispatchError::EffectFailed(reason)) => Err(GatewayError::EffectFailed {
                key,
                reason,
                receipt: Box::new(receipt),
            }),
            Some(DispatchError::Ambiguous) | None => Ok(receipt),
        }
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
            self.close_decided_hold(record)?;
            return Err(ApprovalError::Expired.into());
        }
        match self.validate_approval_time_bounds(&record.evidence) {
            Err(GatewayError::Approval(ApprovalError::Expired)) => {
                self.record_approval_expiration(record)?;
                // Final: the signed reason says the window expired.
                self.close_not_dispatched(record.clone(), NotDispatchedReason::ApprovalExpired)?;
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

    /// A held request with no decision, no expiration and no closing reason:
    /// its receipt is the signed `awaiting_approval` (schema v5).
    fn is_awaiting_approval(record: &ExecutionRecord) -> bool {
        record.authorization == AuthorizationStatus::RequiresApproval
            && record.execution == ExecutionStatus::NotDispatched
            && record.human_approval.is_none()
            && record.approval_expiration.is_none()
            && Self::closed_reason(record).is_none()
    }

    /// A held request with a decision or an expiration and no signed close.
    /// A stored schema v2 `not_dispatched` attestation (no reason) is not a
    /// close of it.
    fn inconsistent_hold(record: &ExecutionRecord) -> bool {
        record.authorization == AuthorizationStatus::RequiresApproval
            && record.execution == ExecutionStatus::NotDispatched
            && (record.human_approval.is_some() || record.approval_expiration.is_some())
            && Self::closed_reason(record).is_none()
    }

    fn attest_record(&self, record: &mut ExecutionRecord) -> Result<GatewayReceipt, GatewayError> {
        let awaiting = Self::is_awaiting_approval(record);
        if let Some(attestation) = &record.execution_attestation
            && attestation.execution.journal_status() == record.execution
            // A held request signed before schema v5 (`not_dispatched`, no
            // reason) is signed again as awaiting approval below.
            && (attestation.execution == AttestedExecution::AwaitingApproval) == awaiting
            // An inconsistent hold's stored v2 attestation is not
            // `awaiting_approval`, and the row is not awaiting either, so
            // the comparison above is `false == false`. That attestation
            // is not returned.
            && !Self::inconsistent_hold(record)
        {
            attestation
                .validate_binding(
                    &record.evidence,
                    record.authorization,
                    attestation.execution,
                    record.output.as_ref(),
                )
                .map_err(|_| GatewayError::Journal(JournalError::InvalidRecord))?;
            return Ok(Self::receipt(
                record.evidence.clone(),
                record.authorization,
                record.output.clone(),
                attestation.clone(),
            ));
        }

        let outcome = match (record.execution, record.output.clone()) {
            (ExecutionStatus::NotDispatched, None) if awaiting => AttestedOutcome::AwaitingApproval,
            // A held request with a decision or an expiration but no signed
            // close is inconsistent: it is never signed as `not_dispatched`
            // with no reason, the form of a denied request.
            (ExecutionStatus::NotDispatched, None)
                if record.authorization == AuthorizationStatus::RequiresApproval =>
            {
                return Err(GatewayError::Journal(JournalError::InvalidRecord));
            }
            (ExecutionStatus::NotDispatched, None) => AttestedOutcome::NotDispatched(None),
            (ExecutionStatus::Executed, Some(output)) => AttestedOutcome::Executed(output),
            (ExecutionStatus::Confirmed, Some(output)) => AttestedOutcome::Confirmed(output),
            (ExecutionStatus::OutcomeUnknown, None) => AttestedOutcome::OutcomeUnknown,
            // A `failed` record without its signed classification is never
            // re-signed after the fact: the class is only known when the
            // adapter reports it. Intermediate states are never attested.
            _ => return Err(GatewayError::Journal(JournalError::InvalidRecord)),
        };
        let attestation =
            self.create_execution_attestation(&record.evidence, record.authorization, &outcome)?;
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
            record.output.clone(),
            attestation,
        ))
    }

    fn record_terminal_attested(
        &self,
        record: &mut ExecutionRecord,
        outcome: AttestedOutcome,
    ) -> Result<GatewayReceipt, GatewayError> {
        let attestation =
            self.create_execution_attestation(&record.evidence, record.authorization, &outcome)?;
        let execution = outcome.execution().journal_status();
        let output = outcome.into_output();
        self.journal
            .record_terminal_attested(record.key, execution, output.as_ref(), &attestation)
            .map_err(|_| GatewayError::OutcomeNotRecorded(record.key))?;
        record.execution = execution;
        record.output = output.clone();
        record.execution_attestation = Some(attestation.clone());
        Ok(Self::receipt(
            record.evidence.clone(),
            record.authorization,
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
        self.after_commit(evidence)
    }

    /// G7: refuses a request whose action type the policy does not declare.
    /// The engine verifies it like a mission request and commits a signed
    /// DENY (engine guard `unclassified_action`) with its replay claim; the
    /// execution is then closed as not dispatched, exactly as for a policy
    /// DENY. Nothing is dispatched.
    pub fn refuse_unclassified(
        &self,
        request: praetore_core::authorization::UnclassifiedRequest,
    ) -> Result<GatewayReceipt, GatewayError> {
        let evidence = self
            .engine
            .refuse_unclassified_with_atomic_commit(request, self.journal.as_ref())
            .map_err(map_atomic_evaluation_error)?;
        if evidence.decision.outcome != DecisionOutcome::Deny {
            return Err(GatewayError::InvalidEvidence);
        }
        self.after_commit(evidence)
    }

    fn after_commit(&self, evidence: Evidence) -> Result<GatewayReceipt, GatewayError> {
        if !evidence.is_high_assurance_shape()
            || evidence.evaluation_mode.as_deref() != Some("high_assurance")
            || evidence.policy_digest.is_none()
            || !evidence.verify_integrity()
        {
            return Err(GatewayError::InvalidEvidence);
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

        if authorization != AuthorizationStatus::Denied
            && let Err(refusal) = self
                .dispatcher
                .preflight(&evidence.authority, &evidence.action)
        {
            // Explicit, terminal refusal: nothing was dispatched, and the
            // signed `dispatch_refused` attestation says so. Never left as
            // outcome_unknown, and a held approval closed this way can never
            // be approved (the agent must submit a new request).
            let attestation = self.create_execution_attestation(
                &evidence,
                authorization,
                &AttestedOutcome::NotDispatched(Some(NotDispatchedReason::DispatchRefused)),
            )?;
            self.journal
                .mark_not_dispatched_attested(key, &attestation)?;
            return Err(GatewayError::DispatchRefused {
                key,
                reason: refusal.reason(),
                transient: refusal.is_transient(),
                receipt: Some(Box::new(Self::receipt(
                    evidence,
                    authorization,
                    None,
                    attestation,
                ))),
            });
        }

        if authorization != AuthorizationStatus::Allowed {
            let execution = ExecutionStatus::NotDispatched;
            // A held request is signed as awaiting approval (schema v5): its
            // receipt never states that the action was not dispatched. A
            // denial is final and stays `not_dispatched`.
            let outcome = if authorization == AuthorizationStatus::RequiresApproval {
                AttestedOutcome::AwaitingApproval
            } else {
                AttestedOutcome::NotDispatched(None)
            };
            let attestation =
                self.create_execution_attestation(&evidence, authorization, &outcome)?;
            self.journal
                .record_attestation(key, execution, None, &attestation)?;
            return Ok(Self::receipt(evidence, authorization, None, attestation));
        }

        self.journal.mark_dispatched(key)?;
        if let Err(error) = self.engine.validate_allow_evidence_for_dispatch(&evidence) {
            // The adapter was never invoked: positive proof of no effect.
            let execution = ExecutionStatus::Failed;
            let attestation = self.create_execution_attestation(
                &evidence,
                authorization,
                &AttestedOutcome::Failed(ExecutionFailure::NoEffect {
                    reason: RefusalCode::new("dispatch_revalidation_failed")
                        .expect("valid refusal code"),
                }),
            )?;
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
                    &AttestedOutcome::NotDispatched(None),
                )?;
                self.journal
                    .mark_not_dispatched_attested(key, &execution_attestation)?;
                record.execution = ExecutionStatus::NotDispatched;
                record.execution_attestation = Some(execution_attestation.clone());
                return Ok(Self::receipt(
                    record.evidence,
                    record.authorization,
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
                            AttestedOutcome::Confirmed(output),
                        );
                    }
                    // The adapter was invoked and its outcome was ambiguous:
                    // "not applied" afterwards does not prove that nothing
                    // was touched, so the class is `effect_failed`.
                    ReconciliationReport::NotApplied => {
                        return self.record_terminal_attested(
                            &mut record,
                            AttestedOutcome::Failed(ExecutionFailure::EffectFailed),
                        );
                    }
                    ReconciliationReport::Unknown => {
                        if record.execution == ExecutionStatus::Dispatched {
                            return self.record_terminal_attested(
                                &mut record,
                                AttestedOutcome::OutcomeUnknown,
                            );
                        }
                    }
                }
            }
            ExecutionStatus::NotDispatched => {
                if let Some(receipt) = self.close_decided_hold(&record)? {
                    return Ok(receipt);
                }
            }
            ExecutionStatus::Executed | ExecutionStatus::Confirmed | ExecutionStatus::Failed => {}
        }

        self.attest_record(&mut record)
    }
}
