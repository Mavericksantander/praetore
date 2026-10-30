use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use praetore_core::{
    Action, AgentId, AgentKeyPair, AuthorizationRequest, DecisionOutcome, Evidence,
    EvidenceAttesterKey, HighAssuranceConfig, Policy, PolicyEffect, PolicyRule, PraetoreError,
    TrustedAuthorityIssuer, VerifiedPublicKey,
    authority::{Authority, Validity},
    engine::{AuthorizationEngine, Clock, EvaluationMode, FixedClock},
    freshness::{FreshnessError, FreshnessLease, FreshnessProvider},
    identity::AgentKeyFingerprint,
    replay::{
        AtomicAuthorizationCommit, AuthorizationCommitError, CompletedAuthorization, ReplayGuard,
        ReplayGuardError,
    },
};
use praetore_gateway::{
    ActionDispatcher, ApprovalError, AuthorizationStatus, DispatchError, DispatchReport,
    ExecutionAttestationError, ExecutionAttestationSigner, ExecutionJournal, ExecutionKey,
    ExecutionRecord, ExecutionStatus, Gateway, GatewayError, HumanApprovalDecision,
    HumanApprovalOutcome, HumanApprovalResult, HumanApprovalVerifier, JournalError,
    NotDispatchedReason, ReconciliationReport, authority_tenant_id,
};
use praetore_gateway::{http_api, local_demo::LocalDemoDispatcher};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;
use uuid::Uuid;

/// `verify_execution_attestation` also checks the evidence signature, so it
/// needs the evidence attester key. These tests use several fixtures; pick
/// the test attester whose key id the evidence names.
trait VerifyWithTestEvidenceAttester {
    fn verify_with_test_evidence_attester(
        &self,
        public_key: &VerifiedPublicKey,
        expected_key_id: &str,
    ) -> Result<(), ExecutionAttestationError>;
}

impl VerifyWithTestEvidenceAttester for praetore_gateway::GatewayReceipt {
    fn verify_with_test_evidence_attester(
        &self,
        public_key: &VerifiedPublicKey,
        expected_key_id: &str,
    ) -> Result<(), ExecutionAttestationError> {
        let evidence_key = [13, 23, 33]
            .into_iter()
            .map(|secret| EvidenceAttesterKey::from_secret_bytes(&[secret; 32]))
            .find(|key| self.evidence.attester_key_id.as_deref() == Some(key.key_id().as_str()))
            .expect("evidence signed by a known test attester")
            .public_key()
            .unwrap();
        self.verify_execution_attestation(public_key, expected_key_id, &evidence_key)
    }
}

const NOW: &str = "2026-06-01T12:00:00Z";
const TEST_TENANT_ID: Uuid = Uuid::from_u128(1);

struct TestExecutionAttester {
    signing_key: SigningKey,
    fail_signing: AtomicBool,
    sign_count: AtomicUsize,
}

impl TestExecutionAttester {
    fn new() -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&[14; 32]),
            fail_signing: AtomicBool::new(false),
            sign_count: AtomicUsize::new(0),
        }
    }
}

impl ExecutionAttestationSigner for TestExecutionAttester {
    fn key_id(&self) -> &str {
        "test-execution-attester-v1"
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ExecutionAttestationError> {
        if self.fail_signing.load(Ordering::SeqCst) {
            return Err(ExecutionAttestationError::SignerFailed);
        }
        self.sign_count.fetch_add(1, Ordering::SeqCst);
        Ok(self.signing_key.sign(message).to_bytes().to_vec())
    }
}

fn execution_attester() -> Arc<TestExecutionAttester> {
    Arc::new(TestExecutionAttester::new())
}

impl TestExecutionAttester {
    fn sign_count(&self) -> usize {
        self.sign_count.load(Ordering::SeqCst)
    }
}

fn execution_attester_public_key() -> VerifiedPublicKey {
    VerifiedPublicKey::from_bytes(
        &TestExecutionAttester::new()
            .signing_key
            .verifying_key()
            .to_bytes(),
    )
    .unwrap()
}

fn long_validity() -> Validity {
    Validity {
        not_before: Some("2026-01-01T00:00:00Z".into()),
        not_after: Some("2026-12-31T00:00:00Z".into()),
    }
}

#[derive(Default)]
struct MemoryReplayGuard {
    claims: Mutex<HashSet<(Uuid, Uuid, Uuid)>>,
    unavailable: AtomicBool,
}

impl ReplayGuard for MemoryReplayGuard {
    fn claim_once(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        request_id: Uuid,
    ) -> Result<(), ReplayGuardError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(ReplayGuardError::Unavailable);
        }
        let mut claims = self
            .claims
            .lock()
            .map_err(|_| ReplayGuardError::Unavailable)?;
        if claims.insert((tenant_id, agent_id, request_id)) {
            Ok(())
        } else {
            Err(ReplayGuardError::AlreadyClaimed)
        }
    }
}

struct CurrentFreshness;

impl FreshnessProvider for CurrentFreshness {
    fn check(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &praetore_core::AuthorityId,
        _policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        Ok(FreshnessLease {
            valid_until: now + Duration::seconds(30),
        })
    }

    fn check_authority(
        &self,
        agent: &AgentKeyFingerprint,
        authority_id: &praetore_core::AuthorityId,
        authority_digest: &str,
        policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        if authority_digest.len() != 64 {
            return Err(FreshnessError::InvalidResponse);
        }
        self.check(agent, authority_id, policy_digest, now)
    }
}

struct SharedTestClock(Arc<Mutex<OffsetDateTime>>);

impl Clock for SharedTestClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

struct ExpiringOnDispatchFreshness {
    clock: Arc<Mutex<OffsetDateTime>>,
    calls: AtomicUsize,
    expire_on_call: usize,
    advance_by: Duration,
    lease_duration: Duration,
}

impl FreshnessProvider for ExpiringOnDispatchFreshness {
    fn check(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &praetore_core::AuthorityId,
        _policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        Ok(FreshnessLease {
            valid_until: now + self.lease_duration,
        })
    }

    fn check_authority(
        &self,
        agent: &AgentKeyFingerprint,
        authority_id: &praetore_core::AuthorityId,
        authority_digest: &str,
        policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        if authority_digest.len() != 64 {
            return Err(FreshnessError::InvalidResponse);
        }
        if self.calls.fetch_add(1, Ordering::SeqCst) == self.expire_on_call {
            let mut clock = self.clock.lock().unwrap();
            *clock += self.advance_by;
        }
        self.check(agent, authority_id, policy_digest, now)
    }
}

struct JournalEntry {
    evidence: Option<Evidence>,
    authorization: Option<AuthorizationStatus>,
    states: Vec<ExecutionStatus>,
    execution: ExecutionStatus,
    action_digest: String,
    output: Option<Value>,
    execution_attestations: Vec<praetore_gateway::ExecutionAttestation>,
    human_approval: Option<HumanApprovalDecision>,
    approval_expiration: Option<praetore_gateway::ApprovalExpiredReceipt>,
}

impl Default for JournalEntry {
    fn default() -> Self {
        Self {
            evidence: None,
            authorization: None,
            states: Vec::new(),
            execution: ExecutionStatus::NotDispatched,
            action_digest: String::new(),
            output: None,
            execution_attestations: Vec::new(),
            human_approval: None,
            approval_expiration: None,
        }
    }
}

#[derive(Default)]
struct MemoryJournal {
    entries: Mutex<HashMap<ExecutionKey, JournalEntry>>,
    fail_dispatched: AtomicBool,
    fail_terminal: AtomicBool,
    unavailable: AtomicBool,
    /// SAF-10 test hook: once an expiration receipt is stored, reads of that
    /// record fail as if the stored receipt were unreadable.
    unreadable_expiration: AtomicBool,
}

impl MemoryJournal {
    fn record_authorization(
        &self,
        key: ExecutionKey,
        evidence: &Evidence,
        authorization: AuthorizationStatus,
    ) -> Result<(), JournalError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(JournalError::Unavailable);
        }
        let mut entries = self.entries.lock().map_err(|_| JournalError::Unavailable)?;
        if let Some(existing) = entries.get(&key) {
            let action = praetore_gateway::action_digest(&evidence.action)
                .map_err(|_| JournalError::InvalidRecord)?;
            return if existing.action_digest == action {
                Err(JournalError::AlreadyRecorded)
            } else {
                Err(JournalError::ConflictingRequest)
            };
        }
        let action_digest = praetore_gateway::action_digest(&evidence.action)
            .map_err(|_| JournalError::InvalidRecord)?;
        entries.insert(
            key,
            JournalEntry {
                evidence: Some(evidence.clone()),
                authorization: Some(authorization),
                states: Vec::new(),
                execution: if authorization == AuthorizationStatus::Allowed {
                    ExecutionStatus::Authorized
                } else {
                    ExecutionStatus::NotDispatched
                },
                action_digest,
                output: None,
                execution_attestations: Vec::new(),
                human_approval: None,
                approval_expiration: None,
            },
        );
        Ok(())
    }

    fn entry(&self, key: ExecutionKey) -> Option<JournalEntrySnapshot> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(&key)?;
        Some(JournalEntrySnapshot {
            evidence: entry.evidence.clone()?,
            authorization: entry.authorization?,
            states: entry.states.clone(),
            execution: entry.execution,
            output: entry.output.clone(),
            execution_attestation: entry.execution_attestations.last().cloned(),
        })
    }
}

struct JournalEntrySnapshot {
    evidence: Evidence,
    authorization: AuthorizationStatus,
    states: Vec<ExecutionStatus>,
    execution: ExecutionStatus,
    output: Option<Value>,
    execution_attestation: Option<praetore_gateway::ExecutionAttestation>,
}

impl AtomicAuthorizationCommit for MemoryJournal {
    fn commit_authorization(
        &self,
        authorization: &CompletedAuthorization,
        trusted_attester: &VerifiedPublicKey,
    ) -> Result<(), AuthorizationCommitError> {
        let evidence = authorization.evidence();
        evidence
            .verify_attester_signature(trusted_attester)
            .map_err(|_| AuthorizationCommitError::InvalidRecord)?;
        let key = ExecutionKey {
            tenant_id: authority_tenant_id(&evidence.authority)
                .ok_or(AuthorizationCommitError::InvalidRecord)?,
            agent_id: *evidence.agent.id.as_uuid(),
            request_id: evidence.request_id,
        };
        let authorization = match evidence.decision.outcome {
            DecisionOutcome::Allow => AuthorizationStatus::Allowed,
            DecisionOutcome::RequireApproval => AuthorizationStatus::RequiresApproval,
            DecisionOutcome::Deny => AuthorizationStatus::Denied,
        };
        self.record_authorization(key, evidence, authorization)
            .map_err(|error| match error {
                JournalError::AlreadyRecorded => AuthorizationCommitError::AlreadyCommitted,
                JournalError::ConflictingRequest => AuthorizationCommitError::ConflictingRequest,
                JournalError::OrphanedReplayClaim => AuthorizationCommitError::OrphanedReplayClaim,
                JournalError::Unavailable => AuthorizationCommitError::Unavailable,
                JournalError::ApprovalAlreadyRecorded | JournalError::ApprovalExpired => {
                    AuthorizationCommitError::InvalidRecord
                }
                JournalError::InvalidTransition | JournalError::InvalidRecord => {
                    AuthorizationCommitError::InvalidRecord
                }
            })
    }

    fn verify_committed_authorization(
        &self,
        authorization: &CompletedAuthorization,
        trusted_attester: &VerifiedPublicKey,
    ) -> Result<(), AuthorizationCommitError> {
        let evidence = authorization.evidence();
        evidence
            .verify_attester_signature(trusted_attester)
            .map_err(|_| AuthorizationCommitError::InvalidRecord)?;
        let key = ExecutionKey {
            tenant_id: authority_tenant_id(&evidence.authority)
                .ok_or(AuthorizationCommitError::InvalidRecord)?,
            agent_id: *evidence.agent.id.as_uuid(),
            request_id: evidence.request_id,
        };
        let record = self
            .get(key)
            .map_err(|_| AuthorizationCommitError::Unavailable)?
            .ok_or(AuthorizationCommitError::NotFound)?;
        let expected = evidence
            .to_json()
            .map_err(|_| AuthorizationCommitError::InvalidRecord)?;
        let actual = record
            .evidence
            .to_json()
            .map_err(|_| AuthorizationCommitError::InvalidRecord)?;
        let initial_status = if record.authorization == AuthorizationStatus::Allowed {
            ExecutionStatus::Authorized
        } else {
            ExecutionStatus::NotDispatched
        };
        if expected != actual || record.execution != initial_status {
            return Err(AuthorizationCommitError::InvalidRecord);
        }
        Ok(())
    }
}

impl ExecutionJournal for MemoryJournal {
    fn mark_dispatched(&self, key: ExecutionKey) -> Result<(), JournalError> {
        if self.unavailable.load(Ordering::SeqCst) || self.fail_dispatched.load(Ordering::SeqCst) {
            return Err(JournalError::Unavailable);
        }
        let mut entries = self.entries.lock().map_err(|_| JournalError::Unavailable)?;
        let entry = entries
            .get_mut(&key)
            .ok_or(JournalError::InvalidTransition)?;
        if entry.execution != ExecutionStatus::Authorized
            || entry.authorization != Some(AuthorizationStatus::Allowed)
        {
            return Err(JournalError::InvalidTransition);
        }
        entry.states.push(ExecutionStatus::Dispatched);
        entry.execution = ExecutionStatus::Dispatched;
        Ok(())
    }

    fn record_terminal_attested(
        &self,
        key: ExecutionKey,
        execution: ExecutionStatus,
        output: Option<&Value>,
        attestation: &praetore_gateway::ExecutionAttestation,
    ) -> Result<(), JournalError> {
        if self.unavailable.load(Ordering::SeqCst) || self.fail_terminal.load(Ordering::SeqCst) {
            return Err(JournalError::Unavailable);
        }
        if !matches!(
            execution,
            ExecutionStatus::Executed
                | ExecutionStatus::Confirmed
                | ExecutionStatus::OutcomeUnknown
                | ExecutionStatus::Failed
        ) {
            return Err(JournalError::InvalidTransition);
        }
        let mut entries = self.entries.lock().map_err(|_| JournalError::Unavailable)?;
        let entry = entries
            .get_mut(&key)
            .ok_or(JournalError::InvalidTransition)?;
        let evidence = entry.evidence.as_ref().ok_or(JournalError::InvalidRecord)?;
        let authorization = entry.authorization.ok_or(JournalError::InvalidRecord)?;
        attestation
            .validate_binding(evidence, authorization, execution, output)
            .map_err(|_| JournalError::InvalidRecord)?;
        if !matches!(
            entry.execution,
            ExecutionStatus::Dispatched | ExecutionStatus::OutcomeUnknown
        ) {
            let existing = entry.execution_attestations.last();
            return if entry.execution == execution
                && entry.output.as_ref() == output
                && existing.is_some_and(|existing| {
                    serde_json::to_value(existing).ok() == serde_json::to_value(attestation).ok()
                }) {
                Ok(())
            } else {
                Err(JournalError::InvalidTransition)
            };
        }
        entry.states.push(execution);
        entry.execution = execution;
        entry.output = output.cloned();
        entry.execution_attestations.push(attestation.clone());
        Ok(())
    }

    fn record_attestation(
        &self,
        key: ExecutionKey,
        execution: ExecutionStatus,
        output: Option<&Value>,
        attestation: &praetore_gateway::ExecutionAttestation,
    ) -> Result<(), JournalError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(JournalError::Unavailable);
        }
        let mut entries = self.entries.lock().map_err(|_| JournalError::Unavailable)?;
        let entry = entries
            .get_mut(&key)
            .ok_or(JournalError::InvalidTransition)?;
        let evidence = entry.evidence.as_ref().ok_or(JournalError::InvalidRecord)?;
        let authorization = entry.authorization.ok_or(JournalError::InvalidRecord)?;
        if entry.execution != execution || entry.output.as_ref() != output {
            return Err(JournalError::InvalidTransition);
        }
        attestation
            .validate_binding(evidence, authorization, execution, output)
            .map_err(|_| JournalError::InvalidRecord)?;
        if let Some(existing) = entry
            .execution_attestations
            .iter()
            .find(|existing| existing.execution == execution)
        {
            return if serde_json::to_value(existing).ok() == serde_json::to_value(attestation).ok()
            {
                Ok(())
            } else {
                Err(JournalError::InvalidTransition)
            };
        }
        entry.execution_attestations.push(attestation.clone());
        Ok(())
    }

    fn get(&self, key: ExecutionKey) -> Result<Option<ExecutionRecord>, JournalError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(JournalError::Unavailable);
        }
        let entries = self.entries.lock().map_err(|_| JournalError::Unavailable)?;
        let Some(entry) = entries.get(&key) else {
            return Ok(None);
        };
        if self.unreadable_expiration.load(Ordering::SeqCst) && entry.approval_expiration.is_some()
        {
            return Err(JournalError::InvalidRecord);
        }
        Ok(Some(ExecutionRecord {
            key,
            evidence: entry.evidence.clone().ok_or(JournalError::InvalidRecord)?,
            authorization: entry.authorization.ok_or(JournalError::InvalidRecord)?,
            execution: entry.execution,
            action_digest: entry.action_digest.clone(),
            output: entry.output.clone(),
            execution_attestation: entry.execution_attestations.last().cloned(),
            human_approval: entry.human_approval.clone(),
            approval_expiration: entry.approval_expiration.clone(),
        }))
    }

    fn mark_not_dispatched_attested(
        &self,
        key: ExecutionKey,
        attestation: &praetore_gateway::ExecutionAttestation,
    ) -> Result<(), JournalError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(JournalError::Unavailable);
        }
        let mut entries = self.entries.lock().map_err(|_| JournalError::Unavailable)?;
        let entry = entries
            .get_mut(&key)
            .ok_or(JournalError::InvalidTransition)?;
        let evidence = entry.evidence.as_ref().ok_or(JournalError::InvalidRecord)?;
        let authorization = entry.authorization.ok_or(JournalError::InvalidRecord)?;
        let from = match (authorization, attestation.not_dispatched_reason) {
            (AuthorizationStatus::Allowed, None) => ExecutionStatus::Authorized,
            (AuthorizationStatus::RequiresApproval, Some(_)) => {
                ExecutionStatus::ApprovedPendingDispatch
            }
            _ => return Err(JournalError::InvalidTransition),
        };
        if entry.execution != from {
            return Err(JournalError::InvalidTransition);
        }
        attestation
            .validate_binding(
                evidence,
                authorization,
                ExecutionStatus::NotDispatched,
                None,
            )
            .map_err(|_| JournalError::InvalidRecord)?;
        entry.execution = ExecutionStatus::NotDispatched;
        entry.states.push(ExecutionStatus::NotDispatched);
        entry.execution_attestations.push(attestation.clone());
        Ok(())
    }

    fn record_human_approval(
        &self,
        key: ExecutionKey,
        decision: &HumanApprovalDecision,
        now: OffsetDateTime,
    ) -> Result<(), JournalError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(JournalError::Unavailable);
        }
        let expires_at = OffsetDateTime::parse(
            &decision.challenge.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| JournalError::InvalidRecord)?;
        if expires_at <= now {
            return Err(JournalError::InvalidRecord);
        }
        let mut entries = self.entries.lock().map_err(|_| JournalError::Unavailable)?;
        let entry = entries
            .get_mut(&key)
            .ok_or(JournalError::InvalidTransition)?;
        if entry.authorization != Some(AuthorizationStatus::RequiresApproval)
            || entry.execution != ExecutionStatus::NotDispatched
        {
            return Err(JournalError::InvalidTransition);
        }
        if entry.human_approval.is_some() || entry.approval_expiration.is_some() {
            return Err(JournalError::ApprovalAlreadyRecorded);
        }
        if decision.outcome == HumanApprovalOutcome::Approve {
            entry.states.push(ExecutionStatus::ApprovedPendingDispatch);
            entry.execution = ExecutionStatus::ApprovedPendingDispatch;
        }
        entry.human_approval = Some(decision.clone());
        Ok(())
    }

    fn claim_dispatch(&self, key: ExecutionKey, now: OffsetDateTime) -> Result<(), JournalError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(JournalError::Unavailable);
        }
        let mut entries = self.entries.lock().map_err(|_| JournalError::Unavailable)?;
        let entry = entries
            .get_mut(&key)
            .ok_or(JournalError::InvalidTransition)?;
        if entry.authorization != Some(AuthorizationStatus::RequiresApproval)
            || entry.execution != ExecutionStatus::ApprovedPendingDispatch
        {
            return Err(JournalError::InvalidTransition);
        }
        let decision = entry
            .human_approval
            .as_ref()
            .filter(|decision| decision.outcome == HumanApprovalOutcome::Approve)
            .ok_or(JournalError::InvalidRecord)?;
        let expires_at = OffsetDateTime::parse(
            &decision.challenge.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| JournalError::InvalidRecord)?;
        if expires_at <= now {
            return Err(JournalError::ApprovalExpired);
        }
        entry.states.push(ExecutionStatus::Dispatched);
        entry.execution = ExecutionStatus::Dispatched;
        Ok(())
    }

    fn record_approval_expiration(
        &self,
        key: ExecutionKey,
        receipt: &praetore_gateway::ApprovalExpiredReceipt,
    ) -> Result<(), JournalError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(JournalError::Unavailable);
        }
        let mut entries = self.entries.lock().map_err(|_| JournalError::Unavailable)?;
        let entry = entries
            .get_mut(&key)
            .ok_or(JournalError::InvalidTransition)?;
        if entry.human_approval.is_some() {
            return Err(JournalError::ApprovalAlreadyRecorded);
        }
        if entry.approval_expiration.is_some() {
            return Ok(());
        }
        let evidence = entry.evidence.as_ref().ok_or(JournalError::InvalidRecord)?;
        if entry.authorization != Some(AuthorizationStatus::RequiresApproval)
            || entry.execution != ExecutionStatus::NotDispatched
            || receipt.key() != key
            || receipt.validate_binding(evidence).is_err()
        {
            return Err(JournalError::InvalidRecord);
        }
        entry.approval_expiration = Some(receipt.clone());
        Ok(())
    }
}

#[derive(Default)]
struct LocalSetTool {
    values: Mutex<HashMap<String, Value>>,
    execution_keys: Mutex<Vec<ExecutionKey>>,
    outcomes: Mutex<HashMap<ExecutionKey, Value>>,
    invocations: AtomicUsize,
    fail_after_write: AtomicBool,
    reconciliation_unknown: AtomicBool,
    refuse_preflight: AtomicBool,
}

impl LocalSetTool {
    fn value(&self, key: &str) -> Option<Value> {
        self.values.lock().ok()?.get(key).cloned()
    }

    fn invocations(&self) -> usize {
        self.invocations.load(Ordering::SeqCst)
    }

    fn execution_keys(&self) -> Vec<ExecutionKey> {
        self.execution_keys.lock().unwrap().clone()
    }
}

impl ActionDispatcher for LocalSetTool {
    fn dispatch(
        &self,
        execution_key: ExecutionKey,
        _authority: &Authority,
        action: &Action,
        _action_digest: &str,
    ) -> Result<DispatchReport, DispatchError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        self.execution_keys
            .lock()
            .map_err(|_| DispatchError)?
            .push(execution_key);
        if action.action_type != "local:set_value"
            || action.target.as_deref() != Some("local-state")
            || action.capability.as_deref() != Some("local:write")
        {
            return Err(DispatchError);
        }
        let parameters = action.parameters.as_object().ok_or(DispatchError)?;
        if parameters.len() != 2 {
            return Err(DispatchError);
        }
        let parameter_key = parameters
            .get("key")
            .and_then(Value::as_str)
            .ok_or(DispatchError)?;
        let value = parameters.get("value").ok_or(DispatchError)?.clone();

        self.values
            .lock()
            .map_err(|_| DispatchError)?
            .insert(parameter_key.to_owned(), value.clone());
        let output = json!({"key": parameter_key, "value": value});
        self.outcomes
            .lock()
            .map_err(|_| DispatchError)?
            .insert(execution_key, output.clone());

        if self.fail_after_write.swap(false, Ordering::SeqCst) {
            return Err(DispatchError);
        }

        let observed = self.value(parameter_key).ok_or(DispatchError)?;
        if observed != value {
            return Err(DispatchError);
        }
        Ok(DispatchReport::Confirmed(
            json!({"key": parameter_key, "value": observed}),
        ))
    }

    fn reconcile(
        &self,
        execution_key: ExecutionKey,
        _authority: &Authority,
        _action: &Action,
        _action_digest: &str,
    ) -> ReconciliationReport {
        if self.reconciliation_unknown.load(Ordering::SeqCst) {
            return ReconciliationReport::Unknown;
        }
        self.outcomes
            .lock()
            .ok()
            .and_then(|outcomes| outcomes.get(&execution_key).cloned())
            .map(ReconciliationReport::Applied)
            .unwrap_or(ReconciliationReport::Unknown)
    }

    fn preflight(&self, _action: &Action) -> Result<(), praetore_gateway::DispatchRefused> {
        if self.refuse_preflight.load(Ordering::SeqCst) {
            return Err(praetore_gateway::DispatchRefused("test_refusal"));
        }
        Ok(())
    }
}

struct Fixture {
    gateway: Gateway,
    request: AuthorizationRequest,
    tool: Arc<LocalSetTool>,
    journal: Arc<MemoryJournal>,
    execution_attester: Arc<TestExecutionAttester>,
    policy: Policy,
    issuer_public_key: VerifiedPublicKey,
    attester: EvidenceAttesterKey,
}

fn fixture(effect: Option<PolicyEffect>, expired: bool) -> Fixture {
    fixture_with_replay(effect, expired, Arc::new(MemoryReplayGuard::default()))
}

fn production_engine(
    policy: Policy,
    issuer_public_key: VerifiedPublicKey,
    attester: EvidenceAttesterKey,
    replay_guard: Arc<MemoryReplayGuard>,
) -> AuthorizationEngine {
    let issuer_pin = TrustedAuthorityIssuer::new("local-test-issuer", issuer_public_key)
        .unwrap()
        .with_validity(long_validity())
        .unwrap();
    let config = HighAssuranceConfig::new(policy.digest().unwrap(), vec![issuer_pin], attester)
        .unwrap()
        .with_audience("local-test-gateway")
        .with_replay_guard(replay_guard)
        .with_freshness_provider(Arc::new(CurrentFreshness));
    AuthorizationEngine::production_with_clock(policy, config, FixedClock::try_new(NOW).unwrap())
        .unwrap()
}

fn fixture_with_replay(
    effect: Option<PolicyEffect>,
    expired: bool,
    replay_guard: Arc<MemoryReplayGuard>,
) -> Fixture {
    let agent_key = AgentKeyPair::from_secret_bytes(&[11; 32]);
    let issuer_key = AgentKeyPair::from_secret_bytes(&[12; 32]);
    let attester = EvidenceAttesterKey::from_secret_bytes(&[13; 32]);
    let agent = agent_key.identity(AgentId::new());
    let mut authority = Authority::new(
        agent.id.clone(),
        "local-test-issuer",
        vec!["local:write".into()],
    )
    .with_validity(long_validity())
    .with_constraint("tenant_id", TEST_TENANT_ID.to_string());
    authority.sign_for_agent(&issuer_key, &agent).unwrap();

    let action = Action::new(
        "local:set_value",
        Some("local-state".into()),
        json!({"key": "mode", "value": "safe"}),
    )
    .unwrap()
    .with_capability("local:write");
    let rules = effect
        .map(|effect| {
            vec![
                PolicyRule::new("local-set", "local:set_value", effect)
                    .with_capability("local:write"),
            ]
        })
        .unwrap_or_default();
    let policy = Policy::new_v2("local-gateway-test", 1, rules);
    let clock = FixedClock::try_new(NOW).unwrap();
    let now = clock.now();
    let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
    let (issued_at, expires_at) = if expired {
        (now - Duration::minutes(2), now - Duration::seconds(1))
    } else {
        (now - Duration::seconds(1), now + Duration::minutes(1))
    };
    request
        .sign_intent_v2(
            &agent_key,
            "local-test-gateway",
            issued_at,
            expires_at,
            policy.digest().unwrap(),
        )
        .unwrap();

    let issuer_public_key = issuer_key.public_key();
    let engine = production_engine(
        policy.clone(),
        issuer_public_key.clone(),
        attester.clone(),
        replay_guard,
    );
    let tool = Arc::new(LocalSetTool::default());
    let journal = Arc::new(MemoryJournal::default());
    let execution_attester = execution_attester();
    let gateway = Gateway::new(
        engine,
        journal.clone(),
        tool.clone(),
        execution_attester.clone(),
    )
    .unwrap();
    Fixture {
        gateway,
        request,
        tool,
        journal,
        execution_attester,
        policy,
        issuer_public_key,
        attester,
    }
}

fn http_request(body: String) -> Request<Body> {
    http_body_request("POST", "/v1/execute", body)
}

fn http_body_request(method: &str, uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn human_approval_decision(
    challenge: praetore_gateway::ApprovalChallenge,
    outcome: HumanApprovalOutcome,
    signing_key: &SigningKey,
) -> HumanApprovalDecision {
    let mut decision = HumanApprovalDecision {
        schema_version: 1,
        approval_id: Uuid::new_v4(),
        approver_key_id: "test-human-approver-v1".into(),
        challenge,
        outcome,
        signature: String::new(),
    };
    decision.signature = hex::encode(
        signing_key
            .sign(&decision.signing_message().unwrap())
            .to_bytes(),
    );
    decision
}

fn approval_fixture() -> (
    Gateway,
    AuthorizationRequest,
    Arc<LocalSetTool>,
    Arc<MemoryJournal>,
    SigningKey,
) {
    approval_fixture_with_provider(|_| Arc::new(CurrentFreshness))
}

fn approval_fixture_with_provider(
    build_provider: impl FnOnce(Arc<Mutex<OffsetDateTime>>) -> Arc<dyn FreshnessProvider>,
) -> (
    Gateway,
    AuthorizationRequest,
    Arc<LocalSetTool>,
    Arc<MemoryJournal>,
    SigningKey,
) {
    approval_fixture_with_approver(build_provider, [34; 32])
}

fn approval_fixture_with_policy(
    edit: impl FnOnce(&mut Policy),
) -> (
    Gateway,
    AuthorizationRequest,
    Arc<LocalSetTool>,
    Arc<MemoryJournal>,
    SigningKey,
) {
    approval_fixture_with_approver_and_policy(|_| Arc::new(CurrentFreshness), [34; 32], edit)
}

fn approval_fixture_with_approver(
    build_provider: impl FnOnce(Arc<Mutex<OffsetDateTime>>) -> Arc<dyn FreshnessProvider>,
    approver_secret: [u8; 32],
) -> (
    Gateway,
    AuthorizationRequest,
    Arc<LocalSetTool>,
    Arc<MemoryJournal>,
    SigningKey,
) {
    approval_fixture_with_approver_and_policy(build_provider, approver_secret, |_| {})
}

fn approval_fixture_with_approver_and_policy(
    build_provider: impl FnOnce(Arc<Mutex<OffsetDateTime>>) -> Arc<dyn FreshnessProvider>,
    approver_secret: [u8; 32],
    edit: impl FnOnce(&mut Policy),
) -> (
    Gateway,
    AuthorizationRequest,
    Arc<LocalSetTool>,
    Arc<MemoryJournal>,
    SigningKey,
) {
    let (gateway, request, tool, journal, approver_key, _) =
        approval_fixture_full(build_provider, approver_secret, edit, |approver_key| {
            vec![
                HumanApprovalVerifier::new(
                    "test-human-approver-v1",
                    VerifiedPublicKey::from_bytes(&approver_key.verifying_key().to_bytes())
                        .unwrap(),
                )
                .unwrap(),
            ]
        });
    (gateway, request, tool, journal, approver_key)
}

type ApprovalFixtureWithClock = (
    Gateway,
    AuthorizationRequest,
    Arc<LocalSetTool>,
    Arc<MemoryJournal>,
    SigningKey,
    Arc<Mutex<OffsetDateTime>>,
);

fn approval_fixture_with_verifiers(
    verifiers: impl FnOnce(&SigningKey) -> Vec<HumanApprovalVerifier>,
) -> ApprovalFixtureWithClock {
    approval_fixture_full(|_| Arc::new(CurrentFreshness), [34; 32], |_| {}, verifiers)
}

fn approval_fixture_full(
    build_provider: impl FnOnce(Arc<Mutex<OffsetDateTime>>) -> Arc<dyn FreshnessProvider>,
    approver_secret: [u8; 32],
    edit: impl FnOnce(&mut Policy),
    verifiers: impl FnOnce(&SigningKey) -> Vec<HumanApprovalVerifier>,
) -> ApprovalFixtureWithClock {
    let agent_key = AgentKeyPair::from_secret_bytes(&[31; 32]);
    let issuer_key = AgentKeyPair::from_secret_bytes(&[32; 32]);
    let attester = EvidenceAttesterKey::from_secret_bytes(&[33; 32]);
    let agent = agent_key.identity(AgentId::new());
    let mut authority = Authority::new(
        agent.id.clone(),
        "local-test-issuer",
        vec!["local:write".into()],
    )
    .with_validity(long_validity())
    .with_constraint("tenant_id", TEST_TENANT_ID.to_string());
    authority.sign_for_agent(&issuer_key, &agent).unwrap();
    let action = Action::new(
        "local:set_value",
        Some("local-state".into()),
        json!({"key": "mode", "value": "approved"}),
    )
    .unwrap()
    .with_capability("local:write");
    let mut policy = Policy::new_v2(
        "human-approval-test",
        1,
        vec![
            PolicyRule::new(
                "require-human-approval",
                "local:set_value",
                PolicyEffect::RequireApproval,
            )
            .with_capability("local:write"),
        ],
    );
    edit(&mut policy);
    let now = OffsetDateTime::now_utc();
    let clock = Arc::new(Mutex::new(now));
    let policy_digest = policy.digest().unwrap();
    let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
    request
        .sign_intent_v2(
            &agent_key,
            "local-test-gateway",
            now,
            now + Duration::seconds(20),
            policy_digest.clone(),
        )
        .unwrap();

    let issuer_pin = TrustedAuthorityIssuer::new("local-test-issuer", issuer_key.public_key())
        .unwrap()
        .with_validity(long_validity())
        .unwrap();
    let config = HighAssuranceConfig::new(policy_digest, vec![issuer_pin], attester)
        .unwrap()
        .with_audience("local-test-gateway")
        .with_replay_guard(Arc::new(MemoryReplayGuard::default()))
        .with_freshness_provider(build_provider(clock.clone()));
    let engine =
        AuthorizationEngine::production_with_clock(policy, config, SharedTestClock(clock.clone()))
            .unwrap();
    let tool = Arc::new(LocalSetTool::default());
    let journal = Arc::new(MemoryJournal::default());
    let approver_key = SigningKey::from_bytes(&approver_secret);
    let mut gateway =
        Gateway::new(engine, journal.clone(), tool.clone(), execution_attester()).unwrap();
    for verifier in verifiers(&approver_key) {
        gateway = gateway.with_human_approval_verifier(verifier);
    }
    (gateway, request, tool, journal, approver_key, clock)
}

#[tokio::test]
async fn http_gateway_returns_receipt_and_dispatches_allowed_action_once() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    let request_body = serde_json::to_string(&fixture.request).unwrap();
    let app = http_api::router(
        Arc::new(fixture.gateway),
        http_api::ApiAuth::UnauthenticatedLoopbackDemo,
    );

    let response = app.oneshot(http_request(request_body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let receipt: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(receipt["authorization"], "allowed");
    assert_eq!(receipt["execution"], "confirmed");
    assert_eq!(fixture.tool.invocations(), 1);

    let receipt: praetore_gateway::GatewayReceipt = serde_json::from_value(receipt).unwrap();
    receipt
        .verify_with_test_evidence_attester(
            &execution_attester_public_key(),
            "test-execution-attester-v1",
        )
        .unwrap();
    assert_eq!(
        receipt.execution_attestation.tenant_id,
        Some(TEST_TENANT_ID)
    );
    let mut reassigned_attestation = receipt.clone();
    reassigned_attestation.execution_attestation.tenant_id = Some(Uuid::from_u128(2));
    assert!(matches!(
        reassigned_attestation.verify_with_test_evidence_attester(
            &execution_attester_public_key(),
            "test-execution-attester-v1"
        ),
        Err(ExecutionAttestationError::InvalidPayload)
    ));
}

#[tokio::test]
async fn http_gateway_returns_denials_without_dispatch() {
    let fixture = fixture(None, false);
    let request_body = serde_json::to_string(&fixture.request).unwrap();
    let app = http_api::router(
        Arc::new(fixture.gateway),
        http_api::ApiAuth::UnauthenticatedLoopbackDemo,
    );

    let response = app.oneshot(http_request(request_body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let receipt: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(receipt["authorization"], "denied");
    assert_eq!(receipt["execution"], "not_dispatched");
    assert_eq!(fixture.tool.invocations(), 0);
}

#[tokio::test]
async fn http_gateway_returns_approval_receipt_without_dispatch() {
    let fixture = fixture(Some(PolicyEffect::RequireApproval), false);
    let request_body = serde_json::to_string(&fixture.request).unwrap();
    let app = http_api::router(
        Arc::new(fixture.gateway),
        http_api::ApiAuth::UnauthenticatedLoopbackDemo,
    );

    let response = app.oneshot(http_request(request_body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let receipt: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(receipt["authorization"], "requires_approval");
    assert_eq!(receipt["execution"], "not_dispatched");
    assert_eq!(fixture.tool.invocations(), 0);
}

#[test]
fn signed_human_approval_dispatches_the_exact_persisted_action_once() {
    let (gateway, request, tool, journal, approver_key) = approval_fixture();
    let pending = gateway.execute(request).unwrap();
    assert_eq!(pending.authorization, AuthorizationStatus::RequiresApproval);
    assert_eq!(pending.execution, ExecutionStatus::NotDispatched);
    assert_eq!(tool.invocations(), 0);

    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let challenge = gateway.approval_challenge(key).unwrap();
    let other_tenant_key = ExecutionKey {
        tenant_id: Uuid::from_u128(2),
        ..key
    };
    assert!(matches!(
        gateway.approval_challenge(other_tenant_key),
        Err(GatewayError::ExecutionNotFound(_))
    ));
    assert_eq!(
        challenge.action_digest,
        praetore_gateway::action_digest(&pending.evidence.action).unwrap()
    );
    let decision = human_approval_decision(challenge, HumanApprovalOutcome::Approve, &approver_key);
    let resolution = gateway.resolve_human_approval(decision.clone()).unwrap();

    // Approval only records intent: nothing ran yet.
    let HumanApprovalResult::ApprovedPendingDispatch {
        decision: approved_decision,
    } = resolution
    else {
        panic!("approval must report approved_pending_dispatch");
    };
    assert_eq!(approved_decision, decision);
    assert_eq!(tool.invocations(), 0);
    assert_eq!(
        journal.get(key).unwrap().unwrap().execution,
        ExecutionStatus::ApprovedPendingDispatch
    );

    let receipt = gateway.dispatch_approved(key).unwrap();
    assert_eq!(receipt.authorization, AuthorizationStatus::RequiresApproval);
    assert_eq!(receipt.execution, ExecutionStatus::Confirmed);
    assert_eq!(tool.value("mode"), Some(json!("approved")));
    assert_eq!(tool.invocations(), 1);
    assert_eq!(
        journal.get(key).unwrap().unwrap().human_approval,
        Some(decision.clone())
    );
    receipt
        .verify_with_test_evidence_attester(
            &execution_attester_public_key(),
            "test-execution-attester-v1",
        )
        .unwrap();
    assert!(matches!(
        gateway.resolve_human_approval(decision),
        Err(GatewayError::Approval(ApprovalError::NotPending))
    ));
    assert!(matches!(
        gateway.dispatch_approved(key),
        Err(GatewayError::Approval(ApprovalError::NotPending))
    ));
    assert_eq!(tool.invocations(), 1);
    assert_eq!(
        journal.entry(key).unwrap().states,
        vec![
            ExecutionStatus::ApprovedPendingDispatch,
            ExecutionStatus::Dispatched,
            ExecutionStatus::Confirmed
        ]
    );
}

#[test]
fn approved_action_is_not_dispatched_if_freshness_expires_during_approval_commit() {
    let (gateway, request, tool, journal, approver_key) = approval_fixture_with_provider(|clock| {
        Arc::new(ExpiringOnDispatchFreshness {
            clock,
            calls: AtomicUsize::new(0),
            expire_on_call: 2,
            advance_by: Duration::seconds(6),
            lease_duration: Duration::seconds(5),
        })
    });
    let pending = gateway.execute(request).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Approve,
        &approver_key,
    );

    assert!(matches!(
        gateway.resolve_human_approval(decision.clone()),
        Ok(HumanApprovalResult::ApprovedPendingDispatch { .. })
    ));
    // The window closes before the claim: never dispatched, closed with a
    // signed approval_expired reason instead of a failed execution.
    assert!(matches!(
        gateway.dispatch_approved(key),
        Err(GatewayError::Approval(ApprovalError::Expired))
    ));
    assert_eq!(tool.value("mode"), None);
    assert_eq!(tool.invocations(), 0);
    let record = journal.get(key).unwrap().unwrap();
    assert_eq!(record.execution, ExecutionStatus::NotDispatched);
    assert_eq!(record.human_approval, Some(decision.clone()));
    let attestation = record.execution_attestation.unwrap();
    assert_eq!(attestation.execution, ExecutionStatus::NotDispatched);
    assert_eq!(
        attestation.not_dispatched_reason,
        Some(NotDispatchedReason::ApprovalExpired)
    );
    assert_eq!(attestation.schema_version, 3);
    assert!(
        !journal
            .entry(key)
            .unwrap()
            .states
            .contains(&ExecutionStatus::Dispatched)
    );
    assert!(matches!(
        gateway.resolve_human_approval(decision),
        Err(GatewayError::Approval(ApprovalError::NotPending))
    ));
    assert_eq!(tool.invocations(), 0);
}

#[test]
fn human_approval_signature_cannot_be_reused_for_modified_action_scope() {
    let (gateway, request, tool, _, approver_key) = approval_fixture();
    let pending = gateway.execute(request).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let challenge = gateway.approval_challenge(key).unwrap();
    let mut decision =
        human_approval_decision(challenge, HumanApprovalOutcome::Approve, &approver_key);
    decision.challenge.action_digest = "0".repeat(64);

    assert!(matches!(
        gateway.resolve_human_approval(decision),
        Err(GatewayError::Approval(ApprovalError::InvalidChallenge))
    ));
    assert_eq!(tool.invocations(), 0);
}

#[test]
fn rejected_human_approval_is_persisted_without_dispatch() {
    let (gateway, request, tool, journal, approver_key) = approval_fixture();
    let pending = gateway.execute(request).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Reject,
        &approver_key,
    );
    let HumanApprovalResult::Rejected { decision, receipt } =
        gateway.resolve_human_approval(decision).unwrap()
    else {
        panic!("a rejection must return its receipt");
    };

    assert_eq!(receipt.execution, ExecutionStatus::NotDispatched);
    assert_eq!(tool.value("mode"), None);
    assert_eq!(tool.invocations(), 0);
    assert_eq!(
        journal.get(key).unwrap().unwrap().human_approval.unwrap(),
        decision
    );
    assert!(matches!(
        gateway.dispatch_approved(key),
        Err(GatewayError::Approval(ApprovalError::NotPending))
    ));
    assert!(matches!(
        gateway.approval_challenge(key),
        Err(GatewayError::Approval(ApprovalError::NotPending))
    ));
}

#[test]
fn expired_human_rejection_uses_the_engine_clock() {
    let captured_clock = Arc::new(Mutex::new(None));
    let capture = captured_clock.clone();
    let (gateway, request, tool, journal, approver_key) =
        approval_fixture_with_provider(move |clock| {
            *capture.lock().unwrap() = Some(clock);
            Arc::new(CurrentFreshness)
        });
    let pending = gateway.execute(request).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Reject,
        &approver_key,
    );
    let clock = captured_clock.lock().unwrap().clone().unwrap();
    *clock.lock().unwrap() += Duration::seconds(21);

    assert!(matches!(
        gateway.resolve_human_approval(decision),
        Err(GatewayError::Approval(ApprovalError::Expired))
    ));
    let record = journal.get(key).unwrap().unwrap();
    assert_eq!(record.execution, ExecutionStatus::NotDispatched);
    assert!(record.human_approval.is_none());
    assert_eq!(tool.invocations(), 0);
}

#[tokio::test]
async fn http_human_approval_resumes_the_pending_execution() {
    let (gateway, request, tool, _, approver_key) = approval_fixture();
    let app = http_api::router(
        Arc::new(gateway),
        http_api::ApiAuth::UnauthenticatedLoopbackDemo,
    );
    let response = app
        .clone()
        .oneshot(http_request(serde_json::to_string(&request).unwrap()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let pending: praetore_gateway::GatewayReceipt = serde_json::from_slice(&body).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };

    let wrong_tenant_response = app
        .clone()
        .oneshot(http_body_request(
            "GET",
            &format!(
                "/v1/approvals/{}/{}/{}",
                Uuid::from_u128(2),
                key.agent_id,
                key.request_id
            ),
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(wrong_tenant_response.status(), StatusCode::NOT_FOUND);

    let response = app
        .clone()
        .oneshot(http_body_request(
            "GET",
            &format!(
                "/v1/approvals/{}/{}/{}",
                key.tenant_id, key.agent_id, key.request_id
            ),
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let view =
        praetore_gateway::ApprovalChallengeView::from_json(std::str::from_utf8(&body).unwrap())
            .unwrap();
    assert!(view.action_matches_challenge());
    assert_eq!(
        serde_json::to_value(&view.action).unwrap(),
        serde_json::to_value(&request.action).unwrap()
    );
    let challenge = view.challenge;
    let decision = human_approval_decision(challenge, HumanApprovalOutcome::Approve, &approver_key);

    let mismatched_path = app
        .clone()
        .oneshot(http_body_request(
            "POST",
            &format!(
                "/v1/approvals/{}/{}/{}",
                key.tenant_id,
                Uuid::new_v4(),
                key.request_id
            ),
            serde_json::to_string(&decision).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(mismatched_path.status(), StatusCode::BAD_REQUEST);
    assert_eq!(tool.invocations(), 0);

    let response = app
        .clone()
        .oneshot(http_body_request(
            "POST",
            &format!(
                "/v1/approvals/{}/{}/{}",
                key.tenant_id, key.agent_id, key.request_id
            ),
            serde_json::to_string(&decision).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let resolution: Value = serde_json::from_slice(&body).unwrap();
    // The approval response never suggests the action ran.
    assert_eq!(resolution["status"], "approved_pending_dispatch");
    assert!(resolution.get("receipt").is_none());
    assert!(resolution.get("execution").is_none());
    assert_eq!(tool.invocations(), 0);

    let dispatch_path = format!(
        "/v1/approvals/{}/{}/{}/dispatch",
        key.tenant_id, key.agent_id, key.request_id
    );
    let response = app
        .clone()
        .oneshot(http_body_request("POST", &dispatch_path, String::new()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let receipt: praetore_gateway::GatewayReceipt = serde_json::from_slice(&body).unwrap();
    assert_eq!(receipt.execution, ExecutionStatus::Confirmed);
    assert_eq!(tool.value("mode"), Some(json!("approved")));
    assert_eq!(tool.invocations(), 1);

    let response = app
        .oneshot(http_body_request("POST", &dispatch_path, String::new()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(tool.invocations(), 1);
}

#[tokio::test]
async fn http_gateway_executes_authorized_action_with_local_demo_adapter() {
    let agent_key = AgentKeyPair::from_secret_bytes(&[11; 32]);
    let issuer_key = AgentKeyPair::from_secret_bytes(&[12; 32]);
    let evidence_attester = EvidenceAttesterKey::from_secret_bytes(&[13; 32]);
    let agent = agent_key.identity(AgentId::new());
    let mut authority = Authority::new(
        agent.id.clone(),
        "local-test-issuer",
        vec!["demo:write".into()],
    )
    .with_validity(long_validity())
    .with_constraint("tenant_id", TEST_TENANT_ID.to_string());
    authority.sign_for_agent(&issuer_key, &agent).unwrap();

    let action = Action::new(
        "demo:set_value",
        Some("demo-state".into()),
        json!({"key": "mode", "value": "safe"}),
    )
    .unwrap()
    .with_capability("demo:write");
    let policy = Policy::new_v2(
        "local-demo",
        1,
        vec![
            PolicyRule::new("allow-demo-write", "demo:set_value", PolicyEffect::Allow)
                .with_capability("demo:write"),
        ],
    );
    let now = FixedClock::try_new(NOW).unwrap().now();
    let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
    request
        .sign_intent_v2(
            &agent_key,
            "local-test-gateway",
            now - Duration::seconds(1),
            now + Duration::minutes(1),
            policy.digest().unwrap(),
        )
        .unwrap();

    let engine = production_engine(
        policy,
        issuer_key.public_key(),
        evidence_attester,
        Arc::new(MemoryReplayGuard::default()),
    );
    let dispatcher = Arc::new(LocalDemoDispatcher::new());
    let signer = execution_attester();
    let gateway = Gateway::new(
        engine,
        Arc::new(MemoryJournal::default()),
        dispatcher.clone(),
        signer.clone(),
    )
    .unwrap();
    let app = http_api::router(
        Arc::new(gateway),
        http_api::ApiAuth::UnauthenticatedLoopbackDemo,
    );
    let response = app
        .oneshot(http_request(serde_json::to_string(&request).unwrap()))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let receipt: praetore_gateway::GatewayReceipt = serde_json::from_slice(&body).unwrap();
    receipt
        .verify_with_test_evidence_attester(
            &execution_attester_public_key(),
            "test-execution-attester-v1",
        )
        .unwrap();
    assert_eq!(receipt.authorization, AuthorizationStatus::Allowed);
    assert_eq!(receipt.execution, ExecutionStatus::Confirmed);
    assert_eq!(dispatcher.value("mode").as_deref(), Some("safe"));
}

#[tokio::test]
async fn http_gateway_rejects_duplicate_json_keys_before_gateway_execution() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    let mut request_body = serde_json::to_string(&fixture.request).unwrap();
    request_body = request_body.replacen(
        '{',
        &format!(r#"{{"request_id":"{}", "#, fixture.request.request_id),
        1,
    );
    let app = http_api::router(
        Arc::new(fixture.gateway),
        http_api::ApiAuth::UnauthenticatedLoopbackDemo,
    );

    let response = app.oneshot(http_request(request_body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(fixture.tool.invocations(), 0);
}

#[test]
fn allowed_action_is_confirmed_once_and_receipt_separates_decision_from_effect() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    let receipt = fixture.gateway.execute(fixture.request.clone()).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *receipt.evidence.agent.id.as_uuid(),
        request_id: receipt.evidence.request_id,
    };
    let entry = fixture.journal.entry(key).unwrap();

    assert_eq!(receipt.authorization, AuthorizationStatus::Allowed);
    assert_eq!(receipt.execution, ExecutionStatus::Confirmed);
    receipt
        .verify_with_test_evidence_attester(
            &execution_attester_public_key(),
            "test-execution-attester-v1",
        )
        .unwrap();
    assert_eq!(receipt.evidence.decision.outcome, DecisionOutcome::Allow);
    assert_eq!(
        entry.states,
        [ExecutionStatus::Dispatched, ExecutionStatus::Confirmed]
    );
    assert_eq!(entry.execution, ExecutionStatus::Confirmed);
    assert_eq!(entry.authorization, AuthorizationStatus::Allowed);
    assert!(entry.execution_attestation.is_some());
    assert_eq!(
        serde_json::to_value(entry.execution_attestation.unwrap()).unwrap(),
        serde_json::to_value(receipt.execution_attestation.clone()).unwrap()
    );
    assert_eq!(entry.evidence.context_hash, receipt.evidence.context_hash);
    assert_eq!(entry.output, receipt.output);
    assert_eq!(
        receipt.evidence.action.parameters["value"],
        receipt.output.as_ref().unwrap()["value"]
    );

    let mut tampered = receipt.clone();
    tampered.output = Some(json!({"key": "mode", "value": "changed"}));
    assert_eq!(
        tampered.verify_with_test_evidence_attester(
            &execution_attester_public_key(),
            "test-execution-attester-v1",
        ),
        Err(ExecutionAttestationError::InvalidPayload)
    );
    assert_eq!(
        receipt
            .verify_with_test_evidence_attester(&execution_attester_public_key(), "wrong-key-id",),
        Err(ExecutionAttestationError::KeyMismatch)
    );
    assert_eq!(fixture.tool.value("mode"), Some(json!("safe")));
    assert_eq!(fixture.tool.invocations(), 1);
    assert_eq!(fixture.tool.execution_keys(), [key]);

    assert!(matches!(
        fixture.gateway.execute(fixture.request),
        Err(GatewayError::Journal(JournalError::AlreadyRecorded))
    ));
    assert_eq!(fixture.tool.invocations(), 1);
    assert_eq!(
        fixture.journal.mark_dispatched(key),
        Err(JournalError::InvalidTransition)
    );
}

#[test]
fn denied_or_unmatched_action_has_no_observable_tool_effect() {
    for effect in [Some(PolicyEffect::Deny), None] {
        let fixture = fixture(effect, false);
        let receipt = fixture.gateway.execute(fixture.request).unwrap();
        assert_eq!(receipt.authorization, AuthorizationStatus::Denied);
        assert_eq!(receipt.execution, ExecutionStatus::NotDispatched);
        receipt
            .verify_with_test_evidence_attester(
                &execution_attester_public_key(),
                "test-execution-attester-v1",
            )
            .unwrap();
        assert_eq!(fixture.tool.value("mode"), None);
        assert_eq!(fixture.tool.invocations(), 0);
    }
}

#[test]
fn approval_required_is_not_permission_to_dispatch() {
    let fixture = fixture(Some(PolicyEffect::RequireApproval), false);
    let receipt = fixture.gateway.execute(fixture.request).unwrap();
    assert_eq!(receipt.authorization, AuthorizationStatus::RequiresApproval);
    assert_eq!(receipt.execution, ExecutionStatus::NotDispatched);
    receipt
        .verify_with_test_evidence_attester(
            &execution_attester_public_key(),
            "test-execution-attester-v1",
        )
        .unwrap();
    assert_eq!(fixture.tool.value("mode"), None);
    assert_eq!(fixture.tool.invocations(), 0);
}

#[test]
fn expired_request_is_rejected_before_any_tool_invocation() {
    let fixture = fixture(Some(PolicyEffect::Allow), true);
    assert!(matches!(
        fixture.gateway.execute(fixture.request),
        Err(GatewayError::Authorization(PraetoreError::IntentInvalid))
    ));
    assert_eq!(fixture.tool.value("mode"), None);
    assert_eq!(fixture.tool.invocations(), 0);
}

#[test]
fn gateway_does_not_dispatch_when_freshness_expires_after_journal_claim() {
    let agent_key = AgentKeyPair::from_secret_bytes(&[21; 32]);
    let issuer_key = AgentKeyPair::from_secret_bytes(&[22; 32]);
    let attester = EvidenceAttesterKey::from_secret_bytes(&[23; 32]);
    let agent = agent_key.identity(AgentId::new());
    let mut authority = Authority::new(
        agent.id.clone(),
        "local-test-issuer",
        vec!["local:write".into()],
    )
    .with_validity(long_validity())
    .with_constraint("tenant_id", TEST_TENANT_ID.to_string());
    authority.sign_for_agent(&issuer_key, &agent).unwrap();
    let action = Action::new(
        "local:set_value",
        Some("local-state".into()),
        json!({"key": "mode", "value": "safe"}),
    )
    .unwrap()
    .with_capability("local:write");
    let policy = Policy::new_v2(
        "dispatch-freshness-test",
        1,
        vec![
            PolicyRule::new("allow-local-set", "local:set_value", PolicyEffect::Allow)
                .with_capability("local:write"),
        ],
    );
    let initial_time = FixedClock::try_new(NOW).unwrap().now();
    let clock = Arc::new(Mutex::new(initial_time));
    let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
    request
        .sign_intent_v2(
            &agent_key,
            "local-test-gateway",
            initial_time - Duration::seconds(1),
            initial_time + Duration::minutes(1),
            policy.digest().unwrap(),
        )
        .unwrap();
    let issuer_pin = TrustedAuthorityIssuer::new("local-test-issuer", issuer_key.public_key())
        .unwrap()
        .with_validity(long_validity())
        .unwrap();
    let config =
        HighAssuranceConfig::new(policy.digest().unwrap(), vec![issuer_pin], attester.clone())
            .unwrap()
            .with_audience("local-test-gateway")
            .with_replay_guard(Arc::new(MemoryReplayGuard::default()))
            .with_freshness_provider(Arc::new(ExpiringOnDispatchFreshness {
                clock: clock.clone(),
                calls: AtomicUsize::new(0),
                expire_on_call: 1,
                advance_by: Duration::seconds(31),
                lease_duration: Duration::seconds(30),
            }));
    let engine =
        AuthorizationEngine::production_with_clock(policy, config, SharedTestClock(clock)).unwrap();
    let tool = Arc::new(LocalSetTool::default());
    let journal = Arc::new(MemoryJournal::default());
    let gateway =
        Gateway::new(engine, journal.clone(), tool.clone(), execution_attester()).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *request.agent.id.as_uuid(),
        request_id: request.request_id,
    };

    assert!(matches!(
        gateway.execute(request.clone()),
        Err(GatewayError::Authorization(
            PraetoreError::FreshnessCheckFailed(FreshnessError::Expired)
        ))
    ));
    assert_eq!(tool.value("mode"), None);
    assert_eq!(tool.invocations(), 0);
    let record = journal.get(key).unwrap().unwrap();
    assert_eq!(record.execution, ExecutionStatus::Failed);
    assert_eq!(
        record.execution_attestation.unwrap().execution,
        ExecutionStatus::Failed
    );
    assert!(matches!(
        gateway.execute(request),
        Err(GatewayError::Journal(JournalError::AlreadyRecorded))
    ));
    assert_eq!(tool.invocations(), 0);
}

#[test]
fn changing_signed_action_parameters_before_authorization_fails_closed() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    let mut modified = fixture.request;
    modified.action.parameters["value"] = json!("privileged");

    assert!(matches!(
        fixture.gateway.execute(modified),
        Err(GatewayError::Authorization(PraetoreError::IntentInvalid))
    ));
    assert_eq!(fixture.tool.value("mode"), None);
    assert_eq!(fixture.tool.invocations(), 0);
}

#[test]
fn gateway_uses_atomic_commit_instead_of_standalone_replay_guard() {
    let replay_guard = Arc::new(MemoryReplayGuard::default());
    replay_guard.unavailable.store(true, Ordering::SeqCst);
    let fixture = fixture_with_replay(Some(PolicyEffect::Allow), false, replay_guard);
    let receipt = fixture.gateway.execute(fixture.request).unwrap();
    assert_eq!(receipt.execution, ExecutionStatus::Confirmed);
    assert_eq!(fixture.tool.value("mode"), Some(json!("safe")));
    assert_eq!(fixture.tool.invocations(), 1);
}

#[test]
fn development_engine_cannot_construct_gateway() {
    let engine = AuthorizationEngine::development(Policy::new_v2("development-only", 1, vec![]));
    assert_eq!(engine.mode(), EvaluationMode::Development);
    assert!(matches!(
        Gateway::new(
            engine,
            Arc::new(MemoryJournal::default()),
            Arc::new(LocalSetTool::default()),
            execution_attester()
        ),
        Err(GatewayError::HighAssuranceRequired)
    ));
}

#[test]
fn journal_failure_before_dispatch_prevents_tool_invocation() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    fixture
        .journal
        .fail_dispatched
        .store(true, Ordering::SeqCst);
    assert!(matches!(
        fixture.gateway.execute(fixture.request),
        Err(GatewayError::Journal(JournalError::Unavailable))
    ));
    assert_eq!(fixture.tool.value("mode"), None);
    assert_eq!(fixture.tool.invocations(), 0);
}

#[test]
fn ambiguous_adapter_failure_is_recorded_and_never_retried() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    fixture.tool.fail_after_write.store(true, Ordering::SeqCst);
    let receipt = fixture.gateway.execute(fixture.request.clone()).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *receipt.evidence.agent.id.as_uuid(),
        request_id: receipt.evidence.request_id,
    };
    let entry = fixture.journal.entry(key).unwrap();

    assert_eq!(receipt.execution, ExecutionStatus::OutcomeUnknown);
    assert_eq!(fixture.tool.value("mode"), Some(json!("safe")));
    assert_eq!(fixture.tool.invocations(), 1);
    assert_eq!(
        entry.states,
        [ExecutionStatus::Dispatched, ExecutionStatus::OutcomeUnknown]
    );
    fixture
        .tool
        .reconciliation_unknown
        .store(true, Ordering::SeqCst);
    let unresolved = fixture.gateway.reconcile(key).unwrap();
    assert_eq!(unresolved.execution, ExecutionStatus::OutcomeUnknown);
    assert_eq!(fixture.tool.invocations(), 1);
    fixture
        .tool
        .reconciliation_unknown
        .store(false, Ordering::SeqCst);
    let reconciled = fixture.gateway.reconcile(key).unwrap();
    assert_eq!(reconciled.execution, ExecutionStatus::Confirmed);
    assert!(matches!(
        fixture.gateway.execute(fixture.request),
        Err(GatewayError::Journal(JournalError::AlreadyRecorded))
    ));
    assert_eq!(fixture.tool.invocations(), 1);
}

#[test]
fn terminal_journal_failure_is_reported_without_a_retry() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    fixture.journal.fail_terminal.store(true, Ordering::SeqCst);
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *fixture.request.agent.id.as_uuid(),
        request_id: fixture.request.request_id,
    };

    assert!(matches!(
        fixture.gateway.execute(fixture.request.clone()),
        Err(GatewayError::OutcomeNotRecorded(actual_key)) if actual_key == key
    ));
    assert_eq!(fixture.tool.value("mode"), Some(json!("safe")));
    assert_eq!(fixture.tool.invocations(), 1);
    fixture.journal.fail_terminal.store(false, Ordering::SeqCst);
    let reconciled = fixture.gateway.reconcile(key).unwrap();
    assert_eq!(reconciled.execution, ExecutionStatus::Confirmed);
    assert_eq!(fixture.tool.invocations(), 1);
    assert!(matches!(
        fixture.gateway.execute(fixture.request),
        Err(GatewayError::Journal(JournalError::AlreadyRecorded))
    ));
    assert_eq!(fixture.tool.invocations(), 1);
}

#[test]
fn signer_failure_after_execution_is_recoverable_without_redispatch() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    fixture
        .execution_attester
        .fail_signing
        .store(true, Ordering::SeqCst);
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *fixture.request.agent.id.as_uuid(),
        request_id: fixture.request.request_id,
    };

    assert!(matches!(
        fixture.gateway.execute(fixture.request.clone()),
        Err(GatewayError::ExecutionAttestation(
            ExecutionAttestationError::SignerFailed
        ))
    ));
    assert_eq!(fixture.tool.invocations(), 1);
    let persisted = fixture.journal.entry(key).unwrap();
    assert_eq!(persisted.execution, ExecutionStatus::Dispatched);
    assert!(persisted.execution_attestation.is_none());

    fixture
        .execution_attester
        .fail_signing
        .store(false, Ordering::SeqCst);
    let receipt = fixture.gateway.reconcile(key).unwrap();
    assert_eq!(receipt.execution, ExecutionStatus::Confirmed);
    receipt
        .verify_with_test_evidence_attester(
            &execution_attester_public_key(),
            "test-execution-attester-v1",
        )
        .unwrap();
    assert_eq!(fixture.tool.invocations(), 1);
}

#[test]
fn reconciliation_reuses_the_persisted_attestation_without_signing_again() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    let receipt = fixture.gateway.execute(fixture.request).unwrap();
    let signed_count = fixture.execution_attester.sign_count();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *receipt.evidence.agent.id.as_uuid(),
        request_id: receipt.evidence.request_id,
    };

    let recovered = fixture.gateway.reconcile(key).unwrap();
    assert_eq!(recovered.execution, ExecutionStatus::Confirmed);
    assert_eq!(fixture.execution_attester.sign_count(), signed_count);
    assert_eq!(
        serde_json::to_value(recovered.execution_attestation).unwrap(),
        serde_json::to_value(receipt.execution_attestation).unwrap()
    );
    assert_eq!(fixture.tool.invocations(), 1);
}

#[test]
fn concurrent_duplicate_requests_cause_at_most_one_effect() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    let workers = 12;
    let gateway = Arc::new(fixture.gateway);
    let request = fixture.request;
    let handles = (0..workers)
        .map(|_| {
            let gateway = gateway.clone();
            let request = request.clone();
            thread::spawn(move || gateway.execute(request))
        })
        .collect::<Vec<_>>();
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(
                result,
                Err(GatewayError::Journal(JournalError::AlreadyRecorded))
            ))
            .count(),
        workers - 1
    );
    assert_eq!(fixture.tool.value("mode"), Some(json!("safe")));
    assert_eq!(fixture.tool.invocations(), 1);
}

#[test]
fn shared_execution_journal_rejects_duplicate_key_across_independent_engines() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *fixture.request.agent.id.as_uuid(),
        request_id: fixture.request.request_id,
    };
    let second_engine = production_engine(
        fixture.policy.clone(),
        fixture.issuer_public_key.clone(),
        fixture.attester.clone(),
        Arc::new(MemoryReplayGuard::default()),
    );
    let second_gateway = Gateway::new(
        second_engine,
        fixture.journal.clone(),
        fixture.tool.clone(),
        execution_attester(),
    )
    .unwrap();

    fixture
        .gateway
        .execute(fixture.request.clone())
        .expect("first engine should authorize and execute");
    assert!(matches!(
        second_gateway.execute(fixture.request),
        Err(GatewayError::Journal(JournalError::AlreadyRecorded))
    ));
    assert_eq!(fixture.tool.value("mode"), Some(json!("safe")));
    assert_eq!(fixture.tool.invocations(), 1);
    let reconciled = fixture.gateway.reconcile(key).unwrap();
    assert_eq!(reconciled.execution, ExecutionStatus::Confirmed);
    assert_eq!(fixture.tool.invocations(), 1);
}

#[test]
fn journal_backend_failure_fails_closed_before_effect() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    fixture.journal.unavailable.store(true, Ordering::SeqCst);
    assert!(matches!(
        fixture.gateway.execute(fixture.request),
        Err(GatewayError::Journal(JournalError::Unavailable))
    ));
    assert_eq!(fixture.tool.value("mode"), None);
    assert_eq!(fixture.tool.invocations(), 0);
}

#[test]
fn requesting_agent_key_cannot_approve_its_own_action() {
    // The fixture agent key is derived from [31; 32]; configure the approver
    // verifier with that same key so the signature is valid but self-issued.
    let (gateway, request, tool, journal, approver_key) =
        approval_fixture_with_approver(|_| Arc::new(CurrentFreshness), [31; 32]);
    let pending = gateway.execute(request).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Approve,
        &approver_key,
    );

    assert!(matches!(
        gateway.resolve_human_approval(decision),
        Err(GatewayError::Approval(ApprovalError::SelfApproval))
    ));
    let record = journal.get(key).unwrap().unwrap();
    assert_eq!(record.execution, ExecutionStatus::NotDispatched);
    assert!(record.human_approval.is_none());
    assert_eq!(tool.invocations(), 0);
}

#[test]
fn approval_for_unknown_execution_is_rejected_without_dispatch() {
    let (gateway, request, tool, _, approver_key) = approval_fixture();
    let pending = gateway.execute(request).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let mut decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Approve,
        &approver_key,
    );
    decision.challenge.request_id = Uuid::new_v4();
    assert!(matches!(
        gateway.resolve_human_approval(decision),
        Err(GatewayError::ExecutionNotFound(_))
    ));
    let unknown = ExecutionKey {
        request_id: Uuid::new_v4(),
        ..key
    };
    assert!(matches!(
        gateway.approval_challenge(unknown),
        Err(GatewayError::ExecutionNotFound(_))
    ));
    assert_eq!(tool.invocations(), 0);
}

fn pending_key(gateway: &Gateway, request: AuthorizationRequest) -> ExecutionKey {
    let pending = gateway.execute(request).unwrap();
    ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    }
}

#[test]
fn approval_resolution_reports_pending_then_approved() {
    let (gateway, request, tool, _, approver_key) = approval_fixture();
    let key = pending_key(&gateway, request);
    assert_eq!(
        gateway.approval_resolution(key).unwrap(),
        praetore_gateway::ApprovalResolution::Pending
    );
    let decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Approve,
        &approver_key,
    );
    gateway.resolve_human_approval(decision).unwrap();
    assert_eq!(
        gateway.approval_resolution(key).unwrap(),
        praetore_gateway::ApprovalResolution::Approved
    );
    assert_eq!(tool.invocations(), 0);
    gateway.dispatch_approved(key).unwrap();
    assert_eq!(
        gateway.approval_resolution(key).unwrap(),
        praetore_gateway::ApprovalResolution::Approved
    );
    assert_eq!(tool.invocations(), 1);
}

#[test]
fn approval_resolution_reports_rejected_without_dispatch() {
    let (gateway, request, tool, _, approver_key) = approval_fixture();
    let key = pending_key(&gateway, request);
    let decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Reject,
        &approver_key,
    );
    gateway.resolve_human_approval(decision).unwrap();
    assert_eq!(
        gateway.approval_resolution(key).unwrap(),
        praetore_gateway::ApprovalResolution::Rejected
    );
    assert_eq!(tool.invocations(), 0);
}

#[test]
fn approval_resolution_reports_expired_and_challenge_is_refused() {
    let captured_clock = Arc::new(Mutex::new(None));
    let capture = captured_clock.clone();
    let (gateway, request, tool, _, _) = approval_fixture_with_provider(move |clock| {
        *capture.lock().unwrap() = Some(clock);
        Arc::new(CurrentFreshness)
    });
    let key = pending_key(&gateway, request);
    let clock = captured_clock.lock().unwrap().clone().unwrap();
    *clock.lock().unwrap() += Duration::seconds(21);
    assert_eq!(
        gateway.approval_resolution(key).unwrap(),
        praetore_gateway::ApprovalResolution::Expired
    );
    assert!(matches!(
        gateway.approval_challenge(key),
        Err(GatewayError::Approval(ApprovalError::Expired))
    ));
    assert_eq!(tool.invocations(), 0);
}

#[test]
fn approval_resolution_is_scoped_to_the_exact_key() {
    let (gateway, request, _, _, _) = approval_fixture();
    let key = pending_key(&gateway, request);
    for other in [
        ExecutionKey {
            tenant_id: Uuid::from_u128(2),
            ..key
        },
        ExecutionKey {
            agent_id: Uuid::new_v4(),
            ..key
        },
        ExecutionKey {
            request_id: Uuid::new_v4(),
            ..key
        },
    ] {
        assert!(matches!(
            gateway.approval_resolution(other),
            Err(GatewayError::ExecutionNotFound(_))
        ));
    }
}

#[test]
fn approval_resolution_is_not_reported_for_actions_that_never_required_approval() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    let receipt = fixture.gateway.execute(fixture.request).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *receipt.evidence.agent.id.as_uuid(),
        request_id: receipt.evidence.request_id,
    };
    assert!(matches!(
        fixture.gateway.approval_resolution(key),
        Err(GatewayError::Approval(ApprovalError::NotPending))
    ));
}

async fn json_response(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: String,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(http_body_request(method, uri, body))
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn http_conflicts_and_status_report_the_resolution() {
    for (outcome, expected, execution) in [
        (
            HumanApprovalOutcome::Approve,
            "approved",
            "approved_pending_dispatch",
        ),
        (HumanApprovalOutcome::Reject, "rejected", "not_dispatched"),
    ] {
        let (gateway, request, _, _, approver_key) = approval_fixture();
        let gateway = Arc::new(gateway);
        let key = pending_key(&gateway, request);
        let app = http_api::router(
            gateway.clone(),
            http_api::ApiAuth::UnauthenticatedLoopbackDemo,
        );
        let path = format!(
            "/v1/approvals/{}/{}/{}",
            key.tenant_id, key.agent_id, key.request_id
        );
        let (status, body) =
            json_response(&app, "GET", &format!("{path}/status"), String::new()).await;
        assert_eq!(
            (status, body),
            (
                StatusCode::OK,
                json!({"resolution": "pending", "execution": "not_dispatched"})
            )
        );

        let decision = human_approval_decision(
            gateway.approval_challenge(key).unwrap(),
            outcome,
            &approver_key,
        );
        let decision_json = serde_json::to_string(&decision).unwrap();
        let (status, _) = json_response(&app, "POST", &path, decision_json.clone()).await;
        assert_eq!(status, StatusCode::OK);

        let conflict = json!({"code": "approval_not_pending", "resolution": expected});
        let (status, body) = json_response(&app, "GET", &path, String::new()).await;
        assert_eq!((status, body), (StatusCode::CONFLICT, conflict.clone()));
        let (status, body) = json_response(&app, "POST", &path, decision_json).await;
        assert_eq!((status, body), (StatusCode::CONFLICT, conflict));
        let (status, body) =
            json_response(&app, "GET", &format!("{path}/status"), String::new()).await;
        assert_eq!(
            (status, body),
            (
                StatusCode::OK,
                json!({"resolution": expected, "execution": execution})
            )
        );

        let other_tenant = format!(
            "/v1/approvals/{}/{}/{}/status",
            Uuid::from_u128(2),
            key.agent_id,
            key.request_id
        );
        let (status, body) = json_response(&app, "GET", &other_tenant, String::new()).await;
        assert_eq!(
            (status, body),
            (
                StatusCode::NOT_FOUND,
                json!({"code": "execution_not_found"})
            )
        );
    }
}

#[tokio::test]
async fn http_expired_approval_reports_expired_resolution() {
    let captured_clock = Arc::new(Mutex::new(None));
    let capture = captured_clock.clone();
    let (gateway, request, _, _, _) = approval_fixture_with_provider(move |clock| {
        *capture.lock().unwrap() = Some(clock);
        Arc::new(CurrentFreshness)
    });
    let gateway = Arc::new(gateway);
    let key = pending_key(&gateway, request);
    let clock = captured_clock.lock().unwrap().clone().unwrap();
    *clock.lock().unwrap() += Duration::seconds(21);
    let app = http_api::router(gateway, http_api::ApiAuth::UnauthenticatedLoopbackDemo);
    let path = format!(
        "/v1/approvals/{}/{}/{}",
        key.tenant_id, key.agent_id, key.request_id
    );
    let (status, body) = json_response(&app, "GET", &path, String::new()).await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(body["code"], "approval_expired");
    assert_eq!(body["resolution"], "expired");
}

// SAF-10 property tests (docs/proposals/SAF-10-RECOVER-Y-VENCIMIENTO-DE-APROBACIONES.md §8).
// `saf10_today` holds on a797bea already; `saf10_full` needs the SAF-10
// implementation (ApprovalExpiredReceipt, Recover, max_approval_ms).
mod saf10_today {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Property 5 (current subset): with no signed human decision and
        /// the engine clock past `expires_at`, nothing is dispatched, the
        /// resolution is Expired, and a late approval is refused and not
        /// stored. (The single signed `ApprovalExpiredReceipt` is pending.)
        #[test]
        fn p5_no_approval_by_silence(advance in 21i64..86_400) {
            let captured_clock = Arc::new(Mutex::new(None));
            let capture = captured_clock.clone();
            let (gateway, request, tool, journal, approver_key) =
                approval_fixture_with_provider(move |clock| {
                    *capture.lock().unwrap() = Some(clock);
                    Arc::new(CurrentFreshness)
                });
            let key = pending_key(&gateway, request);
            let late = human_approval_decision(
                gateway.approval_challenge(key).unwrap(),
                HumanApprovalOutcome::Approve,
                &approver_key,
            );
            let clock = captured_clock.lock().unwrap().clone().unwrap();
            *clock.lock().unwrap() += Duration::seconds(advance);

            prop_assert_eq!(
                gateway.approval_resolution(key).unwrap(),
                praetore_gateway::ApprovalResolution::Expired
            );
            prop_assert!(matches!(
                gateway.resolve_human_approval(late),
                Err(GatewayError::Approval(ApprovalError::Expired))
            ));
            let record = journal.get(key).unwrap().unwrap();
            prop_assert_eq!(record.execution, ExecutionStatus::NotDispatched);
            prop_assert!(record.human_approval.is_none());
            prop_assert_eq!(tool.invocations(), 0);
        }

        /// Property 2 (dispatch part): a Deny never reaches the adapter.
        #[test]
        fn p2_deny_never_dispatches(_case in 0u8..4) {
            let fixture = fixture(Some(PolicyEffect::Deny), false);
            let receipt = fixture.gateway.execute(fixture.request).unwrap();
            prop_assert_eq!(receipt.authorization, AuthorizationStatus::Denied);
            prop_assert_eq!(receipt.execution, ExecutionStatus::NotDispatched);
            prop_assert_eq!(fixture.tool.invocations(), 0);
        }

        /// Property 8 (current subset): v2 evidence produced today keeps
        /// verifying after a JSON round trip, for every outcome. There is no
        /// frozen v2 golden vector in the repo yet (review note 5).
        #[test]
        fn p8_v2_evidence_round_trip_verifies(
            effect in prop_oneof![
                Just(Some(PolicyEffect::Allow)),
                Just(Some(PolicyEffect::RequireApproval)),
                Just(Some(PolicyEffect::Deny)),
                Just(None),
            ]
        ) {
            let fixture = fixture(effect, false);
            let receipt = fixture.gateway.execute(fixture.request).unwrap();
            let evidence = receipt.evidence;
            prop_assert_eq!(evidence.evidence_schema_version, 2);
            prop_assert!(evidence.verify_integrity());
            let json = serde_json::to_string(&evidence).unwrap();
            let parsed: Evidence = serde_json::from_str(&json).unwrap();
            prop_assert!(parsed.verify_integrity());
            prop_assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
        }
    }
}

/// SAF-10 properties against the implemented gateway API.
mod saf10_full {
    use super::*;
    use praetore_gateway::{ApprovalExpiredReceipt, ExpiredOutcome};

    type ExpiredFixture = (
        Gateway,
        ExecutionKey,
        Arc<LocalSetTool>,
        Arc<MemoryJournal>,
        SigningKey,
        Arc<Mutex<OffsetDateTime>>,
    );

    fn expired_fixture() -> ExpiredFixture {
        let captured_clock = Arc::new(Mutex::new(None));
        let capture = captured_clock.clone();
        let (gateway, request, tool, journal, approver_key) =
            approval_fixture_with_provider(move |clock| {
                *capture.lock().unwrap() = Some(clock);
                Arc::new(CurrentFreshness)
            });
        let key = pending_key(&gateway, request);
        let clock = captured_clock.lock().unwrap().clone().unwrap();
        (gateway, key, tool, journal, approver_key, clock)
    }

    fn receipt(journal: &MemoryJournal, key: ExecutionKey) -> Option<ApprovalExpiredReceipt> {
        journal.get(key).unwrap().unwrap().approval_expiration
    }

    /// Property 5 (full): after expiry there is no dispatch and exactly one
    /// valid signed `ApprovalExpiredReceipt`, stable across every detection
    /// path (status query, challenge, late resolution).
    #[test]
    fn p5_exactly_one_expiration_receipt() {
        let (gateway, key, tool, journal, approver_key, clock) = expired_fixture();
        let late = human_approval_decision(
            gateway.approval_challenge(key).unwrap(),
            HumanApprovalOutcome::Approve,
            &approver_key,
        );
        assert!(receipt(&journal, key).is_none());
        *clock.lock().unwrap() += Duration::seconds(21);
        let observed = *clock.lock().unwrap();

        assert_eq!(
            gateway.approval_resolution(key).unwrap(),
            praetore_gateway::ApprovalResolution::Expired
        );
        let first = receipt(&journal, key).expect("receipt on first detection");
        assert!(gateway.approval_challenge(key).is_err());
        assert!(gateway.resolve_human_approval(late).is_err());
        gateway.approval_resolution(key).unwrap();
        let again = receipt(&journal, key).unwrap();
        assert_eq!(
            serde_json::to_value(&first).unwrap(),
            serde_json::to_value(&again).unwrap()
        );

        let record = journal.get(key).unwrap().unwrap();
        first
            .verify(
                &record.evidence,
                &execution_attester_public_key(),
                "test-execution-attester-v1",
            )
            .unwrap();
        assert_eq!(first.effective_outcome, ExpiredOutcome::Deny);
        assert_eq!(
            OffsetDateTime::parse(
                &first.observed_at,
                &time::format_description::well_known::Rfc3339
            )
            .unwrap(),
            observed
        );
        assert!(record.human_approval.is_none());
        assert_eq!(record.execution, ExecutionStatus::NotDispatched);
        assert_eq!(tool.invocations(), 0);

        let mut forged = first.clone();
        forged.request_id = Uuid::from_u128(9);
        assert!(
            forged
                .verify(
                    &record.evidence,
                    &execution_attester_public_key(),
                    "test-execution-attester-v1"
                )
                .is_err()
        );
    }

    /// Property 6: a human decision and an expiration never coexist.
    #[test]
    fn p6_decision_then_expiry_keeps_only_the_decision() {
        let (gateway, key, _, journal, approver_key, clock) = expired_fixture();
        let decision = human_approval_decision(
            gateway.approval_challenge(key).unwrap(),
            HumanApprovalOutcome::Reject,
            &approver_key,
        );
        gateway.resolve_human_approval(decision).unwrap();
        *clock.lock().unwrap() += Duration::seconds(21);
        assert_eq!(
            gateway.approval_resolution(key).unwrap(),
            praetore_gateway::ApprovalResolution::Rejected
        );
        let record = journal.get(key).unwrap().unwrap();
        assert!(record.human_approval.is_some());
        assert!(record.approval_expiration.is_none());
    }

    #[test]
    fn p6_expiry_then_decision_is_refused_by_the_journal() {
        let (gateway, key, _, journal, approver_key, clock) = expired_fixture();
        let decision = human_approval_decision(
            gateway.approval_challenge(key).unwrap(),
            HumanApprovalOutcome::Approve,
            &approver_key,
        );
        *clock.lock().unwrap() += Duration::seconds(21);
        gateway.approval_resolution(key).unwrap();
        let now = *clock.lock().unwrap();
        assert!(journal.record_human_approval(key, &decision, now).is_err());
        let record = journal.get(key).unwrap().unwrap();
        assert!(record.human_approval.is_none());
        assert!(record.approval_expiration.is_some());
    }

    /// Property 4: a decision with recovery is NotDispatched with zero
    /// adapter invocations, even though a signed denial attestation exists.
    #[test]
    fn p4_recover_never_dispatches() {
        let fixture = fixture(
            Some(PolicyEffect::Recover {
                recovery_id: "safe-hold".into(),
                deadline_ms: 500,
            }),
            false,
        );
        let receipt = fixture.gateway.execute(fixture.request).unwrap();
        let recovery = receipt.evidence.decision.recovery.as_ref().unwrap();
        assert_eq!(recovery.recovery_id, "safe-hold");
        assert_eq!(receipt.evidence.evidence_schema_version, 3);
        assert_eq!(receipt.authorization, AuthorizationStatus::Denied);
        assert_eq!(receipt.execution, ExecutionStatus::NotDispatched);
        receipt
            .verify_with_test_evidence_attester(
                &execution_attester_public_key(),
                "test-execution-attester-v1",
            )
            .unwrap();
        assert_eq!(fixture.tool.invocations(), 0);
        let reparsed = Evidence::from_json(&serde_json::to_string(&receipt.evidence).unwrap());
        assert!(reparsed.unwrap().verify_integrity());
    }

    /// HTTP 410 carries the id of the persisted `ApprovalExpiredReceipt`,
    /// both on the challenge read and on a late signed decision.
    #[tokio::test]
    async fn http_410_carries_the_expiration_receipt_id() {
        let (gateway, key, tool, journal, approver_key, clock) = expired_fixture();
        let late = human_approval_decision(
            gateway.approval_challenge(key).unwrap(),
            HumanApprovalOutcome::Approve,
            &approver_key,
        );
        *clock.lock().unwrap() += Duration::seconds(21);
        let app = http_api::router(
            Arc::new(gateway),
            http_api::ApiAuth::UnauthenticatedLoopbackDemo,
        );
        let path = format!(
            "/v1/approvals/{}/{}/{}",
            key.tenant_id, key.agent_id, key.request_id
        );

        let (status, body) = json_response(&app, "GET", &path, String::new()).await;
        let receipt = receipt(&journal, key).expect("receipt persisted on first detection");
        assert_eq!(
            (status, body),
            (
                StatusCode::GONE,
                json!({
                    "code": "approval_expired",
                    "resolution": "expired",
                    "expiration_receipt_id": receipt.receipt_id.to_string(),
                })
            )
        );
        let (status, body) =
            json_response(&app, "POST", &path, serde_json::to_string(&late).unwrap()).await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(
            body["expiration_receipt_id"],
            json!(receipt.receipt_id.to_string())
        );
        assert_eq!(tool.invocations(), 0);
    }

    /// A 410 whose receipt cannot be read back omits
    /// `expiration_receipt_id` and still dispatches nothing.
    #[tokio::test]
    async fn http_410_with_unreadable_receipt_omits_the_id() {
        let (gateway, key, tool, journal, _, clock) = expired_fixture();
        journal.unreadable_expiration.store(true, Ordering::SeqCst);
        *clock.lock().unwrap() += Duration::seconds(21);
        let app = http_api::router(
            Arc::new(gateway),
            http_api::ApiAuth::UnauthenticatedLoopbackDemo,
        );
        let path = format!(
            "/v1/approvals/{}/{}/{}",
            key.tenant_id, key.agent_id, key.request_id
        );
        let (status, body) = json_response(&app, "GET", &path, String::new()).await;
        assert_eq!(
            (status, body),
            (StatusCode::GONE, json!({"code": "approval_expired"}))
        );
        // The receipt was persisted; only reading it back fails.
        journal.unreadable_expiration.store(false, Ordering::SeqCst);
        assert!(receipt(&journal, key).is_some());
        assert_eq!(tool.invocations(), 0);
    }

    /// Decision 2 (CTO): a request whose approval window exceeds
    /// `max_approval_ms` is rejected before any record or dispatch.
    #[test]
    fn approval_window_longer_than_policy_bound_is_rejected() {
        let (gateway, request, tool, journal, _) =
            approval_fixture_with_policy(|policy| policy.max_approval_ms = Some(5_000));
        let key = ExecutionKey {
            tenant_id: TEST_TENANT_ID,
            agent_id: *request.agent.id.as_uuid(),
            request_id: request.request_id,
        };
        assert!(gateway.execute(request).is_err());
        assert!(journal.get(key).unwrap().is_none());
        assert_eq!(tool.invocations(), 0);
    }

    #[test]
    fn approval_window_within_policy_bound_is_pending() {
        let (gateway, request, tool, _, _) =
            approval_fixture_with_policy(|policy| policy.max_approval_ms = Some(60_000));
        let receipt = gateway.execute(request).unwrap();
        assert_eq!(receipt.authorization, AuthorizationStatus::RequiresApproval);
        assert_eq!(tool.invocations(), 0);
    }
}

/// approved_pending_dispatch (APD) against the in-memory journal.
mod apd {
    use super::*;
    use proptest::prelude::*;

    type ClockedFixture = (
        Gateway,
        ExecutionKey,
        Arc<LocalSetTool>,
        Arc<MemoryJournal>,
        SigningKey,
        Arc<Mutex<OffsetDateTime>>,
    );

    fn clocked_fixture() -> ClockedFixture {
        let captured_clock = Arc::new(Mutex::new(None));
        let capture = captured_clock.clone();
        let (gateway, request, tool, journal, approver_key) =
            approval_fixture_with_provider(move |clock| {
                *capture.lock().unwrap() = Some(clock);
                Arc::new(CurrentFreshness)
            });
        let key = pending_key(&gateway, request);
        let clock = captured_clock.lock().unwrap().clone().unwrap();
        (gateway, key, tool, journal, approver_key, clock)
    }

    fn approve(gateway: &Gateway, key: ExecutionKey, approver_key: &SigningKey) {
        let decision = human_approval_decision(
            gateway.approval_challenge(key).unwrap(),
            HumanApprovalOutcome::Approve,
            approver_key,
        );
        assert!(matches!(
            gateway.resolve_human_approval(decision),
            Ok(HumanApprovalResult::ApprovedPendingDispatch { .. })
        ));
    }

    /// Receipts consumed by the external verifiers (praetore-verify and the
    /// Python package). `UPDATE_RECEIPT_FIXTURES=1` regenerates them; by
    /// default the committed files must still verify.
    #[test]
    fn receipt_fixtures_for_external_verifiers() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages/praetore-python/tests/fixtures");
        let key_id = "test-execution-attester-v1";
        let public_key = execution_attester_public_key();
        // The evidence attester used by `approval_fixture_with_approver_and_policy`.
        let evidence_key = EvidenceAttesterKey::from_secret_bytes(&[33; 32])
            .public_key()
            .unwrap();
        let evidence_key_path = dir.join("receipt-evidence-attester-public-key.hex");
        if std::env::var_os("UPDATE_RECEIPT_FIXTURES").is_some()
            || std::env::var_os("UPDATE_RECEIPT_V1_FIXTURE").is_some()
        {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&evidence_key_path, hex::encode(evidence_key.as_bytes())).unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(&evidence_key_path).unwrap().trim(),
            hex::encode(evidence_key.as_bytes())
        );
        if std::env::var_os("UPDATE_RECEIPT_FIXTURES").is_some() {
            let (gateway, key, _, _, approver_key, _) = clocked_fixture();
            approve(&gateway, key, &approver_key);
            let closed = gateway.reconcile(key).unwrap();
            assert_eq!(closed.execution_attestation.schema_version, 3);
            let (gateway, key, _, _, approver_key, _) = clocked_fixture();
            approve(&gateway, key, &approver_key);
            let dispatched = gateway.dispatch_approved(key).unwrap();
            assert_eq!(dispatched.execution_attestation.schema_version, 2);
            std::fs::create_dir_all(&dir).unwrap();
            for (name, receipt) in [
                ("receipt-v3-crash-recovered.json", &closed),
                ("receipt-v2-confirmed.json", &dispatched),
            ] {
                std::fs::write(dir.join(name), serde_json::to_string(receipt).unwrap()).unwrap();
            }
            std::fs::write(
                dir.join("execution-attester-public-key.hex"),
                hex::encode(public_key.as_bytes()),
            )
            .unwrap();
        }
        // The gateway no longer emits v1 (it always binds a tenant), so the v1
        // fixture re-signs the committed v2 receipt as a legacy v1
        // attestation with the same test key and canonical payload rules.
        if std::env::var_os("UPDATE_RECEIPT_FIXTURES").is_some()
            || std::env::var_os("UPDATE_RECEIPT_V1_FIXTURE").is_some()
        {
            let v2 = std::fs::read_to_string(dir.join("receipt-v2-confirmed.json")).unwrap();
            let mut receipt: Value = serde_json::from_str(&v2).unwrap();
            let attestation = receipt["execution_attestation"].as_object_mut().unwrap();
            attestation.insert("schema_version".into(), json!(1));
            attestation.remove("tenant_id");
            attestation.remove("signature");
            let canonical = praetore_core::canonical::canonicalize_json(
                &serde_json::to_string(attestation).unwrap(),
            )
            .unwrap();
            let mut message = b"PRAETORE_EXECUTION_ATTESTATION_V1\0".to_vec();
            message.extend_from_slice(&canonical);
            let signature = TestExecutionAttester::new().signing_key.sign(&message);
            attestation.insert("tenant_id".into(), Value::Null);
            attestation.insert("signature".into(), json!(hex::encode(signature.to_bytes())));
            std::fs::write(
                dir.join("receipt-v1-confirmed.json"),
                serde_json::to_string(&receipt).unwrap(),
            )
            .unwrap();
        }
        let v1 = std::fs::read_to_string(dir.join("receipt-v1-confirmed.json")).unwrap();
        let receipt =
            praetore_gateway::verify_gateway_receipt_json(&v1, &public_key, key_id, &evidence_key)
                .unwrap();
        assert_eq!(receipt.execution_attestation.schema_version, 1);
        assert_eq!(receipt.execution_attestation.tenant_id, None);
        let tampered = v1.replacen("\"confirmed\"", "\"failed\"", 1);
        assert_ne!(tampered, v1);
        assert!(
            praetore_gateway::verify_gateway_receipt_json(
                &tampered,
                &public_key,
                key_id,
                &evidence_key
            )
            .is_err()
        );
        let v3 = std::fs::read_to_string(dir.join("receipt-v3-crash-recovered.json")).unwrap();
        let receipt =
            praetore_gateway::verify_gateway_receipt_json(&v3, &public_key, key_id, &evidence_key)
                .unwrap();
        assert_eq!(
            receipt.execution_attestation.not_dispatched_reason,
            Some(NotDispatchedReason::CrashRecovered)
        );
        let v2 = std::fs::read_to_string(dir.join("receipt-v2-confirmed.json")).unwrap();
        praetore_gateway::verify_gateway_receipt_json(&v2, &public_key, key_id, &evidence_key)
            .unwrap();
        // Unknown reason: rejected at parse time.
        let unknown = v3.replace("\"crash_recovered\"", "\"operator_override\"");
        assert_ne!(unknown, v3);
        assert!(matches!(
            praetore_gateway::verify_gateway_receipt_json(
                &unknown,
                &public_key,
                key_id,
                &evidence_key
            ),
            Err(ExecutionAttestationError::InvalidPayload)
        ));
        // A different known reason breaks the signature.
        let swapped = v3.replace("\"crash_recovered\"", "\"approval_expired\"");
        assert!(matches!(
            praetore_gateway::verify_gateway_receipt_json(
                &swapped,
                &public_key,
                key_id,
                &evidence_key
            ),
            Err(ExecutionAttestationError::InvalidSignature)
        ));
    }

    #[test]
    fn reconcile_closes_apd_as_crash_recovered_without_the_adapter() {
        let (gateway, key, tool, journal, approver_key, _) = clocked_fixture();
        approve(&gateway, key, &approver_key);
        let receipt = gateway.reconcile(key).unwrap();
        assert_eq!(receipt.execution, ExecutionStatus::NotDispatched);
        assert_eq!(
            receipt.execution_attestation.not_dispatched_reason,
            Some(NotDispatchedReason::CrashRecovered)
        );
        receipt
            .verify_with_test_evidence_attester(
                &execution_attester_public_key(),
                "test-execution-attester-v1",
            )
            .unwrap();
        assert_eq!(tool.invocations(), 0);
        assert_eq!(
            journal.entry(key).unwrap().states,
            vec![
                ExecutionStatus::ApprovedPendingDispatch,
                ExecutionStatus::NotDispatched
            ]
        );
        // No re-dispatch after recovery.
        assert!(matches!(
            gateway.dispatch_approved(key),
            Err(GatewayError::Approval(ApprovalError::NotPending))
        ));
        assert_eq!(tool.invocations(), 0);
    }

    #[test]
    fn engine_clock_expiry_before_claim_closes_as_approval_expired() {
        let (gateway, key, tool, journal, approver_key, clock) = clocked_fixture();
        approve(&gateway, key, &approver_key);
        *clock.lock().unwrap() += Duration::seconds(21);
        assert!(matches!(
            gateway.dispatch_approved(key),
            Err(GatewayError::Approval(ApprovalError::Expired))
        ));
        let record = journal.get(key).unwrap().unwrap();
        assert_eq!(record.execution, ExecutionStatus::NotDispatched);
        assert!(record.approval_expiration.is_none());
        assert_eq!(
            record.execution_attestation.unwrap().not_dispatched_reason,
            Some(NotDispatchedReason::ApprovalExpired)
        );
        assert_eq!(tool.invocations(), 0);
    }

    #[test]
    fn receipts_and_attestations_never_carry_apd_or_a_stray_reason() {
        let (gateway, key, _, _, approver_key, _) = clocked_fixture();
        approve(&gateway, key, &approver_key);
        let closed = gateway.reconcile(key).unwrap();
        let key_id = "test-execution-attester-v1";
        let public_key = execution_attester_public_key();

        let mut forged = closed.clone();
        forged.execution = ExecutionStatus::ApprovedPendingDispatch;
        forged.execution_attestation.execution = ExecutionStatus::ApprovedPendingDispatch;
        assert!(
            forged
                .verify_with_test_evidence_attester(&public_key, key_id)
                .is_err()
        );

        // The reason is signed: changing or removing it breaks verification.
        let mut changed = closed.clone();
        changed.execution_attestation.not_dispatched_reason =
            Some(NotDispatchedReason::DispatchFailed);
        assert!(
            changed
                .verify_with_test_evidence_attester(&public_key, key_id)
                .is_err()
        );
        let mut removed = closed.clone();
        removed.execution_attestation.not_dispatched_reason = None;
        assert!(
            removed
                .verify_with_test_evidence_attester(&public_key, key_id)
                .is_err()
        );
        let mut downgraded = closed;
        downgraded.execution_attestation.schema_version = 2;
        assert!(
            downgraded
                .verify_with_test_evidence_attester(&public_key, key_id)
                .is_err()
        );
    }

    #[derive(Debug, Clone, Copy)]
    enum Op {
        Approve,
        Reject,
        Expire,
        Claim,
        Reconcile,
        Crash,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            Just(Op::Approve),
            Just(Op::Reject),
            Just(Op::Expire),
            Just(Op::Claim),
            Just(Op::Reconcile),
            Just(Op::Crash),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// For arbitrary sequences of approve, reject, expire, claim,
        /// reconcile and crash (a crash drops in-flight work; recovery is a
        /// reconcile): the adapter runs at most once, `Dispatched` is always
        /// preceded by `ApprovedPendingDispatch`, an expiry before the claim
        /// never reaches `Dispatched`, and a closed APD never reopens.
        #[test]
        fn apd_sequences_dispatch_at_most_once(ops in prop::collection::vec(op(), 1..12)) {
            let (gateway, key, tool, journal, approver_key, clock) = clocked_fixture();
            let challenge = gateway.approval_challenge(key).unwrap();
            let mut expired_before_claim = false;
            for op in ops {
                let claimed = journal
                    .entry(key)
                    .unwrap()
                    .states
                    .contains(&ExecutionStatus::Dispatched);
                match op {
                    Op::Approve | Op::Reject => {
                        let outcome = if matches!(op, Op::Approve) {
                            HumanApprovalOutcome::Approve
                        } else {
                            HumanApprovalOutcome::Reject
                        };
                        let decision =
                            human_approval_decision(challenge.clone(), outcome, &approver_key);
                        let _ = gateway.resolve_human_approval(decision);
                    }
                    Op::Expire => {
                        *clock.lock().unwrap() += Duration::seconds(21);
                        if !claimed {
                            expired_before_claim = true;
                        }
                    }
                    Op::Claim => {
                        let _ = gateway.dispatch_approved(key);
                    }
                    Op::Crash => {
                        // A crash may strike after the claim but before the
                        // adapter call: claim with the journal only.
                        if let Ok(pending) = gateway.pending_dispatch(key) {
                            let _ = gateway.claim_dispatch(pending);
                        }
                        let _ = gateway.reconcile(key);
                    }
                    Op::Reconcile => {
                        let _ = gateway.reconcile(key);
                    }
                }
                let states = journal.entry(key).unwrap().states;
                prop_assert!(tool.invocations() <= 1);
                if let Some(dispatched) =
                    states.iter().position(|s| *s == ExecutionStatus::Dispatched)
                {
                    prop_assert!(dispatched > 0);
                    prop_assert_eq!(
                        states[dispatched - 1],
                        ExecutionStatus::ApprovedPendingDispatch
                    );
                    prop_assert!(!expired_before_claim);
                }
                prop_assert!(
                    states
                        .iter()
                        .filter(|s| **s == ExecutionStatus::ApprovedPendingDispatch)
                        .count()
                        <= 1
                );
                // The adapter only ever runs after a durable claim.
                if tool.invocations() == 1 {
                    prop_assert!(states.contains(&ExecutionStatus::Dispatched));
                }
            }
        }
    }
}

fn approver_public_key(approver_key: &SigningKey) -> VerifiedPublicKey {
    VerifiedPublicKey::from_bytes(&approver_key.verifying_key().to_bytes()).unwrap()
}

#[test]
fn tenant_scoped_approver_key_does_not_verify_for_another_tenant() {
    let other_tenant = Uuid::from_u128(2);
    let (gateway, request, tool, journal, approver_key, _) =
        approval_fixture_with_verifiers(|approver_key| {
            vec![
                HumanApprovalVerifier::for_tenant(
                    other_tenant,
                    "test-human-approver-v1",
                    approver_public_key(approver_key),
                )
                .unwrap(),
            ]
        });
    let key = pending_key(&gateway, request);
    let decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Approve,
        &approver_key,
    );
    assert!(matches!(
        gateway.resolve_human_approval(decision),
        Err(GatewayError::Approval(ApprovalError::InvalidSignature))
    ));
    let record = journal.get(key).unwrap().unwrap();
    assert_eq!(record.execution, ExecutionStatus::NotDispatched);
    assert!(record.human_approval.is_none());
    assert_eq!(tool.invocations(), 0);
}

#[test]
fn tenant_scoped_approver_key_verifies_only_its_own_tenant() {
    let other_tenant = Uuid::from_u128(2);
    let other_key = SigningKey::from_bytes(&[35; 32]);
    let other_public = approver_public_key(&other_key);
    let (gateway, request, tool, _, approver_key, _) =
        approval_fixture_with_verifiers(|approver_key| {
            vec![
                HumanApprovalVerifier::for_tenant(
                    other_tenant,
                    "tenant-two-approver",
                    other_public,
                )
                .unwrap(),
                HumanApprovalVerifier::for_tenant(
                    TEST_TENANT_ID,
                    "test-human-approver-v1",
                    approver_public_key(approver_key),
                )
                .unwrap(),
            ]
        });
    let key = pending_key(&gateway, request);
    let challenge = gateway.approval_challenge(key).unwrap();

    // Tenant B's approver signing under its own key id is refused for A.
    let mut foreign =
        human_approval_decision(challenge.clone(), HumanApprovalOutcome::Approve, &other_key);
    foreign.approver_key_id = "tenant-two-approver".into();
    foreign.signature = hex::encode(
        other_key
            .sign(&foreign.signing_message().unwrap())
            .to_bytes(),
    );
    assert!(matches!(
        gateway.resolve_human_approval(foreign),
        Err(GatewayError::Approval(ApprovalError::InvalidSignature))
    ));

    let decision = human_approval_decision(challenge, HumanApprovalOutcome::Approve, &approver_key);
    gateway.resolve_human_approval(decision).unwrap();
    gateway.dispatch_approved(key).unwrap();
    assert_eq!(tool.invocations(), 1);
}

#[test]
fn nil_tenant_approver_binding_is_rejected() {
    let key = SigningKey::from_bytes(&[36; 32]);
    assert!(matches!(
        HumanApprovalVerifier::for_tenant(Uuid::nil(), "approver", approver_public_key(&key)),
        Err(ApprovalError::InvalidVerifier)
    ));
}

#[test]
fn transient_clock_failure_at_claim_leaves_the_approval_retryable() {
    let (gateway, request, tool, journal, approver_key, clock) =
        approval_fixture_with_verifiers(|approver_key| {
            vec![
                HumanApprovalVerifier::new(
                    "test-human-approver-v1",
                    approver_public_key(approver_key),
                )
                .unwrap(),
            ]
        });
    let key = pending_key(&gateway, request);
    let decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Approve,
        &approver_key,
    );
    gateway.resolve_human_approval(decision).unwrap();

    // The engine clock steps back before the decision time: the trusted
    // clock is unhealthy, which says nothing about the approval itself.
    let now = *clock.lock().unwrap();
    *clock.lock().unwrap() = now - Duration::seconds(30);
    assert!(matches!(
        gateway.dispatch_approved(key),
        Err(GatewayError::Authorization(
            PraetoreError::TrustedClockUnavailable
        ))
    ));
    assert_eq!(tool.invocations(), 0);
    let record = journal.get(key).unwrap().unwrap();
    assert_eq!(record.execution, ExecutionStatus::ApprovedPendingDispatch);
    assert_eq!(
        gateway.approval_resolution(key).unwrap(),
        praetore_gateway::ApprovalResolution::Approved
    );

    *clock.lock().unwrap() = now;
    let receipt = gateway.dispatch_approved(key).unwrap();
    assert_eq!(receipt.execution, ExecutionStatus::Confirmed);
    assert_eq!(tool.invocations(), 1);
}

struct SwitchableFreshness {
    state: Arc<Mutex<Option<FreshnessError>>>,
}

impl FreshnessProvider for SwitchableFreshness {
    fn check(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &praetore_core::AuthorityId,
        _policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        match *self.state.lock().unwrap() {
            Some(error) => Err(error),
            None => Ok(FreshnessLease {
                valid_until: now + Duration::seconds(30),
            }),
        }
    }

    fn check_authority(
        &self,
        agent: &AgentKeyFingerprint,
        authority_id: &praetore_core::AuthorityId,
        _authority_digest: &str,
        policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        self.check(agent, authority_id, policy_digest, now)
    }
}

#[test]
fn unavailable_freshness_at_claim_is_retryable_but_revocation_is_terminal() {
    let state = Arc::new(Mutex::new(None));
    let provider_state = state.clone();
    let (gateway, request, tool, journal, approver_key, _) = approval_fixture_full(
        move |_| {
            Arc::new(SwitchableFreshness {
                state: provider_state,
            })
        },
        [34; 32],
        |_| {},
        |approver_key| {
            vec![
                HumanApprovalVerifier::new(
                    "test-human-approver-v1",
                    approver_public_key(approver_key),
                )
                .unwrap(),
            ]
        },
    );
    let key = pending_key(&gateway, request);
    let decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Approve,
        &approver_key,
    );
    gateway.resolve_human_approval(decision).unwrap();

    *state.lock().unwrap() = Some(FreshnessError::Unavailable);
    assert!(matches!(
        gateway.dispatch_approved(key),
        Err(GatewayError::Authorization(
            PraetoreError::FreshnessCheckFailed(FreshnessError::Unavailable)
        ))
    ));
    assert_eq!(
        journal.get(key).unwrap().unwrap().execution,
        ExecutionStatus::ApprovedPendingDispatch
    );

    *state.lock().unwrap() = Some(FreshnessError::Revoked);
    assert!(matches!(
        gateway.dispatch_approved(key),
        Err(GatewayError::Authorization(
            PraetoreError::FreshnessCheckFailed(FreshnessError::Revoked)
        ))
    ));
    let record = journal.get(key).unwrap().unwrap();
    assert_eq!(record.execution, ExecutionStatus::NotDispatched);
    assert_eq!(
        record.execution_attestation.unwrap().not_dispatched_reason,
        Some(NotDispatchedReason::DispatchFailed)
    );
    let state = gateway.approval_state(key).unwrap();
    assert_eq!(
        state.resolution,
        praetore_gateway::ApprovalResolution::NotDispatched
    );
    assert_eq!(
        state.not_dispatched_reason,
        Some(NotDispatchedReason::DispatchFailed)
    );
    assert_eq!(tool.invocations(), 0);
}

#[test]
fn approval_resolution_reports_not_dispatched_after_crash_recovery_or_expiry() {
    let (gateway, request, tool, _, approver_key) = approval_fixture();
    let key = pending_key(&gateway, request);
    let decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Approve,
        &approver_key,
    );
    gateway.resolve_human_approval(decision).unwrap();
    gateway.reconcile(key).unwrap();
    let state = gateway.approval_state(key).unwrap();
    assert_eq!(
        state.resolution,
        praetore_gateway::ApprovalResolution::NotDispatched
    );
    assert_eq!(state.execution, ExecutionStatus::NotDispatched);
    assert_eq!(
        state.not_dispatched_reason,
        Some(NotDispatchedReason::CrashRecovered)
    );
    assert_eq!(
        serde_json::to_value(state).unwrap(),
        json!({
            "resolution": "not_dispatched",
            "execution": "not_dispatched",
            "not_dispatched_reason": "crash_recovered"
        })
    );
    assert_eq!(tool.invocations(), 0);

    let (gateway, request, _, _, approver_key) = approval_fixture_with_provider(|clock| {
        Arc::new(ExpiringOnDispatchFreshness {
            clock,
            calls: AtomicUsize::new(0),
            expire_on_call: 2,
            advance_by: Duration::seconds(6),
            lease_duration: Duration::seconds(5),
        })
    });
    let key = pending_key(&gateway, request);
    let decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Approve,
        &approver_key,
    );
    gateway.resolve_human_approval(decision).unwrap();
    assert!(gateway.dispatch_approved(key).is_err());
    let state = gateway.approval_state(key).unwrap();
    assert_eq!(
        state.resolution,
        praetore_gateway::ApprovalResolution::NotDispatched
    );
    assert_eq!(
        state.not_dispatched_reason,
        Some(NotDispatchedReason::ApprovalExpired)
    );
}

#[test]
fn claim_reverifies_the_recorded_approval_before_dispatch() {
    let (gateway, request, tool, journal, approver_key) = approval_fixture();
    let key = pending_key(&gateway, request);
    let decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Approve,
        &approver_key,
    );
    gateway.resolve_human_approval(decision.clone()).unwrap();

    // A journal row whose stored approval no longer verifies (corrupted or
    // forged storage) is never dispatched, and its state is left untouched.
    let forged_key = SigningKey::from_bytes(&[99; 32]);
    let forged = human_approval_decision(
        decision.challenge.clone(),
        HumanApprovalOutcome::Approve,
        &forged_key,
    );
    journal
        .entries
        .lock()
        .unwrap()
        .get_mut(&key)
        .unwrap()
        .human_approval = Some(forged);
    assert!(matches!(
        gateway.dispatch_approved(key),
        Err(GatewayError::Approval(ApprovalError::InvalidSignature))
    ));
    assert_eq!(tool.invocations(), 0);
    assert_eq!(
        journal.get(key).unwrap().unwrap().execution,
        ExecutionStatus::ApprovedPendingDispatch
    );

    // A validly signed approval for a different challenge is refused too.
    let mut other_challenge = decision.challenge.clone();
    other_challenge.action_digest = "0".repeat(64);
    let mismatched = human_approval_decision(
        other_challenge,
        HumanApprovalOutcome::Approve,
        &approver_key,
    );
    journal
        .entries
        .lock()
        .unwrap()
        .get_mut(&key)
        .unwrap()
        .human_approval = Some(mismatched);
    assert!(matches!(
        gateway.dispatch_approved(key),
        Err(GatewayError::Approval(ApprovalError::InvalidChallenge))
    ));
    assert_eq!(tool.invocations(), 0);

    journal
        .entries
        .lock()
        .unwrap()
        .get_mut(&key)
        .unwrap()
        .human_approval = Some(decision);
    gateway.dispatch_approved(key).unwrap();
    assert_eq!(tool.invocations(), 1);
}

const AGENT_A_TOKEN: &str = "agent-a-token-0123456789abcdef0123456789";
const APPROVER_A_TOKEN: &str = "approver-a-token-0123456789abcdef01234567";
const AGENT_B_TOKEN: &str = "agent-b-token-0123456789abcdef0123456789";
const APPROVER_B_TOKEN: &str = "approver-b-token-0123456789abcdef01234567";

fn api_credentials() -> http_api::ApiCredentials {
    let tenant_b = Uuid::from_u128(2);
    let entry = |name: &str, tenant: Uuid, role: &str, token: &str| {
        json!({
            "name": name,
            "tenant_id": tenant,
            "role": role,
            "token_sha256": http_api::ApiCredentials::token_sha256_hex(token),
        })
    };
    let document = json!({
        "schema_version": 1,
        "credentials": [
            entry("tenant-a-agent", TEST_TENANT_ID, "agent", AGENT_A_TOKEN),
            entry("tenant-a-approver", TEST_TENANT_ID, "approver", APPROVER_A_TOKEN),
            entry("tenant-b-agent", tenant_b, "agent", AGENT_B_TOKEN),
            entry("tenant-b-approver", tenant_b, "approver", APPROVER_B_TOKEN),
        ]
    });
    http_api::ApiCredentials::from_json(&document.to_string()).unwrap()
}

async fn authed(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: String,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 262_144).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn http_api_requires_tenant_scoped_role_bound_credentials() {
    let (gateway, request, tool, journal, approver_key) = approval_fixture();
    let app = http_api::router(
        Arc::new(gateway),
        http_api::ApiAuth::required(api_credentials()),
    );
    let request_json = serde_json::to_string(&request).unwrap();

    let health = app
        .clone()
        .oneshot(http_body_request("GET", "/healthz", String::new()))
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::NO_CONTENT);

    // No, malformed, too-short or unknown credentials: 401.
    for token in [
        None,
        Some("short"),
        Some("unknown-token-0123456789abcdef0123456789"),
    ] {
        let (status, body) = authed(&app, "POST", "/v1/execute", token, request_json.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, json!({"code": "authentication_required"}));
    }
    // Approver credentials cannot submit agent requests; tenant B's agent
    // cannot submit (and so cannot consume) tenant A's signed request.
    for token in [APPROVER_A_TOKEN, AGENT_B_TOKEN] {
        let (status, body) = authed(
            &app,
            "POST",
            "/v1/execute",
            Some(token),
            request_json.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"code": "caller_not_authorized"}));
    }
    assert!(journal.entries.lock().unwrap().is_empty());

    let (status, pending) = authed(
        &app,
        "POST",
        "/v1/execute",
        Some(AGENT_A_TOKEN),
        request_json,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: pending["evidence"]["agent"]["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
        request_id: pending["evidence"]["request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    };
    let path = format!(
        "/v1/approvals/{}/{}/{}",
        key.tenant_id, key.agent_id, key.request_id
    );

    // Unauthenticated, agent and other-tenant callers never reach the
    // challenge, decision or dispatch endpoints.
    for (method, uri) in [
        ("GET", path.clone()),
        ("POST", path.clone()),
        ("POST", format!("{path}/dispatch")),
        ("GET", format!("{path}/status")),
    ] {
        let (status, _) = authed(&app, method, &uri, None, String::new()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        let (status, _) = authed(&app, method, &uri, Some(APPROVER_B_TOKEN), String::new()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
        let (status, _) = authed(&app, method, &uri, Some(AGENT_B_TOKEN), String::new()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
    }
    for (method, uri) in [
        ("GET", path.clone()),
        ("POST", path.clone()),
        ("POST", format!("{path}/dispatch")),
    ] {
        let (status, _) = authed(&app, method, &uri, Some(AGENT_A_TOKEN), String::new()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
    }
    // The tenant's own agent may observe the status.
    let (status, body) = authed(
        &app,
        "GET",
        &format!("{path}/status"),
        Some(AGENT_A_TOKEN),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["resolution"], "pending");

    let (status, view) = authed(&app, "GET", &path, Some(APPROVER_A_TOKEN), String::new()).await;
    assert_eq!(status, StatusCode::OK);
    let view: praetore_gateway::ApprovalChallengeView = serde_json::from_value(view).unwrap();
    assert!(view.action_matches_challenge());
    let decision =
        human_approval_decision(view.challenge, HumanApprovalOutcome::Approve, &approver_key);
    let (status, body) = authed(
        &app,
        "POST",
        &path,
        Some(APPROVER_A_TOKEN),
        serde_json::to_string(&decision).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "approved_pending_dispatch");

    // Even after approval, the requesting agent cannot trigger dispatch.
    let (status, _) = authed(
        &app,
        "POST",
        &format!("{path}/dispatch"),
        Some(AGENT_A_TOKEN),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(tool.invocations(), 0);

    let (status, receipt) = authed(
        &app,
        "POST",
        &format!("{path}/dispatch"),
        Some(APPROVER_A_TOKEN),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["execution"], "confirmed");
    assert_eq!(tool.invocations(), 1);
}

#[test]
fn api_credentials_file_is_strictly_validated() {
    let hash = http_api::ApiCredentials::token_sha256_hex(AGENT_A_TOKEN);
    let entry = |name: &str, tenant: Uuid, hash: &str| json!({"name": name, "tenant_id": tenant, "role": "agent", "token_sha256": hash});
    let parse = |credentials: Value| {
        http_api::ApiCredentials::from_json(
            &json!({"schema_version": 1, "credentials": credentials}).to_string(),
        )
    };
    assert_eq!(
        parse(json!([entry("a", TEST_TENANT_ID, &hash)]))
            .unwrap()
            .len(),
        1
    );
    // Duplicate token digests or names, nil tenants, non-canonical digests.
    assert!(
        parse(json!([
            entry("a", TEST_TENANT_ID, &hash),
            entry("b", Uuid::from_u128(2), &hash)
        ]))
        .is_err()
    );
    let other = http_api::ApiCredentials::token_sha256_hex(AGENT_B_TOKEN);
    assert!(
        parse(json!([
            entry("a", TEST_TENANT_ID, &hash),
            entry("a", TEST_TENANT_ID, &other)
        ]))
        .is_err()
    );
    assert!(parse(json!([entry("a", Uuid::nil(), &hash)])).is_err());
    assert!(parse(json!([entry("a", TEST_TENANT_ID, &hash.to_uppercase())])).is_err());
    assert!(parse(json!([entry("a", TEST_TENANT_ID, &hash[..62])])).is_err());
    assert!(parse(json!([entry("Bad Name", TEST_TENANT_ID, &hash)])).is_err());
    assert!(parse(json!([])).is_err());
    let mut unknown_role = entry("a", TEST_TENANT_ID, &hash);
    unknown_role["role"] = json!("operator");
    assert!(parse(json!([unknown_role])).is_err());
    let mut unknown_field = entry("a", TEST_TENANT_ID, &hash);
    unknown_field["extra"] = json!(true);
    assert!(parse(json!([unknown_field])).is_err());
    let duplicate_key =
        json!({"schema_version": 1, "credentials": [entry("a", TEST_TENANT_ID, &hash)]})
            .to_string()
            .replacen(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1",
                1,
            );
    assert!(http_api::ApiCredentials::from_json(&duplicate_key).is_err());
    assert!(
        http_api::ApiCredentials::from_json(
            &json!({"schema_version": 2, "credentials": [entry("a", TEST_TENANT_ID, &hash)]})
                .to_string()
        )
        .is_err()
    );
}

// Signatures are lowercase hex only: an uppercase copy of a valid approval
// signature is another encoding of the same bytes and is refused.
#[test]
fn uppercase_human_approval_signature_is_refused() {
    let (gateway, request, tool, _, approver_key) = approval_fixture();
    let key = pending_key(&gateway, request);
    let mut decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Approve,
        &approver_key,
    );
    assert!(decision.signature.bytes().any(|b| b.is_ascii_lowercase()));
    let lowercase = decision.signature.clone();
    decision.signature = lowercase.to_ascii_uppercase();
    assert!(matches!(
        gateway.resolve_human_approval(decision.clone()),
        Err(GatewayError::Approval(ApprovalError::InvalidSignature))
    ));
    decision.signature = lowercase;
    gateway.resolve_human_approval(decision).unwrap();
    assert_eq!(tool.invocations(), 0);
}

fn key_from_receipt_json(receipt: &Value) -> ExecutionKey {
    ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: receipt["evidence"]["agent"]["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
        request_id: receipt["evidence"]["request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    }
}

/// An approved action the adapter would no longer perform (for example a
/// sandbox file swapped for a symlink after approval) is closed at claim
/// time as `not_dispatched`, after the approval was re-verified, and the
/// adapter is never invoked.
#[test]
fn claim_dispatch_refuses_an_approved_action_the_adapter_no_longer_admits() {
    let (gateway, request, tool, journal, approver_key) = approval_fixture();
    let pending = gateway.execute(request).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let decision = human_approval_decision(
        gateway.approval_challenge(key).unwrap(),
        HumanApprovalOutcome::Approve,
        &approver_key,
    );
    gateway.resolve_human_approval(decision).unwrap();
    tool.refuse_preflight.store(true, Ordering::SeqCst);
    assert!(matches!(
        gateway.dispatch_approved(key),
        Err(GatewayError::DispatchRefused {
            reason: "test_refusal",
            ..
        })
    ));
    assert_eq!(tool.invocations(), 0);
    let state = gateway.approval_state(key).unwrap();
    assert_eq!(state.execution, ExecutionStatus::NotDispatched);
    assert_eq!(
        state.not_dispatched_reason,
        Some(NotDispatchedReason::DispatchFailed)
    );
    assert_eq!(
        journal.entry(key).unwrap().states,
        vec![
            ExecutionStatus::ApprovedPendingDispatch,
            ExecutionStatus::NotDispatched
        ]
    );
    tool.refuse_preflight.store(false, Ordering::SeqCst);
    assert!(gateway.dispatch_approved(key).is_err(), "never retried");
    assert_eq!(tool.invocations(), 0);
}

/// Preflight refusals at submission and at approval never invoke the
/// adapter and never consume the decision.
#[test]
fn preflight_refusal_before_approval_keeps_the_decision_unconsumed() {
    let (gateway, request, tool, journal, approver_key) = approval_fixture();
    let pending = gateway.execute(request).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let challenge = gateway.approval_challenge(key).unwrap();
    tool.refuse_preflight.store(true, Ordering::SeqCst);
    assert!(matches!(
        gateway.approval_challenge(key),
        Err(GatewayError::DispatchRefused { .. })
    ));
    let decision = human_approval_decision(challenge, HumanApprovalOutcome::Approve, &approver_key);
    assert!(matches!(
        gateway.resolve_human_approval(decision.clone()),
        Err(GatewayError::DispatchRefused { .. })
    ));
    assert!(journal.get(key).unwrap().unwrap().human_approval.is_none());
    assert_eq!(tool.invocations(), 0);
    tool.refuse_preflight.store(false, Ordering::SeqCst);
    gateway.resolve_human_approval(decision).unwrap();
}

/// With gateway-executed effects, `praetore-exec-mode` is checked only after
/// caller authentication (it never substitutes for a credential), it can only
/// refuse, and an agent never gets a plain `approved` answer to act on.
#[tokio::test]
async fn exec_mode_header_runs_after_auth_and_never_changes_who_executes() {
    let (gateway, request, tool, journal, approver_key) = approval_fixture();
    let gateway = Arc::new(gateway);
    let app = http_api::router_with_options(
        gateway.clone(),
        http_api::ApiAuth::required(api_credentials()),
        http_api::HttpOptions {
            gateway_executes_effects: true,
        },
    );
    let send =
        |method: &str, uri: String, token: Option<&str>, mode: Option<&str>, body: String| {
            let mut builder = Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json");
            if let Some(token) = token {
                builder = builder.header("authorization", format!("Bearer {token}"));
            }
            if let Some(mode) = mode {
                builder = builder.header(http_api::EXEC_MODE_HEADER, mode);
            }
            let app = app.clone();
            let request = builder.body(Body::from(body)).unwrap();
            async move {
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let executed_by = response
                    .headers()
                    .get("praetore-executed-by")
                    .map(|value| value.to_str().unwrap().to_owned());
                let body = to_bytes(response.into_body(), 262_144).await.unwrap();
                (
                    status,
                    serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
                    executed_by,
                )
            }
        };
    let request_json = serde_json::to_string(&request).unwrap();

    // The header is no credential: 401 without a bearer token.
    let (status, ..) = send(
        "POST",
        "/v1/execute".into(),
        None,
        Some("gateway"),
        request_json.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Authenticated agent without (or with a wrong) declaration: 409 before
    // anything is evaluated or journaled.
    for mode in [None, Some("cooperative")] {
        let (status, body, _) = send(
            "POST",
            "/v1/execute".into(),
            Some(AGENT_A_TOKEN),
            mode,
            request_json.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], "exec_mode_gateway_required");
    }
    assert!(journal.entries.lock().unwrap().is_empty());

    let (status, pending, _) = send(
        "POST",
        "/v1/execute".into(),
        Some(AGENT_A_TOKEN),
        Some("gateway"),
        request_json,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let key = key_from_receipt_json(&pending);
    let path = format!(
        "/v1/approvals/{}/{}/{}",
        key.tenant_id, key.agent_id, key.request_id
    );
    // An agent declaring `gateway` still cannot read challenges, decide or
    // dispatch: the role check comes first.
    for (method, uri) in [
        ("GET", path.clone()),
        ("POST", path.clone()),
        ("POST", format!("{path}/dispatch")),
    ] {
        let (status, ..) = send(
            method,
            uri.clone(),
            Some(AGENT_A_TOKEN),
            Some("gateway"),
            String::new(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
    }
    let (status, body, _) = send(
        "GET",
        format!("{path}/status"),
        Some(AGENT_A_TOKEN),
        Some("gateway"),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["resolution"], "pending");

    // The approver must also declare gateway execution.
    let (status, ..) = send(
        "GET",
        path.clone(),
        Some(APPROVER_A_TOKEN),
        None,
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, view, _) = send(
        "GET",
        path.clone(),
        Some(APPROVER_A_TOKEN),
        Some("gateway"),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let challenge: praetore_gateway::ApprovalChallenge =
        serde_json::from_value(view["challenge"].clone()).unwrap();
    let decision = human_approval_decision(challenge, HumanApprovalOutcome::Approve, &approver_key);
    let decision_json = serde_json::to_string(&decision).unwrap();
    let (status, ..) = send(
        "POST",
        path.clone(),
        Some(APPROVER_A_TOKEN),
        None,
        decision_json.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(journal.get(key).unwrap().unwrap().human_approval.is_none());
    let (status, body, _) = send(
        "POST",
        path.clone(),
        Some(APPROVER_A_TOKEN),
        Some("gateway"),
        decision_json,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "approved_pending_dispatch");

    // Approved but not yet dispatched: the agent is told not to execute.
    let (status, body, executed_by) = send(
        "GET",
        format!("{path}/status"),
        Some(AGENT_A_TOKEN),
        Some("gateway"),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "cooperative_exec_rejected");
    assert_eq!(body["resolution"], "approved");
    assert_eq!(body["execution"], "approved_pending_dispatch");
    assert_eq!(executed_by, None);
    assert_eq!(tool.invocations(), 0);

    let (status, ..) = send(
        "POST",
        format!("{path}/dispatch"),
        Some(APPROVER_A_TOKEN),
        None,
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(tool.invocations(), 0);
    let (status, receipt, executed_by) = send(
        "POST",
        format!("{path}/dispatch"),
        Some(APPROVER_A_TOKEN),
        Some("gateway"),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["execution"], "confirmed");
    assert_eq!(executed_by.as_deref(), Some("gateway"));
    assert_eq!(tool.invocations(), 1);

    let (status, body, executed_by) = send(
        "GET",
        format!("{path}/status"),
        Some(AGENT_A_TOKEN),
        Some("gateway"),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "cooperative_exec_rejected");
    assert_eq!(body["execution"], "confirmed");
    assert_eq!(executed_by.as_deref(), Some("gateway"));
    assert_eq!(tool.invocations(), 1);
}
