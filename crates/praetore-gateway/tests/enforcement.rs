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
    ActionDispatcher, AuthorizationStatus, DispatchError, DispatchReport, ExecutionJournal,
    ExecutionKey, ExecutionRecord, ExecutionStatus, Gateway, GatewayError, JournalError,
    ReconciliationReport,
};
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
use uuid::Uuid;

const NOW: &str = "2026-06-01T12:00:00Z";
fn long_validity() -> Validity {
    Validity {
        not_before: Some("2026-01-01T00:00:00Z".into()),
        not_after: Some("2026-12-31T00:00:00Z".into()),
    }
}

#[derive(Default)]
struct MemoryReplayGuard {
    claims: Mutex<HashSet<(Uuid, Uuid)>>,
    unavailable: AtomicBool,
}

impl ReplayGuard for MemoryReplayGuard {
    fn claim_once(&self, agent_id: Uuid, request_id: Uuid) -> Result<(), ReplayGuardError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(ReplayGuardError::Unavailable);
        }
        let mut claims = self
            .claims
            .lock()
            .map_err(|_| ReplayGuardError::Unavailable)?;
        if claims.insert((agent_id, request_id)) {
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

struct JournalEntry {
    evidence: Option<Evidence>,
    authorization: Option<AuthorizationStatus>,
    states: Vec<ExecutionStatus>,
    execution: ExecutionStatus,
    action_digest: String,
    output: Option<Value>,
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
        }
    }
}

#[derive(Default)]
struct MemoryJournal {
    entries: Mutex<HashMap<ExecutionKey, JournalEntry>>,
    fail_dispatched: AtomicBool,
    fail_terminal: AtomicBool,
    unavailable: AtomicBool,
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
            let action =
                serde_json::to_string(&evidence.action).map_err(|_| JournalError::InvalidRecord)?;
            return if existing.action_digest == action {
                Err(JournalError::AlreadyRecorded)
            } else {
                Err(JournalError::ConflictingRequest)
            };
        }
        let action_digest =
            serde_json::to_string(&evidence.action).map_err(|_| JournalError::InvalidRecord)?;
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
        })
    }
}

struct JournalEntrySnapshot {
    evidence: Evidence,
    authorization: AuthorizationStatus,
    states: Vec<ExecutionStatus>,
    execution: ExecutionStatus,
    output: Option<Value>,
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

    fn record_terminal(
        &self,
        key: ExecutionKey,
        execution: ExecutionStatus,
        output: Option<&Value>,
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
        if !matches!(
            entry.execution,
            ExecutionStatus::Dispatched | ExecutionStatus::OutcomeUnknown
        ) {
            return Err(JournalError::InvalidTransition);
        }
        entry.states.push(execution);
        entry.execution = execution;
        entry.output = output.cloned();
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
        Ok(Some(ExecutionRecord {
            key,
            evidence: entry.evidence.clone().ok_or(JournalError::InvalidRecord)?,
            authorization: entry.authorization.ok_or(JournalError::InvalidRecord)?,
            execution: entry.execution,
            action_digest: entry.action_digest.clone(),
            output: entry.output.clone(),
        }))
    }

    fn mark_not_dispatched(&self, key: ExecutionKey) -> Result<(), JournalError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(JournalError::Unavailable);
        }
        let mut entries = self.entries.lock().map_err(|_| JournalError::Unavailable)?;
        let entry = entries
            .get_mut(&key)
            .ok_or(JournalError::InvalidTransition)?;
        if entry.execution != ExecutionStatus::Authorized {
            return Err(JournalError::InvalidTransition);
        }
        entry.execution = ExecutionStatus::NotDispatched;
        entry.states.push(ExecutionStatus::NotDispatched);
        Ok(())
    }

    fn mark_outcome_unknown(&self, key: ExecutionKey) -> Result<(), JournalError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(JournalError::Unavailable);
        }
        let mut entries = self.entries.lock().map_err(|_| JournalError::Unavailable)?;
        let entry = entries
            .get_mut(&key)
            .ok_or(JournalError::InvalidTransition)?;
        match entry.execution {
            ExecutionStatus::Dispatched => {
                entry.execution = ExecutionStatus::OutcomeUnknown;
                entry.states.push(ExecutionStatus::OutcomeUnknown);
                Ok(())
            }
            ExecutionStatus::OutcomeUnknown => Ok(()),
            _ => Err(JournalError::InvalidTransition),
        }
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
}

struct Fixture {
    gateway: Gateway,
    request: AuthorizationRequest,
    tool: Arc<LocalSetTool>,
    journal: Arc<MemoryJournal>,
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
    .with_validity(long_validity());
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
    let gateway = Gateway::new(engine, journal.clone(), tool.clone()).unwrap();
    Fixture {
        gateway,
        request,
        tool,
        journal,
        policy,
        issuer_public_key,
        attester,
    }
}

#[test]
fn allowed_action_is_confirmed_once_and_receipt_separates_decision_from_effect() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    let receipt = fixture.gateway.execute(fixture.request.clone()).unwrap();
    let key = ExecutionKey {
        agent_id: *receipt.evidence.agent.id.as_uuid(),
        request_id: receipt.evidence.request_id,
    };
    let entry = fixture.journal.entry(key).unwrap();

    assert_eq!(receipt.authorization, AuthorizationStatus::Allowed);
    assert_eq!(receipt.execution, ExecutionStatus::Confirmed);
    assert_eq!(receipt.evidence.decision.outcome, DecisionOutcome::Allow);
    assert_eq!(
        entry.states,
        [ExecutionStatus::Dispatched, ExecutionStatus::Confirmed]
    );
    assert_eq!(entry.execution, ExecutionStatus::Confirmed);
    assert_eq!(entry.authorization, AuthorizationStatus::Allowed);
    assert_eq!(entry.evidence.context_hash, receipt.evidence.context_hash);
    assert_eq!(entry.output, receipt.output);
    assert_eq!(
        receipt.evidence.action.parameters["value"],
        receipt.output.as_ref().unwrap()["value"]
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
            Arc::new(LocalSetTool::default())
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
        agent_id: *fixture.request.agent.id.as_uuid(),
        request_id: fixture.request.request_id,
    };
    let second_engine = production_engine(
        fixture.policy.clone(),
        fixture.issuer_public_key.clone(),
        fixture.attester.clone(),
        Arc::new(MemoryReplayGuard::default()),
    );
    let second_gateway =
        Gateway::new(second_engine, fixture.journal.clone(), fixture.tool.clone()).unwrap();

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
