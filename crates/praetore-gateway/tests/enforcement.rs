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
    ActionDispatcher, AuthorizationStatus, DispatchError, DispatchReport,
    ExecutionAttestationError, ExecutionAttestationSigner, ExecutionJournal, ExecutionKey,
    ExecutionRecord, ExecutionStatus, Gateway, GatewayError, JournalError, ReconciliationReport,
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

const NOW: &str = "2026-06-01T12:00:00Z";

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
    execution_attestations: Vec<praetore_gateway::ExecutionAttestation>,
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
                execution_attestations: Vec::new(),
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
        Ok(Some(ExecutionRecord {
            key,
            evidence: entry.evidence.clone().ok_or(JournalError::InvalidRecord)?,
            authorization: entry.authorization.ok_or(JournalError::InvalidRecord)?,
            execution: entry.execution,
            action_digest: entry.action_digest.clone(),
            output: entry.output.clone(),
            execution_attestation: entry.execution_attestations.last().cloned(),
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
        if entry.execution != ExecutionStatus::Authorized {
            return Err(JournalError::InvalidTransition);
        }
        let evidence = entry.evidence.as_ref().ok_or(JournalError::InvalidRecord)?;
        let authorization = entry.authorization.ok_or(JournalError::InvalidRecord)?;
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
    Request::builder()
        .method("POST")
        .uri("/v1/execute")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn http_gateway_returns_receipt_and_dispatches_allowed_action_once() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    let request_body = serde_json::to_string(&fixture.request).unwrap();
    let app = http_api::router(Arc::new(fixture.gateway));

    let response = app.oneshot(http_request(request_body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let receipt: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(receipt["authorization"], "allowed");
    assert_eq!(receipt["execution"], "confirmed");
    assert_eq!(fixture.tool.invocations(), 1);

    let receipt: praetore_gateway::GatewayReceipt = serde_json::from_value(receipt).unwrap();
    receipt
        .verify_execution_attestation(
            &execution_attester_public_key(),
            "test-execution-attester-v1",
        )
        .unwrap();
}

#[tokio::test]
async fn http_gateway_returns_denials_without_dispatch() {
    let fixture = fixture(None, false);
    let request_body = serde_json::to_string(&fixture.request).unwrap();
    let app = http_api::router(Arc::new(fixture.gateway));

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
    let app = http_api::router(Arc::new(fixture.gateway));

    let response = app.oneshot(http_request(request_body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let receipt: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(receipt["authorization"], "requires_approval");
    assert_eq!(receipt["execution"], "not_dispatched");
    assert_eq!(fixture.tool.invocations(), 0);
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
    .with_validity(long_validity());
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
    let app = http_api::router(Arc::new(gateway));
    let response = app
        .oneshot(http_request(serde_json::to_string(&request).unwrap()))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let receipt: praetore_gateway::GatewayReceipt = serde_json::from_slice(&body).unwrap();
    receipt
        .verify_execution_attestation(
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
    let app = http_api::router(Arc::new(fixture.gateway));

    let response = app.oneshot(http_request(request_body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(fixture.tool.invocations(), 0);
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
    receipt
        .verify_execution_attestation(
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
        tampered.verify_execution_attestation(
            &execution_attester_public_key(),
            "test-execution-attester-v1",
        ),
        Err(ExecutionAttestationError::InvalidPayload)
    );
    assert_eq!(
        receipt.verify_execution_attestation(&execution_attester_public_key(), "wrong-key-id",),
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
            .verify_execution_attestation(
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
        .verify_execution_attestation(
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
fn signer_failure_after_execution_is_recoverable_without_redispatch() {
    let fixture = fixture(Some(PolicyEffect::Allow), false);
    fixture
        .execution_attester
        .fail_signing
        .store(true, Ordering::SeqCst);
    let key = ExecutionKey {
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
        .verify_execution_attestation(
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
