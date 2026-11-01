//! G7: the gateway HTTP API never sends a safety action to the engine.
//!
//! An AI-enabled system whose executor runs safety actions (`safety:halt`,
//! `safety:stop_all`, ...) without waiting for PRÆTORE must get an immediate,
//! typed answer even when PRÆTORE's journal is down. These tests run the
//! real router with a journal that fails every call and counts it, and with
//! counting replay, freshness, dispatch and signing probes. The engine and
//! policy evaluation counters come from praetore-core's `test-probe` feature
//! (enabled only for tests).

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use praetore_core::{
    Action, ActionClass, AgentId, AgentKeyPair, AuthorizationRequest, EvidenceAttesterKey,
    HighAssuranceConfig, Policy, PolicyEffect, PolicyRule, TrustedAuthorityIssuer,
    VerifiedPublicKey,
    authority::{Authority, Validity},
    engine::{AuthorizationEngine, FixedClock},
    freshness::{FreshnessError, FreshnessLease, FreshnessProvider},
    identity::AgentKeyFingerprint,
    probe,
    replay::{AtomicAuthorizationCommit, AuthorizationCommitError, CompletedAuthorization},
};
use praetore_gateway::{
    ActionDispatcher, ApprovalExpiredReceipt, DispatchError, DispatchReport, ExecutionAttestation,
    ExecutionAttestationError, ExecutionAttestationSigner, ExecutionJournal, ExecutionKey,
    ExecutionRecord, ExecutionStatus, Gateway, HumanApprovalDecision, JournalError, http_api,
};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration as StdDuration, Instant},
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use tower::ServiceExt;
use uuid::Uuid;

const NOW: &str = "2026-06-01T12:00:00Z";
const TENANT: Uuid = Uuid::from_u128(7);
/// Upper bound for the answer to a safety action.
const BOUND: StdDuration = StdDuration::from_millis(100);

#[derive(Default)]
struct Counter(AtomicUsize);

impl Counter {
    fn hit(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn get(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// A journal that is down: every call fails, and is counted.
#[derive(Default)]
struct DownJournal(Counter);

impl AtomicAuthorizationCommit for DownJournal {
    fn commit_authorization(
        &self,
        _: &CompletedAuthorization,
        _: &VerifiedPublicKey,
    ) -> Result<(), AuthorizationCommitError> {
        self.0.hit();
        Err(AuthorizationCommitError::Unavailable)
    }

    fn verify_committed_authorization(
        &self,
        _: &CompletedAuthorization,
        _: &VerifiedPublicKey,
    ) -> Result<(), AuthorizationCommitError> {
        self.0.hit();
        Err(AuthorizationCommitError::Unavailable)
    }
}

impl ExecutionJournal for DownJournal {
    fn mark_dispatched(&self, _: ExecutionKey) -> Result<(), JournalError> {
        self.0.hit();
        Err(JournalError::Unavailable)
    }

    fn record_terminal_attested(
        &self,
        _: ExecutionKey,
        _: ExecutionStatus,
        _: Option<&Value>,
        _: &ExecutionAttestation,
    ) -> Result<(), JournalError> {
        self.0.hit();
        Err(JournalError::Unavailable)
    }

    fn record_attestation(
        &self,
        _: ExecutionKey,
        _: ExecutionStatus,
        _: Option<&Value>,
        _: &ExecutionAttestation,
    ) -> Result<(), JournalError> {
        self.0.hit();
        Err(JournalError::Unavailable)
    }

    fn get(&self, _: ExecutionKey) -> Result<Option<ExecutionRecord>, JournalError> {
        self.0.hit();
        Err(JournalError::Unavailable)
    }

    fn mark_not_dispatched_attested(
        &self,
        _: ExecutionKey,
        _: &ExecutionAttestation,
    ) -> Result<(), JournalError> {
        self.0.hit();
        Err(JournalError::Unavailable)
    }

    fn record_human_approval(
        &self,
        _: ExecutionKey,
        _: &HumanApprovalDecision,
        _: OffsetDateTime,
    ) -> Result<(), JournalError> {
        self.0.hit();
        Err(JournalError::Unavailable)
    }

    fn claim_dispatch(&self, _: ExecutionKey, _: OffsetDateTime) -> Result<(), JournalError> {
        self.0.hit();
        Err(JournalError::Unavailable)
    }

    fn record_approval_expiration(
        &self,
        _: ExecutionKey,
        _: &ApprovalExpiredReceipt,
    ) -> Result<(), JournalError> {
        self.0.hit();
        Err(JournalError::Unavailable)
    }
}

#[derive(Default)]
struct CountingReplayGuard(Counter);

impl praetore_core::ReplayGuard for CountingReplayGuard {
    fn claim_once(&self, _: Uuid, _: Uuid, _: Uuid) -> Result<(), praetore_core::ReplayGuardError> {
        self.0.hit();
        Err(praetore_core::ReplayGuardError::Unavailable)
    }
}

#[derive(Default)]
struct CountingFreshness(Counter);

impl FreshnessProvider for CountingFreshness {
    fn check(
        &self,
        _: &AgentKeyFingerprint,
        _: &praetore_core::AuthorityId,
        _: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        self.0.hit();
        Ok(FreshnessLease {
            valid_until: now + Duration::seconds(30),
        })
    }

    fn check_authority(
        &self,
        agent: &AgentKeyFingerprint,
        authority_id: &praetore_core::AuthorityId,
        _: &str,
        policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        self.check(agent, authority_id, policy_digest, now)
    }
}

#[derive(Default)]
struct CountingDispatcher(Counter);

impl ActionDispatcher for CountingDispatcher {
    fn dispatch(
        &self,
        _: ExecutionKey,
        _: &Authority,
        _: &Action,
        _: &str,
    ) -> Result<DispatchReport, DispatchError> {
        self.0.hit();
        Err(DispatchError)
    }
}

#[derive(Default)]
struct CountingSigner(Counter);

impl ExecutionAttestationSigner for CountingSigner {
    fn key_id(&self) -> &str {
        "g7-test-signer"
    }

    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, ExecutionAttestationError> {
        self.0.hit();
        Err(ExecutionAttestationError::SignerFailed)
    }
}

struct Probes {
    policy_id: String,
    journal: Arc<DownJournal>,
    replay: Arc<CountingReplayGuard>,
    freshness: Arc<CountingFreshness>,
    dispatcher: Arc<CountingDispatcher>,
    signer: Arc<CountingSigner>,
}

impl Probes {
    fn assert_untouched(&self) {
        assert_eq!(probe::engine_calls(&self.policy_id), 0, "engine calls");
        assert_eq!(
            probe::policy_evaluations(&self.policy_id),
            0,
            "policy evaluations"
        );
        assert_eq!(self.journal.0.get(), 0, "journal calls");
        assert_eq!(self.replay.0.get(), 0, "replay claims");
        assert_eq!(self.freshness.0.get(), 0, "freshness checks");
        assert_eq!(self.dispatcher.0.get(), 0, "dispatches");
        assert_eq!(self.signer.0.get(), 0, "execution signatures");
    }
}

fn validity() -> Validity {
    Validity {
        not_before: Some("2026-01-01T00:00:00Z".into()),
        not_after: Some("2026-12-31T00:00:00Z".into()),
    }
}

/// A HighAssurance gateway whose journal is down, plus a signed mission
/// request serialized as JSON. Each test passes its own policy id so the
/// process-wide probe counters are not shared between tests.
fn setup(policy_id: &str) -> (Gateway, Probes, Value) {
    let agent_key = AgentKeyPair::from_secret_bytes(&[31; 32]);
    let issuer_key = AgentKeyPair::from_secret_bytes(&[32; 32]);
    let agent = agent_key.identity(AgentId::new());
    let mut authority = Authority::new(agent.id.clone(), "g7-issuer", vec!["demo:write".into()])
        .with_validity(validity())
        .with_constraint("tenant_id", TENANT.to_string());
    authority.sign_for_agent(&issuer_key, &agent).unwrap();

    let policy = Policy::new_v2(
        policy_id,
        1,
        vec![
            PolicyRule::new("allow-set", "demo:set_value", PolicyEffect::Allow)
                .with_capability("demo:write"),
        ],
    )
    .with_mission_actions(["demo:set_value"])
    .with_action_class("safety:halt", ActionClass::Safety)
    .with_action_class("safety:stop_all", ActionClass::Safety);
    let action = Action::new(
        "demo:set_value",
        Some("demo-state".into()),
        json!({"value": 1}),
    )
    .unwrap()
    .with_capability("demo:write");
    let mut request = AuthorizationRequest::new(
        agent,
        authority,
        policy.classify(action).unwrap().into_mission().unwrap(),
    )
    .unwrap();
    let now = OffsetDateTime::parse(NOW, &Rfc3339).unwrap();
    request
        .sign_intent_v2(
            &agent_key,
            "g7-gateway",
            now - Duration::seconds(1),
            now + Duration::minutes(1),
            policy.digest().unwrap(),
        )
        .unwrap();

    let probes = Probes {
        policy_id: policy_id.into(),
        journal: Arc::default(),
        replay: Arc::default(),
        freshness: Arc::default(),
        dispatcher: Arc::default(),
        signer: Arc::default(),
    };
    let pin = TrustedAuthorityIssuer::new("g7-issuer", issuer_key.public_key())
        .unwrap()
        .with_validity(validity())
        .unwrap();
    let config = HighAssuranceConfig::new(
        policy.digest().unwrap(),
        vec![pin],
        EvidenceAttesterKey::from_secret_bytes(&[33; 32]),
    )
    .unwrap()
    .with_audience("g7-gateway")
    .with_replay_guard(probes.replay.clone())
    .with_freshness_provider(probes.freshness.clone());
    let engine = AuthorizationEngine::production_with_clock(
        policy,
        config,
        FixedClock::try_new(NOW).unwrap(),
    )
    .unwrap();
    let gateway = Gateway::new(
        engine,
        probes.journal.clone(),
        probes.dispatcher.clone(),
        probes.signer.clone(),
    )
    .unwrap();
    let body = serde_json::to_value(&request).unwrap();
    (gateway, probes, body)
}

async fn post(gateway: Gateway, body: &Value) -> (StatusCode, Value, StdDuration) {
    let app = http_api::router(
        Arc::new(gateway),
        http_api::ApiAuth::UnauthenticatedLoopbackDemo,
    );
    let request = Request::builder()
        .method("POST")
        .uri("/v1/execute")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let started = Instant::now();
    let response = app.oneshot(request).await.unwrap();
    let elapsed = started.elapsed();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65_536).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap(), elapsed)
}

#[tokio::test]
async fn safety_action_is_refused_before_the_engine_with_the_journal_down() {
    for action_type in ["safety:halt", "safety:stop_all"] {
        let policy_id = format!("g7-gateway-safety-{action_type}");
        let (gateway, probes, mut body) = setup(&policy_id);
        body["action"]["action_type"] = json!(action_type);

        let (status, response, elapsed) = post(gateway, &body).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{response}");
        assert_eq!(response["code"], "safety_action_not_governed");
        assert!(response["receipt"].is_null());
        probes.assert_untouched();
        assert!(elapsed < BOUND, "answered in {elapsed:?}");
    }
}

#[tokio::test]
async fn unclassified_action_is_refused_before_the_engine() {
    // Not declared, including an undeclared `safety:` action.
    for action_type in ["demo:delete", "safety:hold"] {
        let policy_id = format!("g7-gateway-unclassified-{action_type}");
        let (gateway, probes, mut body) = setup(&policy_id);
        body["action"]["action_type"] = json!(action_type);

        let (status, response, elapsed) = post(gateway, &body).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{response}");
        assert_eq!(response["code"], "unclassified_action");
        probes.assert_untouched();
        assert!(elapsed < BOUND, "answered in {elapsed:?}");
    }
}

/// Control: the same setup sends a mission action to the engine, and with
/// the journal down the gateway fails closed. This shows the probes count
/// real calls and the journal really is down.
#[tokio::test]
async fn mission_action_reaches_the_engine_and_fails_closed_with_the_journal_down() {
    let policy_id = "g7-gateway-mission-control";
    let (gateway, probes, body) = setup(policy_id);

    let (status, response, _) = post(gateway, &body).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{response}");
    assert_eq!(probe::engine_calls(policy_id), 1);
    assert!(probe::policy_evaluations(policy_id) >= 1);
    assert!(
        probes.journal.0.get() >= 1,
        "the commit reached the journal"
    );
    assert_eq!(probes.dispatcher.0.get(), 0, "nothing was dispatched");
}
