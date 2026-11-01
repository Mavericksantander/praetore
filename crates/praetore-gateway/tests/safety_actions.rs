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
    setup_with(policy_id, "demo:set_value")
}

/// Like [`setup`], with a request signed for `action_type`: a mission
/// request when the policy declares it, an unclassified one otherwise.
fn setup_with(policy_id: &str, action_type: &str) -> (Gateway, Probes, Value) {
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
    let action = Action::new(action_type, Some("demo-state".into()), json!({"value": 1}))
        .unwrap()
        .with_capability("demo:write");
    let now = OffsetDateTime::parse(NOW, &Rfc3339).unwrap();
    let (issued, expires) = (now - Duration::seconds(1), now + Duration::minutes(1));
    let body = match policy.classify(action.clone()) {
        Ok(classified) => {
            let mut request =
                AuthorizationRequest::new(agent, authority, classified.into_mission().unwrap())
                    .unwrap();
            request
                .sign_intent_v2(
                    &agent_key,
                    "g7-gateway",
                    issued,
                    expires,
                    policy.digest().unwrap(),
                )
                .unwrap();
            serde_json::to_value(&request).unwrap()
        }
        Err(_) => {
            let mut request = AuthorizationRequest::new_unclassified(
                agent,
                authority,
                policy.unclassified(action).unwrap(),
            )
            .unwrap();
            request
                .sign_intent_v2(
                    &agent_key,
                    "g7-gateway",
                    issued,
                    expires,
                    policy.digest().unwrap(),
                )
                .unwrap();
            serde_json::to_value(&request).unwrap()
        }
    };

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

/// G7: an undeclared action type without the reserved prefix is
/// verified by the engine and refused with a signed DENY that must be
/// committed like any decision; it is never evaluated against policy rules.
/// With the journal down, the commit fails and the gateway fails closed.
#[tokio::test]
async fn unclassified_action_is_not_evaluated_and_fails_closed_with_the_journal_down() {
    for action_type in ["demo:delete", "SAFETY:hold"] {
        let policy_id = format!("g7-gateway-unclassified-{action_type}");
        let (gateway, probes, body) = setup_with(&policy_id, action_type);

        let (status, response, _) = post(gateway, &body).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{response}");
        assert_eq!(probe::engine_calls(&policy_id), 1);
        assert_eq!(
            probe::policy_evaluations(&policy_id),
            0,
            "no rule evaluated"
        );
        assert!(
            probes.journal.0.get() >= 1,
            "the DENY commit reached the journal"
        );
        assert_eq!(probes.dispatcher.0.get(), 0);
    }
}

/// G7: an undeclared request whose intent signature does not cover it (a
/// mission request with its action type edited) is rejected by the
/// engine's verification: nothing reaches the journal, nothing is signed.
#[tokio::test]
async fn forged_unclassified_request_reaches_no_journal() {
    let policy_id = "g7-gateway-forged";
    let (gateway, probes, mut body) = setup(policy_id);
    body["action"]["action_type"] = json!("demo:delete");

    let (status, response, _) = post(gateway, &body).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
    assert_eq!(probe::policy_evaluations(policy_id), 0);
    assert_eq!(probes.journal.0.get(), 0, "no commit");
    assert_eq!(probes.signer.0.get(), 0);
    assert_eq!(probes.dispatcher.0.get(), 0);
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

/// Captures WARN events (message and fields) for the whole test process.
/// Installed once as the global default, so the callsite interest does not
/// depend on which test thread registered it first; each test filters the
/// lines by its own (random) agent id.
#[derive(Default, Clone)]
struct WarnCapture(Arc<std::sync::Mutex<Vec<String>>>);

fn warn_capture() -> &'static WarnCapture {
    static CAPTURE: std::sync::OnceLock<WarnCapture> = std::sync::OnceLock::new();
    CAPTURE.get_or_init(|| {
        let capture = WarnCapture::default();
        tracing::subscriber::set_global_default(capture.clone()).expect("one global subscriber");
        capture
    })
}

struct FieldText<'a>(&'a mut String);

impl tracing::field::Visit for FieldText<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={value:?}", field.name()));
    }
}

impl tracing::Subscriber for WarnCapture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::WARN
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() == tracing::Level::WARN {
            let mut line = String::new();
            event.record(&mut FieldText(&mut line));
            self.0.lock().unwrap().push(line);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

async fn post_raw(gateway: Gateway, body: &Value) -> (StatusCode, Vec<(String, Vec<u8>)>, Vec<u8>) {
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
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect();
    let bytes = to_bytes(response.into_body(), 65_536)
        .await
        .unwrap()
        .to_vec();
    (status, headers, bytes)
}

/// G7 (gateway): every action type with the reserved `safety:` prefix gets
/// the same answer, declared Safety or not: byte-identical status, headers
/// and body, no engine call and no journal row. Each is logged once (WARN,
/// unsigned) with the same fields and `declared` true or false.
#[tokio::test]
async fn reserved_safety_prefix_answers_the_same_declared_or_not() {
    let capture = warn_capture();
    let declared_id = "g7-gateway-prefix-declared";
    let undeclared_id = "g7-gateway-prefix-undeclared";
    let (declared_gateway, declared_probes, mut declared) = setup(declared_id);
    declared["action"]["action_type"] = json!("safety:halt");
    let (undeclared_gateway, undeclared_probes, mut undeclared) = setup(undeclared_id);
    undeclared["action"]["action_type"] = json!("safety:hold\u{200b}");

    let declared_response = post_raw(declared_gateway, &declared).await;
    let undeclared_response = post_raw(undeclared_gateway, &undeclared).await;

    assert_eq!(declared_response.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(declared_response, undeclared_response, "byte-identical");
    let body: Value = serde_json::from_slice(&declared_response.2).unwrap();
    assert_eq!(body["code"], "safety_action_not_governed");
    declared_probes.assert_untouched();
    undeclared_probes.assert_untouched();

    // Exactly one event per request at the prefix gate, declared or not,
    // with the same fields; only `declared` differs.
    let lines_for = |body: &Value| {
        let agent_id = body["agent"]["id"].as_str().unwrap().to_owned();
        capture
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.contains(&agent_id))
            .cloned()
            .collect::<Vec<_>>()
    };
    let declared_lines = lines_for(&declared);
    let undeclared_lines = lines_for(&undeclared);
    assert_eq!(declared_lines.len(), 1, "{declared_lines:?}");
    assert_eq!(undeclared_lines.len(), 1, "{undeclared_lines:?}");
    for line in declared_lines.iter().chain(&undeclared_lines) {
        assert!(
            line.contains("safety action refused as not governed"),
            "{line}"
        );
        assert!(line.contains("claimed_agent_id="), "{line}");
        assert!(line.contains("action_type="), "{line}");
    }
    assert!(
        declared_lines[0].contains("declared=true"),
        "{declared_lines:?}"
    );
    assert!(
        declared_lines[0].contains("action_type=safety:halt "),
        "{declared_lines:?}"
    );
    assert!(
        undeclared_lines[0].contains("declared=false"),
        "{undeclared_lines:?}"
    );
    assert!(
        undeclared_lines[0].contains("action_type=safety:hold\\u{200b}"),
        "escaped: {undeclared_lines:?}"
    );
}
