use postgres::{Client, NoTls};
use praetore_core::{
    Action, AgentId, AgentKeyPair, AuthorizationRequest, DecisionOutcome, EvidenceAttesterKey,
    HighAssuranceConfig, Policy, PolicyEffect, PolicyRule, TrustedAuthorityIssuer,
    VerifiedPublicKey,
    authority::{Authority, Validity},
    engine::{AuthorizationEngine, Clock, FixedClock},
    freshness::{FreshnessError, FreshnessLease, FreshnessProvider},
    identity::AgentKeyFingerprint,
    replay::{
        AtomicAuthorizationCommit, AuthorizationCommitError, CompletedAuthorization, ReplayGuard,
        ReplayGuardError,
    },
};
use praetore_gateway::{
    ActionDispatcher, DispatchError, DispatchReport, ExecutionJournal, ExecutionKey,
    ExecutionRecord, ExecutionStatus, Gateway, GatewayError, JournalError, ReconciliationReport,
    action_digest,
};
use praetore_replay_postgres::{PostgresExecutionJournal, PostgresReplayGuard};
use serde_json::{Value, json};
use std::{
    env,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

static TEST_DATABASE_SETUP: OnceLock<()> = OnceLock::new();
const TEST_NOW: &str = "2026-06-01T12:00:00Z";

fn connect_client() -> Client {
    let url = env::var("PRAETORE_TEST_DATABASE_URL")
        .expect("PRAETORE_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    Client::connect(&url, NoTls).expect("connect to PostgreSQL test service")
}

fn initialize_test_database() {
    TEST_DATABASE_SETUP.get_or_init(|| {
        let mut client = connect_client();
        client
            .batch_execute(include_str!("../migrations/0001_replay_claims.sql"))
            .expect("install replay guard test schema");
        client
            .batch_execute(include_str!("../migrations/0002_execution_journal.sql"))
            .expect("install execution journal schema");
        client
            .batch_execute(include_str!("../migrations/0003_execution_replay_link.sql"))
            .expect("link execution journal to replay claims");
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS praetore.gateway_test_effects (\
                     agent_id UUID NOT NULL, request_id UUID NOT NULL, \
                     action_digest CHAR(64) NOT NULL, output_json TEXT NOT NULL, \
                     PRIMARY KEY (agent_id, request_id)); \
                 CREATE TABLE IF NOT EXISTS praetore.gateway_test_invocations (\
                     invocation_id BIGSERIAL PRIMARY KEY, \
                     agent_id UUID NOT NULL, request_id UUID NOT NULL);",
            )
            .expect("install persistent test adapter tables");
        client
            .batch_execute(
                "DO $$ BEGIN \
                     CREATE ROLE praetore_replay_test NOLOGIN; \
                 EXCEPTION WHEN duplicate_object THEN NULL; END $$; \
                 REVOKE ALL ON SCHEMA praetore FROM PUBLIC; \
                 REVOKE ALL ON TABLE praetore.replay_claims FROM PUBLIC; \
                 REVOKE ALL ON TABLE praetore.replay_claims FROM praetore_replay_test; \
                 REVOKE ALL ON TABLE praetore.execution_journal FROM PUBLIC; \
                 REVOKE ALL ON TABLE praetore.execution_journal FROM praetore_replay_test; \
                 GRANT USAGE ON SCHEMA praetore TO praetore_replay_test; \
                 GRANT SELECT (agent_id, request_id) ON praetore.replay_claims \
                     TO praetore_replay_test; \
                 GRANT INSERT (agent_id, request_id) ON praetore.replay_claims \
                     TO praetore_replay_test; \
                 GRANT SELECT, INSERT, UPDATE ON praetore.execution_journal \
                     TO praetore_replay_test",
            )
            .expect("configure least-privilege test role");
    });
}

fn connect_journal_client() -> Client {
    initialize_test_database();
    let mut client = connect_client();
    client
        .batch_execute("SET ROLE praetore_replay_test")
        .expect("assume least-privilege execution journal role");
    client
}

fn connect_journal() -> PostgresExecutionJournal {
    let url = env::var("PRAETORE_TEST_DATABASE_URL")
        .expect("PRAETORE_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    PostgresExecutionJournal::from_connection_factory(move || {
        let mut client = Client::connect(&url, NoTls)?;
        client.batch_execute("SET ROLE praetore_replay_test")?;
        Ok(client)
    })
    .unwrap()
}

fn connect_guard() -> PostgresReplayGuard {
    initialize_test_database();
    let mut client = connect_client();
    client
        .batch_execute("SET ROLE praetore_replay_test")
        .expect("assume least-privilege replay role");
    PostgresReplayGuard::from_client(client)
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn claim_is_unique_and_survives_a_new_client() {
    let agent_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let first_guard = connect_guard();
    assert_eq!(first_guard.claim_once(agent_id, request_id), Ok(()));

    let second_guard = connect_guard();
    assert_eq!(
        second_guard.claim_once(agent_id, request_id),
        Err(ReplayGuardError::AlreadyClaimed)
    );
    assert_eq!(second_guard.claim_once(agent_id, Uuid::new_v4()), Ok(()));
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn concurrent_connections_allow_exactly_one_claim() {
    let agent_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    initialize_test_database();
    let workers = 12;
    let barrier = Arc::new(std::sync::Barrier::new(workers));
    let guards = (0..workers).map(|_| connect_guard()).collect::<Vec<_>>();
    let handles = guards
        .into_iter()
        .map(|guard| {
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                guard.claim_once(agent_id, request_id)
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("claim worker must not panic"))
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(ReplayGuardError::AlreadyClaimed))
            .count(),
        workers - 1
    );
    assert!(
        results
            .iter()
            .all(|result| matches!(result, Ok(()) | Err(ReplayGuardError::AlreadyClaimed)))
    );
}

#[test]
#[ignore = "requires a PostgreSQL service"]
fn a_lost_database_connection_fails_closed_and_a_new_client_recovers() {
    let agent_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    initialize_test_database();
    let mut client = connect_client();
    let backend_pid: i32 = client
        .query_one("SELECT pg_backend_pid()", &[])
        .expect("read test connection backend pid")
        .get(0);
    let guard = PostgresReplayGuard::from_client(client);

    let mut admin = connect_client();
    let terminated: bool = admin
        .query_one("SELECT pg_terminate_backend($1)", &[&backend_pid])
        .expect("terminate replay client's backend")
        .get(0);
    assert!(terminated);
    assert_eq!(
        guard.claim_once(agent_id, request_id),
        Err(ReplayGuardError::Unavailable)
    );

    let recovered_guard = connect_guard();
    assert_eq!(recovered_guard.claim_once(agent_id, request_id), Ok(()));
}

#[test]
#[ignore = "requires a PostgreSQL server restart between before and after phases"]
fn replay_claim_survives_server_restart() {
    let agent_id = Uuid::parse_str("00000000-0000-0000-0000-000000000101").unwrap();
    let request_id = Uuid::parse_str("00000000-0000-0000-0000-000000000102").unwrap();
    let phase = env::var("PRAETORE_TEST_RESTART_PHASE")
        .expect("set PRAETORE_TEST_RESTART_PHASE=before or after");
    match phase.as_str() {
        "before" => {
            initialize_test_database();
            connect_client()
                .execute(
                    "DELETE FROM praetore.replay_claims WHERE agent_id = $1 AND request_id = $2",
                    &[&agent_id, &request_id],
                )
                .expect("clear only the fixed restart-test claim");
            assert_eq!(connect_guard().claim_once(agent_id, request_id), Ok(()));
        }
        "after" => {
            assert_eq!(
                connect_guard().claim_once(agent_id, request_id),
                Err(ReplayGuardError::AlreadyClaimed)
            );
            connect_client()
                .execute(
                    "DELETE FROM praetore.replay_claims WHERE agent_id = $1 AND request_id = $2",
                    &[&agent_id, &request_id],
                )
                .expect("remove only the fixed restart-test claim");
        }
        _ => panic!("PRAETORE_TEST_RESTART_PHASE must be before or after"),
    }
}

struct TestFreshness;

impl FreshnessProvider for TestFreshness {
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

struct PostgresTestAdapter {
    client: Mutex<Client>,
    invocations: AtomicUsize,
    fail_after_effect: AtomicBool,
    reconciliation_unknown: AtomicBool,
    kill_backend_after_effect: Option<i32>,
}

impl PostgresTestAdapter {
    fn new(kill_backend_after_effect: Option<i32>) -> Self {
        Self {
            client: Mutex::new(connect_client()),
            invocations: AtomicUsize::new(0),
            fail_after_effect: AtomicBool::new(false),
            reconciliation_unknown: AtomicBool::new(false),
            kill_backend_after_effect,
        }
    }

    fn invocation_count(&self) -> usize {
        self.invocations.load(Ordering::SeqCst)
    }

    fn effect_output(&self, key: ExecutionKey) -> Option<(String, Value)> {
        let mut client = connect_client();
        let row = client
            .query_opt(
                "SELECT action_digest, output_json FROM praetore.gateway_test_effects \
                 WHERE agent_id = $1 AND request_id = $2",
                &[&key.agent_id, &key.request_id],
            )
            .ok()??;
        let digest: String = row.get(0);
        let output_json: String = row.get(1);
        Some((digest, serde_json::from_str(&output_json).ok()?))
    }
}

impl ActionDispatcher for PostgresTestAdapter {
    fn dispatch(
        &self,
        key: ExecutionKey,
        action: &Action,
        digest: &str,
    ) -> Result<DispatchReport, DispatchError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        let parameters = action.parameters.as_object().ok_or(DispatchError)?;
        let parameter_key = parameters
            .get("key")
            .and_then(Value::as_str)
            .ok_or(DispatchError)?;
        let value = parameters.get("value").ok_or(DispatchError)?;
        let output = json!({"key": parameter_key, "value": value});

        let mut client = self.client.lock().map_err(|_| DispatchError)?;
        let mut transaction = client.transaction().map_err(|_| DispatchError)?;
        transaction
            .execute(
                "INSERT INTO praetore.gateway_test_invocations (agent_id, request_id) \
                 VALUES ($1, $2)",
                &[&key.agent_id, &key.request_id],
            )
            .map_err(|_| DispatchError)?;
        let inserted = transaction
            .execute(
                "INSERT INTO praetore.gateway_test_effects \
                 (agent_id, request_id, action_digest, output_json) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT (agent_id, request_id) DO NOTHING",
                &[
                    &key.agent_id,
                    &key.request_id,
                    &digest,
                    &serde_json::to_string(&output).map_err(|_| DispatchError)?,
                ],
            )
            .map_err(|_| DispatchError)?;
        if inserted == 0 {
            let existing: String = transaction
                .query_one(
                    "SELECT action_digest FROM praetore.gateway_test_effects \
                     WHERE agent_id = $1 AND request_id = $2",
                    &[&key.agent_id, &key.request_id],
                )
                .map_err(|_| DispatchError)?
                .get(0);
            if existing != digest {
                return Err(DispatchError);
            }
        }
        transaction.commit().map_err(|_| DispatchError)?;

        if let Some(pid) = self.kill_backend_after_effect {
            let mut admin = connect_client();
            let terminated: bool = admin
                .query_one("SELECT pg_terminate_backend($1)", &[&pid])
                .map_err(|_| DispatchError)?
                .get(0);
            if !terminated {
                return Err(DispatchError);
            }
        }
        if self.fail_after_effect.swap(false, Ordering::SeqCst) {
            return Err(DispatchError);
        }
        Ok(DispatchReport::Confirmed(output))
    }

    fn reconcile(
        &self,
        key: ExecutionKey,
        _action: &Action,
        expected_digest: &str,
    ) -> ReconciliationReport {
        if self.reconciliation_unknown.load(Ordering::SeqCst) {
            return ReconciliationReport::Unknown;
        }
        match self.effect_output(key) {
            Some((stored_digest, output)) if stored_digest.trim() == expected_digest => {
                ReconciliationReport::Applied(output)
            }
            Some(_) => ReconciliationReport::Unknown,
            None => ReconciliationReport::NotApplied,
        }
    }
}

struct CommitFaultJournal {
    inner: PostgresExecutionJournal,
    fail_before_commit: AtomicBool,
    lose_acknowledgement: AtomicBool,
    fail_verification: AtomicBool,
    fail_terminal: AtomicBool,
}

impl AtomicAuthorizationCommit for CommitFaultJournal {
    fn commit_authorization(
        &self,
        authorization: &CompletedAuthorization,
        trusted_attester: &VerifiedPublicKey,
    ) -> Result<(), AuthorizationCommitError> {
        if self.fail_before_commit.swap(false, Ordering::SeqCst) {
            return Err(AuthorizationCommitError::Unavailable);
        }
        self.inner
            .commit_authorization(authorization, trusted_attester)?;
        if self.lose_acknowledgement.swap(false, Ordering::SeqCst) {
            return Err(AuthorizationCommitError::Unavailable);
        }
        Ok(())
    }

    fn verify_committed_authorization(
        &self,
        authorization: &CompletedAuthorization,
        trusted_attester: &VerifiedPublicKey,
    ) -> Result<(), AuthorizationCommitError> {
        if self.fail_verification.load(Ordering::SeqCst) {
            return Err(AuthorizationCommitError::Unavailable);
        }
        self.inner
            .verify_committed_authorization(authorization, trusted_attester)
    }
}

impl ExecutionJournal for CommitFaultJournal {
    fn mark_dispatched(&self, key: ExecutionKey) -> Result<(), JournalError> {
        self.inner.mark_dispatched(key)
    }

    fn record_terminal(
        &self,
        key: ExecutionKey,
        execution: ExecutionStatus,
        output: Option<&Value>,
    ) -> Result<(), JournalError> {
        if self.fail_terminal.swap(false, Ordering::SeqCst) {
            return Err(JournalError::Unavailable);
        }
        self.inner.record_terminal(key, execution, output)
    }

    fn get(&self, key: ExecutionKey) -> Result<Option<ExecutionRecord>, JournalError> {
        self.inner.get(key)
    }

    fn mark_not_dispatched(&self, key: ExecutionKey) -> Result<(), JournalError> {
        self.inner.mark_not_dispatched(key)
    }

    fn mark_outcome_unknown(&self, key: ExecutionKey) -> Result<(), JournalError> {
        self.inner.mark_outcome_unknown(key)
    }
}

struct PostgresGatewayFixture {
    gateway: Gateway,
    engine: AuthorizationEngine,
    request: AuthorizationRequest,
    policy: Policy,
    issuer_public_key: praetore_core::VerifiedPublicKey,
    attester: EvidenceAttesterKey,
    agent_key: AgentKeyPair,
    adapter: Arc<PostgresTestAdapter>,
}

fn test_validity() -> Validity {
    Validity {
        not_before: Some("2026-01-01T00:00:00Z".into()),
        not_after: Some("2026-12-31T00:00:00Z".into()),
    }
}

fn create_postgres_gateway(request_id: Uuid) -> PostgresGatewayFixture {
    initialize_test_database();
    let agent_key = AgentKeyPair::from_secret_bytes(&[71; 32]);
    let issuer_key = AgentKeyPair::from_secret_bytes(&[72; 32]);
    let attester = EvidenceAttesterKey::from_secret_bytes(&[73; 32]);
    let agent = agent_key.identity(AgentId::new());
    let validity = test_validity();
    let mut authority = Authority::new(
        agent.id.clone(),
        "gateway-test-issuer",
        vec!["local:write".into()],
    )
    .with_validity(validity.clone());
    authority.sign_for_agent(&issuer_key, &agent).unwrap();
    let action = Action::new(
        "local:set_value",
        Some("persistent-state".into()),
        json!({"key": "state", "value": "safe"}),
    )
    .unwrap()
    .with_capability("local:write");
    let policy = Policy::new_v2(
        "postgres-gateway-test",
        1,
        vec![
            PolicyRule::new("allow-local-write", "local:set_value", PolicyEffect::Allow)
                .with_capability("local:write"),
        ],
    );
    let clock = FixedClock::try_new(TEST_NOW).unwrap();
    let now = clock.now();
    let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
    request.request_id = request_id;
    request
        .sign_intent_v2(
            &agent_key,
            "postgres-test-gateway",
            now,
            now + Duration::minutes(1),
            policy.digest().unwrap(),
        )
        .unwrap();
    let issuer_public_key = issuer_key.public_key();
    let engine = create_test_engine(policy.clone(), issuer_public_key.clone(), attester.clone());
    let adapter = Arc::new(PostgresTestAdapter::new(None));
    let gateway =
        Gateway::new(engine.clone(), Arc::new(connect_journal()), adapter.clone()).unwrap();
    PostgresGatewayFixture {
        gateway,
        engine,
        request,
        policy,
        issuer_public_key,
        attester,
        agent_key,
        adapter,
    }
}

fn create_test_engine(
    policy: Policy,
    issuer_public_key: praetore_core::VerifiedPublicKey,
    attester: EvidenceAttesterKey,
) -> AuthorizationEngine {
    let issuer_pin = TrustedAuthorityIssuer::new("gateway-test-issuer", issuer_public_key)
        .unwrap()
        .with_validity(test_validity())
        .unwrap();
    let config = HighAssuranceConfig::new(policy.digest().unwrap(), vec![issuer_pin], attester)
        .unwrap()
        .with_audience("postgres-test-gateway")
        .with_replay_guard(Arc::new(connect_guard()))
        .with_freshness_provider(Arc::new(TestFreshness));
    AuthorizationEngine::production_with_clock(
        policy,
        config,
        FixedClock::try_new(TEST_NOW).unwrap(),
    )
    .unwrap()
}

fn create_gateway_for_fixture(
    fixture: &PostgresGatewayFixture,
    adapter: Arc<PostgresTestAdapter>,
) -> Gateway {
    Gateway::new(
        create_test_engine(
            fixture.policy.clone(),
            fixture.issuer_public_key.clone(),
            fixture.attester.clone(),
        ),
        Arc::new(connect_journal()),
        adapter,
    )
    .unwrap()
}

fn evaluate_and_commit(
    fixture: &PostgresGatewayFixture,
    request: AuthorizationRequest,
) -> praetore_core::Evidence {
    fixture
        .engine
        .evaluate_with_atomic_commit(request, &connect_journal())
        .unwrap()
}

fn database_invocation_count(key: ExecutionKey) -> i64 {
    connect_client()
        .query_one(
            "SELECT count(*) FROM praetore.gateway_test_invocations \
             WHERE agent_id = $1 AND request_id = $2",
            &[&key.agent_id, &key.request_id],
        )
        .unwrap()
        .get(0)
}

fn database_effect_count(key: ExecutionKey) -> i64 {
    connect_client()
        .query_one(
            "SELECT count(*) FROM praetore.gateway_test_effects \
             WHERE agent_id = $1 AND request_id = $2",
            &[&key.agent_id, &key.request_id],
        )
        .unwrap()
        .get(0)
}

fn database_replay_claim_count(key: ExecutionKey) -> i64 {
    connect_client()
        .query_one(
            "SELECT count(*) FROM praetore.replay_claims \
             WHERE agent_id = $1 AND request_id = $2",
            &[&key.agent_id, &key.request_id],
        )
        .unwrap()
        .get(0)
}

fn database_journal_count(key: ExecutionKey) -> i64 {
    connect_client()
        .query_one(
            "SELECT count(*) FROM praetore.execution_journal \
             WHERE agent_id = $1 AND request_id = $2",
            &[&key.agent_id, &key.request_id],
        )
        .unwrap()
        .get(0)
}

fn database_agent_for_request(request_id: Uuid) -> Uuid {
    connect_client()
        .query_one(
            "SELECT agent_id FROM praetore.execution_journal WHERE request_id = $1",
            &[&request_id],
        )
        .unwrap()
        .get(0)
}

fn clear_journal_restart_fixtures(request_ids: &[Uuid]) {
    let mut client = connect_client();
    for request_id in request_ids {
        for table in [
            "praetore.gateway_test_invocations",
            "praetore.gateway_test_effects",
            "praetore.execution_journal",
            "praetore.replay_claims",
        ] {
            client
                .execute(
                    &format!("DELETE FROM {table} WHERE request_id = $1"),
                    &[request_id],
                )
                .unwrap();
        }
    }
}

fn database_rows_for_request(table: &str, request_id: Uuid) -> i64 {
    let query = match table {
        "praetore.replay_claims" | "praetore.execution_journal" => {
            format!("SELECT COUNT(*) FROM {table} WHERE request_id = $1")
        }
        _ => panic!("unsupported test table"),
    };
    connect_client()
        .query_one(&query, &[&request_id])
        .unwrap()
        .get(0)
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_gateway_authorizes_and_persists_one_effect() {
    let fixture = create_postgres_gateway(Uuid::new_v4());
    let receipt = fixture.gateway.execute(fixture.request).unwrap();
    let key = ExecutionKey {
        agent_id: *receipt.evidence.agent.id.as_uuid(),
        request_id: receipt.evidence.request_id,
    };
    assert_eq!(receipt.execution, ExecutionStatus::Confirmed);
    assert_eq!(receipt.evidence.decision.outcome, DecisionOutcome::Allow);
    assert_eq!(database_effect_count(key), 1);
    assert_eq!(database_invocation_count(key), 1);
    let persisted = connect_journal().get(key).unwrap().unwrap();
    assert_eq!(persisted.execution, ExecutionStatus::Confirmed);
    assert_eq!(
        persisted.action_digest,
        action_digest(&receipt.evidence.action).unwrap()
    );
    assert_eq!(database_replay_claim_count(key), 1);
    assert_eq!(database_journal_count(key), 1);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_atomic_commit_rolls_back_claim_when_journal_insert_fails() {
    const REQUEST_ID: &str = "00000000-0000-0000-0000-000000000301";
    let request_id = Uuid::parse_str(REQUEST_ID).unwrap();
    let fixture = create_postgres_gateway(request_id);
    let mut admin = connect_client();
    admin
        .batch_execute(&format!(
            "CREATE OR REPLACE FUNCTION praetore.fail_selected_execution_insert() \
             RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
             IF NEW.request_id = '{REQUEST_ID}'::uuid THEN \
                 RAISE EXCEPTION 'injected journal insert failure'; \
             END IF; RETURN NEW; END; $$; \
             DROP TRIGGER IF EXISTS fail_selected_execution_insert \
                 ON praetore.execution_journal; \
             CREATE TRIGGER fail_selected_execution_insert \
                 BEFORE INSERT ON praetore.execution_journal \
                 FOR EACH ROW EXECUTE FUNCTION praetore.fail_selected_execution_insert();"
        ))
        .unwrap();

    assert!(matches!(
        fixture.gateway.execute(fixture.request.clone()),
        Err(GatewayError::Journal(JournalError::Unavailable))
    ));
    let key = ExecutionKey {
        agent_id: *fixture.request.agent.id.as_uuid(),
        request_id,
    };
    assert_eq!(database_replay_claim_count(key), 0);
    assert_eq!(database_journal_count(key), 0);
    assert_eq!(database_effect_count(key), 0);
    assert_eq!(database_invocation_count(key), 0);

    admin
        .batch_execute(
            "DROP TRIGGER fail_selected_execution_insert ON praetore.execution_journal; \
             DROP FUNCTION praetore.fail_selected_execution_insert();",
        )
        .unwrap();
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_lost_commit_ack_is_verified_before_dispatch() {
    let fixture = create_postgres_gateway(Uuid::new_v4());
    let journal = Arc::new(CommitFaultJournal {
        inner: connect_journal(),
        fail_before_commit: AtomicBool::new(false),
        lose_acknowledgement: AtomicBool::new(true),
        fail_verification: AtomicBool::new(false),
        fail_terminal: AtomicBool::new(false),
    });
    let gateway = Gateway::new(
        create_test_engine(
            fixture.policy.clone(),
            fixture.issuer_public_key.clone(),
            fixture.attester.clone(),
        ),
        journal,
        fixture.adapter.clone(),
    )
    .unwrap();
    let receipt = gateway.execute(fixture.request).unwrap();
    let key = ExecutionKey {
        agent_id: *receipt.evidence.agent.id.as_uuid(),
        request_id: receipt.evidence.request_id,
    };
    assert_eq!(receipt.execution, ExecutionStatus::Confirmed);
    assert_eq!(database_replay_claim_count(key), 1);
    assert_eq!(database_journal_count(key), 1);
    assert_eq!(database_effect_count(key), 1);
    assert_eq!(database_invocation_count(key), 1);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_unverifiable_commit_acknowledgement_blocks_dispatch() {
    let fixture = create_postgres_gateway(Uuid::new_v4());
    let journal = Arc::new(CommitFaultJournal {
        inner: connect_journal(),
        fail_before_commit: AtomicBool::new(false),
        lose_acknowledgement: AtomicBool::new(true),
        fail_verification: AtomicBool::new(true),
        fail_terminal: AtomicBool::new(false),
    });
    let gateway = Gateway::new(
        create_test_engine(
            fixture.policy.clone(),
            fixture.issuer_public_key.clone(),
            fixture.attester.clone(),
        ),
        journal,
        fixture.adapter.clone(),
    )
    .unwrap();
    let key = ExecutionKey {
        agent_id: *fixture.request.agent.id.as_uuid(),
        request_id: fixture.request.request_id,
    };
    assert!(matches!(
        gateway.execute(fixture.request),
        Err(GatewayError::Journal(JournalError::Unavailable))
    ));
    assert_eq!(database_replay_claim_count(key), 1);
    assert_eq!(database_journal_count(key), 1);
    assert_eq!(database_effect_count(key), 0);
    assert_eq!(database_invocation_count(key), 0);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_legacy_replay_claim_without_authorization_is_orphaned_and_blocked() {
    let fixture = create_postgres_gateway(Uuid::new_v4());
    let key = ExecutionKey {
        agent_id: *fixture.request.agent.id.as_uuid(),
        request_id: fixture.request.request_id,
    };
    connect_guard()
        .claim_once(key.agent_id, key.request_id)
        .unwrap();

    assert!(matches!(
        fixture.gateway.execute(fixture.request),
        Err(GatewayError::Journal(JournalError::OrphanedReplayClaim))
    ));
    assert_eq!(database_replay_claim_count(key), 1);
    assert_eq!(database_journal_count(key), 0);
    assert_eq!(database_effect_count(key), 0);
    assert_eq!(database_invocation_count(key), 0);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_journal_prevents_concurrent_duplicate_effects_across_engines() {
    let fixture = create_postgres_gateway(Uuid::new_v4());
    let workers = 8;
    let barrier = Arc::new(std::sync::Barrier::new(workers));
    let gateways = (0..workers)
        .map(|_| create_gateway_for_fixture(&fixture, fixture.adapter.clone()))
        .collect::<Vec<_>>();
    let handles = gateways
        .into_iter()
        .map(|gateway| {
            let barrier = barrier.clone();
            let request = fixture.request.clone();
            thread::spawn(move || {
                barrier.wait();
                gateway.execute(request)
            })
        })
        .collect::<Vec<_>>();
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    let successful = outcomes.iter().filter(|result| result.is_ok()).count();
    let duplicates = outcomes
        .iter()
        .filter(|result| {
            matches!(
                result,
                Err(GatewayError::Journal(JournalError::AlreadyRecorded))
            )
        })
        .count();
    let key = ExecutionKey {
        agent_id: *fixture.request.agent.id.as_uuid(),
        request_id: fixture.request.request_id,
    };
    assert_eq!(successful, 1);
    assert_eq!(duplicates, workers - 1);
    assert_eq!(fixture.adapter.invocation_count(), 1);
    assert_eq!(database_effect_count(key), 1);
    assert_eq!(database_invocation_count(key), 1);
    assert_eq!(database_replay_claim_count(key), 1);
    assert_eq!(database_journal_count(key), 1);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_journal_rejects_execution_key_reused_with_different_action() {
    let fixture = create_postgres_gateway(Uuid::new_v4());
    let first = fixture.gateway.execute(fixture.request.clone()).unwrap();
    let first_key = ExecutionKey {
        agent_id: *first.evidence.agent.id.as_uuid(),
        request_id: first.evidence.request_id,
    };
    assert!(connect_journal().get(first_key).unwrap().is_some());
    let mut changed = fixture.request.clone();
    changed.action.parameters["value"] = json!("different");
    changed.request_id = first.evidence.request_id;
    changed
        .sign_intent_v2(
            &fixture.agent_key,
            "postgres-test-gateway",
            OffsetDateTime::parse(TEST_NOW, &time::format_description::well_known::Rfc3339)
                .unwrap(),
            OffsetDateTime::parse(TEST_NOW, &time::format_description::well_known::Rfc3339)
                .unwrap()
                + Duration::minutes(1),
            fixture.policy.digest().unwrap(),
        )
        .unwrap();
    let second_gateway = create_gateway_for_fixture(&fixture, fixture.adapter.clone());
    let changed_result = second_gateway.execute(changed);
    assert!(matches!(
        &changed_result,
        Err(GatewayError::Journal(JournalError::ConflictingRequest))
    ));
    let mut changed_context = fixture
        .request
        .clone()
        .with_context("region", json!("changed"));
    changed_context
        .sign_intent_v2(
            &fixture.agent_key,
            "postgres-test-gateway",
            OffsetDateTime::parse(TEST_NOW, &time::format_description::well_known::Rfc3339)
                .unwrap(),
            OffsetDateTime::parse(TEST_NOW, &time::format_description::well_known::Rfc3339)
                .unwrap()
                + Duration::minutes(1),
            fixture.policy.digest().unwrap(),
        )
        .unwrap();
    let third_gateway = create_gateway_for_fixture(&fixture, fixture.adapter.clone());
    assert!(matches!(
        third_gateway.execute(changed_context),
        Err(GatewayError::Journal(JournalError::ConflictingRequest))
    ));
    let key = ExecutionKey {
        agent_id: *first.evidence.agent.id.as_uuid(),
        request_id: first.evidence.request_id,
    };
    assert_eq!(fixture.adapter.invocation_count(), 1);
    assert_eq!(database_effect_count(key), 1);
    assert_eq!(database_invocation_count(key), 1);
    assert_eq!(database_replay_claim_count(key), 1);
    assert_eq!(database_journal_count(key), 1);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_journal_failure_before_dispatch_prevents_effect() {
    let fixture = create_postgres_gateway(Uuid::new_v4());
    let journal = Arc::new(CommitFaultJournal {
        inner: connect_journal(),
        fail_before_commit: AtomicBool::new(true),
        lose_acknowledgement: AtomicBool::new(false),
        fail_verification: AtomicBool::new(false),
        fail_terminal: AtomicBool::new(false),
    });
    let adapter = Arc::new(PostgresTestAdapter::new(None));
    let gateway = Gateway::new(
        create_test_engine(fixture.policy, fixture.issuer_public_key, fixture.attester),
        journal,
        adapter.clone(),
    )
    .unwrap();
    assert!(matches!(
        gateway.execute(fixture.request.clone()),
        Err(GatewayError::Journal(JournalError::Unavailable))
    ));
    let key = ExecutionKey {
        agent_id: *fixture.request.agent.id.as_uuid(),
        request_id: fixture.request.request_id,
    };
    assert_eq!(adapter.invocation_count(), 0);
    assert_eq!(database_effect_count(key), 0);
    assert_eq!(database_replay_claim_count(key), 0);
    assert_eq!(database_journal_count(key), 0);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_recovery_never_dispatches_authorized_or_ambiguous_rows() {
    let authorized = create_postgres_gateway(Uuid::new_v4());
    let evidence = evaluate_and_commit(&authorized, authorized.request.clone());
    let authorized_key = ExecutionKey {
        agent_id: *evidence.agent.id.as_uuid(),
        request_id: evidence.request_id,
    };
    let recovered = create_gateway_for_fixture(&authorized, authorized.adapter.clone());
    let receipt = recovered.reconcile(authorized_key).unwrap();
    assert_eq!(receipt.execution, ExecutionStatus::NotDispatched);
    assert_eq!(database_effect_count(authorized_key), 0);
    assert_eq!(authorized.adapter.invocation_count(), 0);

    let ambiguous = create_postgres_gateway(Uuid::new_v4());
    let evidence = evaluate_and_commit(&ambiguous, ambiguous.request.clone());
    let ambiguous_key = ExecutionKey {
        agent_id: *evidence.agent.id.as_uuid(),
        request_id: evidence.request_id,
    };
    let journal = connect_journal();
    journal.mark_dispatched(ambiguous_key).unwrap();
    let recovered = create_gateway_for_fixture(&ambiguous, ambiguous.adapter.clone());
    let receipt = recovered.reconcile(ambiguous_key).unwrap();
    assert_eq!(receipt.execution, ExecutionStatus::Failed);
    assert_eq!(database_effect_count(ambiguous_key), 0);
    assert_eq!(ambiguous.adapter.invocation_count(), 0);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_reconciliation_only_resolves_when_adapter_proves_outcome() {
    let fixture = create_postgres_gateway(Uuid::new_v4());
    let key = ExecutionKey {
        agent_id: *fixture.request.agent.id.as_uuid(),
        request_id: fixture.request.request_id,
    };
    fixture
        .adapter
        .fail_after_effect
        .store(true, Ordering::SeqCst);
    assert!(fixture.gateway.execute(fixture.request.clone()).is_ok());
    assert_eq!(database_effect_count(key), 1);
    assert_eq!(database_invocation_count(key), 1);

    fixture
        .adapter
        .reconciliation_unknown
        .store(true, Ordering::SeqCst);
    let gateway = create_gateway_for_fixture(&fixture, fixture.adapter.clone());
    let unresolved = gateway.reconcile(key).unwrap();
    assert_eq!(unresolved.execution, ExecutionStatus::OutcomeUnknown);
    assert_eq!(database_effect_count(key), 1);
    assert_eq!(database_invocation_count(key), 1);

    fixture
        .adapter
        .reconciliation_unknown
        .store(false, Ordering::SeqCst);
    let resolved = gateway.reconcile(key).unwrap();
    assert_eq!(resolved.execution, ExecutionStatus::Confirmed);
    assert_eq!(database_effect_count(key), 1);
    assert_eq!(database_invocation_count(key), 1);
    assert_eq!(
        connect_journal().get(key).unwrap().unwrap().execution,
        ExecutionStatus::Confirmed
    );
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_effect_survives_failed_terminal_write_and_is_reconciled_without_retry() {
    let fixture = create_postgres_gateway(Uuid::new_v4());
    let journal = Arc::new(CommitFaultJournal {
        inner: connect_journal(),
        fail_before_commit: AtomicBool::new(false),
        lose_acknowledgement: AtomicBool::new(false),
        fail_verification: AtomicBool::new(false),
        fail_terminal: AtomicBool::new(true),
    });
    let adapter = Arc::new(PostgresTestAdapter::new(None));
    let gateway = Gateway::new(
        create_test_engine(
            fixture.policy.clone(),
            fixture.issuer_public_key.clone(),
            fixture.attester.clone(),
        ),
        journal,
        adapter.clone(),
    )
    .unwrap();
    let key = ExecutionKey {
        agent_id: *fixture.request.agent.id.as_uuid(),
        request_id: fixture.request.request_id,
    };
    assert!(matches!(
        gateway.execute(fixture.request.clone()),
        Err(GatewayError::OutcomeNotRecorded(actual)) if actual == key
    ));
    assert_eq!(database_effect_count(key), 1);
    assert_eq!(database_invocation_count(key), 1);

    let recovered = create_gateway_for_fixture(&fixture, adapter.clone());
    let receipt = recovered.reconcile(key).unwrap();
    assert_eq!(receipt.execution, ExecutionStatus::Confirmed);
    assert_eq!(adapter.invocation_count(), 1);
    assert_eq!(database_effect_count(key), 1);
    assert_eq!(database_invocation_count(key), 1);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_journal_terminal_states_cannot_return_to_dispatchable() {
    let fixture = create_postgres_gateway(Uuid::new_v4());
    let receipt = fixture.gateway.execute(fixture.request).unwrap();
    let key = ExecutionKey {
        agent_id: *receipt.evidence.agent.id.as_uuid(),
        request_id: receipt.evidence.request_id,
    };
    let journal = connect_journal();
    assert_eq!(
        journal.mark_dispatched(key),
        Err(JournalError::InvalidTransition)
    );
    assert_eq!(
        journal.record_terminal(key, ExecutionStatus::Failed, None),
        Err(JournalError::InvalidTransition)
    );
    assert_eq!(
        journal.record_terminal(key, ExecutionStatus::Confirmed, receipt.output.as_ref()),
        Ok(())
    );

    let mut direct_client = connect_journal_client();
    assert!(
        direct_client
            .execute(
                "UPDATE praetore.execution_journal SET execution_status = 'authorized' \
                 WHERE agent_id = $1 AND request_id = $2",
                &[&key.agent_id, &key.request_id],
            )
            .is_err()
    );
    assert_eq!(
        connect_journal().get(key).unwrap().unwrap().execution,
        ExecutionStatus::Confirmed
    );
    assert_eq!(database_invocation_count(key), 1);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_journal_survives_server_restart_without_automatic_dispatch() {
    const AUTHORIZED_REQUEST: &str = "00000000-0000-0000-0000-000000000201";
    const DISPATCHING_REQUEST: &str = "00000000-0000-0000-0000-000000000202";
    const ROLLED_BACK_REQUEST: &str = "00000000-0000-0000-0000-000000000203";
    let phase = env::var("PRAETORE_TEST_JOURNAL_RESTART_PHASE")
        .expect("set PRAETORE_TEST_JOURNAL_RESTART_PHASE=before or after");
    match phase.as_str() {
        "before" => {
            initialize_test_database();
            clear_journal_restart_fixtures(&[
                Uuid::parse_str(AUTHORIZED_REQUEST).unwrap(),
                Uuid::parse_str(DISPATCHING_REQUEST).unwrap(),
                Uuid::parse_str(ROLLED_BACK_REQUEST).unwrap(),
            ]);
            let authorized_fixture =
                create_postgres_gateway(Uuid::parse_str(AUTHORIZED_REQUEST).unwrap());
            let authorized_evidence =
                evaluate_and_commit(&authorized_fixture, authorized_fixture.request.clone());
            let authorized_key = ExecutionKey {
                agent_id: *authorized_evidence.agent.id.as_uuid(),
                request_id: authorized_evidence.request_id,
            };
            let journal = connect_journal();

            let dispatching_fixture =
                create_postgres_gateway(Uuid::parse_str(DISPATCHING_REQUEST).unwrap());
            let dispatching_evidence =
                evaluate_and_commit(&dispatching_fixture, dispatching_fixture.request.clone());
            let dispatching_key = ExecutionKey {
                agent_id: *dispatching_evidence.agent.id.as_uuid(),
                request_id: dispatching_evidence.request_id,
            };
            journal.mark_dispatched(dispatching_key).unwrap();
            assert_eq!(database_effect_count(authorized_key), 0);
            assert_eq!(database_effect_count(dispatching_key), 0);

            let rolled_back_request = Uuid::parse_str(ROLLED_BACK_REQUEST).unwrap();
            let rolled_back_fixture = create_postgres_gateway(rolled_back_request);
            let mut admin = connect_client();
            admin
                .batch_execute(&format!(
                    "CREATE OR REPLACE FUNCTION praetore.fail_restart_execution_insert() \
                     RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
                     IF NEW.request_id = '{ROLLED_BACK_REQUEST}'::uuid THEN \
                         RAISE EXCEPTION 'injected restart-test rollback'; \
                     END IF; RETURN NEW; END; $$; \
                     DROP TRIGGER IF EXISTS fail_restart_execution_insert \
                         ON praetore.execution_journal; \
                     CREATE TRIGGER fail_restart_execution_insert \
                         BEFORE INSERT ON praetore.execution_journal \
                         FOR EACH ROW EXECUTE FUNCTION praetore.fail_restart_execution_insert();"
                ))
                .unwrap();
            assert!(matches!(
                rolled_back_fixture
                    .gateway
                    .execute(rolled_back_fixture.request.clone()),
                Err(GatewayError::Journal(JournalError::Unavailable))
            ));
            admin
                .batch_execute(
                    "DROP TRIGGER fail_restart_execution_insert \
                         ON praetore.execution_journal; \
                     DROP FUNCTION praetore.fail_restart_execution_insert();",
                )
                .unwrap();
            assert_eq!(
                database_rows_for_request("praetore.replay_claims", rolled_back_request),
                0
            );
            assert_eq!(
                database_rows_for_request("praetore.execution_journal", rolled_back_request),
                0
            );
        }
        "after" => {
            let authorized_request = Uuid::parse_str(AUTHORIZED_REQUEST).unwrap();
            let dispatching_request = Uuid::parse_str(DISPATCHING_REQUEST).unwrap();
            let rolled_back_request = Uuid::parse_str(ROLLED_BACK_REQUEST).unwrap();
            let authorized_key = ExecutionKey {
                agent_id: database_agent_for_request(authorized_request),
                request_id: authorized_request,
            };
            let dispatching_key = ExecutionKey {
                agent_id: database_agent_for_request(dispatching_request),
                request_id: dispatching_request,
            };
            let authorized_fixture = create_postgres_gateway(Uuid::new_v4());
            let authorized_gateway =
                create_gateway_for_fixture(&authorized_fixture, authorized_fixture.adapter.clone());
            let authorized_receipt = authorized_gateway.reconcile(authorized_key).unwrap();
            assert_eq!(authorized_receipt.execution, ExecutionStatus::NotDispatched);
            assert_eq!(authorized_fixture.adapter.invocation_count(), 0);

            let dispatching_fixture = create_postgres_gateway(Uuid::new_v4());
            let dispatching_gateway = create_gateway_for_fixture(
                &dispatching_fixture,
                dispatching_fixture.adapter.clone(),
            );
            let dispatching_receipt = dispatching_gateway.reconcile(dispatching_key).unwrap();
            assert_eq!(dispatching_receipt.execution, ExecutionStatus::Failed);
            assert_eq!(dispatching_fixture.adapter.invocation_count(), 0);
            assert_eq!(database_effect_count(authorized_key), 0);
            assert_eq!(database_effect_count(dispatching_key), 0);
            assert_eq!(
                database_rows_for_request("praetore.replay_claims", rolled_back_request),
                0
            );
            assert_eq!(
                database_rows_for_request("praetore.execution_journal", rolled_back_request),
                0
            );
            clear_journal_restart_fixtures(&[
                authorized_request,
                dispatching_request,
                rolled_back_request,
            ]);
        }
        _ => panic!("PRAETORE_TEST_JOURNAL_RESTART_PHASE must be before or after"),
    }
}
