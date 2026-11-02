use ed25519_dalek::{Signer, SigningKey};
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
    ActionDispatcher, DispatchError, DispatchReport, ExecutionAttestationError,
    ExecutionAttestationSigner, ExecutionJournal, ExecutionKey, ExecutionRecord, ExecutionStatus,
    Gateway, GatewayError, HumanApprovalDecision, HumanApprovalOutcome, HumanApprovalResult,
    HumanApprovalVerifier, JournalError, NotDispatchedReason, ReconciliationReport, action_digest,
};
use praetore_replay_postgres::{PostgresExecutionJournal, PostgresReplayGuard};
use serde_json::{Value, json};
use std::{
    env,
    sync::{
        Arc, Mutex, OnceLock, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};
use time::{Duration, OffsetDateTime};
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
        let evidence_key = [73, 83]
            .into_iter()
            .map(|secret| EvidenceAttesterKey::from_secret_bytes(&[secret; 32]))
            .find(|key| self.evidence.attester_key_id.as_deref() == Some(key.key_id().as_str()))
            .expect("evidence signed by a known test attester")
            .public_key()
            .unwrap();
        self.verify_execution_attestation(public_key, expected_key_id, &evidence_key)
    }
}

static TEST_DATABASE_SETUP: OnceLock<()> = OnceLock::new();
const TEST_NOW: &str = "2026-06-01T12:00:00Z";
const TEST_TENANT_ID: Uuid = Uuid::from_u128(1);

struct TestExecutionAttester(SigningKey);

impl TestExecutionAttester {
    fn new() -> Self {
        Self(SigningKey::from_bytes(&[74; 32]))
    }
}

impl ExecutionAttestationSigner for TestExecutionAttester {
    fn key_id(&self) -> &str {
        "postgres-test-execution-attester-v1"
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ExecutionAttestationError> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}

fn execution_attester() -> Arc<TestExecutionAttester> {
    Arc::new(TestExecutionAttester::new())
}

fn execution_attester_public_key() -> VerifiedPublicKey {
    VerifiedPublicKey::from_bytes(&TestExecutionAttester::new().0.verifying_key().to_bytes())
        .unwrap()
}

fn connect_client() -> Client {
    let url = env::var("PRAETORE_TEST_DATABASE_URL")
        .expect("PRAETORE_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    Client::connect(&url, NoTls).expect("connect to PostgreSQL test service")
}

/// Membership in `pg_read_all_data` is cluster-wide: while one test holds
/// such a grant, every other test's runtime check on any database would see
/// it. Runtime checks take this lock shared; a test that grants it takes the
/// lock exclusively (`ClusterWideGrant`) until the grant is revoked.
static CLUSTER_WIDE_GRANTS: RwLock<()> = RwLock::new(());

fn verify_runtime_role(
    client: &mut Client,
) -> Result<(), praetore_replay_postgres::RuntimeRoleError> {
    let _shared = CLUSTER_WIDE_GRANTS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    praetore_replay_postgres::verify_runtime_role(client)
}

fn verify_runtime_role_with(
    client: &mut Client,
    options: &praetore_replay_postgres::RuntimeRoleOptions,
) -> Result<(), praetore_replay_postgres::RuntimeRoleError> {
    let _shared = CLUSTER_WIDE_GRANTS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    praetore_replay_postgres::verify_runtime_role_with(client, options)
}

/// A cluster-wide grant held exclusively (see `CLUSTER_WIDE_GRANTS`) and
/// revoked on drop, even if the test panics. Runtime checks made while it is
/// held call the library directly.
struct ClusterWideGrant {
    revoke: String,
    _exclusive: std::sync::RwLockWriteGuard<'static, ()>,
}

impl ClusterWideGrant {
    fn grant(grant: &str, revoke: &str) -> Self {
        let exclusive = CLUSTER_WIDE_GRANTS
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        connect_client().batch_execute(grant).unwrap();
        Self {
            revoke: revoke.to_owned(),
            _exclusive: exclusive,
        }
    }
}

impl Drop for ClusterWideGrant {
    fn drop(&mut self) {
        let _ = connect_client().batch_execute(&self.revoke);
    }
}

fn initialize_test_database() {
    TEST_DATABASE_SETUP.get_or_init(|| {
        let mut client = connect_client();
        praetore_replay_postgres::apply_migrations(&mut client).expect("apply migrations once");
        assert_eq!(
            praetore_replay_postgres::apply_migrations(&mut client)
                .expect("second run is a no-op"),
            Vec::<&str>::new(),
            "no migration may be applied twice"
        );
        client
            .batch_execute(
                "CREATE SCHEMA IF NOT EXISTS praetore_test_adapter; \
                 CREATE TABLE IF NOT EXISTS praetore_test_adapter.gateway_test_effects (\
                     tenant_id UUID NOT NULL, agent_id UUID NOT NULL, request_id UUID NOT NULL, \
                     action_digest CHAR(64) NOT NULL, output_json TEXT NOT NULL, \
                     PRIMARY KEY (tenant_id, agent_id, request_id)); \
                 CREATE TABLE IF NOT EXISTS praetore_test_adapter.gateway_test_invocations (\
                     invocation_id BIGSERIAL PRIMARY KEY, tenant_id UUID NOT NULL, \
                     agent_id UUID NOT NULL, request_id UUID NOT NULL); \
                 ALTER TABLE praetore_test_adapter.gateway_test_effects \
                     ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL \
                     DEFAULT '00000000-0000-0000-0000-000000000000'; \
                 ALTER TABLE praetore_test_adapter.gateway_test_effects \
                     DROP CONSTRAINT IF EXISTS gateway_test_effects_pkey; \
                 ALTER TABLE praetore_test_adapter.gateway_test_effects \
                     ADD CONSTRAINT gateway_test_effects_pkey \
                     PRIMARY KEY (tenant_id, agent_id, request_id); \
                 ALTER TABLE praetore_test_adapter.gateway_test_invocations \
                     ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL \
                     DEFAULT '00000000-0000-0000-0000-000000000000';",
            )
            .expect("install persistent test adapter tables");
        client
            .batch_execute(
                "DO $$ BEGIN \
                     CREATE ROLE praetore_replay_test NOLOGIN; \
                 EXCEPTION WHEN duplicate_object THEN NULL; END $$; \
                DO $$ BEGIN \
                    CREATE ROLE praetore_observe NOLOGIN; \
                EXCEPTION WHEN duplicate_object THEN NULL; END $$; \
                 REVOKE ALL ON SCHEMA praetore FROM PUBLIC; \
                 REVOKE ALL ON TABLE praetore.replay_claims FROM PUBLIC; \
                 REVOKE ALL ON TABLE praetore.replay_claims FROM praetore_replay_test; \
                 REVOKE ALL ON TABLE praetore.execution_journal FROM PUBLIC; \
                 REVOKE ALL ON TABLE praetore.execution_journal FROM praetore_replay_test; \
                 REVOKE ALL ON TABLE praetore.execution_journal_events FROM PUBLIC; \
                 REVOKE ALL ON TABLE praetore.execution_attestations FROM PUBLIC; \
                 REVOKE ALL ON TABLE praetore.human_approvals FROM PUBLIC; \
                 REVOKE ALL ON TABLE praetore.execution_journal_events \
                     FROM praetore_replay_test; \
                 REVOKE ALL ON TABLE praetore.execution_attestations \
                     FROM praetore_replay_test; \
                 REVOKE ALL ON TABLE praetore.human_approvals \
                     FROM praetore_replay_test; \
                 REVOKE ALL ON TABLE praetore.human_approval_expirations \
                     FROM praetore_replay_test; \
                 REVOKE ALL ON SCHEMA praetore FROM praetore_replay_test; \
                 GRANT praetore_runtime TO praetore_replay_test; \
                 GRANT USAGE ON SCHEMA praetore TO praetore_observe; \
                 REVOKE ALL ON TABLE praetore.execution_journal \
                     FROM praetore_observe; \
                 REVOKE ALL ON TABLE praetore.execution_journal_events \
                     FROM praetore_observe; \
                 GRANT SELECT (tenant_id, agent_id, request_id, request_digest, action_digest, \
                     authorization_status, execution_status, evidence_json, created_at, updated_at) \
                     ON praetore.execution_journal TO praetore_observe; \
                 GRANT SELECT (event_id, tenant_id, agent_id, request_id, from_status, to_status, occurred_at) \
                     ON praetore.execution_journal_events TO praetore_observe",
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

fn connect_observability_reader() -> praetore_replay_postgres::PostgresObservabilityReader {
    initialize_test_database();
    let mut client = connect_client();
    client
        .batch_execute("SET ROLE praetore_observe")
        .expect("assume read-only observability role");
    praetore_replay_postgres::PostgresObservabilityReader::from_client(client).unwrap()
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
    assert_eq!(
        first_guard.claim_once(TEST_TENANT_ID, agent_id, request_id),
        Ok(())
    );

    let second_guard = connect_guard();
    assert_eq!(
        second_guard.claim_once(TEST_TENANT_ID, agent_id, request_id),
        Err(ReplayGuardError::AlreadyClaimed)
    );
    assert_eq!(
        second_guard.claim_once(TEST_TENANT_ID, agent_id, Uuid::new_v4()),
        Ok(())
    );
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn replay_claims_are_namespaced_by_tenant() {
    let agent_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let first_tenant = Uuid::from_u128(1);
    let second_tenant = Uuid::from_u128(2);
    let guard = connect_guard();

    assert_eq!(guard.claim_once(first_tenant, agent_id, request_id), Ok(()));
    assert_eq!(
        guard.claim_once(second_tenant, agent_id, request_id),
        Ok(())
    );
    assert_eq!(
        guard.claim_once(first_tenant, agent_id, request_id),
        Err(ReplayGuardError::AlreadyClaimed)
    );
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
                guard.claim_once(TEST_TENANT_ID, agent_id, request_id)
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
        guard.claim_once(TEST_TENANT_ID, agent_id, request_id),
        Err(ReplayGuardError::Unavailable)
    );

    let recovered_guard = connect_guard();
    assert_eq!(
        recovered_guard.claim_once(TEST_TENANT_ID, agent_id, request_id),
        Ok(())
    );
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
                    "DELETE FROM praetore.replay_claims \
                     WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                    &[&TEST_TENANT_ID, &agent_id, &request_id],
                )
                .expect("clear only the fixed restart-test claim");
            assert_eq!(
                connect_guard().claim_once(TEST_TENANT_ID, agent_id, request_id),
                Ok(())
            );
        }
        "after" => {
            assert_eq!(
                connect_guard().claim_once(TEST_TENANT_ID, agent_id, request_id),
                Err(ReplayGuardError::AlreadyClaimed)
            );
            connect_client()
                .execute(
                    "DELETE FROM praetore.replay_claims \
                     WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                    &[&TEST_TENANT_ID, &agent_id, &request_id],
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
                "SELECT action_digest, output_json FROM praetore_test_adapter.gateway_test_effects \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
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
        _authority: &Authority,
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
                "INSERT INTO praetore_test_adapter.gateway_test_invocations \
                 (tenant_id, agent_id, request_id) VALUES ($1, $2, $3)",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| DispatchError)?;
        let inserted = transaction
            .execute(
                "INSERT INTO praetore_test_adapter.gateway_test_effects \
                 (tenant_id, agent_id, request_id, action_digest, output_json) \
                 VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (tenant_id, agent_id, request_id) DO NOTHING",
                &[
                    &key.tenant_id,
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
                    "SELECT action_digest FROM praetore_test_adapter.gateway_test_effects \
                     WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                    &[&key.tenant_id, &key.agent_id, &key.request_id],
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
        _authority: &Authority,
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
    /// Fails `record_human_approval` before anything is written.
    fail_approval: AtomicBool,
    /// Commits `claim_dispatch`, then reports the journal as unavailable.
    lose_claim_acknowledgement: AtomicBool,
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

    fn record_terminal_attested(
        &self,
        key: ExecutionKey,
        execution: ExecutionStatus,
        output: Option<&Value>,
        attestation: &praetore_gateway::ExecutionAttestation,
    ) -> Result<(), JournalError> {
        if self.fail_terminal.swap(false, Ordering::SeqCst) {
            return Err(JournalError::Unavailable);
        }
        self.inner
            .record_terminal_attested(key, execution, output, attestation)
    }

    fn record_attestation(
        &self,
        key: ExecutionKey,
        execution: ExecutionStatus,
        output: Option<&Value>,
        attestation: &praetore_gateway::ExecutionAttestation,
    ) -> Result<(), JournalError> {
        self.inner
            .record_attestation(key, execution, output, attestation)
    }

    fn get(&self, key: ExecutionKey) -> Result<Option<ExecutionRecord>, JournalError> {
        self.inner.get(key)
    }

    fn mark_not_dispatched_attested(
        &self,
        key: ExecutionKey,
        attestation: &praetore_gateway::ExecutionAttestation,
    ) -> Result<(), JournalError> {
        self.inner.mark_not_dispatched_attested(key, attestation)
    }

    fn record_human_approval(
        &self,
        key: ExecutionKey,
        decision: &praetore_gateway::HumanApprovalDecision,
        now: OffsetDateTime,
    ) -> Result<(), JournalError> {
        if self.fail_approval.swap(false, Ordering::SeqCst) {
            return Err(JournalError::Unavailable);
        }
        self.inner.record_human_approval(key, decision, now)
    }

    fn claim_dispatch(&self, key: ExecutionKey, now: OffsetDateTime) -> Result<(), JournalError> {
        self.inner.claim_dispatch(key, now)?;
        if self
            .lose_claim_acknowledgement
            .swap(false, Ordering::SeqCst)
        {
            return Err(JournalError::Unavailable);
        }
        Ok(())
    }

    fn record_approval_expiration(
        &self,
        key: ExecutionKey,
        receipt: &praetore_gateway::ApprovalExpiredReceipt,
    ) -> Result<(), JournalError> {
        self.inner.record_approval_expiration(key, receipt)
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

struct PostgresApprovalFixture {
    gateway: Gateway,
    engine: AuthorizationEngine,
    request: AuthorizationRequest,
    adapter: Arc<PostgresTestAdapter>,
    approver_key: SigningKey,
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
    .with_validity(validity.clone())
    .with_constraint("tenant_id", TEST_TENANT_ID.to_string());
    authority.sign_for_agent(&issuer_key, &agent).unwrap();
    let action = Action::new(
        "local:set_value",
        Some("persistent-state".into()),
        json!({"key": "state", "value": "safe"}),
    )
    .unwrap()
    .with_capability("local:write");
    let policy = mission_policy(Policy::new_v2(
        "postgres-gateway-test",
        1,
        vec![
            PolicyRule::new("allow-local-write", "local:set_value", PolicyEffect::Allow)
                .with_capability("local:write"),
        ],
    ));
    let clock = FixedClock::try_new(TEST_NOW).unwrap();
    let now = clock.now();
    let mut request = AuthorizationRequest::new(agent, authority, mission(action)).unwrap();
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
    let gateway = Gateway::new(
        engine.clone(),
        Arc::new(connect_journal()),
        adapter.clone(),
        execution_attester(),
    )
    .unwrap();
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

fn create_postgres_approval_gateway(request_id: Uuid) -> PostgresApprovalFixture {
    create_postgres_approval_gateway_with_clock(request_id, None)
}

/// Advanceable engine clock for SAF-10 expiry tests.
#[derive(Clone)]
struct SharedClock(Arc<std::sync::Mutex<OffsetDateTime>>);

impl SharedClock {
    /// Starts at the fixed `TEST_NOW`, inside `test_validity()`, so no
    /// validity check depends on the host clock.
    fn at_test_now() -> Self {
        Self(Arc::new(std::sync::Mutex::new(test_now())))
    }
}

fn test_now() -> OffsetDateTime {
    FixedClock::try_new(TEST_NOW).unwrap().now()
}

impl praetore_core::engine::Clock for SharedClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

fn create_postgres_approval_gateway_with_clock(
    request_id: Uuid,
    clock: Option<SharedClock>,
) -> PostgresApprovalFixture {
    initialize_test_database();
    let agent_key = AgentKeyPair::from_secret_bytes(&[81; 32]);
    let issuer_key = AgentKeyPair::from_secret_bytes(&[82; 32]);
    let attester = EvidenceAttesterKey::from_secret_bytes(&[83; 32]);
    let agent = agent_key.identity(AgentId::new());
    let validity = test_validity();
    let mut authority = Authority::new(
        agent.id.clone(),
        "gateway-test-issuer",
        vec!["local:write".into()],
    )
    .with_validity(validity.clone())
    .with_constraint("tenant_id", TEST_TENANT_ID.to_string());
    authority.sign_for_agent(&issuer_key, &agent).unwrap();
    let action = Action::new(
        "local:set_value",
        Some("persistent-state".into()),
        json!({"key": "state", "value": "human-approved"}),
    )
    .unwrap()
    .with_capability("local:write");
    let policy = mission_policy(Policy::new_v2(
        "postgres-human-approval",
        1,
        vec![
            PolicyRule::new(
                "require-human-approval",
                "local:set_value",
                PolicyEffect::RequireApproval,
            )
            .with_capability("local:write"),
        ],
    ));
    // Intents are signed at the engine's (injected) time, never host time.
    let clock = clock.unwrap_or_else(SharedClock::at_test_now);
    let now = clock.now();
    let mut request = AuthorizationRequest::new(agent, authority, mission(action)).unwrap();
    request.request_id = request_id;
    request
        .sign_intent_v2(
            &agent_key,
            "postgres-test-gateway",
            now,
            now + Duration::seconds(20),
            policy.digest().unwrap(),
        )
        .unwrap();
    let issuer_pin = TrustedAuthorityIssuer::new("gateway-test-issuer", issuer_key.public_key())
        .unwrap()
        .with_validity(validity)
        .unwrap();
    let config = HighAssuranceConfig::new(policy.digest().unwrap(), vec![issuer_pin], attester)
        .unwrap()
        .with_audience("postgres-test-gateway")
        .with_replay_guard(Arc::new(connect_guard()))
        .with_freshness_provider(Arc::new(TestFreshness));
    let engine = AuthorizationEngine::production_with_clock(policy, config, clock).unwrap();
    let adapter = Arc::new(PostgresTestAdapter::new(None));
    let approver_key = SigningKey::from_bytes(&[84; 32]);
    let verifier = HumanApprovalVerifier::new(
        "postgres-human-approver-v1",
        VerifiedPublicKey::from_bytes(&approver_key.verifying_key().to_bytes()).unwrap(),
    )
    .unwrap();
    let gateway = Gateway::new(
        engine.clone(),
        Arc::new(connect_journal()),
        adapter.clone(),
        execution_attester(),
    )
    .unwrap()
    .with_human_approval_verifier(verifier);
    PostgresApprovalFixture {
        gateway,
        engine,
        request,
        adapter,
        approver_key,
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
        execution_attester(),
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
            "SELECT count(*) FROM praetore_test_adapter.gateway_test_invocations \
             WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
            &[&key.tenant_id, &key.agent_id, &key.request_id],
        )
        .unwrap()
        .get(0)
}

fn database_effect_count(key: ExecutionKey) -> i64 {
    connect_client()
        .query_one(
            "SELECT count(*) FROM praetore_test_adapter.gateway_test_effects \
             WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
            &[&key.tenant_id, &key.agent_id, &key.request_id],
        )
        .unwrap()
        .get(0)
}

fn database_replay_claim_count(key: ExecutionKey) -> i64 {
    connect_client()
        .query_one(
            "SELECT count(*) FROM praetore.replay_claims \
             WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
            &[&key.tenant_id, &key.agent_id, &key.request_id],
        )
        .unwrap()
        .get(0)
}

fn database_unscoped_replay_claim_count(key: ExecutionKey) -> i64 {
    connect_client()
        .query_one(
            "SELECT count(*) FROM praetore.replay_claims \
             WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
            &[&Uuid::nil(), &key.agent_id, &key.request_id],
        )
        .unwrap()
        .get(0)
}

fn database_journal_count(key: ExecutionKey) -> i64 {
    connect_client()
        .query_one(
            "SELECT count(*) FROM praetore.execution_journal \
             WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
            &[&key.tenant_id, &key.agent_id, &key.request_id],
        )
        .unwrap()
        .get(0)
}

fn database_agent_for_request(request_id: Uuid) -> Uuid {
    connect_client()
        .query_one(
            "SELECT agent_id FROM praetore.execution_journal \
             WHERE tenant_id = $1 AND request_id = $2",
            &[&TEST_TENANT_ID, &request_id],
        )
        .unwrap()
        .get(0)
}

fn clear_journal_restart_fixtures(request_ids: &[Uuid]) {
    let mut client = connect_client();
    client
        .batch_execute(
            "BEGIN; \
             ALTER TABLE praetore.execution_journal_events \
                 DISABLE TRIGGER execution_journal_events_immutable; \
             ALTER TABLE praetore.execution_attestations \
                 DISABLE TRIGGER execution_attestations_immutable; \
             ALTER TABLE praetore.human_approvals \
                 DISABLE TRIGGER human_approvals_immutable;",
        )
        .unwrap();
    for request_id in request_ids {
        for table in [
            "praetore_test_adapter.gateway_test_invocations",
            "praetore_test_adapter.gateway_test_effects",
            "praetore.execution_attestations",
            "praetore.human_approvals",
            "praetore.execution_journal_events",
            "praetore.execution_journal",
            "praetore.replay_claims",
        ] {
            client
                .execute(
                    &format!("DELETE FROM {table} WHERE tenant_id = $1 AND request_id = $2"),
                    &[&TEST_TENANT_ID, request_id],
                )
                .unwrap();
        }
    }
    client
        .batch_execute(
            "ALTER TABLE praetore.execution_journal_events \
                 ENABLE TRIGGER execution_journal_events_immutable; \
             ALTER TABLE praetore.execution_attestations \
                 ENABLE TRIGGER execution_attestations_immutable; \
             ALTER TABLE praetore.human_approvals \
                 ENABLE TRIGGER human_approvals_immutable; \
             COMMIT;",
        )
        .unwrap();
}

fn database_rows_for_request(table: &str, request_id: Uuid) -> i64 {
    let query = match table {
        "praetore.replay_claims"
        | "praetore.execution_journal"
        | "praetore.human_approval_expirations"
        | "praetore.human_approvals" => {
            format!("SELECT COUNT(*) FROM {table} WHERE tenant_id = $1 AND request_id = $2")
        }
        _ => panic!("unsupported test table"),
    };
    connect_client()
        .query_one(&query, &[&TEST_TENANT_ID, &request_id])
        .unwrap()
        .get(0)
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_gateway_authorizes_and_persists_one_effect() {
    let fixture = create_postgres_gateway(Uuid::new_v4());
    let receipt = fixture.gateway.execute(fixture.request.clone()).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *receipt.evidence.agent.id.as_uuid(),
        request_id: receipt.evidence.request_id,
    };
    assert_eq!(receipt.execution, ExecutionStatus::Confirmed);
    receipt
        .verify_with_test_evidence_attester(
            &execution_attester_public_key(),
            "postgres-test-execution-attester-v1",
        )
        .unwrap();
    assert_eq!(receipt.evidence.decision.outcome, DecisionOutcome::Allow);
    assert_eq!(database_effect_count(key), 1);
    assert_eq!(database_invocation_count(key), 1);
    let persisted = connect_journal().get(key).unwrap().unwrap();
    assert_eq!(persisted.execution, ExecutionStatus::Confirmed);
    assert_eq!(
        persisted.action_digest,
        action_digest(&receipt.evidence.action).unwrap()
    );
    assert_eq!(
        serde_json::to_value(persisted.execution_attestation.unwrap()).unwrap(),
        serde_json::to_value(receipt.execution_attestation.clone()).unwrap()
    );
    let recovered = create_gateway_for_fixture(&fixture, fixture.adapter.clone())
        .reconcile(key)
        .unwrap();
    recovered
        .verify_with_test_evidence_attester(
            &execution_attester_public_key(),
            "postgres-test-execution-attester-v1",
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(recovered.execution_attestation).unwrap(),
        serde_json::to_value(receipt.execution_attestation).unwrap()
    );
    assert_eq!(fixture.adapter.invocation_count(), 1);
    assert_eq!(database_replay_claim_count(key), 1);
    assert_eq!(database_journal_count(key), 1);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_execution_identity_isolated_for_same_agent_and_request_across_tenants() {
    let first = create_postgres_gateway(Uuid::new_v4());
    let first_receipt = first.gateway.execute(first.request.clone()).unwrap();
    let second_tenant = Uuid::from_u128(2);
    let agent_key = AgentKeyPair::from_secret_bytes(&[71; 32]);
    let issuer_key = AgentKeyPair::from_secret_bytes(&[72; 32]);
    let agent = first.request.agent.clone();
    let mut authority = Authority::new(
        agent.id.clone(),
        "gateway-test-issuer",
        vec!["local:write".into()],
    )
    .with_validity(test_validity())
    .with_constraint("tenant_id", second_tenant.to_string());
    authority.sign_for_agent(&issuer_key, &agent).unwrap();

    let mut second_request =
        AuthorizationRequest::new(agent, authority, first.request.action.clone()).unwrap();
    second_request.request_id = first.request.request_id;
    let now = FixedClock::try_new(TEST_NOW).unwrap().now();
    second_request
        .sign_intent_v2(
            &agent_key,
            "postgres-test-gateway",
            now,
            now + Duration::minutes(1),
            first.policy.digest().unwrap(),
        )
        .unwrap();
    let second_adapter = Arc::new(PostgresTestAdapter::new(None));
    let second_gateway = Gateway::new(
        create_test_engine(
            first.policy.clone(),
            first.issuer_public_key.clone(),
            first.attester.clone(),
        ),
        Arc::new(connect_journal()),
        second_adapter.clone(),
        execution_attester(),
    )
    .unwrap();
    let second_receipt = second_gateway.execute(second_request).unwrap();
    let first_key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *first_receipt.evidence.agent.id.as_uuid(),
        request_id: first_receipt.evidence.request_id,
    };
    let second_key = ExecutionKey {
        tenant_id: second_tenant,
        agent_id: *second_receipt.evidence.agent.id.as_uuid(),
        request_id: second_receipt.evidence.request_id,
    };

    assert_eq!(first_key.agent_id, second_key.agent_id);
    assert_eq!(first_key.request_id, second_key.request_id);
    assert_ne!(first_key.tenant_id, second_key.tenant_id);
    assert_eq!(database_journal_count(first_key), 1);
    assert_eq!(database_journal_count(second_key), 1);
    assert_eq!(database_replay_claim_count(first_key), 1);
    assert_eq!(database_replay_claim_count(second_key), 1);
    assert_eq!(database_effect_count(first_key), 1);
    assert_eq!(database_effect_count(second_key), 1);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_atomic_commit_rolls_back_claim_when_journal_insert_fails() {
    // The fault-injection trigger is an object in praetore: in the shared
    // database, another test's migration run would see it as drift.
    if !in_own_scratch_database("postgres_atomic_commit_rolls_back_claim_when_journal_insert_fails")
    {
        return;
    }
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
        tenant_id: TEST_TENANT_ID,
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
        fail_approval: AtomicBool::new(false),
        lose_claim_acknowledgement: AtomicBool::new(false),
    });
    let gateway = Gateway::new(
        create_test_engine(
            fixture.policy.clone(),
            fixture.issuer_public_key.clone(),
            fixture.attester.clone(),
        ),
        journal,
        fixture.adapter.clone(),
        execution_attester(),
    )
    .unwrap();
    let receipt = gateway.execute(fixture.request).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
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
        fail_approval: AtomicBool::new(false),
        lose_claim_acknowledgement: AtomicBool::new(false),
    });
    let gateway = Gateway::new(
        create_test_engine(
            fixture.policy.clone(),
            fixture.issuer_public_key.clone(),
            fixture.attester.clone(),
        ),
        journal,
        fixture.adapter.clone(),
        execution_attester(),
    )
    .unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
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
        tenant_id: TEST_TENANT_ID,
        agent_id: *fixture.request.agent.id.as_uuid(),
        request_id: fixture.request.request_id,
    };
    connect_guard()
        .claim_once(Uuid::nil(), key.agent_id, key.request_id)
        .unwrap();

    assert!(matches!(
        fixture.gateway.execute(fixture.request),
        Err(GatewayError::Journal(JournalError::OrphanedReplayClaim))
    ));
    assert_eq!(database_unscoped_replay_claim_count(key), 1);
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
        tenant_id: TEST_TENANT_ID,
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
        tenant_id: TEST_TENANT_ID,
        agent_id: *first.evidence.agent.id.as_uuid(),
        request_id: first.evidence.request_id,
    };
    assert!(connect_journal().get(first_key).unwrap().is_some());
    let mut changed = fixture.request.clone();
    let mut action = changed.action.action().clone();
    action.parameters["value"] = json!("different");
    changed.action = mission(action);
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
        tenant_id: TEST_TENANT_ID,
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
        fail_approval: AtomicBool::new(false),
        lose_claim_acknowledgement: AtomicBool::new(false),
    });
    let adapter = Arc::new(PostgresTestAdapter::new(None));
    let gateway = Gateway::new(
        create_test_engine(fixture.policy, fixture.issuer_public_key, fixture.attester),
        journal,
        adapter.clone(),
        execution_attester(),
    )
    .unwrap();
    assert!(matches!(
        gateway.execute(fixture.request.clone()),
        Err(GatewayError::Journal(JournalError::Unavailable))
    ));
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
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
        tenant_id: TEST_TENANT_ID,
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
        tenant_id: TEST_TENANT_ID,
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
        tenant_id: TEST_TENANT_ID,
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
    unresolved
        .verify_with_test_evidence_attester(
            &execution_attester_public_key(),
            "postgres-test-execution-attester-v1",
        )
        .unwrap();
    assert_eq!(
        connect_journal()
            .get(key)
            .unwrap()
            .unwrap()
            .execution_attestation
            .unwrap()
            .execution,
        ExecutionStatus::OutcomeUnknown
    );
    assert_eq!(database_effect_count(key), 1);
    assert_eq!(database_invocation_count(key), 1);

    fixture
        .adapter
        .reconciliation_unknown
        .store(false, Ordering::SeqCst);
    let resolved = gateway.reconcile(key).unwrap();
    assert_eq!(resolved.execution, ExecutionStatus::Confirmed);
    resolved
        .verify_with_test_evidence_attester(
            &execution_attester_public_key(),
            "postgres-test-execution-attester-v1",
        )
        .unwrap();
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
        fail_approval: AtomicBool::new(false),
        lose_claim_acknowledgement: AtomicBool::new(false),
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
        execution_attester(),
    )
    .unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
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
        tenant_id: TEST_TENANT_ID,
        agent_id: *receipt.evidence.agent.id.as_uuid(),
        request_id: receipt.evidence.request_id,
    };
    let journal = connect_journal();
    assert_eq!(
        journal.mark_dispatched(key),
        Err(JournalError::InvalidTransition)
    );
    assert_eq!(
        journal.record_terminal_attested(
            key,
            ExecutionStatus::Failed,
            None,
            &receipt.execution_attestation,
        ),
        Err(JournalError::InvalidRecord)
    );
    assert_eq!(
        journal.record_terminal_attested(
            key,
            ExecutionStatus::Confirmed,
            receipt.output.as_ref(),
            &receipt.execution_attestation,
        ),
        Ok(())
    );

    let mut direct_client = connect_journal_client();
    direct_client
        .query_one(
            "SELECT set_config('praetore.tenant_id', $1, false)",
            &[&key.tenant_id.to_string()],
        )
        .unwrap();
    assert!(
        direct_client
            .execute(
                "UPDATE praetore.execution_journal SET execution_status = 'authorized' \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
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
fn postgres_observability_lists_filters_and_reads_real_transition_history() {
    let fixture = create_postgres_gateway(Uuid::new_v4());
    let receipt = fixture.gateway.execute(fixture.request).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *receipt.evidence.agent.id.as_uuid(),
        request_id: receipt.evidence.request_id,
    };
    let reader = connect_observability_reader();
    assert!(reader.database_available());

    let filters = praetore_replay_postgres::ExecutionFilters {
        tenant_id: Some(key.tenant_id),
        agent_id: Some(key.agent_id),
        decision: Some(praetore_gateway::AuthorizationStatus::Allowed),
        execution: Some(ExecutionStatus::Confirmed),
        from: Some(OffsetDateTime::now_utc() - Duration::days(1)),
        to: Some(OffsetDateTime::now_utc() + Duration::days(1)),
        limit: 10,
        offset: 0,
    };
    let page = reader.list(&filters).unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].key, key);
    assert_eq!(
        page.rows[0].authorization,
        praetore_gateway::AuthorizationStatus::Allowed
    );
    assert_eq!(page.rows[0].execution, ExecutionStatus::Confirmed);
    assert!(page.rows[0].evidence.verify_integrity());
    assert!(page.rows[0].output_available);

    let (detail, history) = reader.get(key).unwrap().unwrap();
    assert_eq!(detail.key, key);
    assert_eq!(
        history.iter().map(|event| event.to).collect::<Vec<_>>(),
        vec![
            ExecutionStatus::Authorized,
            ExecutionStatus::Dispatched,
            ExecutionStatus::Confirmed
        ]
    );
    assert_eq!(history[0].from, None);
    assert_eq!(history[1].from, Some(ExecutionStatus::Authorized));
    assert_eq!(history[2].from, Some(ExecutionStatus::Dispatched));

    let mut read_only_client = connect_client();
    read_only_client
        .batch_execute("SET ROLE praetore_observe")
        .unwrap();
    assert!(
        read_only_client
            .query_opt(
                "SELECT output_json FROM praetore.execution_journal \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .is_err()
    );
    assert!(
        read_only_client
            .execute(
                "UPDATE praetore.execution_journal SET execution_status = 'failed' \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .is_err()
    );
    assert!(
        connect_client()
            .execute(
                "DELETE FROM praetore.execution_journal_events \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .is_err()
    );
    assert!(
        read_only_client
            .execute(
                "DELETE FROM praetore.execution_journal_events \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .is_err()
    );
    assert_eq!(
        read_only_client
            .query_one(
                "SELECT count(*) FROM praetore.execution_journal \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .unwrap()
            .get::<_, i64>(0),
        0,
        "RLS must hide tenant rows when no tenant context is set"
    );

    let mut rls_client = connect_client();
    rls_client
        .batch_execute("SET ROLE praetore_observe")
        .unwrap();
    let mut rls_transaction = rls_client.transaction().unwrap();
    rls_transaction
        .query_one(
            "SELECT set_config('praetore.tenant_id', $1, true)",
            &[&key.tenant_id.to_string()],
        )
        .unwrap();
    assert_eq!(
        rls_transaction
            .query_one(
                "SELECT count(*) FROM praetore.execution_journal \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    rls_transaction
        .query_one(
            "SELECT set_config('praetore.tenant_id', $1, true)",
            &[&Uuid::from_u128(2).to_string()],
        )
        .unwrap();
    assert_eq!(
        rls_transaction
            .query_one(
                "SELECT count(*) FROM praetore.execution_journal \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .unwrap()
            .get::<_, i64>(0),
        0,
        "RLS must hide another tenant even when the query asks for its exact key"
    );
    rls_transaction.commit().unwrap();

    assert_eq!(
        connect_journal().get(key).unwrap().unwrap().execution,
        ExecutionStatus::Confirmed
    );
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_human_approval_is_persisted_atomically_and_consumed_once() {
    let fixture = create_postgres_approval_gateway(Uuid::new_v4());
    let pending = fixture.gateway.execute(fixture.request).unwrap();
    assert_eq!(
        pending.evidence.decision.outcome,
        DecisionOutcome::RequireApproval
    );
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let challenge = fixture.gateway.approval_challenge(key).unwrap();
    let mut decision = HumanApprovalDecision {
        schema_version: 1,
        approval_id: Uuid::new_v4(),
        approver_key_id: "postgres-human-approver-v1".into(),
        challenge,
        outcome: HumanApprovalOutcome::Approve,
        signature: String::new(),
    };
    decision.signature = hex::encode(
        fixture
            .approver_key
            .sign(&decision.signing_message().unwrap())
            .to_bytes(),
    );

    let resolution = fixture
        .gateway
        .resolve_human_approval(decision.clone())
        .unwrap();
    assert!(matches!(
        resolution,
        HumanApprovalResult::ApprovedPendingDispatch { .. }
    ));
    assert_eq!(fixture.adapter.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        connect_journal().get(key).unwrap().unwrap().execution,
        ExecutionStatus::ApprovedPendingDispatch
    );
    let receipt = fixture.gateway.dispatch_approved(key).unwrap();
    assert_eq!(receipt.execution, ExecutionStatus::Confirmed);
    assert_eq!(fixture.adapter.invocations.load(Ordering::SeqCst), 1);

    let record = connect_journal().get(key).unwrap().unwrap();
    assert_eq!(
        record.authorization,
        praetore_gateway::AuthorizationStatus::RequiresApproval
    );
    assert_eq!(record.execution, ExecutionStatus::Confirmed);
    assert_eq!(record.human_approval, Some(decision.clone()));
    assert_eq!(database_invocation_count(key), 1);
    assert_eq!(database_effect_count(key), 1);
    assert!(
        connect_client()
            .execute(
                "UPDATE praetore.human_approvals SET outcome = 'reject' \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .is_err()
    );
    assert!(fixture.gateway.resolve_human_approval(decision).is_err());
    assert_eq!(fixture.adapter.invocations.load(Ordering::SeqCst), 1);
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
                tenant_id: TEST_TENANT_ID,
                agent_id: *authorized_evidence.agent.id.as_uuid(),
                request_id: authorized_evidence.request_id,
            };
            let journal = connect_journal();

            let dispatching_fixture =
                create_postgres_gateway(Uuid::parse_str(DISPATCHING_REQUEST).unwrap());
            let dispatching_evidence =
                evaluate_and_commit(&dispatching_fixture, dispatching_fixture.request.clone());
            let dispatching_key = ExecutionKey {
                tenant_id: TEST_TENANT_ID,
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
                tenant_id: TEST_TENANT_ID,
                agent_id: database_agent_for_request(authorized_request),
                request_id: authorized_request,
            };
            let dispatching_key = ExecutionKey {
                tenant_id: TEST_TENANT_ID,
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

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_approval_expiration_is_signed_unique_exclusive_and_append_only() {
    let clock = SharedClock::at_test_now();
    let fixture = create_postgres_approval_gateway_with_clock(Uuid::new_v4(), Some(clock.clone()));
    let pending = fixture.gateway.execute(fixture.request).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let challenge = fixture.gateway.approval_challenge(key).unwrap();
    let mut late = HumanApprovalDecision {
        schema_version: 1,
        approval_id: Uuid::new_v4(),
        approver_key_id: "postgres-human-approver-v1".into(),
        challenge,
        outcome: HumanApprovalOutcome::Approve,
        signature: String::new(),
    };
    late.signature = hex::encode(
        fixture
            .approver_key
            .sign(&late.signing_message().unwrap())
            .to_bytes(),
    );
    *clock.0.lock().unwrap() += Duration::seconds(21);

    assert_eq!(
        fixture.gateway.approval_resolution(key).unwrap(),
        praetore_gateway::ApprovalResolution::Expired
    );
    assert!(
        fixture
            .gateway
            .resolve_human_approval(late.clone())
            .is_err()
    );
    assert!(fixture.gateway.approval_challenge(key).is_err());
    assert_eq!(
        fixture.gateway.approval_resolution(key).unwrap(),
        praetore_gateway::ApprovalResolution::Expired
    );

    let record = connect_journal().get(key).unwrap().unwrap();
    let receipt = record
        .approval_expiration
        .clone()
        .expect("expiration receipt");
    receipt
        .verify(
            &record.evidence,
            &execution_attester_public_key(),
            "postgres-test-execution-attester-v1",
        )
        .unwrap();
    assert!(record.human_approval.is_none());
    assert_eq!(record.execution, ExecutionStatus::NotDispatched);
    assert_eq!(fixture.adapter.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        database_rows_for_request("praetore.human_approval_expirations", key.request_id),
        1
    );

    // Idempotent re-record keeps the first receipt; a late human decision is
    // refused by the journal and by the database trigger.
    connect_journal()
        .record_approval_expiration(key, &receipt)
        .unwrap();
    assert!(matches!(
        connect_journal().record_human_approval(key, &late, clock.now()),
        Err(JournalError::ApprovalAlreadyRecorded)
    ));
    let mut admin = connect_client();
    assert!(
        admin
            .execute(
                "INSERT INTO praetore.human_approvals \
                     (approval_id, tenant_id, agent_id, request_id, evidence_id, evidence_hash, \
                      action_digest, policy_digest, outcome, approver_key_id, expires_at, \
                      decision_json) \
                 SELECT $1, tenant_id, agent_id, request_id, evidence_id, evidence_hash, \
                      action_digest, policy_digest, 'approve', 'x', expires_at, receipt_json \
                 FROM praetore.human_approval_expirations \
                 WHERE tenant_id = $2 AND agent_id = $3 AND request_id = $4",
                &[
                    &Uuid::new_v4(),
                    &key.tenant_id,
                    &key.agent_id,
                    &key.request_id
                ],
            )
            .is_err()
    );
    for statement in [
        "UPDATE praetore.human_approval_expirations SET gateway_key_id = 'x' \
         WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
        "DELETE FROM praetore.human_approval_expirations \
         WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
    ] {
        assert!(
            admin
                .execute(statement, &[&key.tenant_id, &key.agent_id, &key.request_id])
                .is_err(),
            "{statement}"
        );
    }
    assert!(
        admin
            .batch_execute("TRUNCATE praetore.human_approval_expirations")
            .is_err()
    );

    assert_eq!(
        receipt.receipt_id,
        connect_journal()
            .get(key)
            .unwrap()
            .unwrap()
            .approval_expiration
            .unwrap()
            .receipt_id
    );

    // Row-level security: the least-privilege role sees the row only under
    // its own tenant context.
    let mut client = connect_journal_client();
    let count = |client: &mut Client, tenant: Uuid| -> i64 {
        let mut transaction = client.transaction().unwrap();
        transaction
            .execute(
                "SELECT set_config('praetore.tenant_id', $1, true)",
                &[&tenant.to_string()],
            )
            .unwrap();
        let rows: i64 = transaction
            .query_one(
                "SELECT count(*) FROM praetore.human_approval_expirations \
                 WHERE agent_id = $1 AND request_id = $2",
                &[&key.agent_id, &key.request_id],
            )
            .unwrap()
            .get(0);
        transaction.commit().unwrap();
        rows
    };
    assert_eq!(count(&mut client, TEST_TENANT_ID), 1);
    assert_eq!(count(&mut client, Uuid::from_u128(2)), 0);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_journal_row_with_expiration_receipt_cannot_be_deleted() {
    let clock = SharedClock::at_test_now();
    let fixture = create_postgres_approval_gateway_with_clock(Uuid::new_v4(), Some(clock.clone()));
    let pending = fixture.gateway.execute(fixture.request).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    *clock.0.lock().unwrap() += Duration::seconds(21);
    assert_eq!(
        fixture.gateway.approval_resolution(key).unwrap(),
        praetore_gateway::ApprovalResolution::Expired
    );

    // RESTRICT semantics without a FK (0009 trigger): blocked even for the
    // owner role, and before any FK check from other tables runs.
    let error = connect_client()
        .execute(
            "DELETE FROM praetore.execution_journal \
             WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
            &[&key.tenant_id, &key.agent_id, &key.request_id],
        )
        .expect_err("journal delete must be blocked");
    assert!(
        error.as_db_error().is_some_and(|db| db
            .message()
            .contains("referenced by an approval expiration")),
        "{error:?}"
    );
    assert_eq!(database_journal_count(key), 1);
    assert_eq!(
        database_rows_for_request("praetore.human_approval_expirations", key.request_id),
        1
    );
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_concurrent_expiration_detection_records_exactly_one_receipt() {
    for _ in 0..20 {
        let clock = SharedClock::at_test_now();
        let fixture =
            create_postgres_approval_gateway_with_clock(Uuid::new_v4(), Some(clock.clone()));
        let pending = fixture.gateway.execute(fixture.request).unwrap();
        let key = ExecutionKey {
            tenant_id: TEST_TENANT_ID,
            agent_id: *pending.evidence.agent.id.as_uuid(),
            request_id: pending.evidence.request_id,
        };
        *clock.0.lock().unwrap() += Duration::seconds(21);
        // Two gateways, each with its own journal connection, same database.
        let second = Gateway::new(
            fixture.engine.clone(),
            Arc::new(connect_journal()),
            fixture.adapter.clone(),
            execution_attester(),
        )
        .unwrap();
        let gateways = [fixture.gateway.clone(), second];
        let barrier = Arc::new(std::sync::Barrier::new(gateways.len()));
        let results: Vec<_> = gateways
            .into_iter()
            .map(|gateway| {
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    gateway.approval_resolution(key)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        for result in &results {
            assert_eq!(
                result.as_ref().ok(),
                Some(&praetore_gateway::ApprovalResolution::Expired),
                "{results:?}"
            );
        }
        assert_eq!(
            database_rows_for_request("praetore.human_approval_expirations", key.request_id),
            1
        );
        let record = connect_journal().get(key).unwrap().unwrap();
        record
            .approval_expiration
            .expect("one receipt")
            .verify(
                &record.evidence,
                &execution_attester_public_key(),
                "postgres-test-execution-attester-v1",
            )
            .unwrap();
        assert_eq!(record.execution, ExecutionStatus::NotDispatched);
        assert_eq!(fixture.adapter.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(database_invocation_count(key), 0);
    }
}

// ---------------------------------------------------------------------------
// approved_pending_dispatch (APD)
// ---------------------------------------------------------------------------

const APD_CHECKS: [(&str, &str); 6] = [
    (
        "praetore.execution_journal",
        "execution_journal_execution_status_v2",
    ),
    (
        "praetore.execution_journal",
        "execution_journal_authorization_execution_v2",
    ),
    (
        "praetore.execution_journal",
        "execution_journal_not_dispatched_reason_v2",
    ),
    (
        "praetore.execution_journal_events",
        "execution_journal_events_to_status_v2",
    ),
    (
        "praetore.execution_journal_events",
        "execution_journal_events_from_status_v2",
    ),
    (
        "praetore.execution_attestations",
        "execution_attestations_not_dispatched_reason_v2",
    ),
];

/// Fails unless every CHECK added by 0010 (reason CHECKs as replaced by
/// 0013) exists, the replaced constraints are gone, and only the latest
/// (0013, v3) transition trigger is installed.
fn assert_0010_schema_present(client: &mut Client) {
    for (table, name) in APD_CHECKS {
        let found: i64 = client
            .query_one(
                "SELECT count(*) FROM pg_constraint \
                 WHERE conrelid = $1::text::regclass AND conname = $2 AND contype = 'c'",
                &[&table, &name],
            )
            .unwrap()
            .get(0);
        assert_eq!(found, 1, "CHECK {name} on {table} must be present");
    }
    for (table, name) in [
        (
            "praetore.execution_journal",
            "execution_journal_execution_status_check",
        ),
        (
            "praetore.execution_journal",
            "execution_journal_authorization_execution_check",
        ),
        (
            "praetore.execution_attestations",
            "execution_attestations_identity_status_key",
        ),
        // Replaced by 0013.
        (
            "praetore.execution_journal",
            "execution_journal_not_dispatched_reason_v1",
        ),
        (
            "praetore.execution_attestations",
            "execution_attestations_not_dispatched_reason_v1",
        ),
    ] {
        let found: i64 = client
            .query_one(
                "SELECT count(*) FROM pg_constraint \
                 WHERE conrelid = $1::text::regclass AND conname = $2",
                &[&table, &name],
            )
            .unwrap()
            .get(0);
        assert_eq!(found, 0, "{name} must stay dropped");
    }
    let triggers: Vec<String> = client
        .query(
            "SELECT tgname::text FROM pg_trigger \
             WHERE tgrelid = 'praetore.execution_journal'::regclass \
               AND tgname LIKE 'execution_journal_transition%' ORDER BY 1",
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(triggers, vec!["execution_journal_transition_v3".to_owned()]);
    let recorded: i64 = client
        .query_one("SELECT count(*) FROM praetore.schema_migrations", &[])
        .unwrap()
        .get(0);
    assert_eq!(recorded, praetore_replay_postgres::MIGRATIONS.len() as i64);
}

fn sign_approval(fixture: &PostgresApprovalFixture, key: ExecutionKey) -> HumanApprovalDecision {
    let mut decision = HumanApprovalDecision {
        schema_version: 1,
        approval_id: Uuid::new_v4(),
        approver_key_id: "postgres-human-approver-v1".into(),
        challenge: fixture.gateway.approval_challenge(key).unwrap(),
        outcome: HumanApprovalOutcome::Approve,
        signature: String::new(),
    };
    decision.signature = hex::encode(
        fixture
            .approver_key
            .sign(&decision.signing_message().unwrap())
            .to_bytes(),
    );
    decision
}

/// Executes the fixture request (held for approval) and approves it, leaving
/// the row in `approved_pending_dispatch`.
fn approved_pending(fixture: &PostgresApprovalFixture) -> ExecutionKey {
    let pending = fixture.gateway.execute(fixture.request.clone()).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let decision = sign_approval(fixture, key);
    assert!(matches!(
        fixture.gateway.resolve_human_approval(decision).unwrap(),
        HumanApprovalResult::ApprovedPendingDispatch { .. }
    ));
    assert_eq!(
        connect_journal().get(key).unwrap().unwrap().execution,
        ExecutionStatus::ApprovedPendingDispatch
    );
    key
}

fn database_transitions(key: ExecutionKey) -> Vec<(Option<String>, String)> {
    connect_client()
        .query(
            "SELECT from_status, to_status FROM praetore.execution_journal_events \
             WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3 ORDER BY event_id",
            &[&key.tenant_id, &key.agent_id, &key.request_id],
        )
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect()
}

fn database_not_dispatched_reason(key: ExecutionKey) -> Option<String> {
    connect_client()
        .query_one(
            "SELECT not_dispatched_reason FROM praetore.execution_journal \
             WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
            &[&key.tenant_id, &key.agent_id, &key.request_id],
        )
        .unwrap()
        .get(0)
}

/// A second gateway with its own journal connection and adapter, sharing only
/// the engine configuration (as two instances of one deployment would).
fn second_gateway(fixture: &PostgresApprovalFixture) -> (Gateway, Arc<PostgresTestAdapter>) {
    let adapter = Arc::new(PostgresTestAdapter::new(None));
    let gateway = Gateway::new(
        fixture.engine.clone(),
        Arc::new(connect_journal()),
        adapter.clone(),
        execution_attester(),
    )
    .unwrap()
    .with_human_approval_verifier(
        HumanApprovalVerifier::new(
            "postgres-human-approver-v1",
            VerifiedPublicKey::from_bytes(&fixture.approver_key.verifying_key().to_bytes())
                .unwrap(),
        )
        .unwrap(),
    );
    (gateway, adapter)
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_migrations_apply_once_and_keep_0010_checks() {
    initialize_test_database();
    let mut client = connect_client();
    for _ in 0..2 {
        assert!(
            praetore_replay_postgres::apply_migrations(&mut client)
                .unwrap()
                .is_empty()
        );
    }
    assert_0010_schema_present(&mut client);
    // A new connection is what a restarted process uses.
    let mut client = connect_client();
    assert!(
        praetore_replay_postgres::apply_migrations(&mut client)
            .unwrap()
            .is_empty()
    );
    assert_0010_schema_present(&mut client);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_apd_crash_between_approve_and_claim_closes_as_crash_recovered() {
    let fixture = create_postgres_approval_gateway(Uuid::new_v4());
    let key = approved_pending(&fixture);
    let decision = connect_journal()
        .get(key)
        .unwrap()
        .unwrap()
        .human_approval
        .unwrap();
    // Crash: the approving gateway disappears before claiming. Nothing but the
    // database row survives it.
    let (recovering, adapter) = second_gateway(&fixture);
    drop(fixture.gateway);

    let receipt = recovering.reconcile(key).unwrap();
    assert_eq!(receipt.execution, ExecutionStatus::NotDispatched);
    assert_ne!(receipt.execution, ExecutionStatus::OutcomeUnknown);
    assert_eq!(
        receipt.execution_attestation.not_dispatched_reason,
        Some(NotDispatchedReason::CrashRecovered)
    );
    assert_eq!(receipt.execution_attestation.schema_version, 3);
    receipt
        .verify_with_test_evidence_attester(
            &execution_attester_public_key(),
            "postgres-test-execution-attester-v1",
        )
        .unwrap();
    // Proven not dispatched: the adapter was never invoked by anyone and the
    // journal never entered `dispatched`.
    assert_eq!(fixture.adapter.invocation_count(), 0);
    assert_eq!(adapter.invocation_count(), 0);
    assert_eq!(database_invocation_count(key), 0);
    assert_eq!(database_effect_count(key), 0);
    assert_eq!(
        database_transitions(key),
        vec![
            (None, "not_dispatched".to_owned()),
            (
                Some("not_dispatched".to_owned()),
                "approved_pending_dispatch".to_owned()
            ),
            (
                Some("approved_pending_dispatch".to_owned()),
                "not_dispatched".to_owned()
            ),
        ]
    );
    assert_eq!(
        database_not_dispatched_reason(key).as_deref(),
        Some("crash_recovered")
    );
    let record = connect_journal().get(key).unwrap().unwrap();
    assert_eq!(record.execution, ExecutionStatus::NotDispatched);
    assert_eq!(
        record.execution_attestation.unwrap().not_dispatched_reason,
        Some(NotDispatchedReason::CrashRecovered)
    );
    // Reconcile is idempotent and still never dispatches.
    let again = recovering.reconcile(key).unwrap();
    assert_eq!(again.execution, ExecutionStatus::NotDispatched);
    // No re-dispatch after a crash: the old approval cannot be claimed or
    // replayed; only a new request can run the action.
    assert!(matches!(
        recovering.dispatch_approved(key),
        Err(GatewayError::Approval(
            praetore_gateway::ApprovalError::NotPending
        ))
    ));
    assert!(matches!(
        connect_journal().claim_dispatch(key, test_now()),
        Err(JournalError::InvalidTransition)
    ));
    assert!(recovering.resolve_human_approval(decision).is_err());
    assert!(recovering.approval_challenge(key).is_err());
    assert_eq!(database_invocation_count(key), 0);
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_apd_concurrent_claims_dispatch_exactly_once() {
    let races: usize = env::var("PRAETORE_APD_RACES")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|races| (1..=10_000).contains(races))
        .unwrap_or(100);
    let mut lost_with_invalid_transition = 0;
    for race in 0..races {
        let fixture = create_postgres_approval_gateway(Uuid::new_v4());
        let key = approved_pending(&fixture);
        let (other, other_adapter) = second_gateway(&fixture);
        let gateways = [&fixture.gateway, &other];
        let barrier = std::sync::Barrier::new(2);
        let results: Vec<Result<praetore_gateway::GatewayReceipt, GatewayError>> =
            thread::scope(|scope| {
                let handles: Vec<_> = gateways
                    .iter()
                    .map(|gateway| {
                        let barrier = &barrier;
                        scope.spawn(move || {
                            let pending = gateway.pending_dispatch(key)?;
                            barrier.wait();
                            let permit = gateway.claim_dispatch(pending)?;
                            gateway.dispatch(permit)
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
        let winners = results.iter().filter(|result| result.is_ok()).count();
        assert_eq!(winners, 1, "race {race}: exactly one claim must win");
        for result in &results {
            if let Err(error) = result {
                assert!(
                    matches!(
                        error,
                        GatewayError::Journal(JournalError::InvalidTransition)
                    ),
                    "race {race}: loser must fail the CAS, got {error:?}"
                );
                lost_with_invalid_transition += 1;
            }
        }
        assert_eq!(
            fixture.adapter.invocation_count() + other_adapter.invocation_count(),
            1,
            "race {race}"
        );
        assert_eq!(database_invocation_count(key), 1, "race {race}");
        assert_eq!(database_effect_count(key), 1, "race {race}");
        assert_eq!(
            connect_journal().get(key).unwrap().unwrap().execution,
            ExecutionStatus::Confirmed
        );
    }
    assert_eq!(lost_with_invalid_transition, races);
    println!("APD claim races: {races} run, {races} with exactly one dispatch");
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_apd_expiry_before_claim_closes_as_approval_expired() {
    let clock = SharedClock::at_test_now();
    let fixture = create_postgres_approval_gateway_with_clock(Uuid::new_v4(), Some(clock.clone()));
    let key = approved_pending(&fixture);
    // The engine clock passes the 20 s window.
    *clock.0.lock().unwrap() += Duration::seconds(25);
    assert_eq!(clock.now(), test_now() + Duration::seconds(25));

    assert!(matches!(
        fixture.gateway.dispatch_approved(key),
        Err(GatewayError::Approval(
            praetore_gateway::ApprovalError::Expired
        ))
    ));
    assert_eq!(fixture.adapter.invocation_count(), 0);
    assert_eq!(database_invocation_count(key), 0);
    let record = connect_journal().get(key).unwrap().unwrap();
    assert_eq!(record.execution, ExecutionStatus::NotDispatched);
    // Decision exists, so no ApprovalExpiredReceipt: the signed attestation
    // with its reason is the only record of the lapse.
    assert!(record.approval_expiration.is_none());
    assert!(record.human_approval.is_some());
    let attestation = record.execution_attestation.unwrap();
    assert_eq!(
        attestation.not_dispatched_reason,
        Some(NotDispatchedReason::ApprovalExpired)
    );
    assert_eq!(
        database_not_dispatched_reason(key).as_deref(),
        Some("approval_expired")
    );
    assert!(
        !database_transitions(key)
            .iter()
            .any(|(_, to)| to == "dispatched")
    );
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_apd_journal_checks_use_the_injected_clock() {
    let fixture = create_postgres_approval_gateway(Uuid::new_v4());
    let pending = fixture.gateway.execute(fixture.request.clone()).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let decision = sign_approval(&fixture, key);
    let expires_at = OffsetDateTime::parse(
        &decision.challenge.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    // The fixture runs at the fixed TEST_NOW (host time is irrelevant): the
    // journal must decide only from the time it is given.
    let journal = connect_journal();
    assert!(matches!(
        journal.record_human_approval(key, &decision, expires_at),
        Err(JournalError::InvalidRecord)
    ));
    assert_eq!(
        journal.get(key).unwrap().unwrap().execution,
        ExecutionStatus::NotDispatched
    );
    // An injected clock before expiry accepts it, even far in the past.
    journal
        .record_human_approval(key, &decision, expires_at - Duration::days(30))
        .unwrap();
    assert_eq!(
        journal.get(key).unwrap().unwrap().execution,
        ExecutionStatus::ApprovedPendingDispatch
    );
    // claim_dispatch revalidates under the lock with the injected clock too.
    assert!(matches!(
        journal.claim_dispatch(key, expires_at),
        Err(JournalError::ApprovalExpired)
    ));
    assert_eq!(
        journal.get(key).unwrap().unwrap().execution,
        ExecutionStatus::ApprovedPendingDispatch
    );
    journal
        .claim_dispatch(key, expires_at - Duration::seconds(1))
        .unwrap();
    assert!(matches!(
        journal.claim_dispatch(key, expires_at - Duration::seconds(1)),
        Err(JournalError::InvalidTransition)
    ));
    assert_eq!(
        journal.get(key).unwrap().unwrap().execution,
        ExecutionStatus::Dispatched
    );
    assert_eq!(database_invocation_count(key), 0);
}

fn admin_update(client: &mut Client, key: ExecutionKey, set: &str) -> Result<u64, postgres::Error> {
    let mut transaction = client.transaction().unwrap();
    transaction
        .query_one(
            "SELECT set_config('praetore.tenant_id', $1, true)",
            &[&key.tenant_id.to_string()],
        )
        .unwrap();
    let changed = transaction.execute(
        &format!(
            "UPDATE praetore.execution_journal SET {set} \
             WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3"
        ),
        &[&key.tenant_id, &key.agent_id, &key.request_id],
    )?;
    transaction.commit()?;
    Ok(changed)
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_apd_illegal_transitions_are_rejected_by_sql() {
    let mut admin = connect_client();

    // Not approved: cannot enter APD, cannot go straight to dispatched.
    let fixture = create_postgres_approval_gateway(Uuid::new_v4());
    let pending = fixture.gateway.execute(fixture.request.clone()).unwrap();
    let unapproved = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    for set in [
        "execution_status = 'approved_pending_dispatch'",
        "execution_status = 'dispatched'",
        "not_dispatched_reason = 'crash_recovered'",
    ] {
        assert!(
            admin_update(&mut admin, unapproved, set).is_err(),
            "unapproved row accepted: {set}"
        );
    }

    // Approved (APD): only claim or close-with-reason are legal.
    let fixture = create_postgres_approval_gateway(Uuid::new_v4());
    let key = approved_pending(&fixture);
    for set in [
        "execution_status = 'executed', output_json = '{}'",
        "execution_status = 'confirmed', output_json = '{}'",
        "execution_status = 'failed'",
        "execution_status = 'outcome_unknown'",
        "execution_status = 'not_dispatched'",
        "execution_status = 'not_dispatched', not_dispatched_reason = 'bogus'",
        "execution_status = 'dispatched', not_dispatched_reason = 'crash_recovered'",
        "authorization_status = 'allowed'",
    ] {
        assert!(
            admin_update(&mut admin, key, set).is_err(),
            "APD row accepted: {set}"
        );
    }

    // A row that already had its approval and was closed can never return
    // to APD (CTO decision 6), nor be dispatched (decision 7), nor lose or
    // change its reason.
    let (recovering, _) = second_gateway(&fixture);
    recovering.reconcile(key).unwrap();
    for set in [
        "execution_status = 'approved_pending_dispatch'",
        "execution_status = 'approved_pending_dispatch', not_dispatched_reason = NULL",
        "not_dispatched_reason = NULL",
        "not_dispatched_reason = 'approval_expired'",
        "execution_status = 'dispatched'",
        "execution_status = 'dispatched', not_dispatched_reason = NULL",
    ] {
        assert!(
            admin_update(&mut admin, key, set).is_err(),
            "closed row accepted: {set}"
        );
    }
    assert_eq!(
        database_not_dispatched_reason(key).as_deref(),
        Some("crash_recovered")
    );

    // APD is never valid for an allowed (or denied) authorization.
    let allowed = create_postgres_gateway(Uuid::new_v4());
    let evidence = evaluate_and_commit(&allowed, allowed.request.clone());
    let allowed_key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *evidence.agent.id.as_uuid(),
        request_id: evidence.request_id,
    };
    assert!(
        admin_update(
            &mut admin,
            allowed_key,
            "execution_status = 'approved_pending_dispatch'"
        )
        .is_err()
    );

    // parse_record refuses an APD row without an approve decision even if
    // triggers were bypassed (superuser-only replication role).
    admin
        .batch_execute("SET session_replication_role = replica")
        .unwrap();
    admin_update(
        &mut admin,
        unapproved,
        "execution_status = 'approved_pending_dispatch'",
    )
    .unwrap();
    assert!(matches!(
        connect_journal().get(unapproved),
        Err(JournalError::InvalidRecord)
    ));
    admin_update(
        &mut admin,
        unapproved,
        "execution_status = 'not_dispatched'",
    )
    .unwrap();
    admin
        .batch_execute("SET session_replication_role = origin")
        .unwrap();
    assert_eq!(
        connect_journal()
            .get(unapproved)
            .unwrap()
            .unwrap()
            .execution,
        ExecutionStatus::NotDispatched
    );
}

/// Run in two phases around a PostgreSQL restart:
/// `PRAETORE_TEST_APD_RESTART_PHASE=before`, restart the server, then
/// `PRAETORE_TEST_APD_RESTART_PHASE=after`.
#[test]
#[ignore = "requires a PostgreSQL server restart between before and after phases"]
fn postgres_apd_and_migrations_survive_restart() {
    const APD_REQUEST: &str = "00000000-0000-0000-0000-000000000301";
    let request_id = Uuid::parse_str(APD_REQUEST).unwrap();
    let phase = env::var("PRAETORE_TEST_APD_RESTART_PHASE")
        .expect("set PRAETORE_TEST_APD_RESTART_PHASE=before or after");
    match phase.as_str() {
        "before" => {
            initialize_test_database();
            clear_journal_restart_fixtures(&[request_id]);
            let mut client = connect_client();
            assert!(
                praetore_replay_postgres::apply_migrations(&mut client)
                    .unwrap()
                    .is_empty()
            );
            assert_0010_schema_present(&mut client);
            let fixture = create_postgres_approval_gateway(request_id);
            let key = approved_pending(&fixture);
            assert_eq!(database_invocation_count(key), 0);
        }
        "after" => {
            // A restarted process runs the migrations again: nothing is
            // reapplied and the 0010 CHECKs are intact.
            let mut client = connect_client();
            assert!(
                praetore_replay_postgres::apply_migrations(&mut client)
                    .unwrap()
                    .is_empty()
            );
            assert_0010_schema_present(&mut client);
            let key = ExecutionKey {
                tenant_id: TEST_TENANT_ID,
                agent_id: database_agent_for_request(request_id),
                request_id,
            };
            assert_eq!(
                connect_journal().get(key).unwrap().unwrap().execution,
                ExecutionStatus::ApprovedPendingDispatch
            );
            let fixture = create_postgres_approval_gateway(Uuid::new_v4());
            let (recovering, adapter) = second_gateway(&fixture);
            let receipt = recovering.reconcile(key).unwrap();
            assert_eq!(receipt.execution, ExecutionStatus::NotDispatched);
            assert_eq!(
                receipt.execution_attestation.not_dispatched_reason,
                Some(NotDispatchedReason::CrashRecovered)
            );
            assert_eq!(adapter.invocation_count(), 0);
            assert_eq!(database_invocation_count(key), 0);
            assert_eq!(database_effect_count(key), 0);
            clear_journal_restart_fixtures(&[request_id]);
        }
        _ => panic!("PRAETORE_TEST_APD_RESTART_PHASE must be before or after"),
    }
}

/// A throwaway database on the test server, dropped on `Drop`.
struct ScratchDatabase {
    name: String,
}

impl ScratchDatabase {
    fn create() -> Self {
        let name = format!("praetore_mig_{}", Uuid::new_v4().simple());
        connect_client()
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .expect("create scratch database");
        Self { name }
    }

    fn connect(&self) -> Client {
        let url = env::var("PRAETORE_TEST_DATABASE_URL").unwrap();
        let mut config: postgres::Config = url.parse().unwrap();
        config.dbname(&self.name);
        config.connect(NoTls).expect("connect to scratch database")
    }
}

impl ScratchDatabase {
    /// `PRAETORE_TEST_DATABASE_URL` with this database's name.
    fn url(&self) -> String {
        let url = env::var("PRAETORE_TEST_DATABASE_URL").unwrap();
        let (base, query) = url
            .split_once('?')
            .map_or((url.as_str(), ""), |(base, query)| (base, query));
        let (prefix, _) = base.rsplit_once('/').unwrap();
        if query.is_empty() {
            format!("{prefix}/{}", self.name)
        } else {
            format!("{prefix}/{}?{query}", self.name)
        }
    }
}

const OWN_DATABASE_CHILD_ENV: &str = "PRAETORE_TEST_OWN_DATABASE_CHILD";

/// For a test that must change the shared test database's `praetore`
/// schema: the first call (the test as listed) re-runs `test` in a child
/// process whose `PRAETORE_TEST_DATABASE_URL` is a fresh scratch database,
/// checks that it passed and returns false; in the child it returns true,
/// and the test body runs there.
fn in_own_scratch_database(test: &str) -> bool {
    if env::var_os(OWN_DATABASE_CHILD_ENV).is_some() {
        return true;
    }
    let scratch = ScratchDatabase::create();
    let output = helper_process(test)
        .env(OWN_DATABASE_CHILD_ENV, "1")
        .env("PRAETORE_TEST_DATABASE_URL", scratch.url())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed"),
        "{test} in its own database failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

impl Drop for ScratchDatabase {
    fn drop(&mut self) {
        let _ = connect_client().batch_execute(&format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            self.name
        ));
    }
}

/// `apply_migrations` with the explicit legacy-baseline opt-in
/// (PRAETORE_ADOPT_LEGACY_BASELINE=1 in the binaries).
fn adopt_legacy_baseline(
    client: &mut Client,
) -> Result<Vec<&'static str>, praetore_replay_postgres::MigrationError> {
    praetore_replay_postgres::apply_migrations_with(
        client,
        &praetore_replay_postgres::MigrationOptions {
            adopt_legacy_baseline: true,
            record_signer: Some(std::sync::Arc::new(adoption_attester())),
            ..Default::default()
        },
    )
}

/// The key that signs adoption records in these tests.
fn adoption_attester() -> praetore_core::EvidenceAttesterKey {
    praetore_core::EvidenceAttesterKey::from_secret_bytes(&[42; 32])
}

/// Runs migrations the way the pre-runner code did: plain SQL, no record.
fn apply_legacy_migrations_through(client: &mut Client, last: usize) {
    for (_, sql) in &praetore_replay_postgres::MIGRATIONS[..last] {
        client.batch_execute(sql).expect("apply legacy migration");
    }
}

fn recorded_versions(client: &mut Client) -> Vec<String> {
    client
        .query(
            "SELECT version FROM praetore.schema_migrations ORDER BY version",
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

fn all_versions() -> Vec<String> {
    praetore_replay_postgres::MIGRATIONS
        .iter()
        .map(|(version, _)| (*version).to_owned())
        .collect()
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_empty_database_applies_everything_once() {
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    let applied = praetore_replay_postgres::apply_migrations(&mut client).unwrap();
    assert_eq!(applied.len(), praetore_replay_postgres::MIGRATIONS.len());
    assert!(
        praetore_replay_postgres::apply_migrations(&mut client)
            .unwrap()
            .is_empty()
    );
    assert_eq!(recorded_versions(&mut client), all_versions());
    assert_0010_schema_present(&mut client);
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_0009_database_records_without_reexecuting() {
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    apply_legacy_migrations_through(&mut client, 9);
    // 0007 drops and re-adds this FK and 0008 drops and re-creates the
    // policies on every run, so their OIDs change if 0001-0009 execute again.
    let oids = |client: &mut Client| -> (u32, Vec<u32>) {
        let fk: u32 = client
            .query_one(
                "SELECT oid FROM pg_constraint WHERE conname = 'execution_journal_replay_claim_fk'",
                &[],
            )
            .unwrap()
            .get(0);
        let policies = client
            .query(
                "SELECT p.oid FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid \
                 JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE n.nspname = 'praetore' ORDER BY c.relname",
                &[],
            )
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect();
        (fk, policies)
    };
    let before = oids(&mut client);
    let applied = adopt_legacy_baseline(&mut client).unwrap();
    assert_eq!(
        applied,
        vec![
            "0010_approved_pending_dispatch",
            "0011_runtime_role",
            "0012_dispatch_requires_live_approval",
            "0013_dispatch_refused",
            "0014_closed_execution_row_lock",
            "0015_storage_records"
        ]
    );
    assert_eq!(oids(&mut client), before, "0001-0009 must not run again");
    assert_eq!(recorded_versions(&mut client), all_versions());
    assert_0010_schema_present(&mut client);
    assert!(adopt_legacy_baseline(&mut client).unwrap().is_empty());
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_partial_schema_fails_closed() {
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    apply_legacy_migrations_through(&mut client, 5);
    let error = adopt_legacy_baseline(&mut client).unwrap_err();
    assert!(
        matches!(
            error,
            praetore_replay_postgres::MigrationError::UnrecognizedSchema(_)
        ),
        "{error}"
    );
    let control: bool = client
        .query_one(
            "SELECT to_regclass('praetore.schema_migrations') IS NOT NULL",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(!control, "a refused baseline must not record anything");
}

/// Builds a 0009 database without migration records, applies `tamper`, and
/// asserts that the runner refuses it, names `object`, and records nothing.
fn assert_tampered_baseline_refused(tamper: &str, object: &str) {
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    apply_legacy_migrations_through(&mut client, 9);
    client
        .batch_execute(tamper)
        .expect("tamper with the baseline");
    let error = adopt_legacy_baseline(&mut client)
        .expect_err(&format!("tampered baseline must be refused: {tamper}"));
    assert!(
        matches!(
            error,
            praetore_replay_postgres::MigrationError::UnrecognizedSchema(_)
                | praetore_replay_postgres::MigrationError::UnsafeDatabase(_)
        ),
        "{error}"
    );
    let message = error.to_string();
    assert!(
        message.contains(object),
        "error must name {object}: {message}"
    );
    eprintln!("refused as expected: {message}");
    let control: bool = client
        .query_one(
            "SELECT to_regclass('praetore.schema_migrations') IS NOT NULL",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(!control, "a refused baseline must not record anything");
    let not_dispatched_reason =
        column_exists(&mut client, "execution_journal", "not_dispatched_reason");
    assert!(
        !not_dispatched_reason,
        "a refused baseline must not run 0010"
    );
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_changed_function_body_fails_closed() {
    // A body that no longer rejects mutation.
    assert_tampered_baseline_refused(
        "CREATE OR REPLACE FUNCTION praetore.reject_human_approval_mutation() \
         RETURNS TRIGGER LANGUAGE plpgsql AS $$\nBEGIN\n    RETURN NEW;\nEND;\n$$;",
        "praetore.reject_human_approval_mutation()",
    );
    // The same body with one extra trailing space: no normalization.
    assert_tampered_baseline_refused(
        "CREATE OR REPLACE FUNCTION praetore.reject_execution_attestation_mutation() \
         RETURNS TRIGGER LANGUAGE plpgsql AS $$\nBEGIN\n    \
         RAISE EXCEPTION 'execution attestations are append-only';\nEND;\n $$;",
        "praetore.reject_execution_attestation_mutation()",
    );
    // A missing function (CASCADE also drops its triggers).
    assert_tampered_baseline_refused(
        "DROP FUNCTION praetore.reject_human_approval_expiration_mutation() CASCADE;",
        "function praetore.reject_human_approval_expiration_mutation() is missing",
    );
    // A different language attribute (volatility) with the same body.
    assert_tampered_baseline_refused(
        "ALTER FUNCTION praetore.enforce_approval_resolution_exclusive() STABLE;",
        "praetore.enforce_approval_resolution_exclusive()",
    );
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_changed_security_definer_fails_closed() {
    assert_tampered_baseline_refused(
        "ALTER FUNCTION praetore.record_execution_journal_transition() SECURITY INVOKER;",
        "praetore.record_execution_journal_transition()",
    );
    assert_tampered_baseline_refused(
        "ALTER FUNCTION praetore.enforce_approval_resolution_exclusive() SECURITY DEFINER;",
        "praetore.enforce_approval_resolution_exclusive()",
    );
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_changed_search_path_fails_closed() {
    assert_tampered_baseline_refused(
        "ALTER FUNCTION praetore.record_execution_journal_transition() \
         SET search_path = public, pg_catalog, praetore, pg_temp;",
        "praetore.record_execution_journal_transition()",
    );
    assert_tampered_baseline_refused(
        "ALTER FUNCTION praetore.record_execution_journal_transition() RESET search_path;",
        "praetore.record_execution_journal_transition()",
    );
    assert_tampered_baseline_refused(
        "ALTER FUNCTION praetore.validate_execution_journal_transition() \
         SET search_path = public;",
        "praetore.validate_execution_journal_transition()",
    );
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_added_overload_fails_closed() {
    assert_tampered_baseline_refused(
        "CREATE FUNCTION praetore.reject_human_approval_mutation(reason TEXT) \
         RETURNS TEXT LANGUAGE sql AS $$ SELECT reason $$;",
        "praetore.reject_human_approval_mutation(reason text)",
    );
    assert_tampered_baseline_refused(
        "CREATE FUNCTION praetore.unexpected_helper() RETURNS INTEGER \
         LANGUAGE sql AS $$ SELECT 1 $$;",
        "praetore.unexpected_helper()",
    );
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_changed_trigger_fails_closed() {
    // Same name, no longer fires on DELETE.
    assert_tampered_baseline_refused(
        "DROP TRIGGER human_approvals_immutable ON praetore.human_approvals; \
         CREATE TRIGGER human_approvals_immutable BEFORE UPDATE ON praetore.human_approvals \
         FOR EACH ROW EXECUTE FUNCTION praetore.reject_human_approval_mutation();",
        "human_approvals_immutable",
    );
    // Same events, a different (baseline) function.
    assert_tampered_baseline_refused(
        "DROP TRIGGER execution_journal_transition ON praetore.execution_journal; \
         CREATE TRIGGER execution_journal_transition BEFORE UPDATE ON praetore.execution_journal \
         FOR EACH ROW EXECUTE FUNCTION praetore.reject_human_approval_mutation();",
        "trigger execution_journal_transition on praetore.execution_journal differs from 0009 in: definition",
    );
    // A missing trigger.
    assert_tampered_baseline_refused(
        "DROP TRIGGER human_approvals_exclusive ON praetore.human_approvals;",
        "trigger human_approvals_exclusive on praetore.human_approvals is missing",
    );
    // A WHEN clause that skips the check.
    assert_tampered_baseline_refused(
        "DROP TRIGGER execution_journal_transition ON praetore.execution_journal; \
         CREATE TRIGGER execution_journal_transition BEFORE UPDATE ON praetore.execution_journal \
         FOR EACH ROW WHEN (false) \
         EXECUTE FUNCTION praetore.validate_execution_journal_transition();",
        "execution_journal_transition",
    );
    // Disabled.
    assert_tampered_baseline_refused(
        "ALTER TABLE praetore.execution_journal_events \
         DISABLE TRIGGER execution_journal_events_immutable;",
        "execution_journal_events_immutable",
    );
    // An extra trigger.
    assert_tampered_baseline_refused(
        "CREATE TRIGGER extra_trigger AFTER INSERT ON praetore.replay_claims \
         FOR EACH ROW EXECUTE FUNCTION praetore.reject_human_approval_mutation();",
        "extra_trigger",
    );
}

/// M1 (GHSA-67vm-x598-vhg3): an installation in which a praetore object is
/// bound to a function or operator outside pg_catalog and praetore is
/// refused at runtime start, whatever the session search_path.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_runtime_role_refuses_foreign_dependencies() {
    let runtime = TestRole::create("LOGIN NOBYPASSRLS");
    for (contaminate, expected) in [
        (
            "CREATE FUNCTION public.uuid_eq_any(uuid, uuid) RETURNS boolean \
               LANGUAGE sql IMMUTABLE AS 'SELECT true'; \
             CREATE OPERATOR public.= (LEFTARG = uuid, RIGHTARG = uuid, \
               PROCEDURE = public.uuid_eq_any); \
             ALTER POLICY tenant_isolation ON praetore.replay_claims \
               USING (tenant_id OPERATOR(public.=) \
                      NULLIF(pg_catalog.current_setting('praetore.tenant_id', true), '')::uuid);",
            "-> operator public.=(pg_catalog.uuid,pg_catalog.uuid)",
        ),
        (
            "CREATE FUNCTION public.fake_now() RETURNS timestamptz LANGUAGE sql \
               AS 'SELECT pg_catalog.now()'; \
             ALTER TABLE praetore.replay_claims ALTER COLUMN claimed_at \
               SET DEFAULT public.fake_now();",
            "-> function public.fake_now()",
        ),
    ] {
        let scratch = migrated_with_runtime(&runtime);
        let mut client = connect_scratch_as(&scratch, &runtime.name);
        verify_runtime_role(&mut client).expect("a clean installation is accepted");
        scratch.connect().batch_execute(contaminate).unwrap();
        let error =
            verify_runtime_role(&mut client).expect_err("a foreign dependency must be refused");
        let message = error.to_string();
        assert!(message.contains(expected), "{message}");
        eprintln!("refused as expected: {message}");
    }
}

/// The praetore_observe grant documented in docs/observability-mvp.md is
/// enough for the reader's list(), and passes the runtime role check.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_documented_observe_grant_supports_list() {
    const DOC: &str = include_str!("../../../docs/observability-mvp.md");
    let start = DOC
        .find("CREATE ROLE praetore_observe LOGIN;")
        .expect("documented grant");
    let block = &DOC[start..];
    let grant = &block[..block.find("```").expect("end of the SQL block")];
    let scratch = ScratchDatabase::create();
    let mut admin = scratch.connect();
    praetore_replay_postgres::apply_migrations(&mut admin).unwrap();
    // The documented role name: the runtime check accepts this grant shape
    // only for praetore_observe.
    ensure_test_role(&mut admin, "praetore_observe", "LOGIN NOBYPASSRLS");
    let statements = grant.replace("CREATE ROLE praetore_observe LOGIN;", "");
    admin.batch_execute(&statements).unwrap();
    let mut client = connect_scratch_as(&scratch, "praetore_observe");
    verify_runtime_role(&mut client)
        .expect("the documented observe role passes the runtime role check");
    let reader =
        praetore_replay_postgres::PostgresObservabilityReader::from_client(client).expect("reader");
    let filters = praetore_replay_postgres::ExecutionFilters {
        tenant_id: Some(TEST_TENANT_ID),
        limit: 10,
        ..Default::default()
    };
    let page = reader
        .list(&filters)
        .expect("list() works with the documented grant");
    eprintln!(
        "list() with the documented grant: {} executions",
        page.total
    );
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_changed_policy_fails_closed() {
    assert_tampered_baseline_refused(
        "ALTER POLICY tenant_isolation ON praetore.human_approvals USING (true);",
        "human_approvals.tenant_isolation",
    );
    assert_tampered_baseline_refused(
        "ALTER POLICY tenant_isolation ON praetore.execution_journal \
         WITH CHECK (tenant_id IS NOT NULL);",
        "execution_journal.tenant_isolation",
    );
    // An extra permissive policy widens access even when the original stays.
    assert_tampered_baseline_refused(
        "CREATE POLICY open_read ON praetore.replay_claims FOR SELECT USING (true);",
        "replay_claims.open_read",
    );
    assert_tampered_baseline_refused(
        "ALTER POLICY tenant_isolation ON praetore.execution_attestations TO pg_monitor;",
        "execution_attestations.tenant_isolation",
    );
}

/// A cluster-wide role for one test, dropped (after the scratch databases
/// that reference it) when the guard goes out of scope.
struct TestRole {
    name: String,
}

impl TestRole {
    fn create(options: &str) -> Self {
        let name = format!("t015_{}", Uuid::new_v4().simple());
        connect_client()
            .batch_execute(&format!(
                "CREATE ROLE {name} {options} PASSWORD '{TEST_ROLE_PASSWORD}'"
            ))
            .expect("create test role");
        Self { name }
    }
}

impl Drop for TestRole {
    fn drop(&mut self) {
        // DROP OWNED also revokes grants on shared objects such as
        // configuration parameters (GRANT SET ON PARAMETER).
        let _ = connect_client().batch_execute(&format!(
            "DROP OWNED BY {name}; DROP ROLE IF EXISTS {name}",
            name = self.name
        ));
    }
}

/// Runs `statement` with the scratch database's name in place of `{db}`.
fn for_current_database(statement: &str) -> String {
    format!(
        "DO $do$ BEGIN EXECUTE pg_catalog.replace($sql${statement}$sql$, '{{db}}', \
         pg_catalog.quote_ident(pg_catalog.current_database())); END $do$;"
    )
}

/// A1: a `public.pg_proc` view that shows the original bodies, picked up
/// through the session's or the database's search_path.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_catalog_shadowing_via_search_path_fails_closed() {
    let shadow = "CREATE TABLE public.pristine AS \
          SELECT oid AS poid, prosrc FROM pg_catalog.pg_proc \
          WHERE pronamespace = 'praetore'::regnamespace; \
        CREATE OR REPLACE FUNCTION praetore.reject_human_approval_mutation() \
          RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$; \
        CREATE OR REPLACE FUNCTION praetore.validate_execution_journal_transition() \
          RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$; \
        CREATE VIEW public.pg_proc AS \
          SELECT p.oid, p.proname, p.pronamespace, p.prolang, p.prorettype, p.prosecdef, \
                 p.proconfig, p.provolatile, p.proparallel, p.prokind, p.proisstrict, \
                 p.proleakproof, p.proretset, COALESCE(o.prosrc, p.prosrc) AS prosrc \
          FROM pg_catalog.pg_proc p LEFT JOIN public.pristine o ON o.poid = p.oid;";
    // The caller's session search_path.
    assert_tampered_baseline_refused(
        &format!("{shadow} SET search_path = public, pg_catalog;"),
        "function praetore.reject_human_approval_mutation() differs from 0009 in: body",
    );
    // The database's search_path (the reviewer's reproduction).
    assert_tampered_baseline_refused(
        &format!(
            "{shadow} {}",
            for_current_database("ALTER DATABASE {db} SET search_path = public, pg_catalog")
        ),
        "setting search_path=public, pg_catalog for all roles",
    );
}

/// A2: tenant_isolation recreated with a `public.=` operator that is always
/// true, rendered as `=` under a search_path that puts public first.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_policy_with_shadowing_operator_fails_closed() {
    let mut tamper = "CREATE FUNCTION public.uuid_eq_any(uuid, uuid) RETURNS boolean \
           LANGUAGE sql IMMUTABLE AS 'SELECT true'; \
         CREATE OPERATOR public.= (LEFTARG = uuid, RIGHTARG = uuid, \
           PROCEDURE = public.uuid_eq_any); \
         SET search_path = public, pg_catalog;"
        .to_owned();
    for table in [
        "replay_claims",
        "execution_journal",
        "execution_journal_events",
        "execution_attestations",
        "human_approvals",
        "human_approval_expirations",
    ] {
        tamper.push_str(&format!(
            " DROP POLICY tenant_isolation ON praetore.{table}; \
              CREATE POLICY tenant_isolation ON praetore.{table} \
                USING (tenant_id = NULLIF(current_setting('praetore.tenant_id', true), '')::UUID) \
                WITH CHECK (tenant_id = NULLIF(current_setting('praetore.tenant_id', true), '')::UUID);"
        ));
    }
    assert_tampered_baseline_refused(
        &tamper,
        "policy praetore.execution_attestations.tenant_isolation differs from 0009 in: USING, WITH CHECK",
    );
}

/// A3: rewrite rules that copy approvals out and drop journal events.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_rewrite_rules_fail_closed() {
    assert_tampered_baseline_refused(
        "CREATE TABLE public.leak (LIKE praetore.human_approvals); \
         CREATE RULE leak_approvals AS ON INSERT TO praetore.human_approvals \
           DO ALSO INSERT INTO public.leak SELECT NEW.*;",
        "rule leak_approvals on praetore.human_approvals is not created by 0001-0009",
    );
    assert_tampered_baseline_refused(
        "CREATE RULE drop_events AS ON INSERT TO praetore.execution_journal_events \
           DO INSTEAD NOTHING;",
        "rule drop_events on praetore.execution_journal_events is not created by 0001-0009",
    );
}

/// A4: owners and ACLs of the schema, tables and functions; FORCE RLS off.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_owners_and_acls_fail_closed() {
    let mallory = TestRole::create("LOGIN");
    let m = &mallory.name;
    assert_tampered_baseline_refused(
        &format!(
            "ALTER FUNCTION praetore.enforce_approval_resolution_exclusive() OWNER TO {m}; \
             GRANT USAGE ON SCHEMA praetore TO {m};"
        ),
        "function praetore.enforce_approval_resolution_exclusive() differs from 0009 in: acl, owner",
    );
    assert_tampered_baseline_refused(
        "GRANT EXECUTE ON FUNCTION praetore.record_execution_journal_transition() TO PUBLIC;",
        "function praetore.record_execution_journal_transition() differs from 0009 in: acl",
    );
    assert_tampered_baseline_refused(
        &format!(
            "ALTER SCHEMA praetore OWNER TO {m}; GRANT ALL ON SCHEMA praetore TO CURRENT_USER;"
        ),
        &format!("schema praetore is owned by {m}"),
    );
    assert_tampered_baseline_refused(
        &format!(
            "ALTER TABLE praetore.human_approvals OWNER TO {m}; \
             GRANT USAGE ON SCHEMA praetore TO {m};"
        ),
        "relation praetore.human_approvals differs from 0009 in: acl, owner",
    );
    assert_tampered_baseline_refused(
        &format!(
            "GRANT USAGE ON SCHEMA praetore TO {m}; \
             GRANT SELECT ON ALL TABLES IN SCHEMA praetore TO {m};"
        ),
        "relation praetore.execution_attestations differs from 0009 in: acl",
    );
    assert_tampered_baseline_refused(
        "ALTER TABLE praetore.human_approvals NO FORCE ROW LEVEL SECURITY;",
        "relation praetore.human_approvals differs from 0009 in: force row security",
    );
    assert_tampered_baseline_refused(
        &format!("ALTER DEFAULT PRIVILEGES IN SCHEMA praetore GRANT SELECT ON TABLES TO {m};"),
        "default privileges of",
    );
}

/// A5: child tables attached to praetore tables, from another schema.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_inheritance_fails_closed() {
    assert_tampered_baseline_refused(
        "CREATE TABLE public.forged_approvals () INHERITS (praetore.human_approvals);",
        "inheritance public.forged_approvals of praetore.human_approvals is not created by 0001-0009",
    );
    assert_tampered_baseline_refused(
        "CREATE TABLE public.forged_events () INHERITS (praetore.execution_journal_events);",
        "inheritance public.forged_events of praetore.execution_journal_events",
    );
}

/// A6: settings that disable triggers or RLS, or change name resolution,
/// for the database or a role in it.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_trigger_disabling_settings_fail_closed() {
    let other = TestRole::create("LOGIN");
    assert_tampered_baseline_refused(
        &for_current_database("ALTER DATABASE {db} SET session_replication_role = replica"),
        "setting session_replication_role=replica for all roles",
    );
    assert_tampered_baseline_refused(
        &for_current_database(&format!(
            "ALTER ROLE {} IN DATABASE {{db}} SET session_replication_role = replica",
            other.name
        )),
        &format!(
            "setting session_replication_role=replica for {}",
            other.name
        ),
    );
    assert_tampered_baseline_refused(
        &for_current_database("ALTER DATABASE {db} SET row_security = off"),
        "setting row_security=off for all roles",
    );
}

/// A6: a migrating session without triggers is refused, fresh database or not.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_refuse_a_session_without_triggers() {
    for baseline in [false, true] {
        let scratch = ScratchDatabase::create();
        let mut client = scratch.connect();
        if baseline {
            apply_legacy_migrations_through(&mut client, 9);
        }
        client
            .batch_execute("SET session_replication_role = replica")
            .unwrap();
        let error = adopt_legacy_baseline(&mut client)
            .expect_err("a session without triggers must not migrate");
        let message = error.to_string();
        assert!(message.contains("session_replication_role"), "{message}");
        eprintln!("refused as expected: {message}");
        let control: bool = client
            .query_one(
                "SELECT pg_catalog.to_regclass('praetore.schema_migrations') IS NOT NULL",
                &[],
            )
            .unwrap()
            .get(0);
        assert!(!control, "nothing may be recorded");
    }
}

/// A6 at runtime: the gateway's runtime check refuses a session in which the
/// append-only triggers and foreign keys do not fire.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_runtime_role_refuses_session_replication_role_replica() {
    // Declared first so it is dropped after the scratch database.
    let runtime = TestRole::create("LOGIN NOBYPASSRLS");
    let scratch = ScratchDatabase::create();
    let mut admin = scratch.connect();
    praetore_replay_postgres::apply_migrations(&mut admin).unwrap();
    admin
        .batch_execute(&format!("GRANT praetore_runtime TO {}", runtime.name))
        .unwrap();
    let mut client = connect_scratch_as(&scratch, &runtime.name);
    verify_runtime_role(&mut client).expect("least-privilege runtime role is accepted");
    drop(client);
    admin
        .batch_execute(&format!(
            "ALTER ROLE {} IN DATABASE {} SET session_replication_role = replica",
            runtime.name, scratch.name
        ))
        .unwrap();
    let mut client = connect_scratch_as(&scratch, &runtime.name);
    let error = verify_runtime_role(&mut client)
        .expect_err("runtime session without triggers must be refused");
    let message = error.to_string();
    assert!(
        message.contains("session_replication_role = replica"),
        "{message}"
    );
    eprintln!("refused as expected: {message}");
}

/// M1: constraint definitions, not only names.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_changed_constraints_fail_closed() {
    assert_tampered_baseline_refused(
        "ALTER TABLE praetore.human_approvals DROP CONSTRAINT human_approvals_identity_key; \
         ALTER TABLE praetore.human_approvals ADD CONSTRAINT human_approvals_identity_key \
           UNIQUE (tenant_id, agent_id, request_id, approval_id);",
        "constraint praetore.human_approvals.human_approvals_identity_key differs from 0009 in: definition",
    );
    assert_tampered_baseline_refused(
        "ALTER TABLE praetore.human_approvals DROP CONSTRAINT human_approvals_outcome_check;",
        "constraint praetore.human_approvals.human_approvals_outcome_check is missing",
    );
    assert_tampered_baseline_refused(
        "ALTER TABLE praetore.human_approvals DROP CONSTRAINT human_approvals_journal_fk; \
         ALTER TABLE praetore.human_approvals ADD CONSTRAINT human_approvals_journal_fk \
           FOREIGN KEY (tenant_id) REFERENCES praetore.human_approvals (approval_id) NOT VALID;",
        "constraint praetore.human_approvals.human_approvals_journal_fk differs from 0009 in: definition",
    );
}

/// Lows: columns, defaults, indexes, extra tables and views, event triggers.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_columns_indexes_and_extra_objects_fail_closed() {
    for (tamper, object) in [
        (
            "ALTER TABLE praetore.execution_journal ALTER COLUMN execution_status \
               SET DEFAULT 'confirmed';",
            "column praetore.execution_journal.execution_status differs from 0009 in: default",
        ),
        (
            "ALTER TABLE praetore.human_approvals ALTER COLUMN approver_key_id TYPE VARCHAR(300);",
            "column praetore.human_approvals.approver_key_id differs from 0009 in: type",
        ),
        (
            "ALTER TABLE praetore.human_approvals ALTER COLUMN expires_at DROP NOT NULL;",
            "column praetore.human_approvals.expires_at differs from 0009 in: not null",
        ),
        (
            "ALTER TABLE praetore.human_approvals ADD COLUMN extra TEXT;",
            "column praetore.human_approvals.extra is not created by 0001-0009",
        ),
        (
            "DROP INDEX praetore.execution_journal_events_tenant_identity;",
            "relation praetore.execution_journal_events_tenant_identity is missing",
        ),
        (
            "CREATE TABLE praetore.extra_table (id INT);",
            "relation praetore.extra_table is not created by 0001-0009",
        ),
        (
            "CREATE VIEW praetore.open_view AS SELECT * FROM praetore.human_approvals;",
            "relation praetore.open_view is not created by 0001-0009",
        ),
        (
            "CREATE VIEW public.open_view AS SELECT * FROM praetore.human_approvals;",
            "dependent \"_RETURN\" on public.open_view (rule) is not created by 0001-0009",
        ),
        (
            "CREATE FUNCTION public.t015_ddl() RETURNS event_trigger LANGUAGE plpgsql \
               AS $$ BEGIN END $$; \
             CREATE EVENT TRIGGER t015_ddl ON ddl_command_end \
               EXECUTE FUNCTION public.t015_ddl();",
            "event trigger t015_ddl (ddl_command_end) exists",
        ),
    ] {
        assert_tampered_baseline_refused(tamper, object);
    }
}

/// Pre-runner deployments applied 0001-0009 on every start; that state is
/// still accepted, also when the caller's session has a hostile search_path.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_reapplied_legacy_migrations_are_accepted() {
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    apply_legacy_migrations_through(&mut client, 9);
    apply_legacy_migrations_through(&mut client, 9);
    client
        .batch_execute("SET search_path = public, pg_catalog")
        .unwrap();
    let applied = adopt_legacy_baseline(&mut client).unwrap();
    assert_eq!(
        applied.len(),
        praetore_replay_postgres::MIGRATIONS.len() - 9
    );
    let search_path: String = client.query_one("SHOW search_path", &[]).unwrap().get(0);
    assert_eq!(
        search_path, "public, pg_catalog",
        "the caller's search_path is restored"
    );
    assert_eq!(recorded_versions(&mut client), all_versions());
}

/// Moves the schema, its tables (with their indexes, sequences and row
/// types) and its functions to `role`.
fn transfer_praetore_ownership(role: &str) -> String {
    format!(
        "DO $do$ DECLARE r record; BEGIN \
           EXECUTE pg_catalog.format('ALTER SCHEMA praetore OWNER TO %I', '{role}'); \
           FOR r IN SELECT c.oid::regclass AS t FROM pg_class c \
                    JOIN pg_namespace n ON n.oid = c.relnamespace \
                    WHERE n.nspname = 'praetore' AND c.relkind = 'r' LOOP \
             EXECUTE pg_catalog.format('ALTER TABLE %s OWNER TO %I', r.t, '{role}'); \
           END LOOP; \
           FOR r IN SELECT p.oid::regprocedure AS f FROM pg_proc p \
                    JOIN pg_namespace n ON n.oid = p.pronamespace \
                    WHERE n.nspname = 'praetore' LOOP \
             EXECUTE pg_catalog.format('ALTER FUNCTION %s OWNER TO %I', r.f, '{role}'); \
           END LOOP; \
         END $do$;"
    )
}

/// A migrated scratch database and a LOGIN member of praetore_runtime.
/// `runtime` must outlive the returned database.
fn migrated_with_runtime(runtime: &TestRole) -> ScratchDatabase {
    let scratch = ScratchDatabase::create();
    let mut admin = scratch.connect();
    praetore_replay_postgres::apply_migrations(&mut admin).unwrap();
    admin
        .batch_execute(&format!("GRANT praetore_runtime TO {}", runtime.name))
        .unwrap();
    scratch
}

/// Round 2, H2: a `public.set_config` that swaps the tenant, picked up
/// through a database-level search_path. The runtime check refuses to start,
/// and the tenant context still binds the requested tenant.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_runtime_tenant_context_ignores_hostile_search_path() {
    let runtime = TestRole::create("LOGIN NOBYPASSRLS");
    let scratch = ScratchDatabase::create();
    let mut admin = scratch.connect();
    admin
        .batch_execute(
            "CREATE FUNCTION public.set_config(name text, value text, is_local boolean) \
               RETURNS text LANGUAGE sql AS $$ SELECT pg_catalog.set_config(name, \
                 CASE WHEN name = 'praetore.tenant_id' \
                      THEN '22222222-2222-2222-2222-222222222222' ELSE value END, is_local) $$;",
        )
        .unwrap();
    praetore_replay_postgres::apply_migrations(&mut admin).unwrap();
    admin
        .batch_execute(&format!(
            "GRANT praetore_runtime TO {runtime}; \
             ALTER DATABASE {db} SET search_path = public, pg_catalog",
            runtime = runtime.name,
            db = scratch.name
        ))
        .unwrap();

    let mut client = connect_scratch_as(&scratch, &runtime.name);
    let error = verify_runtime_role(&mut client)
        .expect_err("a runtime session with a hostile search_path must be refused");
    let message = error.to_string();
    assert!(
        message.contains("puts public before pg_catalog"),
        "{message}"
    );
    eprintln!("refused as expected: {message}");

    // Even when started anyway, and with the session's own search_path
    // hostile too (as ALTER SYSTEM would leave it), the claim is written
    // under the requested tenant.
    let tenant = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    let request_id = Uuid::new_v4();
    let mut client = connect_scratch_as(&scratch, &runtime.name);
    client
        .batch_execute("SET search_path = public, pg_catalog")
        .unwrap();
    let guard = PostgresReplayGuard::from_client(client);
    guard
        .claim_once(tenant, Uuid::new_v4(), request_id)
        .expect("claim under the requested tenant");
    let stored: Uuid = admin
        .query_one(
            "SELECT tenant_id FROM praetore.replay_claims WHERE request_id = $1",
            &[&request_id],
        )
        .unwrap()
        .get(0);
    assert_eq!(stored, tenant);
}

/// A database or role search_path setting is refused by default, even a
/// harmless one, and accepted only when the operator allows it explicitly
/// (PRAETORE_RUNTIME_ALLOW_SETTINGS=search_path).
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_runtime_role_refuses_a_search_path_setting_unless_allowed() {
    let runtime = TestRole::create("LOGIN NOBYPASSRLS");
    let scratch = migrated_with_runtime(&runtime);
    scratch
        .connect()
        .batch_execute(&format!(
            "ALTER DATABASE {db} SET search_path = \"$user\", public, extensions",
            db = scratch.name
        ))
        .unwrap();
    let mut client = connect_scratch_as(&scratch, &runtime.name);
    let error =
        verify_runtime_role(&mut client).expect_err("a search_path setting is refused by default");
    let message = error.to_string();
    assert!(message.contains("search_path="), "{message}");
    eprintln!("refused as expected: {message}");
    let allowed =
        praetore_replay_postgres::RuntimeRoleOptions::from_allow_settings("search_path").unwrap();
    verify_runtime_role_with(&mut client, &allowed)
        .expect("accepted when search_path is explicitly allowed");
    // The allowlist relaxes only search_path.
    scratch
        .connect()
        .batch_execute(&format!(
            "ALTER ROLE {role} IN DATABASE {db} SET row_security = off",
            role = runtime.name,
            db = scratch.name
        ))
        .unwrap();
    let mut client = connect_scratch_as(&scratch, &runtime.name);
    let error =
        verify_runtime_role_with(&mut client, &allowed).expect_err("row_security stays refused");
    assert!(error.to_string().contains("row_security=off"), "{error}");
}

const OWNER_BACKDOOR: &str = "CREATE FUNCTION public.maintenance(sql text) RETURNS void \
      LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog \
      AS $$ BEGIN EXECUTE sql; END $$; \
    GRANT EXECUTE ON FUNCTION public.maintenance(text) TO PUBLIC;";

/// Round 2, H1: a SECURITY DEFINER function of the praetore owner outside
/// praetore.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_owner_security_definer_function_elsewhere_fails_closed() {
    assert_tampered_baseline_refused(
        OWNER_BACKDOOR,
        "SECURITY DEFINER function public.maintenance(text) outside praetore",
    );
}

/// Round 2, H1 at runtime: the runtime role may not execute such a function.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_runtime_role_refuses_executable_owner_security_definer_function() {
    let runtime = TestRole::create("LOGIN NOBYPASSRLS");
    let scratch = migrated_with_runtime(&runtime);
    let mut client = connect_scratch_as(&scratch, &runtime.name);
    verify_runtime_role(&mut client).expect("least-privilege runtime role is accepted");
    scratch.connect().batch_execute(OWNER_BACKDOOR).unwrap();
    let error = verify_runtime_role(&mut client)
        .expect_err("an executable owner SECURITY DEFINER function must be refused");
    let message = error.to_string();
    assert!(message.contains("public.maintenance(text)"), "{message}");
    eprintln!("refused as expected: {message}");
}

/// Round 2, M1: only the migrating role (and NOLOGIN groups it belongs to)
/// may act as the praetore owner.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_owner_role_memberships_fail_closed() {
    let owner = TestRole::create("NOLOGIN");
    let intruder = TestRole::create("LOGIN");
    let login_owner = TestRole::create("LOGIN");
    // Legitimate: a NOLOGIN owner role with the migrating role as its only member.
    {
        let scratch = ScratchDatabase::create();
        let mut client = scratch.connect();
        apply_legacy_migrations_through(&mut client, 9);
        client
            .batch_execute(&format!(
                "{} GRANT {} TO CURRENT_USER;",
                transfer_praetore_ownership(&owner.name),
                owner.name
            ))
            .unwrap();
        let applied = adopt_legacy_baseline(&mut client)
            .expect("a NOLOGIN owner group of the migrating role is accepted");
        assert_eq!(
            applied.len(),
            praetore_replay_postgres::MIGRATIONS.len() - 9
        );
    }
    // Another member of the owner role.
    assert_tampered_baseline_refused(
        &format!(
            "{} GRANT {owner} TO CURRENT_USER; GRANT {owner} TO {intruder};",
            transfer_praetore_ownership(&owner.name),
            owner = owner.name,
            intruder = intruder.name
        ),
        &format!("role {} can act as the praetore owner", intruder.name),
    );
    // An owner that can log in, with the migrating role made its member.
    assert_tampered_baseline_refused(
        &format!(
            "{} GRANT {owner} TO CURRENT_USER;",
            transfer_praetore_ownership(&login_owner.name),
            owner = login_owner.name
        ),
        &format!("role {} owns praetore", login_owner.name),
    );
}

/// Round 2, M2: sequence parameters.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_changed_sequence_fails_closed() {
    assert_tampered_baseline_refused(
        "ALTER SEQUENCE praetore.execution_journal_events_event_id_seq \
           INCREMENT BY -1 MINVALUE -9223372036854775808 MAXVALUE 1 START WITH 1 RESTART;",
        "relation praetore.execution_journal_events_event_id_seq differs from 0009 in: \
         sequence increment, sequence max, sequence min",
    );
    assert_tampered_baseline_refused(
        "ALTER SEQUENCE praetore.execution_journal_events_event_id_seq MAXVALUE 3 CYCLE;",
        "relation praetore.execution_journal_events_event_id_seq differs from 0009 in: \
         sequence cycle, sequence max",
    );
}

/// Round 2, M3: a parameter grant that lets the runtime turn triggers off
/// after the check.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_runtime_role_refuses_parameter_grants() {
    let runtime = TestRole::create("LOGIN NOBYPASSRLS");
    let group = TestRole::create("NOLOGIN");
    let scratch = migrated_with_runtime(&runtime);
    let mut client = connect_scratch_as(&scratch, &runtime.name);
    verify_runtime_role(&mut client).expect("least-privilege runtime role is accepted");
    let mut admin = scratch.connect();
    for (grant, revoke) in [
        (
            format!(
                "GRANT SET ON PARAMETER session_replication_role TO {}",
                runtime.name
            ),
            format!(
                "REVOKE SET ON PARAMETER session_replication_role FROM {}",
                runtime.name
            ),
        ),
        (
            format!(
                "GRANT {group} TO {runtime}; \
                 GRANT SET ON PARAMETER session_replication_role TO {group}",
                group = group.name,
                runtime = runtime.name
            ),
            format!(
                "REVOKE SET ON PARAMETER session_replication_role FROM {}",
                group.name
            ),
        ),
    ] {
        admin.batch_execute(&grant).unwrap();
        let result = verify_runtime_role(&mut client);
        admin.batch_execute(&revoke).unwrap();
        let error = result.expect_err("a SET grant on session_replication_role must be refused");
        let message = error.to_string();
        assert!(
            message.contains("GRANT SET ON PARAMETER session_replication_role"),
            "{message}"
        );
        eprintln!("refused as expected: {message}");
    }
}

/// Round 2, H3: catalog flags written by a superuser. (The check cannot
/// defend against arbitrary catalog edits; these flags are cheap to compare.)
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_catalog_flags_fail_closed() {
    assert_tampered_baseline_refused(
        "UPDATE pg_catalog.pg_index SET indisvalid = false, indisready = false \
           WHERE indexrelid = 'praetore.replay_claims_pkey'::regclass;",
        "relation praetore.replay_claims_pkey differs from 0009 in: index ready, index valid",
    );
    assert_tampered_baseline_refused(
        "UPDATE pg_catalog.pg_class SET relhastriggers = false \
           WHERE oid = 'praetore.execution_journal_events'::regclass;",
        "relation praetore.execution_journal_events differs from 0009 in: has triggers",
    );
}

/// Round 2, lows: collation with its schema, FOR ALL TABLES publications,
/// and the real cause when the comparison cannot run.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_round2_lows_fail_closed() {
    assert_tampered_baseline_refused(
        "CREATE COLLATION public.\"default\" \
           (provider = icu, locale = 'und-u-ks-level2', deterministic = false); \
         ALTER TABLE praetore.human_approvals \
           ALTER COLUMN outcome TYPE text COLLATE public.\"default\";",
        "column praetore.human_approvals.outcome differs from 0009 in: collation",
    );
    assert_tampered_baseline_refused(
        "CREATE PUBLICATION t015_all FOR ALL TABLES;",
        "publication t015_all is FOR ALL TABLES",
    );
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    apply_legacy_migrations_through(&mut client, 9);
    client
        .batch_execute("SET statement_timeout = '1ms'")
        .unwrap();
    let error =
        adopt_legacy_baseline(&mut client).expect_err("the comparison cannot finish in 1 ms");
    let message = error.to_string();
    // query_canceled (statement timeout), independent of lc_messages.
    assert!(message.contains("SQLSTATE 57014"), "{message}");
    assert!(!message.ends_with("db error"), "{message}");
    eprintln!("refused as expected: {message}");
}

/// Opt-in: an existing schema without migration records is refused unless
/// adoption is requested explicitly; an adoption is recorded; a fresh
/// database is unaffected.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_legacy_baseline_requires_opt_in_and_is_recorded() {
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    apply_legacy_migrations_through(&mut client, 9);
    let error = praetore_replay_postgres::apply_migrations(&mut client)
        .expect_err("an existing schema without records must be refused by default");
    assert!(
        matches!(
            error,
            praetore_replay_postgres::MigrationError::LegacyBaselineNotAdopted
        ),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("PRAETORE_ADOPT_LEGACY_BASELINE=1")
    );
    eprintln!("refused as expected: {error}");
    let control: bool = client
        .query_one(
            "SELECT pg_catalog.to_regclass('praetore.schema_migrations') IS NOT NULL",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(!control, "nothing may be recorded without the opt-in");

    let applied = adopt_legacy_baseline(&mut client).unwrap();
    assert_eq!(
        applied.len(),
        praetore_replay_postgres::MIGRATIONS.len() - 9
    );
    let migrator: String = client
        .query_one("SELECT current_user::text", &[])
        .unwrap()
        .get(0);
    let rows = client
        .query(
            "SELECT version, adopted_legacy_baseline, adopted_by, baseline_structure_sha256 \
             FROM praetore.schema_migrations ORDER BY version",
            &[],
        )
        .unwrap();
    let mut digests = std::collections::BTreeSet::new();
    for (index, row) in rows.iter().enumerate() {
        let version: String = row.get(0);
        let adopted: bool = row.get(1);
        assert_eq!(adopted, index < 9, "{version}");
        if adopted {
            assert_eq!(
                row.get::<_, Option<String>>(2).as_deref(),
                Some(migrator.as_str())
            );
            let digest: String = row.get(3);
            assert!(digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()));
            digests.insert(digest);
        } else {
            assert!(row.get::<_, Option<String>>(2).is_none(), "{version}");
        }
    }
    assert_eq!(digests.len(), 1, "one dump digest for the adopted versions");
    let adoption = praetore_replay_postgres::legacy_baseline_adoption(&mut client)
        .unwrap()
        .expect("the adoption is reported");
    assert_eq!(adoption.adopted_by, migrator);
    assert_eq!(Some(&adoption.structure_sha256), digests.iter().next());
    eprintln!("recorded: {adoption}");

    // A fresh database is migrated without the opt-in and records no adoption.
    let fresh = ScratchDatabase::create();
    let mut client = fresh.connect();
    praetore_replay_postgres::apply_migrations(&mut client).unwrap();
    assert!(
        praetore_replay_postgres::legacy_baseline_adoption(&mut client)
            .unwrap()
            .is_none()
    );
    let adopted: i64 = client
        .query_one(
            "SELECT count(*) FROM praetore.schema_migrations WHERE adopted_legacy_baseline",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(adopted, 0);
}

/// Round 3, A1: state planted before the first migration of a fresh
/// database (default privileges for the future owner) is refused, and
/// nothing is created.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_fresh_database_refuses_planted_default_privileges() {
    let attacker = TestRole::create("LOGIN");
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    client
        .batch_execute(&format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE CURRENT_USER GRANT ALL ON TABLES TO {a}; \
             ALTER DEFAULT PRIVILEGES FOR ROLE CURRENT_USER GRANT USAGE ON SCHEMAS TO {a};",
            a = attacker.name
        ))
        .unwrap();
    let error = praetore_replay_postgres::apply_migrations(&mut client)
        .expect_err("planted default privileges must be refused");
    let message = error.to_string();
    assert!(message.contains("default privileges of"), "{message}");
    eprintln!("refused as expected: {message}");
    let schema: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'praetore')",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(!schema, "nothing may be created");
}

/// Round 3, A1: a SECURITY DEFINER function of the future owner, executable
/// by another role, is refused on a fresh database and on a current one.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_fresh_and_current_database_refuse_owner_security_definer_function() {
    let attacker = TestRole::create("LOGIN");
    let plant = format!(
        "CREATE FUNCTION public.maintenance(sql text) RETURNS void \
           LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog \
           AS $$ BEGIN EXECUTE sql; END $$; \
         REVOKE EXECUTE ON FUNCTION public.maintenance(text) FROM PUBLIC; \
         GRANT EXECUTE ON FUNCTION public.maintenance(text) TO {};",
        attacker.name
    );
    let fresh = ScratchDatabase::create();
    let mut client = fresh.connect();
    client.batch_execute(&plant).unwrap();
    let error = praetore_replay_postgres::apply_migrations(&mut client)
        .expect_err("fresh database with an owner SECURITY DEFINER function");
    assert!(
        error.to_string().contains("public.maintenance(text)"),
        "{error}"
    );
    eprintln!("refused as expected (fresh): {error}");

    let current = ScratchDatabase::create();
    let mut client = current.connect();
    praetore_replay_postgres::apply_migrations(&mut client).unwrap();
    client.batch_execute(&plant).unwrap();
    let error = praetore_replay_postgres::apply_migrations(&mut client)
        .expect_err("current database with an owner SECURITY DEFINER function");
    assert!(
        error.to_string().contains("public.maintenance(text)"),
        "{error}"
    );
    eprintln!("refused as expected (current): {error}");
}

/// Round 3, A1 at runtime: every grant on praetore objects must be one the
/// migrations intend, whichever path created the schema.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_runtime_role_refuses_unexpected_grants() {
    let runtime = TestRole::create("LOGIN NOBYPASSRLS");
    let attacker = TestRole::create("LOGIN");
    let scratch = migrated_with_runtime(&runtime);
    let mut admin = scratch.connect();
    let mut client = connect_scratch_as(&scratch, &runtime.name);
    verify_runtime_role(&mut client).expect("the migrations' own grants are accepted");
    let a = &attacker.name;
    for (grant, revoke, expected) in [
        (
            format!("GRANT DELETE ON praetore.replay_claims TO {a}"),
            format!("REVOKE DELETE ON praetore.replay_claims FROM {a}"),
            format!("relation praetore.replay_claims: DELETE to {a}"),
        ),
        (
            format!("GRANT SELECT (output_json) ON praetore.execution_journal TO {a}"),
            format!("REVOKE SELECT (output_json) ON praetore.execution_journal FROM {a}"),
            format!("column praetore.execution_journal.output_json: SELECT to {a}"),
        ),
        (
            format!("GRANT USAGE ON SCHEMA praetore TO {a}"),
            format!("REVOKE USAGE ON SCHEMA praetore FROM {a}"),
            format!("schema praetore: USAGE to {a}"),
        ),
        (
            "GRANT EXECUTE ON FUNCTION praetore.record_execution_journal_transition() TO PUBLIC"
                .to_owned(),
            "REVOKE EXECUTE ON FUNCTION praetore.record_execution_journal_transition() FROM PUBLIC"
                .to_owned(),
            // Reported first as an executable owner SECURITY DEFINER function.
            "praetore.record_execution_journal_transition()".to_owned(),
        ),
        (
            "GRANT SELECT ON praetore.execution_journal_events_event_id_seq TO praetore_runtime"
                .to_owned(),
            "REVOKE SELECT ON praetore.execution_journal_events_event_id_seq FROM praetore_runtime"
                .to_owned(),
            "relation praetore.execution_journal_events_event_id_seq: SELECT to praetore_runtime"
                .to_owned(),
        ),
    ] {
        admin.batch_execute(&grant).unwrap();
        let result = verify_runtime_role(&mut client);
        admin.batch_execute(&revoke).unwrap();
        let message = result.expect_err(&grant).to_string();
        assert!(message.contains(&expected), "{grant}: {message}");
        eprintln!("refused as expected: {message}");
    }
    // The documented praetore-observe grant shape is accepted.
    ensure_test_role(&mut admin, "praetore_observe", "LOGIN NOBYPASSRLS");
    admin
        .batch_execute(
            "GRANT USAGE ON SCHEMA praetore TO praetore_observe; \
             GRANT SELECT (tenant_id, agent_id, request_id, request_digest, action_digest, \
               authorization_status, execution_status, evidence_json, created_at, updated_at) \
               ON praetore.execution_journal TO praetore_observe; \
             GRANT SELECT (event_id, tenant_id, agent_id, request_id, from_status, to_status, \
               occurred_at) ON praetore.execution_journal_events TO praetore_observe;",
        )
        .unwrap();
    verify_runtime_role(&mut client).expect("the documented observe grants are accepted");
    // Only that exact shape: one more column is refused.
    admin
        .batch_execute(
            "GRANT SELECT (not_dispatched_reason) ON praetore.execution_journal TO praetore_observe",
        )
        .unwrap();
    let result = verify_runtime_role(&mut client);
    admin
        .batch_execute(
            "REVOKE SELECT (not_dispatched_reason) ON praetore.execution_journal \
             FROM praetore_observe",
        )
        .unwrap();
    let message = result
        .expect_err("a column beyond the documented shape")
        .to_string();
    assert!(
        message.contains(
            "column praetore.execution_journal.not_dispatched_reason: SELECT to praetore_observe"
        ),
        "{message}"
    );
}

/// Round 3, B3: a superuser's SECURITY DEFINER function is refused by
/// default, at runtime and when migrating, and accepted only when the
/// operator lists it explicitly.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_superuser_security_definer_function_is_accepted_only_when_trusted() {
    let runtime = TestRole::create("LOGIN NOBYPASSRLS");
    let superuser = TestRole::create("SUPERUSER NOLOGIN");
    let scratch = migrated_with_runtime(&runtime);
    let mut admin = scratch.connect();
    admin
        .batch_execute(&format!(
            "CREATE FUNCTION public.su_helper() RETURNS int LANGUAGE sql SECURITY DEFINER \
               SET search_path = pg_catalog AS 'SELECT 1'; \
             ALTER FUNCTION public.su_helper() OWNER TO {};",
            superuser.name
        ))
        .unwrap();
    let mut client = connect_scratch_as(&scratch, &runtime.name);
    let error = verify_runtime_role(&mut client).expect_err("refused by default");
    assert!(error.to_string().contains("public.su_helper()"), "{error}");
    eprintln!("refused as expected: {error}");
    let trusted = praetore_replay_postgres::RuntimeRoleOptions::default()
        .with_trusted_security_definer("public.su_helper()");
    verify_runtime_role_with(&mut client, &trusted).expect("accepted when trusted explicitly");

    let error = praetore_replay_postgres::apply_migrations(&mut admin)
        .expect_err("migration refuses it by default too");
    assert!(error.to_string().contains("public.su_helper()"), "{error}");
    praetore_replay_postgres::apply_migrations_with(
        &mut admin,
        &praetore_replay_postgres::MigrationOptions {
            trusted_security_definer: vec!["public.su_helper()".to_owned()],
            ..Default::default()
        },
    )
    .expect("accepted when trusted explicitly");
}

/// Round 3, B1: DDL that takes no lock on the praetore tables, committed
/// while the adopting transaction waits, is caught by the comparison right
/// before COMMIT.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_baseline_concurrent_function_replacement_fails_closed() {
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    apply_legacy_migrations_through(&mut client, 9);
    // Holds the control table's name, so the migrator waits on CREATE TABLE
    // after the first comparison.
    let mut blocker = scratch.connect();
    blocker
        .batch_execute("BEGIN; CREATE TABLE praetore.schema_migrations (x int)")
        .unwrap();
    let migrator = std::thread::spawn(move || {
        let result = adopt_legacy_baseline(&mut client);
        (result.map_err(|error| error.to_string()), client)
    });
    let mut observer = scratch.connect();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let waiting: i64 = observer
            .query_one(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE datname = current_database() AND wait_event_type = 'Lock' \
                   AND query LIKE '%schema_migrations%'",
                &[],
            )
            .unwrap()
            .get(0);
        if waiting > 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "migrator never waited"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    observer
        .batch_execute(
            "CREATE OR REPLACE FUNCTION praetore.reject_human_approval_mutation() \
               RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;",
        )
        .unwrap();
    blocker.batch_execute("ROLLBACK").unwrap();
    let (result, mut client) = migrator.join().unwrap();
    let message = result.expect_err("the replaced function must be detected");
    assert!(
        message.contains("function praetore.reject_human_approval_mutation() differs"),
        "{message}"
    );
    eprintln!("refused as expected: {message}");
    let control: bool = client
        .query_one(
            "SELECT pg_catalog.to_regclass('praetore.schema_migrations') IS NOT NULL",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(!control, "nothing may be recorded");
}

/// Round 4, A4-1 (GHSA-67vm-x598-vhg3): a control table is not proof that
/// the schema came from the migrations. Records written by hand over a
/// changed legacy schema, and a change made after migrating, are both
/// refused by the structural comparison that runs on every apply.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_structure_is_compared_on_every_run() {
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    apply_legacy_migrations_through(&mut client, 9);
    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION praetore.reject_human_approval_mutation() \
               RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$; \
             CREATE TABLE praetore.schema_migrations (version TEXT PRIMARY KEY, \
               checksum CHAR(64) NOT NULL, \
               applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());",
        )
        .unwrap();
    for (version, sql) in &praetore_replay_postgres::MIGRATIONS[..9] {
        client
            .execute(
                "INSERT INTO praetore.schema_migrations (version, checksum) VALUES ($1, $2)",
                &[version, &migration_checksum(sql)],
            )
            .unwrap();
    }
    let error = praetore_replay_postgres::apply_migrations(&mut client)
        .expect_err("records written by hand over a changed schema must be refused");
    let message = error.to_string();
    assert!(
        message.contains("function praetore.reject_human_approval_mutation() differs"),
        "{message}"
    );
    eprintln!("refused as expected: {message}");
    let recorded: i64 = client
        .query_one("SELECT count(*) FROM praetore.schema_migrations", &[])
        .unwrap()
        .get(0);
    assert_eq!(recorded, 9, "nothing more may be applied or recorded");

    let current = ScratchDatabase::create();
    let mut client = current.connect();
    praetore_replay_postgres::apply_migrations(&mut client).unwrap();
    client
        .batch_execute(
            "ALTER TABLE praetore.replay_claims DROP CONSTRAINT replay_claims_pkey CASCADE",
        )
        .unwrap();
    let error = praetore_replay_postgres::apply_migrations(&mut client)
        .expect_err("a change after migrating must be refused on the next run");
    let message = error.to_string();
    assert!(
        message.contains("constraint praetore.replay_claims.replay_claims_pkey is missing"),
        "{message}"
    );
    eprintln!("refused as expected: {message}");
}

/// Round 4, A4-1: a schema migrated by another role (here one given CREATE
/// on the database) is refused when the migrating role runs, owners being
/// checked on every run.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_refuse_a_schema_owned_by_another_role() {
    let other = TestRole::create("LOGIN");
    let scratch = ScratchDatabase::create();
    let mut admin = scratch.connect();
    admin
        .batch_execute(&format!(
            "GRANT CREATE ON DATABASE {} TO {}",
            scratch.name, other.name
        ))
        .unwrap();
    let mut client = connect_scratch_as(&scratch, &other.name);
    praetore_replay_postgres::apply_migrations(&mut client).unwrap();
    client
        .batch_execute(
            "ALTER TABLE praetore.replay_claims DROP CONSTRAINT replay_claims_pkey CASCADE",
        )
        .unwrap();
    let error = praetore_replay_postgres::apply_migrations(&mut admin)
        .expect_err("a schema owned by another role must be refused");
    let message = error.to_string();
    assert!(
        message.contains(&format!("schema praetore is owned by {}", other.name)),
        "{message}"
    );
    eprintln!("refused as expected: {message}");
}

/// Round 4, M4-1: access paths outside the praetore ACLs.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_runtime_role_refuses_access_paths_outside_praetore_acls() {
    let runtime = TestRole::create("LOGIN NOBYPASSRLS");
    let attacker = TestRole::create("LOGIN");
    let a = &attacker.name;
    for (setup, expected) in [
        (
            format!(
                "CREATE VIEW public.claims_proxy AS SELECT * FROM praetore.replay_claims; \
                 GRANT SELECT ON public.claims_proxy TO {a};"
            ),
            "on public.claims_proxy".to_owned(),
        ),
        (
            "GRANT SELECT ON praetore.replay_claims TO praetore_runtime WITH GRANT OPTION"
                .to_owned(),
            "relation praetore.replay_claims: SELECT WITH GRANT OPTION to praetore_runtime"
                .to_owned(),
        ),
        (
            format!("GRANT pg_read_all_data TO {a}"),
            format!("role {a} is a member of pg_read_all_data"),
        ),
        (
            format!(
                "CREATE FUNCTION public.maintenance(sql text) RETURNS void \
                   LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog \
                   AS $$ BEGIN EXECUTE sql; END $$; \
                 REVOKE EXECUTE ON FUNCTION public.maintenance(text) FROM PUBLIC; \
                 GRANT EXECUTE ON FUNCTION public.maintenance(text) TO {a};"
            ),
            "public.maintenance(text)".to_owned(),
        ),
        (
            format!("ALTER TABLE praetore.human_approvals OWNER TO {a}"),
            format!("relation praetore.human_approvals ({a})"),
        ),
    ] {
        let scratch = migrated_with_runtime(&runtime);
        let mut client = connect_scratch_as(&scratch, &runtime.name);
        verify_runtime_role(&mut client).expect("a clean installation is accepted");
        // pg_read_all_data is cluster-wide: held exclusively and revoked on
        // drop, so that no other test's runtime check sees it.
        let message = if setup.contains("pg_read_all_data") {
            let _grant =
                ClusterWideGrant::grant(&setup, &format!("REVOKE pg_read_all_data FROM {a}"));
            praetore_replay_postgres::verify_runtime_role(&mut client)
                .expect_err(&setup)
                .to_string()
        } else {
            scratch.connect().batch_execute(&setup).unwrap();
            verify_runtime_role(&mut client)
                .expect_err(&setup)
                .to_string()
        };
        assert!(message.contains(&expected), "{setup}: {message}");
        eprintln!("refused as expected: {message}");
    }
}

/// Round 4, M4-1: members of the owner role are refused unless listed;
/// other login members of praetore_runtime are refused only when the
/// operator configures the allowed logins.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_runtime_role_checks_owner_and_runtime_memberships() {
    use praetore_replay_postgres::RuntimeRoleOptions;
    let runtime = TestRole::create("LOGIN NOBYPASSRLS");
    let other_runtime = TestRole::create("LOGIN NOBYPASSRLS");
    let owner = TestRole::create("NOLOGIN");
    let member = TestRole::create("LOGIN");
    let scratch = migrated_with_runtime(&runtime);
    let mut admin = scratch.connect();
    admin
        .batch_execute(&format!(
            "{} GRANT {owner} TO {member}; GRANT praetore_runtime TO {other};",
            transfer_praetore_ownership(&owner.name),
            owner = owner.name,
            member = member.name,
            other = other_runtime.name
        ))
        .unwrap();
    let mut client = connect_scratch_as(&scratch, &runtime.name);
    let message = verify_runtime_role(&mut client)
        .expect_err("a member of the owner role must be refused")
        .to_string();
    assert!(
        message.contains(&format!(
            "role {} is a member of the praetore owner",
            member.name
        )),
        "{message}"
    );
    eprintln!("refused as expected: {message}");
    let allowed = RuntimeRoleOptions::default().with_schema_owner_members(&member.name);
    verify_runtime_role_with(&mut client, &allowed).expect("accepted when the member is listed");
    let members = praetore_replay_postgres::runtime_role_members(&mut client).unwrap();
    assert!(members.contains(&other_runtime.name), "{members:?}");
    let strict = allowed.clone().with_runtime_logins(&runtime.name);
    let message = verify_runtime_role_with(&mut client, &strict)
        .expect_err("another login member of praetore_runtime when logins are configured")
        .to_string();
    assert!(message.contains(&other_runtime.name), "{message}");
    assert!(!message.contains(&runtime.name), "{message}");
    // Other tests may add login members concurrently, so only this login is
    // checked: once listed, it is no longer reported.
    let both = allowed.with_runtime_logins(&format!("{},{}", runtime.name, other_runtime.name));
    let reported = verify_runtime_role_with(&mut client, &both)
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(!reported.contains(&other_runtime.name), "{reported}");
}

/// Round 4, B4-1: trusted SECURITY DEFINER entries resolve by OID (aliases
/// alike), must be qualified with a signature, and an entry that does not
/// resolve is a configuration error.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_trusted_security_definer_entries_resolve_by_oid_and_fail_closed() {
    use praetore_replay_postgres::{MigrationOptions, RuntimeRoleOptions};
    let runtime = TestRole::create("LOGIN NOBYPASSRLS");
    let superuser = TestRole::create("SUPERUSER NOLOGIN");
    let scratch = migrated_with_runtime(&runtime);
    let mut admin = scratch.connect();
    admin
        .batch_execute(&format!(
            "CREATE FUNCTION public.su_helper(integer) RETURNS int LANGUAGE sql \
               SECURITY DEFINER SET search_path = pg_catalog AS 'SELECT $1'; \
             ALTER FUNCTION public.su_helper(integer) OWNER TO {};",
            superuser.name
        ))
        .unwrap();
    let mut client = connect_scratch_as(&scratch, &runtime.name);
    let alias =
        RuntimeRoleOptions::default().with_trusted_security_definer("public.su_helper(int4)");
    verify_runtime_role_with(&mut client, &alias).expect("an alias resolves to the same function");
    let described =
        praetore_replay_postgres::describe_trusted_security_definer(&mut client, &alias).unwrap();
    assert_eq!(described.len(), 1);
    assert_eq!(described[0].resolved, "public.su_helper(integer)");
    assert!(described[0].owner_is_superuser);
    for entry in [
        "public.nonexistent()",
        "su_helper(integer)",
        "public.su_helper",
    ] {
        let options = RuntimeRoleOptions::default().with_trusted_security_definer(entry);
        let error = verify_runtime_role_with(&mut client, &options).expect_err(entry);
        assert!(
            matches!(
                error,
                praetore_replay_postgres::RuntimeRoleError::InvalidConfiguration(_)
            ),
            "{entry}: {error}"
        );
        let error = praetore_replay_postgres::apply_migrations_with(
            &mut admin,
            &MigrationOptions {
                trusted_security_definer: vec![entry.to_owned()],
                ..Default::default()
            },
        )
        .expect_err(entry);
        assert!(
            matches!(
                error,
                praetore_replay_postgres::MigrationError::InvalidConfiguration(_)
            ),
            "{entry}: {error}"
        );
        eprintln!("refused as expected ({entry}): {error}");
    }
}

/// Round 4, B4-2: the record is not tamper-evident; an erased adoption mark
/// is at least flagged by its single-transaction write.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migration_record_inconsistency_is_flagged() {
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    apply_legacy_migrations_through(&mut client, 9);
    adopt_legacy_baseline(&mut client).unwrap();
    assert!(
        praetore_replay_postgres::migration_record_inconsistency(&mut client)
            .unwrap()
            .is_none(),
        "a marked adoption is consistent"
    );
    client
        .batch_execute(
            "UPDATE praetore.schema_migrations SET adopted_legacy_baseline = false, \
               adopted_by = NULL, baseline_structure_sha256 = NULL",
        )
        .unwrap();
    let problem = praetore_replay_postgres::migration_record_inconsistency(&mut client)
        .unwrap()
        .expect("an erased adoption mark is flagged");
    eprintln!("flagged as expected: {problem}");
    let fresh = ScratchDatabase::create();
    let mut client = fresh.connect();
    praetore_replay_postgres::apply_migrations(&mut client).unwrap();
    assert!(
        praetore_replay_postgres::migration_record_inconsistency(&mut client)
            .unwrap()
            .is_none(),
        "a database migrated by the runner is consistent"
    );
}

/// Option B (GHSA-67vm-x598-vhg3): adopting a legacy baseline writes, in the
/// same transaction, a storage record signed with the attester key into the
/// append-only praetore.storage_records.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_adoption_writes_a_signed_append_only_storage_record() {
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    apply_legacy_migrations_through(&mut client, 9);
    adopt_legacy_baseline(&mut client).unwrap();
    let rows = client
        .query(
            "SELECT record_json, kind FROM praetore.storage_records",
            &[],
        )
        .unwrap();
    assert_eq!(rows.len(), 1, "one adoption record");
    let record = praetore_core::StorageRecord::from_json(rows[0].get(0)).unwrap();
    record
        .verify(&adoption_attester().public_key().unwrap())
        .expect("signed by the attester key");
    assert_eq!(rows[0].get::<_, String>(1), "legacy_baseline_adopted");
    assert_eq!(record.migrations.len(), 9);
    let adoption = praetore_replay_postgres::legacy_baseline_adoption(&mut client)
        .unwrap()
        .unwrap();
    assert_eq!(record.structure_sha256, adoption.structure_sha256);
    eprintln!("record: {}", record.to_json().unwrap());
    for statement in [
        "UPDATE praetore.storage_records SET kind = kind",
        "DELETE FROM praetore.storage_records",
        "TRUNCATE praetore.storage_records",
    ] {
        assert!(client.batch_execute(statement).is_err(), "{statement}");
    }
    // A fresh database has the table and no record.
    let fresh = ScratchDatabase::create();
    let mut client = fresh.connect();
    praetore_replay_postgres::apply_migrations(&mut client).unwrap();
    let count: i64 = client
        .query_one("SELECT count(*) FROM praetore.storage_records", &[])
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
}

/// Option B: no signer, no adoption.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_adoption_without_signer_is_refused() {
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    apply_legacy_migrations_through(&mut client, 9);
    let error = praetore_replay_postgres::apply_migrations_with(
        &mut client,
        &praetore_replay_postgres::MigrationOptions {
            adopt_legacy_baseline: true,
            ..Default::default()
        },
    )
    .expect_err("adoption without a signer");
    assert!(
        matches!(
            error,
            praetore_replay_postgres::MigrationError::AdoptionRequiresSigner
        ),
        "{error}"
    );
    eprintln!("refused as expected: {error}");
    let control: bool = client
        .query_one(
            "SELECT pg_catalog.to_regclass('praetore.schema_migrations') IS NOT NULL",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(!control, "nothing may be recorded");
}

/// M4-2: event triggers are refused unless listed in
/// PRAETORE_TRUSTED_EVENT_TRIGGERS and verifiable (trigger and function
/// owned by superusers unrelated to the praetore owner and the migrating
/// role); a listed trigger that cannot be verified fails closed.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_trusted_event_triggers_allowlist() {
    use praetore_replay_postgres::MigrationOptions;
    let platform = TestRole::create("SUPERUSER NOLOGIN");
    let unprivileged = TestRole::create("NOLOGIN");
    let trusted = |names: &str| MigrationOptions {
        trusted_event_triggers: MigrationOptions::parse_list(names),
        ..Default::default()
    };
    // The trigger function (SECURITY INVOKER, the default) records the role
    // it runs as: B5-3, it is the migrating role, not the function owner.
    let setup = |owner: &str, function_owner: &str| {
        format!(
            "CREATE TABLE public.platform_ddl_log (session_role text, current_role_name text); \
             GRANT INSERT ON public.platform_ddl_log TO PUBLIC; \
             CREATE FUNCTION public.platform_ddl_watch() RETURNS event_trigger \
               LANGUAGE plpgsql AS $$ BEGIN \
                 INSERT INTO public.platform_ddl_log VALUES (session_user, current_user); \
               END $$; \
             CREATE EVENT TRIGGER platform_ddl_watch ON ddl_command_end \
               EXECUTE FUNCTION public.platform_ddl_watch(); \
             ALTER FUNCTION public.platform_ddl_watch() OWNER TO {function_owner}; \
             ALTER EVENT TRIGGER platform_ddl_watch OWNER TO {owner};"
        )
    };
    // Listed and owned by an unrelated superuser: accepted.
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    client
        .batch_execute(&setup(&platform.name, &platform.name))
        .unwrap();
    let report =
        praetore_replay_postgres::event_trigger_report(&mut client, &["platform_ddl_watch".into()])
            .unwrap();
    assert_eq!(report.len(), 1);
    assert!(
        report[0].listed && report[0].problem.is_none(),
        "{report:?}"
    );
    // Not listed: refused.
    let error = praetore_replay_postgres::apply_migrations(&mut client)
        .expect_err("an unlisted event trigger");
    assert!(
        error
            .to_string()
            .contains("not listed in PRAETORE_TRUSTED_EVENT_TRIGGERS"),
        "{error}"
    );
    praetore_replay_postgres::apply_migrations_with(&mut client, &trusted("platform_ddl_watch"))
        .expect("a listed, verifiable event trigger is accepted");
    // It fired during the migrations as the migrating role, not as its
    // function owner (an unrelated superuser).
    let migrator: String = client
        .query_one("SELECT current_user::text", &[])
        .unwrap()
        .get(0);
    let roles: Vec<(String, String, i64)> = client
        .query(
            "SELECT session_role, current_role_name, count(*) FROM public.platform_ddl_log \
             GROUP BY 1, 2",
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    assert_eq!(roles.len(), 1, "{roles:?}");
    assert_eq!(
        (&roles[0].0, &roles[0].1),
        (&migrator, &migrator),
        "{roles:?}"
    );
    assert_ne!(roles[0].1, platform.name);
    assert!(roles[0].2 > 0, "{roles:?}");
    eprintln!(
        "event trigger ran {} times as session_user = current_user = {migrator}",
        roles[0].2
    );
    drop(scratch);
    // Listed, but its function owner cannot be verified (not a superuser),
    // or an owner is the migrating role: refused.
    for (owner, function_owner, expected) in [
        (
            platform.name.clone(),
            unprivileged.name.clone(),
            format!("is owned by {}, not a superuser", unprivileged.name),
        ),
        (
            "CURRENT_USER".to_owned(),
            platform.name.clone(),
            "has as member the praetore owner or the migrating role".to_owned(),
        ),
    ] {
        let scratch = ScratchDatabase::create();
        let mut client = scratch.connect();
        client
            .batch_execute(&setup(&owner, &function_owner))
            .unwrap();
        let error = praetore_replay_postgres::apply_migrations_with(
            &mut client,
            &trusted("platform_ddl_watch"),
        )
        .expect_err("a listed event trigger that cannot be verified");
        let message = error.to_string();
        assert!(message.contains("cannot be verified"), "{message}");
        assert!(message.contains(&expected), "{message}");
        eprintln!("refused as expected: {message}");
    }
}

/// B5-1: a role with CREATE on the database can install a trusted
/// extension into praetore (PostgreSQL 13+); its objects then belong to the
/// bootstrap superuser. Both the runtime check and the migration runner
/// refuse extension objects in praetore, whoever owns them.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_extension_objects_in_praetore_are_refused() {
    let runtime = TestRole::create("LOGIN NOBYPASSRLS");
    let creator = TestRole::create("LOGIN");
    let scratch = migrated_with_runtime(&runtime);
    let mut admin = scratch.connect();
    let mut client = connect_scratch_as(&scratch, &runtime.name);
    verify_runtime_role(&mut client).expect("a clean installation is accepted");
    admin
        .batch_execute(&format!(
            "GRANT CREATE ON DATABASE {} TO {}",
            scratch.name, creator.name
        ))
        .unwrap();
    let mut outsider = connect_scratch_as(&scratch, &creator.name);
    let can_create: bool = outsider
        .query_one("SELECT has_schema_privilege('praetore', 'CREATE')", &[])
        .unwrap()
        .get(0);
    assert!(!can_create, "the creator has no CREATE on praetore");
    outsider
        .batch_execute("CREATE EXTENSION hstore SCHEMA praetore")
        .unwrap();

    let error = verify_runtime_role(&mut client).expect_err("extension objects in praetore");
    assert!(
        matches!(
            error,
            praetore_replay_postgres::RuntimeRoleError::ExtensionObjects(_)
        ),
        "{error}"
    );
    let message = error.to_string();
    assert!(
        message.contains("extension hstore (installed in praetore)"),
        "{message}"
    );
    assert!(message.contains("member of extension hstore"), "{message}");
    eprintln!("runtime refused as expected: {message}");
    let error = praetore_replay_postgres::apply_migrations(&mut admin)
        .expect_err("migrating with extension objects in praetore");
    let message = error.to_string();
    assert!(
        matches!(
            error,
            praetore_replay_postgres::MigrationError::UnsafeDatabase(_)
        ) && message.contains("extension objects are in schema praetore")
            && message.contains("extension hstore"),
        "{message}"
    );
    eprintln!("migration refused as expected: {message}");

    // Gone again: both accept.
    outsider.batch_execute("DROP EXTENSION hstore").unwrap();
    verify_runtime_role(&mut client).expect("accepted once the extension is dropped");
    praetore_replay_postgres::apply_migrations(&mut admin).unwrap();

    // B89-2: an extension elsewhere is fine, but a praetore object marked
    // DEPENDS ON EXTENSION (deptype 'x') would be dropped by DROP EXTENSION
    // ... CASCADE, which the extension's owner (here the outsider) may run.
    outsider
        .batch_execute("CREATE SCHEMA ext_other; CREATE EXTENSION citext SCHEMA ext_other")
        .unwrap();
    verify_runtime_role(&mut client).expect("an extension outside praetore is accepted");
    praetore_replay_postgres::apply_migrations(&mut admin).unwrap();
    let marked = "function praetore.reject_execution_journal_event_mutation() \
                  (depends on extension citext)";
    admin
        .batch_execute(
            "ALTER FUNCTION praetore.reject_execution_journal_event_mutation() \
             DEPENDS ON EXTENSION citext",
        )
        .unwrap();
    let error = verify_runtime_role(&mut client).expect_err("a DEPENDS ON EXTENSION mark");
    let message = error.to_string();
    assert!(
        matches!(
            error,
            praetore_replay_postgres::RuntimeRoleError::ExtensionObjects(_)
        ) && message.contains(marked),
        "{message}"
    );
    eprintln!("runtime refused as expected: {message}");
    let message = praetore_replay_postgres::apply_migrations(&mut admin)
        .expect_err("migrating with a DEPENDS ON EXTENSION mark")
        .to_string();
    assert!(message.contains(marked), "{message}");
    eprintln!("migration refused as expected: {message}");
    admin
        .batch_execute(
            "ALTER FUNCTION praetore.reject_execution_journal_event_mutation() \
             NO DEPENDS ON EXTENSION citext",
        )
        .unwrap();
    verify_runtime_role(&mut client).expect("accepted once the mark is removed");
    praetore_replay_postgres::apply_migrations(&mut admin).unwrap();
}

/// B5-2: with PRAETORE_SCHEMA_OWNER, a praetore schema created by another
/// role (here one given CREATE on the database, before the first legitimate
/// migration) is refused by the runtime check and by migrating; without it,
/// the runtime check trusts whichever role owns the schema.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_schema_owner_is_pinned_by_praetore_schema_owner() {
    use praetore_replay_postgres::{MigrationError, MigrationOptions, RuntimeRoleOptions};
    let runtime = TestRole::create("LOGIN NOBYPASSRLS");
    let squatter = TestRole::create("LOGIN");
    let admin_role: String = connect_client()
        .query_one("SELECT current_user::text", &[])
        .unwrap()
        .get(0);
    let pinned =
        |owner: &str| RuntimeRoleOptions::default().with_schema_owner(&format!(" {owner} "));
    let migrate_as = |owner: &str| MigrationOptions {
        schema_owner: MigrationOptions::parse_schema_owner(Some(owner)),
        ..Default::default()
    };

    // The squatter migrates an empty database first.
    let scratch = ScratchDatabase::create();
    let mut admin = scratch.connect();
    admin
        .batch_execute(&format!(
            "GRANT CREATE ON DATABASE {} TO {}",
            scratch.name, squatter.name
        ))
        .unwrap();
    praetore_replay_postgres::apply_migrations(&mut connect_scratch_as(&scratch, &squatter.name))
        .unwrap();
    admin
        .batch_execute(&format!("GRANT praetore_runtime TO {}", runtime.name))
        .unwrap();
    let mut client = connect_scratch_as(&scratch, &runtime.name);
    verify_runtime_role(&mut client)
        .expect("without PRAETORE_SCHEMA_OWNER the runtime accepts any owner");
    let error = verify_runtime_role_with(&mut client, &pinned(&admin_role))
        .expect_err("a schema owned by another role than PRAETORE_SCHEMA_OWNER");
    let message = error.to_string();
    assert!(
        matches!(
            &error,
            praetore_replay_postgres::RuntimeRoleError::UnexpectedSchemaOwner { actual: Some(actual), .. }
                if *actual == squatter.name
        ),
        "{message}"
    );
    assert!(
        message.contains(&format!(
            "schema praetore is owned by {}, but PRAETORE_SCHEMA_OWNER is {admin_role}",
            squatter.name
        )),
        "{message}"
    );
    eprintln!("runtime refused as expected: {message}");
    verify_runtime_role_with(&mut client, &pinned(&squatter.name))
        .expect("the pinned owner is accepted");
    let message =
        praetore_replay_postgres::apply_migrations_with(&mut admin, &migrate_as(&admin_role))
            .expect_err("migrating a schema owned by another role")
            .to_string();
    assert!(
        message.contains(&format!(
            "schema praetore is owned by {}, but PRAETORE_SCHEMA_OWNER is {admin_role}",
            squatter.name
        )),
        "{message}"
    );
    drop(client);
    drop(admin);
    drop(scratch);

    // No schema yet: the configured owner must be the migrating role or a
    // NOLOGIN group of it (see the owner-group test); a LOGIN role is not.
    let scratch = ScratchDatabase::create();
    let mut admin = scratch.connect();
    let error =
        praetore_replay_postgres::apply_migrations_with(&mut admin, &migrate_as(&squatter.name))
            .expect_err("PRAETORE_SCHEMA_OWNER is another LOGIN role");
    let message = error.to_string();
    assert!(
        matches!(error, MigrationError::UnsafeDatabase(_))
            && message.contains(&format!(
                "PRAETORE_SCHEMA_OWNER names {}, a LOGIN role other than the migrating role \
                 {admin_role}",
                squatter.name
            )),
        "{message}"
    );
    let exists: bool = admin
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'praetore')",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(!exists, "nothing was created");
    praetore_replay_postgres::apply_migrations_with(&mut admin, &migrate_as(&admin_role)).unwrap();
    praetore_replay_postgres::apply_migrations_with(&mut admin, &migrate_as(&admin_role)).unwrap();
    admin
        .batch_execute(&format!("GRANT praetore_runtime TO {}", runtime.name))
        .unwrap();
    verify_runtime_role_with(
        &mut connect_scratch_as(&scratch, &runtime.name),
        &pinned(&admin_role),
    )
    .expect("the configured owner is accepted");
    // The options read the same variable.
    let from_env = RuntimeRoleOptions::from_config(|name| {
        (name == "PRAETORE_SCHEMA_OWNER").then(|| admin_role.clone())
    })
    .unwrap();
    assert_eq!(from_env.schema_owner(), Some(admin_role.as_str()));
}

/// B89-3: PRAETORE_SCHEMA_OWNER naming a NOLOGIN owner group. A migrating
/// role that is a member of the group performs the first migration: the
/// schema and every object are created owned by the group. Any other owner
/// stays refused: a group the migrating role is not a member of, a LOGIN
/// role, a role that does not exist.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_schema_owner_group_performs_the_first_migration() {
    use praetore_replay_postgres::{MigrationOptions, RuntimeRoleOptions};
    let group = TestRole::create("NOLOGIN");
    let migrator = TestRole::create("LOGIN");
    let other_group = TestRole::create("NOLOGIN");
    let other_login = TestRole::create("LOGIN");
    let runtime = TestRole::create("LOGIN NOBYPASSRLS");
    let pinned = |owner: &str| MigrationOptions {
        schema_owner: MigrationOptions::parse_schema_owner(Some(owner)),
        ..Default::default()
    };
    let scratch_for_migrator = || {
        let scratch = ScratchDatabase::create();
        scratch
            .connect()
            .batch_execute(&format!(
                "GRANT CREATE ON DATABASE {db} TO {}, {}; GRANT {} TO {}; GRANT {} TO {}",
                migrator.name,
                group.name,
                group.name,
                migrator.name,
                other_login.name,
                migrator.name,
                db = scratch.name
            ))
            .unwrap();
        scratch
    };

    let scratch = scratch_for_migrator();
    let mut client = connect_scratch_as(&scratch, &migrator.name);
    let applied =
        praetore_replay_postgres::apply_migrations_with(&mut client, &pinned(&group.name))
            .expect("the migrating role creates the schema owned by its group");
    assert_eq!(applied.len(), praetore_replay_postgres::MIGRATIONS.len());
    let owners: Vec<String> = scratch
        .connect()
        .query(
            "SELECT DISTINCT pg_get_userbyid(owner)::text FROM ( \
                 SELECT nspowner AS owner FROM pg_namespace WHERE nspname = 'praetore' \
                 UNION ALL SELECT c.relowner FROM pg_class c \
                     JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'praetore' \
                 UNION ALL SELECT p.proowner FROM pg_proc p \
                     JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'praetore') o",
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(owners, vec![group.name.clone()]);
    assert!(
        praetore_replay_postgres::apply_migrations_with(&mut client, &pinned(&group.name))
            .unwrap()
            .is_empty()
    );
    // The runtime accepts the pinned group owner once its member, the
    // migrating role, is listed (PRAETORE_SCHEMA_OWNER_MEMBERS).
    scratch
        .connect()
        .batch_execute(&format!("GRANT praetore_runtime TO {}", runtime.name))
        .unwrap();
    let mut runtime_client = connect_scratch_as(&scratch, &runtime.name);
    let options = RuntimeRoleOptions::default()
        .with_schema_owner(&group.name)
        .with_schema_owner_members(&migrator.name);
    verify_runtime_role_with(&mut runtime_client, &options)
        .expect("the pinned owner group with its listed member");
    let message = verify_runtime_role_with(
        &mut runtime_client,
        &RuntimeRoleOptions::default().with_schema_owner(&group.name),
    )
    .expect_err("an unlisted member of the owner group")
    .to_string();
    assert!(message.contains(&migrator.name), "{message}");
    drop(runtime_client);
    drop(client);
    drop(scratch);

    // Fail closed for any other owner.
    for (owner, expected) in [
        (
            other_group.name.clone(),
            format!(
                "the migrating role {} is neither PRAETORE_SCHEMA_OWNER ({}) nor a member of it",
                migrator.name, other_group.name
            ),
        ),
        (
            other_login.name.clone(),
            format!(
                "PRAETORE_SCHEMA_OWNER names {}, a LOGIN role other than the migrating role {}",
                other_login.name, migrator.name
            ),
        ),
        (
            "praetore_no_such_owner".to_owned(),
            "names role praetore_no_such_owner, which does not exist".to_owned(),
        ),
    ] {
        let scratch = scratch_for_migrator();
        let mut client = connect_scratch_as(&scratch, &migrator.name);
        let message = praetore_replay_postgres::apply_migrations_with(&mut client, &pinned(&owner))
            .expect_err(&owner)
            .to_string();
        assert!(message.contains(&expected), "{owner}: {message}");
        let exists: bool = client
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'praetore')",
                &[],
            )
            .unwrap()
            .get(0);
        assert!(!exists, "{owner}: nothing was created");
        eprintln!("refused as expected: {message}");
    }
}

/// M4-2: only default privileges for all schemas or for praetore count;
/// a global entry can be trusted (PRAETORE_TRUSTED_DEFAULT_PRIVILEGES) only
/// when it only revokes; entries in praetore never.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_trusted_default_privileges_allowlist() {
    use praetore_replay_postgres::MigrationOptions;
    let other = TestRole::create("NOLOGIN");
    let trusted = |entries: &str| MigrationOptions {
        trusted_default_privileges: MigrationOptions::parse_list(entries),
        ..Default::default()
    };
    let migrator: String = connect_client()
        .query_one("SELECT current_user::text", &[])
        .unwrap()
        .get(0);
    // In another schema: never applies to praetore, ignored.
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    client
        .batch_execute(&format!(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {}",
            other.name
        ))
        .unwrap();
    praetore_replay_postgres::apply_migrations(&mut client)
        .expect("default privileges in another schema are not considered");
    drop(scratch);
    // Global and revoke-only: refused unless listed.
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    client
        .batch_execute("ALTER DEFAULT PRIVILEGES FOR ROLE CURRENT_USER REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC")
        .unwrap();
    let error = praetore_replay_postgres::apply_migrations(&mut client)
        .expect_err("an unlisted global entry");
    assert!(
        error.to_string().contains("default privileges of"),
        "{error}"
    );
    praetore_replay_postgres::apply_migrations_with(
        &mut client,
        &trusted(&format!("{migrator}:*:f")),
    )
    .expect("a listed revoke-only global entry is accepted");
    drop(scratch);
    // Global and granting: refused even when listed.
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    client
        .batch_execute(&format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE CURRENT_USER GRANT SELECT ON TABLES TO {}",
            other.name
        ))
        .unwrap();
    let message = praetore_replay_postgres::apply_migrations_with(
        &mut client,
        &trusted(&format!("{migrator}:*:r")),
    )
    .expect_err("a granting entry")
    .to_string();
    assert!(
        message.contains("only entries that only revoke can be trusted"),
        "{message}"
    );
    drop(scratch);
    // In praetore: never allowed; and a non-global entry is a config error.
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    praetore_replay_postgres::apply_migrations(&mut client).unwrap();
    client
        .batch_execute(&format!(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA praetore GRANT SELECT ON TABLES TO {}",
            other.name
        ))
        .unwrap();
    let message = praetore_replay_postgres::apply_migrations_with(
        &mut client,
        &trusted(&format!("{migrator}:*:r")),
    )
    .expect_err("an entry in praetore")
    .to_string();
    assert!(
        message.contains("default privileges in praetore are never allowed"),
        "{message}"
    );
    let error = praetore_replay_postgres::apply_migrations_with(
        &mut client,
        &trusted(&format!("{migrator}:praetore:f")),
    )
    .expect_err("not role:*:objtype");
    assert!(
        matches!(
            error,
            praetore_replay_postgres::MigrationError::InvalidConfiguration(_)
        ),
        "{error}"
    );
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_unknown_version_refuses_to_start() {
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    praetore_replay_postgres::apply_migrations(&mut client).unwrap();
    client
        .execute(
            "INSERT INTO praetore.schema_migrations (version, checksum) VALUES ($1, $2)",
            &[&"9999_from_the_future", &"0".repeat(64)],
        )
        .unwrap();
    let error = praetore_replay_postgres::apply_migrations(&mut client).unwrap_err();
    assert!(
        matches!(
            &error,
            praetore_replay_postgres::MigrationError::UnknownVersion(version)
                if version == "9999_from_the_future"
        ),
        "{error}"
    );
}

fn column_exists(client: &mut Client, table: &str, column: &str) -> bool {
    client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_schema = 'praetore' AND table_name = $1 AND column_name = $2)",
            &[&table, &column],
        )
        .unwrap()
        .get(0)
}

/// 0007 is written as `BEGIN; ... COMMIT;`. Its effects and its
/// schema_migrations row must commit together: if recording the version
/// fails (here: an injected trigger, standing in for a crash after the body
/// ran), nothing of 0007 may remain.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migration_effects_and_record_commit_atomically() {
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    client
        .batch_execute(
            "CREATE SCHEMA praetore; \
             CREATE TABLE praetore.schema_migrations (\
                 version TEXT PRIMARY KEY, \
                 checksum CHAR(64) NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'), \
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()); \
             CREATE FUNCTION public.fail_0007_record() RETURNS trigger \
             LANGUAGE plpgsql AS $$ BEGIN \
                 IF NEW.version = '0007_tenant_scoped_execution' THEN \
                     RAISE EXCEPTION 'injected failure after the 0007 body'; \
                 END IF; \
                 RETURN NEW; \
             END $$; \
             CREATE TRIGGER fail_0007_record BEFORE INSERT ON praetore.schema_migrations \
             FOR EACH ROW EXECUTE FUNCTION public.fail_0007_record();",
        )
        .unwrap();

    let error = praetore_replay_postgres::apply_migrations(&mut client).unwrap_err();
    assert!(
        matches!(error, praetore_replay_postgres::MigrationError::Database(_)),
        "{error}"
    );
    assert_eq!(recorded_versions(&mut client), all_versions()[..6].to_vec());
    assert!(
        !column_exists(&mut client, "replay_claims", "tenant_id"),
        "0007 effects committed without its schema_migrations row"
    );
    assert!(matches!(
        praetore_replay_postgres::verify_schema_current(&mut client),
        Err(praetore_replay_postgres::MigrationError::Pending(
            "0007_tenant_scoped_execution"
        ))
    ));

    client
        .batch_execute("DROP TRIGGER fail_0007_record ON praetore.schema_migrations")
        .unwrap();
    let applied = praetore_replay_postgres::apply_migrations(&mut client).unwrap();
    assert_eq!(applied.first(), Some(&"0007_tenant_scoped_execution"));
    assert_eq!(recorded_versions(&mut client), all_versions());
    assert!(column_exists(&mut client, "replay_claims", "tenant_id"));
    assert_0010_schema_present(&mut client);
    praetore_replay_postgres::verify_schema_current(&mut client).unwrap();
}

fn fault_journal() -> Arc<CommitFaultJournal> {
    Arc::new(CommitFaultJournal {
        inner: connect_journal(),
        fail_before_commit: AtomicBool::new(false),
        lose_acknowledgement: AtomicBool::new(false),
        fail_verification: AtomicBool::new(false),
        fail_terminal: AtomicBool::new(false),
        fail_approval: AtomicBool::new(false),
        lose_claim_acknowledgement: AtomicBool::new(false),
    })
}

fn gateway_with_fault_journal(
    fixture: &PostgresApprovalFixture,
    journal: Arc<CommitFaultJournal>,
) -> (Gateway, Arc<PostgresTestAdapter>) {
    let adapter = Arc::new(PostgresTestAdapter::new(None));
    let gateway = Gateway::new(
        fixture.engine.clone(),
        journal,
        adapter.clone(),
        execution_attester(),
    )
    .unwrap()
    .with_human_approval_verifier(
        HumanApprovalVerifier::new(
            "postgres-human-approver-v1",
            VerifiedPublicKey::from_bytes(&fixture.approver_key.verifying_key().to_bytes())
                .unwrap(),
        )
        .unwrap(),
    );
    (gateway, adapter)
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_apd_failed_approval_commit_leaves_the_request_pending_and_undispatched() {
    let fixture = create_postgres_approval_gateway(Uuid::new_v4());
    let pending = fixture.gateway.execute(fixture.request.clone()).unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let journal = fault_journal();
    journal.fail_approval.store(true, Ordering::SeqCst);
    let (gateway, adapter) = gateway_with_fault_journal(&fixture, journal);
    let decision = sign_approval(&fixture, key);

    assert!(matches!(
        gateway.resolve_human_approval(decision.clone()),
        Err(GatewayError::Journal(JournalError::Unavailable))
    ));
    let record = connect_journal().get(key).unwrap().unwrap();
    assert_eq!(record.execution, ExecutionStatus::NotDispatched);
    assert!(record.human_approval.is_none());
    assert!(matches!(
        gateway.dispatch_approved(key),
        Err(GatewayError::Approval(
            praetore_gateway::ApprovalError::NotPending
        ))
    ));
    assert_eq!(adapter.invocation_count(), 0);
    assert_eq!(database_invocation_count(key), 0);

    // The fault was transient: the same signed decision now records APD,
    // still without dispatching.
    assert!(matches!(
        gateway.resolve_human_approval(decision).unwrap(),
        HumanApprovalResult::ApprovedPendingDispatch { .. }
    ));
    assert_eq!(adapter.invocation_count(), 0);
    assert_eq!(
        connect_journal().get(key).unwrap().unwrap().execution,
        ExecutionStatus::ApprovedPendingDispatch
    );
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_apd_lost_claim_acknowledgement_never_invokes_the_adapter() {
    let fixture = create_postgres_approval_gateway(Uuid::new_v4());
    let key = approved_pending(&fixture);
    let journal = fault_journal();
    journal
        .lose_claim_acknowledgement
        .store(true, Ordering::SeqCst);
    let (gateway, adapter) = gateway_with_fault_journal(&fixture, journal);

    assert!(matches!(
        gateway.dispatch_approved(key),
        Err(GatewayError::Journal(JournalError::Unavailable))
    ));
    // The claim committed but the gateway never saw it, so no permit existed
    // and the adapter never ran.
    assert_eq!(adapter.invocation_count(), 0);
    assert_eq!(fixture.adapter.invocation_count(), 0);
    assert_eq!(database_invocation_count(key), 0);
    assert_eq!(
        connect_journal().get(key).unwrap().unwrap().execution,
        ExecutionStatus::Dispatched
    );
    // Durable `dispatched` cannot be claimed again. Reconcile asks the
    // adapter, which proves the effect absent (`Failed`, never re-run); an
    // adapter that cannot tell yields outcome_unknown.
    assert!(matches!(
        gateway.dispatch_approved(key),
        Err(GatewayError::Approval(
            praetore_gateway::ApprovalError::NotPending
        ))
    ));
    let receipt = gateway.reconcile(key).unwrap();
    assert_eq!(receipt.execution, ExecutionStatus::Failed);
    assert_eq!(adapter.invocation_count(), 0);
    assert_eq!(database_invocation_count(key), 0);
}

const COPIED_TABLES: [&str; 5] = [
    "replay_claims",
    "execution_journal",
    "execution_attestations",
    "human_approvals",
    "human_approval_expirations",
];

/// Copies every row of `key` from the shared test database into `scratch`
/// verbatim, bypassing triggers and foreign keys (`replica`).
fn copy_execution_rows(scratch: &mut Client, key: ExecutionKey) {
    let mut source = connect_client();
    scratch
        .batch_execute("SET session_replication_role = replica")
        .unwrap();
    for table in COPIED_TABLES {
        let rows = source
            .query(
                &format!(
                    "SELECT row_to_json(t)::text FROM praetore.{table} t \
                     WHERE agent_id = $1 AND request_id = $2"
                ),
                &[&key.agent_id, &key.request_id],
            )
            .unwrap();
        for row in rows {
            let json: String = row.get(0);
            scratch
                .execute(
                    &format!(
                        "INSERT INTO praetore.{table} \
                         SELECT * FROM json_populate_record(NULL::praetore.{table}, $1::text::json)"
                    ),
                    &[&json],
                )
                .unwrap();
        }
    }
}

fn scratch_journal(scratch: &ScratchDatabase) -> PostgresExecutionJournal {
    let url = env::var("PRAETORE_TEST_DATABASE_URL").unwrap();
    let name = scratch.name.clone();
    PostgresExecutionJournal::from_connection_factory(move || {
        let mut config: postgres::Config = url.parse()?;
        config.dbname(&name);
        config.connect(NoTls)
    })
    .unwrap()
}

/// `parse_record` must reject APD rows the SQL constraints would never
/// allow. The rows are forged in a scratch copy with those constraints and
/// triggers removed, so only the Rust check stands between them and use.
#[test]
#[ignore = "requires a PostgreSQL superuser; run in assurance CI"]
fn postgres_apd_parse_record_rejects_forged_apd_rows() {
    let clock = SharedClock::at_test_now();
    let fixture = create_postgres_approval_gateway_with_clock(Uuid::new_v4(), Some(clock.clone()));
    let approved = approved_pending(&fixture);

    // A second request that is signed-for but expires while pending, so it
    // carries a genuine ApprovalExpiredReceipt.
    let other = create_postgres_approval_gateway_with_clock(Uuid::new_v4(), Some(clock.clone()));
    let pending = fixture.gateway.execute(other.request.clone()).unwrap();
    let expired = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    let decision = sign_approval(&fixture, expired);
    *clock.0.lock().unwrap() += Duration::seconds(25);
    assert!(matches!(
        fixture.gateway.resolve_human_approval(decision.clone()),
        Err(GatewayError::Approval(
            praetore_gateway::ApprovalError::Expired
        ))
    ));
    assert!(
        connect_journal()
            .get(expired)
            .unwrap()
            .unwrap()
            .approval_expiration
            .is_some()
    );

    let scratch_db = ScratchDatabase::create();
    let mut scratch = scratch_db.connect();
    praetore_replay_postgres::apply_migrations(&mut scratch).unwrap();
    copy_execution_rows(&mut scratch, approved);
    copy_execution_rows(&mut scratch, expired);
    let journal = scratch_journal(&scratch_db);
    // Controls: the faithful copies parse.
    assert_eq!(
        journal.get(approved).unwrap().unwrap().execution,
        ExecutionStatus::ApprovedPendingDispatch
    );
    assert!(
        journal
            .get(expired)
            .unwrap()
            .unwrap()
            .approval_expiration
            .is_some()
    );

    scratch
        .batch_execute(
            "ALTER TABLE praetore.execution_journal \
                 DROP CONSTRAINT execution_journal_authorization_execution_v2",
        )
        .unwrap();
    let where_key = "WHERE agent_id = $1 AND request_id = $2";

    // APD with an `allowed` authorization.
    scratch
        .execute(
            &format!(
                "UPDATE praetore.execution_journal SET authorization_status = 'allowed' {where_key}"
            ),
            &[&approved.agent_id, &approved.request_id],
        )
        .unwrap();
    assert!(matches!(
        journal.get(approved),
        Err(JournalError::InvalidRecord)
    ));

    // APD with an approve decision *and* an expiration receipt.
    scratch
        .execute(
            &format!(
                "INSERT INTO praetore.human_approvals (approval_id, tenant_id, agent_id, request_id, \
                     evidence_id, evidence_hash, action_digest, policy_digest, outcome, \
                     approver_key_id, expires_at, decision_json) \
                 SELECT $3, tenant_id, agent_id, request_id, evidence_id, evidence_hash, \
                     action_digest, policy_digest, 'approve', $4, expires_at, $5::text::jsonb \
                 FROM praetore.human_approval_expirations {where_key}"
            ),
            &[
                &expired.agent_id,
                &expired.request_id,
                &decision.approval_id,
                &decision.approver_key_id,
                &serde_json::to_string(&decision).unwrap(),
            ],
        )
        .unwrap();
    scratch
        .execute(
            &format!(
                "UPDATE praetore.execution_journal \
                 SET execution_status = 'approved_pending_dispatch' {where_key}"
            ),
            &[&expired.agent_id, &expired.request_id],
        )
        .unwrap();
    assert!(matches!(
        journal.get(expired),
        Err(JournalError::InvalidRecord)
    ));
}

const CRASH_CHILD_ENV: &str = "PRAETORE_APD_CRASH_CHILD";
const CRASH_RECONCILE_ENV: &str = "PRAETORE_APD_CRASH_RECONCILE";

/// Re-runs this test binary to execute exactly one helper test.
fn helper_process(test: &str) -> std::process::Command {
    let mut command = std::process::Command::new(env::current_exe().unwrap());
    command.args([
        "--ignored",
        "--exact",
        test,
        "--nocapture",
        "--test-threads=1",
    ]);
    command
}

/// Child half of the real-crash test: approves, reports the key, then hangs
/// forever before claiming so the parent can SIGKILL it. A no-op unless the
/// parent sets `PRAETORE_APD_CRASH_CHILD`.
#[test]
#[ignore = "helper process for postgres_apd_sigkill_between_approve_and_claim"]
fn crash_helper_approve_then_hang() {
    let Ok(request_id) = env::var(CRASH_CHILD_ENV) else {
        return;
    };
    let fixture = create_postgres_approval_gateway(request_id.parse().unwrap());
    let key = approved_pending(&fixture);
    println!("APD_READY {} {}", key.agent_id, key.request_id);
    loop {
        thread::park();
    }
}

/// Second process of the real-crash test: reconciles the orphaned APD row.
#[test]
#[ignore = "helper process for postgres_apd_sigkill_between_approve_and_claim"]
fn crash_helper_reconcile() {
    let Ok(value) = env::var(CRASH_RECONCILE_ENV) else {
        return;
    };
    let (agent_id, request_id) = value.split_once(' ').unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: agent_id.parse().unwrap(),
        request_id: request_id.parse().unwrap(),
    };
    let fixture = create_postgres_approval_gateway(Uuid::new_v4());
    let (gateway, adapter) = second_gateway(&fixture);
    let receipt = gateway.reconcile(key).unwrap();
    assert_eq!(receipt.execution, ExecutionStatus::NotDispatched);
    assert_eq!(
        receipt.execution_attestation.not_dispatched_reason,
        Some(NotDispatchedReason::CrashRecovered)
    );
    assert_eq!(adapter.invocation_count(), 0);
    println!("RECONCILED not_dispatched crash_recovered");
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_apd_sigkill_between_approve_and_claim() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;

    initialize_test_database();
    let mut child = helper_process("crash_helper_approve_then_hang")
        .env(CRASH_CHILD_ENV, Uuid::new_v4().to_string())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = None;
    for line in BufReader::new(child.stdout.take().unwrap()).lines() {
        let line = line.unwrap();
        // libtest prints "test <name> ... " on the same line first.
        if let Some((_, rest)) = line.split_once("APD_READY ") {
            ready = Some(rest.trim().to_owned());
            break;
        }
    }
    let ready = ready.expect("child must report APD before it is killed");
    let (agent_id, request_id) = ready.split_once(' ').unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: agent_id.parse().unwrap(),
        request_id: request_id.parse().unwrap(),
    };
    assert_eq!(
        connect_journal().get(key).unwrap().unwrap().execution,
        ExecutionStatus::ApprovedPendingDispatch
    );
    child.kill().unwrap(); // SIGKILL on Unix
    let status = child.wait().unwrap();
    assert_eq!(status.signal(), Some(9), "child must die by SIGKILL");

    let output = helper_process("crash_helper_reconcile")
        .env(CRASH_RECONCILE_ENV, ready.clone())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("RECONCILED not_dispatched crash_recovered"),
        "reconcile process failed: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let record = connect_journal().get(key).unwrap().unwrap();
    assert_eq!(record.execution, ExecutionStatus::NotDispatched);
    assert_eq!(
        database_not_dispatched_reason(key).as_deref(),
        Some("crash_recovered")
    );
    // The effect never happened in any process.
    assert_eq!(database_invocation_count(key), 0);
    assert_eq!(database_effect_count(key), 0);
    assert!(
        !database_transitions(key)
            .iter()
            .any(|(_, to)| to == "dispatched")
    );
}

/// APD -> dispatched through raw SQL with an optional
/// `praetore.dispatch_observed_at`.
fn sql_claim(
    client: &mut Client,
    key: ExecutionKey,
    observed_at: Option<OffsetDateTime>,
) -> Result<u64, postgres::Error> {
    let mut transaction = client.transaction().unwrap();
    transaction
        .query_one(
            "SELECT set_config('praetore.tenant_id', $1, true)",
            &[&key.tenant_id.to_string()],
        )
        .unwrap();
    if let Some(observed_at) = observed_at {
        let observed_at = observed_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        transaction
            .query_one(
                "SELECT set_config('praetore.dispatch_observed_at', $1, true)",
                &[&observed_at],
            )
            .unwrap();
    }
    let changed = transaction.execute(
        "UPDATE praetore.execution_journal \
         SET execution_status = 'dispatched', updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
        &[&key.tenant_id, &key.agent_id, &key.request_id],
    )?;
    transaction.commit()?;
    Ok(changed)
}

fn approval_expires_at(key: ExecutionKey) -> OffsetDateTime {
    connect_client()
        .query_one(
            "SELECT expires_at FROM praetore.human_approvals \
             WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
            &[&key.tenant_id, &key.agent_id, &key.request_id],
        )
        .unwrap()
        .get(0)
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_sql_refuses_dispatch_of_an_expired_or_expiration_receipted_approval() {
    let mut admin = connect_client();
    let fixture = create_postgres_approval_gateway(Uuid::new_v4());
    let key = approved_pending(&fixture);
    let expires_at = approval_expires_at(key);

    // Bypassing claim_dispatch: no observation time, or one at/after expiry.
    for observed_at in [None, Some(expires_at), Some(expires_at + Duration::days(1))] {
        assert!(
            sql_claim(&mut admin, key, observed_at).is_err(),
            "dispatch accepted with observed_at {observed_at:?}"
        );
    }
    assert_eq!(
        connect_journal().get(key).unwrap().unwrap().execution,
        ExecutionStatus::ApprovedPendingDispatch
    );

    // An expiration receipt blocks dispatch even with a valid observation
    // time. APD and a receipt are exclusive under the 0009 triggers, so the
    // receipt is planted with triggers disabled (replica role).
    admin
        .batch_execute("SET session_replication_role = replica")
        .unwrap();
    admin
        .execute(
            "INSERT INTO praetore.human_approval_expirations \
                 (tenant_id, agent_id, request_id, evidence_id, evidence_hash, action_digest, \
                  policy_digest, expires_at, observed_at, gateway_key_id, signature, \
                  receipt_json, receipt_id) \
             VALUES ($1, $2, $3, $4, $5, $5, $5, $6, $6, 'planted', $7, '{}'::jsonb, $4)",
            &[
                &key.tenant_id,
                &key.agent_id,
                &key.request_id,
                &Uuid::new_v4(),
                &"0".repeat(64),
                &expires_at,
                &"0".repeat(128),
            ],
        )
        .unwrap();
    admin
        .batch_execute("SET session_replication_role = origin")
        .unwrap();
    assert!(sql_claim(&mut admin, key, Some(expires_at - Duration::seconds(1))).is_err());
    admin
        .batch_execute("SET session_replication_role = replica")
        .unwrap();
    admin
        .execute(
            "DELETE FROM praetore.human_approval_expirations \
             WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
            &[&key.tenant_id, &key.agent_id, &key.request_id],
        )
        .unwrap();
    admin
        .batch_execute("SET session_replication_role = origin")
        .unwrap();

    // Live approval, no receipt, observation before expiry: allowed.
    assert_eq!(
        sql_claim(&mut admin, key, Some(expires_at - Duration::seconds(1))).unwrap(),
        1
    );
    assert_eq!(
        connect_journal().get(key).unwrap().unwrap().execution,
        ExecutionStatus::Dispatched
    );
}

/// Password for the role-separation test roles (CI uses password auth).
const TEST_ROLE_PASSWORD: &str = "praetore-storage-test";

/// Creates (once) a cluster role for role-separation tests. All names are
/// prefixed `praetore_storage_`.
fn ensure_test_role(admin: &mut Client, name: &str, options: &str) {
    admin
        .batch_execute(&format!(
            "DO $$ BEGIN CREATE ROLE {name} {options}; \
             EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$; \
             ALTER ROLE {name} {options} PASSWORD '{TEST_ROLE_PASSWORD}'"
        ))
        .unwrap();
}

fn connect_scratch_as(scratch: &ScratchDatabase, user: &str) -> Client {
    let url = env::var("PRAETORE_TEST_DATABASE_URL").unwrap();
    let mut config: postgres::Config = url.parse().unwrap();
    config
        .dbname(&scratch.name)
        .user(user)
        .password(TEST_ROLE_PASSWORD);
    config.connect(NoTls).expect("connect as test role")
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_runtime_role_must_not_own_or_bypass_the_schema() {
    use praetore_replay_postgres::{RuntimeRoleError, verify_runtime_role};
    let scratch = ScratchDatabase::create();
    let mut admin = scratch.connect();
    praetore_replay_postgres::apply_migrations(&mut admin).unwrap();
    ensure_test_role(&mut admin, "praetore_storage_runtime", "LOGIN NOBYPASSRLS");
    ensure_test_role(&mut admin, "praetore_storage_owner", "LOGIN NOBYPASSRLS");
    ensure_test_role(
        &mut admin,
        "praetore_storage_owner_member",
        "LOGIN NOBYPASSRLS",
    );
    ensure_test_role(&mut admin, "praetore_storage_bypass", "LOGIN BYPASSRLS");
    ensure_test_role(&mut admin, "praetore_storage_creator", "LOGIN NOBYPASSRLS");
    ensure_test_role(
        &mut admin,
        "praetore_storage_createrole",
        "LOGIN NOBYPASSRLS CREATEROLE",
    );
    ensure_test_role(
        &mut admin,
        "praetore_storage_grant_all",
        "LOGIN NOBYPASSRLS",
    );
    ensure_test_role(&mut admin, "praetore_storage_writer", "LOGIN NOBYPASSRLS");
    // pg_write_all_data is cluster-wide: no other test's runtime check may
    // run until it is revoked below.
    let exclusive = CLUSTER_WIDE_GRANTS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    admin
        .batch_execute(
            "GRANT praetore_runtime TO praetore_storage_runtime; \
             GRANT praetore_runtime TO praetore_storage_bypass; \
             GRANT praetore_runtime TO praetore_storage_creator; \
             GRANT praetore_storage_owner TO praetore_storage_owner_member; \
             GRANT USAGE ON SCHEMA praetore TO praetore_storage_owner; \
             CREATE TABLE praetore.owner_probe (id INT); \
             ALTER TABLE praetore.owner_probe OWNER TO praetore_storage_owner; \
             GRANT CREATE ON SCHEMA praetore TO praetore_storage_creator; \
             GRANT praetore_runtime TO praetore_storage_createrole; \
             GRANT praetore_runtime TO praetore_storage_grant_all; \
             GRANT ALL ON ALL TABLES IN SCHEMA praetore TO praetore_storage_grant_all; \
             GRANT praetore_runtime TO praetore_storage_writer; \
             GRANT pg_write_all_data TO praetore_storage_writer",
        )
        .unwrap();

    // Superuser, also when it SET ROLEs to a least-privilege role.
    assert!(matches!(
        verify_runtime_role(&mut admin),
        Err(RuntimeRoleError::PrivilegedRole(_))
    ));
    admin
        .batch_execute("SET ROLE praetore_storage_runtime")
        .unwrap();
    assert!(matches!(
        verify_runtime_role(&mut admin),
        Err(RuntimeRoleError::PrivilegedRole(role)) if role == "postgres"
    ));
    admin.batch_execute("RESET ROLE").unwrap();

    for (user, expected) in [
        ("praetore_storage_bypass", "privileged"),
        ("praetore_storage_owner", "owner"),
        ("praetore_storage_owner_member", "owner"),
        ("praetore_storage_creator", "create"),
        ("praetore_storage_createrole", "privileged"),
        ("praetore_storage_grant_all", "excess"),
        ("praetore_storage_writer", "excess"),
    ] {
        let result = verify_runtime_role(&mut connect_scratch_as(&scratch, user));
        let matched = matches!(
            (&result, expected),
            (Err(RuntimeRoleError::PrivilegedRole(_)), "privileged")
                | (Err(RuntimeRoleError::OwnsSchemaObjects(_)), "owner")
                | (Err(RuntimeRoleError::CanCreateInSchema(_)), "create")
                | (Err(RuntimeRoleError::ExcessTablePrivilege(_)), "excess")
        );
        assert!(matched, "{user}: {result:?}");
    }

    // The grants made above for the other roles are not ones the migrations
    // make, so even the least-privilege runtime role is refused while they
    // exist.
    let mut runtime = connect_scratch_as(&scratch, "praetore_storage_runtime");
    assert!(matches!(
        verify_runtime_role(&mut runtime),
        Err(RuntimeRoleError::UnexpectedGrant(_))
    ));
    admin
        .batch_execute(
            "DROP TABLE praetore.owner_probe; \
             REVOKE CREATE ON SCHEMA praetore FROM praetore_storage_creator; \
             REVOKE USAGE ON SCHEMA praetore FROM praetore_storage_owner; \
             REVOKE ALL ON ALL TABLES IN SCHEMA praetore FROM praetore_storage_grant_all; \
             REVOKE pg_write_all_data FROM praetore_storage_writer",
        )
        .unwrap();
    drop(exclusive);

    // A login member of praetore_runtime passes and has the grants the
    // runtime needs: schema check and a replay claim.
    verify_runtime_role(&mut runtime).unwrap();
    praetore_replay_postgres::verify_schema_current(&mut runtime).unwrap();
    // The runtime role is not the schema owner, so it may not migrate.
    let rerun = praetore_replay_postgres::apply_migrations(&mut runtime);
    assert!(
        matches!(
            rerun,
            Err(praetore_replay_postgres::MigrationError::UnsafeDatabase(_))
        ),
        "{rerun:?}"
    );
    let guard = PostgresReplayGuard::from_client(runtime);
    let (agent, request) = (Uuid::new_v4(), Uuid::new_v4());
    guard.claim_once(TEST_TENANT_ID, agent, request).unwrap();
    assert!(matches!(
        guard.claim_once(TEST_TENANT_ID, agent, request),
        Err(ReplayGuardError::AlreadyClaimed)
    ));
    // The runtime role cannot defeat the append-only design.
    let mut runtime = connect_scratch_as(&scratch, "praetore_storage_runtime");
    for statement in [
        "ALTER TABLE praetore.execution_journal NO FORCE ROW LEVEL SECURITY",
        "ALTER TABLE praetore.execution_journal_events DISABLE TRIGGER USER",
        "DELETE FROM praetore.replay_claims",
        "TRUNCATE praetore.human_approvals",
        "CREATE TABLE praetore.runtime_probe (id INT)",
        "UPDATE praetore.execution_journal SET evidence_json = evidence_json",
    ] {
        assert!(runtime.batch_execute(statement).is_err(), "{statement}");
    }
    drop(runtime);
    drop(guard);
}

/// Regression for the human-approval race across gateway instances, in the
/// two-step flow: two gateways (own journal connections, own adapters, same
/// database) resolve the same pending request concurrently, then both race
/// the dispatch claim. Even iterations submit the same signed decision twice
/// (caught by the `approval_id` key); odd iterations submit two distinct
/// valid decisions for the same challenge, which only the row lock and the
/// status re-check in `record_human_approval` can serialize.
#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_concurrent_human_approval_dispatches_exactly_once() {
    for race in 0..20 {
        let fixture = create_postgres_approval_gateway(Uuid::new_v4());
        let pending = fixture.gateway.execute(fixture.request.clone()).unwrap();
        assert_eq!(
            pending.evidence.decision.outcome,
            DecisionOutcome::RequireApproval
        );
        let key = ExecutionKey {
            tenant_id: TEST_TENANT_ID,
            agent_id: *pending.evidence.agent.id.as_uuid(),
            request_id: pending.evidence.request_id,
        };
        let first_decision = sign_approval(&fixture, key);
        let second_decision = if race % 2 == 0 {
            first_decision.clone()
        } else {
            sign_approval(&fixture, key)
        };
        let (other, other_adapter) = second_gateway(&fixture);
        let gateways = [&fixture.gateway, &other];
        let decisions = [first_decision, second_decision];

        // Phase 1: concurrent approval of the same pending request.
        let barrier = std::sync::Barrier::new(2);
        let approvals: Vec<Result<HumanApprovalResult, GatewayError>> = thread::scope(|scope| {
            let handles: Vec<_> = gateways
                .iter()
                .zip(decisions.iter().cloned())
                .map(|(gateway, decision)| {
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        gateway.resolve_human_approval(decision)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let approved: Vec<_> = approvals
            .iter()
            .filter_map(|result| match result {
                Ok(HumanApprovalResult::ApprovedPendingDispatch { decision }) => Some(decision),
                _ => None,
            })
            .collect();
        assert_eq!(approved.len(), 1, "race {race}: {approvals:?}");
        for result in &approvals {
            if let Err(error) = result {
                assert!(
                    matches!(
                        error,
                        GatewayError::Journal(
                            JournalError::ApprovalAlreadyRecorded | JournalError::InvalidRecord
                        ) | GatewayError::Approval(praetore_gateway::ApprovalError::NotPending)
                    ),
                    "race {race}: losing approval must be refused as already resolved, \
                     got {error:?}"
                );
            }
        }
        let winning_decision = approved[0].clone();
        assert_eq!(
            database_rows_for_request("praetore.human_approvals", key.request_id),
            1,
            "race {race}"
        );
        let record = connect_journal().get(key).unwrap().unwrap();
        assert_eq!(record.execution, ExecutionStatus::ApprovedPendingDispatch);
        assert_eq!(record.human_approval.as_ref(), Some(&winning_decision));
        assert_eq!(
            fixture.adapter.invocation_count() + other_adapter.invocation_count(),
            0,
            "race {race}: approval alone must never dispatch"
        );

        // Phase 2: both gateways load the pending dispatch, then race the claim.
        let barrier = std::sync::Barrier::new(2);
        let dispatches: Vec<Result<praetore_gateway::GatewayReceipt, GatewayError>> =
            thread::scope(|scope| {
                let handles: Vec<_> = gateways
                    .iter()
                    .map(|gateway| {
                        let barrier = &barrier;
                        scope.spawn(move || {
                            let pending = gateway.pending_dispatch(key);
                            barrier.wait();
                            let permit = gateway.claim_dispatch(pending?)?;
                            gateway.dispatch(permit)
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
        let winners: Vec<_> = dispatches.iter().filter_map(|r| r.as_ref().ok()).collect();
        assert_eq!(winners.len(), 1, "race {race}: {dispatches:?}");
        assert_eq!(winners[0].execution, ExecutionStatus::Confirmed);
        for result in &dispatches {
            if let Err(error) = result {
                assert!(
                    matches!(
                        error,
                        GatewayError::Journal(JournalError::InvalidTransition)
                    ),
                    "race {race}: losing claim must fail the CAS, got {error:?}"
                );
            }
        }

        assert_eq!(
            database_rows_for_request("praetore.human_approvals", key.request_id),
            1,
            "race {race}"
        );
        let record = connect_journal().get(key).unwrap().unwrap();
        assert_eq!(record.execution, ExecutionStatus::Confirmed);
        assert_eq!(record.human_approval, Some(winning_decision));
        assert_eq!(
            fixture.adapter.invocation_count() + other_adapter.invocation_count(),
            1,
            "race {race}"
        );
        assert_eq!(database_invocation_count(key), 1, "race {race}");
        assert_eq!(database_effect_count(key), 1, "race {race}");
    }
}

// ---------------------------------------------------------------------------
// dispatch_refused (0013), locked by 0014
// ---------------------------------------------------------------------------

const DISPATCH_REFUSED_CLOSE: &str =
    "execution_status = 'not_dispatched', not_dispatched_reason = 'dispatch_refused'";

fn migration_checksum(sql: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(sql.as_bytes()))
}

fn db_message(error: postgres::Error) -> String {
    error
        .as_db_error()
        .map(|db| db.message().to_owned())
        .unwrap_or_else(|| error.to_string())
}

fn insert_human_approval(client: &mut Client, key: ExecutionKey) -> Result<u64, postgres::Error> {
    let mut transaction = client.transaction().unwrap();
    transaction
        .query_one(
            "SELECT set_config('praetore.tenant_id', $1, true)",
            &[&key.tenant_id.to_string()],
        )
        .unwrap();
    let digest = "0".repeat(64);
    let inserted = transaction.execute(
        "INSERT INTO praetore.human_approvals \
             (approval_id, tenant_id, agent_id, request_id, evidence_id, evidence_hash, \
              action_digest, policy_digest, outcome, approver_key_id, expires_at, decision_json) \
         VALUES ($1, $2, $3, $4, $5, $6, $6, $6, 'approve', 'sql-test', \
                 clock_timestamp() + interval '1 minute', '{}'::jsonb)",
        &[
            &Uuid::new_v4(),
            &key.tenant_id,
            &key.agent_id,
            &key.request_id,
            &Uuid::new_v4(),
            &digest,
        ],
    )?;
    transaction.commit()?;
    Ok(inserted)
}

fn tenant_scoped<T>(
    client: &mut Client,
    tenant: Uuid,
    body: impl FnOnce(&mut postgres::Transaction<'_>) -> Result<T, postgres::Error>,
) -> Result<T, postgres::Error> {
    let mut transaction = client.transaction().unwrap();
    transaction
        .batch_execute("SET LOCAL ROLE praetore_replay_test")
        .unwrap();
    transaction
        .query_one(
            "SELECT set_config('praetore.tenant_id', $1, true)",
            &[&tenant.to_string()],
        )
        .unwrap();
    let value = body(&mut transaction)?;
    transaction.commit()?;
    Ok(value)
}

fn authorized_allowed_key() -> ExecutionKey {
    let allowed = create_postgres_gateway(Uuid::new_v4());
    let evidence = evaluate_and_commit(&allowed, allowed.request.clone());
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *evidence.agent.id.as_uuid(),
        request_id: evidence.request_id,
    };
    assert_eq!(
        connect_journal().get(key).unwrap().unwrap().execution,
        ExecutionStatus::Authorized
    );
    key
}

fn undecided_approval_key() -> ExecutionKey {
    let fixture = create_postgres_approval_gateway(Uuid::new_v4());
    let pending = fixture.gateway.execute(fixture.request.clone()).unwrap();
    assert_eq!(
        pending.evidence.decision.outcome,
        DecisionOutcome::RequireApproval
    );
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *pending.evidence.agent.id.as_uuid(),
        request_id: pending.evidence.request_id,
    };
    assert_eq!(
        connect_journal().get(key).unwrap().unwrap().execution,
        ExecutionStatus::NotDispatched
    );
    assert!(database_not_dispatched_reason(key).is_none());
    assert_eq!(
        database_rows_for_request("praetore.human_approvals", key.request_id),
        0
    );
    key
}

fn journal_execution_status(key: ExecutionKey) -> String {
    connect_client()
        .query_one(
            "SELECT execution_status FROM praetore.execution_journal \
             WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
            &[&key.tenant_id, &key.agent_id, &key.request_id],
        )
        .unwrap()
        .get(0)
}

fn journal_visible_to(client: &mut Client, tenant: Uuid, key: ExecutionKey) -> i64 {
    tenant_scoped(client, tenant, |transaction| {
        transaction
            .query_one(
                "SELECT count(*) FROM praetore.execution_journal \
                 WHERE agent_id = $1 AND request_id = $2",
                &[&key.agent_id, &key.request_id],
            )
            .map(|row| row.get(0))
    })
    .unwrap()
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_dispatch_refused_close_is_final_and_tenant_isolated() {
    let mut admin = connect_client();

    let allowed = authorized_allowed_key();
    assert_eq!(
        admin_update(&mut admin, allowed, DISPATCH_REFUSED_CLOSE).unwrap(),
        1
    );
    assert_eq!(journal_execution_status(allowed), "not_dispatched");
    assert_eq!(
        database_not_dispatched_reason(allowed).as_deref(),
        Some("dispatch_refused")
    );
    let write_once =
        db_message(admin_update(&mut admin, allowed, "not_dispatched_reason = NULL").unwrap_err());
    assert!(write_once.contains("write-once"), "{write_once}");
    let reopen = db_message(
        admin_update(
            &mut admin,
            allowed,
            "execution_status = 'approved_pending_dispatch'",
        )
        .unwrap_err(),
    );
    assert!(
        reopen.contains("invalid execution journal state transition"),
        "{reopen}"
    );
    assert!(reopen.contains("approved_pending_dispatch"), "{reopen}");
    assert_eq!(
        database_not_dispatched_reason(allowed).as_deref(),
        Some("dispatch_refused")
    );
    let closed = db_message(insert_human_approval(&mut admin, allowed).unwrap_err());
    assert!(
        closed.contains("execution is closed without dispatch"),
        "{closed}"
    );

    let undecided = undecided_approval_key();
    assert_eq!(
        admin_update(&mut admin, undecided, DISPATCH_REFUSED_CLOSE).unwrap(),
        1
    );
    assert_eq!(journal_execution_status(undecided), "not_dispatched");
    assert_eq!(
        database_not_dispatched_reason(undecided).as_deref(),
        Some("dispatch_refused")
    );
    let write_once = db_message(
        admin_update(
            &mut admin,
            undecided,
            "not_dispatched_reason = 'approval_expired'",
        )
        .unwrap_err(),
    );
    assert!(write_once.contains("write-once"), "{write_once}");
    let reopen = db_message(
        admin_update(
            &mut admin,
            undecided,
            "execution_status = 'approved_pending_dispatch'",
        )
        .unwrap_err(),
    );
    assert!(
        reopen.contains("invalid execution journal state transition"),
        "{reopen}"
    );
    assert!(reopen.contains("approved_pending_dispatch"), "{reopen}");
    let closed = db_message(insert_human_approval(&mut admin, undecided).unwrap_err());
    assert!(
        closed.contains("execution is closed without dispatch"),
        "{closed}"
    );
    assert_eq!(
        database_rows_for_request("praetore.human_approvals", undecided.request_id),
        0
    );
    assert_eq!(
        database_not_dispatched_reason(undecided).as_deref(),
        Some("dispatch_refused")
    );

    let other_tenant = Uuid::new_v4();
    assert_eq!(
        journal_visible_to(&mut admin, undecided.tenant_id, undecided),
        1
    );
    assert_eq!(journal_visible_to(&mut admin, other_tenant, undecided), 0);
    let changed = tenant_scoped(&mut admin, other_tenant, |transaction| {
        transaction.execute(
            "UPDATE praetore.execution_journal \
             SET not_dispatched_reason = NULL, updated_at = clock_timestamp() \
             WHERE agent_id = $1 AND request_id = $2",
            &[&undecided.agent_id, &undecided.request_id],
        )
    })
    .unwrap();
    assert_eq!(changed, 0);
    let digest = "0".repeat(64);
    let inserted = tenant_scoped(&mut admin, other_tenant, |transaction| {
        transaction.execute(
            "INSERT INTO praetore.human_approvals \
                 (approval_id, tenant_id, agent_id, request_id, evidence_id, evidence_hash, \
                  action_digest, policy_digest, outcome, approver_key_id, expires_at, \
                  decision_json) \
             VALUES ($1, $2, $3, $4, $5, $6, $6, $6, 'approve', 'sql-test', \
                     clock_timestamp() + interval '1 minute', '{}'::jsonb)",
            &[
                &Uuid::new_v4(),
                &undecided.tenant_id,
                &undecided.agent_id,
                &undecided.request_id,
                &Uuid::new_v4(),
                &digest,
            ],
        )
    });
    assert!(
        inserted.is_err(),
        "tenant B inserted an approval for tenant A: {inserted:?}"
    );
    assert_eq!(
        database_not_dispatched_reason(undecided).as_deref(),
        Some("dispatch_refused")
    );
    assert_eq!(
        database_rows_for_request("praetore.human_approvals", undecided.request_id),
        0
    );
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_closed_execution_and_approval_exclude_each_other() {
    let races = 32;
    let mut closes = 0;
    let mut approvals = 0;
    for race in 0..races {
        let key = undecided_approval_key();
        let mut closer = connect_client();
        let mut approver = connect_client();
        let barrier = std::sync::Barrier::new(2);
        let (closed, approved) = thread::scope(|scope| {
            let barrier = &barrier;
            let close = scope.spawn(|| {
                barrier.wait();
                admin_update(&mut closer, key, DISPATCH_REFUSED_CLOSE)
            });
            let approve = scope.spawn(|| {
                barrier.wait();
                insert_human_approval(&mut approver, key)
            });
            (close.join().unwrap(), approve.join().unwrap())
        });
        // Exactly one side wins. Which side is timing; the split is not asserted.
        assert!(
            closed.is_ok() ^ approved.is_ok(),
            "race {race}: exactly one side wins; close={closed:?} approval={approved:?}"
        );
        match (closed, approved) {
            (Ok(changed), Err(error)) => {
                assert_eq!(changed, 1, "race {race}");
                let message = db_message(error);
                assert!(
                    message.contains("execution is closed without dispatch"),
                    "race {race}: {message}"
                );
                closes += 1;
            }
            (Err(error), Ok(changed)) => {
                assert_eq!(changed, 1, "race {race}");
                let message = db_message(error);
                assert!(message.contains("write-once"), "race {race}: {message}");
                approvals += 1;
            }
            (closed, approved) => {
                panic!("race {race}: close={closed:?} approval={approved:?}");
            }
        }
        let reason = database_not_dispatched_reason(key);
        let decisions = database_rows_for_request("praetore.human_approvals", key.request_id);
        let closed_row = reason.as_deref() == Some("dispatch_refused");
        let approved_row = decisions == 1;
        assert!(
            !(closed_row && approved_row),
            "race {race}: closure and an approval are both present (reason={reason:?}, decisions={decisions})"
        );
        assert_eq!(
            journal_execution_status(key),
            "not_dispatched",
            "race {race}"
        );
        if closed_row {
            assert_eq!(decisions, 0, "race {race}");
        } else {
            assert!(reason.is_none(), "race {race}: {reason:?}");
            assert!(approved_row, "race {race}: decisions={decisions}");
        }
    }
    println!("closed-execution races: {races} run, {closes} closes won, {approvals} approvals won");
}

#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_transition_v2_function_is_dropped() {
    initialize_test_database();
    let mut client = connect_client();
    {
        let mut function_count = |name: &str| -> i64 {
            client
                .query_one(
                    "SELECT count(*) FROM pg_proc p \
                     JOIN pg_namespace n ON n.oid = p.pronamespace \
                     WHERE n.nspname = 'praetore' AND p.proname = $1",
                    &[&name],
                )
                .unwrap()
                .get(0)
        };
        assert_eq!(
            function_count("validate_execution_journal_transition_v2"),
            0
        );
        assert_eq!(
            function_count("validate_execution_journal_transition_v3"),
            1
        );
    }
    let referencing_triggers: i64 = client
        .query_one(
            "SELECT count(*) FROM pg_trigger tg \
             JOIN pg_proc p ON p.oid = tg.tgfoid \
             JOIN pg_namespace n ON n.oid = p.pronamespace \
             WHERE n.nspname = 'praetore' \
               AND p.proname = 'validate_execution_journal_transition_v2'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(referencing_triggers, 0);

    let row = client
        .query_one(
            "SELECT p.prosecdef, pg_get_functiondef(p.oid), \
                    has_function_privilege('public', p.oid, 'EXECUTE'), tg.tgname \
             FROM pg_proc p \
             JOIN pg_namespace n ON n.oid = p.pronamespace \
             JOIN pg_trigger tg ON tg.tgfoid = p.oid AND NOT tg.tgisinternal \
             WHERE n.nspname = 'praetore' \
               AND p.proname = 'refuse_decision_for_closed_execution'",
            &[],
        )
        .unwrap();
    let security_definer: bool = row.get(0);
    let definition: String = row.get(1);
    let public_execute: bool = row.get(2);
    let trigger: String = row.get(3);
    assert!(!security_definer);
    assert!(!definition.contains("SECURITY DEFINER"), "{definition}");
    assert!(definition.contains("FOR UPDATE"), "{definition}");
    assert!(definition.contains("search_path"), "{definition}");
    assert!(definition.contains("pg_catalog"), "{definition}");
    assert!(definition.contains("pg_temp"), "{definition}");
    assert!(!public_execute);
    assert_eq!(trigger, "human_approvals_refuse_closed_execution");
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_migrations_0013_database_applies_only_0014() {
    let scratch = ScratchDatabase::create();
    let mut client = scratch.connect();
    let end = praetore_replay_postgres::MIGRATIONS
        .iter()
        .position(|(version, _)| *version == "0014_closed_execution_row_lock")
        .expect("0014 is registered");
    // 0011 grants on this table. The runner creates it before any migration;
    // a database already at 0013 has it, with 0001-0013 recorded.
    client
        .batch_execute(
            "CREATE SCHEMA IF NOT EXISTS praetore; \
             CREATE TABLE praetore.schema_migrations (\
                 version TEXT PRIMARY KEY, \
                 checksum CHAR(64) NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'), \
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
        )
        .unwrap();
    apply_legacy_migrations_through(&mut client, end);
    for (version, sql) in &praetore_replay_postgres::MIGRATIONS[..end] {
        client
            .execute(
                "INSERT INTO praetore.schema_migrations (version, checksum) VALUES ($1, $2)",
                &[version, &migration_checksum(sql)],
            )
            .unwrap();
    }
    let v2_before: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_proc p \
             JOIN pg_namespace n ON n.oid = p.pronamespace \
             WHERE n.nspname = 'praetore' \
               AND p.proname = 'validate_execution_journal_transition_v2')",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(v2_before, "0013 leaves the v2 function in place");

    let applied = praetore_replay_postgres::apply_migrations(&mut client).unwrap();
    let again = praetore_replay_postgres::apply_migrations(&mut client).unwrap();
    println!("0013 database applied {applied:?}; second run applied {again:?}");
    assert_eq!(
        applied,
        vec!["0014_closed_execution_row_lock", "0015_storage_records"]
    );
    assert!(again.is_empty());
    let v2_after: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_proc p \
             JOIN pg_namespace n ON n.oid = p.pronamespace \
             WHERE n.nspname = 'praetore' \
               AND p.proname = 'validate_execution_journal_transition_v2')",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(!v2_after);
    assert_eq!(recorded_versions(&mut client), all_versions());
}

/// G7: with the PostgreSQL journal down (its connection terminated and every
/// reconnect refused), the gateway HTTP API answers a safety action with
/// `safety_action_not_governed` within 100 ms, without calling the engine
/// and without a replay claim or journal row. The mission control request in
/// the same state reaches the engine and fails closed.
#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_g7_safety_action_is_refused_before_the_engine_with_the_journal_down() {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    initialize_test_database();
    let fixture = create_postgres_gateway(Uuid::new_v4());
    let policy_id = "postgres-g7-journal-down";
    let mut policy = fixture
        .policy
        .clone()
        .with_action_class("safety:halt", praetore_core::ActionClass::Safety);
    policy.id = policy_id.into();
    let mut request = fixture.request.clone();
    let now = FixedClock::try_new(TEST_NOW).unwrap().now();
    request
        .sign_intent_v2(
            &fixture.agent_key,
            "postgres-test-gateway",
            now,
            now + Duration::minutes(1),
            policy.digest().unwrap(),
        )
        .unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *request.agent.id.as_uuid(),
        request_id: request.request_id,
    };

    let url = env::var("PRAETORE_TEST_DATABASE_URL").unwrap();
    let down = Arc::new(AtomicBool::new(false));
    let journal = {
        let down = down.clone();
        PostgresExecutionJournal::from_connection_factory(move || {
            if down.load(Ordering::SeqCst) {
                // Any refused connection: the database is unreachable.
                return Client::connect(
                    "host=127.0.0.1 port=1 user=praetore connect_timeout=1",
                    NoTls,
                );
            }
            let mut client = Client::connect(&url, NoTls)?;
            client.batch_execute(
                "SET application_name = 'praetore-g7-journal-down'; SET ROLE praetore_replay_test",
            )?;
            Ok(client)
        })
        .unwrap()
    };
    down.store(true, Ordering::SeqCst);
    let terminated: i64 = connect_client()
        .query_one(
            "SELECT count(*) FROM (SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE application_name = 'praetore-g7-journal-down') AS terminated",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(terminated, 1, "the journal connection was terminated");

    let gateway = Gateway::new(
        create_test_engine(
            policy,
            fixture.issuer_public_key.clone(),
            fixture.attester.clone(),
        ),
        Arc::new(journal),
        fixture.adapter.clone(),
        execution_attester(),
    )
    .unwrap();
    let app = praetore_gateway::http_api::router(
        Arc::new(gateway),
        praetore_gateway::http_api::ApiAuth::UnauthenticatedLoopbackDemo,
    );
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let post = |body: Value| {
        let app = app.clone();
        runtime.block_on(async move {
            let request = Request::builder()
                .method("POST")
                .uri("/v1/execute")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            let started = std::time::Instant::now();
            let response = app.oneshot(request).await.unwrap();
            let elapsed = started.elapsed();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 65_536).await.unwrap();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            (status, body, elapsed)
        })
    };

    let mut safety = serde_json::to_value(&request).unwrap();
    safety["action"]["action_type"] = json!("safety:halt");
    let (status, body, elapsed) = post(safety);
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "safety_action_not_governed");
    assert!(
        elapsed < std::time::Duration::from_millis(100),
        "{elapsed:?}"
    );
    assert_eq!(praetore_core::probe::engine_calls(policy_id), 0);
    assert_eq!(database_replay_claim_count(key), 0);
    assert_eq!(database_journal_count(key), 0);
    assert_eq!(fixture.adapter.invocation_count(), 0);

    // Control: the mission request reaches the engine and fails closed.
    let (status, body, _) = post(serde_json::to_value(&request).unwrap());
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(praetore_core::probe::engine_calls(policy_id), 1);
    assert_eq!(database_replay_claim_count(key), 0);
    assert_eq!(database_journal_count(key), 0);
    assert_eq!(fixture.adapter.invocation_count(), 0);
}

/// G7: an undeclared action type is refused with a signed DENY that the
/// PostgreSQL journal commits atomically with its replay claim, like a
/// policy DENY; nothing is dispatched.
#[test]
#[ignore = "requires a PostgreSQL service; run in assurance CI"]
fn postgres_g7_unclassified_action_commits_a_signed_deny() {
    let fixture = create_postgres_gateway(Uuid::new_v4());
    let issuer_key = AgentKeyPair::from_secret_bytes(&[72; 32]);
    let agent = fixture.agent_key.identity(AgentId::new());
    let mut authority = Authority::new(
        agent.id.clone(),
        "gateway-test-issuer",
        vec!["local:write".into()],
    )
    .with_validity(test_validity())
    .with_constraint("tenant_id", TEST_TENANT_ID.to_string());
    authority.sign_for_agent(&issuer_key, &agent).unwrap();
    let action = Action::new(
        "local:delete_all",
        Some("persistent-state".into()),
        json!({}),
    )
    .unwrap()
    .with_capability("local:write");
    let mut request = AuthorizationRequest::new_unclassified(
        agent,
        authority,
        fixture.policy.unclassified(action).unwrap(),
    )
    .unwrap();
    let now = FixedClock::try_new(TEST_NOW).unwrap().now();
    request
        .sign_intent_v2(
            &fixture.agent_key,
            "postgres-test-gateway",
            now,
            now + Duration::minutes(1),
            fixture.policy.digest().unwrap(),
        )
        .unwrap();
    let key = ExecutionKey {
        tenant_id: TEST_TENANT_ID,
        agent_id: *request.agent.id.as_uuid(),
        request_id: request.request_id,
    };

    let receipt = fixture
        .gateway
        .refuse_unclassified(request.clone())
        .unwrap();

    assert_eq!(receipt.evidence.decision.outcome, DecisionOutcome::Deny);
    assert_eq!(
        receipt.evidence.decision.reason,
        praetore_core::UNCLASSIFIED_DENY_REASON
    );
    assert_eq!(receipt.execution, ExecutionStatus::NotDispatched);
    assert_eq!(database_journal_count(key), 1);
    assert_eq!(database_replay_claim_count(key), 1);
    assert_eq!(fixture.adapter.invocation_count(), 0);
    let persisted = connect_journal().get(key).unwrap().unwrap();
    assert_eq!(
        persisted.evidence.decision.reason,
        praetore_core::UNCLASSIFIED_DENY_REASON
    );
    // The same request again is a replay.
    assert!(fixture.gateway.refuse_unclassified(request).is_err());
    assert_eq!(database_journal_count(key), 1);
}

/// G7 test helper: declares every action type a rule names as Mission.
#[allow(dead_code)]
fn mission_policy(mut policy: praetore_core::Policy) -> praetore_core::Policy {
    for rule in &policy.rules {
        policy
            .action_classes
            .entry(rule.action_type.clone())
            .or_insert(praetore_core::ActionClass::Mission);
    }
    policy
}

/// G7 test helper: classifies `action` as a Mission action. The engine still
/// checks it against its own policy's `action_classes`.
#[allow(dead_code)]
fn mission(action: praetore_core::Action) -> praetore_core::MissionAction {
    praetore_core::Policy::new("classify", 1, vec![])
        .with_mission_actions([action.action_type.clone()])
        .classify(action)
        .expect("classify")
        .into_mission()
        .expect("mission action")
}
