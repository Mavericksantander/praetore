use postgres::{Client, NoTls};
use praetore_core::replay::{ReplayGuard, ReplayGuardError};
use praetore_replay_postgres::PostgresReplayGuard;
use std::{
    env,
    sync::{Arc, OnceLock},
    thread,
};
use uuid::Uuid;

static TEST_DATABASE_SETUP: OnceLock<()> = OnceLock::new();

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
            .batch_execute(
                "DO $$ BEGIN \
                     CREATE ROLE praetore_replay_test NOLOGIN; \
                 EXCEPTION WHEN duplicate_object THEN NULL; END $$; \
                 REVOKE ALL ON SCHEMA praetore FROM PUBLIC; \
                 REVOKE ALL ON TABLE praetore.replay_claims FROM PUBLIC; \
                 REVOKE ALL ON TABLE praetore.replay_claims FROM praetore_replay_test; \
                 GRANT USAGE ON SCHEMA praetore TO praetore_replay_test; \
                 GRANT INSERT (agent_id, request_id) ON praetore.replay_claims \
                     TO praetore_replay_test",
            )
            .expect("configure least-privilege test role");
    });
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
    let handles = (0..workers)
        .map(|_| {
            let barrier = barrier.clone();
            thread::spawn(move || {
                let guard = PostgresReplayGuard::from_client(connect_client());
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
