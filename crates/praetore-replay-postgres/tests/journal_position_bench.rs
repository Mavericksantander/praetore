//! Local measurements for migration 0024 (the per-tenant journal position),
//! not run by CI: run them by hand against a disposable PostgreSQL with
//!
//! ```text
//! PRAETORE_TEST_DATABASE_URL=... cargo test -p praetore-replay-postgres \
//!   --release --test journal_position_bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! They print numbers of one run on one machine; they assert nothing about
//! them. The throughput measurement uses only SQL that exists before and
//! after 0024, so the same file runs on a base without it.

use postgres::{Client, NoTls};
use std::{
    env,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

fn admin_url() -> String {
    env::var("PRAETORE_TEST_DATABASE_URL").expect("PRAETORE_TEST_DATABASE_URL is required")
}

/// A throwaway database, dropped on drop.
struct Scratch {
    name: String,
}

impl Scratch {
    fn create() -> Self {
        let name = format!("praetore_bench_{}", Uuid::new_v4().simple());
        Client::connect(&admin_url(), NoTls)
            .unwrap()
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .unwrap();
        Self { name }
    }

    fn config(&self) -> postgres::Config {
        let mut config: postgres::Config = admin_url().parse().unwrap();
        config.dbname(&self.name);
        config
    }

    fn connect(&self) -> Client {
        self.config().connect(NoTls).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Ok(mut admin) = Client::connect(&admin_url(), NoTls) {
            let _ = admin.batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            ));
        }
    }
}

/// One journal row as the gateway writes it (claim, then row, then
/// COMMIT with synchronous_commit on), with an evidence text of the size of
/// a real receipt. Returns (whole transaction, COMMIT alone).
fn write_one(client: &mut Client, tenant: Uuid, evidence: &str) -> (Duration, Duration) {
    let start = Instant::now();
    let mut transaction = client.transaction().unwrap();
    transaction
        .batch_execute("SET LOCAL synchronous_commit = on")
        .unwrap();
    transaction
        .execute(
            "SELECT pg_catalog.set_config('praetore.tenant_id', $1, true)",
            &[&tenant.to_string()],
        )
        .unwrap();
    let (agent, request) = (Uuid::new_v4(), Uuid::new_v4());
    transaction
        .execute(
            "INSERT INTO praetore.replay_claims (tenant_id, agent_id, request_id) \
             VALUES ($1, $2, $3)",
            &[&tenant, &agent, &request],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO praetore.execution_journal \
             (tenant_id, agent_id, request_id, request_digest, action_digest, \
              authorization_status, execution_status, evidence_json) \
             VALUES ($1, $2, $3, $4, $4, 'allowed', 'authorized', $5)",
            &[&tenant, &agent, &request, &"ab".repeat(32), &evidence],
        )
        .unwrap();
    let commit = Instant::now();
    transaction.commit().unwrap();
    (start.elapsed(), commit.elapsed())
}

fn percentile(sorted: &[Duration], p: f64) -> f64 {
    let index = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[index].as_secs_f64() * 1000.0
}

/// `threads` writers, `total` rows in all, every writer on its own tenant or
/// all on one.
fn run(threads: usize, total: usize, same_tenant: bool) {
    let scratch = Scratch::create();
    praetore_replay_postgres::apply_migrations(&mut scratch.connect()).unwrap();
    let evidence: String = (0..40)
        .map(|_| Uuid::new_v4().simple().to_string())
        .collect();
    let shared = Uuid::new_v4();
    let barrier = Arc::new(Barrier::new(threads));
    let started = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let config = scratch.config();
            let evidence = evidence.clone();
            let barrier = barrier.clone();
            let tenant = if same_tenant { shared } else { Uuid::new_v4() };
            thread::spawn(move || {
                let mut client = config.connect(NoTls).unwrap();
                barrier.wait();
                (0..total / threads)
                    .map(|_| write_one(&mut client, tenant, &evidence))
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut results: Vec<(Duration, Duration)> = handles
        .into_iter()
        .flat_map(|handle| handle.join().unwrap())
        .collect();
    let elapsed = started.elapsed();
    let rows = results.len();
    let mut whole: Vec<Duration> = results.iter().map(|(whole, _)| *whole).collect();
    results.sort_by_key(|(_, commit)| *commit);
    let commits: Vec<Duration> = results.iter().map(|(_, commit)| *commit).collect();
    whole.sort();
    println!(
        "{threads} writers, {} tenant(s), {rows} rows: {:.0} rows/s; COMMIT p50 {:.3} ms, \
         p99 {:.3} ms; whole transaction p50 {:.3} ms, p99 {:.3} ms",
        if same_tenant { 1 } else { threads },
        rows as f64 / elapsed.as_secs_f64(),
        percentile(&commits, 0.50),
        percentile(&commits, 0.99),
        percentile(&whole, 0.50),
        percentile(&whole, 0.99),
    );
}

#[test]
#[ignore = "local measurement; requires PRAETORE_TEST_DATABASE_URL"]
fn measure_concurrent_writers_same_tenant_and_distinct_tenants() {
    let version: String = Client::connect(&admin_url(), NoTls)
        .unwrap()
        .query_one("SELECT version()", &[])
        .unwrap()
        .get(0);
    let has_0024 = praetore_replay_postgres::MIGRATIONS
        .iter()
        .any(|(version, _)| *version == "0024_journal_commit_order_position");
    println!("{version}; migration 0024 present: {has_0024}");
    for same_tenant in [true, false] {
        run(8, 2_000, same_tenant);
    }
}

/// Migration 0024 on a database at 0023 with 10,000 journal rows: the time
/// of its SQL alone, the locks it holds on the journal when it ends, and
/// the time of the whole runner (which also compares the schema with a
/// scratch copy before and after).
#[test]
#[ignore = "local measurement; requires PRAETORE_TEST_DATABASE_URL"]
fn measure_migration_0024_on_10000_rows() {
    let Some(end) = praetore_replay_postgres::MIGRATIONS
        .iter()
        .position(|(version, _)| *version == "0024_journal_commit_order_position")
    else {
        println!("migration 0024 is not in this build; nothing to measure");
        return;
    };
    let scratch = Scratch::create();
    let mut admin = scratch.connect();
    admin
        .batch_execute(
            "CREATE SCHEMA IF NOT EXISTS praetore; \
             CREATE TABLE praetore.schema_migrations (\
                 version TEXT PRIMARY KEY, \
                 checksum CHAR(64) NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'), \
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
        )
        .unwrap();
    for (version, sql) in &praetore_replay_postgres::MIGRATIONS[..end] {
        admin.batch_execute(sql).unwrap();
        use sha2::Digest;
        admin
            .execute(
                "INSERT INTO praetore.schema_migrations (version, checksum) VALUES ($1, $2)",
                &[version, &hex::encode(sha2::Sha256::digest(sql.as_bytes()))],
            )
            .unwrap();
    }
    let evidence: String = (0..40)
        .map(|_| Uuid::new_v4().simple().to_string())
        .collect();
    let tenants: Vec<Uuid> = (0..10).map(|_| Uuid::new_v4()).collect();
    {
        let mut transaction = admin.transaction().unwrap();
        for index in 0..10_000 {
            let tenant = tenants[index % tenants.len()];
            let (agent, request) = (Uuid::new_v4(), Uuid::new_v4());
            transaction
                .execute(
                    "INSERT INTO praetore.replay_claims (tenant_id, agent_id, request_id) \
                     VALUES ($1, $2, $3)",
                    &[&tenant, &agent, &request],
                )
                .unwrap();
            transaction
                .execute(
                    "INSERT INTO praetore.execution_journal \
                     (tenant_id, agent_id, request_id, request_digest, action_digest, \
                      authorization_status, execution_status, evidence_json) \
                     VALUES ($1, $2, $3, $4, $4, 'allowed', 'authorized', $5)",
                    &[&tenant, &agent, &request, &"ab".repeat(32), &evidence],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
    }
    admin.batch_execute("ANALYZE").unwrap();

    // The migration's SQL alone, in a transaction that is rolled back.
    let sql = praetore_replay_postgres::MIGRATIONS[end].1;
    let mut transaction = admin.transaction().unwrap();
    let started = Instant::now();
    transaction.batch_execute(sql).unwrap();
    let body = started.elapsed();
    let locks: Vec<String> = transaction
        .query(
            "SELECT c.relname::text || ': ' || l.mode FROM pg_locks l \
             JOIN pg_class c ON c.oid = l.relation \
             WHERE l.pid = pg_backend_pid() AND l.granted \
               AND c.relname IN ('execution_journal', 'journal_positions') \
             ORDER BY 1",
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    transaction.rollback().unwrap();
    println!(
        "0024 SQL on 10,000 rows: {:.1} ms; locks held until COMMIT: {}",
        body.as_secs_f64() * 1000.0,
        locks.join(", ")
    );

    let started = Instant::now();
    let applied = praetore_replay_postgres::apply_migrations(&mut admin).unwrap();
    println!(
        "apply_migrations (0024 and the runner's checks): {:.1} ms, applied {applied:?}",
        started.elapsed().as_secs_f64() * 1000.0
    );
}
