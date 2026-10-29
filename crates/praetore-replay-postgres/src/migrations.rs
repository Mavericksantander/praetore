//! Applies the bundled schema migrations exactly once each.
//!
//! Every applied migration is recorded in `praetore.schema_migrations` with
//! the SHA-256 of its text. A recorded migration is never executed again;
//! a recorded migration whose text changed is refused (migrations are
//! append-only). A session advisory lock serializes concurrent runners.
//!
//! Databases created before this runner have no control table: on their
//! first run 0001-0009 execute one last time (as every start did before) and
//! are then recorded. 0001-0009 carry their own `BEGIN`/`COMMIT`, so their
//! record is written right after their own commit; 0010 onward run in the
//! same transaction as their record.

use postgres::Client;
use sha2::{Digest, Sha256};

/// Ordered `(version, sql)` pairs. Append only; never edit or reorder.
pub const MIGRATIONS: [(&str, &str); 10] = [
    (
        "0001_replay_claims",
        include_str!("../migrations/0001_replay_claims.sql"),
    ),
    (
        "0002_execution_journal",
        include_str!("../migrations/0002_execution_journal.sql"),
    ),
    (
        "0003_execution_replay_link",
        include_str!("../migrations/0003_execution_replay_link.sql"),
    ),
    (
        "0004_execution_journal_events",
        include_str!("../migrations/0004_execution_journal_events.sql"),
    ),
    (
        "0005_execution_attestations",
        include_str!("../migrations/0005_execution_attestations.sql"),
    ),
    (
        "0006_human_approvals",
        include_str!("../migrations/0006_human_approvals.sql"),
    ),
    (
        "0007_tenant_scoped_execution",
        include_str!("../migrations/0007_tenant_scoped_execution.sql"),
    ),
    (
        "0008_tenant_row_level_security",
        include_str!("../migrations/0008_tenant_row_level_security.sql"),
    ),
    (
        "0009_human_approval_expirations",
        include_str!("../migrations/0009_human_approval_expirations.sql"),
    ),
    (
        "0010_approved_pending_dispatch",
        include_str!("../migrations/0010_approved_pending_dispatch.sql"),
    ),
];

/// Arbitrary constant key for `pg_advisory_lock`.
const MIGRATION_LOCK_KEY: i64 = 0x5052_4145_544f_5245;

#[derive(Debug)]
pub enum MigrationError {
    Database(postgres::Error),
    /// The recorded checksum differs from the bundled text.
    Modified(&'static str),
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(f, "migration failed: {error}"),
            Self::Modified(version) => {
                write!(f, "migration {version} was modified after it was applied")
            }
        }
    }
}

impl std::error::Error for MigrationError {}

impl From<postgres::Error> for MigrationError {
    fn from(error: postgres::Error) -> Self {
        Self::Database(error)
    }
}

/// Applies pending migrations and returns the versions applied by this call
/// (empty when the schema is already current).
pub fn apply_migrations(client: &mut Client) -> Result<Vec<&'static str>, MigrationError> {
    client.execute("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK_KEY])?;
    let result = apply_locked(client);
    let unlock = client.execute("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK_KEY]);
    let applied = result?;
    unlock?;
    Ok(applied)
}

fn apply_locked(client: &mut Client) -> Result<Vec<&'static str>, MigrationError> {
    client.batch_execute(
        "CREATE SCHEMA IF NOT EXISTS praetore; \
         CREATE TABLE IF NOT EXISTS praetore.schema_migrations (\
             version TEXT PRIMARY KEY, \
             checksum CHAR(64) NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'), \
             applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
    )?;
    let mut applied = Vec::new();
    for (version, sql) in MIGRATIONS {
        let checksum = hex::encode(Sha256::digest(sql.as_bytes()));
        let recorded = client.query_opt(
            "SELECT checksum FROM praetore.schema_migrations WHERE version = $1",
            &[&version],
        )?;
        if let Some(row) = recorded {
            if row.get::<_, String>(0) != checksum {
                return Err(MigrationError::Modified(version));
            }
            continue;
        }
        let mut transaction = client.transaction()?;
        transaction.batch_execute(sql)?;
        transaction.execute(
            "INSERT INTO praetore.schema_migrations (version, checksum) VALUES ($1, $2)",
            &[&version, &checksum],
        )?;
        transaction.commit()?;
        applied.push(version);
    }
    Ok(applied)
}
