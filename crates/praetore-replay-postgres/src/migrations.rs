//! Applies the bundled schema migrations exactly once each.
//!
//! Every applied migration is recorded in `praetore.schema_migrations` with
//! the SHA-256 of its text. A recorded migration is never executed again;
//! a recorded migration whose text changed is refused (migrations are
//! append-only). A session advisory lock serializes concurrent runners.
//!
//! Databases created before this runner have no control table. If such a
//! database matches the schema left by 0009 exactly (every expected table,
//! tenant column, constraint, trigger and RLS policy present, and nothing
//! from 0010), 0001-0009 are recorded as applied without executing them and
//! only the newer migrations run. Any other pre-existing `praetore` schema is
//! refused (fail closed). A control table that records a version this binary
//! does not know is refused too, so an older binary never runs against a
//! newer schema.

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
    /// The control table records a version unknown to this binary.
    UnknownVersion(String),
    /// A `praetore` schema exists without a control table and does not match
    /// the 0009 baseline.
    UnrecognizedSchema(&'static str),
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(f, "migration failed: {error}"),
            Self::Modified(version) => {
                write!(f, "migration {version} was modified after it was applied")
            }
            Self::UnknownVersion(version) => write!(
                f,
                "database has migration {version}, which this binary does not know; refusing to start"
            ),
            Self::UnrecognizedSchema(missing) => write!(
                f,
                "existing praetore schema has no migration record and does not match 0009 ({missing}); refusing to migrate"
            ),
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

/// Last migration that existed before the control table was introduced.
const BASELINE_VERSION: &str = "0009_human_approval_expirations";

fn apply_locked(client: &mut Client) -> Result<Vec<&'static str>, MigrationError> {
    let has_control: bool = client
        .query_one(
            "SELECT to_regclass('praetore.schema_migrations') IS NOT NULL",
            &[],
        )?
        .get(0);
    if !has_control {
        let has_schema: bool = client
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'praetore')",
                &[],
            )?
            .get(0);
        let baseline = if has_schema {
            check_0009_baseline(client)?;
            true
        } else {
            false
        };
        let mut transaction = client.transaction()?;
        transaction.batch_execute(
            "CREATE SCHEMA IF NOT EXISTS praetore; \
             CREATE TABLE praetore.schema_migrations (\
                 version TEXT PRIMARY KEY, \
                 checksum CHAR(64) NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'), \
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())",
        )?;
        if baseline {
            for (version, sql) in MIGRATIONS {
                transaction.execute(
                    "INSERT INTO praetore.schema_migrations (version, checksum) VALUES ($1, $2)",
                    &[&version, &checksum(sql)],
                )?;
                if version == BASELINE_VERSION {
                    break;
                }
            }
        }
        transaction.commit()?;
    }

    let recorded = client.query("SELECT version FROM praetore.schema_migrations", &[])?;
    for row in recorded {
        let version: String = row.get(0);
        if !MIGRATIONS.iter().any(|(known, _)| *known == version) {
            return Err(MigrationError::UnknownVersion(version));
        }
    }

    let mut applied = Vec::new();
    for (version, sql) in MIGRATIONS {
        let checksum = checksum(sql);
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

fn checksum(sql: &str) -> String {
    hex::encode(Sha256::digest(sql.as_bytes()))
}

/// Objects that 0001-0009 leave behind, as `(kind, table, name)`.
const BASELINE_OBJECTS: &[(&str, &str, &str)] = &[
    ("column", "replay_claims", "tenant_id"),
    ("column", "execution_journal", "tenant_id"),
    ("column", "execution_journal_events", "tenant_id"),
    ("column", "execution_attestations", "tenant_id"),
    ("column", "human_approvals", "tenant_id"),
    ("column", "human_approval_expirations", "receipt_id"),
    ("constraint", "replay_claims", "replay_claims_pkey"),
    ("constraint", "execution_journal", "execution_journal_pkey"),
    (
        "constraint",
        "execution_journal",
        "execution_journal_replay_claim_fk",
    ),
    (
        "constraint",
        "execution_journal",
        "execution_journal_execution_status_check",
    ),
    (
        "constraint",
        "execution_journal",
        "execution_journal_authorization_execution_check",
    ),
    (
        "constraint",
        "execution_journal_events",
        "execution_journal_events_journal_fk",
    ),
    (
        "constraint",
        "execution_journal_events",
        "execution_journal_events_to_status_check",
    ),
    (
        "constraint",
        "execution_journal_events",
        "execution_journal_events_from_status_check",
    ),
    (
        "constraint",
        "execution_attestations",
        "execution_attestations_journal_fk",
    ),
    (
        "constraint",
        "execution_attestations",
        "execution_attestations_identity_status_key",
    ),
    (
        "constraint",
        "human_approvals",
        "human_approvals_journal_fk",
    ),
    (
        "constraint",
        "human_approvals",
        "human_approvals_identity_key",
    ),
    (
        "constraint",
        "human_approval_expirations",
        "human_approval_expirations_pkey",
    ),
    (
        "trigger",
        "execution_journal",
        "execution_journal_transition",
    ),
    (
        "trigger",
        "execution_journal",
        "execution_journal_event_log",
    ),
    (
        "trigger",
        "execution_journal",
        "execution_journal_expiration_restrict",
    ),
    (
        "trigger",
        "execution_journal_events",
        "execution_journal_events_immutable",
    ),
    (
        "trigger",
        "execution_journal_events",
        "execution_journal_events_no_truncate",
    ),
    (
        "trigger",
        "execution_attestations",
        "execution_attestations_immutable",
    ),
    (
        "trigger",
        "execution_attestations",
        "execution_attestations_no_truncate",
    ),
    ("trigger", "human_approvals", "human_approvals_immutable"),
    ("trigger", "human_approvals", "human_approvals_no_truncate"),
    ("trigger", "human_approvals", "human_approvals_exclusive"),
    (
        "trigger",
        "human_approval_expirations",
        "human_approval_expirations_immutable",
    ),
    (
        "trigger",
        "human_approval_expirations",
        "human_approval_expirations_no_truncate",
    ),
    (
        "trigger",
        "human_approval_expirations",
        "human_approval_expirations_exclusive",
    ),
    ("policy", "replay_claims", "tenant_isolation"),
    ("policy", "execution_journal", "tenant_isolation"),
    ("policy", "execution_journal_events", "tenant_isolation"),
    ("policy", "execution_attestations", "tenant_isolation"),
    ("policy", "human_approvals", "tenant_isolation"),
    ("policy", "human_approval_expirations", "tenant_isolation"),
    ("forced_rls", "replay_claims", ""),
    ("forced_rls", "execution_journal", ""),
    ("forced_rls", "execution_journal_events", ""),
    ("forced_rls", "execution_attestations", ""),
    ("forced_rls", "human_approvals", ""),
];

/// Fails with `UnrecognizedSchema` naming the first missing object, or when
/// anything from 0010 is already present.
fn check_0009_baseline(client: &mut Client) -> Result<(), MigrationError> {
    for &(kind, table, name) in BASELINE_OBJECTS {
        let query = match kind {
            "column" => {
                "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = 'praetore' AND table_name = $1 AND column_name = $2)"
            }
            "constraint" => {
                "SELECT EXISTS (SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid \
                 JOIN pg_namespace n ON n.oid = t.relnamespace \
                 WHERE n.nspname = 'praetore' AND t.relname = $1 AND c.conname = $2)"
            }
            "trigger" => {
                "SELECT EXISTS (SELECT 1 FROM pg_trigger g JOIN pg_class t ON t.oid = g.tgrelid \
                 JOIN pg_namespace n ON n.oid = t.relnamespace \
                 WHERE n.nspname = 'praetore' AND t.relname = $1 AND g.tgname = $2 \
                   AND NOT g.tgisinternal)"
            }
            "policy" => {
                "SELECT EXISTS (SELECT 1 FROM pg_policies \
                 WHERE schemaname = 'praetore' AND tablename = $1 AND policyname = $2)"
            }
            _ => {
                "SELECT EXISTS (SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid = t.relnamespace \
                 WHERE n.nspname = 'praetore' AND t.relname = $1 AND $2 = '' \
                   AND t.relrowsecurity AND t.relforcerowsecurity)"
            }
        };
        let present: bool = client.query_one(query, &[&table, &name])?.get(0);
        if !present {
            return Err(MigrationError::UnrecognizedSchema(if name.is_empty() {
                table
            } else {
                name
            }));
        }
    }
    let newer: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_schema = 'praetore' AND table_name = 'execution_journal' \
               AND column_name = 'not_dispatched_reason')",
            &[],
        )?
        .get(0);
    if newer {
        return Err(MigrationError::UnrecognizedSchema("not_dispatched_reason"));
    }
    Ok(())
}
