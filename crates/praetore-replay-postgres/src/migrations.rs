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
//!
//! Each migration and its `schema_migrations` row commit in one transaction
//! owned by the runner. A migration file may enclose its body in a single
//! top-level `BEGIN;` ... `COMMIT;` pair (0007-0009 do); the runner strips that
//! pair before executing and refuses any other transaction control, so a
//! crash can never leave a migration applied but unrecorded.

use postgres::Client;
use sha2::{Digest, Sha256};

/// Ordered `(version, sql)` pairs. Append only; never edit or reorder.
pub const MIGRATIONS: [(&str, &str); 13] = [
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
    (
        "0011_runtime_role",
        include_str!("../migrations/0011_runtime_role.sql"),
    ),
    (
        "0012_dispatch_requires_live_approval",
        include_str!("../migrations/0012_dispatch_requires_live_approval.sql"),
    ),
    (
        "0013_dispatch_refused",
        include_str!("../migrations/0013_dispatch_refused.sql"),
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
    /// A migration contains transaction control other than one enclosing
    /// top-level `BEGIN;` ... `COMMIT;` pair.
    ExplicitTransactionControl(&'static str),
    /// The schema is not current and this connection may not migrate it.
    Pending(&'static str),
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
            Self::ExplicitTransactionControl(version) => write!(
                f,
                "migration {version} contains transaction control; the runner owns the transaction"
            ),
            Self::Pending(version) => write!(
                f,
                "database schema is not current (migration {version} is not applied); \
                 run the migration step with the owner role first"
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

/// Read-only check for connections that must not migrate (the runtime role):
/// every bundled migration is recorded with its checksum and nothing newer
/// is recorded. Needs only SELECT on `praetore.schema_migrations`.
pub fn verify_schema_current(client: &mut Client) -> Result<(), MigrationError> {
    let has_control: bool = client
        .query_one(
            "SELECT to_regclass('praetore.schema_migrations') IS NOT NULL",
            &[],
        )?
        .get(0);
    if !has_control {
        return Err(MigrationError::Pending(MIGRATIONS[0].0));
    }
    let recorded = client.query(
        "SELECT version, checksum FROM praetore.schema_migrations",
        &[],
    )?;
    for row in &recorded {
        let version: String = row.get(0);
        if !MIGRATIONS.iter().any(|(known, _)| *known == version) {
            return Err(MigrationError::UnknownVersion(version));
        }
    }
    for (version, sql) in MIGRATIONS {
        match recorded.iter().find(|row| row.get::<_, &str>(0) == version) {
            None => return Err(MigrationError::Pending(version)),
            Some(row) if row.get::<_, String>(1) != checksum(sql) => {
                return Err(MigrationError::Modified(version));
            }
            Some(_) => {}
        }
    }
    Ok(())
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
        let body = transactional_body(version, sql)?;
        let mut transaction = client.transaction()?;
        transaction.batch_execute(body)?;
        transaction.execute(
            "INSERT INTO praetore.schema_migrations (version, checksum) VALUES ($1, $2)",
            &[&version, &checksum],
        )?;
        transaction.commit()?;
        applied.push(version);
    }
    Ok(applied)
}

/// Returns the part of `sql` that the runner executes inside its own
/// transaction, together with the `schema_migrations` row.
///
/// 0007, 0008 and 0009 were written as `BEGIN; ... COMMIT;`. Executed as-is,
/// their `COMMIT` would end the runner's transaction early, so the version
/// row would be written in a separate autocommit and a crash in between would
/// leave the migration applied but unrecorded. Their text cannot change
/// (checksums of applied migrations are verified), so a top-level `BEGIN;` as
/// the first statement paired with `COMMIT;` as the last is stripped here and
/// the checksum still covers the original text. Any other top-level
/// transaction control is refused.
fn transactional_body(
    version: &'static str,
    sql: &'static str,
) -> Result<&'static str, MigrationError> {
    let statements = top_level_statements(sql);
    let keyword = |index: usize| -> String {
        statements
            .get(index)
            .map(|&(start, end)| leading_keyword(&sql[start..end]))
            .unwrap_or_default()
    };
    let (mut first, mut last) = (0, statements.len());
    if keyword(0) == "BEGIN" && statements.len() >= 2 && keyword(statements.len() - 1) == "COMMIT" {
        first = 1;
        last -= 1;
    }
    for index in first..last {
        if TRANSACTION_CONTROL.contains(&keyword(index).as_str()) {
            return Err(MigrationError::ExplicitTransactionControl(version));
        }
    }
    let start = if first == 0 { 0 } else { statements[0].1 + 1 };
    let end = if last == statements.len() {
        sql.len()
    } else {
        statements[last].0
    };
    Ok(&sql[start..end])
}

const TRANSACTION_CONTROL: &[&str] = &[
    "BEGIN",
    "START",
    "COMMIT",
    "END",
    "ROLLBACK",
    "ABORT",
    "SAVEPOINT",
    "RELEASE",
    "PREPARE",
];

/// First word of a statement (comments skipped), upper-cased.
fn leading_keyword(statement: &str) -> String {
    let mut rest = statement;
    loop {
        rest = rest.trim_start();
        if let Some(comment) = rest.strip_prefix("--") {
            rest = comment.split_once('\n').map_or("", |(_, tail)| tail);
        } else if let Some(comment) = rest.strip_prefix("/*") {
            rest = comment.split_once("*/").map_or("", |(_, tail)| tail);
        } else {
            break;
        }
    }
    rest.chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Byte spans `(start, end)` of the top-level statements in `sql`; `end` is
/// the index of the terminating `;` (or `sql.len()`). Quoted strings, quoted
/// identifiers, comments and dollar-quoted bodies are skipped, so `BEGIN`
/// inside a PL/pgSQL body is never a top-level statement. Blank or
/// comment-only tails are not statements.
fn top_level_statements(sql: &str) -> Vec<(usize, usize)> {
    let bytes = sql.as_bytes();
    let mut spans = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'-' if bytes.get(index + 1) == Some(&b'-') => {
                index = sql[index..]
                    .find('\n')
                    .map_or(bytes.len(), |offset| index + offset);
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index = sql[index + 2..]
                    .find("*/")
                    .map_or(bytes.len(), |offset| index + 2 + offset + 2);
            }
            quote @ (b'\'' | b'"') => {
                index = sql[index + 1..]
                    .find(quote as char)
                    .map_or(bytes.len(), |offset| index + 1 + offset + 1);
            }
            b'$' => {
                let tag_len = sql[index + 1..]
                    .bytes()
                    .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                    .count();
                let tag_end = index + 1 + tag_len;
                let is_tag = bytes.get(tag_end) == Some(&b'$')
                    && !bytes.get(index + 1).is_some_and(u8::is_ascii_digit);
                if is_tag {
                    let tag = &sql[index..=tag_end];
                    index = sql[tag_end + 1..]
                        .find(tag)
                        .map_or(bytes.len(), |offset| tag_end + 1 + offset + tag.len());
                } else {
                    index += 1;
                }
            }
            b';' => {
                spans.push((start, index));
                start = index + 1;
                index += 1;
            }
            _ => index += 1,
        }
    }
    if !leading_keyword(&sql[start..]).is_empty() {
        spans.push((start, sql.len()));
    }
    spans
        .into_iter()
        .filter(|&(start, end)| !leading_keyword(&sql[start..end]).is_empty())
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_migrations_have_no_transaction_control_inside_the_runner_transaction() {
        for (version, sql) in MIGRATIONS {
            let body = transactional_body(version, sql).unwrap();
            for (start, end) in top_level_statements(body) {
                let keyword = leading_keyword(&body[start..end]);
                assert!(
                    !TRANSACTION_CONTROL.contains(&keyword.as_str()),
                    "{version} still has {keyword}"
                );
            }
        }
    }

    #[test]
    fn enclosing_begin_commit_is_stripped_and_plpgsql_begin_is_kept() {
        let sql = "-- header; with a semicolon\nBEGIN;\nCREATE FUNCTION f() RETURNS void \
                   LANGUAGE plpgsql AS $$\nBEGIN\n  PERFORM 1;\nEND;\n$$;\n\
                   SELECT 'COMMIT;';\nCOMMIT;\n";
        let body = transactional_body("test", Box::leak(sql.to_owned().into_boxed_str())).unwrap();
        assert!(body.contains("CREATE FUNCTION"));
        assert!(body.contains("BEGIN\n  PERFORM 1;"));
        assert!(body.contains("SELECT 'COMMIT;'"));
        assert!(!body.contains("\nBEGIN;"));
        assert!(!body.trim_end().ends_with("COMMIT;"));
        for (_, sql) in MIGRATIONS {
            assert!(!top_level_statements(sql).is_empty());
        }
        let stripped = transactional_body(MIGRATIONS[6].0, MIGRATIONS[6].1).unwrap();
        assert_ne!(
            stripped, MIGRATIONS[6].1,
            "0007 has an enclosing BEGIN/COMMIT"
        );
        assert_eq!(
            transactional_body(MIGRATIONS[9].0, MIGRATIONS[9].1).unwrap(),
            MIGRATIONS[9].1,
            "0010 is executed unchanged"
        );
    }

    #[test]
    fn other_transaction_control_is_refused() {
        for sql in [
            "CREATE TABLE a (); COMMIT; CREATE TABLE b ();",
            "BEGIN; CREATE TABLE a (); COMMIT; BEGIN; CREATE TABLE b (); COMMIT;",
            "CREATE TABLE a (); ROLLBACK;",
            "BEGIN; CREATE TABLE a ();",
            "SAVEPOINT s; CREATE TABLE a ();",
            "START TRANSACTION; CREATE TABLE a (); COMMIT;",
            "CREATE TABLE a (); /* c */ end;",
        ] {
            assert!(
                matches!(
                    transactional_body("test", Box::leak(sql.to_owned().into_boxed_str())),
                    Err(MigrationError::ExplicitTransactionControl("test"))
                ),
                "{sql}"
            );
        }
    }
}
