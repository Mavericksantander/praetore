//! Applies the bundled schema migrations exactly once each.
//!
//! Every applied migration is recorded in `praetore.schema_migrations` with
//! the SHA-256 of its text. A recorded migration is never executed again;
//! a recorded migration whose text changed is refused (migrations are
//! append-only). A session advisory lock serializes concurrent runners.
//!
//! Databases created before this runner have no control table. If such a
//! database matches the schema left by 0009 (every expected tenant column,
//! constraint and forced RLS present; the functions in `praetore` exactly the
//! ones 0001-0009 create, with the same body, SECURITY DEFINER, `SET`
//! search_path, language and volatility, and no other overload; the
//! non-internal triggers exactly the ones 0001-0009 create, with the same
//! events, function, columns and enabled state; the RLS policies exactly the
//! `tenant_isolation` ones with the same USING and WITH CHECK; and nothing
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
pub const MIGRATIONS: [(&str, &str); 14] = [
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
    (
        "0014_closed_execution_row_lock",
        include_str!("../migrations/0014_closed_execution_row_lock.sql"),
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
    /// the 0009 baseline; names the first object that is missing or differs.
    UnrecognizedSchema(String),
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
    skip_leading_comments(statement)
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect::<String>()
        .to_ascii_uppercase()
}

/// `statement` without leading whitespace and comments.
fn skip_leading_comments(statement: &str) -> &str {
    let mut rest = statement;
    loop {
        rest = rest.trim_start();
        if let Some(comment) = rest.strip_prefix("--") {
            rest = comment.split_once('\n').map_or("", |(_, tail)| tail);
        } else if let Some(comment) = rest.strip_prefix("/*") {
            rest = comment.split_once("*/").map_or("", |(_, tail)| tail);
        } else {
            return rest;
        }
    }
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
    ("forced_rls", "replay_claims", ""),
    ("forced_rls", "execution_journal", ""),
    ("forced_rls", "execution_journal_events", ""),
    ("forced_rls", "execution_attestations", ""),
    ("forced_rls", "human_approvals", ""),
    ("forced_rls", "human_approval_expirations", ""),
];

/// A function that 0001-0009 leave in the `praetore` schema. Every one is a
/// PL/pgSQL trigger function without arguments, VOLATILE, not STRICT, not
/// LEAKPROOF, PARALLEL UNSAFE; only these two attributes vary. The expected
/// body is not copied here: it is read from the last
/// `CREATE OR REPLACE FUNCTION` of that function in the bundled 0001-0009
/// text, whose checksums are pinned.
struct BaselineFunction {
    name: &'static str,
    security_definer: bool,
    /// The single `proconfig` entry, as PostgreSQL stores `SET ...`.
    config: Option<&'static str>,
}

const BASELINE_FUNCTIONS: &[BaselineFunction] = &[
    BaselineFunction {
        name: "validate_execution_journal_transition",
        security_definer: false,
        config: None,
    },
    BaselineFunction {
        name: "record_execution_journal_transition",
        security_definer: true,
        config: Some("search_path=pg_catalog, praetore, pg_temp"),
    },
    BaselineFunction {
        name: "reject_execution_journal_event_mutation",
        security_definer: false,
        config: None,
    },
    BaselineFunction {
        name: "reject_execution_attestation_mutation",
        security_definer: false,
        config: None,
    },
    BaselineFunction {
        name: "reject_human_approval_mutation",
        security_definer: false,
        config: None,
    },
    BaselineFunction {
        name: "restrict_journal_delete_with_expiration",
        security_definer: false,
        config: None,
    },
    BaselineFunction {
        name: "reject_human_approval_expiration_mutation",
        security_definer: false,
        config: None,
    },
    BaselineFunction {
        name: "enforce_approval_resolution_exclusive",
        security_definer: false,
        config: None,
    },
];

/// `pg_trigger.tgtype` bits.
const ROW: i32 = 1;
const BEFORE: i32 = 2;
const INSERT: i32 = 4;
const DELETE: i32 = 8;
const UPDATE: i32 = 16;
const TRUNCATE: i32 = 32;

/// Triggers that 0001-0009 leave behind, as
/// `(table, trigger, tgtype, function, UPDATE OF columns)`. Every one is
/// enabled (`O`), has no arguments, no WHEN clause, no transition tables and
/// is not a constraint trigger.
const BASELINE_TRIGGERS: &[(&str, &str, i32, &str, &str)] = &[
    (
        "execution_journal",
        "execution_journal_transition",
        BEFORE | UPDATE | ROW,
        "validate_execution_journal_transition",
        "",
    ),
    (
        "execution_journal",
        "execution_journal_event_log",
        INSERT | UPDATE | ROW,
        "record_execution_journal_transition",
        "execution_status",
    ),
    (
        "execution_journal",
        "execution_journal_expiration_restrict",
        BEFORE | DELETE | ROW,
        "restrict_journal_delete_with_expiration",
        "",
    ),
    (
        "execution_journal_events",
        "execution_journal_events_immutable",
        BEFORE | UPDATE | DELETE | ROW,
        "reject_execution_journal_event_mutation",
        "",
    ),
    (
        "execution_journal_events",
        "execution_journal_events_no_truncate",
        BEFORE | TRUNCATE,
        "reject_execution_journal_event_mutation",
        "",
    ),
    (
        "execution_attestations",
        "execution_attestations_immutable",
        BEFORE | UPDATE | DELETE | ROW,
        "reject_execution_attestation_mutation",
        "",
    ),
    (
        "execution_attestations",
        "execution_attestations_no_truncate",
        BEFORE | TRUNCATE,
        "reject_execution_attestation_mutation",
        "",
    ),
    (
        "human_approvals",
        "human_approvals_immutable",
        BEFORE | UPDATE | DELETE | ROW,
        "reject_human_approval_mutation",
        "",
    ),
    (
        "human_approvals",
        "human_approvals_no_truncate",
        BEFORE | TRUNCATE,
        "reject_human_approval_mutation",
        "",
    ),
    (
        "human_approvals",
        "human_approvals_exclusive",
        BEFORE | INSERT | ROW,
        "enforce_approval_resolution_exclusive",
        "",
    ),
    (
        "human_approval_expirations",
        "human_approval_expirations_immutable",
        BEFORE | UPDATE | DELETE | ROW,
        "reject_human_approval_expiration_mutation",
        "",
    ),
    (
        "human_approval_expirations",
        "human_approval_expirations_no_truncate",
        BEFORE | TRUNCATE,
        "reject_human_approval_expiration_mutation",
        "",
    ),
    (
        "human_approval_expirations",
        "human_approval_expirations_exclusive",
        BEFORE | INSERT | ROW,
        "enforce_approval_resolution_exclusive",
        "",
    ),
];

/// Tables that carry exactly one RLS policy, `tenant_isolation`
/// (0008 and 0009): PERMISSIVE, FOR ALL, TO PUBLIC, with this expression as
/// both USING and WITH CHECK.
const BASELINE_POLICY_TABLES: &[&str] = &[
    "replay_claims",
    "execution_journal",
    "execution_journal_events",
    "execution_attestations",
    "human_approvals",
    "human_approval_expirations",
];
const BASELINE_POLICY_NAME: &str = "tenant_isolation";
const BASELINE_POLICY_EXPRESSION: &str =
    "tenant_id = NULLIF(current_setting('praetore.tenant_id', true), '')::UUID";

/// Fails with `UnrecognizedSchema` naming the first object that is missing or
/// differs from what 0001-0009 leave behind, or when anything from 0010 is
/// already present.
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
            _ => {
                "SELECT EXISTS (SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid = t.relnamespace \
                 WHERE n.nspname = 'praetore' AND t.relname = $1 AND $2 = '' \
                   AND t.relrowsecurity AND t.relforcerowsecurity)"
            }
        };
        let present: bool = client.query_one(query, &[&table, &name])?.get(0);
        if !present {
            return Err(unrecognized(if name.is_empty() {
                format!("forced row level security on {table}")
            } else {
                name.to_owned()
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
        return Err(unrecognized("not_dispatched_reason".to_owned()));
    }
    check_baseline_functions(client)?;
    check_baseline_triggers(client)?;
    check_baseline_policies(client)
}

fn unrecognized(detail: String) -> MigrationError {
    MigrationError::UnrecognizedSchema(detail)
}

/// Every function in the `praetore` schema must be one of
/// `BASELINE_FUNCTIONS`, with no arguments (so an added overload is refused),
/// the expected attributes and a `prosrc` byte-identical to the body in the
/// bundled migration text. `prosrc` is stored verbatim, so this comparison
/// does not depend on how a PostgreSQL version renders definitions.
fn check_baseline_functions(client: &mut Client) -> Result<(), MigrationError> {
    let rows = client.query(
        "SELECT p.proname, pg_get_function_identity_arguments(p.oid), \
                format_type(p.prorettype, NULL), l.lanname, p.prosecdef, p.proconfig, \
                p.provolatile::text, p.proparallel::text, p.prokind::text, p.proisstrict, \
                p.proleakproof, p.proretset, p.prosrc \
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
         JOIN pg_language l ON l.oid = p.prolang \
         WHERE n.nspname = 'praetore' ORDER BY 1, 2",
        &[],
    )?;
    for row in &rows {
        let name: &str = row.get(0);
        let arguments: &str = row.get(1);
        let object = format!("function praetore.{name}({arguments})");
        let Some(expected) = BASELINE_FUNCTIONS
            .iter()
            .find(|function| function.name == name && arguments.is_empty())
        else {
            return Err(unrecognized(format!(
                "{object} is not created by 0001-0009"
            )));
        };
        let config: Option<Vec<String>> = row.get(5);
        let expected_config = expected.config.map(|entry| vec![entry.to_owned()]);
        let mut differences = Vec::new();
        if row.get::<_, &str>(2) != "trigger" || row.get::<_, bool>(11) {
            differences.push("return type");
        }
        if row.get::<_, &str>(3) != "plpgsql" {
            differences.push("language");
        }
        if row.get::<_, bool>(4) != expected.security_definer {
            differences.push("SECURITY DEFINER");
        }
        if config != expected_config {
            differences.push("SET (search_path)");
        }
        if row.get::<_, &str>(6) != "v" {
            differences.push("volatility");
        }
        if row.get::<_, &str>(7) != "u" {
            differences.push("parallel safety");
        }
        if row.get::<_, &str>(8) != "f" {
            differences.push("kind");
        }
        if row.get::<_, bool>(9) {
            differences.push("STRICT");
        }
        if row.get::<_, bool>(10) {
            differences.push("LEAKPROOF");
        }
        if Some(row.get::<_, &str>(12)) != baseline_function_body(expected.name) {
            differences.push("body");
        }
        if !differences.is_empty() {
            return Err(unrecognized(format!(
                "{object} differs from 0009 in: {}",
                differences.join(", ")
            )));
        }
    }
    for expected in BASELINE_FUNCTIONS {
        if !rows
            .iter()
            .any(|row| row.get::<_, &str>(0) == expected.name)
        {
            return Err(unrecognized(format!(
                "function praetore.{}() is missing",
                expected.name
            )));
        }
    }
    Ok(())
}

/// Every non-internal trigger on a `praetore` table must be one of
/// `BASELINE_TRIGGERS`, compared by catalog fields rather than by rendered
/// text: events and timing, level, the function it runs, `UPDATE OF`
/// columns, enabled state, arguments, WHEN clause, transition tables.
fn check_baseline_triggers(client: &mut Client) -> Result<(), MigrationError> {
    let rows = client.query(
        "SELECT t.relname, g.tgname, g.tgtype::int4, g.tgenabled::text, g.tgnargs::int4, \
                g.tgqual IS NULL AND g.tgconstraint = 0 \
                    AND g.tgoldtable IS NULL AND g.tgnewtable IS NULL, \
                fn.nspname, p.proname, pg_get_function_identity_arguments(p.oid), \
                COALESCE((SELECT string_agg(a.attname, ',' ORDER BY a.attnum) \
                          FROM pg_attribute a \
                          WHERE a.attrelid = g.tgrelid AND a.attnum = ANY (g.tgattr)), '') \
         FROM pg_trigger g JOIN pg_class t ON t.oid = g.tgrelid \
         JOIN pg_namespace n ON n.oid = t.relnamespace \
         JOIN pg_proc p ON p.oid = g.tgfoid \
         JOIN pg_namespace fn ON fn.oid = p.pronamespace \
         WHERE n.nspname = 'praetore' AND NOT g.tgisinternal ORDER BY 1, 2",
        &[],
    )?;
    for row in &rows {
        let table: &str = row.get(0);
        let name: &str = row.get(1);
        let object = format!("trigger {name} on praetore.{table}");
        let Some(&(_, _, tgtype, function, columns)) = BASELINE_TRIGGERS
            .iter()
            .find(|(t, n, ..)| *t == table && *n == name)
        else {
            return Err(unrecognized(format!(
                "{object} is not created by 0001-0009"
            )));
        };
        let mut differences = Vec::new();
        if row.get::<_, i32>(2) != tgtype {
            differences.push("timing, events or level");
        }
        if row.get::<_, &str>(3) != "O" {
            differences.push("enabled state");
        }
        if row.get::<_, i32>(4) != 0 {
            differences.push("arguments");
        }
        if !row.get::<_, bool>(5) {
            differences.push("WHEN clause, constraint or transition tables");
        }
        if row.get::<_, &str>(6) != "praetore"
            || row.get::<_, &str>(7) != function
            || !row.get::<_, &str>(8).is_empty()
        {
            differences.push("function");
        }
        if row.get::<_, &str>(9) != columns {
            differences.push("UPDATE OF columns");
        }
        if !differences.is_empty() {
            return Err(unrecognized(format!(
                "{object} differs from 0009 in: {}",
                differences.join(", ")
            )));
        }
    }
    for &(table, name, ..) in BASELINE_TRIGGERS {
        if !rows
            .iter()
            .any(|row| row.get::<_, &str>(0) == table && row.get::<_, &str>(1) == name)
        {
            return Err(unrecognized(format!(
                "trigger {name} on praetore.{table} is missing"
            )));
        }
    }
    Ok(())
}

/// Every RLS policy on a `praetore` table must be `tenant_isolation` on one
/// of `BASELINE_POLICY_TABLES`, so an extra permissive policy is refused.
/// The USING and WITH CHECK expressions are compared with the same server's
/// rendering of `BASELINE_POLICY_EXPRESSION` on a temporary table, created
/// in a transaction that is rolled back, so the result does not depend on
/// how a PostgreSQL version prints expressions.
fn check_baseline_policies(client: &mut Client) -> Result<(), MigrationError> {
    let mut transaction = client.transaction()?;
    transaction.batch_execute(&format!(
        "CREATE TEMPORARY TABLE praetore_baseline_policy_reference (tenant_id UUID); \
         CREATE POLICY reference ON pg_temp.praetore_baseline_policy_reference \
             USING ({BASELINE_POLICY_EXPRESSION}) WITH CHECK ({BASELINE_POLICY_EXPRESSION})"
    ))?;
    let reference = transaction.query_one(
        "SELECT pg_get_expr(polqual, polrelid), pg_get_expr(polwithcheck, polrelid) \
         FROM pg_policy \
         WHERE polrelid = 'pg_temp.praetore_baseline_policy_reference'::regclass",
        &[],
    )?;
    let expected_qual: Option<String> = reference.get(0);
    let expected_check: Option<String> = reference.get(1);
    let rows = transaction.query(
        "SELECT t.relname, p.polname, p.polcmd::text, p.polpermissive, \
                p.polroles = '{0}'::oid[], \
                pg_get_expr(p.polqual, p.polrelid), pg_get_expr(p.polwithcheck, p.polrelid) \
         FROM pg_policy p JOIN pg_class t ON t.oid = p.polrelid \
         JOIN pg_namespace n ON n.oid = t.relnamespace \
         WHERE n.nspname = 'praetore' ORDER BY 1, 2",
        &[],
    )?;
    transaction.rollback()?;
    if expected_qual.is_none() || expected_check.is_none() {
        return Err(unrecognized(
            "reference policy expression could not be rendered".to_owned(),
        ));
    }
    for row in &rows {
        let table: &str = row.get(0);
        let name: &str = row.get(1);
        let object = format!("policy praetore.{table}.{name}");
        if name != BASELINE_POLICY_NAME || !BASELINE_POLICY_TABLES.contains(&table) {
            return Err(unrecognized(format!(
                "{object} is not created by 0001-0009"
            )));
        }
        let mut differences = Vec::new();
        if row.get::<_, &str>(2) != "*" {
            differences.push("command");
        }
        if !row.get::<_, bool>(3) {
            differences.push("PERMISSIVE");
        }
        if !row.get::<_, bool>(4) {
            differences.push("roles");
        }
        if row.get::<_, Option<String>>(5) != expected_qual {
            differences.push("USING");
        }
        if row.get::<_, Option<String>>(6) != expected_check {
            differences.push("WITH CHECK");
        }
        if !differences.is_empty() {
            return Err(unrecognized(format!(
                "{object} differs from 0009 in: {}",
                differences.join(", ")
            )));
        }
    }
    for table in BASELINE_POLICY_TABLES {
        if !rows.iter().any(|row| row.get::<_, &str>(0) == *table) {
            return Err(unrecognized(format!(
                "policy praetore.{table}.{BASELINE_POLICY_NAME} is missing"
            )));
        }
    }
    Ok(())
}

/// Body (the text between the `$$` delimiters) of the last
/// `CREATE OR REPLACE FUNCTION praetore.<name>()` in 0001-0009.
fn baseline_function_body(name: &str) -> Option<&'static str> {
    let header = format!("CREATE OR REPLACE FUNCTION praetore.{name}()");
    let mut body = None;
    for (version, sql) in MIGRATIONS {
        for (start, end) in top_level_statements(sql) {
            let statement = skip_leading_comments(&sql[start..end]);
            if statement.starts_with(&header) {
                let open = statement.find("$$")? + 2;
                let close = open + statement[open..].find("$$")?;
                body = Some(&statement[open..close]);
            }
        }
        if version == BASELINE_VERSION {
            break;
        }
    }
    body
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

    /// Statements of 0001-0009 that start with `prefix`.
    fn baseline_statements(prefix: &str) -> Vec<&'static str> {
        let mut found = Vec::new();
        for (version, sql) in MIGRATIONS {
            for (start, end) in top_level_statements(sql) {
                let statement = skip_leading_comments(&sql[start..end]);
                if statement.starts_with(prefix) {
                    found.push(statement);
                }
            }
            if version == BASELINE_VERSION {
                break;
            }
        }
        found
    }

    #[test]
    fn baseline_functions_are_exactly_those_created_by_0001_to_0009() {
        let mut created: Vec<&str> = baseline_statements("CREATE OR REPLACE FUNCTION praetore.")
            .iter()
            .map(|statement| {
                statement["CREATE OR REPLACE FUNCTION praetore.".len()..]
                    .split_once("()")
                    .expect("baseline functions take no arguments")
                    .0
            })
            .collect();
        created.sort_unstable();
        created.dedup();
        let mut expected: Vec<&str> = BASELINE_FUNCTIONS.iter().map(|f| f.name).collect();
        expected.sort_unstable();
        assert_eq!(created, expected);
        assert!(baseline_statements("CREATE FUNCTION").is_empty());
        for function in BASELINE_FUNCTIONS {
            let header = format!("CREATE OR REPLACE FUNCTION praetore.{}()", function.name);
            let last = *baseline_statements(&header).last().unwrap();
            let (attributes, _) = last.split_once("$$").unwrap();
            assert!(attributes.contains("RETURNS TRIGGER"), "{}", function.name);
            assert!(attributes.contains("LANGUAGE plpgsql"), "{}", function.name);
            assert_eq!(
                attributes.contains("SECURITY DEFINER"),
                function.security_definer,
                "{}",
                function.name
            );
            assert_eq!(
                attributes.contains("SET search_path = pg_catalog, praetore, pg_temp"),
                function.config.is_some(),
                "{}",
                function.name
            );
            for attribute in ["STABLE", "IMMUTABLE", "STRICT", "LEAKPROOF", "PARALLEL"] {
                assert!(!attributes.contains(attribute), "{}", function.name);
            }
            let body = baseline_function_body(function.name).unwrap();
            assert!(last.ends_with(&format!("$${body}$$")), "{}", function.name);
            assert!(
                body.trim_start().starts_with("BEGIN") || body.trim_start().starts_with("DECLARE")
            );
        }
        // 0007's version replaces 0006's, which replaced 0002's.
        let validate = baseline_function_body("validate_execution_journal_transition").unwrap();
        assert!(validate.contains("NEW.tenant_id <> OLD.tenant_id"));
    }

    #[test]
    fn baseline_triggers_are_exactly_those_created_by_0001_to_0009() {
        let mut created: Vec<(String, String, String)> = baseline_statements("CREATE TRIGGER ")
            .iter()
            .map(|statement| {
                let words: Vec<&str> = statement.split_whitespace().collect();
                let on = words.iter().position(|word| *word == "ON").unwrap();
                let function = statement
                    .split_once("EXECUTE FUNCTION praetore.")
                    .unwrap()
                    .1
                    .trim_end_matches("()");
                (
                    words[on + 1].trim_start_matches("praetore.").to_owned(),
                    words[2].to_owned(),
                    function.to_owned(),
                )
            })
            .collect();
        created.sort();
        created.dedup();
        let mut expected: Vec<(String, String, String)> = BASELINE_TRIGGERS
            .iter()
            .map(|(table, name, _, function, _)| {
                (
                    (*table).to_owned(),
                    (*name).to_owned(),
                    (*function).to_owned(),
                )
            })
            .collect();
        expected.sort();
        assert_eq!(created, expected);
        for (_, name, tgtype, ..) in BASELINE_TRIGGERS {
            let statement = *baseline_statements(&format!("CREATE TRIGGER {name}\n"))
                .last()
                .unwrap();
            let header = statement.split_once(" ON ").unwrap().0;
            let mut bits = 0;
            for (word, bit) in [
                ("BEFORE", BEFORE),
                ("INSERT", INSERT),
                ("DELETE", DELETE),
                ("UPDATE", UPDATE),
                ("TRUNCATE", TRUNCATE),
            ] {
                if header.contains(word) {
                    bits |= bit;
                }
            }
            if statement.contains("FOR EACH ROW") {
                bits |= ROW;
            }
            assert_eq!(bits, *tgtype, "{name}");
        }
    }

    #[test]
    fn baseline_policy_expression_matches_0009() {
        let policy = baseline_statements(
            "CREATE POLICY tenant_isolation ON praetore.human_approval_expirations",
        );
        assert_eq!(policy.len(), 1);
        let compact: String = policy[0].split_whitespace().collect();
        let expected: String = BASELINE_POLICY_EXPRESSION.split_whitespace().collect();
        assert_eq!(compact.matches(&format!("({expected})")).count(), 2);
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
