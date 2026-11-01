//! Applies the bundled schema migrations exactly once each.
//!
//! Every applied migration is recorded in `praetore.schema_migrations` with
//! the SHA-256 of its text. A recorded migration is never executed again;
//! a recorded migration whose text changed is refused (migrations are
//! append-only). A session advisory lock serializes concurrent runners.
//!
//! Databases created before this runner have no control table. If such a
//! database matches the schema left by 0009, 0001-0009 are recorded as
//! applied without executing them and only the newer migrations run. The
//! match is live against live (`check_0009_baseline`): 0001-0009 are applied
//! into a scratch schema in a transaction that is rolled back, and a
//! canonical dump of both schemas (definitions, owners, ACLs, rules,
//! inheritance, dependents) must be identical. Any other pre-existing
//! `praetore` schema is
//! refused (fail closed). A control table that records a version this binary
//! does not know is refused too, so an older binary never runs against a
//! newer schema.
//!
//! Each migration and its `schema_migrations` row commit in one transaction
//! owned by the runner. A migration file may enclose its body in a single
//! top-level `BEGIN;` ... `COMMIT;` pair (0007-0009 do); the runner strips that
//! pair before executing and refuses any other transaction control, so a
//! crash can never leave a migration applied but unrecorded.
//!
//! A control table is not taken as proof that the schema came from these
//! migrations: on every run the live structure is compared with a scratch
//! apply of the recorded migrations (`structural_check`), and owners and the
//! environment are checked (`environment_problems`).
//!
//! The baseline check is best effort: it inspects an untrusted database from
//! inside it. It does not validate stored rows, and it cannot defend against
//! a superuser who edits the system catalogs directly.
//!
//! Every statement runs with `search_path = pg_catalog, pg_temp` (restored
//! afterwards), and a session with `session_replication_role` other than
//! `origin` is refused, so neither a shadowing catalog view or operator nor
//! disabled triggers can change what is checked or created.

use postgres::Client;
use sha2::{Digest, Sha256};

/// Ordered `(version, sql)` pairs. Append only; never edit or reorder.
pub const MIGRATIONS: [(&str, &str); 15] = [
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
    (
        "0015_storage_records",
        include_str!("../migrations/0015_storage_records.sql"),
    ),
];

/// The migration that creates `praetore.storage_records`; the runner also
/// executes it inside an adoption transaction (it is idempotent).
const STORAGE_RECORDS_VERSION: &str = "0015_storage_records";

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
    /// The migrating session would not enforce triggers or foreign keys
    /// (`session_replication_role` other than `origin`).
    UnsafeSession(String),
    /// The database carries state, planted before or after migrating, that
    /// would let another role act as the praetore owner or bypass the
    /// append-only design (checked on every run, fresh database or not).
    UnsafeDatabase(String),
    /// An existing `praetore` schema has no migration records and adopting
    /// it as a legacy 0001-0009 baseline was not requested.
    LegacyBaselineNotAdopted,
    /// Adoption was requested without a storage-record signer.
    AdoptionRequiresSigner,
    /// The live `praetore` schema differs from what its recorded migrations
    /// create (compared on every run against a scratch apply).
    SchemaDrift(String),
    /// An option could not be applied, for example a trusted SECURITY
    /// DEFINER function that does not resolve.
    InvalidConfiguration(String),
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => match error.as_db_error() {
                Some(db) => write!(
                    f,
                    "migration failed: {} (SQLSTATE {})",
                    db.message(),
                    db.code().code()
                ),
                None => write!(f, "migration failed: {error}"),
            },
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
            Self::UnsafeSession(reason) => write!(f, "refusing to migrate: {reason}"),
            Self::UnsafeDatabase(problems) => write!(f, "refusing to migrate: {problems}"),
            Self::SchemaDrift(differences) => write!(
                f,
                "praetore schema differs from what its recorded migrations create \
                 ({differences}); refusing to migrate"
            ),
            Self::InvalidConfiguration(reason) => {
                write!(f, "invalid migration configuration: {reason}")
            }
            Self::AdoptionRequiresSigner => write!(
                f,
                "adopting a legacy baseline requires signing its storage record with the \
                 evidence attester key; no signer was configured, refusing to migrate"
            ),
            Self::LegacyBaselineNotAdopted => write!(
                f,
                "existing praetore schema has no migration records; refusing to migrate. To \
                 compare it with 0001-0009 and adopt it as a legacy baseline, set \
                 {}=1 (praetore run --adopt-legacy-baseline)",
                MigrationOptions::ADOPT_LEGACY_BASELINE_ENV
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

/// How `apply_migrations_with` may treat state it would otherwise refuse.
/// Everything is refused by default; binaries fill this explicitly from
/// configuration (the library reads no environment).
#[derive(Clone, Default)]
pub struct MigrationOptions {
    /// Compare an existing `praetore` schema that has no migration records
    /// with 0001-0009 and, if identical, record 0001-0009 as applied (an
    /// adopted legacy baseline). Off by default: such a schema is refused.
    pub adopt_legacy_baseline: bool,
    /// SECURITY DEFINER functions outside `praetore` that run with the
    /// owner's rights and that the operator trusts: schema-qualified names
    /// with their full signature (for example `public.helper(integer)`),
    /// resolved with `to_regprocedure` and compared by OID. An entry that
    /// does not resolve is a configuration error. Whoever can execute a
    /// trusted function acts with its owner's privileges.
    pub trusted_security_definer: Vec<String>,
    /// Signs the storage record written when a legacy baseline is adopted
    /// (the binaries pass the evidence attester key). Without a signer,
    /// adoption is refused.
    pub record_signer: Option<std::sync::Arc<dyn praetore_core::StorageRecordSigner>>,
    /// Event triggers the operator trusts, by exact name
    /// (`PRAETORE_TRUSTED_EVENT_TRIGGERS`); see `environment_problems`.
    pub trusted_event_triggers: Vec<String>,
    /// Default-privilege entries the operator trusts, as
    /// `role:*:objtype` (`PRAETORE_TRUSTED_DEFAULT_PRIVILEGES`).
    pub trusted_default_privileges: Vec<String>,
}

impl std::fmt::Debug for MigrationOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationOptions")
            .field("adopt_legacy_baseline", &self.adopt_legacy_baseline)
            .field("trusted_security_definer", &self.trusted_security_definer)
            .field(
                "record_signer",
                &self.record_signer.as_ref().map(|signer| signer.key_id()),
            )
            .field("trusted_event_triggers", &self.trusted_event_triggers)
            .field(
                "trusted_default_privileges",
                &self.trusted_default_privileges,
            )
            .finish()
    }
}

impl MigrationOptions {
    /// Environment variable the binaries read for `adopt_legacy_baseline`.
    pub const ADOPT_LEGACY_BASELINE_ENV: &'static str = "PRAETORE_ADOPT_LEGACY_BASELINE";
    /// Environment variable the binaries read for trusted SECURITY DEFINER
    /// functions (semicolon-separated `regprocedure` names).
    pub const TRUSTED_SECURITY_DEFINER_ENV: &'static str =
        "PRAETORE_TRUSTED_SECURITY_DEFINER_FUNCTIONS";

    /// `PRAETORE_ADOPT_LEGACY_BASELINE`: unset, empty or `0` is off, `1` is
    /// on, anything else is a configuration error.
    pub fn parse_adopt_legacy_baseline(value: Option<&str>) -> Result<bool, String> {
        match value.map(str::trim) {
            None | Some("") | Some("0") => Ok(false),
            Some("1") => Ok(true),
            Some(other) => Err(format!(
                "{}: expected 1 or 0, got {other:?}",
                Self::ADOPT_LEGACY_BASELINE_ENV
            )),
        }
    }

    /// Environment variable for `trusted_event_triggers` (semicolon-separated
    /// exact names).
    pub const TRUSTED_EVENT_TRIGGERS_ENV: &'static str = "PRAETORE_TRUSTED_EVENT_TRIGGERS";
    /// Environment variable for `trusted_default_privileges`
    /// (semicolon-separated `role:*:objtype`).
    pub const TRUSTED_DEFAULT_PRIVILEGES_ENV: &'static str = "PRAETORE_TRUSTED_DEFAULT_PRIVILEGES";

    /// Semicolon-separated entries, trimmed; empty entries are ignored.
    pub fn parse_list(value: &str) -> Vec<String> {
        Self::parse_trusted_security_definer(value)
    }

    /// Semicolon-separated `regprocedure` names, trimmed; empty entries are
    /// ignored.
    pub fn parse_trusted_security_definer(value: &str) -> Vec<String> {
        value
            .split(';')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect()
    }
}

/// Applies pending migrations and returns the versions applied by this call
/// (empty when the schema is already current). Refuses an existing schema
/// without migration records; see `apply_migrations_with`.
pub fn apply_migrations(client: &mut Client) -> Result<Vec<&'static str>, MigrationError> {
    apply_migrations_with(client, &MigrationOptions::default())
}

/// `apply_migrations` with explicit options.
pub fn apply_migrations_with(
    client: &mut Client,
    options: &MigrationOptions,
) -> Result<Vec<&'static str>, MigrationError> {
    with_safe_search_path(client, |client| {
        check_session_fires_triggers(client)?;
        client.execute(
            "SELECT pg_catalog.pg_advisory_lock($1)",
            &[&MIGRATION_LOCK_KEY],
        )?;
        let result = apply_locked(client, options);
        let unlock = client.execute(
            "SELECT pg_catalog.pg_advisory_unlock($1)",
            &[&MIGRATION_LOCK_KEY],
        );
        let applied = result?;
        unlock?;
        Ok(applied)
    })
}

/// Read-only check for connections that must not migrate (the runtime role):
/// every bundled migration is recorded with its checksum and nothing newer
/// is recorded. Needs only SELECT on `praetore.schema_migrations`.
pub fn verify_schema_current(client: &mut Client) -> Result<(), MigrationError> {
    with_safe_search_path(client, verify_schema_current_inner)
}

fn verify_schema_current_inner(client: &mut Client) -> Result<(), MigrationError> {
    let has_control: bool = client
        .query_one(
            "SELECT pg_catalog.to_regclass('praetore.schema_migrations') IS NOT NULL",
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

/// The control table the runner creates (not a migration file). Adoption
/// columns are set only for 0001-0009 adopted from a legacy baseline.
/// `baseline_structure_sha256` identifies the 0001-0009 structure as the
/// server rendered it; it is the same for every database on a server
/// version and is not evidence about one database.
const CONTROL_TABLE_DDL: &str = "CREATE TABLE praetore.schema_migrations (\
     version TEXT PRIMARY KEY, \
     checksum CHAR(64) NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'), \
     applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), \
     adopted_legacy_baseline BOOLEAN NOT NULL DEFAULT false, \
     adopted_by TEXT, \
     baseline_structure_sha256 CHAR(64) \
         CHECK (baseline_structure_sha256 ~ '^[0-9a-f]{64}$'), \
     CHECK (adopted_legacy_baseline \
            = (adopted_by IS NOT NULL AND baseline_structure_sha256 IS NOT NULL)))";

/// `SET LOCAL ROLE` to the praetore schema owner when it is not the
/// migrating role (a NOLOGIN owner group the migrating role belongs to), so
/// that objects created by migrations get the same owner as the schema.
fn owner_role_statement(
    client: &mut impl postgres::GenericClient,
) -> Result<Option<String>, MigrationError> {
    let row = client.query_opt(
        "SELECT pg_catalog.quote_ident(pg_catalog.pg_get_userbyid(n.nspowner)), \
                n.nspowner OPERATOR(pg_catalog.=) \
                    (SELECT r.oid FROM pg_catalog.pg_roles r \
                     WHERE r.rolname OPERATOR(pg_catalog.=) CURRENT_USER) \
         FROM pg_catalog.pg_namespace n WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore'",
        &[],
    )?;
    Ok(row.and_then(|row| {
        let (owner, is_current): (String, bool) = (row.get(0), row.get(1));
        (!is_current).then(|| format!("SET LOCAL ROLE {owner}"))
    }))
}

/// Last migration that existed before the control table was introduced.
const BASELINE_VERSION: &str = "0009_human_approval_expirations";

fn apply_locked(
    client: &mut Client,
    options: &MigrationOptions,
) -> Result<Vec<&'static str>, MigrationError> {
    {
        let mut transaction = client.build_transaction().read_only(true).start()?;
        transaction.batch_execute(&format!("SET LOCAL search_path = {SAFE_SEARCH_PATH}"))?;
        let problems = environment_problems(&mut transaction, options)?;
        transaction.rollback()?;
        if !problems.is_empty() {
            return Err(MigrationError::UnsafeDatabase(problems.join("; ")));
        }
    }
    let has_control: bool = client
        .query_one(
            "SELECT pg_catalog.to_regclass('praetore.schema_migrations') IS NOT NULL",
            &[],
        )?
        .get(0);
    if !has_control {
        let has_schema: bool = client
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace \
                 WHERE nspname OPERATOR(pg_catalog.=) 'praetore')",
                &[],
            )?
            .get(0);
        if has_schema && !options.adopt_legacy_baseline {
            return Err(MigrationError::LegacyBaselineNotAdopted);
        }
        if has_schema && options.record_signer.is_none() {
            return Err(MigrationError::AdoptionRequiresSigner);
        }
        // The baseline check and the recording of 0001-0009 commit (or roll
        // back) together, with the praetore tables locked, so the schema
        // cannot change between the comparison and the record.
        let mut transaction = client.transaction()?;
        transaction.batch_execute(&format!("SET LOCAL search_path = {SAFE_SEARCH_PATH}"))?;
        let baseline = if has_schema {
            Some(check_0009_baseline(&mut transaction)?)
        } else {
            None
        };
        if let Some(statement) = owner_role_statement(&mut transaction)? {
            transaction.batch_execute(&statement)?;
        }
        if has_schema {
            // CREATE SCHEMA IF NOT EXISTS would still need CREATE on the
            // database, which a NOLOGIN owner group may not have.
            transaction.batch_execute(CONTROL_TABLE_DDL)?;
        } else {
            transaction.batch_execute(&format!(
                "CREATE SCHEMA IF NOT EXISTS praetore; {CONTROL_TABLE_DDL}"
            ))?;
        }
        if let Some(expected) = &baseline {
            let dump_sha256 = dump_checksum(expected);
            let signer = options
                .record_signer
                .as_ref()
                .ok_or(MigrationError::AdoptionRequiresSigner)?;
            for (version, sql) in MIGRATIONS {
                transaction.execute(
                    "INSERT INTO praetore.schema_migrations \
                     (version, checksum, adopted_legacy_baseline, adopted_by, \
                      baseline_structure_sha256) \
                     VALUES ($1, $2, true, SESSION_USER, $3)",
                    &[&version, &checksum(sql), &dump_sha256],
                )?;
                if version == BASELINE_VERSION {
                    break;
                }
            }
            record_adoption(&mut transaction, signer.as_ref(), &dump_sha256)?;
            // DDL that takes no lock on the praetore tables (CREATE OR
            // REPLACE FUNCTION, GRANT, ALTER SEQUENCE ...) can still commit
            // while this transaction waits, for example on CREATE TABLE
            // above. Compare again immediately before COMMIT; what remains is
            // the window between this query and the COMMIT itself.
            let mut live = schema_dump(&mut transaction, "praetore", "praetore")?;
            live.retain(|key, _| !is_control_table_key(key) && !is_storage_records_key(key));
            let differences = dump_differences(&live, expected);
            if !differences.is_empty() {
                return Err(MigrationError::UnrecognizedSchema(format!(
                    "changed while it was being recorded: {}",
                    differences.join("; ")
                )));
            }
        }
        transaction.commit()?;
    }

    let recorded = client.query("SELECT version FROM praetore.schema_migrations", &[])?;
    for row in &recorded {
        let version: String = row.get(0);
        if !MIGRATIONS.iter().any(|(known, _)| *known == version) {
            return Err(MigrationError::UnknownVersion(version));
        }
    }
    // A control table that existed before this run is not proof that the
    // schema came from these migrations: compare the structure with a
    // scratch apply of the recorded ones before migrating further.
    if has_control {
        let versions: Vec<&'static str> = MIGRATIONS
            .iter()
            .map(|(version, _)| *version)
            .filter(|version| recorded.iter().any(|row| row.get::<_, &str>(0) == *version))
            .collect();
        structural_check(client, &versions)?;
    }
    let owner_role = owner_role_statement(client)?;

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
        if let Some(statement) = &owner_role {
            transaction.batch_execute(statement)?;
        }
        transaction.batch_execute(body)?;
        transaction.execute(
            "INSERT INTO praetore.schema_migrations (version, checksum) VALUES ($1, $2)",
            &[&version, &checksum],
        )?;
        transaction.commit()?;
        applied.push(version);
    }
    if !has_control || !applied.is_empty() {
        let versions: Vec<&'static str> = MIGRATIONS.iter().map(|(version, _)| *version).collect();
        structural_check(client, &versions)?;
    }
    Ok(applied)
}

/// Compares the live `praetore` schema with a scratch schema in which
/// `versions` are applied, in a transaction that is always rolled back:
/// the same canonical dump as the baseline check, without the control
/// table (whose columns depend on the runner version that created it). Runs
/// on every `apply_migrations`: before migrating forward a schema that has
/// a control table, and after applying migrations. Needs CREATE on the
/// database, like migrating does.
fn structural_check(client: &mut Client, versions: &[&'static str]) -> Result<(), MigrationError> {
    let mut transaction = client.transaction()?;
    transaction.batch_execute(&format!("SET LOCAL search_path = {SAFE_SEARCH_PATH}"))?;
    let scratch = format!("praetore_check_{}", uuid::Uuid::new_v4().simple());
    let mut savepoint = transaction.savepoint("praetore_structure_scratch")?;
    let scratch_error = |what: &str, error: postgres::Error| {
        MigrationError::SchemaDrift(format!(
            "could not apply {what} to a scratch schema to compare with: {}",
            database_cause(&error)
        ))
    };
    savepoint
        .batch_execute(&rewrite_schema(
            &format!("CREATE SCHEMA praetore; {CONTROL_TABLE_DDL}"),
            &scratch,
        ))
        .map_err(|error| scratch_error("the control table", error))?;
    for (version, sql) in MIGRATIONS {
        if !versions.contains(&version) {
            continue;
        }
        let body = transactional_body(version, sql)?;
        savepoint
            .batch_execute(&rewrite_schema(body, &scratch))
            .map_err(|error| scratch_error(version, error))?;
    }
    let mut live = schema_dump(&mut savepoint, "praetore", "praetore")?;
    let mut expected = schema_dump(&mut savepoint, &scratch, &scratch)?;
    savepoint.rollback()?;
    transaction.rollback()?;
    // ACLs are not compared here: documented grants (praetore_observe) and
    // operator grants differ per installation, and `verify_runtime_role`
    // checks every praetore ACL against what the migrations intend.
    for dump in [&mut live, &mut expected] {
        dump.retain(|key, _| !is_control_table_key(key));
        for fields in dump.values_mut() {
            fields.remove("acl");
        }
    }
    let differences = dump_differences(&live, &expected);
    if differences.is_empty() {
        Ok(())
    } else {
        Err(MigrationError::SchemaDrift(differences.join("; ")))
    }
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

/// Search path for every statement the runner sends. Catalog tables,
/// functions, operators and types resolve in `pg_catalog`; a `public.pg_proc`
/// view or a `public.=` operator cannot shadow them, whatever search_path
/// the database, the role or the caller's session sets.
const SAFE_SEARCH_PATH: &str = "pg_catalog, pg_temp";

/// Runs `body` with `search_path` set to `SAFE_SEARCH_PATH` for the session,
/// then restores the caller's value.
fn with_safe_search_path<T>(
    client: &mut Client,
    body: impl FnOnce(&mut Client) -> Result<T, MigrationError>,
) -> Result<T, MigrationError> {
    let previous: String = client
        .query_one("SELECT pg_catalog.current_setting('search_path')", &[])?
        .get(0);
    client.batch_execute(&format!("SET search_path = {SAFE_SEARCH_PATH}"))?;
    let result = body(client);
    let restore = client.execute(
        "SELECT pg_catalog.set_config('search_path', $1, false)",
        &[&previous],
    );
    let value = result?;
    restore?;
    Ok(value)
}

/// Refuses a session in which triggers (including the internal triggers
/// behind foreign keys) do not fire.
fn check_session_fires_triggers(client: &mut Client) -> Result<(), MigrationError> {
    let role: String = client
        .query_one(
            "SELECT pg_catalog.current_setting('session_replication_role')",
            &[],
        )?
        .get(0);
    if role != "origin" {
        return Err(MigrationError::UnsafeSession(format!(
            "session_replication_role is {role}, so triggers and foreign keys do not fire; \
             it must be origin"
        )));
    }
    Ok(())
}

/// The 0009 baseline check.
///
/// In one transaction that is always rolled back, 0001-0009 are applied into
/// a fresh scratch schema (their text with the schema name rewritten, see
/// `rewrite_schema`), and the same canonical dump (`schema_dump`) is taken
/// of `praetore` and of the scratch schema. Both are rendered by the same
/// server under `SAFE_SEARCH_PATH` with the schema names normalized, so the
/// expected values come from this server and not from constants that a
/// PostgreSQL version could render differently. Any difference fails with
/// `UnrecognizedSchema` naming the objects. A few properties that the dump
/// cannot express (they are not per-schema) are checked on the live
/// database only: event triggers, per-database or per-role settings that
/// change search_path, row_security or session_replication_role, default
/// privileges, and the schema owner.
///
/// The comparison runs in the transaction that then records 0001-0009, with
/// the praetore tables locked (SHARE ROW EXCLUSIVE); the scratch schema lives
/// in a savepoint that is always rolled back. Needs the privileges that
/// applying 0001-0009 needs (CREATE on the database for the scratch schema).
///
/// Limits: this is a best-effort check of a database from inside it. It is
/// structural only: rows already stored (for example events written while
/// triggers were disabled) are not validated, and a legitimate
/// `VALIDATE CONSTRAINT` on the `NOT VALID` foreign keys of 0003/0007 is
/// reported as a difference (fail closed). It cannot defend against a
/// superuser who edits the system catalogs directly: whoever controls the
/// server as superuser controls what the catalogs say.
fn check_0009_baseline(
    transaction: &mut postgres::Transaction<'_>,
) -> Result<SchemaDump, MigrationError> {
    let tables: Vec<String> = transaction
        .query(
            "SELECT pg_catalog.format('%I.%I', n.nspname, c.relname) \
             FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
             WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore' \
               AND (c.relkind OPERATOR(pg_catalog.=) 'r' OR c.relkind OPERATOR(pg_catalog.=) 'p') \
             ORDER BY 1",
            &[],
        )?
        .iter()
        .map(|row| row.get(0))
        .collect();
    if !tables.is_empty() {
        transaction.batch_execute(&format!(
            "LOCK TABLE {} IN SHARE ROW EXCLUSIVE MODE",
            tables.join(", ")
        ))?;
    }
    let live_problems = baseline_only_problems(transaction)?;
    if !live_problems.is_empty() {
        return Err(MigrationError::UnrecognizedSchema(live_problems.join("; ")));
    }
    let scratch = format!("praetore_baseline_{}", uuid::Uuid::new_v4().simple());
    let mut savepoint = transaction.savepoint("praetore_baseline_scratch")?;
    for (version, sql) in MIGRATIONS {
        let body = transactional_body(version, sql)?;
        savepoint
            .batch_execute(&rewrite_schema(body, &scratch))
            .map_err(|error| {
                MigrationError::UnrecognizedSchema(format!(
                    "could not apply {version} to a scratch schema to compare with: {}",
                    database_cause(&error)
                ))
            })?;
        if version == BASELINE_VERSION {
            break;
        }
    }
    let live = schema_dump(&mut savepoint, "praetore", "praetore")?;
    let expected = schema_dump(&mut savepoint, &scratch, &scratch)?;
    savepoint.rollback()?;
    let differences = dump_differences(&live, &expected);
    if differences.is_empty() {
        Ok(expected)
    } else {
        Err(MigrationError::UnrecognizedSchema(differences.join("; ")))
    }
}

/// The server's message and SQLSTATE, not only "db error".
fn database_cause(error: &postgres::Error) -> String {
    match error.as_db_error() {
        Some(db) => format!("{} (SQLSTATE {})", db.message(), db.code().code()),
        None => error.to_string(),
    }
}

/// `sql` with every reference to the `praetore` schema (`praetore.x`,
/// `CREATE SCHEMA ... praetore`, `search_path = ..., praetore, ...`) replaced
/// by `schema`. The `praetore.tenant_id` and `praetore.dispatch_observed_at`
/// setting names are not schema references and are kept.
fn rewrite_schema(sql: &str, schema: &str) -> String {
    const NAME: &str = "praetore";
    let is_identifier = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
    let mut out = String::with_capacity(sql.len() + 64);
    let mut rest = sql;
    while let Some(index) = rest.find(NAME) {
        let (before, tail) = rest.split_at(index);
        let after = &tail[NAME.len()..];
        let boundary_before = !before.chars().next_back().is_some_and(is_identifier);
        let boundary_after = !after.chars().next().is_some_and(is_identifier);
        out.push_str(before);
        let setting = after.starts_with(".tenant_id") || after.starts_with(".dispatch_observed_at");
        if boundary_before && boundary_after && !setting {
            out.push_str(schema);
        } else {
            out.push_str(NAME);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// `key -> field -> value` for every object in one schema.
type SchemaDump = std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>;

/// Owner and ACL grantee/grantor: the schema owner as `OWNER`, PUBLIC as
/// `PUBLIC`, any other role by name.
fn role_sql(column: &str) -> String {
    format!(
        "CASE WHEN {column} OPERATOR(pg_catalog.=) ns.own THEN 'OWNER' \
              WHEN {column} OPERATOR(pg_catalog.=) 0::pg_catalog.oid THEN 'PUBLIC' \
              ELSE pg_catalog.pg_get_userbyid({column})::pg_catalog.text END"
    )
}

/// An ACL as sorted `grantee:grantor:privilege:grantable` entries.
fn acl_sql(acl: &str) -> String {
    format!(
        "(SELECT pg_catalog.string_agg(entry, ',' ORDER BY entry) FROM ( \
             SELECT pg_catalog.concat({grantee}, ':', {grantor}, ':', a.privilege_type, ':', \
                                      a.is_grantable) AS entry \
             FROM pg_catalog.aclexplode({acl}) a) entries)",
        grantee = role_sql("a.grantee"),
        grantor = role_sql("a.grantor"),
    )
}

/// A rendered definition with the dumped schema's name replaced by `praetore`.
fn norm(expression: &str) -> String {
    format!("pg_catalog.replace(({expression})::pg_catalog.text, $2, 'praetore')")
}

/// Canonical dump of schema `$1`, with the name `$2` normalized to
/// `praetore`: the schema (owner, ACL); every relation (kind, persistence,
/// RLS and FORCE RLS, partition flag, `relhastriggers`, `relhasrules`,
/// replica identity, access method, owner, ACL, index or view definition,
/// index flags `indisvalid`/`indisready`/`indislive`/`indimmediate`, and
/// sequence parameters from `pg_sequence`);
/// every column (type, NOT NULL, default, identity, generated, collation,
/// column ACL; collation with its schema); every constraint (`pg_get_constraintdef`, deferrable,
/// validated, inheritance); every function (result, language, SECURITY
/// DEFINER, `SET`, volatility, parallel, kind, STRICT, LEAKPROOF, `prosrc`,
/// owner, ACL, so overloads are separate keys); every non-internal trigger
/// (`pg_get_triggerdef`, enabled) and the enabled state of the internal
/// ones; every RLS policy (command, permissive, roles, USING, WITH CHECK);
/// every rewrite rule; inheritance and partitions in either direction; types;
/// operators, collations, conversions, operator classes and families,
/// extended statistics, text search objects and extensions in the schema;
/// and every object outside the schema that depends on a relation, function
/// or type in it.
fn schema_dump(
    transaction: &mut postgres::Transaction<'_>,
    schema: &str,
    normalized_name: &str,
) -> Result<SchemaDump, MigrationError> {
    let eq = "OPERATOR(pg_catalog.=)";
    let relation_acl_kind =
        format!("CASE WHEN c.relkind {eq} 'S' THEN 's' ELSE 'r' END::pg_catalog.\"char\"");
    let in_schema_relation = |column: &str| {
        format!(
            "EXISTS (SELECT 1 FROM pg_catalog.pg_class x \
                     WHERE x.oid {eq} {column} AND x.relnamespace {eq} ns.oid)"
        )
    };
    let other_objects = [
        ("operator", "pg_operator", "oprname", "oprnamespace"),
        ("collation", "pg_collation", "collname", "collnamespace"),
        ("conversion", "pg_conversion", "conname", "connamespace"),
        ("operator class", "pg_opclass", "opcname", "opcnamespace"),
        ("operator family", "pg_opfamily", "opfname", "opfnamespace"),
        ("statistics", "pg_statistic_ext", "stxname", "stxnamespace"),
        (
            "text search configuration",
            "pg_ts_config",
            "cfgname",
            "cfgnamespace",
        ),
        (
            "text search dictionary",
            "pg_ts_dict",
            "dictname",
            "dictnamespace",
        ),
        (
            "text search parser",
            "pg_ts_parser",
            "prsname",
            "prsnamespace",
        ),
        (
            "text search template",
            "pg_ts_template",
            "tmplname",
            "tmplnamespace",
        ),
        ("extension", "pg_extension", "extname", "extnamespace"),
    ]
    .iter()
    .map(|(label, catalog, name, namespace)| {
        format!(
            "SELECT pg_catalog.concat('{label} praetore.', o.{name}), 'present', '1' \
             FROM ns JOIN pg_catalog.{catalog} o ON o.{namespace} {eq} ns.oid"
        )
    })
    .collect::<Vec<_>>()
    .join(" UNION ALL ");
    let query = format!(
        "WITH ns AS (SELECT n.oid, n.nspowner AS own, n.nspacl FROM pg_catalog.pg_namespace n \
                     WHERE n.nspname {eq} $1::pg_catalog.name) \
         SELECT 'schema praetore', f.field, f.value FROM ns CROSS JOIN LATERAL (VALUES \
             ('owner', 'OWNER'), \
             ('acl', {schema_acl})) f(field, value) \
         UNION ALL \
         SELECT pg_catalog.concat('relation praetore.', c.relname), f.field, f.value \
         FROM ns JOIN pg_catalog.pg_class c ON c.relnamespace {eq} ns.oid \
         CROSS JOIN LATERAL (VALUES \
             ('kind', c.relkind::pg_catalog.text), \
             ('persistence', c.relpersistence::pg_catalog.text), \
             ('row security', c.relrowsecurity::pg_catalog.text), \
             ('force row security', c.relforcerowsecurity::pg_catalog.text), \
             ('partition', c.relispartition::pg_catalog.text), \
             ('has triggers', c.relhastriggers::pg_catalog.text), \
             ('has rules', c.relhasrules::pg_catalog.text), \
             ('replica identity', c.relreplident::pg_catalog.text), \
             ('access method', (SELECT am.amname::pg_catalog.text FROM pg_catalog.pg_am am \
                                WHERE am.oid {eq} c.relam)), \
             ('owner', {relation_owner}), \
             ('acl', {relation_acl}), \
             ('definition', CASE WHEN c.relkind {eq} 'i' THEN {index_def} \
                                 WHEN c.relkind {eq} 'v' OR c.relkind {eq} 'm' THEN {view_def} \
                            END)) f(field, value) \
         UNION ALL \
         SELECT pg_catalog.concat('relation praetore.', c.relname), f.field, f.value \
         FROM ns JOIN pg_catalog.pg_class c ON c.relnamespace {eq} ns.oid \
         JOIN pg_catalog.pg_index i ON i.indexrelid {eq} c.oid \
         CROSS JOIN LATERAL (VALUES \
             ('index valid', i.indisvalid::pg_catalog.text), \
             ('index ready', i.indisready::pg_catalog.text), \
             ('index live', i.indislive::pg_catalog.text), \
             ('index immediate', i.indimmediate::pg_catalog.text), \
             ('index replica identity', i.indisreplident::pg_catalog.text)) f(field, value) \
         UNION ALL \
         SELECT pg_catalog.concat('relation praetore.', c.relname), f.field, f.value \
         FROM ns JOIN pg_catalog.pg_class c ON c.relnamespace {eq} ns.oid \
         JOIN pg_catalog.pg_sequence q ON q.seqrelid {eq} c.oid \
         CROSS JOIN LATERAL (VALUES \
             ('sequence type', pg_catalog.format_type(q.seqtypid, NULL)), \
             ('sequence start', q.seqstart::pg_catalog.text), \
             ('sequence increment', q.seqincrement::pg_catalog.text), \
             ('sequence max', q.seqmax::pg_catalog.text), \
             ('sequence min', q.seqmin::pg_catalog.text), \
             ('sequence cache', q.seqcache::pg_catalog.text), \
             ('sequence cycle', q.seqcycle::pg_catalog.text)) f(field, value) \
         UNION ALL \
         SELECT pg_catalog.concat('column praetore.', c.relname, '.', a.attname), f.field, f.value \
         FROM ns JOIN pg_catalog.pg_class c ON c.relnamespace {eq} ns.oid \
         JOIN pg_catalog.pg_attribute a ON a.attrelid {eq} c.oid \
         CROSS JOIN LATERAL (VALUES \
             ('type', {column_type}), \
             ('not null', a.attnotnull::pg_catalog.text), \
             ('default', (SELECT {column_default} FROM pg_catalog.pg_attrdef d \
                          WHERE d.adrelid {eq} a.attrelid AND d.adnum {eq} a.attnum)), \
             ('identity', a.attidentity::pg_catalog.text), \
             ('generated', a.attgenerated::pg_catalog.text), \
             ('collation', {column_collation}), \
             ('acl', {column_acl})) f(field, value) \
         WHERE a.attnum OPERATOR(pg_catalog.>) 0 AND NOT a.attisdropped \
         UNION ALL \
         SELECT pg_catalog.concat('constraint praetore.', \
                    COALESCE((SELECT r.relname FROM pg_catalog.pg_class r WHERE r.oid {eq} con.conrelid), \
                             (SELECT t.typname FROM pg_catalog.pg_type t WHERE t.oid {eq} con.contypid)), \
                    '.', con.conname), f.field, f.value \
         FROM ns JOIN pg_catalog.pg_constraint con ON con.connamespace {eq} ns.oid \
         CROSS JOIN LATERAL (VALUES \
             ('type', con.contype::pg_catalog.text), \
             ('definition', {constraint_def}), \
             ('deferrable', con.condeferrable::pg_catalog.text), \
             ('deferred', con.condeferred::pg_catalog.text), \
             ('validated', con.convalidated::pg_catalog.text), \
             ('local', con.conislocal::pg_catalog.text), \
             ('inherited count', con.coninhcount::pg_catalog.text), \
             ('no inherit', con.connoinherit::pg_catalog.text)) f(field, value) \
         UNION ALL \
         SELECT pg_catalog.concat('function praetore.', p.proname, '(', \
                    {function_arguments}, ')'), f.field, f.value \
         FROM ns JOIN pg_catalog.pg_proc p ON p.pronamespace {eq} ns.oid \
         CROSS JOIN LATERAL (VALUES \
             ('result', {function_result}), \
             ('language', (SELECT l.lanname::pg_catalog.text FROM pg_catalog.pg_language l \
                           WHERE l.oid {eq} p.prolang)), \
             ('SECURITY DEFINER', p.prosecdef::pg_catalog.text), \
             ('SET (search_path)', {function_config}), \
             ('volatility', p.provolatile::pg_catalog.text), \
             ('parallel', p.proparallel::pg_catalog.text), \
             ('kind', p.prokind::pg_catalog.text), \
             ('STRICT', p.proisstrict::pg_catalog.text), \
             ('LEAKPROOF', p.proleakproof::pg_catalog.text), \
             ('returns set', p.proretset::pg_catalog.text), \
             ('body', {function_body}), \
             ('owner', {function_owner}), \
             ('acl', {function_acl})) f(field, value) \
         UNION ALL \
         SELECT pg_catalog.concat('trigger ', g.tgname, ' on praetore.', c.relname), f.field, f.value \
         FROM ns JOIN pg_catalog.pg_class c ON c.relnamespace {eq} ns.oid \
         JOIN pg_catalog.pg_trigger g ON g.tgrelid {eq} c.oid \
         CROSS JOIN LATERAL (VALUES \
             ('definition', {trigger_def}), \
             ('enabled', g.tgenabled::pg_catalog.text)) f(field, value) \
         WHERE NOT g.tgisinternal \
         UNION ALL \
         SELECT pg_catalog.concat('internal triggers on praetore.', c.relname), f.field, f.value \
         FROM ns JOIN pg_catalog.pg_class c ON c.relnamespace {eq} ns.oid \
         CROSS JOIN LATERAL (SELECT \
             pg_catalog.count(*)::pg_catalog.text AS total, \
             pg_catalog.count(*) FILTER (WHERE g.tgenabled OPERATOR(pg_catalog.<>) 'O')::pg_catalog.text \
                 AS not_origin \
             FROM pg_catalog.pg_trigger g WHERE g.tgrelid {eq} c.oid AND g.tgisinternal) i \
         CROSS JOIN LATERAL (VALUES ('count', i.total), ('not enabled', i.not_origin)) f(field, value) \
         UNION ALL \
         SELECT pg_catalog.concat('policy praetore.', c.relname, '.', pol.polname), f.field, f.value \
         FROM ns JOIN pg_catalog.pg_class c ON c.relnamespace {eq} ns.oid \
         JOIN pg_catalog.pg_policy pol ON pol.polrelid {eq} c.oid \
         CROSS JOIN LATERAL (VALUES \
             ('command', pol.polcmd::pg_catalog.text), \
             ('permissive', pol.polpermissive::pg_catalog.text), \
             ('roles', (SELECT pg_catalog.string_agg(role_name, ',' ORDER BY role_name) FROM \
                          (SELECT {policy_role} AS role_name \
                           FROM pg_catalog.unnest(pol.polroles) r(rid)) roles)), \
             ('USING', {policy_using}), \
             ('WITH CHECK', {policy_check})) f(field, value) \
         UNION ALL \
         SELECT pg_catalog.concat('rule ', rw.rulename, ' on praetore.', c.relname), f.field, f.value \
         FROM ns JOIN pg_catalog.pg_class c ON c.relnamespace {eq} ns.oid \
         JOIN pg_catalog.pg_rewrite rw ON rw.ev_class {eq} c.oid \
         CROSS JOIN LATERAL (VALUES \
             ('definition', {rule_def}), \
             ('enabled', rw.ev_enabled::pg_catalog.text)) f(field, value) \
         UNION ALL \
         SELECT pg_catalog.concat('inheritance ', {child}, ' of ', {parent}), 'present', '1' \
         FROM ns JOIN pg_catalog.pg_inherits h \
             ON {parent_in_schema} OR {child_in_schema} \
         UNION ALL \
         SELECT pg_catalog.concat('type praetore.', t.typname), f.field, f.value \
         FROM ns JOIN pg_catalog.pg_type t ON t.typnamespace {eq} ns.oid \
         CROSS JOIN LATERAL (VALUES \
             ('kind', t.typtype::pg_catalog.text), \
             ('owner', {type_owner}), \
             ('acl', {type_acl})) f(field, value) \
         UNION ALL \
         {other_objects} \
         UNION ALL \
         SELECT pg_catalog.concat('dependent ', {dependent_identity}, ' (', o.type, ')'), \
                'present', '1' \
         FROM ns JOIN pg_catalog.pg_depend d ON \
             (d.refclassid {eq} 'pg_catalog.pg_class'::pg_catalog.regclass \
                 AND {referenced_relation}) \
             OR (d.refclassid {eq} 'pg_catalog.pg_proc'::pg_catalog.regclass \
                 AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc x \
                             WHERE x.oid {eq} d.refobjid AND x.pronamespace {eq} ns.oid)) \
             OR (d.refclassid {eq} 'pg_catalog.pg_type'::pg_catalog.regclass \
                 AND EXISTS (SELECT 1 FROM pg_catalog.pg_type x \
                             WHERE x.oid {eq} d.refobjid AND x.typnamespace {eq} ns.oid)) \
         CROSS JOIN LATERAL pg_catalog.pg_identify_object(d.classid, d.objid, d.objsubid) o \
         WHERE o.schema IS NULL \
            OR NOT (o.schema {eq} $1::pg_catalog.text OR o.schema {eq} 'pg_toast')",
        schema_acl = acl_sql("COALESCE(ns.nspacl, pg_catalog.acldefault('n', ns.own))"),
        relation_owner = role_sql("c.relowner"),
        relation_acl = acl_sql(&format!(
            "COALESCE(c.relacl, pg_catalog.acldefault({relation_acl_kind}, c.relowner))"
        )),
        index_def = norm("pg_catalog.pg_get_indexdef(c.oid)"),
        view_def = norm("pg_catalog.pg_get_viewdef(c.oid)"),
        column_type = norm("pg_catalog.format_type(a.atttypid, a.atttypmod)"),
        column_default = norm("pg_catalog.pg_get_expr(d.adbin, d.adrelid)"),
        column_acl = acl_sql("a.attacl"),
        column_collation = norm(&format!(
            "CASE WHEN a.attcollation {eq} 0::pg_catalog.oid THEN NULL \
                  ELSE a.attcollation::pg_catalog.regcollation END"
        )),
        constraint_def = norm("pg_catalog.pg_get_constraintdef(con.oid)"),
        function_arguments = norm("pg_catalog.pg_get_function_identity_arguments(p.oid)"),
        function_result = norm("pg_catalog.pg_get_function_result(p.oid)"),
        function_config = norm("pg_catalog.array_to_string(p.proconfig, ';')"),
        function_body = norm("p.prosrc"),
        function_owner = role_sql("p.proowner"),
        function_acl = acl_sql("COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))"),
        trigger_def = norm("pg_catalog.pg_get_triggerdef(g.oid)"),
        policy_role = role_sql("r.rid"),
        policy_using = norm("pg_catalog.pg_get_expr(pol.polqual, pol.polrelid)"),
        policy_check = norm("pg_catalog.pg_get_expr(pol.polwithcheck, pol.polrelid)"),
        rule_def = norm("pg_catalog.pg_get_ruledef(rw.oid)"),
        child = norm("h.inhrelid::pg_catalog.regclass"),
        parent = norm("h.inhparent::pg_catalog.regclass"),
        parent_in_schema = in_schema_relation("h.inhparent"),
        child_in_schema = in_schema_relation("h.inhrelid"),
        type_owner = role_sql("t.typowner"),
        type_acl = acl_sql("COALESCE(t.typacl, pg_catalog.acldefault('T', t.typowner))"),
        dependent_identity = norm("o.identity"),
        referenced_relation = in_schema_relation("d.refobjid"),
    );
    let mut dump = SchemaDump::new();
    for row in transaction.query(&query, &[&schema, &normalized_name])? {
        let key: String = row.get(0);
        let field: String = row.get(1);
        let value: Option<String> = row.get(2);
        dump.entry(key)
            .or_default()
            .insert(field, value.unwrap_or_else(|| "<none>".to_owned()));
    }
    Ok(dump)
}

/// SHA-256 of a canonical dump (`key`, `field`, `value` lines in order), as
/// recorded for an adopted legacy baseline.
fn dump_checksum(dump: &SchemaDump) -> String {
    let mut hasher = Sha256::new();
    for (key, fields) in dump {
        for (field, value) in fields {
            for part in [
                key.as_str(),
                "\t",
                field.as_str(),
                "\t",
                value.as_str(),
                "\n",
            ] {
                hasher.update(part.as_bytes());
            }
        }
    }
    hex::encode(hasher.finalize())
}

/// How 0001-0009 were recorded when they were adopted from a legacy
/// baseline instead of executed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyBaselineAdoption {
    /// When the adoption was recorded (`applied_at`, as text).
    pub adopted_at: String,
    /// The migrating role that compared and adopted the schema.
    pub adopted_by: String,
    /// SHA-256 of the canonical 0001-0009 structure as the server rendered
    /// it. The same for every database on a server version: it identifies
    /// what was compared, not the database.
    pub structure_sha256: String,
}

impl std::fmt::Display for LegacyBaselineAdoption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "0001-0009 adopted from a legacy baseline at {} by {} (structure sha256 {}; \
             this record is not tamper-evident)",
            self.adopted_at, self.adopted_by, self.structure_sha256
        )
    }
}

/// Reports whether 0001-0009 were adopted from a legacy baseline. Needs
/// only SELECT on `praetore.schema_migrations`; `None` for a schema created
/// by migrations (or by a runner older than this record).
pub fn legacy_baseline_adoption(
    client: &mut Client,
) -> Result<Option<LegacyBaselineAdoption>, MigrationError> {
    with_safe_search_path(client, |client| {
        let has_column: bool = client
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a \
                 WHERE a.attrelid OPERATOR(pg_catalog.=) \
                       pg_catalog.to_regclass('praetore.schema_migrations') \
                   AND a.attname OPERATOR(pg_catalog.=) 'adopted_legacy_baseline' \
                   AND NOT a.attisdropped)",
                &[],
            )?
            .get(0);
        if !has_column {
            return Ok(None);
        }
        let row = client.query_opt(
            "SELECT applied_at::pg_catalog.text, adopted_by, baseline_structure_sha256::pg_catalog.text \
             FROM praetore.schema_migrations \
             WHERE version OPERATOR(pg_catalog.=) $1 AND adopted_legacy_baseline",
            &[&BASELINE_VERSION],
        )?;
        Ok(row.map(|row| LegacyBaselineAdoption {
            adopted_at: row.get(0),
            adopted_by: row.get(1),
            structure_sha256: row.get(2),
        }))
    })
}

/// A hint that the migration record does not match how it was written:
/// 0001-0009 written (or last updated) in one transaction, which is what an
/// adoption does, but not marked as adopted. The record is not
/// tamper-evident: the schema owner can rewrite it; this only flags the
/// most direct inconsistency.
pub fn migration_record_inconsistency(
    client: &mut Client,
) -> Result<Option<String>, MigrationError> {
    with_safe_search_path(client, |client| {
        let has_table: bool = client
            .query_one(
                "SELECT pg_catalog.to_regclass('praetore.schema_migrations') IS NOT NULL",
                &[],
            )?
            .get(0);
        if !has_table {
            return Ok(None);
        }
        let has_column: bool = client
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a \
                 WHERE a.attrelid OPERATOR(pg_catalog.=) \
                       pg_catalog.to_regclass('praetore.schema_migrations') \
                   AND a.attname OPERATOR(pg_catalog.=) 'adopted_legacy_baseline' \
                   AND NOT a.attisdropped)",
                &[],
            )?
            .get(0);
        let adopted = if has_column {
            "pg_catalog.bool_or(adopted_legacy_baseline)"
        } else {
            "false"
        };
        let row = client.query_one(
            &format!(
                "SELECT pg_catalog.count(*), \
                        pg_catalog.count(DISTINCT xmin::pg_catalog.text), {adopted} \
                 FROM praetore.schema_migrations \
                 WHERE version OPERATOR(pg_catalog.<=) $1"
            ),
            &[&BASELINE_VERSION],
        )?;
        let (rows, transactions, adopted): (i64, i64, Option<bool>) =
            (row.get(0), row.get(1), row.get(2));
        Ok(
            (rows == 9 && transactions == 1 && adopted != Some(true)).then(|| {
                "0001-0009 were recorded in a single transaction, as an adoption is, but are not \
             marked as adopted"
                    .to_owned()
            }),
        )
    })
}

/// At most this many differences are named in one error.
const MAX_REPORTED_DIFFERENCES: usize = 10;

fn dump_differences(live: &SchemaDump, expected: &SchemaDump) -> Vec<String> {
    // Whole objects first, their parts (columns, types, dependency rows)
    // last, so the most telling difference is named within the limit.
    let rank = |key: &str| {
        [
            "schema ",
            "setting",
            "relation ",
            "function ",
            "trigger ",
            "policy ",
            "rule ",
            "inheritance ",
            "constraint ",
            "internal ",
            "column ",
            "type ",
            "dependent ",
        ]
        .iter()
        .position(|prefix| key.starts_with(prefix))
        .unwrap_or(1)
    };
    let mut keys: Vec<&String> = live.keys().chain(expected.keys()).collect();
    keys.sort_by(|a, b| rank(a).cmp(&rank(b)).then_with(|| a.cmp(b)));
    keys.dedup();
    let mut differences = Vec::new();
    for key in keys {
        let difference = match (live.get(key), expected.get(key)) {
            (Some(_), None) => format!("{key} is not created by 0001-0009"),
            (None, Some(_)) => format!("{key} is missing"),
            (Some(found), Some(wanted)) if found != wanted => {
                let mut fields: Vec<&String> = found.keys().chain(wanted.keys()).collect();
                fields.sort();
                fields.dedup();
                let changed: Vec<&str> = fields
                    .into_iter()
                    .filter(|field| found.get(*field) != wanted.get(*field))
                    .map(String::as_str)
                    .collect();
                format!("{key} differs from 0009 in: {}", changed.join(", "))
            }
            _ => continue,
        };
        differences.push(difference);
        if differences.len() == MAX_REPORTED_DIFFERENCES {
            differences.push("...".to_owned());
            break;
        }
    }
    differences
}

/// One event trigger and, if it is refused, why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventTriggerStatus {
    pub name: String,
    pub listed: bool,
    pub problem: Option<String>,
}

/// Every event trigger in the database, checked against
/// `PRAETORE_TRUSTED_EVENT_TRIGGERS`. An unlisted trigger is refused. A
/// listed one is accepted only if it can be verified: the trigger and its
/// function are owned by superusers, the function is not in `praetore`,
/// and neither owner is, belongs to, or has as member the praetore owner or
/// the migrating role. A listed trigger that cannot be verified is refused
/// (fail closed).
fn event_trigger_statuses(
    transaction: &mut impl postgres::GenericClient,
    trusted: &[String],
) -> Result<Vec<EventTriggerStatus>, MigrationError> {
    let rows = transaction.query(
        &format!(
            "WITH RECURSIVE anchors(role) AS ( \
                 SELECT {OWNER_SQL} \
                 UNION SELECT r.oid FROM pg_catalog.pg_roles r \
                       WHERE r.rolname OPERATOR(pg_catalog.=) CURRENT_USER), \
             groups(role) AS ( \
                 SELECT role FROM anchors \
                 UNION \
                 SELECT m.roleid FROM pg_catalog.pg_auth_members m \
                 JOIN groups ON m.member OPERATOR(pg_catalog.=) groups.role), \
             members(role) AS ( \
                 SELECT role FROM anchors \
                 UNION \
                 SELECT m.member FROM pg_catalog.pg_auth_members m \
                 JOIN members ON m.roleid OPERATOR(pg_catalog.=) members.role), \
             related(role) AS (SELECT role FROM groups UNION SELECT role FROM members) \
             SELECT e.evtname::pg_catalog.text, e.evtevent::pg_catalog.text, \
                    pg_catalog.pg_get_userbyid(e.evtowner)::pg_catalog.text, \
                    COALESCE(ow.rolsuper, false), \
                    p.oid::pg_catalog.regprocedure::pg_catalog.text, \
                    pg_catalog.pg_get_userbyid(p.proowner)::pg_catalog.text, \
                    COALESCE(fo.rolsuper, false), \
                    fn.nspname OPERATOR(pg_catalog.=) 'praetore', \
                    EXISTS (SELECT 1 FROM related \
                            WHERE related.role OPERATOR(pg_catalog.=) e.evtowner \
                               OR related.role OPERATOR(pg_catalog.=) p.proowner) \
             FROM pg_catalog.pg_event_trigger e \
             LEFT JOIN pg_catalog.pg_roles ow ON ow.oid OPERATOR(pg_catalog.=) e.evtowner \
             LEFT JOIN pg_catalog.pg_proc p ON p.oid OPERATOR(pg_catalog.=) e.evtfoid \
             LEFT JOIN pg_catalog.pg_roles fo ON fo.oid OPERATOR(pg_catalog.=) p.proowner \
             LEFT JOIN pg_catalog.pg_namespace fn ON fn.oid OPERATOR(pg_catalog.=) p.pronamespace \
             ORDER BY 1"
        ),
        &[],
    )?;
    Ok(rows
        .iter()
        .map(|row| {
            let name: String = row.get(0);
            let listed = trusted.contains(&name);
            let (event, owner, owner_super, function, function_owner, function_super) = (
                row.get::<_, String>(1),
                row.get::<_, String>(2),
                row.get::<_, bool>(3),
                row.get::<_, Option<String>>(4).unwrap_or_default(),
                row.get::<_, Option<String>>(5).unwrap_or_default(),
                row.get::<_, bool>(6),
            );
            let (in_praetore, related): (Option<bool>, bool) = (row.get(7), row.get(8));
            let problem = if !listed {
                Some(format!(
                    "event trigger {name} ({event}) exists; it would run during migrations \
                     (not listed in PRAETORE_TRUSTED_EVENT_TRIGGERS)"
                ))
            } else {
                let mut reasons = Vec::new();
                if !owner_super {
                    reasons.push(format!("its owner {owner} is not a superuser"));
                }
                if !function_super {
                    reasons.push(format!(
                        "its function {function} is owned by {function_owner}, not a superuser"
                    ));
                }
                if in_praetore.unwrap_or(true) {
                    reasons.push("its function is in praetore or cannot be resolved".to_owned());
                }
                if related {
                    reasons.push(
                        "an owner is, belongs to, or has as member the praetore owner or the \
                         migrating role"
                            .to_owned(),
                    );
                }
                (!reasons.is_empty()).then(|| {
                    format!(
                        "event trigger {name} is listed in PRAETORE_TRUSTED_EVENT_TRIGGERS but \
                         cannot be verified: {}",
                        reasons.join("; ")
                    )
                })
            };
            EventTriggerStatus {
                name,
                listed,
                problem,
            }
        })
        .collect())
}

/// Event triggers and their status, for the startup log and `praetore
/// doctor`.
pub fn event_trigger_report(
    client: &mut Client,
    trusted: &[String],
) -> Result<Vec<EventTriggerStatus>, MigrationError> {
    with_safe_search_path(client, |client| {
        let mut transaction = client.build_transaction().read_only(true).start()?;
        let statuses = event_trigger_statuses(&mut transaction, trusted);
        transaction.rollback()?;
        statuses
    })
}

/// `PRAETORE_TRUSTED_DEFAULT_PRIVILEGES` entries: `role:*:objtype`, with
/// `objtype` one of `r`, `S`, `f`, `T`, `n` (as in `pg_default_acl`). Only
/// global entries can be trusted: entries in `praetore` are never allowed,
/// and entries in other schemas never apply to praetore objects.
pub fn parse_trusted_default_privileges(
    entries: &[String],
) -> Result<Vec<(String, String)>, String> {
    entries
        .iter()
        .map(|entry| {
            let parts: Vec<&str> = entry.split(':').collect();
            match parts.as_slice() {
                [role, "*", kind]
                    if !role.is_empty() && matches!(*kind, "r" | "S" | "f" | "T" | "n") =>
                {
                    Ok(((*role).to_owned(), (*kind).to_owned()))
                }
                _ => Err(format!(
                    "PRAETORE_TRUSTED_DEFAULT_PRIVILEGES entry {entry:?} must be role:*:objtype \
                     with objtype r, S, f, T or n"
                )),
            }
        })
        .collect()
}

/// The future or current owner of `praetore`: the schema owner, or the
/// migrating role when the schema does not exist yet.
const OWNER_SQL: &str = "(SELECT COALESCE(\
     (SELECT n.nspowner FROM pg_catalog.pg_namespace n \
      WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore'), \
     (SELECT r.oid FROM pg_catalog.pg_roles r \
      WHERE r.rolname OPERATOR(pg_catalog.=) CURRENT_USER)))";

/// A function owner `p.proowner` that has the rights of `owner_role.oid`
/// (superusers included, since they have every role's rights). Functions
/// the operator trusts are excluded by OID (`$1`, resolved from
/// `MigrationOptions::trusted_security_definer`).
const OWNER_RIGHTS_SQL: &str = "pg_catalog.pg_has_role(p.proowner, owner_role.oid, 'USAGE') \
     AND NOT (p.oid OPERATOR(pg_catalog.=) ANY ($1::pg_catalog.oid[]))";

/// Whether a `search_path` value lets another schema shadow `pg_catalog`
/// (`pg_catalog` listed after another schema). `"$user", public` does not:
/// an unlisted `pg_catalog` is searched first.
fn search_path_shadows_catalog(value: &str) -> bool {
    let entries: Vec<&str> = value
        .split(',')
        .map(|entry| entry.trim().trim_matches('"'))
        .filter(|entry| !entry.is_empty())
        .collect();
    match entries.iter().position(|entry| *entry == "pg_catalog") {
        None => false,
        Some(index) => entries[..index]
            .iter()
            .any(|entry| !entry.starts_with("pg_temp")),
    }
}

/// Writes the signed adoption record: creates `praetore.storage_records`
/// with migration 0015 (idempotent; recorded later in the normal order) and
/// inserts the record, in the adoption transaction.
fn record_adoption(
    transaction: &mut postgres::Transaction<'_>,
    signer: &dyn praetore_core::StorageRecordSigner,
    structure_sha256: &str,
) -> Result<(), MigrationError> {
    let (_, sql) = MIGRATIONS
        .iter()
        .find(|(version, _)| *version == STORAGE_RECORDS_VERSION)
        .expect("0015 is bundled");
    transaction.batch_execute(transactional_body(STORAGE_RECORDS_VERSION, sql)?)?;
    let row = transaction.query_one(
        "SELECT pg_catalog.to_char(pg_catalog.clock_timestamp() AT TIME ZONE 'UTC', \
                    'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), \
                pg_catalog.current_database()::pg_catalog.text, \
                (SELECT d.oid FROM pg_catalog.pg_database d \
                 WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()), \
                SESSION_USER::pg_catalog.text",
        &[],
    )?;
    let payload = praetore_core::StorageRecordPayload {
        schema_version: praetore_core::storage_record::STORAGE_RECORD_SCHEMA_VERSION,
        kind: praetore_core::storage_record::LEGACY_BASELINE_ADOPTED.to_owned(),
        record_id: uuid::Uuid::new_v4(),
        recorded_at: row.get(0),
        database: row.get(1),
        database_oid: row.get(2),
        recorded_by: row.get(3),
        migrations: MIGRATIONS
            .iter()
            .take_while(|(version, _)| *version <= BASELINE_VERSION)
            .map(|(version, sql)| praetore_core::RecordedMigration {
                version: (*version).to_owned(),
                checksum: checksum(sql),
            })
            .collect(),
        structure_sha256: structure_sha256.to_owned(),
        key_id: signer.key_id(),
    };
    let record = signer.sign_storage_record(payload).map_err(|error| {
        MigrationError::InvalidConfiguration(format!("cannot sign the adoption record: {error}"))
    })?;
    let json = record.to_json().map_err(|error| {
        MigrationError::InvalidConfiguration(format!("cannot encode the adoption record: {error}"))
    })?;
    transaction.execute(
        "INSERT INTO praetore.storage_records (record_id, kind, record_json) VALUES ($1, $2, $3)",
        &[&record.record_id, &record.kind, &json],
    )?;
    Ok(())
}

/// Keys of `praetore.storage_records` and its trigger function, which the
/// adoption transaction creates before 0015 is recorded.
fn is_storage_records_key(key: &str) -> bool {
    let Some((_, rest)) = key.split_once("praetore.") else {
        return false;
    };
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    matches!(
        name.as_str(),
        "storage_records"
            | "storage_records_pkey"
            | "_storage_records"
            | "reject_storage_record_mutation"
    )
}

/// Keys of the control table, created in the recording transaction: the
/// first object named after `praetore.` is `schema_migrations`, its primary
/// key index or its array type.
fn is_control_table_key(key: &str) -> bool {
    let Some((_, rest)) = key.split_once("praetore.") else {
        return false;
    };
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    matches!(
        name.as_str(),
        "schema_migrations" | "schema_migrations_pkey" | "_schema_migrations"
    )
}

/// State checked on every `apply_migrations`, fresh database, baseline or
/// current, because a dump of `praetore` cannot see it: event triggers;
/// per-database or per-role `row_security`, `session_replication_role` or
/// a `search_path` that lets another schema shadow `pg_catalog`; default
/// privileges for the praetore schema, its owner or the migrating role;
/// SECURITY DEFINER functions outside `praetore` with the owner's rights;
/// and roles other than the migrating role (and NOLOGIN groups it belongs
/// to) that can act as the owner. The owner is the schema owner, or the
/// migrating role for a fresh database.
fn environment_problems(
    transaction: &mut postgres::Transaction<'_>,
    options: &MigrationOptions,
) -> Result<Vec<String>, MigrationError> {
    const OWNER: &str = OWNER_SQL;
    const OWNER_RIGHTS: &str = OWNER_RIGHTS_SQL;
    let trusted: Vec<u32> = crate::connection::resolve_trusted_security_definer(
        transaction,
        &options.trusted_security_definer,
    )
    .map_err(MigrationError::InvalidConfiguration)?
    .iter()
    .map(|function| function.oid)
    .collect();
    let mut problems = Vec::new();
    for status in event_trigger_statuses(transaction, &options.trusted_event_triggers)? {
        if let Some(problem) = status.problem {
            problems.push(problem);
        }
    }
    for row in transaction.query(
        "SELECT COALESCE(r.rolname::pg_catalog.text, 'all roles'), \
                COALESCE(d.datname::pg_catalog.text, 'all databases'), s.setting \
         FROM pg_catalog.pg_db_role_setting rs \
         LEFT JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) rs.setrole \
         LEFT JOIN pg_catalog.pg_database d ON d.oid OPERATOR(pg_catalog.=) rs.setdatabase \
         CROSS JOIN LATERAL pg_catalog.unnest(rs.setconfig) s(setting) \
         WHERE (rs.setdatabase OPERATOR(pg_catalog.=) 0::pg_catalog.oid \
                OR d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) \
           AND (pg_catalog.starts_with(s.setting, 'session_replication_role=') \
                OR pg_catalog.starts_with(s.setting, 'row_security=') \
                OR pg_catalog.starts_with(s.setting, 'search_path=')) \
         ORDER BY 1, 2, 3",
        &[],
    )? {
        let (role, database, setting): (String, String, String) =
            (row.get(0), row.get(1), row.get(2));
        if let Some(value) = setting.strip_prefix("search_path=")
            && !search_path_shadows_catalog(value)
        {
            continue;
        }
        problems.push(format!(
            "setting {setting} for {role} in {database} is not allowed"
        ));
    }
    let trusted_defaults = parse_trusted_default_privileges(&options.trusted_default_privileges)
        .map_err(MigrationError::InvalidConfiguration)?;
    for row in transaction.query(
        &format!(
            "SELECT pg_catalog.pg_get_userbyid(a.defaclrole)::pg_catalog.text, \
                    a.defaclnamespace OPERATOR(pg_catalog.<>) 0::pg_catalog.oid, \
                    a.defaclobjtype::pg_catalog.text, \
                    NOT EXISTS ( \
                        SELECT 1 FROM pg_catalog.aclexplode(a.defaclacl) g \
                        WHERE NOT EXISTS ( \
                            SELECT 1 FROM pg_catalog.aclexplode(pg_catalog.acldefault( \
                                CASE WHEN a.defaclobjtype OPERATOR(pg_catalog.=) 'S' THEN 's' \
                                     ELSE a.defaclobjtype::pg_catalog.text END::pg_catalog.\"char\", \
                                a.defaclrole)) d \
                            WHERE d.grantee OPERATOR(pg_catalog.=) g.grantee \
                              AND d.privilege_type OPERATOR(pg_catalog.=) g.privilege_type \
                              AND (d.is_grantable OR NOT g.is_grantable))) \
             FROM pg_catalog.pg_default_acl a \
             WHERE a.defaclnamespace OPERATOR(pg_catalog.=) \
                       (SELECT n.oid FROM pg_catalog.pg_namespace n \
                        WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore') \
                OR (a.defaclnamespace OPERATOR(pg_catalog.=) 0::pg_catalog.oid \
                    AND (a.defaclrole OPERATOR(pg_catalog.=) {OWNER} \
                         OR a.defaclrole OPERATOR(pg_catalog.=) \
                            (SELECT r.oid FROM pg_catalog.pg_roles r \
                             WHERE r.rolname OPERATOR(pg_catalog.=) CURRENT_USER))) \
             ORDER BY 1, 2, 3"
        ),
        &[],
    )? {
        let (role, in_praetore, kind, revoke_only): (String, bool, String, bool) =
            (row.get(0), row.get(1), row.get(2), row.get(3));
        let schema = if in_praetore { "praetore" } else { "all schemas" };
        let listed = trusted_defaults
            .iter()
            .any(|(trusted_role, trusted_kind)| *trusted_role == role && *trusted_kind == kind);
        if !in_praetore && listed && revoke_only {
            continue;
        }
        let why = if in_praetore {
            "default privileges in praetore are never allowed"
        } else if listed {
            "it is listed in PRAETORE_TRUSTED_DEFAULT_PRIVILEGES but grants privileges; only \
             entries that only revoke can be trusted"
        } else {
            "not allowed"
        };
        problems.push(format!(
            "default privileges of {role} in {schema} (object type {kind}): {why}"
        ));
    }
    for row in transaction.query(
        &format!(
            "SELECT p.oid::pg_catalog.regprocedure::pg_catalog.text \
             FROM pg_catalog.pg_proc p \
             JOIN pg_catalog.pg_namespace fn ON fn.oid OPERATOR(pg_catalog.=) p.pronamespace \
             CROSS JOIN (SELECT {OWNER} AS oid) owner_role \
             WHERE p.prosecdef \
               AND fn.nspname OPERATOR(pg_catalog.<>) 'pg_catalog' \
               AND fn.nspname OPERATOR(pg_catalog.<>) 'information_schema' \
               AND fn.nspname OPERATOR(pg_catalog.<>) 'praetore' \
               AND {OWNER_RIGHTS} \
             ORDER BY 1"
        ),
        &[&trusted],
    )? {
        let function: String = row.get(0);
        problems.push(format!(
            "SECURITY DEFINER function {function} outside praetore runs with the rights of the \
             praetore owner"
        ));
    }
    for row in transaction.query(
        &format!(
            "WITH RECURSIVE \
             owner_role AS (SELECT {OWNER} AS oid), \
             migrator AS (SELECT r.oid FROM pg_catalog.pg_roles r \
                          WHERE r.rolname OPERATOR(pg_catalog.=) CURRENT_USER), \
             acting(role) AS ( \
                 SELECT oid FROM owner_role \
                 UNION \
                 SELECT m.member FROM pg_catalog.pg_auth_members m \
                 JOIN acting a ON m.roleid OPERATOR(pg_catalog.=) a.role), \
             migrator_groups(role) AS ( \
                 SELECT oid FROM migrator \
                 UNION \
                 SELECT m.roleid FROM pg_catalog.pg_auth_members m \
                 JOIN migrator_groups g ON m.member OPERATOR(pg_catalog.=) g.role) \
         SELECT r.rolname::pg_catalog.text, r.rolcanlogin, \
                EXISTS (SELECT 1 FROM migrator_groups g \
                        WHERE g.role OPERATOR(pg_catalog.=) a.role), \
                a.role OPERATOR(pg_catalog.=) (SELECT oid FROM owner_role) \
         FROM acting a JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) a.role \
         WHERE NOT EXISTS (SELECT 1 FROM migrator \
                           WHERE migrator.oid OPERATOR(pg_catalog.=) a.role) \
         ORDER BY 1"
        ),
        &[],
    )? {
        let (role, can_login, on_migrator_path, is_owner): (String, bool, bool, bool) =
            (row.get(0), row.get(1), row.get(2), row.get(3));
        if is_owner && !on_migrator_path {
            problems.push(format!(
                "schema praetore is owned by {role}, and the migrating role is neither that role \
                 nor a member of it"
            ));
            continue;
        }
        if !on_migrator_path {
            problems.push(format!(
                "role {role} can act as the praetore owner (it is, or is a member of, the \
                 owner role) but is not the migrating role or one of its groups"
            ));
        } else if can_login {
            problems.push(format!(
                "role {role} owns praetore or links the migrating role to the owner, and can \
                 log in; the owner and the roles in between must be NOLOGIN"
            ));
        }
    }
    Ok(problems)
}

/// Checks only for adopting a legacy baseline: no publication may replicate
/// the praetore tables. (Owners are checked on every run.)
fn baseline_only_problems(
    transaction: &mut postgres::Transaction<'_>,
) -> Result<Vec<String>, MigrationError> {
    let mut problems = Vec::new();
    for row in transaction.query(
        "SELECT p.pubname::pg_catalog.text FROM pg_catalog.pg_publication p \
         WHERE p.puballtables ORDER BY 1",
        &[],
    )? {
        let name: String = row.get(0);
        problems.push(format!("publication {name} is FOR ALL TABLES"));
    }
    let has_schema_publications: bool = transaction
        .query_one(
            "SELECT pg_catalog.to_regclass('pg_catalog.pg_publication_namespace') IS NOT NULL",
            &[],
        )?
        .get(0);
    if has_schema_publications {
        for row in transaction.query(
            "SELECT p.pubname::pg_catalog.text FROM pg_catalog.pg_publication p \
             JOIN pg_catalog.pg_publication_namespace pn \
               ON pn.pnpubid OPERATOR(pg_catalog.=) p.oid \
             JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) pn.pnnspid \
             WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore' ORDER BY 1",
            &[],
        )? {
            let name: String = row.get(0);
            problems.push(format!(
                "publication {name} includes TABLES IN SCHEMA praetore"
            ));
        }
    }
    Ok(problems)
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
    fn rewrite_schema_replaces_every_schema_reference_and_keeps_the_tenant_setting() {
        let scratch = "praetore_baseline_test";
        for (version, sql) in MIGRATIONS {
            let rewritten = rewrite_schema(transactional_body(version, sql).unwrap(), scratch);
            let leftover = rewritten
                .replace(scratch, "")
                .replace("praetore.tenant_id", "");
            assert!(!leftover.contains("praetore"), "{version}: {leftover}");
            if version == BASELINE_VERSION {
                break;
            }
        }
        assert_eq!(
            rewrite_schema(
                "CREATE SCHEMA IF NOT EXISTS praetore; SET search_path = pg_catalog, praetore, \
                 pg_temp; praetore.t; praetore_runtime; my_praetore; \
                 current_setting('praetore.tenant_id', true)",
                "s"
            ),
            "CREATE SCHEMA IF NOT EXISTS s; SET search_path = pg_catalog, s, \
             pg_temp; s.t; praetore_runtime; my_praetore; \
             current_setting('praetore.tenant_id', true)"
        );
    }

    #[test]
    fn only_a_search_path_that_lists_another_schema_before_pg_catalog_shadows_it() {
        for harmless in [
            "\"$user\", public",
            "public, extensions",
            "pg_catalog, public",
            "pg_temp, pg_catalog",
            "",
        ] {
            assert!(!search_path_shadows_catalog(harmless), "{harmless}");
        }
        for hostile in [
            "public, pg_catalog",
            "\"$user\", pg_catalog",
            "x,pg_catalog",
        ] {
            assert!(search_path_shadows_catalog(hostile), "{hostile}");
        }
    }

    #[test]
    fn control_table_keys_are_exactly_the_control_table() {
        for key in [
            "relation praetore.schema_migrations",
            "relation praetore.schema_migrations_pkey",
            "internal triggers on praetore.schema_migrations_pkey",
            "column praetore.schema_migrations.version",
            "constraint praetore.schema_migrations.schema_migrations_check",
            "type praetore._schema_migrations",
            "dependent for praetore.schema_migrations.applied_at (default value)",
        ] {
            assert!(is_control_table_key(key), "{key}");
        }
        for key in [
            "relation praetore.schema_migrations_extra",
            "relation praetore.replay_claims",
            "function praetore.schema_migrations_helper()",
            "schema praetore",
        ] {
            assert!(!is_control_table_key(key), "{key}");
        }
    }

    #[test]
    fn dump_differences_name_missing_extra_and_changed_objects() {
        let dump = |entries: &[(&str, &str, &str)]| {
            let mut dump = SchemaDump::new();
            for (key, field, value) in entries {
                dump.entry((*key).to_owned())
                    .or_default()
                    .insert((*field).to_owned(), (*value).to_owned());
            }
            dump
        };
        let expected = dump(&[("a", "body", "x"), ("b", "owner", "OWNER")]);
        assert!(dump_differences(&expected, &expected).is_empty());
        let live = dump(&[("a", "body", "y"), ("c", "present", "1")]);
        assert_eq!(
            dump_differences(&live, &expected),
            vec![
                "a differs from 0009 in: body",
                "b is missing",
                "c is not created by 0001-0009"
            ]
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
