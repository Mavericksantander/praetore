//! `praetore journal-export`: producer of the hash-linked JSONL format in
//! `docs/proposals/journal-chain-jsonl.md`. The chain itself is built by
//! `praetore_core::journal_chain::ChainExporter`, the same code the verifier
//! uses, so producer and verifier cannot disagree on the link.

use praetore_core::{
    Evidence, VerifiedPublicKey,
    journal_chain::{ChainExporter, ChainHead, MAX_CHAIN_ENTRIES},
};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

const MAX_RECEIPT_BYTES: u64 = 65_536;

/// Where the receipts come from. Exactly one source per export.
#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    /// A directory of `*.json` receipts, chained in byte order of file name.
    ReceiptsDir(PathBuf),
    /// `praetore.execution_journal` rows of one tenant, ordered by
    /// `(created_at, request_id, agent_id)`; the primary key is
    /// `(tenant_id, agent_id, request_id)`, so `agent_id` makes the order
    /// total. Both ids are `UUID`, compared byte by byte (the same order as
    /// their lowercase hex text). Reads `PRAETORE_GATEWAY_DATABASE_URL`.
    Database { tenant_id: Uuid },
}

#[derive(Debug, PartialEq, Eq)]
pub struct ExportArgs {
    pub source: Source,
    pub attester_pin: PathBuf,
    pub output: PathBuf,
}

pub fn parse(args: impl Iterator<Item = String>) -> CliResult<ExportArgs> {
    let mut receipts_dir = None;
    let mut tenant = None;
    let mut attester_pin = None;
    let mut output = None;
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--receipts-dir" => &mut receipts_dir,
            "--tenant" => &mut tenant,
            "--attester-pin" => &mut attester_pin,
            "--output" => &mut output,
            _ => return Err(format!("unexpected argument: {flag}").into()),
        };
        let value = args.next().ok_or(format!("missing value for {flag}"))?;
        if slot.replace(value).is_some() {
            return Err(format!("{flag} given twice").into());
        }
    }
    let source = match (receipts_dir, tenant) {
        (Some(dir), None) => Source::ReceiptsDir(dir.into()),
        (None, Some(tenant)) => Source::Database {
            tenant_id: Uuid::parse_str(&tenant).map_err(|_| "--tenant must be a UUID")?,
        },
        _ => return Err("pass exactly one of --receipts-dir or --tenant".into()),
    };
    Ok(ExportArgs {
        source,
        attester_pin: attester_pin.ok_or("missing --attester-pin")?.into(),
        output: output.ok_or("missing --output")?.into(),
    })
}

pub fn run(args: ExportArgs) -> CliResult<()> {
    let attester = read_attester_pin(&args.attester_pin)?;
    let receipts = match &args.source {
        Source::ReceiptsDir(dir) => read_receipts_dir(dir)?,
        Source::Database { tenant_id } => {
            let url = std::env::var("PRAETORE_GATEWAY_DATABASE_URL")
                .map_err(|_| "PRAETORE_GATEWAY_DATABASE_URL must point to local PostgreSQL")?;
            read_journal(&url, *tenant_id)?
        }
    };
    let (text, head) = export(&receipts, &attester)?;
    // Never overwrite: an existing file may be an anchored export.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)
        .map_err(|error| format!("cannot create {}: {error}", args.output.display()))?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "command": "journal-export",
            "entries": head.entries.get(),
            "head": head.head.to_hex(),
        })
    );
    Ok(())
}

/// Chains receipts given as JSON text, in order. Fails on the first receipt
/// that does not parse, lacks or fails its attester signature, or repeats an
/// `evidence_id`.
pub fn export(receipts: &[String], attester: &VerifiedPublicKey) -> CliResult<(String, ChainHead)> {
    let mut exporter = ChainExporter::new(attester);
    for (index, json) in receipts.iter().enumerate() {
        let evidence = Evidence::from_json(json.trim_end())
            .map_err(|error| format!("receipt {index}: {error}"))?;
        exporter.push(&evidence)?;
    }
    Ok(exporter.finish()?)
}

fn read_attester_pin(path: &Path) -> CliResult<VerifiedPublicKey> {
    let text = read_limited(path)?;
    let encoded = text.trim();
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("attester pin must be 64 lowercase hex characters".into());
    }
    Ok(VerifiedPublicKey::from_bytes(&hex::decode(encoded)?)?)
}

fn read_limited(path: &Path) -> CliResult<String> {
    let mut text = String::new();
    fs::File::open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(format!("{} exceeds {MAX_RECEIPT_BYTES} bytes", path.display()).into());
    }
    Ok(text)
}

/// Reads every entry of `dir`. Fails closed on anything that is not a regular
/// `*.json` file (subdirectories, symlinks, other extensions).
fn read_receipts_dir(dir: &Path) -> CliResult<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "receipt file names must be UTF-8")?;
        if !entry.file_type()?.is_file() || !name.ends_with(".json") {
            return Err(format!("unexpected entry in receipts dir: {name}").into());
        }
        names.push(name);
        if names.len() > MAX_CHAIN_ENTRIES {
            return Err("too many receipts for one export".into());
        }
    }
    names.sort();
    names
        .iter()
        .map(|name| read_limited(&dir.join(name)))
        .collect()
}

/// Total order of one tenant's rows. Without `agent_id`, two agents of the
/// same tenant reusing a `request_id` with equal `created_at` would come back
/// in an unspecified order, and two exports of the same journal could differ.
const JOURNAL_QUERY: &str = "SELECT evidence_json FROM praetore.execution_journal \
     WHERE tenant_id = $1 ORDER BY created_at, request_id, agent_id LIMIT $2";

fn read_journal(database_url: &str, tenant_id: Uuid) -> CliResult<Vec<String>> {
    let mut client = crate::connect_local_database(database_url)?;
    // Same policy as `praetore run`: a privileged or owner role is allowed for
    // the local demo, but then row-level security may not apply and only the
    // tenant filter of the query isolates tenants.
    if let Err(error) = praetore_replay_postgres::verify_runtime_role(&mut client) {
        eprintln!("warning: {error} (the export query still filters by tenant)");
    }
    read_journal_rows(&mut client, tenant_id)
}

fn read_journal_rows(client: &mut postgres::Client, tenant_id: Uuid) -> CliResult<Vec<String>> {
    let mut transaction = export_transaction(client, tenant_id)?;
    let limit = (MAX_CHAIN_ENTRIES + 1) as i64;
    let rows = transaction.query(JOURNAL_QUERY, &[&tenant_id, &limit])?;
    transaction.commit()?;
    if rows.len() > MAX_CHAIN_ENTRIES {
        return Err("too many journal rows for one export".into());
    }
    Ok(rows.iter().map(|row| row.get(0)).collect())
}

/// A READ ONLY transaction with `praetore.tenant_id` set for its duration
/// only, which is what the `tenant_isolation` RLS policies (migration 0008)
/// read.
fn export_transaction(
    client: &mut postgres::Client,
    tenant_id: Uuid,
) -> Result<postgres::Transaction<'_>, postgres::Error> {
    let mut transaction = client.build_transaction().read_only(true).start()?;
    praetore_replay_postgres::set_tenant_context(&mut transaction, tenant_id)?;
    Ok(transaction)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> CliResult<ExportArgs> {
        parse(list.iter().map(|s| s.to_string()))
    }

    #[test]
    fn exactly_one_source_is_required() {
        assert!(args(&["--attester-pin", "p", "--output", "o"]).is_err());
        assert!(
            args(&[
                "--receipts-dir",
                "d",
                "--tenant",
                "00000000-0000-0000-0000-000000000001",
                "--attester-pin",
                "p",
                "--output",
                "o",
            ])
            .is_err()
        );
        assert!(args(&["--tenant", "nope", "--attester-pin", "p", "--output", "o"]).is_err());
        assert!(
            args(&[
                "--receipts-dir",
                "d",
                "--receipts-dir",
                "e",
                "--attester-pin",
                "p",
                "--output",
                "o"
            ])
            .is_err()
        );
        assert_eq!(
            args(&[
                "--receipts-dir",
                "d",
                "--attester-pin",
                "p",
                "--output",
                "o"
            ])
            .unwrap(),
            ExportArgs {
                source: Source::ReceiptsDir("d".into()),
                attester_pin: "p".into(),
                output: "o".into(),
            }
        );
    }

    fn set(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/claude-code-hook/evidence")
            .join(name)
    }

    #[test]
    fn export_of_set_04_reproduces_the_published_chain() {
        let set = set("04-sesion-real-bloqueada-web-fetch");
        let attester = read_attester_pin(&set.join("attester-public-key.hex")).unwrap();
        let receipts = read_receipts_dir(&set.join("evidence")).unwrap();
        let (text, head) = export(&receipts, &attester).unwrap();
        assert_eq!(head.entries.get(), 8);
        assert_eq!(
            text,
            fs::read_to_string(set.join("journal-chain.jsonl")).unwrap()
        );
        let verified =
            praetore_core::journal_chain::verify_chain(&text, &attester, None, Some(&head.head))
                .unwrap();
        assert_eq!(verified, head);
    }

    #[test]
    fn export_fails_closed() {
        let set = set("04-sesion-real-bloqueada-web-fetch");
        let attester = read_attester_pin(&set.join("attester-public-key.hex")).unwrap();
        let receipts = read_receipts_dir(&set.join("evidence")).unwrap();

        // Nothing to export.
        assert!(export(&[], &attester).is_err());
        // Same receipt twice.
        assert!(export(&[receipts[0].clone(), receipts[0].clone()], &attester).is_err());
        // Altered receipt.
        let altered = receipts[0].replacen("\"reason\":\"P", "\"reason\":\"p", 1);
        assert_ne!(altered, receipts[0]);
        assert!(export(&[altered], &attester).is_err());
        // Wrong attester key.
        let other = praetore_core::EvidenceAttesterKey::from_secret_bytes(&[9; 32]);
        assert!(export(&receipts, &other.public_key().unwrap()).is_err());
        // Signature removed.
        let mut unsigned = Evidence::from_json(&receipts[0]).unwrap();
        unsigned.attester_signature = None;
        let unsigned = serde_json::to_string(&unsigned).unwrap();
        assert!(export(&[unsigned], &attester).is_err());
        // A directory with anything other than regular *.json files.
        assert!(read_receipts_dir(&set).is_err());
    }

    /// Inserts one journal row (and its replay claim) as the connected role.
    /// `created_at` is RFC 3339 text, or `None` for the column default.
    fn insert_row(
        client: &mut postgres::Client,
        key: (Uuid, Uuid, Uuid),
        json: &str,
        created_at: Option<&str>,
    ) {
        let (tenant_id, agent_id, request_id) = key;
        let mut tx = client.transaction().unwrap();
        tx.query_one(
            "SELECT set_config('praetore.tenant_id', $1, true)",
            &[&tenant_id.to_string()],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO praetore.replay_claims (tenant_id, agent_id, request_id) \
             VALUES ($1, $2, $3)",
            &[&tenant_id, &agent_id, &request_id],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO praetore.execution_journal \
             (tenant_id, agent_id, request_id, request_digest, action_digest, \
              authorization_status, execution_status, evidence_json, created_at) \
             VALUES ($1, $2, $3, $4, $4, 'allowed', 'not_dispatched', $5, \
                     COALESCE(($6::text)::timestamptz, clock_timestamp()))",
            &[
                &tenant_id,
                &agent_id,
                &request_id,
                &"ab".repeat(32),
                &json,
                &created_at,
            ],
        )
        .unwrap();
        tx.commit().unwrap();
    }

    fn test_url() -> String {
        let url = std::env::var("PRAETORE_TEST_DATABASE_URL").unwrap();
        crate::apply_migrations(&url).unwrap();
        url
    }

    const RUNTIME_LOGIN: &str = "praetore_export_test_runtime";
    const RUNTIME_PASSWORD: &str = "praetore-export-test";

    /// URL of a LOGIN member of `praetore_runtime`, the NOLOGIN group role of
    /// migration 0011 (operators are expected to create such a login role).
    /// Created once per process by the admin URL, which needs CREATEROLE.
    fn runtime_url(admin_url: &str) -> String {
        static PROVISIONED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        PROVISIONED.get_or_init(|| {
            crate::connect_local_database(admin_url)
                .unwrap()
                .batch_execute(&format!(
                    "DO $$ BEGIN CREATE ROLE {RUNTIME_LOGIN} LOGIN; \
                     EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$; \
                     ALTER ROLE {RUNTIME_LOGIN} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE \
                         NOCREATEDB PASSWORD '{RUNTIME_PASSWORD}'; \
                     GRANT praetore_runtime TO {RUNTIME_LOGIN}"
                ))
                .unwrap();
        });
        let (scheme, rest) = admin_url.split_once("://").expect("URL form");
        let host = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
        format!("{scheme}://{RUNTIME_LOGIN}:{RUNTIME_PASSWORD}@{host}")
    }

    fn sql_state(error: &postgres::Error) -> Option<&postgres::error::SqlState> {
        error.code()
    }

    /// Exports real `praetore.execution_journal` rows of one tenant. Run with:
    /// `PRAETORE_TEST_DATABASE_URL=postgresql://user@127.0.0.1:port/db cargo test -p praetore-cli -- --ignored journal_export`
    #[test]
    #[ignore = "requires PRAETORE_TEST_DATABASE_URL pointing to a disposable local PostgreSQL"]
    fn postgres_export_reads_only_the_tenant_rows_in_insert_order() {
        let url = test_url();
        let set = set("04-sesion-real-bloqueada-web-fetch");
        let attester = read_attester_pin(&set.join("attester-public-key.hex")).unwrap();
        let receipts = read_receipts_dir(&set.join("evidence")).unwrap();
        let (tenant, other) = (Uuid::new_v4(), Uuid::new_v4());
        let mut client = crate::connect_local_database(&url).unwrap();
        // Rows for `other` first, so ordering and the tenant filter both matter.
        for (tenant_id, json) in [(other, &receipts[3])]
            .into_iter()
            .chain(receipts[..3].iter().map(|json| (tenant, json)))
        {
            assert!(
                Evidence::from_json(json)
                    .unwrap()
                    .attester_signature
                    .is_some()
            );
            insert_row(
                &mut client,
                (tenant_id, Uuid::new_v4(), Uuid::new_v4()),
                json,
                None,
            );
        }
        let rows = read_journal(&url, tenant).unwrap();
        assert_eq!(rows, receipts[..3].to_vec());
        let (_, head) = export(&rows, &attester).unwrap();
        let (_, expected) = export(&receipts[..3], &attester).unwrap();
        assert_eq!(head, expected);
        assert!(read_journal(&url, Uuid::new_v4()).unwrap().is_empty());
    }

    /// Connected as a login member of `praetore_runtime` (not the owner, not a
    /// superuser), the export sees only its tenant even without the SQL
    /// filter, sees nothing without the tenant setting, and cannot write.
    #[test]
    #[ignore = "requires PRAETORE_TEST_DATABASE_URL pointing to a disposable local PostgreSQL"]
    fn postgres_export_as_runtime_role_is_confined_by_row_level_security() {
        use postgres::error::SqlState;
        let admin_url = test_url();
        let runtime_url = runtime_url(&admin_url);
        let set = set("04-sesion-real-bloqueada-web-fetch");
        let attester = read_attester_pin(&set.join("attester-public-key.hex")).unwrap();
        let receipts = read_receipts_dir(&set.join("evidence")).unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut admin = crate::connect_local_database(&admin_url).unwrap();
        // Interleaved: b, a, b, a.
        for (tenant_id, json) in [
            (b, &receipts[4]),
            (a, &receipts[0]),
            (b, &receipts[5]),
            (a, &receipts[1]),
        ] {
            insert_row(
                &mut admin,
                (tenant_id, Uuid::new_v4(), Uuid::new_v4()),
                json,
                None,
            );
        }
        let rows_of_a = receipts[..2].to_vec();
        let rows_of_b = receipts[4..6].to_vec();

        // It really is the least-privilege runtime role.
        let mut runtime = crate::connect_local_database(&runtime_url).unwrap();
        let role = runtime
            .query_one(
                "SELECT current_user::text, rolsuper, rolbypassrls, \
                        pg_has_role(current_user, 'praetore_runtime', 'MEMBER') \
                 FROM pg_catalog.pg_roles WHERE rolname = current_user",
                &[],
            )
            .unwrap();
        assert_eq!(role.get::<_, String>(0), RUNTIME_LOGIN);
        assert!(!role.get::<_, bool>(1) && !role.get::<_, bool>(2));
        assert!(role.get::<_, bool>(3));
        praetore_replay_postgres::verify_runtime_role(&mut runtime).unwrap();

        // The export path, as the runtime role.
        assert_eq!(read_journal(&runtime_url, a).unwrap(), rows_of_a);
        assert_eq!(read_journal(&runtime_url, b).unwrap(), rows_of_b);
        let (_, head) = export(&read_journal(&runtime_url, a).unwrap(), &attester).unwrap();
        assert_eq!(head, export(&rows_of_a, &attester).unwrap().1);

        // Second line: the export transaction without any tenant filter still
        // returns only the rows of the tenant in `praetore.tenant_id`.
        let unfiltered = "SELECT evidence_json, tenant_id FROM praetore.execution_journal \
                          ORDER BY created_at, request_id, agent_id";
        // These checks use their own SQL, not JOURNAL_QUERY, so they hold
        // whatever filter the export query has.
        let by_tenant = "SELECT evidence_json FROM praetore.execution_journal WHERE tenant_id = $1";
        {
            let mut tx = export_transaction(&mut runtime, a).unwrap();
            let rows = tx.query(unfiltered, &[]).unwrap();
            assert!(rows.iter().all(|row| row.get::<_, Uuid>(1) == a));
            let json: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
            assert_eq!(json, rows_of_a);
            // A filter naming the other tenant finds nothing.
            assert!(tx.query(by_tenant, &[&b]).unwrap().is_empty());
            tx.commit().unwrap();
        }
        // Contrast: a superuser bypasses RLS, so there the filter is the only line.
        let superuser: bool = admin
            .query_one(
                "SELECT rolsuper FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .unwrap()
            .get(0);
        if superuser {
            let mut tx = export_transaction(&mut admin, a).unwrap();
            let count: i64 = tx
                .query_one(
                    "SELECT count(*) FROM praetore.execution_journal WHERE tenant_id = $1",
                    &[&b],
                )
                .unwrap()
                .get(0);
            assert_eq!(count, 2);
            tx.commit().unwrap();
        }

        // Fails closed without the setting, or with an empty or wrong one:
        // no rows, and an export of no rows is refused.
        let count_all = "SELECT count(*) FROM praetore.execution_journal";
        {
            let mut tx = runtime.build_transaction().read_only(true).start().unwrap();
            assert_eq!(tx.query_one(count_all, &[]).unwrap().get::<_, i64>(0), 0);
            tx.query_one("SELECT set_config('praetore.tenant_id', '', true)", &[])
                .unwrap();
            assert_eq!(tx.query_one(count_all, &[]).unwrap().get::<_, i64>(0), 0);
            tx.commit().unwrap();
        }
        {
            let mut tx = runtime.build_transaction().read_only(true).start().unwrap();
            tx.query_one(
                "SELECT set_config('praetore.tenant_id', 'not-a-uuid', true)",
                &[],
            )
            .unwrap();
            let error = tx.query_one(count_all, &[]).unwrap_err();
            assert_eq!(
                sql_state(&error),
                Some(&SqlState::INVALID_TEXT_REPRESENTATION)
            );
        }
        {
            let mut tx = export_transaction(&mut runtime, b).unwrap();
            assert!(tx.query(by_tenant, &[&a]).unwrap().is_empty());
            tx.commit().unwrap();
        }
        let unknown = read_journal(&runtime_url, Uuid::new_v4()).unwrap();
        assert!(unknown.is_empty());
        assert!(export(&unknown, &attester).is_err());

        // The export transaction is READ ONLY: no insert or update gets through,
        // even ones the runtime role is granted.
        {
            let mut tx = export_transaction(&mut runtime, a).unwrap();
            let error = tx
                .execute(
                    "INSERT INTO praetore.replay_claims (tenant_id, agent_id, request_id) \
                     VALUES ($1, $2, $3)",
                    &[&a, &Uuid::new_v4(), &Uuid::new_v4()],
                )
                .unwrap_err();
            assert_eq!(
                sql_state(&error),
                Some(&SqlState::READ_ONLY_SQL_TRANSACTION)
            );
        }
        {
            let mut tx = export_transaction(&mut runtime, a).unwrap();
            let error = tx
                .execute(
                    "UPDATE praetore.execution_journal SET updated_at = updated_at \
                     WHERE tenant_id = $1",
                    &[&a],
                )
                .unwrap_err();
            assert_eq!(
                sql_state(&error),
                Some(&SqlState::READ_ONLY_SQL_TRANSACTION)
            );
        }
        // And the role has no DELETE at all, in or out of the export path.
        {
            let mut tx = runtime.transaction().unwrap();
            tx.query_one(
                "SELECT set_config('praetore.tenant_id', $1, true)",
                &[&a.to_string()],
            )
            .unwrap();
            let error = tx
                .execute(
                    "DELETE FROM praetore.execution_journal WHERE tenant_id = $1",
                    &[&a],
                )
                .unwrap_err();
            assert_eq!(sql_state(&error), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
        }
        assert_eq!(read_journal(&runtime_url, a).unwrap(), rows_of_a);
    }

    /// Insert order differs from `(created_at, request_id, agent_id)`, with
    /// equal `created_at` and an equal `(created_at, request_id)` pair.
    #[test]
    #[ignore = "requires PRAETORE_TEST_DATABASE_URL pointing to a disposable local PostgreSQL"]
    fn postgres_export_orders_by_created_at_then_request_id_then_agent_id() {
        let admin_url = test_url();
        let runtime_url = runtime_url(&admin_url);
        let set = set("04-sesion-real-bloqueada-web-fetch");
        let attester = read_attester_pin(&set.join("attester-public-key.hex")).unwrap();
        let receipts = read_receipts_dir(&set.join("evidence")).unwrap();
        let tenant = Uuid::new_v4();
        let id = |text: &str| Uuid::parse_str(text).unwrap();
        // UUIDs compare byte by byte, which is the order of their lowercase
        // hex text: "0a..." < "a0..." < "ff...".
        let (req_0a, req_a0, req_ff) = (
            id("0a000000-0000-4000-8000-000000000000"),
            id("a0000000-0000-4000-8000-000000000000"),
            id("ffffffff-0000-4000-8000-000000000000"),
        );
        let (agent_00, agent_01, agent_ff) = (
            id("00000000-0000-4000-8000-000000000001"),
            id("01000000-0000-4000-8000-000000000000"),
            id("ff000000-0000-4000-8000-000000000000"),
        );
        let (t0, t1) = ("2026-01-01T00:00:00.000001Z", "2026-01-01T00:00:00.000002Z");
        // (created_at, request_id, agent_id), in insert order.
        let inserts = [
            (t1, req_a0, agent_00), // expected 3rd
            (t1, req_0a, agent_ff), // expected 2nd: same t1 and request as the next one
            (t0, req_ff, agent_01), // expected 0th: earliest, despite the largest ids
            (t1, req_0a, agent_01), // expected 1st
        ];
        let mut admin = crate::connect_local_database(&admin_url).unwrap();
        for (index, (created_at, request_id, agent_id)) in inserts.iter().enumerate() {
            insert_row(
                &mut admin,
                (tenant, *agent_id, *request_id),
                &receipts[index],
                Some(created_at),
            );
        }
        let expected: Vec<String> = [2, 3, 1, 0].map(|i| receipts[i].clone()).to_vec();
        let uuid_matches_text: bool = admin
            .query_one(
                "WITH v (a, b, c) AS (SELECT $1::text, $2::text, $3::text) \
                 SELECT (a::uuid < b::uuid) = (a < b) AND (b::uuid < c::uuid) = (b < c) \
                    AND a::uuid < b::uuid AND b::uuid < c::uuid FROM v",
                &[
                    &req_0a.to_string(),
                    &req_a0.to_string(),
                    &req_ff.to_string(),
                ],
            )
            .unwrap()
            .get(0);
        assert!(uuid_matches_text);

        // The export path, as the runtime role and as the admin role.
        assert_eq!(read_journal(&runtime_url, tenant).unwrap(), expected);
        assert_eq!(read_journal(&admin_url, tenant).unwrap(), expected);
        // With index scans off the rows come from the heap in insert order, so
        // the result depends only on ORDER BY, not on which index the planner
        // picks (the primary key is already sorted by agent_id).
        let mut runtime = crate::connect_local_database(&runtime_url).unwrap();
        runtime
            .batch_execute("SET enable_indexscan = off; SET enable_bitmapscan = off")
            .unwrap();
        assert_eq!(read_journal_rows(&mut runtime, tenant).unwrap(), expected);

        let (text, head) = export(&expected, &attester).unwrap();
        let chain: Vec<String> = text
            .lines()
            .map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                value["evidence"]["evidence_id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        let ids: Vec<String> = expected
            .iter()
            .map(|json| Evidence::from_json(json).unwrap().evidence_id.to_string())
            .collect();
        assert_eq!(chain, ids);
        assert_eq!(head.entries.get(), 4);
    }
}
