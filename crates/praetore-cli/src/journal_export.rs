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
    /// `(created_at, request_id)`. Reads `PRAETORE_GATEWAY_DATABASE_URL`.
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

fn read_journal(database_url: &str, tenant_id: Uuid) -> CliResult<Vec<String>> {
    let mut client = crate::connect_local_database(database_url)?;
    let mut transaction = client.build_transaction().read_only(true).start()?;
    transaction.query_one(
        "SELECT set_config('praetore.tenant_id', $1, true)",
        &[&tenant_id.to_string()],
    )?;
    let limit = (MAX_CHAIN_ENTRIES + 1) as i64;
    let rows = transaction.query(
        "SELECT evidence_json FROM praetore.execution_journal \
         WHERE tenant_id = $1 ORDER BY created_at, request_id LIMIT $2",
        &[&tenant_id, &limit],
    )?;
    transaction.commit()?;
    if rows.len() > MAX_CHAIN_ENTRIES {
        return Err("too many journal rows for one export".into());
    }
    Ok(rows.iter().map(|row| row.get(0)).collect())
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

    /// Exports real `praetore.execution_journal` rows of one tenant. Run with:
    /// `PRAETORE_TEST_DATABASE_URL=postgresql://user@127.0.0.1:port/db cargo test -p praetore-cli -- --ignored journal_export`
    #[test]
    #[ignore = "requires PRAETORE_TEST_DATABASE_URL pointing to a disposable local PostgreSQL"]
    fn postgres_export_reads_only_the_tenant_rows_in_insert_order() {
        let url = std::env::var("PRAETORE_TEST_DATABASE_URL").unwrap();
        crate::apply_migrations(&url).unwrap();
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
            let evidence = Evidence::from_json(json).unwrap();
            let (agent_id, request_id) = (Uuid::new_v4(), Uuid::new_v4());
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
                  authorization_status, execution_status, evidence_json) \
                 VALUES ($1, $2, $3, $4, $4, 'allowed', 'not_dispatched', $5)",
                &[&tenant_id, &agent_id, &request_id, &"ab".repeat(32), json],
            )
            .unwrap();
            tx.commit().unwrap();
            assert!(evidence.attester_signature.is_some());
        }
        let rows = read_journal(&url, tenant).unwrap();
        assert_eq!(rows, receipts[..3].to_vec());
        let (_, head) = export(&rows, &attester).unwrap();
        let (_, expected) = export(&receipts[..3], &attester).unwrap();
        assert_eq!(head, expected);
        assert!(read_journal(&url, Uuid::new_v4()).unwrap().is_empty());
    }
}
