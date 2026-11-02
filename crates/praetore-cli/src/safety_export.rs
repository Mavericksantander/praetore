//! `praetore journal-export --safety --tenant UUID --source ID --ingest-pin
//! HEX_FILE [--ingest-pin HEX_FILE]... [--source-pins JSONL] --output NEW`
//! (G1): exports one safety chain (`praetore.safety_records`, migration
//! 0016) as JSONL, one canonical record per line in `chain_seq` order
//! (`docs/proposals/safety-ingestion-jsonl.md`).
//!
//! The chain is verified with `praetore_core::safety_ingest::verify_safety_chain`,
//! the code `praetore-verify safety-journal` runs, before anything is
//! written; the output file is never overwritten. `--source` is a source id
//! or `_unattributed` (rejected input and losses inside the ingester).
//! Reads `PRAETORE_SAFETY_DATABASE_URL` (or `PRAETORE_SAFETY_DATABASE_URL_FILE`,
//! an owner-only file): a role that may read `praetore.safety_records`, for
//! example the ingester's.

use praetore_core::{
    VerifiedPublicKey,
    safety_ingest::{SourcePins, is_valid_chain, verify_safety_chain},
};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

const MAX_INGEST_PINS: usize = 16;
const MAX_SOURCE_PINS_BYTES: u64 = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct SafetyExportArgs {
    pub tenant_id: Uuid,
    pub chain: String,
    pub ingest_pins: Vec<PathBuf>,
    pub source_pins: Option<PathBuf>,
    pub output: PathBuf,
}

pub fn parse(args: impl Iterator<Item = String>) -> CliResult<SafetyExportArgs> {
    let (mut tenant, mut chain, mut source_pins, mut output) = (None, None, None, None);
    let mut ingest_pins = Vec::new();
    let mut safety = false;
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        if flag == "--safety" {
            if std::mem::replace(&mut safety, true) {
                return Err("--safety given twice".into());
            }
            continue;
        }
        if flag == "--ingest-pin" {
            let value = args.next().ok_or("missing value for --ingest-pin")?;
            if ingest_pins.len() == MAX_INGEST_PINS {
                return Err(format!("at most {MAX_INGEST_PINS} --ingest-pin").into());
            }
            ingest_pins.push(PathBuf::from(value));
            continue;
        }
        let slot = match flag.as_str() {
            "--tenant" => &mut tenant,
            "--source" => &mut chain,
            "--source-pins" => &mut source_pins,
            "--output" => &mut output,
            _ => return Err(format!("unexpected argument for --safety: {flag}").into()),
        };
        let value = args.next().ok_or(format!("missing value for {flag}"))?;
        if slot.replace(value).is_some() {
            return Err(format!("{flag} given twice").into());
        }
    }
    if !safety {
        return Err("missing --safety".into());
    }
    let chain = chain.ok_or("missing --source")?;
    if !is_valid_chain(&chain) {
        return Err("--source must be a source id or _unattributed".into());
    }
    if ingest_pins.is_empty() {
        return Err("missing --ingest-pin".into());
    }
    Ok(SafetyExportArgs {
        tenant_id: Uuid::parse_str(&tenant.ok_or("missing --tenant")?)
            .map_err(|_| "--tenant must be a UUID")?,
        chain,
        ingest_pins,
        source_pins: source_pins.map(PathBuf::from),
        output: output.ok_or("missing --output")?.into(),
    })
}

fn database_url() -> CliResult<String> {
    let value = |name| std::env::var(name).ok().filter(|v: &String| !v.is_empty());
    match (
        value("PRAETORE_SAFETY_DATABASE_URL"),
        value("PRAETORE_SAFETY_DATABASE_URL_FILE"),
    ) {
        (Some(url), None) => Ok(url),
        (None, Some(path)) => {
            let contents = crate::secret_file::read_private_file(Path::new(&path), 4096)
                .map_err(|error| format!("the database URL file {path} {error}"))?;
            Ok(String::from_utf8(contents)
                .map_err(|_| "the database URL file is not UTF-8")?
                .trim_end()
                .to_owned())
        }
        _ => Err("set exactly one of PRAETORE_SAFETY_DATABASE_URL and \
                  PRAETORE_SAFETY_DATABASE_URL_FILE"
            .into()),
    }
}

pub fn run(args: SafetyExportArgs) -> CliResult<()> {
    let mut pins: Vec<VerifiedPublicKey> = Vec::with_capacity(args.ingest_pins.len());
    for path in &args.ingest_pins {
        let key = crate::journal_export::read_attester_pin(path)
            .map_err(|error| format!("ingest pin {}: {error}", path.display()))?;
        if pins.contains(&key) {
            return Err(format!("ingest pin {} repeats a key", path.display()).into());
        }
        pins.push(key);
    }
    let source_pins = match &args.source_pins {
        None => None,
        Some(path) => {
            let mut text = String::new();
            std::fs::File::open(path)
                .map_err(|error| format!("cannot open {}: {error}", path.display()))?
                .take(MAX_SOURCE_PINS_BYTES + 1)
                .read_to_string(&mut text)?;
            Some(SourcePins::from_jsonl(&text).map_err(|error| format!("--source-pins: {error}"))?)
        }
    };
    let connector = praetore_replay_postgres::DatabaseConnector::from_url(&database_url()?)?
        .connect_timeout(std::time::Duration::from_secs(3));
    let mut client = connector.connect()?;
    let records =
        praetore_replay_postgres::read_safety_chain(&mut client, args.tenant_id, &args.chain)?;
    if records.is_empty() {
        return Err(format!(
            "tenant {} has no safety records on chain {}",
            args.tenant_id, args.chain
        )
        .into());
    }
    let mut text = String::new();
    for record in &records {
        text.push_str(record);
        text.push('\n');
    }
    let report = verify_safety_chain(&text, &pins, source_pins.as_ref(), None)
        .map_err(|error| format!("{} ({})", error, error.code()))?;
    // Never overwrite: an existing file may be an anchored export.
    let mut file = std::fs::OpenOptions::new()
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
            "kind": "safety",
            "tenant_id": report.tenant_id,
            "chain": report.chain,
            "entries": report.entries,
            "head": report.head,
            "high_water": report.high_water,
            "counts": report.counts,
            "source_signatures_verified": report.source_signatures_verified,
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> CliResult<SafetyExportArgs> {
        parse(list.iter().map(|s| s.to_string()))
    }

    #[test]
    fn safety_export_arguments_are_strict() {
        let tenant = "00000000-0000-0000-0000-000000000001";
        let ok = args(&[
            "--safety",
            "--tenant",
            tenant,
            "--source",
            "executor-1",
            "--ingest-pin",
            "p",
            "--output",
            "o",
        ])
        .unwrap();
        assert_eq!(ok.chain, "executor-1");
        assert_eq!(ok.ingest_pins, vec![PathBuf::from("p")]);
        for bad in [
            vec![
                "--tenant",
                tenant,
                "--source",
                "e",
                "--ingest-pin",
                "p",
                "--output",
                "o",
            ],
            vec![
                "--safety",
                "--source",
                "e",
                "--ingest-pin",
                "p",
                "--output",
                "o",
            ],
            vec![
                "--safety",
                "--tenant",
                tenant,
                "--ingest-pin",
                "p",
                "--output",
                "o",
            ],
            vec![
                "--safety", "--tenant", tenant, "--source", "e", "--output", "o",
            ],
            vec![
                "--safety",
                "--tenant",
                tenant,
                "--source",
                "E",
                "--ingest-pin",
                "p",
                "--output",
                "o",
            ],
            vec![
                "--safety",
                "--tenant",
                tenant,
                "--source",
                "e",
                "--ingest-pin",
                "p",
                "--output",
                "o",
                "--attester-pin",
                "a",
            ],
            vec![
                "--safety",
                "--safety",
                "--tenant",
                tenant,
                "--source",
                "e",
                "--ingest-pin",
                "p",
                "--output",
                "o",
            ],
        ] {
            assert!(args(&bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            args(&[
                "--safety",
                "--tenant",
                tenant,
                "--source",
                "_unattributed",
                "--ingest-pin",
                "p",
                "--output",
                "o",
            ])
            .unwrap()
            .chain,
            "_unattributed"
        );
    }
}
