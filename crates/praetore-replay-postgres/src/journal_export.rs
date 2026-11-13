//! Producer of the hash-linked JSONL format in
//! `docs/proposals/journal-chain-jsonl.md` for one tenant of a PostgreSQL
//! journal. `praetore journal-export --tenant` and the local console's
//! compliance package both call [`export_tenant`], so the two cannot
//! produce different chains for the same database state. The chain itself is
//! built by `praetore_core::journal_chain::ChainExporter`, the same code the
//! verifier uses.

use postgres::{Client, Transaction};
use praetore_core::{
    Evidence, StorageRecord, VerifiedPublicKey,
    journal_chain::{ChainExporter, ChainHead, DatabaseHead, MAX_CHAIN_ENTRIES},
};
use praetore_receipt::{
    AttestedExecution, ExecutionAttestation, GatewayReceipt,
    outcomes::{MAX_OUTCOME_LINES, Outcome},
};
use uuid::Uuid;

pub type ExportResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Hint for a storage record signed by a key that is not pinned.
pub const RECORD_PIN_HINT: &str = "storage records keep the signature of the attester key that \
     was current when they were recorded; after a key rotation, pass the retired key's pin as \
     another --attester-pin";

/// One tenant's chain, as `praetore journal-export --tenant` writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantExport {
    /// The JSONL file, every line ending in a newline.
    pub text: String,
    pub head: ChainHead,
    /// The database chain head the first line references, when the
    /// database has storage records.
    pub database_head: Option<DatabaseHead>,
    /// Positions of the `attesters` that verified no receipt and no storage
    /// record. `praetore journal-export` accepts them; the console refuses
    /// them, so a file that is not the attester's public key never reaches
    /// its package.
    pub unused_attesters: Vec<usize>,
}

/// Total order of one tenant's rows. Without `agent_id`, two agents of the
/// same tenant reusing a `request_id` with equal `created_at` would come back
/// in an unspecified order, and two exports of the same journal could differ.
pub const JOURNAL_QUERY: &str = "SELECT evidence_json FROM praetore.execution_journal \
     WHERE tenant_id = $1 ORDER BY created_at, request_id, agent_id LIMIT $2";

/// Storage records in recording order (none before migration 0015).
const STORAGE_RECORDS_QUERY: &str = "SELECT record_json FROM praetore.storage_records \
     ORDER BY created_at, record_id LIMIT $1";

/// Reads the tenant's receipts and the database's storage records in one
/// repeatable-read, read-only snapshot and chains them: the tenant chain
/// references the database head of the same moment. Every receipt and
/// storage record must be signed by one of `attesters`.
pub fn export_tenant(
    client: &mut Client,
    tenant_id: Uuid,
    attesters: &[VerifiedPublicKey],
) -> ExportResult<TenantExport> {
    let (receipts, records) = read_tenant_export(client, tenant_id)?;
    chain_tenant(&receipts, &records, attesters)
}

/// The tenant's human decisions, approval-expiration receipts and execution
/// attestations, in journal order and, within a request, in recording
/// order. An execution attestation becomes the [`GatewayReceipt`] the
/// gateway returned for it: the journal's evidence, and the journal's output
/// for `executed` and `confirmed`.
const OUTCOMES_QUERY: &str = "SELECT record.kind, record.payload, \
     CASE WHEN record.kind = 2 THEN journal.evidence_json END, \
     CASE WHEN record.kind = 2 THEN journal.output_json END FROM ( \
     SELECT 0 AS kind, decision_json AS payload, tenant_id, agent_id, request_id, created_at, \
     approval_id::text AS id FROM praetore.human_approvals WHERE tenant_id = $1 \
     UNION ALL \
     SELECT 1, receipt_json, tenant_id, agent_id, request_id, created_at, receipt_id::text \
     FROM praetore.human_approval_expirations WHERE tenant_id = $1 \
     UNION ALL \
     SELECT 2, attestation_json, tenant_id, agent_id, request_id, created_at, \
     attestation_id::text FROM praetore.execution_attestations WHERE tenant_id = $1 \
     ) record JOIN praetore.execution_journal journal \
     ON journal.tenant_id = record.tenant_id AND journal.agent_id = record.agent_id \
     AND journal.request_id = record.request_id \
     ORDER BY journal.created_at, journal.request_id, journal.agent_id, record.created_at, \
     record.kind, record.id LIMIT $2";

/// [`export_tenant`], plus the tenant's approval and execution records
/// ([`OUTCOMES_QUERY`]), all read in the same read-only, repeatable-read
/// snapshot, so every record belongs to a request of the chain. The records
/// are parsed, not verified: see `praetore_receipt::outcomes::verify_outcomes`.
pub fn export_tenant_with_outcomes(
    client: &mut Client,
    tenant_id: Uuid,
    attesters: &[VerifiedPublicKey],
) -> ExportResult<(TenantExport, Vec<Outcome>)> {
    let mut transaction = export_transaction(client, tenant_id)?;
    let limit = (MAX_CHAIN_ENTRIES + 1) as i64;
    let rows = transaction.query(JOURNAL_QUERY, &[&tenant_id, &limit])?;
    let records = read_storage_records(&mut transaction)?;
    let outcome_limit = (MAX_OUTCOME_LINES + 1) as i64;
    let outcome_rows = transaction.query(OUTCOMES_QUERY, &[&tenant_id, &outcome_limit])?;
    transaction.commit()?;
    if rows.len() > MAX_CHAIN_ENTRIES {
        return Err("too many journal rows for one export".into());
    }
    if outcome_rows.len() > MAX_OUTCOME_LINES {
        return Err("too many approval and execution records for one export".into());
    }
    let receipts: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
    let export = chain_tenant(&receipts, &records, attesters)?;
    let mut outcomes = Vec::with_capacity(outcome_rows.len());
    for (index, row) in outcome_rows.iter().enumerate() {
        let kind: i32 = row.get(0);
        let payload: serde_json::Value = row.get(1);
        let outcome = match kind {
            0 => serde_json::from_value(payload).map(Outcome::HumanDecision),
            1 => serde_json::from_value(payload).map(Outcome::ApprovalExpired),
            _ => serde_json::from_value::<ExecutionAttestation>(payload).and_then(|attestation| {
                // Evidence and output come only with execution receipts.
                let evidence = row
                    .get::<_, Option<String>>(2)
                    .ok_or_else(|| {
                        serde_json::Error::io(std::io::Error::other("journal row has no evidence"))
                    })
                    .and_then(|json| {
                        Evidence::from_json(&json)
                            .map_err(|error| serde_json::Error::io(std::io::Error::other(error)))
                    })?;
                let output = match attestation.execution {
                    AttestedExecution::Executed | AttestedExecution::Confirmed => row
                        .get::<_, Option<String>>(3)
                        .map(|json| serde_json::from_str(&json))
                        .transpose()?,
                    _ => None,
                };
                Ok(Outcome::ExecutionReceipt(Box::new(GatewayReceipt {
                    evidence,
                    authorization: attestation.authorization,
                    execution: attestation.execution,
                    output,
                    execution_attestation: attestation,
                })))
            }),
        }
        .map_err(|error| format!("approval or execution record {index}: {error}"))?;
        outcomes.push(outcome);
    }
    Ok((export, outcomes))
}

fn chain_tenant(
    receipts: &[String],
    records: &[String],
    attesters: &[VerifiedPublicKey],
) -> ExportResult<TenantExport> {
    let mut used = vec![false; attesters.len()];
    let database_head = if records.is_empty() {
        None
    } else {
        let (_, head, unused) = chain_storage_records(records, attesters)
            .map_err(|error| format!("database chain: {error} ({RECORD_PIN_HINT})"))?;
        mark_used(&mut used, &unused);
        Some(DatabaseHead::from(head))
    };
    let (text, head, unused) = chain_receipts(receipts, database_head, attesters)?;
    mark_used(&mut used, &unused);
    Ok(TenantExport {
        text,
        head,
        database_head,
        unused_attesters: used
            .iter()
            .enumerate()
            .filter(|(_, used)| !**used)
            .map(|(index, _)| index)
            .collect(),
    })
}

/// A tenant chain; with `database_head`, its first line references the
/// database chain (`docs/proposals/journal-chain-jsonl.md`). Fails on the
/// first receipt that does not parse, lacks or fails its attester signature,
/// or repeats an `evidence_id`, and when there is nothing to chain.
pub fn export_with_database_head(
    receipts: &[String],
    database_head: Option<DatabaseHead>,
    attesters: &[VerifiedPublicKey],
) -> ExportResult<(String, ChainHead)> {
    let (text, head, _) = chain_receipts(receipts, database_head, attesters)?;
    Ok((text, head))
}

/// Pins every unused list leaves out are marked used.
fn mark_used(used: &mut [bool], unused: &[usize]) {
    for (index, slot) in used.iter_mut().enumerate() {
        if !unused.contains(&index) {
            *slot = true;
        }
    }
}

/// [`export_with_database_head`], plus the pins that verified no receipt.
pub fn chain_receipts(
    receipts: &[String],
    database_head: Option<DatabaseHead>,
    attesters: &[VerifiedPublicKey],
) -> ExportResult<(String, ChainHead, Vec<usize>)> {
    let mut exporter = ChainExporter::with_attesters(attesters);
    if let Some(reference) = &database_head {
        exporter.push_database_head(reference)?;
    }
    for (index, json) in receipts.iter().enumerate() {
        let evidence = Evidence::from_json(json.trim_end())
            .map_err(|error| format!("receipt {index}: {error}"))?;
        exporter.push(&evidence)?;
    }
    let unused = exporter.unused_attesters();
    let (text, head) = exporter.finish()?;
    Ok((text, head, unused))
}

/// The database chain: signed storage records in recording order.
pub fn export_storage_records(
    records: &[String],
    attesters: &[VerifiedPublicKey],
) -> ExportResult<(String, ChainHead)> {
    let (text, head, _) = chain_storage_records(records, attesters)?;
    Ok((text, head))
}

fn chain_storage_records(
    records: &[String],
    attesters: &[VerifiedPublicKey],
) -> ExportResult<(String, ChainHead, Vec<usize>)> {
    let mut exporter = ChainExporter::with_attesters(attesters);
    for (index, json) in records.iter().enumerate() {
        let record = StorageRecord::from_json(json)
            .map_err(|error| format!("storage record {index}: {error}"))?;
        exporter.push_record(&record)?;
    }
    let unused = exporter.unused_attesters();
    let (text, head) = exporter.finish()?;
    Ok((text, head, unused))
}

/// An attester pin file's text: 64 lowercase hex characters (an Ed25519
/// public key), surrounding whitespace ignored.
pub fn parse_attester_pin(text: &str) -> ExportResult<VerifiedPublicKey> {
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

/// The tenant's receipts and the database's storage records, read in one
/// repeatable-read snapshot.
pub fn read_tenant_export(
    client: &mut Client,
    tenant_id: Uuid,
) -> ExportResult<(Vec<String>, Vec<String>)> {
    let mut transaction = export_transaction(client, tenant_id)?;
    let limit = (MAX_CHAIN_ENTRIES + 1) as i64;
    let rows = transaction.query(JOURNAL_QUERY, &[&tenant_id, &limit])?;
    let records = read_storage_records(&mut transaction)?;
    transaction.commit()?;
    if rows.len() > MAX_CHAIN_ENTRIES {
        return Err("too many journal rows for one export".into());
    }
    Ok((rows.iter().map(|row| row.get(0)).collect(), records))
}

/// Every storage record of the database (for `journal-export --database`).
pub fn read_storage_records_only(client: &mut Client) -> ExportResult<Vec<String>> {
    let mut transaction = export_transaction(client, Uuid::nil())?;
    let records = read_storage_records(&mut transaction)?;
    transaction.commit()?;
    Ok(records)
}

fn read_storage_records(transaction: &mut Transaction<'_>) -> ExportResult<Vec<String>> {
    let exists: bool = transaction
        .query_one(
            "SELECT pg_catalog.to_regclass('praetore.storage_records') IS NOT NULL",
            &[],
        )?
        .get(0);
    if !exists {
        return Ok(Vec::new());
    }
    let limit = (MAX_CHAIN_ENTRIES + 1) as i64;
    let rows = transaction.query(STORAGE_RECORDS_QUERY, &[&limit])?;
    if rows.len() > MAX_CHAIN_ENTRIES {
        return Err("too many storage records for one export".into());
    }
    Ok(rows.iter().map(|row| row.get(0)).collect())
}

/// A READ ONLY transaction with `praetore.tenant_id` set for its duration
/// only, which is what the `tenant_isolation` RLS policies (migration 0008)
/// read.
pub fn export_transaction(
    client: &mut Client,
    tenant_id: Uuid,
) -> Result<Transaction<'_>, postgres::Error> {
    let mut transaction = client
        .build_transaction()
        .read_only(true)
        .isolation_level(postgres::IsolationLevel::RepeatableRead)
        .start()?;
    crate::set_tenant_context(&mut transaction, tenant_id)?;
    Ok(transaction)
}
