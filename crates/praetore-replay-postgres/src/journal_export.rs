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
    journal_chain::{
        ChainError, ChainExporter, ChainHead, ChainLink, DatabaseHead, MAX_CHAIN_ENTRIES,
        receipt_link,
    },
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

/// Total order of one tenant's rows: `chain_seq`, the position migration
/// 0024 assigns in commit order (rows written before 0024 were numbered in
/// the earlier `created_at, request_id, agent_id` order). The second column
/// is that position; every reader checks with [`check_position`] that the
/// positions run from 0 without a gap.
pub const JOURNAL_QUERY: &str = "SELECT evidence_json, chain_seq FROM praetore.execution_journal \
     WHERE tenant_id = $1 ORDER BY chain_seq LIMIT $2";

/// [`JOURNAL_QUERY`] with no limit, read through a portal in batches: a
/// range export reads the receipts before the range to compute its anchor,
/// in the same order.
const JOURNAL_RANGE_QUERY: &str = "SELECT evidence_json, chain_seq FROM praetore.execution_journal \
     WHERE tenant_id = $1 ORDER BY chain_seq";

/// The `index`-th receipt of a tenant (from 0) must have `chain_seq` equal
/// to `index`: the positions are assigned without gaps and never change, so
/// a gap or a jump means that a row was deleted, or written or changed by
/// hand, by someone with write access to the database.
pub fn check_position(index: u64, chain_seq: i64) -> ExportResult<()> {
    if u64::try_from(chain_seq).ok() == Some(index) {
        Ok(())
    } else {
        Err(format!(
            "journal positions are not contiguous: expected chain_seq {index}, found {chain_seq} \
             (a row was deleted, or written or changed outside the gateway)"
        )
        .into())
    }
}

/// The receipts of [`JOURNAL_QUERY`] rows, after [`check_position`].
pub fn receipts_in_chain_order(rows: &[postgres::Row]) -> ExportResult<Vec<String>> {
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            check_position(index as u64, row.get(1))?;
            Ok(row.get(0))
        })
        .collect()
}

/// Rows fetched per round trip by a range export.
const RANGE_BATCH: i32 = 512;

/// One range of a tenant chain, as `praetore journal-export --tenant
/// --from-seq N --limit M` writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRange {
    /// The JSONL file: for N > 0 the anchor (the receipt at `seq` N - 1)
    /// first, then the range.
    pub text: String,
    /// The range's last link; `entries` counts from the chain's start.
    pub head: ChainHead,
    /// `seq` of the range's first receipt (N).
    pub range_start: u64,
    /// The anchor's link (the previous range's head); `None` when N is 0.
    pub anchor: Option<ChainLink>,
    /// Where the next range starts, or `None` at the end of the chain.
    pub next_from_seq: Option<u64>,
}

/// One range of the tenant's chain of receipts, read in one read-only,
/// repeatable-read snapshot, in the order of [`JOURNAL_QUERY`]: the `seq` of
/// every receipt is its `chain_seq` ([`check_position`]). A range
/// chains receipts only, from `seq` 0 for the first receipt: unlike
/// [`export_tenant`], it carries no reference to the database chain, so
/// that every range of one journal state is linked the same way however the
/// database chain grows. The receipts before the range are read to compute
/// the links up to the anchor (the receipt at `from_seq - 1`), whose full
/// line opens the range. At most `max_entries` receipts (capped at
/// [`MAX_CHAIN_ENTRIES`]) and [`praetore_core::journal_chain::MAX_CHAIN_BYTES`]
/// per range, anchor included.
pub fn export_tenant_range(
    client: &mut Client,
    tenant_id: Uuid,
    attesters: &[VerifiedPublicKey],
    from_seq: u64,
    max_entries: usize,
) -> ExportResult<TenantRange> {
    let max_entries = max_entries.clamp(1, MAX_CHAIN_ENTRIES);
    let mut transaction = export_transaction(client, tenant_id)?;
    let portal = transaction.bind(JOURNAL_RANGE_QUERY, &[&tenant_id])?;
    let mut seq = 0u64;
    let mut prev = ChainLink::GENESIS;
    let mut exporter = (from_seq == 0).then(|| ChainExporter::with_attesters(attesters));
    let mut anchor = None;
    let mut taken = 0usize;
    let mut next_from_seq = None;
    'rows: loop {
        let rows = transaction.query_portal(&portal, RANGE_BATCH)?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let json: String = row.get(0);
            check_position(seq, row.get(1))?;
            let evidence = Evidence::from_json(json.trim_end())
                .map_err(|error| format!("receipt {seq}: {error}"))?;
            if seq + 1 < from_seq {
                // Before the anchor: only its link is needed.
                prev = receipt_link(seq, &prev, &evidence)?;
            } else if seq + 1 == from_seq {
                exporter = Some(ChainExporter::resume_after(
                    attesters, seq, prev, &evidence,
                )?);
                prev = receipt_link(seq, &prev, &evidence)?;
                anchor = Some(prev);
            } else {
                let exporter = exporter.as_mut().ok_or("range export lost its exporter")?;
                if taken == max_entries {
                    next_from_seq = Some(seq);
                    break 'rows;
                }
                match exporter.push(&evidence) {
                    Ok(()) => taken += 1,
                    // The size limit ends the range; the next one starts here.
                    Err(ChainError::TooLarge) if taken > 0 => {
                        next_from_seq = Some(seq);
                        break 'rows;
                    }
                    Err(error) => return Err(format!("receipt {seq}: {error}").into()),
                }
            }
            seq += 1;
        }
    }
    drop(portal);
    transaction.commit()?;
    if from_seq > 0 && anchor.is_none() {
        return Err(format!(
            "tenant {tenant_id} has no receipt at seq {} to anchor the range",
            from_seq - 1
        )
        .into());
    }
    if taken == 0 {
        return Err(format!("tenant {tenant_id} has no receipt at or after seq {from_seq}").into());
    }
    let exporter = exporter.ok_or("range export has no exporter")?;
    let (text, head) = exporter.finish()?;
    Ok(TenantRange {
        text,
        head,
        range_start: from_seq,
        anchor,
        next_from_seq,
    })
}

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
/// attestations, in chain order (`chain_seq`) and, within a request, in recording
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
     ORDER BY journal.chain_seq, record.created_at, record.kind, record.id LIMIT $2";

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
    let receipts = receipts_in_chain_order(&rows)?;
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
    Ok((receipts_in_chain_order(&rows)?, records))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_reads_receipts_in_the_whole_export_s_order() {
        // Commit order: the position of migration 0024, not created_at.
        assert!(JOURNAL_QUERY.contains("ORDER BY chain_seq LIMIT"));
        assert!(!JOURNAL_QUERY.contains("created_at"));
        assert!(OUTCOMES_QUERY.contains("ORDER BY journal.chain_seq, record.created_at"));
        assert_eq!(
            JOURNAL_RANGE_QUERY,
            JOURNAL_QUERY.strip_suffix(" LIMIT $2").unwrap()
        );
    }

    #[test]
    fn a_gap_or_a_jump_in_the_positions_is_refused() {
        check_position(0, 0).unwrap();
        check_position(7, 7).unwrap();
        for (index, found) in [(0, 1), (3, 2), (3, 5), (0, -1)] {
            let error = check_position(index, found).unwrap_err().to_string();
            assert!(
                error.contains(&format!("expected chain_seq {index}")),
                "{error}"
            );
            assert!(error.contains(&format!("found {found}")), "{error}");
        }
    }
}
