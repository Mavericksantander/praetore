//! Storage of post-hoc safety records (G1, SAF-09.5) in
//! `praetore.safety_records` (migration 0016).
//!
//! Used by `praetore-safety-ingest`, with its own login role (a member of
//! `praetore_safety_ingest`, checked by
//! [`crate::verify_safety_ingest_role_with`]), and by `praetore
//! journal-export --safety`. Row-level security (migration 0017) shows a
//! session only the rows of the tenant its login role is registered for in
//! `praetore.safety_ingest_tenants`; [`PostgresSafetyStore::check_registration`]
//! checks that registration before anything is read or written.

use std::collections::BTreeMap;

use postgres::Client;
use praetore_core::{
    VerifiedPublicKey,
    safety_ingest::{
        ChainHead, EventLookup, EventRef, MAX_SAFETY_CHAIN_ENTRIES, PreparedRecords, SafetyRecord,
        SafetyRecordError, safety_ingest_key_id,
    },
};
use uuid::Uuid;

use crate::set_tenant_context;

/// Why a safety record could not be read or stored.
#[derive(Debug)]
pub enum SafetyStoreError {
    Database(postgres::Error),
    /// A stored record does not parse or its hash does not match.
    Record {
        chain: String,
        error: SafetyRecordError,
    },
    /// The stored head of a chain names one of the given ingestion keys
    /// but its hash or signature does not verify.
    HeadSignature {
        chain: String,
    },
    /// The stored head of a chain is signed by an ingestion key that is
    /// neither the current one nor a configured previous one: a key change
    /// that was not registered, or a row written by someone else.
    UnpinnedHead {
        chain: String,
        key_id: String,
    },
    /// Too many records for one export.
    TooLarge,
    /// The login role is not registered in `praetore.safety_ingest_tenants`,
    /// or is registered for another tenant or ingestion key.
    Registration {
        role: String,
        expected_tenant: Uuid,
        expected_key_id: Option<String>,
        found: Option<(Uuid, String)>,
    },
}

impl std::fmt::Display for SafetyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => match error.as_db_error() {
                Some(db) => write!(
                    f,
                    "safety store: {} (SQLSTATE {})",
                    db.message(),
                    db.code().code()
                ),
                None => write!(f, "safety store: {error}"),
            },
            Self::Record { chain, error } => write!(f, "safety chain {chain}: {error}"),
            Self::HeadSignature { chain } => write!(
                f,
                "safety chain {chain}: the last record names a pinned ingestion key but its \
                 signature does not verify"
            ),
            Self::UnpinnedHead { chain, key_id } => write!(
                f,
                "safety chain {chain}: the last record is signed by ingestion key {key_id}, \
                 which is neither this key nor a configured previous key \
                 (PRAETORE_SAFETY_PREVIOUS_INGEST_PINS_FILE); refusing to continue the chain"
            ),
            Self::TooLarge => write!(f, "too many safety records for one export"),
            Self::Registration {
                role,
                expected_tenant,
                expected_key_id,
                found,
            } => {
                let key = expected_key_id.as_deref().unwrap_or("<ingestion key id>");
                match found {
                    None => write!(
                        f,
                        "database role {role} is not registered for safety ingestion; the \
                         schema owner registers it once: INSERT INTO \
                         praetore.safety_ingest_tenants (role_name, tenant_id, ingest_key_id) \
                         VALUES ('{role}', '{expected_tenant}', '{key}')"
                    ),
                    Some((tenant, key_id)) => write!(
                        f,
                        "database role {role} is registered for tenant {tenant} with ingestion \
                         key {key_id}, not for tenant {expected_tenant}{}; refusing to start",
                        expected_key_id
                            .as_deref()
                            .map(|key| format!(" with key {key}"))
                            .unwrap_or_default()
                    ),
                }
            }
        }
    }
}

impl std::error::Error for SafetyStoreError {}

impl From<postgres::Error> for SafetyStoreError {
    fn from(error: postgres::Error) -> Self {
        Self::Database(error)
    }
}

/// The last head of a chain as read at startup, and who signed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHead {
    pub head: ChainHead,
    /// The ingestion key id of the last record.
    pub key_id: String,
    /// The last record itself: [`praetore_core::safety_ingest::SafetyIngestor::resume_heads`]
    /// derives the head from it again.
    pub record: SafetyRecord,
}

/// `praetore.safety_records` through one connection.
pub struct PostgresSafetyStore {
    client: Client,
}

impl PostgresSafetyStore {
    pub fn from_client(client: Client) -> Self {
        Self { client }
    }

    pub fn client(&mut self) -> &mut Client {
        &mut self.client
    }

    /// Checks that the session's login role is registered for `tenant_id`
    /// (and, with `key_id`, for that ingestion key id) in
    /// `praetore.safety_ingest_tenants`. Row-level security shows and
    /// accepts only that tenant's rows, and the insert trigger only records
    /// signed by that key, so a mismatch would otherwise show up as an empty
    /// chain or a refused insert.
    pub fn check_registration(
        &mut self,
        tenant_id: Uuid,
        key_id: Option<&str>,
    ) -> Result<(), SafetyStoreError> {
        let row = self.client.query_one(
            "SELECT SESSION_USER::pg_catalog.text, t.tenant_id, \
                    t.ingest_key_id::pg_catalog.text \
             FROM (SELECT 1) one \
             LEFT JOIN praetore.safety_ingest_tenants t \
               ON t.role_name OPERATOR(pg_catalog.=) SESSION_USER",
            &[],
        )?;
        let role: String = row.get(0);
        let found = match (
            row.get::<_, Option<Uuid>>(1),
            row.get::<_, Option<String>>(2),
        ) {
            (Some(tenant), Some(key)) => Some((tenant, key)),
            _ => None,
        };
        let matches = found.as_ref().is_some_and(|(tenant, key)| {
            *tenant == tenant_id && key_id.is_none_or(|expected| expected == key)
        });
        if matches {
            return Ok(());
        }
        Err(SafetyStoreError::Registration {
            role,
            expected_tenant: tenant_id,
            expected_key_id: key_id.map(str::to_owned),
            found,
        })
    }

    /// Takes the session advisory lock of `tenant_id`'s safety chains, so
    /// that a second ingester for the same tenant refuses to start. Held
    /// until the connection closes. `false` when another session holds it.
    pub fn try_lock_tenant(&mut self, tenant_id: Uuid) -> Result<bool, SafetyStoreError> {
        Ok(self
            .client
            .query_one(
                "SELECT pg_catalog.pg_try_advisory_lock($1, pg_catalog.hashtext($2))",
                &[&SAFETY_LOCK_CLASS, &tenant_id.to_string()],
            )?
            .get(0))
    }

    /// The sessions holding the lock of `tenant_id` (see
    /// [`Self::try_lock_tenant`]): `pid`, login role, `application_name`
    /// and start time, as `pg_stat_activity` shows them to this role. The
    /// lock needs no privilege, so any role of the database can hold it
    /// (a known limitation): this tells the operator whom to stop.
    pub fn tenant_lock_holders(
        &mut self,
        tenant_id: Uuid,
    ) -> Result<Vec<String>, SafetyStoreError> {
        let rows = self.client.query(
            "SELECT l.pid, coalesce(a.usename::text, '?'), coalesce(a.application_name, ''), \
                    coalesce(a.backend_start::text, '?') \
             FROM pg_catalog.pg_locks l \
             LEFT JOIN pg_catalog.pg_stat_activity a ON a.pid = l.pid \
             WHERE l.locktype = 'advisory' AND l.granted AND l.objsubid = 2 \
               AND l.classid = $1::bigint::oid \
               AND l.objid = ((pg_catalog.hashtext($2)::bigint + 4294967296) % 4294967296)::oid \
               AND l.pid <> pg_catalog.pg_backend_pid() \
             ORDER BY l.pid",
            &[&i64::from(SAFETY_LOCK_CLASS), &tenant_id.to_string()],
        )?;
        Ok(rows
            .iter()
            .map(|row| {
                let pid: i32 = row.get(0);
                let user: String = row.get(1);
                let application: String = row.get(2);
                let started: String = row.get(3);
                format!("pid {pid}, role {user}, application {application:?}, since {started}")
            })
            .collect())
    }

    /// The last record of every chain of `tenant_id`. Each must parse, and
    /// its key id, hash and signature must verify under one of
    /// `ingest_pins` (the current ingestion key and the previous ones of a
    /// registered rotation). A head signed by any other key fails closed
    /// ([`SafetyStoreError::UnpinnedHead`]).
    pub fn load_heads(
        &mut self,
        tenant_id: Uuid,
        ingest_pins: &[VerifiedPublicKey],
    ) -> Result<BTreeMap<String, StoredHead>, SafetyStoreError> {
        let mut transaction = self
            .client
            .build_transaction()
            .read_only(true)
            .isolation_level(postgres::IsolationLevel::RepeatableRead)
            .start()?;
        set_tenant_context(&mut transaction, tenant_id)?;
        let rows = transaction.query(
            "SELECT DISTINCT ON (chain) chain, record_json, high_water \
             FROM praetore.safety_records WHERE tenant_id = $1 \
             ORDER BY chain, chain_seq DESC",
            &[&tenant_id],
        )?;
        transaction.commit()?;
        let mut heads = BTreeMap::new();
        for row in rows {
            let chain: String = row.get(0);
            let json: String = row.get(1);
            let high_water: i64 = row.get(2);
            let record =
                SafetyRecord::from_json(&json).map_err(|error| SafetyStoreError::Record {
                    chain: chain.clone(),
                    error,
                })?;
            let key_id = record.payload().key_id.clone();
            if !ingest_pins
                .iter()
                .any(|pin| safety_ingest_key_id(pin) == key_id)
            {
                return Err(SafetyStoreError::UnpinnedHead { chain, key_id });
            }
            if record.verify(ingest_pins).is_err() {
                return Err(SafetyStoreError::HeadSignature { chain });
            }
            // The head comes from the signed record; the column is only an
            // index and must agree with it.
            let head = record.next_head();
            if head.high_water != high_water as u64 {
                return Err(SafetyStoreError::Record {
                    chain,
                    error: SafetyRecordError::Invalid(
                        "the high_water column differs from the signed high_water".into(),
                    ),
                });
            }
            heads.insert(
                chain,
                StoredHead {
                    head,
                    key_id,
                    record,
                },
            );
        }
        Ok(heads)
    }

    /// Stores `prepared` in one transaction with `synchronous_commit = on`.
    /// The insert trigger refuses a record that does not extend its chain.
    pub fn store(
        &mut self,
        tenant_id: Uuid,
        prepared: &PreparedRecords,
    ) -> Result<(), SafetyStoreError> {
        let mut transaction = self.client.transaction()?;
        transaction.batch_execute("SET LOCAL synchronous_commit = on")?;
        set_tenant_context(&mut transaction, tenant_id)?;
        if prepared.high_waters.len() != prepared.records.len() {
            return Err(SafetyStoreError::Record {
                chain: prepared.chain.clone(),
                error: SafetyRecordError::Invalid("high_waters does not match records".into()),
            });
        }
        for (record, high_water) in prepared.records.iter().zip(&prepared.high_waters) {
            let payload = record.payload();
            let json = record.to_json().map_err(|error| SafetyStoreError::Record {
                chain: payload.chain.clone(),
                error,
            })?;
            transaction.execute(
                "INSERT INTO praetore.safety_records \
                 (tenant_id, chain, chain_seq, record_id, status, source_seq, event_hash, \
                  high_water, prev_record_hash, record_hash, record_json, source_epoch) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                &[
                    &payload.tenant_id,
                    &payload.chain,
                    &(payload.chain_seq as i64),
                    &payload.record_id,
                    &payload.status.as_str(),
                    &payload
                        .event
                        .as_ref()
                        .map(|event| event.source_seq() as i64),
                    &payload.event_hash,
                    &(*high_water as i64),
                    &payload.prev_record_hash,
                    &record.record_hash(),
                    &json,
                    &payload.source_epoch.map(|epoch| epoch as i64),
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
}

/// `classid` of the advisory lock that serializes ingesters of a tenant.
const SAFETY_LOCK_CLASS: i32 = 0x5341_4645; // "SAFE"

impl EventLookup for PostgresSafetyStore {
    type Error = postgres::Error;

    fn first_event(
        &mut self,
        tenant_id: Uuid,
        chain: &str,
        source_epoch: u64,
        source_seq: u64,
    ) -> Result<Option<EventRef>, Self::Error> {
        let mut transaction = self.client.build_transaction().read_only(true).start()?;
        set_tenant_context(&mut transaction, tenant_id)?;
        let row = transaction.query_opt(
            "SELECT event_hash::pg_catalog.text, record_hash::pg_catalog.text \
             FROM praetore.safety_records \
             WHERE tenant_id = $1 AND chain = $2 AND source_epoch = $3 AND source_seq = $4 \
               AND status IN ('accepted', 'undeclared', 'invalid_name', 'late') \
             ORDER BY chain_seq LIMIT 1",
            &[
                &tenant_id,
                &chain,
                &(source_epoch as i64),
                &(source_seq as i64),
            ],
        )?;
        transaction.commit()?;
        Ok(row.map(|row| EventRef {
            event_hash: row.get(0),
            record_hash: row.get(1),
        }))
    }
}

/// The records of one chain of `tenant_id`, in `chain_seq` order, read in
/// one read-only snapshot (for `praetore journal-export --safety`).
pub fn read_safety_chain(
    client: &mut Client,
    tenant_id: Uuid,
    chain: &str,
) -> Result<Vec<String>, SafetyStoreError> {
    let mut transaction = client
        .build_transaction()
        .read_only(true)
        .isolation_level(postgres::IsolationLevel::RepeatableRead)
        .start()?;
    set_tenant_context(&mut transaction, tenant_id)?;
    let limit = (MAX_SAFETY_CHAIN_ENTRIES + 1) as i64;
    let rows = transaction.query(
        "SELECT record_json FROM praetore.safety_records \
         WHERE tenant_id = $1 AND chain = $2 ORDER BY chain_seq LIMIT $3",
        &[&tenant_id, &chain, &limit],
    )?;
    transaction.commit()?;
    if rows.len() > MAX_SAFETY_CHAIN_ENTRIES {
        return Err(SafetyStoreError::TooLarge);
    }
    Ok(rows.iter().map(|row| row.get(0)).collect())
}

/// One range of a chain for `praetore journal-export --safety --from-seq`:
/// the anchor (the record at `from_seq - 1`, absent when `from_seq` is 0)
/// and the records from `from_seq`, at most `max_records` of them and at
/// most `max_bytes` in total (anchor included). A range never ends right
/// after a `source_seq` gap loss record: the event that revealed the gap
/// goes in the same range, even one record over `max_records`. `next_from_seq` is where the next range starts,
/// or `None` at the end of the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyChainRange {
    pub anchor: Option<String>,
    pub records: Vec<String>,
    pub next_from_seq: Option<u64>,
}

pub fn read_safety_chain_range(
    client: &mut Client,
    tenant_id: Uuid,
    chain: &str,
    from_seq: u64,
    max_records: usize,
    max_bytes: usize,
) -> Result<SafetyChainRange, SafetyStoreError> {
    let mut transaction = client
        .build_transaction()
        .read_only(true)
        .isolation_level(postgres::IsolationLevel::RepeatableRead)
        .start()?;
    set_tenant_context(&mut transaction, tenant_id)?;
    let start = from_seq.saturating_sub(1) as i64;
    // The anchor, the range and one record more (to know whether the
    // chain continues, and to finish a gap loss record's pair).
    let limit = (max_records.min(MAX_SAFETY_CHAIN_ENTRIES) + 3) as i64;
    let rows = transaction.query(
        "SELECT chain_seq, status, record_json FROM praetore.safety_records \
         WHERE tenant_id = $1 AND chain = $2 AND chain_seq >= $3 \
         ORDER BY chain_seq LIMIT $4",
        &[&tenant_id, &chain, &start, &limit],
    )?;
    transaction.commit()?;
    let mut rows = rows.iter().map(|row| {
        (
            row.get::<_, i64>(0) as u64,
            row.get::<_, String>(1),
            row.get::<_, String>(2),
        )
    });
    let mut bytes = 0;
    let anchor = if from_seq == 0 {
        None
    } else {
        match rows.next() {
            Some((seq, _, json)) if seq == from_seq - 1 => {
                bytes += json.len() + 1;
                Some(json)
            }
            _ => {
                return Err(SafetyStoreError::Record {
                    chain: chain.to_owned(),
                    error: SafetyRecordError::Invalid(format!(
                        "no record at chain_seq {} to anchor the range",
                        from_seq - 1
                    )),
                });
            }
        }
    };
    let rows: Vec<(u64, String, String)> = rows.collect();
    let mut taken = 0;
    while taken < rows.len()
        && taken < max_records.min(MAX_SAFETY_CHAIN_ENTRIES)
        && bytes + rows[taken].2.len() < max_bytes
    {
        bytes += rows[taken].2.len() + 1;
        taken += 1;
    }
    // Do not end on a gap loss record: take its event too (one record over
    // `max_records` if needed), or leave the loss record for the next range
    // when the size limit does not allow it.
    if taken > 0 && taken < rows.len() && is_gap_loss(&rows[taken - 1]) {
        if bytes + rows[taken].2.len() < max_bytes {
            taken += 1;
        } else {
            taken -= 1;
        }
    }
    if taken == 0 && !rows.is_empty() {
        return Err(SafetyStoreError::TooLarge);
    }
    let next_from_seq = rows.get(taken).map(|row| row.0);
    Ok(SafetyChainRange {
        anchor,
        records: rows.into_iter().take(taken).map(|row| row.2).collect(),
        next_from_seq,
    })
}

fn is_gap_loss(row: &(u64, String, String)) -> bool {
    row.1 == "loss" && row.2.contains("\"reason\":\"source_seq_gap\"")
}
