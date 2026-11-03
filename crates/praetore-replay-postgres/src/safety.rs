//! Storage of post-hoc safety records (G1, SAF-09.5) in
//! `praetore.safety_records` (migration 0016).
//!
//! Used by `praetore-safety-ingest`, with its own login role (a member of
//! `praetore_safety_ingest`, checked by
//! [`crate::verify_safety_ingest_role_with`]), and by `praetore
//! journal-export --safety`. Every transaction sets the tenant context, so
//! the `tenant_isolation` policy applies as for the journal tables.

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
            heads.insert(
                chain,
                StoredHead {
                    head: ChainHead {
                        next_chain_seq: record.payload().chain_seq + 1,
                        prev_record_hash: record.record_hash().to_owned(),
                        high_water: high_water as u64,
                    },
                    key_id,
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
                  high_water, prev_record_hash, record_hash, record_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
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
        source_seq: u64,
    ) -> Result<Option<EventRef>, Self::Error> {
        let mut transaction = self.client.build_transaction().read_only(true).start()?;
        set_tenant_context(&mut transaction, tenant_id)?;
        let row = transaction.query_opt(
            "SELECT event_hash::pg_catalog.text, record_hash::pg_catalog.text \
             FROM praetore.safety_records \
             WHERE tenant_id = $1 AND chain = $2 AND source_seq = $3 \
               AND status IN ('accepted', 'undeclared', 'invalid_name', 'late') \
             ORDER BY chain_seq LIMIT 1",
            &[&tenant_id, &chain, &(source_seq as i64)],
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
