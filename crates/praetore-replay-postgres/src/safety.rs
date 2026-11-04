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
    /// An audit role (`praetore_safety_audit`) is not registered for the
    /// tenant in `praetore.safety_audit_tenants`.
    AuditRegistration {
        role: String,
        tenant: Uuid,
    },
    /// The login role cannot lock `tenant`'s registration: it is not the
    /// role registered for that tenant (see [`TenantLock`]).
    LockNotRegistered {
        role: String,
        tenant: Uuid,
    },
    /// Another session holds the lock of `tenant`.
    LockBusy {
        role: String,
        tenant: Uuid,
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
            Self::AuditRegistration { role, tenant } => write!(
                f,
                "audit role {role} is not registered for tenant {tenant}; the schema owner \
                 registers it once: INSERT INTO praetore.safety_audit_tenants (role_oid, \
                 tenant_id) VALUES ('{role}'::regrole, '{tenant}')"
            ),
            Self::LockNotRegistered { role, tenant } => write!(
                f,
                "database role {role} cannot lock tenant {tenant}: it is not the role \
                 registered for that tenant in praetore.safety_ingest_tenants (or the \
                 migrations are not at 0019); refusing to start"
            ),
            Self::LockBusy { role, tenant } => write!(
                f,
                "another session holds the lock of tenant {tenant} (only role {role} or \
                 the schema owner can); refusing to start"
            ),
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
                         praetore.safety_ingest_tenants (role_oid, tenant_id, ingest_key_id) \
                         VALUES ('{role}'::regrole, '{expected_tenant}', '{key}') (or, for a \
                         read-only export, register an audit role in \
                         praetore.safety_audit_tenants)"
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
               ON t.role_oid OPERATOR(pg_catalog.=) \
                  (SELECT r.oid FROM pg_catalog.pg_roles r \
                   WHERE r.rolname OPERATOR(pg_catalog.=) SESSION_USER)",
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

    /// For an export: checks that the session's login role may read
    /// `tenant_id`'s records, as that tenant's registered ingest role or as
    /// an audit role registered for it in `praetore.safety_audit_tenants`.
    /// Row-level security would otherwise show an empty chain.
    pub fn check_read_access(&mut self, tenant_id: Uuid) -> Result<(), SafetyStoreError> {
        let audit: bool = self
            .client
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles g \
                                WHERE g.rolname OPERATOR(pg_catalog.=) 'praetore_safety_audit' \
                                  AND pg_catalog.pg_has_role(SESSION_USER, g.oid, 'MEMBER'))",
                &[],
            )?
            .get(0);
        if !audit {
            return self.check_registration(tenant_id, None);
        }
        let row = self.client.query_one(
            "SELECT SESSION_USER::pg_catalog.text, EXISTS ( \
                 SELECT 1 FROM praetore.safety_audit_tenants a \
                 WHERE a.tenant_id = $1 \
                   AND a.role_oid OPERATOR(pg_catalog.=) \
                       (SELECT r.oid FROM pg_catalog.pg_roles r \
                        WHERE r.rolname OPERATOR(pg_catalog.=) SESSION_USER))",
            &[&tenant_id],
        )?;
        if row.get::<_, bool>(1) {
            return Ok(());
        }
        Err(SafetyStoreError::AuditRegistration {
            role: row.get(0),
            tenant: tenant_id,
        })
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

/// How long [`TenantLock::is_held`] waits for the server.
const LOCK_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The exclusive lock of one tenant's safety chains, so that a second
/// ingester for the tenant refuses to start (migration 0019).
///
/// It is a row lock (`FOR UPDATE NOWAIT`) on the login role's own
/// registration in `praetore.safety_ingest_tenants`, held by an open
/// transaction on a connection of its own: row-level security shows that
/// row only to the registered role (by the OID of `SESSION_USER`), so
/// another role, or the role of another tenant, cannot take it. Released
/// when this value is dropped or the connection closes.
pub struct TenantLock {
    client: Client,
    tenant_id: Uuid,
}

impl TenantLock {
    /// Takes the lock of `tenant_id` on `client`, a connection used for
    /// nothing else. Fails closed: [`SafetyStoreError::LockNotRegistered`]
    /// when the login role cannot lock that tenant's registration (not
    /// registered, registered for another tenant, or no privilege), and
    /// [`SafetyStoreError::LockBusy`] when another session holds it.
    pub fn acquire(mut client: Client, tenant_id: Uuid) -> Result<Self, SafetyStoreError> {
        let role: String = client
            .query_one("SELECT SESSION_USER::pg_catalog.text", &[])?
            .get(0);
        // An idle transaction is the lock: a server-wide timeout must not end it.
        client.batch_execute("SET idle_in_transaction_session_timeout = 0; BEGIN")?;
        let locked = client.query(
            "SELECT t.tenant_id FROM praetore.safety_ingest_tenants t \
             WHERE t.tenant_id = $1 \
               AND t.role_oid OPERATOR(pg_catalog.=) \
                   (SELECT r.oid FROM pg_catalog.pg_roles r \
                    WHERE r.rolname OPERATOR(pg_catalog.=) SESSION_USER) \
             FOR UPDATE NOWAIT",
            &[&tenant_id],
        );
        match locked {
            Ok(rows) if rows.len() == 1 => Ok(Self { client, tenant_id }),
            Ok(_) => Err(SafetyStoreError::LockNotRegistered {
                role,
                tenant: tenant_id,
            }),
            Err(error) if error.code() == Some(&postgres::error::SqlState::LOCK_NOT_AVAILABLE) => {
                Err(SafetyStoreError::LockBusy {
                    role,
                    tenant: tenant_id,
                })
            }
            Err(error)
                if error.code() == Some(&postgres::error::SqlState::INSUFFICIENT_PRIVILEGE) =>
            {
                Err(SafetyStoreError::LockNotRegistered {
                    role,
                    tenant: tenant_id,
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// Whether the lock is still held: one round trip on its connection
    /// (`false` once that connection is gone, for example terminated). The
    /// holder must stop writing until it takes the lock again.
    pub fn is_held(&mut self) -> bool {
        self.client.is_valid(LOCK_CHECK_TIMEOUT).is_ok()
    }

    /// The other sessions of this login role (`pid`, `application_name`
    /// and start time, from `pg_stat_activity`): only this role (or the
    /// table owner) can hold the lock, so after a
    /// [`SafetyStoreError::LockBusy`] one of them holds it.
    pub fn other_sessions(client: &mut Client) -> Result<Vec<String>, SafetyStoreError> {
        let rows = client.query(
            "SELECT a.pid, coalesce(a.application_name, ''), \
                    coalesce(a.backend_start::text, '?') \
             FROM pg_catalog.pg_stat_activity a \
             WHERE a.usename OPERATOR(pg_catalog.=) SESSION_USER \
               AND a.pid <> pg_catalog.pg_backend_pid() \
             ORDER BY a.pid",
            &[],
        )?;
        Ok(rows
            .iter()
            .map(|row| {
                let pid: i32 = row.get(0);
                let application: String = row.get(1);
                let started: String = row.get(2);
                format!("pid {pid}, application {application:?}, since {started}")
            })
            .collect())
    }
}

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
