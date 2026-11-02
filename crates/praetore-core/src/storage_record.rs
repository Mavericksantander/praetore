//! Signed storage records: facts about the journal database itself, such as
//! the adoption of a legacy schema baseline, signed with the attester key
//! and exported in a database-level journal chain
//! (`docs/proposals/journal-chain-jsonl.md`).

use crate::evidence::attester_key_id;
use crate::{EvidenceAttesterKey, PraetoreError, VerifiedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Signature domain of every storage record (27 bytes, NUL included).
pub const STORAGE_RECORD_DOMAIN: &[u8; 27] = b"PRAETORE_STORAGE_RECORD_V1\0";
/// The only schema version this crate writes and accepts.
pub const STORAGE_RECORD_SCHEMA_VERSION: u8 = 1;
/// Kind of the record written when a legacy 0001-0009 baseline is adopted.
pub const LEGACY_BASELINE_ADOPTED: &str = "legacy_baseline_adopted";
/// Maximum size of one record's JSON.
pub const MAX_STORAGE_RECORD_BYTES: usize = 64 * 1024;

/// One migration recorded by an adoption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedMigration {
    pub version: String,
    pub checksum: String,
}

/// What is signed: every field of a [`StorageRecord`] except `record_hash`
/// and `signature`, serialized in this field order as compact JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageRecordPayload {
    pub schema_version: u8,
    pub kind: String,
    pub record_id: Uuid,
    /// RFC 3339, from the database clock at recording time.
    pub recorded_at: String,
    /// `current_database()` and its OID at recording time.
    pub database: String,
    pub database_oid: u32,
    /// The session role that recorded it (the migrating role).
    pub recorded_by: String,
    pub migrations: Vec<RecordedMigration>,
    /// SHA-256 of the compared 0001-0009 structure (as in
    /// `praetore.schema_migrations.baseline_structure_sha256`).
    pub structure_sha256: String,
    /// Attester key id of the signing key.
    pub key_id: String,
}

/// A signed storage record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageRecord {
    pub schema_version: u8,
    pub kind: String,
    pub record_id: Uuid,
    pub recorded_at: String,
    pub database: String,
    pub database_oid: u32,
    pub recorded_by: String,
    pub migrations: Vec<RecordedMigration>,
    pub structure_sha256: String,
    pub key_id: String,
    /// `hex(SHA-256(STORAGE_RECORD_DOMAIN || payload))`.
    pub record_hash: String,
    /// `hex(Ed25519(STORAGE_RECORD_DOMAIN || payload))` by the attester key.
    pub signature: String,
}

/// Signs storage records. The migration runner receives one from the
/// binary and never holds the key itself.
pub trait StorageRecordSigner: Send + Sync {
    fn key_id(&self) -> String;
    fn sign_storage_record(&self, payload: StorageRecordPayload) -> crate::Result<StorageRecord>;
}

impl StorageRecordSigner for EvidenceAttesterKey {
    fn key_id(&self) -> String {
        EvidenceAttesterKey::key_id(self)
    }

    fn sign_storage_record(&self, payload: StorageRecordPayload) -> crate::Result<StorageRecord> {
        if payload.key_id != EvidenceAttesterKey::key_id(self) {
            return Err(record_error("payload key_id is not this attester key"));
        }
        payload.validate()?;
        let bytes = payload.canonical_bytes()?;
        let signature = self.sign_with_domain(STORAGE_RECORD_DOMAIN, &bytes);
        Ok(StorageRecord::from_parts(
            payload,
            hex::encode(record_hash(&bytes)),
            hex::encode(signature),
        ))
    }
}

fn record_error(message: &str) -> PraetoreError {
    PraetoreError::EvidenceError(format!("storage record: {message}"))
}

fn record_hash(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(STORAGE_RECORD_DOMAIN);
    hasher.update(payload);
    hasher.finalize().into()
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl StorageRecordPayload {
    fn canonical_bytes(&self) -> crate::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| record_error("cannot serialize payload"))
    }

    fn validate(&self) -> crate::Result<()> {
        if self.schema_version != STORAGE_RECORD_SCHEMA_VERSION {
            return Err(record_error("unsupported schema_version"));
        }
        if self.kind != LEGACY_BASELINE_ADOPTED {
            return Err(record_error("unknown kind"));
        }
        if !is_lower_hex(&self.structure_sha256, 64) || !is_lower_hex(&self.key_id, 64) {
            return Err(record_error("malformed digest"));
        }
        if self.migrations.is_empty()
            || self
                .migrations
                .iter()
                .any(|migration| !is_lower_hex(&migration.checksum, 64))
        {
            return Err(record_error("malformed migrations"));
        }
        time::OffsetDateTime::parse(
            &self.recorded_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| record_error("recorded_at is not RFC 3339"))?;
        Ok(())
    }
}

impl StorageRecord {
    fn from_parts(payload: StorageRecordPayload, record_hash: String, signature: String) -> Self {
        Self {
            schema_version: payload.schema_version,
            kind: payload.kind,
            record_id: payload.record_id,
            recorded_at: payload.recorded_at,
            database: payload.database,
            database_oid: payload.database_oid,
            recorded_by: payload.recorded_by,
            migrations: payload.migrations,
            structure_sha256: payload.structure_sha256,
            key_id: payload.key_id,
            record_hash,
            signature,
        }
    }

    pub fn payload(&self) -> StorageRecordPayload {
        StorageRecordPayload {
            schema_version: self.schema_version,
            kind: self.kind.clone(),
            record_id: self.record_id,
            recorded_at: self.recorded_at.clone(),
            database: self.database.clone(),
            database_oid: self.database_oid,
            recorded_by: self.recorded_by.clone(),
            migrations: self.migrations.clone(),
            structure_sha256: self.structure_sha256.clone(),
            key_id: self.key_id.clone(),
        }
    }

    /// Parses one record (unknown fields and duplicate keys are refused).
    pub fn from_json(json: &str) -> crate::Result<Self> {
        if json.len() > MAX_STORAGE_RECORD_BYTES {
            return Err(record_error("too large"));
        }
        let record: Self =
            serde_json::from_str(json).map_err(|_| record_error("malformed JSON"))?;
        record.payload().validate()?;
        Ok(record)
    }

    /// Compact JSON, one line, as stored and exported.
    pub fn to_json(&self) -> crate::Result<String> {
        serde_json::to_string(self).map_err(|_| record_error("cannot serialize"))
    }

    /// Checks the record hash and the Ed25519 signature against the pinned
    /// attester key.
    pub fn verify(&self, attester: &VerifiedPublicKey) -> crate::Result<()> {
        let payload = self.payload();
        payload.validate()?;
        if self.key_id != attester_key_id(attester) {
            return Err(PraetoreError::EvidenceError(format!(
                "storage record: signed by attester key {}, not by a pinned key",
                self.key_id
            )));
        }
        let bytes = payload.canonical_bytes()?;
        if !is_lower_hex(&self.record_hash, 64)
            || self.record_hash != hex::encode(record_hash(&bytes))
        {
            return Err(record_error("record_hash does not match"));
        }
        let signature = hex::decode(&self.signature).map_err(|_| record_error("bad signature"))?;
        attester
            .verify_domain_message(STORAGE_RECORD_DOMAIN, &bytes, &signature)
            .map_err(|_| record_error("signature does not verify"))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn sample_record(attester: &EvidenceAttesterKey) -> StorageRecord {
        attester
            .sign_storage_record(StorageRecordPayload {
                schema_version: 1,
                kind: LEGACY_BASELINE_ADOPTED.into(),
                record_id: Uuid::new_v4(),
                recorded_at: "2026-11-01T12:00:00.000000Z".into(),
                database: "praetore".into(),
                database_oid: 16384,
                recorded_by: "mig".into(),
                migrations: vec![RecordedMigration {
                    version: "0001_replay_claims".into(),
                    checksum: "a".repeat(64),
                }],
                structure_sha256: "b".repeat(64),
                key_id: attester.key_id(),
            })
            .unwrap()
    }

    #[test]
    fn signed_record_verifies_and_any_change_fails() {
        let attester = EvidenceAttesterKey::from_secret_bytes(&[7; 32]);
        let pin = attester.public_key().unwrap();
        let record = sample_record(&attester);
        record.verify(&pin).unwrap();
        let parsed = StorageRecord::from_json(&record.to_json().unwrap()).unwrap();
        assert_eq!(parsed, record);
        let mut altered = record.clone();
        altered.recorded_by = "someone".into();
        assert!(altered.verify(&pin).is_err());
        let other = EvidenceAttesterKey::from_secret_bytes(&[8; 32]);
        assert!(record.verify(&other.public_key().unwrap()).is_err());
        let extra = record.to_json().unwrap().replacen('{', "{\"extra\":1,", 1);
        assert!(StorageRecord::from_json(&extra).is_err());
    }

    #[test]
    fn storage_record_signature_is_not_a_receipt_signature() {
        // The domains differ, so a record signature can never verify as a
        // receipt signature over the same bytes, and vice versa.
        assert_ne!(
            &STORAGE_RECORD_DOMAIN[..],
            &b"PRAETORE_JOURNAL_LINK_V1\0"[..]
        );
        let attester = EvidenceAttesterKey::from_secret_bytes(&[7; 32]);
        let pin = attester.public_key().unwrap();
        let record = sample_record(&attester);
        let bytes = record.payload().canonical_bytes().unwrap();
        let signature = hex::decode(&record.signature).unwrap();
        assert!(
            pin.verify_domain_message(b"PRAETORE_EVIDENCE", &bytes, &signature)
                .is_err()
        );
    }
}
