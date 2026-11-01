//! Hash-linked JSONL export of signed receipts
//! (`docs/proposals/journal-chain-jsonl.md`).
//!
//! The producer ([`ChainExporter`]) and the verifier ([`verify_chain`]) share
//! the same link function, so they cannot drift apart.
//!
//! The link is an unkeyed SHA-256. Whoever holds the receipts can rebuild a
//! chain over any subset of them, in any order. A head only proves something
//! when it was anchored somewhere the producer does not control and the
//! verifier compares against it (`expected_head`).

use crate::{Evidence, Policy, PraetoreError, StorageRecord, VerifiedPublicKey};
use serde::Deserialize;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt, num::NonZeroU64};
use uuid::Uuid;

/// Domain separation prefix of every receipt link (25 bytes, NUL included).
pub const LINK_DOMAIN: &[u8; 25] = b"PRAETORE_JOURNAL_LINK_V1\0";
/// Domain of the link of a storage-record line (27 bytes, NUL included).
pub const RECORD_LINK_DOMAIN: &[u8; 27] = b"PRAETORE_JOURNAL_RECORD_V1\0";
/// Domain of the link of a database-head reference line (34 bytes).
pub const DATABASE_HEAD_LINK_DOMAIN: &[u8; 34] = b"PRAETORE_JOURNAL_DATABASE_HEAD_V1\0";
/// Schema version of the `database_head` reference.
pub const DATABASE_HEAD_SCHEMA_VERSION: u8 = 1;
/// Maximum size of one export file.
pub const MAX_CHAIN_BYTES: usize = 8 * 1024 * 1024;
/// Maximum number of entries in one export file.
pub const MAX_CHAIN_ENTRIES: usize = 4_096;

/// A 32-byte link value. Only ever rendered or parsed as 64 lowercase hex
/// characters, so two equal links always have the same text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChainLink([u8; 32]);

impl ChainLink {
    /// `prev` of the first entry: 64 zeros.
    pub const GENESIS: Self = Self([0; 32]);

    /// Parses exactly 64 lowercase hex characters. Anything else is `None`.
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let mut bytes = [0; 32];
        hex::decode_to_slice(text, &mut bytes).ok()?;
        Some(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for ChainLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for ChainLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChainLink({self})")
    }
}

/// A tenant chain's reference to the database chain at export time: its
/// number of entries and its head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatabaseHead {
    pub entries: NonZeroU64,
    pub head: ChainLink,
}

impl From<ChainHead> for DatabaseHead {
    fn from(head: ChainHead) -> Self {
        Self {
            entries: head.entries,
            head: head.head,
        }
    }
}

/// What a verified journal is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalKind {
    /// Receipts of one tenant, optionally referencing the database chain.
    Tenant { database_head: Option<DatabaseHead> },
    /// Storage records of the database.
    Database,
}

/// Result of [`verify_journal`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalSummary {
    pub head: ChainHead,
    pub kind: JournalKind,
}

/// What a tenant chain's database reference must match: a head, and the
/// number of entries when it is known (from a database chain file).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpectedDatabaseHead {
    pub head: ChainLink,
    pub entries: Option<NonZeroU64>,
}

/// Result of a non-empty chain: number of entries and the last link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainHead {
    pub entries: NonZeroU64,
    pub head: ChainLink,
}

/// Why a chain was not produced or not accepted. Every variant is a failure;
/// there is no partial success.
#[derive(Debug)]
pub enum ChainError {
    /// No entries. An empty export is invalid.
    Empty,
    /// Over [`MAX_CHAIN_BYTES`] or [`MAX_CHAIN_ENTRIES`].
    TooLarge,
    /// Line `seq` is not valid JSON in the documented shape.
    Malformed { line: u64 },
    /// `seq` or `prev` of line `line` is not the expected one.
    BrokenLink { line: u64 },
    /// The `evidence_id` was already seen earlier in the chain.
    DuplicateEvidenceId { line: u64, evidence_id: Uuid },
    /// The receipt has no attester signature.
    MissingSignature { line: u64 },
    /// The receipt failed to parse, its integrity hash or its signature.
    Evidence { line: u64, error: PraetoreError },
    /// The receipt does not record the given policy digest.
    PolicyMismatch { line: u64 },
    /// The chain verifies but its head is not the expected one.
    HeadMismatch { actual: ChainLink },
    /// The storage record failed to parse or verify.
    Record { line: u64, error: PraetoreError },
    /// The `record_id` was already seen earlier in the chain.
    DuplicateRecordId { line: u64, record_id: Uuid },
    /// Line `line` is of a kind not allowed there (records mixed with
    /// receipts, or a database reference that is not the first line).
    MixedKinds { line: u64 },
    /// The tenant chain's database reference is missing or does not match.
    DatabaseHeadMismatch,
}

impl ChainError {
    /// Stable machine-readable code, used by the CLIs.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty
            | Self::BrokenLink { .. }
            | Self::DuplicateEvidenceId { .. }
            | Self::DuplicateRecordId { .. }
            | Self::MixedKinds { .. } => "JOURNAL_CHAIN_FAIL",
            Self::Record { .. } => "EVIDENCE_FAIL",
            Self::DatabaseHeadMismatch => "JOURNAL_HEAD_MISMATCH",
            Self::TooLarge => "INPUT_TOO_LARGE",
            Self::Malformed { .. } => "INVALID_REQUEST",
            Self::MissingSignature { .. } => "AUTH_FAIL",
            Self::Evidence { error, .. } => error.code(),
            Self::PolicyMismatch { .. } => "POLICY_MISMATCH",
            Self::HeadMismatch { .. } => "JOURNAL_HEAD_MISMATCH",
        }
    }
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "journal chain is empty"),
            Self::TooLarge => write!(f, "journal chain exceeds the size or entry limit"),
            Self::Malformed { line } => write!(f, "entry {line}: malformed line"),
            Self::BrokenLink { line } => write!(f, "entry {line}: seq or prev does not match"),
            Self::DuplicateEvidenceId { line, evidence_id } => {
                write!(f, "entry {line}: duplicate evidence_id {evidence_id}")
            }
            Self::MissingSignature { line } => {
                write!(f, "entry {line}: receipt has no attester signature")
            }
            Self::Evidence { line, error } => write!(f, "entry {line}: {error}"),
            Self::PolicyMismatch { line } => {
                write!(
                    f,
                    "entry {line}: receipt does not record the given policy digest"
                )
            }
            Self::HeadMismatch { actual } => {
                write!(f, "head {actual} does not match the expected head")
            }
            Self::Record { line, error } => write!(f, "entry {line}: {error}"),
            Self::DuplicateRecordId { line, record_id } => {
                write!(f, "entry {line}: duplicate record_id {record_id}")
            }
            Self::MixedKinds { line } => write!(
                f,
                "entry {line}: line kind not allowed here (a chain holds either storage records \
                 or receipts, and a database reference only as its first line)"
            ),
            Self::DatabaseHeadMismatch => write!(
                f,
                "the tenant chain's database reference is missing or does not match the \
                 database chain"
            ),
        }
    }
}

impl std::error::Error for ChainError {}

/// `SHA-256(LINK_DOMAIN || u64_be(seq) || prev_hex || context_hash || attester_signature)`.
fn link(seq: u64, prev: &ChainLink, evidence: &Evidence) -> Result<ChainLink, ChainError> {
    let signature = evidence
        .attester_signature
        .as_deref()
        .ok_or(ChainError::MissingSignature { line: seq })?;
    let mut hasher = Sha256::new();
    hasher.update(LINK_DOMAIN);
    hasher.update(seq.to_be_bytes());
    hasher.update(prev.to_hex().as_bytes());
    hasher.update(evidence.context_hash.as_bytes());
    hasher.update(signature.as_bytes());
    Ok(ChainLink(hasher.finalize().into()))
}

/// `SHA-256(RECORD_LINK_DOMAIN || u64_be(seq) || prev_hex || record_hash || signature)`.
fn record_link(seq: u64, prev: &ChainLink, record: &StorageRecord) -> ChainLink {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_LINK_DOMAIN);
    hasher.update(seq.to_be_bytes());
    hasher.update(prev.to_hex().as_bytes());
    hasher.update(record.record_hash.as_bytes());
    hasher.update(record.signature.as_bytes());
    ChainLink(hasher.finalize().into())
}

/// `SHA-256(DATABASE_HEAD_LINK_DOMAIN || u64_be(seq) || prev_hex || head_hex || u64_be(entries))`.
fn database_head_link(seq: u64, prev: &ChainLink, reference: &DatabaseHead) -> ChainLink {
    let mut hasher = Sha256::new();
    hasher.update(DATABASE_HEAD_LINK_DOMAIN);
    hasher.update(seq.to_be_bytes());
    hasher.update(prev.to_hex().as_bytes());
    hasher.update(reference.head.to_hex().as_bytes());
    hasher.update(reference.entries.get().to_be_bytes());
    ChainLink(hasher.finalize().into())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Unknown,
    Tenant,
    Database,
}

/// Shared state of producer and verifier: position, last link, seen ids.
struct ChainState<'k> {
    attester: &'k VerifiedPublicKey,
    policy: Option<&'k Policy>,
    seq: u64,
    prev: ChainLink,
    seen: HashSet<Uuid>,
    seen_records: HashSet<Uuid>,
    kind: Kind,
    receipts: u64,
    database_head: Option<DatabaseHead>,
}

impl<'k> ChainState<'k> {
    fn new(attester: &'k VerifiedPublicKey, policy: Option<&'k Policy>) -> Self {
        Self {
            attester,
            policy,
            seq: 0,
            prev: ChainLink::GENESIS,
            seen: HashSet::new(),
            seen_records: HashSet::new(),
            kind: Kind::Unknown,
            receipts: 0,
            database_head: None,
        }
    }

    fn next_line(&self) -> Result<u64, ChainError> {
        if self.seq as usize >= MAX_CHAIN_ENTRIES {
            return Err(ChainError::TooLarge);
        }
        Ok(self.seq)
    }

    /// A storage record: only in a database chain.
    fn append_record(&mut self, record: &StorageRecord) -> Result<(), ChainError> {
        let line = self.next_line()?;
        if self.kind == Kind::Tenant {
            return Err(ChainError::MixedKinds { line });
        }
        record
            .verify(self.attester)
            .map_err(|error| ChainError::Record { line, error })?;
        if !self.seen_records.insert(record.record_id) {
            return Err(ChainError::DuplicateRecordId {
                line,
                record_id: record.record_id,
            });
        }
        self.kind = Kind::Database;
        self.prev = record_link(self.seq, &self.prev, record);
        self.seq += 1;
        Ok(())
    }

    /// A database reference: only as the first line of a tenant chain.
    fn append_database_head(&mut self, reference: &DatabaseHead) -> Result<(), ChainError> {
        let line = self.next_line()?;
        if self.seq != 0 {
            return Err(ChainError::MixedKinds { line });
        }
        self.kind = Kind::Tenant;
        self.database_head = Some(*reference);
        self.prev = database_head_link(self.seq, &self.prev, reference);
        self.seq += 1;
        Ok(())
    }

    /// Checks one receipt at the current position and advances the chain.
    fn append(&mut self, evidence: &Evidence) -> Result<(), ChainError> {
        let line = self.next_line()?;
        if self.kind == Kind::Database {
            return Err(ChainError::MixedKinds { line });
        }
        if evidence.attester_signature.is_none() {
            return Err(ChainError::MissingSignature { line });
        }
        evidence
            .verify_attester_signature(self.attester)
            .map_err(|error| ChainError::Evidence { line, error })?;
        if !self.seen.insert(evidence.evidence_id) {
            return Err(ChainError::DuplicateEvidenceId {
                line,
                evidence_id: evidence.evidence_id,
            });
        }
        if let Some(policy) = self.policy
            && evidence.verify_policy(policy).is_err()
        {
            return Err(ChainError::PolicyMismatch { line });
        }
        self.prev = link(self.seq, &self.prev, evidence)?;
        self.seq += 1;
        self.kind = Kind::Tenant;
        self.receipts += 1;
        Ok(())
    }

    fn head(&self) -> Result<ChainHead, ChainError> {
        // A tenant chain needs at least one receipt besides its reference.
        if self.kind == Kind::Tenant && self.receipts == 0 {
            return Err(ChainError::Empty);
        }
        Ok(ChainHead {
            entries: NonZeroU64::new(self.seq).ok_or(ChainError::Empty)?,
            head: self.prev,
        })
    }

    fn summary(&self) -> Result<JournalSummary, ChainError> {
        Ok(JournalSummary {
            head: self.head()?,
            kind: match self.kind {
                Kind::Database => JournalKind::Database,
                _ => JournalKind::Tenant {
                    database_head: self.database_head,
                },
            },
        })
    }
}

/// Builds a chain from receipts in the given order. Each receipt is checked
/// against the pinned attester key before it is linked, so the producer never
/// emits a chain that its own verifier would reject.
pub struct ChainExporter<'k> {
    state: ChainState<'k>,
    output: String,
}

impl<'k> ChainExporter<'k> {
    pub fn new(attester: &'k VerifiedPublicKey) -> Self {
        Self {
            state: ChainState::new(attester, None),
            output: String::new(),
        }
    }

    pub fn push(&mut self, evidence: &Evidence) -> Result<(), ChainError> {
        let seq = self.state.seq;
        let prev = self.state.prev;
        let json = evidence
            .to_json()
            .map_err(|error| ChainError::Evidence { line: seq, error })?;
        self.state.append(evidence)?;
        // `to_json` is canonical compact JSON (no newline); `prev` is hex.
        let line = format!("{{\"seq\":{seq},\"prev\":\"{prev}\",\"evidence\":{json}}}\n");
        if self.output.len() + line.len() > MAX_CHAIN_BYTES {
            return Err(ChainError::TooLarge);
        }
        self.output.push_str(&line);
        Ok(())
    }

    /// Starts a tenant chain with a reference to the database chain.
    pub fn push_database_head(&mut self, reference: &DatabaseHead) -> Result<(), ChainError> {
        let seq = self.state.seq;
        let prev = self.state.prev;
        self.state.append_database_head(reference)?;
        let line = format!(
            "{{\"seq\":{seq},\"prev\":\"{prev}\",\"database_head\":{{\"schema_version\":{DATABASE_HEAD_SCHEMA_VERSION},\"entries\":{},\"head\":\"{}\"}}}}\n",
            reference.entries, reference.head
        );
        self.push_line(&line)
    }

    /// Appends a storage record (a database chain holds only records).
    pub fn push_record(&mut self, record: &StorageRecord) -> Result<(), ChainError> {
        let seq = self.state.seq;
        let prev = self.state.prev;
        let json = record
            .to_json()
            .map_err(|error| ChainError::Record { line: seq, error })?;
        self.state.append_record(record)?;
        let line = format!("{{\"seq\":{seq},\"prev\":\"{prev}\",\"record\":{json}}}\n");
        self.push_line(&line)
    }

    fn push_line(&mut self, line: &str) -> Result<(), ChainError> {
        if self.output.len() + line.len() > MAX_CHAIN_BYTES {
            return Err(ChainError::TooLarge);
        }
        self.output.push_str(line);
        Ok(())
    }

    /// Returns the JSONL text and its head. Fails if no receipt was pushed.
    pub fn finish(self) -> Result<(String, ChainHead), ChainError> {
        let head = self.state.head()?;
        Ok((self.output, head))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry<'a> {
    seq: u64,
    prev: &'a str,
    #[serde(borrow, default)]
    evidence: Option<&'a RawValue>,
    #[serde(borrow, default)]
    record: Option<&'a RawValue>,
    #[serde(default)]
    database_head: Option<DatabaseHeadField<'a>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DatabaseHeadField<'a> {
    schema_version: u8,
    entries: u64,
    head: &'a str,
}

/// Verifies a JSONL export of receipts (a tenant chain, with or without a
/// database reference) or of storage records (a database chain), and
/// returns its head. Fail-closed: the first problem ends verification.
///
/// Without `expected_head`, a truncated, re-ordered or re-linked subset of
/// validly signed receipts still verifies (see the module docs).
pub fn verify_chain(
    text: &str,
    attester: &VerifiedPublicKey,
    policy: Option<&Policy>,
    expected_head: Option<&ChainLink>,
) -> Result<ChainHead, ChainError> {
    verify_journal(text, attester, policy, expected_head, None).map(|summary| summary.head)
}

/// [`verify_chain`] that also reports the kind of chain and, for a tenant
/// chain, its database reference; with `expected_database_head`, the
/// reference must be present and equal to it.
pub fn verify_journal(
    text: &str,
    attester: &VerifiedPublicKey,
    policy: Option<&Policy>,
    expected_head: Option<&ChainLink>,
    expected_database_head: Option<&ExpectedDatabaseHead>,
) -> Result<JournalSummary, ChainError> {
    if text.len() > MAX_CHAIN_BYTES {
        return Err(ChainError::TooLarge);
    }
    let mut state = ChainState::new(attester, policy);
    let mut rest = text;
    while !rest.is_empty() {
        let line = state.seq;
        let (current, tail) = rest
            .split_once('\n')
            .ok_or(ChainError::Malformed { line })?;
        rest = tail;
        if current.is_empty() || current.contains('\r') {
            return Err(ChainError::Malformed { line });
        }
        let entry: Entry<'_> =
            serde_json::from_str(current).map_err(|_| ChainError::Malformed { line })?;
        let prev = ChainLink::from_hex(entry.prev).ok_or(ChainError::Malformed { line })?;
        if entry.seq != state.seq || prev != state.prev {
            return Err(ChainError::BrokenLink { line });
        }
        match (entry.evidence, entry.record, entry.database_head) {
            (Some(evidence), None, None) => {
                let evidence = Evidence::from_json(evidence.get())
                    .map_err(|error| ChainError::Evidence { line, error })?;
                state.append(&evidence)?;
            }
            (None, Some(record), None) => {
                let record = StorageRecord::from_json(record.get())
                    .map_err(|error| ChainError::Record { line, error })?;
                state.append_record(&record)?;
            }
            (None, None, Some(reference)) => {
                if reference.schema_version != DATABASE_HEAD_SCHEMA_VERSION {
                    return Err(ChainError::Malformed { line });
                }
                let reference = DatabaseHead {
                    entries: NonZeroU64::new(reference.entries)
                        .ok_or(ChainError::Malformed { line })?,
                    head: ChainLink::from_hex(reference.head)
                        .ok_or(ChainError::Malformed { line })?,
                };
                state.append_database_head(&reference)?;
            }
            _ => return Err(ChainError::Malformed { line }),
        }
    }
    let summary = state.summary()?;
    if let Some(expected) = expected_head
        && *expected != summary.head.head
    {
        return Err(ChainError::HeadMismatch {
            actual: summary.head.head,
        });
    }
    if let Some(expected) = expected_database_head {
        let JournalKind::Tenant {
            database_head: Some(reference),
        } = summary.kind
        else {
            return Err(ChainError::DatabaseHeadMismatch);
        };
        if reference.head != expected.head
            || expected
                .entries
                .is_some_and(|entries| entries != reference.entries)
        {
            return Err(ChainError::DatabaseHeadMismatch);
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EvidenceAttesterKey;
    use crate::storage_record::tests::sample_record;

    const SET_03_CHAIN: &str = include_str!(
        "../../../examples/claude-code-hook/evidence/03-bundle-demo-reproducible/journal-chain.jsonl"
    );
    const SET_03_PIN: &str = include_str!(
        "../../../examples/claude-code-hook/evidence/03-bundle-demo-reproducible/attester-public-key.hex"
    );

    fn set_03_pin() -> VerifiedPublicKey {
        VerifiedPublicKey::from_bytes(&hex::decode(SET_03_PIN.trim()).unwrap()).unwrap()
    }

    fn database_chain(attester: &EvidenceAttesterKey, records: usize) -> (String, ChainHead) {
        let pin = attester.public_key().unwrap();
        let mut exporter = ChainExporter::new(&pin);
        for _ in 0..records {
            exporter.push_record(&sample_record(attester)).unwrap();
        }
        exporter.finish().unwrap()
    }

    #[test]
    fn old_receipt_chains_verify_unchanged() {
        let summary = verify_journal(SET_03_CHAIN, &set_03_pin(), None, None, None).unwrap();
        assert_eq!(
            summary.kind,
            JournalKind::Tenant {
                database_head: None
            }
        );
        assert_eq!(
            verify_chain(SET_03_CHAIN, &set_03_pin(), None, None).unwrap(),
            summary.head
        );
    }

    #[test]
    fn database_chain_verifies_and_detects_altered_or_removed_records() {
        let attester = EvidenceAttesterKey::from_secret_bytes(&[7; 32]);
        let pin = attester.public_key().unwrap();
        let (text, head) = database_chain(&attester, 3);
        let summary = verify_journal(&text, &pin, None, Some(&head.head), None).unwrap();
        assert_eq!(summary.kind, JournalKind::Database);
        assert_eq!(summary.head, head);

        // Altered record: its signature no longer verifies.
        let altered = text.replacen("\"recorded_by\":\"mig\"", "\"recorded_by\":\"xyz\"", 1);
        assert!(matches!(
            verify_journal(&altered, &pin, None, None, None),
            Err(ChainError::Record { line: 0, .. })
        ));
        // Removed from the middle: the next link breaks.
        let lines: Vec<&str> = text.lines().collect();
        let removed = format!("{}\n{}\n", lines[0], lines[2]);
        assert!(matches!(
            verify_journal(&removed, &pin, None, None, None),
            Err(ChainError::BrokenLink { line: 1 })
        ));
        // Another key: refused.
        let other = EvidenceAttesterKey::from_secret_bytes(&[8; 32])
            .public_key()
            .unwrap();
        assert!(verify_journal(&text, &other, None, None, None).is_err());
    }

    #[test]
    fn record_lines_have_their_own_domain_and_kinds_do_not_mix() {
        let attester = EvidenceAttesterKey::from_secret_bytes(&[7; 32]);
        let pin = attester.public_key().unwrap();
        let record = sample_record(&attester);
        // The record link differs from what the receipt link would be over
        // the same values.
        let receipt_style = {
            let mut hasher = Sha256::new();
            hasher.update(LINK_DOMAIN);
            hasher.update(0u64.to_be_bytes());
            hasher.update(ChainLink::GENESIS.to_hex().as_bytes());
            hasher.update(record.record_hash.as_bytes());
            hasher.update(record.signature.as_bytes());
            ChainLink(hasher.finalize().into())
        };
        assert_ne!(record_link(0, &ChainLink::GENESIS, &record), receipt_style);
        // A record presented as a receipt does not parse as one.
        let json = record.to_json().unwrap();
        let as_evidence = format!(
            "{{\"seq\":0,\"prev\":\"{}\",\"evidence\":{json}}}\n",
            ChainLink::GENESIS
        );
        assert!(matches!(
            verify_journal(&as_evidence, &pin, None, None, None),
            Err(ChainError::Evidence { line: 0, .. })
        ));
        // A line with both fields is malformed.
        let both = format!(
            "{{\"seq\":0,\"prev\":\"{}\",\"record\":{json},\"evidence\":{json}}}\n",
            ChainLink::GENESIS
        );
        assert!(matches!(
            verify_journal(&both, &pin, None, None, None),
            Err(ChainError::Malformed { line: 0 })
        ));
        // A receipt after a record is refused.
        let (records, _) = database_chain(&attester, 1);
        let receipt_line = SET_03_CHAIN.lines().next().unwrap();
        let receipt_value: serde_json::Value = serde_json::from_str(receipt_line).unwrap();
        let mixed = format!(
            "{records}{{\"seq\":1,\"prev\":\"{}\",\"evidence\":{}}}\n",
            verify_chain(&records, &pin, None, None).unwrap().head,
            receipt_value["evidence"]
        );
        assert!(matches!(
            verify_journal(&mixed, &pin, None, None, None),
            Err(ChainError::MixedKinds { line: 1 })
        ));
    }

    #[test]
    fn tenant_chain_reference_to_the_database_head_verifies_and_mismatches_fail() {
        let attester = EvidenceAttesterKey::from_secret_bytes(&[7; 32]);
        let (_, database) = database_chain(&attester, 2);
        let pin = set_03_pin();
        let receipts: Vec<Evidence> = SET_03_CHAIN
            .lines()
            .map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                Evidence::from_json(&value["evidence"].to_string()).unwrap()
            })
            .collect();
        let mut exporter = ChainExporter::new(&pin);
        exporter.push_database_head(&database.into()).unwrap();
        for receipt in &receipts {
            exporter.push(receipt).unwrap();
        }
        let (tenant, head) = exporter.finish().unwrap();
        let expected = ExpectedDatabaseHead {
            head: database.head,
            entries: Some(database.entries),
        };
        let summary =
            verify_journal(&tenant, &pin, None, Some(&head.head), Some(&expected)).unwrap();
        assert_eq!(
            summary.kind,
            JournalKind::Tenant {
                database_head: Some(database.into())
            }
        );
        // Another database head, or another entry count, fails.
        let (_, other) = database_chain(&attester, 2);
        for wrong in [
            ExpectedDatabaseHead {
                head: other.head,
                entries: None,
            },
            ExpectedDatabaseHead {
                head: database.head,
                entries: NonZeroU64::new(database.entries.get() + 1),
            },
        ] {
            assert!(matches!(
                verify_journal(&tenant, &pin, None, None, Some(&wrong)),
                Err(ChainError::DatabaseHeadMismatch)
            ));
        }
        // An old chain without a reference fails when one is required.
        assert!(matches!(
            verify_journal(SET_03_CHAIN, &pin, None, None, Some(&expected)),
            Err(ChainError::DatabaseHeadMismatch)
        ));
        // Editing the reference breaks the link of the next line.
        let edited = tenant.replacen(&database.head.to_hex(), &other.head.to_hex(), 1);
        assert!(matches!(
            verify_journal(&edited, &pin, None, None, None),
            Err(ChainError::BrokenLink { line: 1 })
        ));
        // A reference that is not the first line is refused.
        let mut late = ChainExporter::new(&pin);
        late.push(&receipts[0]).unwrap();
        assert!(matches!(
            late.push_database_head(&database.into()),
            Err(ChainError::MixedKinds { line: 1 })
        ));
    }
}
