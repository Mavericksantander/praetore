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

use crate::{Evidence, Policy, PraetoreError, VerifiedPublicKey};
use serde::Deserialize;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt, num::NonZeroU64};
use uuid::Uuid;

/// Domain separation prefix of every link (25 bytes, NUL included).
pub const LINK_DOMAIN: &[u8; 25] = b"PRAETORE_JOURNAL_LINK_V1\0";
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
}

impl ChainError {
    /// Stable machine-readable code, used by the CLIs.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty | Self::BrokenLink { .. } | Self::DuplicateEvidenceId { .. } => {
                "JOURNAL_CHAIN_FAIL"
            }
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

/// Shared state of producer and verifier: position, last link, seen ids.
struct ChainState<'k> {
    attester: &'k VerifiedPublicKey,
    policy: Option<&'k Policy>,
    seq: u64,
    prev: ChainLink,
    seen: HashSet<Uuid>,
}

impl<'k> ChainState<'k> {
    fn new(attester: &'k VerifiedPublicKey, policy: Option<&'k Policy>) -> Self {
        Self {
            attester,
            policy,
            seq: 0,
            prev: ChainLink::GENESIS,
            seen: HashSet::new(),
        }
    }

    /// Checks one receipt at the current position and advances the chain.
    fn append(&mut self, evidence: &Evidence) -> Result<(), ChainError> {
        let line = self.seq;
        if self.seq as usize >= MAX_CHAIN_ENTRIES {
            return Err(ChainError::TooLarge);
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
        Ok(())
    }

    fn head(&self) -> Result<ChainHead, ChainError> {
        Ok(ChainHead {
            entries: NonZeroU64::new(self.seq).ok_or(ChainError::Empty)?,
            head: self.prev,
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
    #[serde(borrow)]
    evidence: &'a RawValue,
}

/// Verifies a JSONL export. Fail-closed: the first problem ends verification.
///
/// Without `expected_head`, a truncated, re-ordered or re-linked subset of
/// validly signed receipts still verifies (see the module docs).
pub fn verify_chain(
    text: &str,
    attester: &VerifiedPublicKey,
    policy: Option<&Policy>,
    expected_head: Option<&ChainLink>,
) -> Result<ChainHead, ChainError> {
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
        let evidence = Evidence::from_json(entry.evidence.get())
            .map_err(|error| ChainError::Evidence { line, error })?;
        state.append(&evidence)?;
    }
    let head = state.head()?;
    match expected_head {
        Some(expected) if *expected != head.head => {
            Err(ChainError::HeadMismatch { actual: head.head })
        }
        _ => Ok(head),
    }
}
