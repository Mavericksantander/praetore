//! G1: post-hoc ingestion of safety actions (SAF-09.5).
//!
//! An executor of an AI-enabled system runs a safety action (for example
//! `safety:halt`) without waiting for PRÆTORE. Afterwards, it may report the
//! action to an ingestion process that runs apart from the decision path,
//! with its own process, database role and key. This module holds the parts
//! that the ingester, the exporter and the verifier share, so their rules
//! cannot diverge:
//!
//! * [`SafetyEvent`]: what a source (an executor) reports, signed by the
//!   source's own key ([`SafetySourceKey`]) under [`SAFETY_EVENT_DOMAIN`].
//!   `post_hoc` is always `true`: the event says the action already ran.
//! * [`SafetyRecord`]: what the ingester stores, signed by the ingestion key
//!   ([`SafetyIngestKey`]) under [`SAFETY_RECORD_DOMAIN`]. Records form one
//!   hash chain per source (`chain`, `chain_seq`, `prev_record_hash`, all
//!   inside the signed payload). Input that does not verify is stored too,
//!   as a `rejected` record on the [`UNATTRIBUTED_CHAIN`]; nothing is dropped
//!   silently.
//! * [`SafetyIngestor`]: the deterministic state machine that turns one
//!   input message into the records to store (a loss record for a gap in
//!   `source_seq`, then the event record).
//! * [`verify_safety_chain`]: the verifier of an exported chain (signatures,
//!   hash chain, `source_seq` continuity, an expected head and, with source
//!   pins, the event signatures).
//!
//! Nothing here is on the decision path: no engine, gateway, gate or hook
//! reads a safety record, and an ingestion failure never delays or
//! conditions the executor (the client in `praetore-safety-client` never
//! blocks). What a record shows, and what it does not, is in
//! `docs/proposals/safety-ingestion-jsonl.md` and `docs/threat-model.md`.

use std::collections::{BTreeMap, HashMap, HashSet};

use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    canonical::{
        MAX_JSON_VALUE_BYTES, MAX_SAFE_INTEGER, canonical_json, decode_lower_hex,
        is_canonical_signature_hex, parse_json_strict,
    },
    identity::VerifiedPublicKey,
    safety_namespace::{
        NamespaceMembership, SafetyActionName, SafetyNameError, SafetyNamespaceError,
        SafetyNamespaceManifest, ensure_distinct_keys,
    },
};

/// Signature domain of a [`SafetyEvent`] (25 bytes, NUL included).
pub const SAFETY_EVENT_DOMAIN: &[u8] = b"PRAETORE_SAFETY_EVENT_V1\0";
/// Signature and hash domain of a [`SafetyRecord`] (26 bytes, NUL included).
pub const SAFETY_RECORD_DOMAIN: &[u8] = b"PRAETORE_SAFETY_RECORD_V1\0";
/// Domain of a source key id:
/// `hex(SHA-256(SAFETY_SOURCE_KEY_ID_DOMAIN || public key))`.
pub const SAFETY_SOURCE_KEY_ID_DOMAIN: &[u8] = b"PRAETORE_SAFETY_SOURCE_KEY_V1\0ed25519\0";
/// Domain of an ingestion key id:
/// `hex(SHA-256(SAFETY_INGEST_KEY_ID_DOMAIN || public key))`.
pub const SAFETY_INGEST_KEY_ID_DOMAIN: &[u8] = b"PRAETORE_SAFETY_INGEST_KEY_V1\0ed25519\0";

/// The only event and record schema version this crate writes and accepts.
pub const SAFETY_INGEST_SCHEMA_VERSION: u8 = 1;
/// Largest message (one event) the ingester reads.
pub const MAX_SAFETY_EVENT_BYTES: usize = 8 * 1024;
/// Longest source id, in bytes.
pub const MAX_SOURCE_ID_BYTES: usize = 64;
/// Most entries in an event's `params`.
pub const MAX_EVENT_PARAMS: usize = 16;
/// Longest `params` key, in bytes.
pub const MAX_PARAM_KEY_BYTES: usize = 64;
/// Longest `params` string value, in bytes.
pub const MAX_PARAM_STRING_BYTES: usize = 256;
/// How many bytes of a rejected input a record keeps (escaped).
pub const MAX_RAW_PREFIX_BYTES: usize = 512;
/// How many bytes of an error text a record keeps (escaped).
pub const MAX_DETAIL_INPUT_BYTES: usize = 256;
/// Largest record (its canonical JSON).
pub const MAX_SAFETY_RECORD_BYTES: usize = MAX_JSON_VALUE_BYTES;
/// Largest exported chain file.
pub const MAX_SAFETY_CHAIN_BYTES: usize = 64 * 1024 * 1024;
/// Most records in one exported chain file.
pub const MAX_SAFETY_CHAIN_ENTRIES: usize = 200_000;
/// Most pinned sources.
pub const MAX_SOURCE_PINS: usize = 256;
/// Default of [`IngestorConfig::max_seq_jump`].
pub const DEFAULT_MAX_SEQ_JUMP: u64 = 1_000_000;
/// Default of [`IngestorConfig::max_clock_skew_seconds`].
pub const DEFAULT_MAX_CLOCK_SKEW_SECONDS: u64 = 300;

/// The chain of everything that cannot be attributed to a pinned source:
/// `rejected` records and losses inside the ingester (a full queue, the
/// database unavailable). It is not a valid source id (it starts with `_`).
pub const UNATTRIBUTED_CHAIN: &str = "_unattributed";

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Whether `id` is a valid source id: 1 to 64 bytes of `a-z`, `0-9`, `.`,
/// `_` and `-`, starting with a letter or a digit.
pub fn is_valid_source_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SOURCE_ID_BYTES
        && id
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Whether `chain` names a chain: a source id or [`UNATTRIBUTED_CHAIN`].
pub fn is_valid_chain(chain: &str) -> bool {
    chain == UNATTRIBUTED_CHAIN || is_valid_source_id(chain)
}

fn key_id_with(domain: &[u8], public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(public_key);
    hex::encode(hasher.finalize())
}

/// The key id of a source public key.
pub fn safety_source_key_id(public_key: &VerifiedPublicKey) -> String {
    key_id_with(SAFETY_SOURCE_KEY_ID_DOMAIN, &public_key.as_bytes())
}

/// The key id of an ingestion public key.
pub fn safety_ingest_key_id(public_key: &VerifiedPublicKey) -> String {
    key_id_with(SAFETY_INGEST_KEY_ID_DOMAIN, &public_key.as_bytes())
}

fn sign_with(signing_key: &SigningKey, domain: &[u8], payload: &[u8]) -> [u8; 64] {
    let mut message = Vec::with_capacity(domain.len() + payload.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(payload);
    signing_key.sign(&message).to_bytes()
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && decode_lower_hex(text).is_some()
}

fn sha256_hex(domain: &[u8], payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

fn is_utc_rfc3339(text: &str) -> bool {
    OffsetDateTime::parse(text, &Rfc3339).is_ok_and(|instant| instant.offset() == UtcOffset::UTC)
}

fn format_utc(instant: OffsetDateTime) -> Option<String> {
    instant.to_offset(UtcOffset::UTC).format(&Rfc3339).ok()
}

/// `bytes` as printable ASCII: printable characters and spaces stay, a
/// backslash becomes `\\` and every other byte `\xNN`. Unambiguous, and safe
/// to show: no control, invisible or non-ASCII character survives.
pub fn escape_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b' '..=b'~' => out.push(byte as char),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out
}

fn is_escaped_text(text: &str, max_input: usize) -> bool {
    text.len() <= max_input * 4 && text.bytes().all(|b| matches!(b, b' '..=b'~'))
}

fn bounded_detail(text: &str) -> String {
    let bytes = text.as_bytes();
    let cut = bytes.len().min(MAX_DETAIL_INPUT_BYTES);
    let mut out = escape_bytes(&bytes[..cut]);
    if cut < bytes.len() {
        out.push_str("...");
    }
    out
}

// ---------------------------------------------------------------------------
// Keys.

macro_rules! signing_role {
    ($(#[$doc:meta])* $name:ident, $key_id:ident) => {
        $(#[$doc])*
        pub struct $name {
            signing_key: SigningKey,
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("key_id", &self.key_id())
                    .finish_non_exhaustive()
            }
        }

        impl $name {
            pub fn generate() -> Self {
                Self {
                    signing_key: SigningKey::generate(&mut OsRng),
                }
            }

            pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
                Self {
                    signing_key: SigningKey::from_bytes(secret),
                }
            }

            /// Fails only for a weak public key.
            pub fn public_key(&self) -> crate::Result<VerifiedPublicKey> {
                VerifiedPublicKey::from_bytes(&self.signing_key.verifying_key().to_bytes())
            }

            pub fn key_id(&self) -> String {
                key_id_with($key_id, self.signing_key.verifying_key().as_bytes())
            }
        }
    };
}

signing_role!(
    /// The key of one source (an executor) of safety events. Held by the
    /// executor; the ingester pins its public key per `source_id`.
    SafetySourceKey,
    SAFETY_SOURCE_KEY_ID_DOMAIN
);

signing_role!(
    /// The key of the ingestion process. It signs every [`SafetyRecord`]. A
    /// role of its own: not the evidence attester key, not the namespace
    /// key and not a source key ([`SafetyIngestor::new`] refuses a shared
    /// key without a flag).
    SafetyIngestKey,
    SAFETY_INGEST_KEY_ID_DOMAIN
);

// ---------------------------------------------------------------------------
// Events.

/// One value of an event's `params`: a string (at most
/// [`MAX_PARAM_STRING_BYTES`]), a safe integer or a boolean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ParamValue {
    Bool(bool),
    Integer(i64),
    String(String),
}

/// What a source signs and sends. Build one with [`SafetySourceKey::sign_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyEventDraft {
    pub source_id: String,
    /// Monotonic per source, starting at 1. The ingester records a gap as a
    /// signed loss record.
    pub source_seq: u64,
    /// The raw action name. It is recorded even when it is not a valid
    /// safety name (`invalid_name`) or not declared (`undeclared`).
    pub action: String,
    /// When the action ran, by the source's clock.
    pub occurred_at: OffsetDateTime,
    pub params: BTreeMap<String, ParamValue>,
}

/// A signed post-hoc safety event (schema version 1).
///
/// Its JSON object has exactly `schema_version` (1), `source_id`,
/// `source_key_id`, `source_seq`, `action`, `occurred_at` (RFC 3339 UTC),
/// `params` (optional, never empty), `post_hoc` (`true`) and `signature`:
/// `hex(Ed25519(SAFETY_EVENT_DOMAIN || canonical JSON of every other
/// field))` by the source key. The wire encoding may be any JSON encoding of
/// that object; the signature and the event hash cover the canonical one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyEvent {
    schema_version: u8,
    source_id: String,
    source_key_id: String,
    source_seq: u64,
    action: String,
    occurred_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    params: Option<BTreeMap<String, ParamValue>>,
    post_hoc: bool,
    signature: String,
}

#[derive(Serialize)]
struct EventSigningPayload<'a> {
    schema_version: u8,
    source_id: &'a str,
    source_key_id: &'a str,
    source_seq: u64,
    action: &'a str,
    occurred_at: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<&'a BTreeMap<String, ParamValue>>,
    post_hoc: bool,
}

/// Why an input is a `rejected` record instead of an event record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    /// Larger than [`MAX_SAFETY_EVENT_BYTES`].
    TooLarge,
    /// Not UTF-8, not strict JSON, or not an event of the documented shape.
    Malformed,
    /// `post_hoc` is not `true`.
    NotPostHoc,
    /// `source_id` is not pinned.
    UnknownSource,
    /// `source_key_id` is not the id of the pinned key of `source_id`.
    KeyMismatch,
    /// The signature does not verify under the pinned key.
    SignatureInvalid,
    /// A verified event whose `source_seq` is more than
    /// [`IngestorConfig::max_seq_jump`] above its chain's high-water mark.
    /// It is recorded on the unattributed chain, so it cannot move the
    /// source chain's high-water mark.
    SeqJumpTooLarge,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::Malformed => "malformed",
            Self::NotPostHoc => "not_post_hoc",
            Self::UnknownSource => "unknown_source",
            Self::KeyMismatch => "key_mismatch",
            Self::SignatureInvalid => "signature_invalid",
            Self::SeqJumpTooLarge => "seq_jump_too_large",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [
            Self::TooLarge,
            Self::Malformed,
            Self::NotPostHoc,
            Self::UnknownSource,
            Self::KeyMismatch,
            Self::SignatureInvalid,
            Self::SeqJumpTooLarge,
        ]
        .into_iter()
        .find(|reason| reason.as_str() == text)
    }
}

/// An input that is not a verified event: the reason and an error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRejection {
    pub reason: RejectReason,
    pub detail: String,
}

impl EventRejection {
    fn new(reason: RejectReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for EventRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason.as_str(), self.detail)
    }
}

impl SafetySourceKey {
    /// Signs `draft`. Fails when a field is out of bounds (an invalid
    /// source id, `source_seq` 0 or above 2^53 - 1, an unbounded parameter)
    /// or the event would be larger than [`MAX_SAFETY_EVENT_BYTES`]. The
    /// action name is not checked: the ingester records whatever it is.
    pub fn sign_event(&self, draft: SafetyEventDraft) -> Result<SafetyEvent, EventRejection> {
        let occurred_at = format_utc(draft.occurred_at)
            .ok_or_else(|| EventRejection::new(RejectReason::Malformed, "occurred_at"))?;
        let mut event = SafetyEvent {
            schema_version: SAFETY_INGEST_SCHEMA_VERSION,
            source_id: draft.source_id,
            source_key_id: self.key_id(),
            source_seq: draft.source_seq,
            action: draft.action,
            occurred_at,
            params: (!draft.params.is_empty()).then_some(draft.params),
            post_hoc: true,
            signature: String::new(),
        };
        let payload = event.signing_payload()?;
        event.signature = hex::encode(sign_with(&self.signing_key, SAFETY_EVENT_DOMAIN, &payload));
        event.validate()?;
        if event.to_wire()?.len() > MAX_SAFETY_EVENT_BYTES {
            return Err(EventRejection::new(
                RejectReason::TooLarge,
                format!("event exceeds {MAX_SAFETY_EVENT_BYTES} bytes"),
            ));
        }
        Ok(event)
    }
}

impl SafetyEvent {
    /// Parses one wire message: at most [`MAX_SAFETY_EVENT_BYTES`], UTF-8,
    /// strict JSON (no duplicate keys), exactly the documented fields, each
    /// in bounds, and `post_hoc: true`. Does not check the signature; see
    /// [`Self::verify`].
    pub fn parse(input: &[u8]) -> Result<Self, EventRejection> {
        if input.len() > MAX_SAFETY_EVENT_BYTES {
            return Err(EventRejection::new(
                RejectReason::TooLarge,
                format!(
                    "{} bytes; the maximum is {MAX_SAFETY_EVENT_BYTES}",
                    input.len()
                ),
            ));
        }
        let malformed = |detail: String| EventRejection::new(RejectReason::Malformed, detail);
        let text = std::str::from_utf8(input).map_err(|_| malformed("not UTF-8".into()))?;
        let value = parse_json_strict(text).map_err(|error| malformed(error.to_string()))?;
        let event: Self =
            serde_json::from_value(value).map_err(|error| malformed(error.to_string()))?;
        event.validate()?;
        Ok(event)
    }

    fn validate(&self) -> Result<(), EventRejection> {
        let malformed = |field: &str| {
            EventRejection::new(RejectReason::Malformed, format!("invalid field `{field}`"))
        };
        if self.schema_version != SAFETY_INGEST_SCHEMA_VERSION {
            return Err(malformed("schema_version"));
        }
        if !is_valid_source_id(&self.source_id) {
            return Err(malformed("source_id"));
        }
        if !is_lower_hex(&self.source_key_id, 64) {
            return Err(malformed("source_key_id"));
        }
        if self.source_seq == 0 || self.source_seq > MAX_SAFE_INTEGER {
            return Err(malformed("source_seq"));
        }
        if !is_utc_rfc3339(&self.occurred_at) {
            return Err(malformed("occurred_at"));
        }
        if let Some(params) = &self.params {
            if params.is_empty() || params.len() > MAX_EVENT_PARAMS {
                return Err(malformed("params"));
            }
            for (key, value) in params {
                let key_ok = !key.is_empty()
                    && key.len() <= MAX_PARAM_KEY_BYTES
                    && key
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
                let value_ok = match value {
                    ParamValue::Bool(_) => true,
                    ParamValue::Integer(n) => n.unsigned_abs() <= MAX_SAFE_INTEGER,
                    ParamValue::String(s) => s.len() <= MAX_PARAM_STRING_BYTES,
                };
                if !key_ok || !value_ok {
                    return Err(malformed("params"));
                }
            }
        }
        if !self.post_hoc {
            return Err(EventRejection::new(
                RejectReason::NotPostHoc,
                "post_hoc must be true: the ingester records actions that already ran",
            ));
        }
        if !is_canonical_signature_hex(&self.signature) {
            return Err(malformed("signature"));
        }
        Ok(())
    }

    fn signing_payload(&self) -> Result<Vec<u8>, EventRejection> {
        canonical_json(&EventSigningPayload {
            schema_version: self.schema_version,
            source_id: &self.source_id,
            source_key_id: &self.source_key_id,
            source_seq: self.source_seq,
            action: &self.action,
            occurred_at: &self.occurred_at,
            params: self.params.as_ref(),
            post_hoc: self.post_hoc,
        })
        .map_err(|error| EventRejection::new(RejectReason::Malformed, error.to_string()))
    }

    /// `hex(SHA-256(SAFETY_EVENT_DOMAIN || signed payload))`: equal for two
    /// encodings of the same event, different for any other content.
    pub fn event_hash(&self) -> String {
        // The payload of a parsed or signed event always encodes.
        let payload = self.signing_payload().unwrap_or_default();
        sha256_hex(SAFETY_EVENT_DOMAIN, &payload)
    }

    /// Checks `source_key_id` against `pin` and the signature under
    /// [`SAFETY_EVENT_DOMAIN`] (strict Ed25519).
    pub fn verify(&self, pin: &VerifiedPublicKey) -> Result<(), EventRejection> {
        if self.source_key_id != safety_source_key_id(pin) {
            return Err(EventRejection::new(
                RejectReason::KeyMismatch,
                "source_key_id is not the id of the pinned source key",
            ));
        }
        let signature = decode_lower_hex(&self.signature)
            .ok_or_else(|| EventRejection::new(RejectReason::SignatureInvalid, "bad signature"))?;
        pin.verify_domain_message(SAFETY_EVENT_DOMAIN, &self.signing_payload()?, &signature)
            .map_err(|_| {
                EventRejection::new(
                    RejectReason::SignatureInvalid,
                    "signature does not verify under the pinned source key",
                )
            })
    }

    /// The canonical JSON, as a client sends it.
    pub fn to_wire(&self) -> Result<Vec<u8>, EventRejection> {
        canonical_json(self)
            .map_err(|error| EventRejection::new(RejectReason::Malformed, error.to_string()))
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn source_key_id(&self) -> &str {
        &self.source_key_id
    }

    pub fn source_seq(&self) -> u64 {
        self.source_seq
    }

    /// The raw action name, exactly as sent.
    pub fn action(&self) -> &str {
        &self.action
    }

    pub fn occurred_at(&self) -> &str {
        &self.occurred_at
    }

    pub fn params(&self) -> Option<&BTreeMap<String, ParamValue>> {
        self.params.as_ref()
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }
}

// ---------------------------------------------------------------------------
// Source pins.

/// The pinned public key of each source, by `source_id`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourcePins {
    pins: BTreeMap<String, VerifiedPublicKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePinLine {
    source_id: String,
    public_key: String,
}

impl SourcePins {
    /// Parses a pin file: one `{"source_id":"…","public_key":"<64 hex>"}`
    /// object per line, at most [`MAX_SOURCE_PINS`] lines, no repeated
    /// source id or key. Blank lines are not allowed.
    pub fn from_jsonl(text: &str) -> Result<Self, String> {
        let mut pins = Self::default();
        for (index, line) in text.lines().enumerate() {
            let line_no = index + 1;
            let value =
                parse_json_strict(line).map_err(|error| format!("line {line_no}: {error}"))?;
            let pin: SourcePinLine = serde_json::from_value(value)
                .map_err(|error| format!("line {line_no}: {error}"))?;
            if !is_lower_hex(&pin.public_key, 64) {
                return Err(format!(
                    "line {line_no}: public_key must be 64 lowercase hex characters"
                ));
            }
            let key =
                VerifiedPublicKey::from_bytes(&hex::decode(&pin.public_key).unwrap_or_default())
                    .map_err(|_| {
                        format!("line {line_no}: public_key is not a valid Ed25519 key")
                    })?;
            pins.insert(&pin.source_id, key)
                .map_err(|error| format!("line {line_no}: {error}"))?;
        }
        if pins.pins.is_empty() {
            return Err("no source is pinned".into());
        }
        Ok(pins)
    }

    /// Adds a pin. Refuses an invalid source id, a repeated source id or
    /// key, and more than [`MAX_SOURCE_PINS`] pins.
    pub fn insert(&mut self, source_id: &str, key: VerifiedPublicKey) -> Result<(), String> {
        if !is_valid_source_id(source_id) {
            return Err(format!(
                "source_id {:?} is invalid (1 to 64 of a-z 0-9 . _ -, starting with a letter or a digit)",
                escape_bytes(source_id.as_bytes())
            ));
        }
        if self.pins.contains_key(source_id) {
            return Err(format!("source_id {source_id} is pinned twice"));
        }
        if self.pins.values().any(|pinned| *pinned == key) {
            return Err(format!(
                "the key of {source_id} is already pinned for another source"
            ));
        }
        if self.pins.len() == MAX_SOURCE_PINS {
            return Err(format!("at most {MAX_SOURCE_PINS} sources"));
        }
        self.pins.insert(source_id.to_owned(), key);
        Ok(())
    }

    pub fn get(&self, source_id: &str) -> Option<&VerifiedPublicKey> {
        self.pins.get(source_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &VerifiedPublicKey)> {
        self.pins.iter().map(|(id, key)| (id.as_str(), key))
    }

    pub fn len(&self) -> usize {
        self.pins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Records.

/// What a record says about its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyRecordStatus {
    /// A verified event, next in `source_seq`, whose name the manifest
    /// declares.
    Accepted,
    /// A verified event, next in `source_seq`, with a valid safety name the
    /// manifest does not declare.
    Undeclared,
    /// A verified event, next in `source_seq`, whose action fails
    /// [`SafetyActionName::parse`] (for example `safety:`, `safety:_x`, a
    /// name over 128 bytes, a non-ASCII character, or no `safety:` prefix).
    InvalidName,
    /// A verified event whose `source_seq` was already recorded with the
    /// same event hash (a resend or a replay).
    Duplicate,
    /// A verified event whose `source_seq` was already recorded with a
    /// different event hash.
    Conflict,
    /// A verified event whose `source_seq` was earlier recorded as lost.
    Late,
    /// An input that did not verify (on [`UNATTRIBUTED_CHAIN`]).
    Rejected,
    /// A signed statement that events were lost: a `source_seq` gap, or
    /// messages dropped inside the ingester.
    Loss,
}

impl SafetyRecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Undeclared => "undeclared",
            Self::InvalidName => "invalid_name",
            Self::Duplicate => "duplicate",
            Self::Conflict => "conflict",
            Self::Late => "late",
            Self::Rejected => "rejected",
            Self::Loss => "loss",
        }
    }

    /// Every status, for storage constraints and tests.
    pub const ALL: [Self; 8] = [
        Self::Accepted,
        Self::Undeclared,
        Self::InvalidName,
        Self::Duplicate,
        Self::Conflict,
        Self::Late,
        Self::Rejected,
        Self::Loss,
    ];

    /// Whether the record carries a verified event.
    pub fn has_event(self) -> bool {
        !matches!(self, Self::Rejected | Self::Loss)
    }

    /// Whether the record is the first event of its `source_seq`
    /// (in order, or late).
    pub fn is_first_event(self) -> bool {
        matches!(
            self,
            Self::Accepted | Self::Undeclared | Self::InvalidName | Self::Late
        )
    }
}

/// How the action name of a verified event was classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameClass {
    Declared,
    Undeclared,
    InvalidName,
}

/// The code of a [`SafetyNameError`] in a record's `reason`.
pub fn safety_name_error_code(error: &SafetyNameError) -> &'static str {
    match error {
        SafetyNameError::Empty => "empty",
        SafetyNameError::TooLong { .. } => "too_long",
        SafetyNameError::NotPrintableAscii { .. } => "not_printable_ascii",
        SafetyNameError::MissingPrefix { .. } => "missing_prefix",
        SafetyNameError::InvalidNameStart { .. } => "invalid_name_start",
    }
}

const NAME_ERROR_CODES: [&str; 5] = [
    "empty",
    "too_long",
    "not_printable_ascii",
    "missing_prefix",
    "invalid_name_start",
];

/// Why events were lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LossReason {
    /// `source_seq` jumped: the events `lost_from..=lost_to` never arrived.
    SourceSeqGap,
    /// The ingester's bounded queue was full: `dropped` messages were not
    /// read (unattributed).
    QueueOverflow,
    /// The database was unavailable: `dropped` messages could not be stored
    /// (unattributed).
    StorageError,
}

impl LossReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceSeqGap => "source_seq_gap",
            Self::QueueOverflow => "queue_overflow",
            Self::StorageError => "storage_error",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [Self::SourceSeqGap, Self::QueueOverflow, Self::StorageError]
            .into_iter()
            .find(|reason| reason.as_str() == text)
    }
}

/// The bounded, escaped copy of a rejected input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawInput {
    /// The first [`MAX_RAW_PREFIX_BYTES`] bytes, through [`escape_bytes`].
    pub escaped: String,
    /// The input length in bytes.
    pub len: u64,
    /// `hex(SHA-256(input))` of the whole input.
    pub sha256: String,
    /// Whether `escaped` holds only a prefix.
    pub truncated: bool,
}

impl RawInput {
    pub fn of(input: &[u8]) -> Self {
        let cut = input.len().min(MAX_RAW_PREFIX_BYTES);
        Self {
            escaped: escape_bytes(&input[..cut]),
            len: input.len() as u64,
            sha256: hex::encode(Sha256::digest(input)),
            truncated: cut < input.len(),
        }
    }
}

/// What is signed: every field of a [`SafetyRecord`] except `record_hash`
/// and `signature`. Absent options are omitted from the JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyRecordPayload {
    pub schema_version: u8,
    pub record_id: Uuid,
    pub tenant_id: Uuid,
    pub chain: String,
    /// Position in the chain, from 0.
    pub chain_seq: u64,
    /// `record_hash` of the record at `chain_seq - 1`; 64 zeros at 0.
    pub prev_record_hash: String,
    /// RFC 3339 UTC, by the ingester's clock.
    pub recorded_at: String,
    pub status: SafetyRecordStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<SafetyEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_class: Option<NameClass>,
    /// `policy_digest` of the namespace manifest the name was classified
    /// against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_policy_digest: Option<String>,
    /// For `duplicate` and `conflict`: the record of the first event with
    /// this `source_seq`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_record_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost_from: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost_to: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<RawInput>,
    /// For a record with an event: `occurred_at - recorded_at` in seconds,
    /// present only when its magnitude is above the ingester's
    /// `max_clock_skew_seconds` (an event dated in the future or long ago
    /// by the source's clock).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_skew_seconds: Option<i64>,
    /// The ingestion key id.
    pub key_id: String,
}

/// A signed safety record: [`SafetyRecordPayload`] plus
/// `record_hash = hex(SHA-256(SAFETY_RECORD_DOMAIN || payload))` and
/// `signature = hex(Ed25519(SAFETY_RECORD_DOMAIN || payload))`, where
/// `payload` is the canonical JSON of the payload. Stored and exported as
/// the canonical JSON of the whole record; any other encoding is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyRecord {
    payload: SafetyRecordPayload,
    record_hash: String,
    signature: String,
}

/// Why a record was not built, parsed or verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SafetyRecordError {
    #[error("safety record: {0}")]
    Invalid(String),
    #[error("safety record is not in its canonical encoding")]
    NotCanonical,
    #[error("safety record is signed by ingestion key {0}, not by a pinned key")]
    UnpinnedKey(String),
    #[error("safety record: record_hash does not match")]
    HashMismatch,
    #[error("safety record: signature does not verify")]
    SignatureInvalid,
}

fn invalid(message: impl Into<String>) -> SafetyRecordError {
    SafetyRecordError::Invalid(message.into())
}

impl SafetyRecordPayload {
    fn canonical_bytes(&self) -> Result<Vec<u8>, SafetyRecordError> {
        canonical_json(self).map_err(|error| invalid(format!("cannot encode: {error}")))
    }

    /// Checks every field and the fields each status requires; for a record
    /// with an event, also that `event_hash` is the event's hash and that
    /// `name_class` agrees with [`SafetyActionName::parse`].
    pub fn validate(&self) -> Result<(), SafetyRecordError> {
        use SafetyRecordStatus as S;
        if self.schema_version != SAFETY_INGEST_SCHEMA_VERSION {
            return Err(invalid("unsupported schema_version"));
        }
        if !is_valid_chain(&self.chain) {
            return Err(invalid("invalid chain"));
        }
        if self.chain_seq > MAX_SAFE_INTEGER {
            return Err(invalid("chain_seq out of range"));
        }
        if !is_lower_hex(&self.prev_record_hash, 64)
            || (self.chain_seq == 0) != (self.prev_record_hash == GENESIS_HASH)
        {
            return Err(invalid("invalid prev_record_hash"));
        }
        if !is_utc_rfc3339(&self.recorded_at) {
            return Err(invalid("recorded_at is not RFC 3339 UTC"));
        }
        if !is_lower_hex(&self.key_id, 64) {
            return Err(invalid("invalid key_id"));
        }
        if self
            .detail
            .as_ref()
            .is_some_and(|detail| !is_escaped_text(detail, MAX_DETAIL_INPUT_BYTES + 1))
        {
            return Err(invalid("detail is not bounded escaped text"));
        }
        let unattributed = self.chain == UNATTRIBUTED_CHAIN;
        let has = |present: bool, field: &str| -> Result<(), SafetyRecordError> {
            if present {
                Ok(())
            } else {
                Err(invalid(format!(
                    "{} record has a wrong `{field}`",
                    self.status.as_str()
                )))
            }
        };
        if self.status.has_event() {
            let Some(event) = &self.event else {
                return Err(invalid("event record without event"));
            };
            event
                .validate()
                .map_err(|error| invalid(format!("event: {error}")))?;
            has(!unattributed && event.source_id == self.chain, "chain")?;
            has(
                self.event_hash.as_deref() == Some(&event.event_hash()),
                "event_hash",
            )?;
            has(
                self.namespace_policy_digest
                    .as_deref()
                    .is_some_and(|digest| is_lower_hex(digest, 64)),
                "namespace_policy_digest",
            )?;
            has(self.raw.is_none(), "raw")?;
            has(
                self.lost_from.is_none() && self.lost_to.is_none() && self.dropped.is_none(),
                "lost_from",
            )?;
            let class = self
                .name_class
                .ok_or_else(|| invalid("missing name_class"))?;
            match SafetyActionName::parse(&event.action) {
                Ok(_) => {
                    has(class != NameClass::InvalidName, "name_class")?;
                    has(self.reason.is_none(), "reason")?;
                }
                Err(error) => {
                    has(class == NameClass::InvalidName, "name_class")?;
                    has(
                        self.reason.as_deref() == Some(safety_name_error_code(&error)),
                        "reason",
                    )?;
                }
            }
            match self.status {
                S::Accepted => has(class == NameClass::Declared, "name_class")?,
                S::Undeclared => has(class == NameClass::Undeclared, "name_class")?,
                S::InvalidName => has(class == NameClass::InvalidName, "name_class")?,
                _ => {}
            }
            let needs_original = matches!(self.status, S::Duplicate | S::Conflict);
            has(
                self.original_record_hash
                    .as_deref()
                    .map_or(!needs_original, |hash| {
                        needs_original && is_lower_hex(hash, 64)
                    }),
                "original_record_hash",
            )?;
            if let Some(reason) = &self.reason {
                has(NAME_ERROR_CODES.contains(&reason.as_str()), "reason")?;
            }
            has(
                self.clock_skew_seconds
                    .is_none_or(|skew| skew != 0 && skew.unsigned_abs() <= MAX_SAFE_INTEGER),
                "clock_skew_seconds",
            )?;
            return Ok(());
        }
        has(self.clock_skew_seconds.is_none(), "clock_skew_seconds")?;
        has(
            self.event.is_none()
                && self.event_hash.is_none()
                && self.name_class.is_none()
                && self.namespace_policy_digest.is_none()
                && self.original_record_hash.is_none(),
            "event",
        )?;
        let reason = self.reason.as_deref().unwrap_or_default();
        match self.status {
            S::Rejected => {
                has(unattributed, "chain")?;
                has(RejectReason::parse(reason).is_some(), "reason")?;
                has(
                    self.lost_from.is_none() && self.lost_to.is_none() && self.dropped.is_none(),
                    "lost_from",
                )?;
                let raw = self
                    .raw
                    .as_ref()
                    .ok_or_else(|| invalid("rejected record without raw"))?;
                has(
                    is_escaped_text(&raw.escaped, MAX_RAW_PREFIX_BYTES)
                        && is_lower_hex(&raw.sha256, 64)
                        && raw.len <= MAX_SAFE_INTEGER,
                    "raw",
                )?;
            }
            S::Loss => {
                has(self.raw.is_none(), "raw")?;
                match LossReason::parse(reason) {
                    Some(LossReason::SourceSeqGap) => {
                        has(!unattributed, "chain")?;
                        has(self.dropped.is_none(), "dropped")?;
                        match (self.lost_from, self.lost_to) {
                            (Some(from), Some(to))
                                if from >= 1 && from <= to && to <= MAX_SAFE_INTEGER => {}
                            _ => return Err(invalid("loss record with a wrong range")),
                        }
                    }
                    Some(LossReason::QueueOverflow | LossReason::StorageError) => {
                        has(unattributed, "chain")?;
                        has(
                            self.lost_from.is_none() && self.lost_to.is_none(),
                            "lost_from",
                        )?;
                        has(
                            self.dropped
                                .is_some_and(|dropped| (1..=MAX_SAFE_INTEGER).contains(&dropped)),
                            "dropped",
                        )?;
                    }
                    None => return Err(invalid("loss record with an unknown reason")),
                }
            }
            _ => unreachable!("statuses with an event are handled above"),
        }
        Ok(())
    }
}

impl SafetyIngestKey {
    /// Validates `payload` and signs it. `payload.key_id` must be this key's.
    pub fn sign_record(
        &self,
        payload: SafetyRecordPayload,
    ) -> Result<SafetyRecord, SafetyRecordError> {
        if payload.key_id != self.key_id() {
            return Err(invalid("payload key_id is not this ingestion key"));
        }
        payload.validate()?;
        let bytes = payload.canonical_bytes()?;
        let record = SafetyRecord {
            record_hash: sha256_hex(SAFETY_RECORD_DOMAIN, &bytes),
            signature: hex::encode(sign_with(&self.signing_key, SAFETY_RECORD_DOMAIN, &bytes)),
            payload,
        };
        // The stored form must be readable back (size limit).
        record.to_json()?;
        Ok(record)
    }
}

impl SafetyRecord {
    pub fn payload(&self) -> &SafetyRecordPayload {
        &self.payload
    }

    pub fn record_hash(&self) -> &str {
        &self.record_hash
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }

    /// The canonical JSON of the whole record, one line, as stored and
    /// exported.
    pub fn to_json(&self) -> Result<String, SafetyRecordError> {
        let mut value = serde_json::to_value(&self.payload)
            .map_err(|_| invalid("cannot encode the payload"))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| invalid("payload is not an object"))?;
        object.insert(
            "record_hash".into(),
            Value::String(self.record_hash.clone()),
        );
        object.insert("signature".into(), Value::String(self.signature.clone()));
        let bytes = canonical_json(&value).map_err(|error| invalid(error.to_string()))?;
        if bytes.len() > MAX_SAFETY_RECORD_BYTES {
            return Err(invalid("too large"));
        }
        String::from_utf8(bytes).map_err(|_| invalid("not UTF-8"))
    }

    /// Parses one record: strict JSON, exactly the documented fields, valid
    /// per status, and `json` exactly its canonical encoding. Does not check
    /// the hash or the signature; see [`Self::verify`].
    pub fn from_json(json: &str) -> Result<Self, SafetyRecordError> {
        if json.len() > MAX_SAFETY_RECORD_BYTES {
            return Err(invalid("too large"));
        }
        let mut value = parse_json_strict(json).map_err(|error| invalid(error.to_string()))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| invalid("not an object"))?;
        let mut take = |field: &str| match object.remove(field) {
            Some(Value::String(text)) => Ok(text),
            _ => Err(invalid(format!("missing or invalid `{field}`"))),
        };
        let record_hash = take("record_hash")?;
        let signature = take("signature")?;
        let payload: SafetyRecordPayload =
            serde_json::from_value(value).map_err(|error| invalid(error.to_string()))?;
        payload.validate()?;
        if !is_lower_hex(&record_hash, 64) || !is_canonical_signature_hex(&signature) {
            return Err(invalid("invalid record_hash or signature"));
        }
        let record = Self {
            payload,
            record_hash,
            signature,
        };
        if record.to_json()? != json {
            return Err(SafetyRecordError::NotCanonical);
        }
        Ok(record)
    }

    /// Checks the record against the pinned ingestion keys: `key_id` names
    /// one of them, `record_hash` is the hash of the payload and the
    /// signature verifies under that key.
    pub fn verify(&self, ingest_pins: &[VerifiedPublicKey]) -> Result<(), SafetyRecordError> {
        self.payload.validate()?;
        let Some(pin) = ingest_pins
            .iter()
            .find(|pin| safety_ingest_key_id(pin) == self.payload.key_id)
        else {
            return Err(SafetyRecordError::UnpinnedKey(self.payload.key_id.clone()));
        };
        let bytes = self.payload.canonical_bytes()?;
        if self.record_hash != sha256_hex(SAFETY_RECORD_DOMAIN, &bytes) {
            return Err(SafetyRecordError::HashMismatch);
        }
        let signature =
            decode_lower_hex(&self.signature).ok_or(SafetyRecordError::SignatureInvalid)?;
        pin.verify_domain_message(SAFETY_RECORD_DOMAIN, &bytes, &signature)
            .map_err(|_| SafetyRecordError::SignatureInvalid)
    }

    /// The `record_hash` recomputed from the payload, without a key.
    pub fn recomputed_hash(&self) -> Result<String, SafetyRecordError> {
        Ok(sha256_hex(
            SAFETY_RECORD_DOMAIN,
            &self.payload.canonical_bytes()?,
        ))
    }

    /// The chain position after this record: what the next record of the
    /// chain links to, and the `source_seq` high-water mark.
    fn next_head(&self, previous_high_water: u64) -> ChainHead {
        let payload = &self.payload;
        let high_water = match payload.status {
            SafetyRecordStatus::Accepted
            | SafetyRecordStatus::Undeclared
            | SafetyRecordStatus::InvalidName => payload
                .event
                .as_ref()
                .map_or(previous_high_water, |event| event.source_seq),
            SafetyRecordStatus::Loss => payload.lost_to.unwrap_or(previous_high_water),
            _ => previous_high_water,
        };
        ChainHead {
            next_chain_seq: payload.chain_seq + 1,
            prev_record_hash: self.record_hash.clone(),
            high_water,
        }
    }
}

// ---------------------------------------------------------------------------
// Ingestion.

/// The position of one chain: the next `chain_seq`, the hash it links to
/// and the `source_seq` high-water mark (every `source_seq` up to it is
/// recorded as an event or covered by a loss record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainHead {
    pub next_chain_seq: u64,
    pub prev_record_hash: String,
    pub high_water: u64,
}

impl Default for ChainHead {
    fn default() -> Self {
        Self {
            next_chain_seq: 0,
            prev_record_hash: GENESIS_HASH.to_owned(),
            high_water: 0,
        }
    }
}

impl ChainHead {
    /// The head after `record`, given the head before it.
    pub fn after(&self, record: &SafetyRecord) -> Self {
        record.next_head(self.high_water)
    }
}

/// The first event recorded for one `source_seq` of a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRef {
    pub event_hash: String,
    pub record_hash: String,
}

/// Reads earlier records: the storage behind the ingester.
pub trait EventLookup {
    type Error;
    /// The first event record (`accepted`, `undeclared`, `invalid_name` or
    /// `late`) of `chain` with `source_seq`, if any.
    fn first_event(
        &mut self,
        tenant_id: Uuid,
        chain: &str,
        source_seq: u64,
    ) -> Result<Option<EventRef>, Self::Error>;
}

/// Records to store together (one transaction), and the chain head after
/// them. Apply it with [`SafetyIngestor::commit`] once stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRecords {
    pub chain: String,
    pub records: Vec<SafetyRecord>,
    /// The `source_seq` high-water mark after each record (stored with it,
    /// so that the ingester can resume from the last record of a chain).
    pub high_waters: Vec<u64>,
    pub head: ChainHead,
}

/// Why the ingester could not be configured.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IngestSetupError {
    /// The namespace manifest does not verify under the pinned namespace key.
    #[error("safety namespace manifest: {0}")]
    Manifest(SafetyNamespaceError),
    /// Two roles share one public key.
    #[error("{first} and {second} must be different keys ({error})")]
    SameKey {
        first: String,
        second: String,
        error: SafetyNamespaceError,
    },
    /// A chain head read from storage is not consistent.
    #[error("chain head of {chain}: {reason}")]
    InvalidHead { chain: String, reason: String },
    #[error("no source is pinned")]
    NoSources,
    #[error("max_seq_jump must be between 1 and 2^53 - 1")]
    InvalidMaxSeqJump,
}

/// Why one input produced no record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestError<E> {
    /// The storage lookup failed.
    Lookup(E),
    /// A record could not be signed (should not happen for bounded input).
    Record(SafetyRecordError),
}

impl<E: std::fmt::Display> std::fmt::Display for IngestError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lookup(error) => write!(f, "storage lookup failed: {error}"),
            Self::Record(error) => write!(f, "{error}"),
        }
    }
}

/// The ingestion state machine. Deterministic apart from `record_id`
/// (random) and the `now` the caller passes.
pub struct SafetyIngestor {
    key: SafetyIngestKey,
    key_id: String,
    tenant_id: Uuid,
    manifest: SafetyNamespaceManifest,
    sources: SourcePins,
    heads: BTreeMap<String, ChainHead>,
    max_seq_jump: u64,
    max_clock_skew_seconds: u64,
}

impl std::fmt::Debug for SafetyIngestor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafetyIngestor")
            .field("key_id", &self.key_id)
            .field("tenant_id", &self.tenant_id)
            .field("sources", &self.sources.len())
            .finish_non_exhaustive()
    }
}

/// What [`SafetyIngestor::new`] needs.
pub struct IngestorConfig {
    pub ingest_key: SafetyIngestKey,
    pub tenant_id: Uuid,
    /// Parsed with [`SafetyNamespaceManifest::from_file`]; verified here.
    pub manifest: SafetyNamespaceManifest,
    pub namespace_pin: VerifiedPublicKey,
    /// The gateway's evidence attester public key: only compared, so the
    /// ingestion key cannot be it.
    pub attester_pin: VerifiedPublicKey,
    pub sources: SourcePins,
    /// The last head of every chain in storage.
    pub heads: BTreeMap<String, ChainHead>,
    /// The largest accepted step of `source_seq` above a chain's high-water
    /// mark (at least 1; [`DEFAULT_MAX_SEQ_JUMP`] by default). A verified
    /// event further ahead is recorded as `rejected`
    /// ([`RejectReason::SeqJumpTooLarge`]) on the unattributed chain and
    /// does not move the high-water mark, so one event (a source bug, or a
    /// compromised source key) cannot push the chain to the end of the
    /// `source_seq` range.
    pub max_seq_jump: u64,
    /// The largest `|occurred_at - recorded_at|`, in seconds, recorded
    /// without a mark ([`DEFAULT_MAX_CLOCK_SKEW_SECONDS`] by default). Above
    /// it the record keeps its status and carries `clock_skew_seconds`.
    pub max_clock_skew_seconds: u64,
}

impl SafetyIngestor {
    /// Verifies the manifest against the namespace pin and refuses any two
    /// roles that share a key: the ingestion key, the namespace key, the
    /// attester key and every source key are pairwise distinct
    /// ([`ensure_distinct_keys`]). There is no flag to skip either check.
    pub fn new(config: IngestorConfig) -> Result<Self, IngestSetupError> {
        config
            .manifest
            .verify(&config.namespace_pin)
            .map_err(IngestSetupError::Manifest)?;
        if config.sources.is_empty() {
            return Err(IngestSetupError::NoSources);
        }
        if config.max_seq_jump == 0 || config.max_seq_jump > MAX_SAFE_INTEGER {
            return Err(IngestSetupError::InvalidMaxSeqJump);
        }
        let ingest_pin = config
            .ingest_key
            .public_key()
            .map_err(|_| IngestSetupError::SameKey {
                first: "ingestion key".into(),
                second: "a valid key".into(),
                error: SafetyNamespaceError::SignatureInvalid,
            })?;
        let mut roles: Vec<(String, &VerifiedPublicKey)> = vec![
            ("the ingestion key".into(), &ingest_pin),
            ("the namespace key".into(), &config.namespace_pin),
            ("the attester key".into(), &config.attester_pin),
        ];
        for (source, key) in config.sources.iter() {
            roles.push((format!("the key of source {source}"), key));
        }
        for (index, (first, a)) in roles.iter().enumerate() {
            for (second, b) in &roles[index + 1..] {
                ensure_distinct_keys(a, b).map_err(|error| IngestSetupError::SameKey {
                    first: first.clone(),
                    second: second.clone(),
                    error,
                })?;
            }
        }
        let mut ingestor = Self {
            key_id: config.ingest_key.key_id(),
            key: config.ingest_key,
            tenant_id: config.tenant_id,
            manifest: config.manifest,
            sources: config.sources,
            heads: BTreeMap::new(),
            max_seq_jump: config.max_seq_jump,
            max_clock_skew_seconds: config.max_clock_skew_seconds,
        };
        ingestor.set_heads(config.heads)?;
        Ok(ingestor)
    }

    /// Replaces every chain head, for example after reading them again from
    /// storage once the database is reachable again.
    pub fn set_heads(
        &mut self,
        heads: BTreeMap<String, ChainHead>,
    ) -> Result<(), IngestSetupError> {
        for (chain, head) in &heads {
            let bad = |reason: &str| IngestSetupError::InvalidHead {
                chain: chain.clone(),
                reason: reason.into(),
            };
            if !is_valid_chain(chain) {
                return Err(bad("invalid chain name"));
            }
            if !is_lower_hex(&head.prev_record_hash, 64) || head.high_water > MAX_SAFE_INTEGER {
                return Err(bad("invalid head"));
            }
        }
        self.heads = heads;
        Ok(())
    }

    /// The namespace manifest names are classified against.
    pub fn manifest(&self) -> &SafetyNamespaceManifest {
        &self.manifest
    }

    pub fn sources(&self) -> &SourcePins {
        &self.sources
    }

    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn head(&self, chain: &str) -> ChainHead {
        self.heads.get(chain).cloned().unwrap_or_default()
    }

    /// Applies records once they are stored.
    pub fn commit(&mut self, prepared: &PreparedRecords) {
        self.heads
            .insert(prepared.chain.clone(), prepared.head.clone());
    }

    fn payload(
        &self,
        chain: &str,
        head: &ChainHead,
        status: SafetyRecordStatus,
        now: &str,
    ) -> SafetyRecordPayload {
        SafetyRecordPayload {
            schema_version: SAFETY_INGEST_SCHEMA_VERSION,
            record_id: Uuid::new_v4(),
            tenant_id: self.tenant_id,
            chain: chain.to_owned(),
            chain_seq: head.next_chain_seq,
            prev_record_hash: head.prev_record_hash.clone(),
            recorded_at: now.to_owned(),
            status,
            reason: None,
            detail: None,
            event: None,
            event_hash: None,
            name_class: None,
            namespace_policy_digest: None,
            original_record_hash: None,
            lost_from: None,
            lost_to: None,
            dropped: None,
            raw: None,
            clock_skew_seconds: None,
            key_id: self.key_id.clone(),
        }
    }

    fn now_text(now: OffsetDateTime) -> Result<String, SafetyRecordError> {
        format_utc(now).ok_or_else(|| invalid("recorded_at"))
    }

    fn sign_all(
        &self,
        chain: &str,
        payloads: Vec<SafetyRecordPayload>,
        mut head: ChainHead,
    ) -> Result<PreparedRecords, SafetyRecordError> {
        let mut records = Vec::with_capacity(payloads.len());
        let mut high_waters = Vec::with_capacity(payloads.len());
        for mut payload in payloads {
            payload.chain_seq = head.next_chain_seq;
            payload.prev_record_hash = head.prev_record_hash.clone();
            let record = self.key.sign_record(payload)?;
            head = head.after(&record);
            high_waters.push(head.high_water);
            records.push(record);
        }
        Ok(PreparedRecords {
            chain: chain.to_owned(),
            records,
            high_waters,
            head,
        })
    }

    /// A signed loss record of `dropped` messages that never reached the
    /// state machine (a full queue, the database unavailable), on the
    /// unattributed chain.
    pub fn prepare_dropped(
        &self,
        reason: LossReason,
        dropped: u64,
        now: OffsetDateTime,
    ) -> Result<PreparedRecords, SafetyRecordError> {
        if reason == LossReason::SourceSeqGap {
            return Err(invalid("a source_seq gap belongs to a source chain"));
        }
        let head = self.head(UNATTRIBUTED_CHAIN);
        let mut payload = self.payload(
            UNATTRIBUTED_CHAIN,
            &head,
            SafetyRecordStatus::Loss,
            &Self::now_text(now)?,
        );
        payload.reason = Some(reason.as_str().into());
        payload.dropped = Some(dropped.min(MAX_SAFE_INTEGER));
        self.sign_all(UNATTRIBUTED_CHAIN, vec![payload], head)
    }

    /// A signed `rejected` record for an input that did not verify, with
    /// its bounded, escaped raw copy, on the unattributed chain.
    fn prepare_rejected(
        &self,
        input: &[u8],
        rejection: &EventRejection,
        now: &str,
    ) -> Result<PreparedRecords, SafetyRecordError> {
        let head = self.head(UNATTRIBUTED_CHAIN);
        let mut payload =
            self.payload(UNATTRIBUTED_CHAIN, &head, SafetyRecordStatus::Rejected, now);
        payload.reason = Some(rejection.reason.as_str().into());
        payload.detail = Some(bounded_detail(&rejection.detail));
        payload.raw = Some(RawInput::of(input));
        self.sign_all(UNATTRIBUTED_CHAIN, vec![payload], head)
    }

    /// `occurred_at - now` in whole seconds when its magnitude is above
    /// `max_clock_skew_seconds`.
    fn clock_skew(&self, record: &SafetyRecordPayload, now: OffsetDateTime) -> Option<i64> {
        let occurred =
            OffsetDateTime::parse(record.event.as_ref()?.occurred_at(), &Rfc3339).ok()?;
        let skew = (occurred - now).whole_seconds();
        (skew.unsigned_abs() > self.max_clock_skew_seconds)
            .then_some(skew.clamp(-(MAX_SAFE_INTEGER as i64), MAX_SAFE_INTEGER as i64))
    }

    /// Parses `input` and verifies it against the pinned source key.
    pub fn authenticate(&self, input: &[u8]) -> Result<SafetyEvent, EventRejection> {
        let event = SafetyEvent::parse(input)?;
        let pin = self.sources.get(&event.source_id).ok_or_else(|| {
            EventRejection::new(RejectReason::UnknownSource, "source_id is not pinned")
        })?;
        event.verify(pin)?;
        Ok(event)
    }

    /// The records for one input message, not yet stored:
    ///
    /// * an input that does not parse or verify: one `rejected` record on
    ///   the unattributed chain (never dropped);
    /// * a verified event more than `max_seq_jump` above the high-water
    ///   mark: one `rejected` record (`seq_jump_too_large`) on the
    ///   unattributed chain; the source chain does not change;
    /// * an event whose `source_seq` is above the next expected one: a
    ///   `loss` record for the missing range, then the event record;
    /// * an event whose `source_seq` was already recorded: `duplicate` (same
    ///   event hash) or `conflict` (another one); if it was recorded as
    ///   lost: `late`;
    /// * otherwise the event record: `accepted` (declared name),
    ///   `undeclared` or `invalid_name`.
    pub fn prepare<L: EventLookup>(
        &self,
        input: &[u8],
        now: OffsetDateTime,
        lookup: &mut L,
    ) -> Result<PreparedRecords, IngestError<L::Error>> {
        let now_instant = now;
        let now = Self::now_text(now).map_err(IngestError::Record)?;
        let event = match self.authenticate(input) {
            Ok(event) => event,
            Err(rejection) => {
                return self
                    .prepare_rejected(input, &rejection, &now)
                    .map_err(IngestError::Record);
            }
        };
        let chain = event.source_id.clone();
        let head = self.head(&chain);
        let (class, name_reason, name_detail) = match SafetyActionName::parse(&event.action) {
            Ok(name) => match self.manifest.classify_name(&name) {
                NamespaceMembership::Declared => (NameClass::Declared, None, None),
                NamespaceMembership::Undeclared => (NameClass::Undeclared, None, None),
            },
            Err(error) => (
                NameClass::InvalidName,
                Some(safety_name_error_code(&error).to_owned()),
                Some(bounded_detail(&error.to_string())),
            ),
        };
        let seq = event.source_seq;
        if seq - head.high_water.min(seq) > self.max_seq_jump {
            let rejection = EventRejection::new(
                RejectReason::SeqJumpTooLarge,
                format!(
                    "source {chain}: source_seq {seq} is {} above the high-water mark {}; the \
                     maximum step is {}",
                    seq - head.high_water,
                    head.high_water,
                    self.max_seq_jump
                ),
            );
            return self
                .prepare_rejected(input, &rejection, &now)
                .map_err(IngestError::Record);
        }
        let expected = head.high_water.saturating_add(1);
        let mut payloads = Vec::with_capacity(2);
        let (status, original) = if seq >= expected {
            if seq > expected {
                let mut loss = self.payload(&chain, &head, SafetyRecordStatus::Loss, &now);
                loss.reason = Some(LossReason::SourceSeqGap.as_str().into());
                loss.lost_from = Some(expected);
                loss.lost_to = Some(seq - 1);
                payloads.push(loss);
            }
            let status = match class {
                NameClass::Declared => SafetyRecordStatus::Accepted,
                NameClass::Undeclared => SafetyRecordStatus::Undeclared,
                NameClass::InvalidName => SafetyRecordStatus::InvalidName,
            };
            (status, None)
        } else {
            let event_hash = event.event_hash();
            match lookup
                .first_event(self.tenant_id, &chain, seq)
                .map_err(IngestError::Lookup)?
            {
                Some(first) if first.event_hash == event_hash => {
                    (SafetyRecordStatus::Duplicate, Some(first.record_hash))
                }
                Some(first) => (SafetyRecordStatus::Conflict, Some(first.record_hash)),
                None => (SafetyRecordStatus::Late, None),
            }
        };
        let mut record = self.payload(&chain, &head, status, &now);
        record.event_hash = Some(event.event_hash());
        record.event = Some(event);
        record.name_class = Some(class);
        record.namespace_policy_digest = Some(self.manifest.policy_digest().to_owned());
        record.reason = name_reason;
        record.detail = name_detail;
        record.original_record_hash = original;
        record.clock_skew_seconds = self.clock_skew(&record, now_instant);
        payloads.push(record);
        self.sign_all(&chain, payloads, head)
            .map_err(IngestError::Record)
    }
}

/// An in-memory [`EventLookup`] over records already prepared (tests, and
/// the verifier's own bookkeeping).
#[derive(Debug, Default)]
pub struct MemoryLookup {
    first: HashMap<(Uuid, String, u64), EventRef>,
}

impl MemoryLookup {
    pub fn record(&mut self, record: &SafetyRecord) {
        let payload = &record.payload;
        if !payload.status.is_first_event() {
            return;
        }
        if let (Some(event), Some(event_hash)) = (&payload.event, &payload.event_hash) {
            self.first
                .entry((payload.tenant_id, payload.chain.clone(), event.source_seq))
                .or_insert_with(|| EventRef {
                    event_hash: event_hash.clone(),
                    record_hash: record.record_hash.clone(),
                });
        }
    }
}

impl EventLookup for MemoryLookup {
    type Error = std::convert::Infallible;

    fn first_event(
        &mut self,
        tenant_id: Uuid,
        chain: &str,
        source_seq: u64,
    ) -> Result<Option<EventRef>, Self::Error> {
        Ok(self
            .first
            .get(&(tenant_id, chain.to_owned(), source_seq))
            .cloned())
    }
}

// ---------------------------------------------------------------------------
// Verification of an exported chain.

/// Counts of an exported chain, by status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SafetyCounts {
    pub accepted: u64,
    pub undeclared: u64,
    pub invalid_name: u64,
    pub duplicate: u64,
    pub conflict: u64,
    pub late: u64,
    pub rejected: u64,
    /// `rejected` records by reason (for example `seq_jump_too_large`: a
    /// verified event that was too far ahead of its chain).
    pub rejected_by_reason: BTreeMap<String, u64>,
    /// Loss records.
    pub loss: u64,
    /// `source_seq` values covered by gap loss records.
    pub lost_events: u64,
    /// Messages dropped inside the ingester (unattributed loss records).
    pub dropped_messages: u64,
    /// Event records marked with `clock_skew_seconds`.
    pub clock_skew: u64,
}

/// Result of [`verify_safety_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyChainReport {
    pub chain: String,
    pub tenant_id: Uuid,
    pub entries: u64,
    /// `record_hash` of the last record.
    pub head: String,
    /// Every `source_seq` up to this value is an event or covered by a
    /// loss record (0 for the unattributed chain).
    pub high_water: u64,
    pub counts: SafetyCounts,
    /// Whether every event's signature was checked against a source pin.
    pub source_signatures_verified: bool,
    /// Records per ingestion key id.
    pub signed_by: BTreeMap<String, u64>,
}

/// Why an exported chain was not accepted. Every variant is a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyChainError {
    Empty,
    TooLarge,
    /// Line `line` (from 0) does not parse as a canonical record.
    Malformed {
        line: u64,
        error: SafetyRecordError,
    },
    /// The record's key, hash or signature does not verify.
    Record {
        line: u64,
        error: SafetyRecordError,
    },
    /// `chain_seq`, `prev_record_hash`, `chain` or `tenant_id` does not
    /// continue the chain, or a `record_id` repeats.
    BrokenChain {
        line: u64,
        reason: String,
    },
    /// A `source_seq` is not the next one and no loss record covers the
    /// gap.
    SequenceGap {
        line: u64,
        expected: u64,
        found: u64,
    },
    /// A duplicate, conflict or late record does not match what the chain
    /// recorded before.
    SequenceInconsistent {
        line: u64,
        reason: String,
    },
    /// A record of this status does not belong in this chain.
    WrongChain {
        line: u64,
    },
    /// An event's source is not among the given source pins.
    UnpinnedSource {
        line: u64,
        source_id: String,
    },
    /// An event's signature does not verify under its source pin.
    EventSignature {
        line: u64,
        rejection: EventRejection,
    },
    /// The chain verifies, but its head is not the expected one.
    HeadMismatch {
        actual: String,
    },
}

impl SafetyChainError {
    /// Stable machine-readable code, used by the CLIs.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty | Self::BrokenChain { .. } | Self::WrongChain { .. } => "SAFETY_CHAIN_FAIL",
            Self::TooLarge => "INPUT_TOO_LARGE",
            Self::Malformed { .. } => "INVALID_REQUEST",
            Self::Record {
                error: SafetyRecordError::UnpinnedKey(_),
                ..
            } => "AUTH_FAIL",
            Self::Record { .. } => "EVIDENCE_FAIL",
            Self::SequenceGap { .. } | Self::SequenceInconsistent { .. } => "SAFETY_SEQUENCE_FAIL",
            Self::UnpinnedSource { .. } => "AUTH_FAIL",
            Self::EventSignature { .. } => "SAFETY_EVENT_SIGNATURE_INVALID",
            Self::HeadMismatch { .. } => "JOURNAL_HEAD_MISMATCH",
        }
    }
}

impl std::fmt::Display for SafetyChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "safety chain is empty"),
            Self::TooLarge => write!(f, "safety chain exceeds the size or entry limit"),
            Self::Malformed { line, error } => write!(f, "record {line}: {error}"),
            Self::Record { line, error } => write!(f, "record {line}: {error}"),
            Self::BrokenChain { line, reason } => write!(f, "record {line}: {reason}"),
            Self::SequenceGap {
                line,
                expected,
                found,
            } => write!(
                f,
                "record {line}: source_seq {found} where {expected} was expected, and no loss \
                 record covers the gap"
            ),
            Self::SequenceInconsistent { line, reason } => write!(f, "record {line}: {reason}"),
            Self::WrongChain { line } => {
                write!(
                    f,
                    "record {line}: this status does not belong in this chain"
                )
            }
            Self::UnpinnedSource { line, source_id } => {
                write!(f, "record {line}: source {source_id} is not pinned")
            }
            Self::EventSignature { line, rejection } => {
                write!(f, "record {line}: event {rejection}")
            }
            Self::HeadMismatch { actual } => {
                write!(f, "head {actual} does not match the expected head")
            }
        }
    }
}

impl std::error::Error for SafetyChainError {}

/// Verifies a JSONL export of one safety chain
/// (`docs/proposals/safety-ingestion-jsonl.md`). Fail closed: the first
/// problem ends verification.
///
/// For every record, in order: it is the canonical encoding of a valid
/// record; `key_id` names one of `ingest_pins`, `record_hash` matches and
/// the signature verifies; `chain` and `tenant_id` are those of the first
/// record, `chain_seq` is its line number, `prev_record_hash` is the
/// previous record's hash (64 zeros first) and `record_id` is unique. On a
/// source chain, `source_seq` is continuous: each `accepted`, `undeclared`
/// or `invalid_name` event is the next one, a gap is covered by a loss
/// record that is immediately followed by the event that revealed it, a
/// `duplicate` or `conflict` names the first record of its `source_seq`
/// (same or different event hash), and a `late` event fills a lost
/// `source_seq` that had no event. The unattributed chain holds only
/// `rejected` records and ingester losses. With `source_pins`, every
/// event's signature is checked against the pin of its source. With
/// `expected_head`, the last `record_hash` must equal it.
///
/// Without `expected_head`, a truncated chain (a prefix) still verifies.
pub fn verify_safety_chain(
    text: &str,
    ingest_pins: &[VerifiedPublicKey],
    source_pins: Option<&SourcePins>,
    expected_head: Option<&str>,
) -> Result<SafetyChainReport, SafetyChainError> {
    if text.len() > MAX_SAFETY_CHAIN_BYTES {
        return Err(SafetyChainError::TooLarge);
    }
    let mut report: Option<SafetyChainReport> = None;
    let mut prev = GENESIS_HASH.to_owned();
    let mut record_ids = HashSet::new();
    // source_seq -> (event_hash, record_hash) of its first event.
    let mut first_events: HashMap<u64, (String, String)> = HashMap::new();
    let mut loss_ranges: Vec<(u64, u64)> = Vec::new();
    let mut must_follow: Option<u64> = None;
    let mut high_water = 0u64;
    let mut line = 0u64;
    let mut rest = text;
    while !rest.is_empty() {
        if line as usize >= MAX_SAFETY_CHAIN_ENTRIES {
            return Err(SafetyChainError::TooLarge);
        }
        let (current, tail) = rest.split_once('\n').ok_or(SafetyChainError::Malformed {
            line,
            error: invalid("the last line does not end in a newline"),
        })?;
        rest = tail;
        let record = SafetyRecord::from_json(current)
            .map_err(|error| SafetyChainError::Malformed { line, error })?;
        record
            .verify(ingest_pins)
            .map_err(|error| SafetyChainError::Record { line, error })?;
        let payload = &record.payload;
        let broken = |reason: &str| SafetyChainError::BrokenChain {
            line,
            reason: reason.into(),
        };
        let summary = report.get_or_insert_with(|| SafetyChainReport {
            chain: payload.chain.clone(),
            tenant_id: payload.tenant_id,
            entries: 0,
            head: String::new(),
            high_water: 0,
            counts: SafetyCounts::default(),
            source_signatures_verified: source_pins.is_some(),
            signed_by: BTreeMap::new(),
        });
        if payload.chain != summary.chain {
            return Err(broken("chain differs from the first record"));
        }
        if payload.tenant_id != summary.tenant_id {
            return Err(broken("tenant_id differs from the first record"));
        }
        if payload.chain_seq != line {
            return Err(broken("chain_seq is not the record's position"));
        }
        if payload.prev_record_hash != prev {
            return Err(broken("prev_record_hash is not the previous record_hash"));
        }
        if !record_ids.insert(payload.record_id) {
            return Err(broken("record_id repeats"));
        }
        let unattributed = summary.chain == UNATTRIBUTED_CHAIN;
        let counts = &mut summary.counts;
        let inconsistent = |reason: String| SafetyChainError::SequenceInconsistent { line, reason };
        if let Some(next) = must_follow.take() {
            let follows = payload.status.is_first_event()
                && payload.status != SafetyRecordStatus::Late
                && payload.event.as_ref().is_some_and(|e| e.source_seq == next);
            if !follows {
                return Err(inconsistent(format!(
                    "a loss record must be followed by the event with source_seq {next}"
                )));
            }
        }
        if let (Some(event), Some(pins)) = (&payload.event, source_pins) {
            let pin =
                pins.get(&event.source_id)
                    .ok_or_else(|| SafetyChainError::UnpinnedSource {
                        line,
                        source_id: event.source_id.clone(),
                    })?;
            event
                .verify(pin)
                .map_err(|rejection| SafetyChainError::EventSignature { line, rejection })?;
        }
        if payload.clock_skew_seconds.is_some() {
            counts.clock_skew += 1;
        }
        let event_seq = payload.event.as_ref().map(|event| event.source_seq);
        let event_hash = payload.event_hash.clone().unwrap_or_default();
        use SafetyRecordStatus as S;
        match payload.status {
            S::Rejected => {
                if !unattributed {
                    return Err(SafetyChainError::WrongChain { line });
                }
                counts.rejected += 1;
                *counts
                    .rejected_by_reason
                    .entry(payload.reason.clone().unwrap_or_default())
                    .or_default() += 1;
            }
            S::Loss => {
                counts.loss += 1;
                match (payload.lost_from, payload.lost_to, payload.dropped) {
                    (Some(from), Some(to), None) => {
                        if unattributed {
                            return Err(SafetyChainError::WrongChain { line });
                        }
                        if from != high_water + 1 {
                            return Err(inconsistent(format!(
                                "loss record starts at {from}, not at {}",
                                high_water + 1
                            )));
                        }
                        counts.lost_events += to - from + 1;
                        loss_ranges.push((from, to));
                        high_water = to;
                        must_follow = Some(to + 1);
                    }
                    (None, None, Some(dropped)) => {
                        if !unattributed {
                            return Err(SafetyChainError::WrongChain { line });
                        }
                        counts.dropped_messages += dropped;
                    }
                    _ => return Err(broken("loss record with a wrong shape")),
                }
            }
            S::Accepted | S::Undeclared | S::InvalidName => {
                if unattributed {
                    return Err(SafetyChainError::WrongChain { line });
                }
                let seq = event_seq.unwrap_or_default();
                if seq != high_water + 1 {
                    return Err(SafetyChainError::SequenceGap {
                        line,
                        expected: high_water + 1,
                        found: seq,
                    });
                }
                high_water = seq;
                first_events.insert(seq, (event_hash, record.record_hash.clone()));
                match payload.status {
                    S::Accepted => counts.accepted += 1,
                    S::Undeclared => counts.undeclared += 1,
                    _ => counts.invalid_name += 1,
                }
            }
            S::Late => {
                if unattributed {
                    return Err(SafetyChainError::WrongChain { line });
                }
                let seq = event_seq.unwrap_or_default();
                let lost = loss_ranges
                    .iter()
                    .any(|&(from, to)| (from..=to).contains(&seq));
                if !lost || first_events.contains_key(&seq) {
                    return Err(inconsistent(format!(
                        "late event {seq} does not fill a lost source_seq"
                    )));
                }
                first_events.insert(seq, (event_hash, record.record_hash.clone()));
                counts.late += 1;
            }
            S::Duplicate | S::Conflict => {
                if unattributed {
                    return Err(SafetyChainError::WrongChain { line });
                }
                let seq = event_seq.unwrap_or_default();
                let Some((first_hash, first_record)) = first_events.get(&seq) else {
                    return Err(inconsistent(format!(
                        "{} of source_seq {seq}, which has no earlier event",
                        payload.status.as_str()
                    )));
                };
                if payload.original_record_hash.as_deref() != Some(first_record) {
                    return Err(inconsistent(
                        "original_record_hash is not the first record of its source_seq".into(),
                    ));
                }
                let same = *first_hash == event_hash;
                if same != (payload.status == S::Duplicate) {
                    return Err(inconsistent(format!(
                        "{} with {} event hash",
                        payload.status.as_str(),
                        if same { "the same" } else { "a different" }
                    )));
                }
                if same {
                    counts.duplicate += 1;
                } else {
                    counts.conflict += 1;
                }
            }
        }
        *summary.signed_by.entry(payload.key_id.clone()).or_default() += 1;
        summary.entries += 1;
        summary.high_water = high_water;
        prev = record.record_hash.clone();
        summary.head = prev.clone();
        line += 1;
    }
    let report = report.ok_or(SafetyChainError::Empty)?;
    if let Some(next) = must_follow {
        return Err(SafetyChainError::SequenceInconsistent {
            line,
            reason: format!("the chain ends after a loss record, before source_seq {next}"),
        });
    }
    if let Some(expected) = expected_head
        && expected != report.head
    {
        return Err(SafetyChainError::HeadMismatch {
            actual: report.head,
        });
    }
    Ok(report)
}

#[cfg(test)]
mod tests;
