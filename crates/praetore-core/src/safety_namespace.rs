//! G2: the safety namespace.
//!
//! Two pieces, shared by policy loading and by the future ingestion path
//! for safety actions (SAF-09.5), so their rules cannot diverge:
//!
//! * [`SafetyActionName`]: the one validator of `safety:*` names. Policy
//!   format 2 uses it for every `Safety` entry of `action_classes`.
//! * [`SafetyNamespaceManifest`]: a signed statement of the `Safety` names a
//!   format 2 policy declares, bound to that policy's digest. An executor of
//!   an AI-enabled system and PRÆTORE can compare it to confirm they share
//!   the same safety namespace, and an executor can detect that it holds a
//!   manifest for another policy version.
//!
//! The manifest authorizes nothing. No engine, gateway, gate or hook reads
//! it: it is not consulted on the decision path.

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use crate::{
    canonical::{
        JsonError, MAX_JSON_VALUE_BYTES, canonical_json, decode_lower_hex,
        is_canonical_signature_hex, parse_json_strict,
    },
    identity::VerifiedPublicKey,
    policy::{ActionClass, MAX_ACTION_CLASSES, MAX_POLICY_TEXT_BYTES, Policy},
};

/// The prefix every safety action type carries, and only safety action
/// types carry. Exact, lowercase ASCII.
pub const SAFETY_ACTION_PREFIX: &str = "safety:";

/// Maximum length of a safety action name, in bytes, prefix included.
/// Every byte is printable ASCII, so this is also the length in characters.
pub const MAX_SAFETY_ACTION_NAME_BYTES: usize = 128;

/// Signature domain of a [`SafetyNamespaceManifest`] (29 bytes, NUL
/// included). No other PRÆTORE domain is a prefix of it, and it is a prefix
/// of none (checked by `tests/safety_namespace.rs` over every domain literal
/// in the repository).
pub const SAFETY_NAMESPACE_DOMAIN: &[u8; 29] = b"PRAETORE_SAFETY_NAMESPACE_V1\0";

/// Domain of the key id of a [`SafetyNamespaceKey`]:
/// `hex(SHA-256(SAFETY_NAMESPACE_KEY_ID_DOMAIN || public key))`. Distinct
/// from the attester, issuer and agent key id domains, so the same public
/// key never has the same id in two roles.
pub const SAFETY_NAMESPACE_KEY_ID_DOMAIN: &[u8] = b"PRAETORE_SAFETY_NAMESPACE_KEY_V1\0ed25519\0";

/// The only manifest schema version this crate writes and accepts.
pub const SAFETY_NAMESPACE_SCHEMA_VERSION: u8 = 1;

/// Why a string is not a [`SafetyActionName`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SafetyNameError {
    /// The name is the empty string.
    #[error("safety action name is empty")]
    Empty,
    /// The name is longer than [`MAX_SAFETY_ACTION_NAME_BYTES`]. The name
    /// itself is not kept, so the error stays small.
    #[error("safety action name is {bytes} bytes; the maximum is {max}")]
    TooLong { bytes: usize, max: usize },
    /// A character outside printable ASCII (`!` to `~`): whitespace, a
    /// control or format character (zero-width space, byte order mark), or
    /// any non-ASCII character (a homoglyph, a full-width letter or colon).
    #[error("safety action name {name:?} must be printable ASCII without whitespace")]
    NotPrintableAscii { name: String },
    /// The name does not start with the exact, lowercase `safety:`.
    #[error("safety action name {name:?} does not start with the exact prefix `safety:`")]
    MissingPrefix { name: String },
    /// Nothing follows `safety:`, or what follows does not start with an
    /// ASCII letter or digit.
    #[error(
        "safety action name {name:?} must continue after `safety:` with an ASCII letter or digit"
    )]
    InvalidNameStart { name: String },
}

/// A validated safety action name: the exact ASCII prefix `safety:`, then a
/// name that starts with an ASCII letter or digit, all printable ASCII
/// without whitespace, at most [`MAX_SAFETY_ACTION_NAME_BYTES`] bytes.
///
/// [`Self::parse`] is the only constructor. Policy format 2 accepts a
/// `Safety` entry in `action_classes` exactly when `parse` accepts its key.
///
/// ```
/// use praetore_core::{SafetyActionName, SafetyNameError};
///
/// let halt = SafetyActionName::parse("safety:halt").unwrap();
/// assert_eq!(halt.as_str(), "safety:halt");
/// assert_eq!(halt.name_after_prefix(), "halt");
/// assert!(matches!(
///     SafetyActionName::parse("SAFETY:halt"),
///     Err(SafetyNameError::MissingPrefix { .. })
/// ));
/// assert!(matches!(
///     SafetyActionName::parse("safety:halt\u{200b}"),
///     Err(SafetyNameError::NotPrintableAscii { .. })
/// ));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SafetyActionName(String);

impl SafetyActionName {
    /// Checks, in this order: not empty, at most
    /// [`MAX_SAFETY_ACTION_NAME_BYTES`] bytes, printable ASCII only, the
    /// exact prefix `safety:`, and an ASCII letter or digit right after it.
    pub fn parse(name: &str) -> Result<Self, SafetyNameError> {
        if name.is_empty() {
            return Err(SafetyNameError::Empty);
        }
        if name.len() > MAX_SAFETY_ACTION_NAME_BYTES {
            return Err(SafetyNameError::TooLong {
                bytes: name.len(),
                max: MAX_SAFETY_ACTION_NAME_BYTES,
            });
        }
        if !name.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(SafetyNameError::NotPrintableAscii {
                name: name.to_owned(),
            });
        }
        let Some(rest) = name.strip_prefix(SAFETY_ACTION_PREFIX) else {
            return Err(SafetyNameError::MissingPrefix {
                name: name.to_owned(),
            });
        };
        if !rest
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(SafetyNameError::InvalidNameStart {
                name: name.to_owned(),
            });
        }
        Ok(Self(name.to_owned()))
    }

    /// The full name, prefix included.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The part after `safety:` (never empty).
    pub fn name_after_prefix(&self) -> &str {
        &self.0[SAFETY_ACTION_PREFIX.len()..]
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for SafetyActionName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Printable ASCII by construction: nothing to escape.
        f.write_str(&self.0)
    }
}

impl AsRef<str> for SafetyActionName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SafetyActionName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Whether `action_type` contains `safety` in any ASCII case. Policy format
/// 2 rejects such a name unless it is a valid `Safety` entry, so a name
/// cannot look like a safety action without being one.
pub fn mentions_safety(action_type: &str) -> bool {
    action_type
        .as_bytes()
        .windows(6)
        .any(|window| window.eq_ignore_ascii_case(b"safety"))
}

/// Whether a safety action name is in a manifest's namespace. An undeclared
/// name is a normal answer, not an error: the ingestion path records it,
/// marked `undeclared`, instead of dropping it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceMembership {
    Declared,
    Undeclared,
}

impl NamespaceMembership {
    /// `"declared"` or `"undeclared"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Undeclared => "undeclared",
        }
    }
}

/// The key that signs safety namespace manifests.
///
/// A dedicated role, separate from the evidence attester key (online, on
/// the decision path), the authority issuer key (grants capabilities) and
/// the key of the future ingestion path. It is held by whoever releases the
/// policy and can stay offline: a manifest is signed once per policy
/// version. Its key id uses its own domain
/// ([`SAFETY_NAMESPACE_KEY_ID_DOMAIN`]).
pub struct SafetyNamespaceKey {
    signing_key: SigningKey,
}

impl std::fmt::Debug for SafetyNamespaceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafetyNamespaceKey")
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

impl SafetyNamespaceKey {
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
        key_id_of(self.signing_key.verifying_key().as_bytes())
    }

    fn sign(&self, payload: &[u8]) -> [u8; 64] {
        let mut message = Vec::with_capacity(SAFETY_NAMESPACE_DOMAIN.len() + payload.len());
        message.extend_from_slice(SAFETY_NAMESPACE_DOMAIN);
        message.extend_from_slice(payload);
        self.signing_key.sign(&message).to_bytes()
    }
}

/// The key id a manifest signed by `public_key` records.
pub fn safety_namespace_key_id(public_key: &VerifiedPublicKey) -> String {
    key_id_of(&public_key.as_bytes())
}

fn key_id_of(public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SAFETY_NAMESPACE_KEY_ID_DOMAIN);
    hasher.update(public_key);
    hex::encode(hasher.finalize())
}

/// Which manifest field differs from the policy it is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestField {
    PolicyId,
    PolicyVersion,
    PolicyDigest,
    SafetyActions,
}

impl ManifestField {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyId => "policy_id",
            Self::PolicyVersion => "policy_version",
            Self::PolicyDigest => "policy_digest",
            Self::SafetyActions => "safety_actions",
        }
    }
}

impl std::fmt::Display for ManifestField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a safety namespace manifest was not built, parsed or verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SafetyNamespaceError {
    /// Not strict JSON within the structural limits (malformed, duplicate
    /// key, too large, too deep, unsafe integer).
    #[error("safety namespace manifest is not valid JSON: {0}")]
    Json(JsonError),
    /// Wrong shape: an unknown or missing field, or a value of the wrong
    /// type.
    #[error("safety namespace manifest has an invalid shape: {0}")]
    Schema(String),
    /// A `schema_version` other than [`SAFETY_NAMESPACE_SCHEMA_VERSION`].
    #[error("unsupported safety namespace manifest schema_version {found}")]
    UnsupportedSchemaVersion { found: u64 },
    /// A field that does not have its single valid form (lowercase hex of
    /// the right length, canonical RFC 3339 UTC, a canonical policy id, a
    /// positive version).
    #[error("safety namespace manifest field `{field}` is invalid")]
    InvalidField { field: &'static str },
    /// An entry of `safety_actions` is not a [`SafetyActionName`].
    #[error("safety_actions[{index}] is invalid: {error}")]
    InvalidSafetyName {
        index: usize,
        error: SafetyNameError,
    },
    /// `safety_actions` is not sorted by byte value, or repeats a name.
    #[error("safety_actions must be sorted by byte value without duplicates")]
    SafetyActionsNotCanonical,
    /// `safety_actions` has more than `MAX_ACTION_CLASSES` entries.
    #[error("safety_actions has more than {max} entries")]
    TooManySafetyActions { max: usize },
    /// The manifest's `key_id` is not the id of the pinned key.
    #[error("safety namespace manifest key_id does not match the pinned key")]
    KeyIdMismatch,
    /// The signature does not verify under the pinned key and
    /// [`SAFETY_NAMESPACE_DOMAIN`].
    #[error("safety namespace manifest signature is invalid")]
    SignatureInvalid,
    /// The policy to build from, or to check against, is not a valid
    /// format 2 policy. `code` is its [`crate::PraetoreError::code`].
    #[error("policy rejected ({code}): {reason}")]
    PolicyRejected { code: &'static str, reason: String },
    /// The manifest was not derived from the given policy.
    #[error("safety namespace manifest does not match the policy: {field} differs")]
    PolicyMismatch { field: ManifestField },
}

impl SafetyNamespaceError {
    /// A stable machine code for command-line and API answers.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Json(_)
            | Self::Schema(_)
            | Self::InvalidField { .. }
            | Self::InvalidSafetyName { .. }
            | Self::SafetyActionsNotCanonical
            | Self::TooManySafetyActions { .. } => "SAFETY_MANIFEST_INVALID",
            Self::UnsupportedSchemaVersion { .. } => "SAFETY_MANIFEST_VERSION_UNSUPPORTED",
            Self::KeyIdMismatch => "SAFETY_MANIFEST_KEY_MISMATCH",
            Self::SignatureInvalid => "SAFETY_MANIFEST_SIGNATURE_INVALID",
            Self::PolicyRejected { code, .. } => code,
            Self::PolicyMismatch { .. } => "POLICY_MISMATCH",
        }
    }
}

fn policy_rejected(error: crate::PraetoreError) -> SafetyNamespaceError {
    SafetyNamespaceError::PolicyRejected {
        code: error.code(),
        reason: error.to_string(),
    }
}

/// The `Safety` names `policy` declares, sorted by byte value, without
/// duplicates. Validates the policy first.
fn declared_safety_actions(
    policy: &Policy,
) -> Result<(String, Vec<SafetyActionName>), SafetyNamespaceError> {
    let digest = policy.digest().map_err(policy_rejected)?;
    let mut names = BTreeSet::new();
    for (index, (action_type, class)) in policy.action_classes.iter().enumerate() {
        if *class == ActionClass::Safety {
            let name = SafetyActionName::parse(action_type)
                .map_err(|error| SafetyNamespaceError::InvalidSafetyName { index, error })?;
            names.insert(name);
        }
    }
    Ok((digest, names.into_iter().collect()))
}

/// A signed statement of the safety namespace of one format 2 policy
/// (schema version 1).
///
/// The file is the canonical JSON (keys sorted, no whitespace) of this
/// object:
///
/// | Field | Value |
/// | --- | --- |
/// | `schema_version` | `1` |
/// | `policy_digest` | the policy's digest (SHA-256 of its canonical JSON, lowercase hex) |
/// | `policy_id`, `policy_version` | the policy's `id` and `version` |
/// | `safety_actions` | every name the policy declares `Safety`, sorted by byte value, no duplicates |
/// | `issued_at` | RFC 3339 UTC, in the form `time` formats it (`Z`, fraction only when non-zero) |
/// | `key_id` | `hex(SHA-256(SAFETY_NAMESPACE_KEY_ID_DOMAIN \|\| public key))` |
/// | `signature` | `hex(Ed25519(SAFETY_NAMESPACE_DOMAIN \|\| canonical JSON of every other field))` |
///
/// The fields are private: a manifest is built only by [`Self::from_policy`]
/// or parsed by [`Self::from_json`], both of which validate it. Parsing does
/// not check the signature: call [`Self::verify`] with a pinned key before
/// relying on the content.
///
/// What a verified manifest shows: the holder of the namespace key stated
/// that the policy with this digest declares exactly these `Safety` names.
/// It authorizes nothing and is not read on the decision path.
///
/// ```
/// use praetore_core::{
///     ActionClass, NamespaceMembership, Policy, SafetyActionName, SafetyNamespaceKey,
///     SafetyNamespaceManifest,
/// };
/// use time::OffsetDateTime;
///
/// let policy = Policy::new_v2("operations", 3, vec![])
///     .with_action_class("safety:halt", ActionClass::Safety)
///     .with_action_class("safety:hold", ActionClass::Safety);
/// let key = SafetyNamespaceKey::from_secret_bytes(&[7; 32]);
/// let issued_at = OffsetDateTime::from_unix_timestamp(1_793_491_200).unwrap(); // 2026-11-01
/// let manifest = SafetyNamespaceManifest::from_policy(&policy, issued_at, &key).unwrap();
///
/// let parsed = SafetyNamespaceManifest::from_json(&manifest.to_json().unwrap()).unwrap();
/// parsed.verify(&key.public_key().unwrap()).unwrap();
/// parsed.verify_matches_policy(&policy).unwrap();
///
/// let halt = SafetyActionName::parse("safety:halt").unwrap();
/// let stop = SafetyActionName::parse("safety:stop_all").unwrap();
/// assert_eq!(parsed.classify_name(&halt), NamespaceMembership::Declared);
/// assert_eq!(parsed.classify_name(&stop), NamespaceMembership::Undeclared);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SafetyNamespaceManifest {
    schema_version: u8,
    policy_digest: String,
    policy_id: String,
    policy_version: u32,
    safety_actions: Vec<SafetyActionName>,
    issued_at: String,
    key_id: String,
    signature: String,
}

/// What is signed: every manifest field except `signature`.
#[derive(Serialize)]
struct SigningPayload<'a> {
    schema_version: u8,
    policy_digest: &'a str,
    policy_id: &'a str,
    policy_version: u32,
    safety_actions: &'a [SafetyActionName],
    issued_at: &'a str,
    key_id: &'a str,
}

/// The document as read, before validation. `safety_actions` stays text so
/// an invalid entry gets a typed error with its index.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    schema_version: u64,
    policy_digest: String,
    policy_id: String,
    policy_version: u32,
    safety_actions: Vec<String>,
    issued_at: String,
    key_id: String,
    signature: String,
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && decode_lower_hex(text).is_some()
}

/// `issued_at` in its single accepted form: UTC, formatted by `time`'s RFC
/// 3339 formatter.
fn format_issued_at(instant: OffsetDateTime) -> Result<String, SafetyNamespaceError> {
    instant
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| SafetyNamespaceError::InvalidField { field: "issued_at" })
}

fn check_issued_at(text: &str) -> Result<(), SafetyNamespaceError> {
    let invalid = SafetyNamespaceError::InvalidField { field: "issued_at" };
    let instant = OffsetDateTime::parse(text, &Rfc3339).map_err(|_| invalid.clone())?;
    if instant.offset() != UtcOffset::UTC || format_issued_at(instant)? != text {
        return Err(invalid);
    }
    Ok(())
}

impl SafetyNamespaceManifest {
    /// Builds and signs the manifest of `policy`. Deterministic: the same
    /// policy, instant and key give the same bytes (Ed25519 signatures are
    /// deterministic). Fails when `policy` is not a valid format 2 policy.
    pub fn from_policy(
        policy: &Policy,
        issued_at: OffsetDateTime,
        key: &SafetyNamespaceKey,
    ) -> Result<Self, SafetyNamespaceError> {
        let (policy_digest, safety_actions) = declared_safety_actions(policy)?;
        let mut manifest = Self {
            schema_version: SAFETY_NAMESPACE_SCHEMA_VERSION,
            policy_digest,
            policy_id: policy.id.clone(),
            policy_version: policy.version,
            safety_actions,
            issued_at: format_issued_at(issued_at)?,
            key_id: key.key_id(),
            signature: String::new(),
        };
        manifest.signature = hex::encode(key.sign(&manifest.signing_payload()?));
        // The file must be readable back by `from_json`.
        manifest.to_json()?;
        Ok(manifest)
    }

    /// Parses and validates a manifest document (strict JSON, no unknown
    /// fields, every field in its single valid form). Does not check the
    /// signature; see [`Self::verify`].
    pub fn from_json(text: &str) -> Result<Self, SafetyNamespaceError> {
        let value = parse_json_strict(text).map_err(SafetyNamespaceError::Json)?;
        let raw: RawManifest = serde_json::from_value(value)
            .map_err(|error| SafetyNamespaceError::Schema(error.to_string()))?;
        if raw.schema_version != u64::from(SAFETY_NAMESPACE_SCHEMA_VERSION) {
            return Err(SafetyNamespaceError::UnsupportedSchemaVersion {
                found: raw.schema_version,
            });
        }
        let invalid = |field| SafetyNamespaceError::InvalidField { field };
        if !is_lower_hex(&raw.policy_digest, 64) {
            return Err(invalid("policy_digest"));
        }
        if raw.policy_id.trim().is_empty()
            || raw.policy_id != raw.policy_id.trim()
            || raw.policy_id.len() > MAX_POLICY_TEXT_BYTES
        {
            return Err(invalid("policy_id"));
        }
        if raw.policy_version == 0 {
            return Err(invalid("policy_version"));
        }
        if raw.safety_actions.len() > MAX_ACTION_CLASSES {
            return Err(SafetyNamespaceError::TooManySafetyActions {
                max: MAX_ACTION_CLASSES,
            });
        }
        let mut safety_actions = Vec::with_capacity(raw.safety_actions.len());
        for (index, name) in raw.safety_actions.iter().enumerate() {
            let name = SafetyActionName::parse(name)
                .map_err(|error| SafetyNamespaceError::InvalidSafetyName { index, error })?;
            if safety_actions
                .last()
                .is_some_and(|previous| *previous >= name)
            {
                return Err(SafetyNamespaceError::SafetyActionsNotCanonical);
            }
            safety_actions.push(name);
        }
        check_issued_at(&raw.issued_at)?;
        if !is_lower_hex(&raw.key_id, 64) {
            return Err(invalid("key_id"));
        }
        if !is_canonical_signature_hex(&raw.signature) {
            return Err(invalid("signature"));
        }
        Ok(Self {
            schema_version: SAFETY_NAMESPACE_SCHEMA_VERSION,
            policy_digest: raw.policy_digest,
            policy_id: raw.policy_id,
            policy_version: raw.policy_version,
            safety_actions,
            issued_at: raw.issued_at,
            key_id: raw.key_id,
            signature: raw.signature,
        })
    }

    /// The canonical JSON of the whole manifest: the bytes of a manifest
    /// file (the CLI adds a final newline).
    pub fn to_json(&self) -> Result<String, SafetyNamespaceError> {
        let bytes = canonical_json(self).map_err(SafetyNamespaceError::Json)?;
        if bytes.len() > MAX_JSON_VALUE_BYTES {
            return Err(SafetyNamespaceError::Json(JsonError::CanonicalTooLarge));
        }
        String::from_utf8(bytes).map_err(|_| SafetyNamespaceError::Json(JsonError::Unrepresentable))
    }

    /// The signed bytes, without the domain: the canonical JSON of every
    /// field except `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>, SafetyNamespaceError> {
        canonical_json(&SigningPayload {
            schema_version: self.schema_version,
            policy_digest: &self.policy_digest,
            policy_id: &self.policy_id,
            policy_version: self.policy_version,
            safety_actions: &self.safety_actions,
            issued_at: &self.issued_at,
            key_id: &self.key_id,
        })
        .map_err(SafetyNamespaceError::Json)
    }

    /// Checks that `key_id` is the id of `pin` and that the signature
    /// verifies under `pin` and [`SAFETY_NAMESPACE_DOMAIN`] (strict
    /// Ed25519).
    pub fn verify(&self, pin: &VerifiedPublicKey) -> Result<(), SafetyNamespaceError> {
        if self.key_id != safety_namespace_key_id(pin) {
            return Err(SafetyNamespaceError::KeyIdMismatch);
        }
        let signature =
            decode_lower_hex(&self.signature).ok_or(SafetyNamespaceError::SignatureInvalid)?;
        pin.verify_domain_message(
            SAFETY_NAMESPACE_DOMAIN,
            &self.signing_payload()?,
            &signature,
        )
        .map_err(|_| SafetyNamespaceError::SignatureInvalid)
    }

    /// Checks that this manifest was derived from `policy`: same id,
    /// version and digest, and exactly the same `Safety` names. Does not
    /// check the signature; see [`Self::verify`].
    pub fn verify_matches_policy(&self, policy: &Policy) -> Result<(), SafetyNamespaceError> {
        let (digest, safety_actions) = declared_safety_actions(policy)?;
        let mismatch = |field| Err(SafetyNamespaceError::PolicyMismatch { field });
        if self.policy_id != policy.id {
            return mismatch(ManifestField::PolicyId);
        }
        if self.policy_version != policy.version {
            return mismatch(ManifestField::PolicyVersion);
        }
        if self.policy_digest != digest {
            return mismatch(ManifestField::PolicyDigest);
        }
        if self.safety_actions != safety_actions {
            return mismatch(ManifestField::SafetyActions);
        }
        Ok(())
    }

    /// Whether `name` is one of the declared `Safety` names. Never an
    /// error: an undeclared name is reported as
    /// [`NamespaceMembership::Undeclared`] so it can be recorded, not
    /// dropped. Only meaningful on a manifest that passed [`Self::verify`].
    pub fn classify_name(&self, name: &SafetyActionName) -> NamespaceMembership {
        if self.safety_actions.binary_search(name).is_ok() {
            NamespaceMembership::Declared
        } else {
            NamespaceMembership::Undeclared
        }
    }

    pub fn schema_version(&self) -> u8 {
        self.schema_version
    }

    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub fn policy_version(&self) -> u32 {
        self.policy_version
    }

    /// Sorted by byte value, without duplicates.
    pub fn safety_actions(&self) -> &[SafetyActionName] {
        &self.safety_actions
    }

    pub fn issued_at(&self) -> &str {
        &self.issued_at
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::new_v2("p", 1, vec![])
            .with_action_class("safety:hold", ActionClass::Safety)
            .with_action_class("safety:halt", ActionClass::Safety)
            .with_mission_actions(["fs:write_file"])
    }

    fn key() -> SafetyNamespaceKey {
        SafetyNamespaceKey::from_secret_bytes(&[9; 32])
    }

    fn manifest() -> SafetyNamespaceManifest {
        let issued_at = OffsetDateTime::from_unix_timestamp(1_793_534_400).unwrap();
        SafetyNamespaceManifest::from_policy(&policy(), issued_at, &key()).unwrap()
    }

    /// A reordered list that bypasses `from_json`'s order check is still
    /// refused: the order is part of the signed bytes.
    #[test]
    fn a_reordered_list_does_not_verify_even_when_parsing_is_bypassed() {
        let mut manifest = manifest();
        manifest.safety_actions.reverse();
        assert_eq!(
            manifest.verify(&key().public_key().unwrap()),
            Err(SafetyNamespaceError::SignatureInvalid)
        );
    }

    #[test]
    fn a_dropped_or_added_name_does_not_verify_even_when_parsing_is_bypassed() {
        let pin = key().public_key().unwrap();
        let mut dropped = manifest();
        dropped.safety_actions.pop();
        assert_eq!(
            dropped.verify(&pin),
            Err(SafetyNamespaceError::SignatureInvalid)
        );
        let mut added = manifest();
        added
            .safety_actions
            .push(SafetyActionName::parse("safety:stop_all").unwrap());
        assert_eq!(
            added.verify(&pin),
            Err(SafetyNamespaceError::SignatureInvalid)
        );
    }

    #[test]
    fn issued_at_has_a_single_accepted_form() {
        assert!(check_issued_at("2026-11-01T12:00:00Z").is_ok());
        assert!(check_issued_at("2026-11-01T12:00:00.5Z").is_ok());
        for text in [
            "2026-11-01T12:00:00+00:00",
            "2026-11-01T13:00:00+01:00",
            "2026-11-01T12:00:00.000Z",
            "2026-11-01t12:00:00z",
            "2026-11-01 12:00:00Z",
            "",
        ] {
            assert!(check_issued_at(text).is_err(), "{text}");
        }
    }

    #[test]
    fn mentions_safety_is_ascii_case_insensitive_only() {
        for name in ["safety:x", "SAFETY", "ops:skip_SaFeTy", "unsafety"] {
            assert!(mentions_safety(name), "{name}");
        }
        for name in ["saf", "s\u{430}fety", "\u{ff53}afety", "safe_ty", ""] {
            assert!(!mentions_safety(name), "{name}");
        }
    }
}
