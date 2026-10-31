//! Evaluates one MCP `tools/call` with the PRÆTORE HighAssurance engine and
//! appends the attested evidence to the receipts journal.

use crate::store::{self, ACTION_TYPE, AUDIENCE, CAPABILITY, Home, LoadedHome};
use praetore_core::{
    Action, AgentIdentity, AgentKeyPair, Authority, AuthorizationRequest, DecisionOutcome,
    Evidence, FreshnessError, FreshnessLease, FreshnessProvider, HighAssuranceConfig,
    MatchOperator, Policy, ReplayGuard, ReplayGuardError, authority::AuthorityId,
    engine::AuthorizationEngine, identity::AgentKeyFingerprint,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use time::{Duration, OffsetDateTime};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

/// Context key binding the proxy mode into the signed intent and evidence.
pub const MODE_CONTEXT_KEY: &str = "praetore.mode";
/// Context key naming the component that produced the request.
pub const PROXY_CONTEXT_KEY: &str = "praetore.proxy";
/// Context key recording, for each argument a `PathPrefix` rule covers, the
/// value the client sent, the value it resolves to and the check result.
pub const PATH_CHECK_CONTEXT_KEY: &str = "praetore.path_check";
/// Value the engine sees instead of a path that does not resolve to itself.
/// It is not absolute, so core's `PathPrefix` treats it as unsafe: it
/// matches every DENY / REQUIRE_APPROVAL `PathPrefix` rule and no ALLOW one.
pub const UNRESOLVED_PATH: &str = "praetore-mcp:path-check-failed";
/// Maximum canonical size of `arguments` (and the flattened copies) kept
/// inline in the action. Larger arguments are replaced by their SHA-256 so
/// a receipt always stays below the 64 KiB evidence limit.
pub const MAX_INLINE_ARGUMENTS_BYTES: usize = 8 * 1024;
const MAX_INLINE_TOOL_BYTES: usize = 512;
const INTENT_LIFETIME: Duration = Duration::seconds(60);
const MAX_REPLAY_CLAIMS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Observe,
    Enforce,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Observe => "observe",
            Mode::Enforce => "enforce",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "observe" => Some(Mode::Observe),
            "enforce" => Some(Mode::Enforce),
            _ => None,
        }
    }
}

/// Result of a successful evaluation.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub outcome: DecisionOutcome,
    pub evidence_id: Uuid,
    pub rule_ids: Vec<String>,
    pub reason: String,
    /// Whether the evidence reached the journal (fsynced).
    pub journaled: Result<PathBuf, String>,
}

/// Anything that can evaluate a `tools/call`. The proxy logic is generic over
/// this so it can be unit-tested without keys.
pub trait Evaluator {
    fn evaluate(&mut self, server: &str, params: &Value) -> Result<Verdict, String>;
}

/// Builds the action parameters for a `tools/call`.
///
/// `server`, `tool` and `arguments` are always present (missing values are
/// JSON `null`). Top-level argument keys are also copied as
/// `arguments.<key>`, because policy conditions only address top-level
/// parameter keys. Oversized values are replaced by digests; v2 policy
/// semantics then treat conditions on the missing keys as unknown, which
/// matches DENY / REQUIRE_APPROVAL rules and never an ALLOW rule (fail-safe).
///
/// `digest_only` forces the digest form; it is used when the inline form is
/// rejected by core validation (depth, unsafe integers, node count).
pub fn build_parameters(server: &str, params: &Value, digest_only: bool) -> Value {
    let tool = params.get("name").cloned().unwrap_or(Value::Null);
    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
    let mut out = Map::new();
    out.insert("server".into(), Value::String(server.to_owned()));

    let tool_bytes = serde_json::to_vec(&tool).unwrap_or_default();
    if !digest_only && tool_bytes.len() <= MAX_INLINE_TOOL_BYTES {
        out.insert("tool".into(), tool);
    } else {
        out.insert("tool_sha256".into(), Value::String(sha256_hex(&tool_bytes)));
        out.insert("tool_omitted".into(), Value::Bool(true));
    }

    let argument_bytes = serde_json::to_vec(&arguments).unwrap_or_default();
    if !digest_only && argument_bytes.len() <= MAX_INLINE_ARGUMENTS_BYTES {
        if let Value::Object(entries) = &arguments {
            for (key, value) in entries {
                out.insert(format!("arguments.{key}"), value.clone());
            }
        }
        out.insert("arguments".into(), arguments);
    } else {
        out.insert(
            "arguments_sha256".into(),
            Value::String(sha256_hex(&argument_bytes)),
        );
        out.insert("arguments_bytes".into(), json!(argument_bytes.len()));
        out.insert("arguments_omitted".into(), Value::Bool(true));
    }
    Value::Object(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// In-process replay guard. Request IDs are fresh UUIDv4s minted by this
/// proxy; the guard rejects reuse within the process and fails closed when
/// full instead of evicting. It is not durable across restarts (see README).
#[derive(Default)]
struct MemoryReplayGuard(Mutex<HashSet<(Uuid, Uuid, Uuid)>>);

impl ReplayGuard for MemoryReplayGuard {
    fn claim_once(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        request_id: Uuid,
    ) -> Result<(), ReplayGuardError> {
        let mut claims = self.0.lock().map_err(|_| ReplayGuardError::Unavailable)?;
        if claims.len() >= MAX_REPLAY_CLAIMS {
            return Err(ReplayGuardError::Unavailable);
        }
        if claims.insert((tenant_id, agent_id, request_id)) {
            Ok(())
        } else {
            Err(ReplayGuardError::AlreadyClaimed)
        }
    }
}

/// Local freshness: there is no revocation source for LOCAL/DEV keys, so it
/// grants a one-minute lease. It still rejects malformed authority digests.
struct LocalFreshness;

impl FreshnessProvider for LocalFreshness {
    fn check(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &AuthorityId,
        _policy_digest: &str,
        _now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        Err(FreshnessError::InvalidResponse)
    }

    fn check_authority(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &AuthorityId,
        authority_digest: &str,
        _policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        if authority_digest.len() != 64 {
            return Err(FreshnessError::InvalidResponse);
        }
        Ok(FreshnessLease {
            valid_until: now + Duration::minutes(1),
        })
    }
}

pub struct Gate {
    engine: AuthorizationEngine,
    agent_key: AgentKeyPair,
    agent: AgentIdentity,
    authority: Authority,
    policy_digest: String,
    mode: Mode,
    journal: Journal,
    /// Parameter keys used by `PathPrefix` conditions (T-014).
    path_keys: BTreeSet<String>,
    /// Expected values of those conditions, for the case/normalization check.
    path_prefixes: BTreeSet<String>,
}

/// Parameter keys that some rule matches with `PathPrefix`.
pub fn path_prefix_keys(policy: &Policy) -> BTreeSet<String> {
    policy
        .rules
        .iter()
        .flat_map(|rule| &rule.parameter_conditions)
        .filter(|condition| condition.operator == MatchOperator::PathPrefix)
        .map(|condition| condition.key.clone())
        .collect()
}

/// Expected values of every `PathPrefix` condition, whatever its key.
pub fn path_prefix_values(policy: &Policy) -> BTreeSet<String> {
    policy
        .rules
        .iter()
        .flat_map(|rule| &rule.parameter_conditions)
        .filter(|condition| condition.operator == MatchOperator::PathPrefix)
        .filter_map(|condition| condition.expected.as_str().map(str::to_owned))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathCheck {
    /// The path resolves to itself (no symlink, `.` or `..` on the way).
    Same,
    /// The path resolves to another path (a symlink, `..`, a trailing `/.`).
    Differs,
    /// The path or its parent does not exist, is a dangling symlink, or is
    /// not UTF-8: it cannot be resolved now.
    Unresolved,
    /// The path resolves to itself, but it may name an entry at or under a
    /// policy `PathPrefix` that it does not match byte for byte: on a
    /// filesystem that ignores case or Unicode normalization (see
    /// [`folds_into_prefix`]), or through another spelling of the same
    /// directory, such as a macOS firmlink (see [`aliases_prefix`]).
    Ambiguous,
}

impl PathCheck {
    fn as_str(self) -> &'static str {
        match self {
            Self::Same => "same",
            Self::Differs => "differs",
            Self::Unresolved => "unresolved",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// Resolves an absolute path through the filesystem. A missing final
/// component is allowed (a file about to be created) if its parent resolves
/// and nothing, not even a dangling symlink, exists at that name.
pub fn resolve_path(lexical: &str) -> (PathCheck, Option<String>) {
    let path = Path::new(lexical);
    let resolved = match fs::canonicalize(path) {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
                return (PathCheck::Unresolved, None);
            };
            if fs::symlink_metadata(path).is_ok() {
                return (PathCheck::Unresolved, None);
            }
            match fs::canonicalize(parent) {
                Ok(parent) => parent.join(name),
                Err(_) => return (PathCheck::Unresolved, None),
            }
        }
        Err(_) => return (PathCheck::Unresolved, None),
    };
    let Ok(resolved) = resolved.into_os_string().into_string() else {
        return (PathCheck::Unresolved, None);
    };
    let normalized = match lexical.strip_suffix('/') {
        Some(stripped) if !stripped.is_empty() => stripped,
        _ => lexical,
    };
    let check = if normalized == resolved {
        PathCheck::Same
    } else {
        PathCheck::Differs
    };
    (check, Some(resolved))
}

/// How a directory compares the names in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insensitivity {
    /// `a` and `A` name the same entry.
    pub case: bool,
    /// Canonically equivalent Unicode strings (NFC `é`, NFD `e\u{301}`)
    /// name the same entry.
    pub normalization: bool,
}

impl Insensitivity {
    pub const NONE: Self = Self {
        case: false,
        normalization: false,
    };
    pub const FULL: Self = Self {
        case: true,
        normalization: true,
    };
}

/// Bound on fold rounds; every scalar reaches a fixed point well within it
/// (checked over all of Unicode by
/// `fold_key_is_idempotent_and_covers_every_mapping`).
const MAX_FOLD_ROUNDS: usize = 8;

/// Comparison key of a name under `mode`.
///
/// Case: Unicode full case folding (CaseFolding.txt, status C+F, via
/// `caseless`) and then upper- followed by lower-casing, repeated until the
/// key stops changing, so `ẞ`, `ß`, `ss` and `SS` share a key. With
/// normalization, every round works on NFD and the key is NFC: this contains
/// the canonical caseless match of Unicode D145 (`NFD(toCasefold(NFD(x)))`)
/// and is deliberately broader than any filesystem's folding (it also
/// merges `ı`/`I` and `İ`/`i`); a wider fold can only turn more paths into
/// [`PathCheck::Ambiguous`]. When case is folded, trailing `.` and ` ` are
/// dropped too (vfat/exfat on Linux ignore them; macOS FAT does not, which
/// only costs a few extra refusals there and on case-insensitive APFS).
fn fold_key(name: &str, mode: Insensitivity) -> String {
    // ASCII fast path, exact: NFC/NFD are the identity on ASCII and full
    // case folding of ASCII is `to_ascii_lowercase` (checked against the
    // slow path by `fold_key_is_idempotent_and_covers_every_mapping`).
    if name.is_ascii() {
        return if mode.case {
            name.to_ascii_lowercase()
                .trim_end_matches(['.', ' '])
                .to_owned()
        } else {
            name.to_owned()
        };
    }
    fold_key_slow(name, mode)
}

fn fold_key_slow(name: &str, mode: Insensitivity) -> String {
    let normalize = |text: String| -> String {
        if mode.normalization {
            text.nfd().collect()
        } else {
            text
        }
    };
    let mut key = normalize(name.to_owned());
    if mode.case {
        for _ in 0..MAX_FOLD_ROUNDS {
            let folded = normalize(caseless::default_case_fold_str(&key));
            let next = normalize(
                folded
                    .chars()
                    .flat_map(char::to_uppercase)
                    .flat_map(char::to_lowercase)
                    .collect(),
            );
            if next == key {
                break;
            }
            key = next;
        }
    }
    let key: String = if mode.normalization {
        key.nfc().collect()
    } else {
        key
    };
    // vfat/exfat on Linux (and Windows) drop trailing dots and spaces when
    // looking a name up; fold them on every case-folding filesystem.
    if mode.case {
        key.trim_end_matches(['.', ' ']).to_owned()
    } else {
        key
    }
}

fn segments(path: &str) -> Vec<&str> {
    let body = path.strip_prefix('/').unwrap_or(path);
    let body = body.strip_suffix('/').unwrap_or(body);
    if body.is_empty() {
        Vec::new()
    } else {
        body.split('/').collect()
    }
}

/// Returns a `prefix` that `path` is at or under once names are compared
/// the way the filesystem compares them, but not byte for byte; core's
/// lexical `PathPrefix` would then miss a path the filesystem treats as
/// inside the prefix. Each differing segment is compared with the
/// sensitivity of the directory that holds it, as reported by
/// `insensitivity` (queried only for names equal under full folding).
pub fn folds_into_prefix<'a>(
    path: &str,
    prefixes: &'a BTreeSet<String>,
    insensitivity: impl Fn(&str) -> Insensitivity,
) -> Option<&'a str> {
    let path_segments = segments(path);
    prefixes.iter().map(String::as_str).find(|prefix| {
        let prefix_segments = segments(prefix);
        if !prefix.starts_with('/') || prefix_segments.len() > path_segments.len() {
            return false;
        }
        let mut differs = false;
        for (index, (name, expected)) in path_segments.iter().zip(&prefix_segments).enumerate() {
            if name == expected {
                continue;
            }
            if fold_key(name, Insensitivity::FULL) != fold_key(expected, Insensitivity::FULL) {
                return false;
            }
            let dir = format!("/{}", path_segments[..index].join("/"));
            let mode = insensitivity(&dir);
            if fold_key(name, mode) != fold_key(expected, mode) {
                return false;
            }
            differs = true;
        }
        differs
    })
}

fn join_segments(segments: &[&str]) -> String {
    format!("/{}", segments.join("/"))
}

/// `(st_dev, st_ino)` of what `path` names, following symlinks.
#[cfg(unix)]
fn file_id(path: &str) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path)
        .ok()
        .map(|metadata| (metadata.dev(), metadata.ino()))
}

/// No portable identity outside Unix: the alias check is skipped there.
#[cfg(not(unix))]
fn file_id(_path: &str) -> Option<(u64, u64)> {
    None
}

/// Per-call memo of [`file_id`]: policy prefixes usually share ancestors.
#[derive(Default)]
struct FileIds(std::cell::RefCell<std::collections::HashMap<String, Option<(u64, u64)>>>);

impl FileIds {
    fn get(&self, path: &str) -> Option<(u64, u64)> {
        if let Some(id) = self.0.borrow().get(path) {
            return *id;
        }
        let id = file_id(path);
        self.0.borrow_mut().insert(path.to_owned(), id);
        id
    }

    /// Depth and identity of the deepest existing ancestor-or-self of
    /// `segments`, walking down from `/` and stopping at the first that
    /// cannot be `stat`ed (nothing below it can be either).
    fn deepest(&self, segments: &[&str]) -> Option<(usize, (u64, u64))> {
        let mut found = None;
        for depth in 0..=segments.len() {
            match self.get(&join_segments(&segments[..depth])) {
                Some(id) => found = Some((depth, id)),
                None => break,
            }
        }
        found
    }
}

/// Whether `path_segments` is at or under `prefix_segments` once each
/// differing name is compared the way its directory compares names.
fn under_prefix_folded(
    path_segments: &[&str],
    prefix_segments: &[&str],
    insensitivity: impl Fn(&str) -> Insensitivity,
) -> bool {
    path_segments.len() >= prefix_segments.len()
        && path_segments
            .iter()
            .zip(prefix_segments)
            .enumerate()
            .all(|(index, (name, expected))| {
                name == expected
                    || fold_key(name, Insensitivity::FULL)
                        == fold_key(expected, Insensitivity::FULL)
                        && {
                            let mode = insensitivity(&join_segments(&path_segments[..index]));
                            fold_key(name, mode) == fold_key(expected, mode)
                        }
            })
}

/// Returns a `prefix` that `path` reaches on disk under another spelling of
/// the prefix (or of one of its ancestors): a macOS firmlink
/// (`/System/Volumes/Data/Users/u` is `/Users/u`), a bind mount of the
/// prefix itself, a hard link to a file that is the prefix, or a prefix
/// written through a symlink. The deepest existing ancestor-or-self of the
/// prefix is compared by `(st_dev, st_ino)` with each existing
/// ancestor-or-self of `path`; on a match, the rest of `path` must start
/// with the prefix's missing tail (names compared as the directory compares
/// them). A `path` lexically at or under the prefix is left to core, which
/// already matches it. Aliases of a *descendant* of the prefix are the job
/// of [`firmlink_spelling_into_prefix`] (macOS) and are not detected for
/// Linux bind mounts of a subdirectory.
///
/// Cost per covered argument: one `stat` per ancestor of `path` and per
/// distinct ancestor of the prefixes (memoized for the call).
pub fn aliases_prefix<'a>(
    path: &str,
    prefixes: &'a BTreeSet<String>,
    insensitivity: impl Fn(&str) -> Insensitivity + Copy,
) -> Option<&'a str> {
    let ids = FileIds::default();
    let path_segments = segments(path);
    let mut ancestors: Option<Vec<Option<(u64, u64)>>> = None;
    prefixes.iter().map(String::as_str).find(|prefix| {
        let prefix_segments = segments(prefix);
        if !prefix.starts_with('/') || path_segments.starts_with(&prefix_segments) {
            return false;
        }
        let Some((depth, id)) = ids.deepest(&prefix_segments) else {
            return false;
        };
        let tail = &prefix_segments[depth..];
        let ancestors = ancestors.get_or_insert_with(|| {
            (0..=path_segments.len())
                .map(|depth| ids.get(&join_segments(&path_segments[..depth])))
                .collect()
        });
        ancestors.iter().enumerate().any(|(index, ancestor)| {
            let rest = &path_segments[index..];
            *ancestor == Some(id)
                && under_prefix_folded(rest, tail, |dir: &str| {
                    // `dir` is relative to the matching ancestor.
                    let base = join_segments(&path_segments[..index]);
                    insensitivity(&match (base.as_str(), dir) {
                        (_, "/") => base.clone(),
                        ("/", _) => dir.to_owned(),
                        _ => format!("{base}{dir}"),
                    })
                })
        })
    })
}

/// macOS data volume: firmlinked directories (`/usr/share/firmlinks`:
/// `/Users`, `/private`, `/usr/local`, `/System/Library/Caches`, ...) are
/// also reachable under it.
pub const MACOS_DATA_VOLUME: &str = "/System/Volumes/Data";

/// The other macOS spelling of `path`: with [`MACOS_DATA_VOLUME`] added or
/// removed, when the deepest existing ancestor-or-self of `path` is the same
/// `(st_dev, st_ino)` under both spellings (everything below it then is
/// too). `None` elsewhere, and for paths outside firmlinked directories.
pub fn firmlink_spelling(path: &str) -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let path_segments = segments(path);
    let ids = FileIds::default();
    let (depth, id) = ids.deepest(&path_segments)?;
    let existing = join_segments(&path_segments[..depth]);
    let (other, other_existing) = match path.strip_prefix(MACOS_DATA_VOLUME) {
        Some(rest) if rest.starts_with('/') => (
            rest.to_owned(),
            existing[MACOS_DATA_VOLUME.len()..].to_owned(),
        ),
        Some(_) => return None,
        None => (
            format!("{MACOS_DATA_VOLUME}{path}"),
            format!("{MACOS_DATA_VOLUME}{existing}"),
        ),
    };
    (!other_existing.is_empty() && file_id(&other_existing) == Some(id)).then_some(other)
}

/// Returns a `prefix` that the other macOS spelling of `path` (see
/// [`firmlink_spelling`]) is at or under, with names folded, while `path`
/// itself is not at or under it byte for byte. This catches what
/// [`aliases_prefix`] cannot: a prefix that contains the firmlink target,
/// such as DENY `/System/Volumes/Data` against `/Users/u/.ssh/x`, or DENY
/// `/usr` against `/System/Volumes/Data/usr/local/x`.
pub fn firmlink_spelling_into_prefix<'a>(
    path: &str,
    prefixes: &'a BTreeSet<String>,
    insensitivity: impl Fn(&str) -> Insensitivity + Copy,
) -> Option<&'a str> {
    let other = firmlink_spelling(path)?;
    let path_segments = segments(path);
    let other_segments = segments(&other);
    prefixes.iter().map(String::as_str).find(|prefix| {
        let prefix_segments = segments(prefix);
        prefix.starts_with('/')
            && !path_segments.starts_with(&prefix_segments)
            && under_prefix_folded(&other_segments, &prefix_segments, insensitivity)
    })
}

/// The `/System/Volumes/Data` spelling of a macOS firmlinked path (or any
/// path whose remainder is the same directory entry), for `policy check`.
pub fn firmlink_alias(prefix: &str) -> Option<String> {
    let rest = prefix.strip_prefix(MACOS_DATA_VOLUME)?;
    if !rest.starts_with('/') {
        return None;
    }
    let id = file_id(prefix)?;
    (file_id(rest) == Some(id)).then(|| rest.to_owned())
}

/// `policy check`: a prefix that is `/System`, `/System/Volumes`, or at or
/// under `/System/Volumes/Data` contains (or is) a firmlink target, so
/// arguments in the usual spelling (`/Users/...`, `/private/...`) are
/// `ambiguous` against it.
pub fn firmlink_prefix_warning(prefix: &str) -> Option<String> {
    let trimmed = match prefix.strip_suffix('/') {
        Some(stripped) if !stripped.is_empty() => stripped,
        _ => prefix,
    };
    let under_data =
        trimmed == MACOS_DATA_VOLUME || trimmed.starts_with(&format!("{MACOS_DATA_VOLUME}/"));
    if !(trimmed == "/System" || trimmed == "/System/Volumes" || under_data) {
        return None;
    }
    Some(match firmlink_alias(trimmed) {
        Some(alias) => format!(
            "is the macOS data-volume spelling of the firmlinked {alias:?}; clients use {alias:?}, which this rule treats as ambiguous (refused by DENY/REQUIRE_APPROVAL, never matched by ALLOW), so use {alias:?}"
        ),
        None => "contains macOS firmlink targets (/Users, /private, /usr/local, /System/Library/Caches, ... live on /System/Volumes/Data): arguments in their usual spelling are ambiguous against it (refused by DENY/REQUIRE_APPROVAL, never matched by ALLOW); write the rule on the usual spelling instead".to_owned(),
    })
}

/// Sensitivity of the filesystem holding `dir`. When it cannot be
/// established, the answer is [`Insensitivity::FULL`] (fail closed: at worst
/// a path that folds into a policy prefix is refused).
pub fn dir_insensitivity(dir: &str) -> Insensitivity {
    platform::dir_insensitivity(dir)
}

#[cfg(target_os = "macos")]
mod platform {
    use super::Insensitivity;
    use std::ffi::CString;

    /// APFS (both variants) and HFS+ ignore Unicode normalization; case
    /// sensitivity is per volume and `pathconf` reports it.
    pub fn dir_insensitivity(dir: &str) -> Insensitivity {
        let Ok(dir) = CString::new(dir) else {
            return Insensitivity::FULL;
        };
        // SAFETY: `dir` is a valid NUL-terminated string; `pathconf` only
        // reads it.
        let sensitive = unsafe { libc::pathconf(dir.as_ptr(), libc::_PC_CASE_SENSITIVE) };
        Insensitivity {
            case: sensitive != 1,
            normalization: true,
        }
    }
}

const EXT4_SUPER_MAGIC: u32 = 0xEF53;
const F2FS_SUPER_MAGIC: u32 = 0xF2F5_2010;
const TMPFS_MAGIC: u32 = 0x0102_1994;
#[cfg_attr(not(test), allow(dead_code))]
const XFS_SUPER_MAGIC: u32 = 0x5846_5342;
const BTRFS_SUPER_MAGIC: u32 = 0x9123_683E;

/// Linux decision from the `statfs` magic and the directory's casefold flag
/// (`None` when it could not be read). Only filesystems known to compare
/// names byte for byte are sensitive: btrfs, and ext4/f2fs/tmpfs
/// directories whose flags were read and lack `FS_CASEFOLD_FL`
/// (casefolded directories also normalize). Anything else (vfat, exfat,
/// ntfs, cifs, zfs, overlayfs..., or an unreadable flag) folds. XFS folds
/// too: a filesystem made with `mkfs.xfs -n version=ci` ignores ASCII case,
/// and telling it apart needs `XFS_IOC_FSGEOMETRY`, which is not probed.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_insensitivity(kind: u32, casefold: Option<bool>) -> Insensitivity {
    match (kind, casefold) {
        (BTRFS_SUPER_MAGIC, _) => Insensitivity::NONE,
        (EXT4_SUPER_MAGIC | F2FS_SUPER_MAGIC | TMPFS_MAGIC, Some(false)) => Insensitivity::NONE,
        _ => Insensitivity::FULL,
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{Insensitivity, linux_insensitivity};
    use std::{
        ffi::CString,
        fs::OpenOptions,
        os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    };

    /// `FS_CASEFOLD_FL` in `linux/fs.h`.
    const FS_CASEFOLD_FL: libc::c_int = 0x4000_0000;

    pub fn dir_insensitivity(dir: &str) -> Insensitivity {
        let Ok(path) = CString::new(dir) else {
            return Insensitivity::FULL;
        };
        // SAFETY: `statfs` is plain old data; all-zero is a valid value.
        let mut stats: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: `path` is NUL-terminated and outlives the call; `stats`
        // is a valid, exclusive out pointer of the type libc declares.
        if unsafe { libc::statfs(path.as_ptr(), &mut stats) } != 0 {
            return Insensitivity::FULL;
        }
        // `f_type` is i64, u32 or i32 depending on the target; every magic
        // fits in the low 32 bits.
        #[allow(clippy::unnecessary_cast)]
        let kind = stats.f_type as u32;
        linux_insensitivity(kind, casefold(dir))
    }

    /// The directory's `FS_CASEFOLD_FL`, or `None` when it cannot be read
    /// (open or ioctl failure, including old kernels): the caller folds.
    fn casefold(dir: &str) -> Option<bool> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(dir)
            .ok()?;
        // The kernel writes an `int` (`put_user(flags, (int __user *)arg)`)
        // although the request number is declared with `long`: a `c_long`
        // buffer would put the flag in the wrong half on big-endian targets.
        let mut flags: libc::c_int = 0;
        // SAFETY: the fd is open for the whole call and `flags` is a valid,
        // exclusive pointer to the `int` the kernel writes.
        let result = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                libc::FS_IOC_GETFLAGS,
                &mut flags as *mut libc::c_int,
            )
        };
        (result == 0).then_some(flags & FS_CASEFOLD_FL != 0)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::Insensitivity;

    /// No sensitivity probe here (Windows NTFS is case-insensitive by
    /// default): fold everything.
    pub fn dir_insensitivity(_dir: &str) -> Insensitivity {
        Insensitivity::FULL
    }
}

/// T-014: `PathPrefix` in core is lexical by design. Before evaluation, each
/// absolute string argument under `keys` is resolved; unless it resolves to
/// itself, the engine sees [`UNRESOLVED_PATH`] instead (fail closed). A path
/// that resolves to itself but names an entry at or under one of `prefixes`
/// without matching it byte for byte (case or normalization variants, a
/// firmlink, bind mount or other alias of the same directory) is
/// [`PathCheck::Ambiguous`] and hidden too. The bytes
/// forwarded to the server are never changed, so the engine either sees
/// exactly those bytes or the sentinel. Returns the record for
/// [`PATH_CHECK_CONTEXT_KEY`], or `None` when no covered argument is present.
pub fn check_paths(
    parameters: &mut Value,
    keys: &BTreeSet<String>,
    prefixes: &BTreeSet<String>,
) -> Option<Value> {
    check_paths_with(parameters, keys, prefixes, dir_insensitivity)
}

fn check_paths_with(
    parameters: &mut Value,
    keys: &BTreeSet<String>,
    prefixes: &BTreeSet<String>,
    insensitivity: impl Fn(&str) -> Insensitivity + Copy,
) -> Option<Value> {
    let mut record = Map::new();
    for key in keys {
        let Some(Value::String(lexical)) = parameters.get(key) else {
            continue;
        };
        // Relative and other non-absolute values are already unsafe for
        // core's `PathPrefix`; there is nothing to resolve.
        if !lexical.starts_with('/') {
            continue;
        }
        let lexical = lexical.clone();
        let (mut check, resolved) = resolve_path(&lexical);
        if check == PathCheck::Same
            && (folds_into_prefix(&lexical, prefixes, insensitivity).is_some()
                || aliases_prefix(&lexical, prefixes, insensitivity).is_some()
                || firmlink_spelling_into_prefix(&lexical, prefixes, insensitivity).is_some())
        {
            check = PathCheck::Ambiguous;
        }
        if check != PathCheck::Same {
            parameters[key.as_str()] = Value::String(UNRESOLVED_PATH.into());
        }
        record.insert(
            key.clone(),
            json!({"lexical": lexical, "resolved": resolved, "status": check.as_str()}),
        );
    }
    (!record.is_empty()).then_some(Value::Object(record))
}

impl Gate {
    pub fn load(home: &Home, mode: Mode) -> Result<Self, String> {
        let LoadedHome {
            agent_key,
            agent,
            authority,
            attester_key,
            issuer_pins,
            policy,
            ..
        } = store::load(home)?;
        let policy_digest = policy.digest().map_err(|e| format!("policy digest: {e}"))?;
        let path_keys = path_prefix_keys(&policy);
        let path_prefixes = path_prefix_values(&policy);
        let config = HighAssuranceConfig::new(policy_digest.clone(), issuer_pins, attester_key)
            .map_err(|e| format!("HighAssurance config: {e}"))?
            .with_audience(AUDIENCE)
            .with_replay_guard(Arc::new(MemoryReplayGuard::default()))
            .with_freshness_provider(Arc::new(LocalFreshness));
        let engine = AuthorizationEngine::production(policy, config)
            .map_err(|e| format!("cannot start HighAssurance engine ({}): {e}", e.code()))?;
        Ok(Self {
            engine,
            agent_key,
            agent,
            authority,
            policy_digest,
            mode,
            journal: Journal::new(home.receipts_dir()),
            path_keys,
            path_prefixes,
        })
    }

    /// Evaluates and returns the attested evidence without journaling it.
    pub fn evaluate_evidence(&self, server: &str, params: &Value) -> Result<Evidence, String> {
        let target = Some(server.to_owned());
        let mut path_check = None;
        let mut inline = build_parameters(server, params, false);
        if !self.path_keys.is_empty() {
            path_check = check_paths(&mut inline, &self.path_keys, &self.path_prefixes);
        }
        let action = Action::new(ACTION_TYPE, target.clone(), inline)
            .or_else(|_| {
                // The digest form has no `arguments.<key>` copies, so no path
                // is checked; conditions on them are unknown (fail closed).
                path_check = None;
                Action::new(ACTION_TYPE, target, build_parameters(server, params, true))
            })
            .map_err(|e| format!("{}: {e}", e.code()))?
            .with_capability(CAPABILITY);
        let mut request =
            AuthorizationRequest::new(self.agent.clone(), self.authority.clone(), action)
                .map_err(|e| format!("{}: {e}", e.code()))?
                .with_context(MODE_CONTEXT_KEY, Value::String(self.mode.as_str().into()))
                .with_context(
                    PROXY_CONTEXT_KEY,
                    Value::String(concat!("praetore-mcp/", env!("CARGO_PKG_VERSION")).into()),
                );
        if let Some(record) = path_check {
            request = request.with_context(PATH_CHECK_CONTEXT_KEY, record);
        }
        let now = OffsetDateTime::now_utc();
        request
            .sign_intent_v2(
                &self.agent_key,
                AUDIENCE,
                now,
                now + INTENT_LIFETIME,
                self.policy_digest.clone(),
            )
            .map_err(|e| format!("{}: {e}", e.code()))?;
        self.engine
            .evaluate(request)
            .map_err(|e| format!("{}: {e}", e.code()))
    }
}

impl Evaluator for Gate {
    fn evaluate(&mut self, server: &str, params: &Value) -> Result<Verdict, String> {
        let evidence = self.evaluate_evidence(server, params)?;
        let journaled = self.journal.append(&evidence);
        Ok(verdict_from(&evidence, journaled))
    }
}

pub fn verdict_from(evidence: &Evidence, journaled: Result<PathBuf, String>) -> Verdict {
    let outcome = evidence.decision.outcome;
    Verdict {
        outcome,
        evidence_id: evidence.evidence_id,
        rule_ids: evidence
            .decision
            .contributions
            .iter()
            .filter(|c| c.outcome == outcome)
            .map(|c| c.rule_id.clone())
            .collect(),
        reason: evidence.decision.reason.clone(),
        journaled,
    }
}

/// Append-only JSONL journal: `receipts/<UTC date>.jsonl`, one canonical
/// evidence document per line, fsynced after each write.
pub struct Journal {
    dir: PathBuf,
}

impl Journal {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn path_for(&self, now: OffsetDateTime) -> PathBuf {
        let date = now.date();
        self.dir.join(format!(
            "{:04}-{:02}-{:02}.jsonl",
            date.year(),
            u8::from(date.month()),
            date.day()
        ))
    }

    pub fn append(&self, evidence: &Evidence) -> Result<PathBuf, String> {
        let mut line = evidence
            .to_json()
            .map_err(|e| format!("cannot serialize evidence: {e}"))?;
        line.push('\n');
        store::ensure_dir(&self.dir, false)?;
        let path = self.path_for(OffsetDateTime::now_utc());
        if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(format!(
                "{} is a symlink; refusing to append",
                path.display()
            ));
        }
        append_line(&path, line.as_bytes())
            .map_err(|e| format!("cannot append to {}: {e}", path.display()))?;
        Ok(path)
    }
}

fn append_line(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    // One write per line keeps concurrent wrappers (one per server) from
    // interleaving within a line on local filesystems with O_APPEND.
    file.write_all(bytes)?;
    file.sync_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A canonical temporary root (macOS `/var` is a symlink to `/private/var`).
    fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        (temp, root)
    }

    fn text(path: &Path) -> String {
        path.to_str().unwrap().to_owned()
    }

    #[cfg(unix)]
    #[test]
    fn resolve_path_detects_symlinks_and_missing_parents() {
        use std::os::unix::fs::symlink;
        let (_temp, root) = canonical_tempdir();
        let sandbox = root.join("sandbox");
        let outside = root.join("outside");
        fs::create_dir_all(&sandbox).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(sandbox.join("file"), b"x").unwrap();
        fs::write(outside.join("secret"), b"s").unwrap();
        symlink(outside.join("secret"), sandbox.join("link")).unwrap();
        symlink(&outside, sandbox.join("dirlink")).unwrap();
        symlink(outside.join("missing"), sandbox.join("dangling")).unwrap();

        let same = |path: PathBuf| {
            let (check, resolved) = resolve_path(&text(&path));
            assert_eq!(check, PathCheck::Same, "{}", path.display());
            assert_eq!(resolved.as_deref(), Some(text(&path).as_str()));
        };
        same(sandbox.join("file"));
        same(sandbox.join("new-file"));
        same(sandbox.clone());
        assert_eq!(
            resolve_path(&format!("{}/", text(&sandbox))).0,
            PathCheck::Same
        );

        let (check, resolved) = resolve_path(&text(&sandbox.join("link")));
        assert_eq!(check, PathCheck::Differs);
        assert_eq!(resolved, Some(text(&outside.join("secret"))));
        // A new file under a symlinked directory resolves outside too.
        let (check, resolved) = resolve_path(&text(&sandbox.join("dirlink").join("new")));
        assert_eq!(check, PathCheck::Differs);
        assert_eq!(resolved, Some(text(&outside.join("new"))));
        assert_eq!(
            resolve_path(&format!("{}/../outside/secret", text(&sandbox))).0,
            PathCheck::Differs
        );

        for path in [
            sandbox.join("dangling"),
            sandbox.join("no-dir").join("file"),
            sandbox.join("file").join("under-a-file"),
        ] {
            assert_eq!(
                resolve_path(&text(&path)),
                (PathCheck::Unresolved, None),
                "{}",
                path.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn check_paths_hides_unresolved_paths_from_the_engine_only() {
        use std::os::unix::fs::symlink;
        let (_temp, root) = canonical_tempdir();
        fs::create_dir_all(root.join("outside")).unwrap();
        symlink(root.join("outside"), root.join("link")).unwrap();
        let keys = BTreeSet::from(["arguments.path".to_owned(), "arguments.to".to_owned()]);
        let ok = text(&root.join("a.txt"));
        let escape = text(&root.join("link").join("x"));
        let call = json!({"name": "move", "arguments": {
            "path": ok, "to": escape, "other": escape, "rel": "x/y"}});
        let mut built = build_parameters("fs", &call, false);
        let record = check_paths(&mut built, &keys, &BTreeSet::new()).unwrap();

        assert_eq!(built["arguments.path"], ok);
        assert_eq!(built["arguments.to"], UNRESOLVED_PATH);
        // Keys no PathPrefix rule covers, and the full `arguments`, keep the
        // client's value.
        assert_eq!(built["arguments.other"], escape);
        assert_eq!(built["arguments"]["to"], escape);
        assert_eq!(record["arguments.path"]["status"], "same");
        assert_eq!(record["arguments.to"]["status"], "differs");
        assert_eq!(record["arguments.to"]["lexical"], escape);
        assert_eq!(
            record["arguments.to"]["resolved"],
            text(&root.join("outside").join("x"))
        );

        // Relative values and absent keys are left alone and not recorded.
        let mut built = build_parameters("fs", &json!({"arguments": {"path": "x/y"}}), false);
        assert_eq!(check_paths(&mut built, &keys, &BTreeSet::new()), None);
        assert_eq!(built["arguments.path"], "x/y");
    }

    const NFC_CAFE: &str = "caf\u{e9}";
    const NFD_CAFE: &str = "cafe\u{301}";

    fn prefixes(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn folds_into_prefix_compares_names_like_the_filesystem() {
        let rules = prefixes(&["/r/secret", &format!("/r/{NFC_CAFE}"), "relative"]);
        let full = |_: &str| Insensitivity::FULL;
        let none = |_: &str| Insensitivity::NONE;
        // Case-sensitive APFS: case matters, normalization does not.
        let apfs_cs = |_: &str| Insensitivity {
            case: false,
            normalization: true,
        };
        let nfd = format!("/r/{NFD_CAFE}");
        let nfd_under = format!("/r/{NFD_CAFE}/x");
        let upper_nfd = "/r/CAFE\u{301}";

        for path in [
            "/r/SECRET",
            "/r/Secret/x",
            "/R/secret",
            &nfd,
            &nfd_under,
            upper_nfd,
        ] {
            assert!(folds_into_prefix(path, &rules, full).is_some(), "{path}");
            assert_eq!(folds_into_prefix(path, &rules, none), None, "{path}");
        }
        assert_eq!(folds_into_prefix("/r/SECRET", &rules, apfs_cs), None);
        let cafe_rule = format!("/r/{NFC_CAFE}");
        assert_eq!(
            folds_into_prefix(&nfd, &rules, apfs_cs),
            Some(cafe_rule.as_str())
        );
        assert_eq!(folds_into_prefix(upper_nfd, &rules, apfs_cs), None);

        // Byte-for-byte matches are left to core; unrelated, sibling and
        // shorter paths never fold into the prefix.
        for path in [
            "/r/secret",
            "/r/secret/x",
            "/r/secrets",
            "/r/SECRETS",
            "/r",
            "/",
            "/other/SECRET",
            "/r/public/SECRET",
        ] {
            assert_eq!(folds_into_prefix(path, &rules, full), None, "{path}");
        }

        // Each segment uses the sensitivity of the directory that holds it.
        let only_r = |dir: &str| {
            if dir == "/r" {
                Insensitivity::FULL
            } else {
                Insensitivity::NONE
            }
        };
        assert!(folds_into_prefix("/r/SECRET", &rules, only_r).is_some());
        assert_eq!(folds_into_prefix("/R/secret", &rules, only_r), None);
    }

    /// Independent review of `a9dbbdf`, Alta 1: one upper/lower round left
    /// `ẞ` -> `ß` -> `ss` with three different keys.
    #[test]
    fn fold_key_is_idempotent_and_covers_every_mapping() {
        let mut checked = 0usize;
        for c in (0..=0x10_FFFFu32).filter_map(char::from_u32) {
            let name = c.to_string();
            let key = fold_key(&name, Insensitivity::FULL);
            assert_eq!(fold_key(&key, Insensitivity::FULL), key, "{c:?}");
            for variant in [
                c.to_uppercase().collect::<String>(),
                c.to_lowercase().collect(),
                caseless::default_case_fold_str(&name),
                name.nfd().collect(),
            ] {
                assert_eq!(
                    fold_key(&variant, Insensitivity::FULL),
                    key,
                    "{c:?} vs {variant:?}"
                );
            }
            checked += 1;
        }
        assert_eq!(checked, 0x11_0000 - 0x800);
        // The ASCII fast path agrees with the slow path on every ASCII pair.
        for a in 0u8..0x80 {
            for b in [0u8, b'x', b'.', b' ', b'A'] {
                let name: String = [a as char, b as char]
                    .iter()
                    .filter(|c| **c != '\0')
                    .collect();
                let apfs_cs = Insensitivity {
                    case: false,
                    normalization: true,
                };
                for mode in [Insensitivity::FULL, Insensitivity::NONE, apfs_cs] {
                    assert_eq!(
                        fold_key(&name, mode),
                        fold_key_slow(&name, mode),
                        "{name:?}"
                    );
                }
            }
        }
        let sharp = [
            "\u{1e9e}",
            "\u{df}",
            "ss",
            "SS",
            "Ss",
            "\u{17f}s",
            "\u{17f}\u{17f}",
        ];
        for name in sharp {
            assert_eq!(fold_key(name, Insensitivity::FULL), "ss", "{name:?}");
        }
        let rules = prefixes(&["/r/.ssh", "/r/stra\u{df}e"]);
        for path in [
            "/r/.\u{1e9e}h",
            "/r/.\u{1e9e}h/authorized_keys",
            "/r/.\u{df}h",
            "/r/.SSH",
            "/r/STRA\u{1e9e}E/",
            "/r/strasse",
        ] {
            assert!(
                folds_into_prefix(path, &rules, |_| Insensitivity::FULL).is_some(),
                "{path:?}"
            );
        }
    }

    /// Review Baja 4: a casefold flag that cannot be read folds, on every
    /// filesystem type (tmpfs included).
    #[test]
    fn linux_decision_folds_unless_known_byte_for_byte() {
        for kind in [EXT4_SUPER_MAGIC, F2FS_SUPER_MAGIC, TMPFS_MAGIC] {
            assert_eq!(linux_insensitivity(kind, Some(false)), Insensitivity::NONE);
            assert_eq!(linux_insensitivity(kind, Some(true)), Insensitivity::FULL);
            assert_eq!(
                linux_insensitivity(kind, None),
                Insensitivity::FULL,
                "{kind:#x}"
            );
        }
        assert_eq!(
            linux_insensitivity(BTRFS_SUPER_MAGIC, None),
            Insensitivity::NONE
        );
        // Review round 2, Baja 2: XFS may be `ascii-ci`; it folds.
        for casefold in [None, Some(false)] {
            assert_eq!(
                linux_insensitivity(XFS_SUPER_MAGIC, casefold),
                Insensitivity::FULL
            );
        }
        // procfs, overlayfs, vfat, an unknown magic.
        for kind in [0x9fa0, 0x794c_7630, 0x4d44, 0xdead_beef] {
            assert_eq!(linux_insensitivity(kind, Some(false)), Insensitivity::FULL);
        }
    }

    /// Review Alta 2, portable part: another spelling of the same entry is
    /// caught by `(st_dev, st_ino)` (a hard link to a denied file, a prefix
    /// written through a symlink), and ordinary paths are untouched.
    #[cfg(unix)]
    #[test]
    fn check_paths_hides_other_spellings_of_a_prefix() {
        use std::os::unix::fs::symlink;
        let (_temp, root) = canonical_tempdir();
        fs::create_dir_all(root.join("real").join("secret")).unwrap();
        fs::write(root.join("secret.txt"), b"s").unwrap();
        fs::hard_link(root.join("secret.txt"), root.join("public.txt")).unwrap();
        symlink(root.join("real"), root.join("link")).unwrap();
        let rules = prefixes(&[
            &text(&root.join("secret.txt")),
            &text(&root.join("link").join("secret")),
            &text(&root.join("link").join("missing")),
        ]);
        let keys = BTreeSet::from(["arguments.path".to_owned()]);
        let check = |path: &Path| {
            let path = text(path);
            let mut built = build_parameters("fs", &json!({"arguments": {"path": path}}), false);
            let record =
                check_paths_with(&mut built, &keys, &rules, |_| Insensitivity::NONE).unwrap();
            (
                built["arguments.path"].as_str().unwrap().to_owned(),
                record["arguments.path"]["status"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        };
        for path in [
            root.join("public.txt"),
            root.join("real").join("secret"),
            root.join("real").join("secret").join("new"),
            root.join("real").join("missing"),
        ] {
            assert_eq!(
                check(&path),
                (UNRESOLVED_PATH.to_owned(), "ambiguous".to_owned()),
                "{}",
                path.display()
            );
        }
        for path in [
            root.join("other.txt"),
            root.join("real").join("public"),
            root.join("real").join("missingx"),
            root.join("secret.txt"),
        ] {
            assert_eq!(
                check(&path),
                (text(&path), "same".to_owned()),
                "{}",
                path.display()
            );
        }
    }

    /// Review Alta 2 on this Mac: `realpath` keeps the
    /// `/System/Volumes/Data` spelling, which is the same directory as the
    /// firmlinked one (`/Users`, `/private`, ...).
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_firmlink_spellings_are_ambiguous() {
        let (_temp, root) = canonical_tempdir();
        fs::create_dir_all(root.join("vault")).unwrap();
        let data = |path: &Path| format!("/System/Volumes/Data{}", text(path));
        let keys = BTreeSet::from(["arguments.path".to_owned()]);
        let check = |path: &str, rules: &BTreeSet<String>| {
            let mut built = build_parameters("fs", &json!({"arguments": {"path": path}}), false);
            let record = check_paths(&mut built, &keys, rules).unwrap();
            (
                built["arguments.path"].as_str().unwrap().to_owned(),
                record["arguments.path"]["status"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        };
        let rules = prefixes(&[&text(&root.join("vault")), &text(&root.join("later"))]);
        for path in [
            data(&root.join("vault").join("k")),
            data(&root.join("vault")),
            data(&root.join("later")),
        ] {
            assert_eq!(
                resolve_path(&path).0,
                PathCheck::Same,
                "realpath keeps {path}"
            );
            let result = check(&path, &rules);
            eprintln!("firmlink: {path} -> {result:?}");
            assert_eq!(result, (UNRESOLVED_PATH.to_owned(), "ambiguous".to_owned()));
        }
        let ordinary = data(&root.join("notes.txt"));
        assert_eq!(
            check(&ordinary, &rules),
            (ordinary.clone(), "same".to_owned())
        );

        // The real home directory: only `stat` is used, nothing is written.
        let home = std::env::var("HOME").unwrap();
        let ssh = prefixes(&[&format!("{home}/.ssh")]);
        for path in [
            format!("/System/Volumes/Data{home}/.ssh"),
            format!("/System/Volumes/Data{home}/.ssh/authorized_keys"),
        ] {
            let result = check(&path, &ssh);
            eprintln!("firmlink: {path} -> {result:?}");
            assert_eq!(result.0, UNRESOLVED_PATH, "{path}");
        }
        // The rule written in the Data spelling hides the usual one, and
        // `policy check` points at it.
        let data_rule = format!("/System/Volumes/Data{}", text(&root.join("vault")));
        assert_eq!(
            check(
                &text(&root.join("vault").join("k")),
                &prefixes(&[&data_rule])
            )
            .0,
            UNRESOLVED_PATH
        );
        assert_eq!(firmlink_alias(&data_rule), Some(text(&root.join("vault"))));
        assert_eq!(firmlink_alias(&text(&root.join("vault"))), None);
    }

    /// Review round 2, Baja 3: on case-folding filesystems trailing dots and
    /// spaces do not distinguish names (Linux vfat/exfat).
    #[test]
    fn fold_key_drops_trailing_dots_and_spaces_when_folding_case() {
        for name in [
            "secret.", "secret..", "secret ", "secret. ", "SECRET.", "secret",
        ] {
            assert_eq!(fold_key(name, Insensitivity::FULL), "secret", "{name:?}");
        }
        let apfs_cs = Insensitivity {
            case: false,
            normalization: true,
        };
        assert_eq!(fold_key("secret.", apfs_cs), "secret.");
        assert_eq!(fold_key("secret.", Insensitivity::NONE), "secret.");
        let rules = prefixes(&["/usb/secret"]);
        for path in ["/usb/secret.", "/usb/SECRET. /x", "/usb/secret  "] {
            assert!(
                folds_into_prefix(path, &rules, |_| Insensitivity::FULL).is_some(),
                "{path:?}"
            );
            assert_eq!(
                folds_into_prefix(path, &rules, |_| apfs_cs),
                None,
                "{path:?}"
            );
        }
        // Inner dots still matter.
        assert_eq!(
            folds_into_prefix("/usb/sec.ret", &rules, |_| Insensitivity::FULL),
            None
        );
    }

    /// Review round 2, Media 1 (`policy check` part): prefixes that contain
    /// firmlink targets.
    #[test]
    fn firmlink_prefix_warning_names_prefixes_that_contain_firmlink_targets() {
        for prefix in [
            "/System",
            "/System/",
            "/System/Volumes",
            "/System/Volumes/Data",
            "/System/Volumes/Data/",
            "/System/Volumes/Data/usr",
            "/System/Volumes/Data/System/Library",
            "/System/Volumes/Data/Users/u/.ssh",
        ] {
            assert!(firmlink_prefix_warning(prefix).is_some(), "{prefix}");
        }
        for prefix in [
            "/Users/u",
            "/Systemx",
            "/System/Library",
            "/System/VolumesX",
            "/",
        ] {
            assert_eq!(firmlink_prefix_warning(prefix), None, "{prefix}");
        }
    }

    /// Review round 2, Media 1, on this Mac: a prefix that *contains* a
    /// firmlink target (or the other spelling of the argument falls under
    /// the prefix) is caught through the argument's other spelling.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_prefixes_containing_firmlink_targets_are_ambiguous() {
        let (_temp, root) = canonical_tempdir();
        fs::write(root.join("f.txt"), b"x").unwrap();
        let home = std::env::var("HOME").unwrap();
        let keys = BTreeSet::from(["arguments.path".to_owned()]);
        let check = |path: &str, prefix: &str| {
            let rules = prefixes(&[prefix]);
            let mut built = build_parameters("fs", &json!({"arguments": {"path": path}}), false);
            let record = check_paths(&mut built, &keys, &rules).unwrap();
            (
                built["arguments.path"].as_str().unwrap().to_owned(),
                record["arguments.path"]["status"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        };
        let f = text(&root.join("f.txt"));
        let hidden = [
            // The reviewer's four cases.
            (
                format!("{home}/.ssh/authorized_keys"),
                "/System/Volumes/Data".to_owned(),
            ),
            (f.clone(), "/System/Volumes".to_owned()),
            (
                "/usr/local/praetore-r2-new".to_owned(),
                "/System/Volumes/Data/usr".to_owned(),
            ),
            (
                "/System/Library/Caches/praetore-r2-new".to_owned(),
                "/System/Volumes/Data/System/Library".to_owned(),
            ),
            // Symmetric: the data-volume spelling under a system-volume prefix.
            (
                "/System/Volumes/Data/usr/local/praetore-r2-new".to_owned(),
                "/usr".to_owned(),
            ),
            (
                "/System/Volumes/Data/System/Library/Caches/praetore-r2-new".to_owned(),
                "/System/Library".to_owned(),
            ),
            // With folding: the other spelling only folds into the prefix.
            (f.clone(), "/SYSTEM/Volumes/data".to_owned()),
        ];
        for (path, prefix) in &hidden {
            assert_eq!(resolve_path(path).0, PathCheck::Same, "{path}");
            let result = check(path, prefix);
            eprintln!("firmlink r2: DENY {prefix:?} path {path:?} -> {result:?}");
            assert_eq!(
                result,
                (UNRESOLVED_PATH.to_owned(), "ambiguous".to_owned()),
                "DENY {prefix} path {path}"
            );
        }
        // Controls: outside firmlinked directories there is no other
        // spelling; inside, a prefix the other spelling is not under.
        assert_eq!(firmlink_spelling("/bin/ls"), None);
        assert_eq!(
            firmlink_spelling(&f),
            Some(format!("/System/Volumes/Data{f}"))
        );
        assert_eq!(
            firmlink_spelling(&format!("/System/Volumes/Data{f}")),
            Some(f.clone())
        );
        for (path, prefix) in [
            ("/bin/ls".to_owned(), "/System/Volumes/Data"),
            (f.clone(), "/System/Volumes/Data/Users"),
            (text(&root.join("notes.txt")), "/System/Volumes/Data/usr"),
        ] {
            assert_eq!(
                check(&path, prefix),
                (path.clone(), "same".to_owned()),
                "{path}"
            );
        }
    }

    /// The adversarial finding on `ccea7be`: the denied directory does not
    /// exist yet, so a case or NFD variant resolves "to itself" and core's
    /// lexical `PathPrefix` would not match it.
    #[cfg(unix)]
    #[test]
    fn check_paths_hides_case_and_nfd_variants_of_a_missing_prefix() {
        let (_temp, root) = canonical_tempdir();
        let rules = prefixes(&[&text(&root.join("secret")), &text(&root.join(NFC_CAFE))]);
        let keys = BTreeSet::from(["arguments.path".to_owned()]);
        let check = |path: &str, mode: Insensitivity| {
            let mut built = build_parameters("fs", &json!({"arguments": {"path": path}}), false);
            let record = check_paths_with(&mut built, &keys, &rules, |_| mode).unwrap();
            (
                built["arguments.path"].as_str().unwrap().to_owned(),
                record["arguments.path"]["status"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        };
        let upper = text(&root.join("SECRET"));
        let nfd = text(&root.join(NFD_CAFE));
        for path in [&upper, &nfd] {
            assert_eq!(
                check(path, Insensitivity::FULL),
                (UNRESOLVED_PATH.to_owned(), "ambiguous".to_owned()),
                "{path:?}"
            );
            // A case- and normalization-sensitive filesystem: another name.
            assert_eq!(
                check(path, Insensitivity::NONE),
                (path.clone(), "same".to_owned()),
                "{path:?}"
            );
        }
        // The exact prefix and ordinary paths reach the engine unchanged.
        for path in [
            text(&root.join("secret")),
            text(&root.join(NFC_CAFE)),
            text(&root.join("public.txt")),
            text(&root.join("secrets")),
        ] {
            assert_eq!(
                check(&path, Insensitivity::FULL),
                (path.clone(), "same".to_owned())
            );
        }
    }

    /// Under an existing directory a variant never reaches the engine: it is
    /// `differs` where the filesystem folds (realpath returns the stored
    /// name) and `unresolved` where it does not (no such parent).
    #[cfg(unix)]
    #[test]
    fn case_and_nfd_variants_under_an_existing_dir_are_hidden() {
        let (_temp, root) = canonical_tempdir();
        fs::create_dir_all(root.join("secret")).unwrap();
        fs::create_dir_all(root.join(NFC_CAFE)).unwrap();
        fs::write(root.join("secret").join("x.txt"), b"x").unwrap();
        let rules = prefixes(&[&text(&root.join("secret")), &text(&root.join(NFC_CAFE))]);
        let keys = BTreeSet::from(["arguments.path".to_owned()]);
        for path in [
            root.join("SECRET").join("x.txt"),
            root.join("SECRET").join("new.txt"),
            root.join(NFD_CAFE).join("new.txt"),
        ] {
            let path = text(&path);
            let mut built = build_parameters("fs", &json!({"arguments": {"path": path}}), false);
            let record = check_paths(&mut built, &keys, &rules).unwrap();
            assert_eq!(built["arguments.path"], UNRESOLVED_PATH, "{path:?}");
            assert_ne!(record["arguments.path"]["status"], "same", "{path:?}");
        }
        // The exact, stored (NFC) spelling is unchanged.
        let exact = text(&root.join("secret").join("x.txt"));
        let mut built = build_parameters("fs", &json!({"arguments": {"path": exact}}), false);
        let record = check_paths(&mut built, &keys, &rules).unwrap();
        assert_eq!(built["arguments.path"], exact);
        assert_eq!(record["arguments.path"]["status"], "same");
    }

    /// Real APFS behaviour on the macOS volume holding the temp directory.
    #[cfg(target_os = "macos")]
    #[test]
    fn apfs_case_and_normalization_behaviour() {
        let (_temp, root) = canonical_tempdir();
        let mode = dir_insensitivity(&text(&root));
        eprintln!("APFS: dir_insensitivity({}) = {mode:?}", root.display());
        assert!(mode.normalization);

        // realpath(3) returns the stored spelling of existing entries.
        fs::create_dir_all(root.join("secret")).unwrap();
        fs::create_dir_all(root.join(NFC_CAFE)).unwrap();
        fs::write(root.join("secret").join("x.txt"), b"x").unwrap();
        let (check, resolved) = resolve_path(&text(&root.join(NFD_CAFE)));
        eprintln!("APFS: NFD {NFD_CAFE:?} -> {check:?} {resolved:?}");
        assert_eq!(check, PathCheck::Differs);
        assert_eq!(resolved, Some(text(&root.join(NFC_CAFE))));
        let (check, resolved) = resolve_path(&text(&root.join("SECRET").join("x.txt")));
        eprintln!("APFS: SECRET/x.txt -> {check:?} {resolved:?}");
        if mode.case {
            assert_eq!(check, PathCheck::Differs);
            assert_eq!(resolved, Some(text(&root.join("secret").join("x.txt"))));
        } else {
            assert_eq!(check, PathCheck::Unresolved);
        }
        let (check, _) = resolve_path(&text(&root.join("secret").join("x.txt")));
        assert_eq!(check, PathCheck::Same);

        // A missing denied name: the variant is the entry that the denied
        // name will later open, and it is hidden from the engine.
        let missing = root.join("later");
        let rules = prefixes(&[&text(&missing), &text(&root.join("cr\u{e8}me"))]);
        let keys = BTreeSet::from(["arguments.path".to_owned()]);
        let check = |path: &str| {
            let mut built = build_parameters("fs", &json!({"arguments": {"path": path}}), false);
            let record = check_paths(&mut built, &keys, &rules).unwrap();
            (
                built["arguments.path"].as_str().unwrap().to_owned(),
                record["arguments.path"]["status"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        };
        let upper = text(&root.join("LATER"));
        let nfd = text(&root.join("cre\u{300}me"));
        let (seen, status) = check(&upper);
        eprintln!("APFS: missing LATER -> {status} (engine sees {seen:?})");
        if mode.case {
            assert_eq!(seen, UNRESOLVED_PATH);
            fs::write(&upper, b"x").unwrap();
            assert!(missing.exists(), "APFS folds case: LATER is later");
            fs::remove_file(&upper).unwrap();
        } else {
            assert_eq!(seen, upper);
        }
        let (seen, status) = check(&nfd);
        eprintln!("APFS: missing NFD cre\\u{{300}}me -> {status} (engine sees {seen:?})");
        assert_eq!(seen, UNRESOLVED_PATH);
        fs::write(&nfd, b"x").unwrap();
        assert!(
            root.join("cr\u{e8}me").exists(),
            "APFS ignores normalization"
        );

        // Control: an ordinary new file is unchanged.
        let ordinary = text(&root.join("notes.txt"));
        assert_eq!(check(&ordinary), (ordinary.clone(), "same".to_owned()));
    }

    /// Linux: on a filesystem known to compare bytes, a case variant of a
    /// missing prefix is an ordinary, different name and is not refused.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_case_sensitive_filesystems_do_not_fold() {
        let (_temp, root) = canonical_tempdir();
        let mode = dir_insensitivity(&text(&root));
        eprintln!("linux: dir_insensitivity({}) = {mode:?}", root.display());
        let rules = prefixes(&[&text(&root.join("secret"))]);
        let keys = BTreeSet::from(["arguments.path".to_owned()]);
        let upper = text(&root.join("SECRET"));
        let mut built = build_parameters("fs", &json!({"arguments": {"path": upper}}), false);
        check_paths(&mut built, &keys, &rules).unwrap();
        let expected = if mode.case {
            UNRESOLVED_PATH
        } else {
            upper.as_str()
        };
        assert_eq!(built["arguments.path"], expected);
        // `/proc` is procfs, an unknown type: fail closed.
        assert_eq!(dir_insensitivity("/proc"), Insensitivity::FULL);
    }

    #[test]
    fn path_prefix_keys_come_from_every_rule() {
        use praetore_core::{PolicyCondition, PolicyEffect, PolicyRule};
        let policy = Policy::new_v2(
            "p",
            1,
            vec![
                PolicyRule::new("a", ACTION_TYPE, PolicyEffect::Allow)
                    .with_parameter_condition(PolicyCondition::path_prefix("arguments.path", "/a")),
                PolicyRule::new("d", ACTION_TYPE, PolicyEffect::Deny)
                    .with_parameter_condition(PolicyCondition::path_prefix("arguments.to", "/b"))
                    .with_parameter_condition(PolicyCondition::prefix("arguments.name", "x")),
            ],
        );
        assert_eq!(
            path_prefix_keys(&policy),
            BTreeSet::from(["arguments.path".to_owned(), "arguments.to".to_owned()])
        );
    }

    #[test]
    fn parameters_flatten_top_level_arguments() {
        let params = json!({"name": "write_file", "arguments": {"path": "/tmp/x", "n": 1}});
        let built = build_parameters("fs", &params, false);
        assert_eq!(built["server"], "fs");
        assert_eq!(built["tool"], "write_file");
        assert_eq!(built["arguments"]["path"], "/tmp/x");
        assert_eq!(built["arguments.path"], "/tmp/x");
        assert_eq!(built["arguments.n"], 1);
    }

    #[test]
    fn parameters_tolerate_missing_and_odd_shapes() {
        let built = build_parameters("s", &json!(null), false);
        assert_eq!(built["tool"], Value::Null);
        assert_eq!(built["arguments"], Value::Null);
        let built = build_parameters("s", &json!({"name": 7, "arguments": [1, 2]}), false);
        assert_eq!(built["tool"], 7);
        assert_eq!(built["arguments"], json!([1, 2]));
    }

    #[test]
    fn oversized_arguments_are_digested() {
        let big = "x".repeat(MAX_INLINE_ARGUMENTS_BYTES + 1);
        let built = build_parameters(
            "s",
            &json!({"name": "t", "arguments": {"data": big}}),
            false,
        );
        assert!(built.get("arguments").is_none());
        assert!(built.get("arguments.data").is_none());
        assert_eq!(built["arguments_omitted"], true);
        assert_eq!(built["arguments_sha256"].as_str().unwrap().len(), 64);
    }

    #[cfg(unix)]
    #[test]
    fn journal_refuses_symlinked_receipts_dir() {
        let temp = tempfile::tempdir().unwrap();
        let elsewhere = temp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let receipts = temp.path().join("receipts");
        std::os::unix::fs::symlink(&elsewhere, &receipts).unwrap();
        assert!(
            store::ensure_dir(&receipts, false)
                .unwrap_err()
                .contains("symlink")
        );
    }

    #[test]
    fn journal_file_name_is_utc_date() {
        let journal = Journal::new(PathBuf::from("/r"));
        let at = OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap();
        assert_eq!(journal.path_for(at), PathBuf::from("/r/2026-05-28.jsonl"));
    }
}
