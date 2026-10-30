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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathCheck {
    /// The path resolves to itself (no symlink, `.` or `..` on the way).
    Same,
    /// The path resolves to another path (a symlink, `..`, a trailing `/.`).
    Differs,
    /// The path or its parent does not exist, is a dangling symlink, or is
    /// not UTF-8: it cannot be resolved now.
    Unresolved,
}

impl PathCheck {
    fn as_str(self) -> &'static str {
        match self {
            Self::Same => "same",
            Self::Differs => "differs",
            Self::Unresolved => "unresolved",
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

/// T-014: `PathPrefix` in core is lexical by design. Before evaluation, each
/// absolute string argument under `keys` is resolved; unless it resolves to
/// itself, the engine sees [`UNRESOLVED_PATH`] instead (fail closed). The
/// bytes forwarded to the server are never changed. Returns the record for
/// [`PATH_CHECK_CONTEXT_KEY`], or `None` when no covered argument is present.
pub fn check_paths(parameters: &mut Value, keys: &BTreeSet<String>) -> Option<Value> {
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
        let (check, resolved) = resolve_path(&lexical);
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
        })
    }

    /// Evaluates and returns the attested evidence without journaling it.
    pub fn evaluate_evidence(&self, server: &str, params: &Value) -> Result<Evidence, String> {
        let target = Some(server.to_owned());
        let mut path_check = None;
        let mut inline = build_parameters(server, params, false);
        if !self.path_keys.is_empty() {
            path_check = check_paths(&mut inline, &self.path_keys);
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
        let record = check_paths(&mut built, &keys).unwrap();

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
        assert_eq!(check_paths(&mut built, &keys), None);
        assert_eq!(built["arguments.path"], "x/y");
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
