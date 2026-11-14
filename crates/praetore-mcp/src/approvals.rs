//! Local, file-backed human approval for `REQUIRE_APPROVAL` tool calls.
//!
//! Nothing here talks to PostgreSQL, a server, or the network. Pending calls
//! live under `DIR/approvals/pending/`. Signed decisions and the one
//! execution that consumes an approval live in `DIR/approvals/journal.jsonl`,
//! a hash-linked file that `verify` reads next to the receipts journal.
//!
//! The receipts journal itself is unchanged: a held call and the later
//! retry are ordinary evidence lines. Putting decisions in that chain would
//! have changed how v0.3.3 lines are linked.

use crate::store::{self, Home};
use ed25519_dalek::{Signer, SigningKey};
use praetore_core::{DecisionOutcome, Evidence, VerifiedPublicKey};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const DECISION_DOMAIN: &[u8] = b"PRAETORE_MCP_LOCAL_APPROVAL_V1\0";
const EXECUTION_DOMAIN: &[u8] = b"PRAETORE_MCP_LOCAL_APPROVAL_EXEC_V1\0";
const JOURNAL_DOMAIN: &[u8] = b"PRAETORE_MCP_APPROVAL_JOURNAL_V1\0";
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const DEFAULT_TTL_SECONDS: i64 = 600;
const MAX_TTL_SECONDS: i64 = 86_400;
/// One approval record stays small enough to append in one write.
const MAX_RECORD_BYTES: usize = 48 * 1024;
const MODE_KEY: &str = "praetore.mode";

const DECISION_KEYS: &[&str] = &[
    "approval_id",
    "approver_key_id",
    "arguments",
    "created_at",
    "decided_at",
    "expires_at",
    "kind",
    "outcome",
    "pending_evidence_id",
    "schema",
    "server",
    "signature",
    "tool",
];
const EXECUTION_KEYS: &[&str] = &[
    "approval_id",
    "arguments",
    "attester_key_id",
    "evidence_id",
    "executed_at",
    "kind",
    "schema",
    "server",
    "signature",
    "tool",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HumanOutcome {
    Approve,
    Reject,
}

impl HumanOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Binding {
    server: String,
    tool: String,
    arguments: Value,
}

/// What enforce does with a `REQUIRE_APPROVAL` verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldOrForward {
    /// The call was not forwarded. `message` is the MCP tool error text.
    Hold { message: String },
    /// One unused approval matched this exact call and was consumed.
    Forward { approval_id: String },
}

#[derive(Debug, Clone)]
pub struct PendingInfo {
    pub approval_id: String,
    pub server: String,
    pub tool: String,
    pub arguments_preview: String,
    pub expires_at: String,
    pub evidence_id: String,
}

#[derive(Debug, Clone)]
pub struct Decided {
    pub approval_id: String,
    pub outcome: String,
    pub server: String,
    pub tool: String,
    pub expires_at: String,
    pub approver_key_id: String,
}

#[derive(Debug, Default)]
pub struct ApprovalReport {
    pub decisions: usize,
    pub executions: usize,
    pub failures: Vec<String>,
    /// Link after the last approval record. `None` when the journal is
    /// absent or empty. Removing the tail is only visible against a copy of
    /// this value kept outside the home, same as the receipts head.
    pub head: Option<String>,
}

struct JournalEntry {
    seq: u64,
    prev: String,
    record: Value,
    canonical: Vec<u8>,
}

/// Enforce path: do not forward. Either consume one matching approval or
/// register (or reuse) a pending id the person can approve from a terminal.
pub fn on_require_approval(
    home: &Home,
    server: &str,
    params: &Value,
    evidence: &Evidence,
) -> Result<HoldOrForward, String> {
    let binding = binding_from_call(server, params)?;
    if evidence.decision.outcome != DecisionOutcome::RequireApproval {
        return Err("approval handling called for a call that is not REQUIRE_APPROVAL".into());
    }
    binding_matches_evidence(&binding, evidence)?;
    with_lock(home, |journal| {
        let entries = read_journal(journal)?;
        let now = now_utc()?;
        if let Some(approval_id) = first_unused_approval(home, &entries, &binding, now)? {
            append_execution(
                home,
                journal,
                &entries,
                &approval_id,
                &binding,
                &evidence.evidence_id.to_string(),
                now,
            )?;
            return Ok(HoldOrForward::Forward { approval_id });
        }
        let pending = reuse_or_create_pending(
            home,
            &binding,
            &evidence.evidence_id.to_string(),
            now,
            ttl(home)?,
        )?;
        Ok(HoldOrForward::Hold {
            message: hold_message(home, &pending),
        })
    })
}

/// Pending approvals, soonest expiry first.
pub fn list_pending(home: &Home) -> Result<Vec<PendingInfo>, String> {
    let mut listed = Vec::new();
    let dir = pending_dir(home);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(listed),
        Err(error) => return Err(format!("cannot read {}: {error}", dir.display())),
    };
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let text = fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let value: Value = serde_json::from_str(&text)
            .map_err(|e| format!("{} is not JSON: {e}", path.display()))?;
        listed.push(pending_info(&value).map_err(|e| format!("{}: {e}", path.display()))?);
    }
    listed.sort_by(|a, b| {
        a.expires_at
            .cmp(&b.expires_at)
            .then(a.approval_id.cmp(&b.approval_id))
    });
    Ok(listed)
}

/// What `approve` prints before it asks for the confirmation code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCall {
    pub server: String,
    pub tool: String,
    pub expires_at: String,
    pub evidence_id: String,
    /// Canonical JSON of the arguments, not truncated.
    pub arguments_canonical: String,
}

/// Reads one pending file. Does not sign or delete it.
pub fn pending_call(home: &Home, approval_id: &str) -> Result<PendingCall, String> {
    if !valid_id(approval_id) {
        return Err(format!(
            "approval id {approval_id:?} is not a 64-character lowercase hex id"
        ));
    }
    let path = pending_path(home, approval_id);
    let text = fs::read_to_string(&path).map_err(|_| {
        format!("no pending approval {approval_id} (unknown id, or already decided)")
    })?;
    let pending: Value =
        serde_json::from_str(&text).map_err(|e| format!("{} is not JSON: {e}", path.display()))?;
    let info = pending_info(&pending)?;
    if info.approval_id != approval_id {
        return Err(format!("{} does not match its approval id", path.display()));
    }
    let arguments = pending
        .get("arguments")
        .cloned()
        .ok_or("pending approval has no arguments")?;
    let canonical = String::from_utf8(canonical_bytes(&arguments)?)
        .map_err(|_| "canonical arguments are not UTF-8".to_owned())?;
    Ok(PendingCall {
        server: info.server,
        tool: info.tool,
        expires_at: info.expires_at,
        evidence_id: info.evidence_id,
        arguments_canonical: canonical,
    })
}

fn load_signed_receipt(home: &Home, evidence_id: &str) -> Result<Evidence, String> {
    let attester = store::read_attester_pin(&home.attester_pin())?;
    let pins = store::read_issuer_pins(&home.issuer_pins())?;
    for line in crate::receipts::read_journal(home)? {
        let parsed = crate::journal::parse_line(&line.text)
            .map_err(|error| format!("{}:{}: {error}", line.file.display(), line.line_number))?;
        if parsed.evidence.evidence_id.to_string() != evidence_id {
            continue;
        }
        return crate::receipts::verify_line(&line.text, &attester, &pins).map_err(|error| {
            format!(
                "pending evidence {evidence_id} does not verify ({error}); nothing was signed and the pending file was kept"
            )
        });
    }
    Err(format!(
        "pending evidence {evidence_id} is not in the receipts journal; nothing was signed and the pending file was kept"
    ))
}

/// Signs a decision for a pending id and appends it to the approval journal.
/// The `approve` command is what requires an interactive terminal.
pub fn decide(
    home: &Home,
    approval_id: &str,
    outcome: HumanOutcome,
    shown: Option<&PendingCall>,
) -> Result<Decided, String> {
    if !valid_id(approval_id) {
        return Err(format!(
            "approval id {approval_id:?} is not a 64-character lowercase hex id"
        ));
    }
    with_lock(home, |journal| {
        if let Some(existing) = find_decision(&read_journal(journal)?, approval_id)? {
            let previous = existing["outcome"].as_str().unwrap_or("?");
            return Err(format!(
                "approval {approval_id} was already decided ({previous}); nothing new was signed"
            ));
        }
        let path = pending_path(home, approval_id);
        let text = fs::read_to_string(&path).map_err(|_| {
            format!("no pending approval {approval_id} (unknown id, or already decided)")
        })?;
        let pending: Value = serde_json::from_str(&text)
            .map_err(|e| format!("{} is not JSON: {e}", path.display()))?;
        let info = pending_info(&pending)?;
        if info.approval_id != approval_id {
            return Err(format!("{} does not match its approval id", path.display()));
        }
        let now = now_utc()?;
        let expires = parse_time(&info.expires_at)?;
        if now > expires {
            return Err(format!(
                "approval {approval_id} expired at {}; nothing was signed",
                info.expires_at
            ));
        }
        let binding = binding_from_pending(&pending)?;
        if let Some(shown) = shown {
            let current = String::from_utf8(canonical_bytes(&binding.arguments)?)
                .map_err(|_| "canonical arguments are not UTF-8".to_owned())?;
            if shown.server != binding.server
                || shown.tool != binding.tool
                || shown.arguments_canonical != current
                || shown.evidence_id != info.evidence_id
            {
                return Err(
                    "the pending call changed after it was shown; nothing was signed and the pending file was kept"
                        .into(),
                );
            }
        }
        // The pending file is not signed. Refuse to sign it unless it still
        // matches the receipt written when the call was held.
        let evidence = load_signed_receipt(home, &info.evidence_id)?;
        binding_matches_evidence(&binding, &evidence).map_err(|error| {
            format!("{error}; nothing was signed and the pending file was kept")
        })?;
        let approver = store::approver_secret(home)?;
        let approver_key_id = public_hex(&approver);
        let pin = read_approver_pin(home)?;
        if hex::encode(pin.as_bytes()) != approver_key_id {
            return Err(
                "approver-public-key.hex does not match the approver key; nothing was signed"
                    .into(),
            );
        }
        let created_at = pending["created_at"]
            .as_str()
            .ok_or("pending approval has no created_at")?
            .to_owned();
        let arguments = pending
            .get("arguments")
            .cloned()
            .ok_or("pending approval has no arguments")?;
        let record = json!({
            "schema": 1,
            "kind": "decision",
            "approval_id": approval_id,
            "approver_key_id": approver_key_id,
            "outcome": outcome.as_str(),
            "server": info.server,
            "tool": info.tool,
            "arguments": arguments,
            "pending_evidence_id": info.evidence_id,
            "created_at": created_at,
            "expires_at": info.expires_at,
            "decided_at": timestamp(now)?,
        });
        let signed = sign_record(&record, DECISION_DOMAIN, &approver)?;
        let entries = read_journal(journal)?;
        append_signed(journal, &entries, &signed)?;
        fs::remove_file(&path).map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
        Ok(Decided {
            approval_id: approval_id.to_owned(),
            outcome: outcome.as_str().to_owned(),
            server: info.server,
            tool: info.tool,
            expires_at: info.expires_at,
            approver_key_id,
        })
    })
}

/// Signs and appends another execution for an approval that already has one.
///
/// The proxy does not call this. `on_require_approval` consumes an approval
/// once before it forwards. `verify` rejects a journal with two executions
/// of one approval. Tests use this to build that journal.
pub fn record_duplicate_execution(
    home: &Home,
    approval_id: &str,
    evidence: &Evidence,
) -> Result<(), String> {
    if !valid_id(approval_id) {
        return Err("approval id is not 64 lowercase hex characters".into());
    }
    with_lock(home, |journal| {
        let entries = read_journal(journal)?;
        let decision = find_decision(&entries, approval_id)?
            .ok_or_else(|| format!("no signed decision for {approval_id}"))?;
        if decision["outcome"] != "approve" {
            return Err(format!("approval {approval_id} was not approved"));
        }
        let binding = binding_from_record(decision)?;
        binding_matches_evidence(&binding, evidence)?;
        append_execution(
            home,
            journal,
            &entries,
            approval_id,
            &binding,
            &evidence.evidence_id.to_string(),
            now_utc()?,
        )
    })
}

/// Evidence id → short status for `receipts`. Not a signature check; `verify`
/// does that. A missing approval directory yields an empty map.
pub fn status_by_evidence(home: &Home) -> Result<BTreeMap<String, String>, String> {
    let mut status = BTreeMap::new();
    if let Ok(entries) = read_journal_unlocked(home) {
        for entry in &entries {
            match entry.record["kind"].as_str() {
                Some("decision") => {
                    let Some(id) = entry.record["pending_evidence_id"].as_str() else {
                        continue;
                    };
                    let outcome = entry.record["outcome"].as_str().unwrap_or("?");
                    let key: String = entry.record["approver_key_id"]
                        .as_str()
                        .unwrap_or("?")
                        .chars()
                        .take(16)
                        .collect();
                    status.insert(id.to_owned(), format!("{outcome} by {key}"));
                }
                Some("execution") => {
                    let Some(id) = entry.record["evidence_id"].as_str() else {
                        continue;
                    };
                    status.insert(id.to_owned(), "executed once".into());
                }
                _ => {}
            }
        }
    }
    if let Ok(pending) = list_pending(home) {
        for item in pending {
            status
                .entry(item.evidence_id)
                .or_insert_with(|| "pending".into());
        }
    }
    Ok(status)
}

/// Checks the approval journal: signatures, binding to the named receipts,
/// expiry, and single use. An absent journal is success (homes from v0.3.3).
pub fn verify(home: &Home, evidence: &[Evidence]) -> Result<ApprovalReport, String> {
    let path = journal_path(home);
    if !path.exists() {
        return Ok(ApprovalReport::default());
    }
    let entries = read_journal_unlocked(home)?;
    let mut report = ApprovalReport::default();
    let approver = match read_approver_pin(home) {
        Ok(key) => Some(key),
        Err(_) if entries.is_empty() => None,
        Err(error) => {
            report
                .failures
                .push(format!("FAIL approvals: cannot read approver key: {error}"));
            return Ok(report);
        }
    };
    let attester = store::read_attester_pin(&home.attester_pin()).ok();
    let mut expected_seq = 0u64;
    let mut expected_prev = GENESIS.to_owned();
    let mut head = GENESIS.to_owned();
    let mut executions_of: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen_decision: BTreeSet<String> = BTreeSet::new();
    for entry in &entries {
        let at = format!("{} seq {}", path.display(), entry.seq);
        if entry.seq != expected_seq || entry.prev != expected_prev {
            report.failures.push(format!(
                "FAIL {at}: approval journal does not follow the previous record (expected seq {expected_seq})"
            ));
        }
        expected_prev = hex::encode(link_bytes(entry.seq, &entry.prev, &entry.canonical));
        expected_seq = expected_seq.saturating_add(1);
        head.clone_from(&expected_prev);
        match entry.record["kind"].as_str() {
            Some("decision") => {
                report.decisions += 1;
                if let Err(error) =
                    verify_decision(entry, approver.as_ref(), evidence, &mut seen_decision)
                {
                    report.failures.push(format!("FAIL {at}: {error}"));
                }
            }
            Some("execution") => {
                report.executions += 1;
                if let Some(id) = entry.record["approval_id"].as_str() {
                    *executions_of.entry(id.to_owned()).or_default() += 1;
                }
                if let Err(error) = verify_execution(entry, attester.as_ref(), evidence) {
                    report.failures.push(format!("FAIL {at}: {error}"));
                }
            }
            other => report.failures.push(format!(
                "FAIL {at}: unknown approval record kind {}",
                other.unwrap_or("missing")
            )),
        }
    }
    for (approval_id, count) in &executions_of {
        let decision = entries.iter().find(|entry| {
            entry.record["kind"] == "decision"
                && entry.record["approval_id"] == approval_id.as_str()
        });
        match decision {
            None => report.failures.push(format!(
                "FAIL approvals: execution of {approval_id} has no signed decision"
            )),
            Some(decision) if decision.record["outcome"] != "approve" => {
                report.failures.push(format!(
                    "FAIL approvals: {approval_id} was rejected and still has an execution"
                ));
            }
            Some(decision) => {
                if let Err(error) = execution_within_window(&decision.record, &entries, approval_id)
                {
                    report
                        .failures
                        .push(format!("FAIL approvals: {approval_id}: {error}"));
                }
                let execution = entries.iter().find(|entry| {
                    entry.record["kind"] == "execution"
                        && entry.record["approval_id"] == approval_id.as_str()
                });
                if execution.and_then(|entry| binding_from_record(&entry.record).ok())
                    != binding_from_record(&decision.record).ok()
                {
                    report.failures.push(format!(
                        "FAIL approvals: execution of {approval_id} is not bound to the signed call"
                    ));
                }
            }
        }
        if *count > 1 {
            report.failures.push(format!(
                "FAIL approvals: {approval_id} was reused: {count} execution records, and an approval authorizes one call"
            ));
        }
    }
    if !entries.is_empty() {
        report.head = Some(head);
    }
    Ok(report)
}

fn verify_decision(
    entry: &JournalEntry,
    approver: Option<&VerifiedPublicKey>,
    evidence: &[Evidence],
    seen: &mut BTreeSet<String>,
) -> Result<(), String> {
    exact_keys(&entry.record, DECISION_KEYS)?;
    let approver = approver.ok_or("approver public key is missing")?;
    let key_id = required_str(&entry.record, "approver_key_id")?;
    if key_id != hex::encode(approver.as_bytes()) {
        return Err("approver_key_id does not match approver-public-key.hex".into());
    }
    check_signature(&entry.record, DECISION_DOMAIN, approver)?;
    let approval_id = required_str(&entry.record, "approval_id")?;
    if !valid_id(approval_id) {
        return Err("approval_id is not 64 lowercase hex characters".into());
    }
    if !seen.insert(approval_id.to_owned()) {
        return Err(format!(
            "approval_id {approval_id} is signed more than once"
        ));
    }
    let outcome = required_str(&entry.record, "outcome")?;
    if outcome != "approve" && outcome != "reject" {
        return Err(format!("outcome {outcome:?} is not approve or reject"));
    }
    if entry.record["schema"] != 1 || entry.record["kind"] != "decision" {
        return Err("decision schema or kind is not 1/decision".into());
    }
    let created = parse_time(required_str(&entry.record, "created_at")?)?;
    let decided = parse_time(required_str(&entry.record, "decided_at")?)?;
    let expires = parse_time(required_str(&entry.record, "expires_at")?)?;
    if created > decided || decided > expires {
        return Err("decision times are not created_at <= decided_at <= expires_at".into());
    }
    let pending_id = required_str(&entry.record, "pending_evidence_id")?;
    let evidence = find_evidence(evidence, pending_id)?;
    if evidence.decision.outcome != DecisionOutcome::RequireApproval {
        return Err("pending evidence is not a REQUIRE_APPROVAL receipt".into());
    }
    if mode_of(evidence) != Some("enforce") {
        return Err("pending evidence is not an enforce receipt".into());
    }
    binding_matches_evidence(&binding_from_record(&entry.record)?, evidence)
}

fn verify_execution(
    entry: &JournalEntry,
    attester: Option<&VerifiedPublicKey>,
    evidence: &[Evidence],
) -> Result<(), String> {
    exact_keys(&entry.record, EXECUTION_KEYS)?;
    let attester = attester.ok_or("attester public key is missing")?;
    let key_id = required_str(&entry.record, "attester_key_id")?;
    if key_id != hex::encode(attester.as_bytes()) {
        return Err("attester_key_id does not match attester-public-key.hex".into());
    }
    check_signature(&entry.record, EXECUTION_DOMAIN, attester)?;
    let approval_id = required_str(&entry.record, "approval_id")?;
    if !valid_id(approval_id) {
        return Err("approval_id is not 64 lowercase hex characters".into());
    }
    if entry.record["schema"] != 1 || entry.record["kind"] != "execution" {
        return Err("execution schema or kind is not 1/execution".into());
    }
    let evidence_id = required_str(&entry.record, "evidence_id")?;
    let evidence = find_evidence(evidence, evidence_id)?;
    if evidence.decision.outcome != DecisionOutcome::RequireApproval {
        return Err("executed evidence is not a REQUIRE_APPROVAL receipt".into());
    }
    if mode_of(evidence) != Some("enforce") {
        return Err("executed evidence is not an enforce receipt".into());
    }
    binding_matches_evidence(&binding_from_record(&entry.record)?, evidence)
}

fn execution_within_window(
    decision: &Value,
    entries: &[JournalEntry],
    approval_id: &str,
) -> Result<(), String> {
    let decided = parse_time(required_str(decision, "decided_at")?)?;
    let expires = parse_time(required_str(decision, "expires_at")?)?;
    for entry in entries.iter().filter(|entry| {
        entry.record["kind"] == "execution" && entry.record["approval_id"] == approval_id
    }) {
        let executed = parse_time(required_str(&entry.record, "executed_at")?)?;
        if executed < decided || executed > expires {
            return Err(
                "execution is outside the approval window (decided_at <= executed_at <= expires_at)"
                    .into(),
            );
        }
    }
    Ok(())
}

fn first_unused_approval(
    home: &Home,
    entries: &[JournalEntry],
    binding: &Binding,
    now: OffsetDateTime,
) -> Result<Option<String>, String> {
    let used: BTreeSet<&str> = entries
        .iter()
        .filter(|entry| entry.record["kind"] == "execution")
        .filter_map(|entry| entry.record["approval_id"].as_str())
        .collect();
    let approver = read_approver_pin(home).ok();
    for entry in entries {
        if entry.record["kind"] != "decision" || entry.record["outcome"] != "approve" {
            continue;
        }
        let id = required_str(&entry.record, "approval_id")?;
        if used.contains(id) || binding_from_record(&entry.record)? != *binding {
            continue;
        }
        let expires = parse_time(required_str(&entry.record, "expires_at")?)?;
        if now > expires {
            continue;
        }
        let Some(approver) = approver.as_ref() else {
            return Err(
                "an approval is signed but approver-public-key.hex is missing; run `praetore-mcp init` to add the approver key"
                    .into(),
            );
        };
        check_signature(&entry.record, DECISION_DOMAIN, approver)?;
        if required_str(&entry.record, "approver_key_id")? != hex::encode(approver.as_bytes()) {
            return Err("approval signature key does not match approver-public-key.hex".into());
        }
        return Ok(Some(id.to_owned()));
    }
    Ok(None)
}

fn reuse_or_create_pending(
    home: &Home,
    binding: &Binding,
    evidence_id: &str,
    now: OffsetDateTime,
    ttl: Duration,
) -> Result<PendingInfo, String> {
    for pending in list_pending(home)? {
        let path = pending_path(home, &pending.approval_id);
        let text = fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let value: Value = serde_json::from_str(&text)
            .map_err(|e| format!("{} is not JSON: {e}", path.display()))?;
        let existing = binding_from_pending(&value)?;
        let expires = parse_time(&pending.expires_at)?;
        if existing == *binding && now <= expires {
            return pending_info(&value);
        }
    }
    let approval_id = random_id();
    let value = json!({
        "schema": 1,
        "approval_id": approval_id,
        "server": binding.server,
        "tool": binding.tool,
        "arguments": binding.arguments,
        "evidence_id": evidence_id,
        "created_at": timestamp(now)?,
        "expires_at": timestamp(
            now.checked_add(ttl)
                .ok_or("approval expiry is outside the representable range")?,
        )?,
    });
    let path = pending_path(home, &approval_id);
    if let Some(parent) = path.parent() {
        store::ensure_dir(parent, false)?;
    }
    let text = serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?;
    write_private(&path, &text)?;
    pending_info(&value)
}

fn append_execution(
    home: &Home,
    journal: &Path,
    entries: &[JournalEntry],
    approval_id: &str,
    binding: &Binding,
    evidence_id: &str,
    now: OffsetDateTime,
) -> Result<(), String> {
    let attester = store::attester_secret(home)?;
    let record = json!({
        "schema": 1,
        "kind": "execution",
        "approval_id": approval_id,
        "evidence_id": evidence_id,
        "server": binding.server,
        "tool": binding.tool,
        "arguments": binding.arguments,
        "executed_at": timestamp(now)?,
        "attester_key_id": public_hex(&attester),
    });
    let signed = sign_record(&record, EXECUTION_DOMAIN, &attester)?;
    append_signed(journal, entries, &signed)
}

fn append_signed(journal: &Path, entries: &[JournalEntry], record: &Value) -> Result<(), String> {
    let canonical = canonical_bytes(record)?;
    if canonical.len() > MAX_RECORD_BYTES {
        return Err(format!(
            "approval record is {} bytes; the limit is {MAX_RECORD_BYTES}",
            canonical.len()
        ));
    }
    let (seq, prev) = next_position(entries)?;
    let canonical_text = std::str::from_utf8(&canonical)
        .map_err(|_| "canonical approval record is not UTF-8".to_owned())?;
    let line = format!("{{\"seq\":{seq},\"prev\":\"{prev}\",\"record\":{canonical_text}}}\n");
    // The line we write must be the line verify parses back.
    let parsed = parse_journal_text(line.trim_end_matches('\n'))?;
    if parsed.seq != seq || parsed.prev != prev || parsed.canonical != canonical {
        return Err("approval journal line did not round-trip".into());
    }
    append_line(journal, line.as_bytes())
}

fn next_position(entries: &[JournalEntry]) -> Result<(u64, String), String> {
    let Some(last) = entries.last() else {
        return Ok((0, GENESIS.to_owned()));
    };
    let seq = last
        .seq
        .checked_add(1)
        .ok_or("approval journal sequence number overflow")?;
    let prev = hex::encode(link_bytes(last.seq, &last.prev, &last.canonical));
    Ok((seq, prev))
}

fn sign_record(unsigned: &Value, domain: &[u8], secret: &[u8; 32]) -> Result<Value, String> {
    let payload = canonical_bytes(unsigned)?;
    let signature = sign(secret, domain, &payload);
    let mut record = unsigned
        .as_object()
        .ok_or("approval record is not an object")?
        .clone();
    record.insert("signature".into(), Value::String(hex::encode(signature)));
    Ok(Value::Object(record))
}

fn sign(secret: &[u8; 32], domain: &[u8], payload: &[u8]) -> [u8; 64] {
    let key = SigningKey::from_bytes(secret);
    let mut message = Vec::with_capacity(domain.len() + payload.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(payload);
    key.sign(&message).to_bytes()
}

fn check_signature(
    record: &Value,
    domain: &[u8],
    public: &VerifiedPublicKey,
) -> Result<(), String> {
    let signature = required_str(record, "signature")?;
    if !praetore_core::canonical::is_canonical_signature_hex(signature) {
        return Err("signature is not 128 lowercase hex characters".into());
    }
    let bytes = hex::decode(signature).map_err(|_| "signature is not hex")?;
    let mut unsigned = record
        .as_object()
        .ok_or("approval record is not an object")?
        .clone();
    unsigned.remove("signature");
    let payload = canonical_bytes(&Value::Object(unsigned))?;
    public
        .verify_domain_message(domain, &payload, &bytes)
        .map_err(|_| "signature is invalid".to_owned())
}

fn public_hex(secret: &[u8; 32]) -> String {
    hex::encode(SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

fn binding_from_call(server: &str, params: &Value) -> Result<Binding, String> {
    let Some(tool) = params.get("name").and_then(Value::as_str) else {
        return Err("tool name is not a string, so the call cannot be bound to an approval".into());
    };
    if tool.is_empty() || tool.chars().any(char::is_control) {
        return Err("tool name is empty or contains a control character".into());
    }
    Ok(Binding {
        server: server.to_owned(),
        tool: tool.to_owned(),
        arguments: params.get("arguments").cloned().unwrap_or(Value::Null),
    })
}

fn binding_from_record(record: &Value) -> Result<Binding, String> {
    Ok(Binding {
        server: required_str(record, "server")?.to_owned(),
        tool: required_str(record, "tool")?.to_owned(),
        arguments: record
            .get("arguments")
            .cloned()
            .ok_or("approval record has no arguments")?,
    })
}

fn binding_from_pending(pending: &Value) -> Result<Binding, String> {
    binding_from_record(pending)
}

fn binding_matches_evidence(binding: &Binding, evidence: &Evidence) -> Result<(), String> {
    if evidence.action.target.as_deref() != Some(binding.server.as_str()) {
        return Err("server does not match the approval".into());
    }
    let params = &evidence.action.parameters;
    match params.get("tool") {
        Some(Value::String(tool)) if tool == &binding.tool => {}
        _ if params.get("tool_omitted") == Some(&Value::Bool(true)) => {
            let digest = sha256_hex(
                &serde_json::to_vec(&Value::String(binding.tool.clone()))
                    .map_err(|e| e.to_string())?,
            );
            if params.get("tool_sha256").and_then(Value::as_str) != Some(digest.as_str()) {
                return Err("tool does not match the approval".into());
            }
        }
        _ => return Err("tool does not match the approval".into()),
    }
    if params.get("arguments_omitted") == Some(&Value::Bool(true)) {
        let digest =
            sha256_hex(&serde_json::to_vec(&binding.arguments).map_err(|e| e.to_string())?);
        if params.get("arguments_sha256").and_then(Value::as_str) != Some(digest.as_str()) {
            return Err("arguments do not match the approval".into());
        }
        return Ok(());
    }
    let actual = params.get("arguments").cloned().unwrap_or(Value::Null);
    if canonical_bytes(&actual)? != canonical_bytes(&binding.arguments)? {
        return Err("arguments do not match the approval".into());
    }
    Ok(())
}

fn pending_info(value: &Value) -> Result<PendingInfo, String> {
    let approval_id = required_str(value, "approval_id")?.to_owned();
    if !valid_id(&approval_id) {
        return Err("approval id is not 64 lowercase hex characters".into());
    }
    let arguments = value
        .get("arguments")
        .cloned()
        .ok_or("pending approval has no arguments")?;
    let preview = canonical_bytes(&arguments)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| arguments.to_string());
    Ok(PendingInfo {
        approval_id,
        server: required_str(value, "server")?.to_owned(),
        tool: required_str(value, "tool")?.to_owned(),
        arguments_preview: crate::proxy::display_safe(&preview),
        expires_at: required_str(value, "expires_at")?.to_owned(),
        evidence_id: required_str(value, "evidence_id")?.to_owned(),
    })
}

fn hold_message(home: &Home, pending: &PendingInfo) -> String {
    let dir = shell_quote(&home.root.display().to_string());
    let mut message = format!(
        "This tool call is waiting for local human approval and was not executed.\n\
         Approval id: {id}\n\
         Server: {server}\n\
         Tool: {tool}\n\
         Expires (UTC): {expires}\n\
         A person at this computer has to approve it in a terminal:\n\
           praetore-mcp approve {id} --dir {dir}\n\
         To reject it:\n\
           praetore-mcp reject {id} --dir {dir}\n\
         Evidence id: {evidence}\n",
        id = pending.approval_id,
        server = crate::proxy::display_safe(&pending.server),
        tool = crate::proxy::display_safe(&pending.tool),
        expires = pending.expires_at,
        evidence = pending.evidence_id,
    );
    if !home.approver_key().is_file() || !home.approver_pin().is_file() {
        message.push_str(&format!(
            "This home has no approver key yet. Run `praetore-mcp init --dir {dir}` first; it adds that key and leaves existing keys and receipts in place.\n"
        ));
    }
    message
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn exact_keys(record: &Value, expected: &[&str]) -> Result<(), String> {
    let keys: BTreeSet<&str> = record
        .as_object()
        .ok_or("approval record is not an object")?
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    if keys != expected {
        return Err("approval record fields are not the expected set".into());
    }
    Ok(())
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {key}"))
}

fn find_decision<'a>(
    entries: &'a [JournalEntry],
    approval_id: &str,
) -> Result<Option<&'a Value>, String> {
    let mut found = None;
    for entry in entries {
        if entry.record["kind"] == "decision" && entry.record["approval_id"] == approval_id {
            if found.is_some() {
                return Err(format!("approval {approval_id} is signed more than once"));
            }
            found = Some(&entry.record);
        }
    }
    Ok(found)
}

fn find_evidence<'a>(evidence: &'a [Evidence], id: &str) -> Result<&'a Evidence, String> {
    evidence
        .iter()
        .find(|item| item.evidence_id.to_string() == id)
        .ok_or_else(|| format!("evidence {id} is not in the receipts journal"))
}

fn mode_of(evidence: &Evidence) -> Option<&str> {
    evidence.context.get(MODE_KEY).and_then(Value::as_str)
}

fn valid_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn random_id() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn canonical_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let text = serde_json::to_string(value).map_err(|e| format!("cannot serialize JSON: {e}"))?;
    praetore_core::canonical::canonicalize_json(&text).map_err(|e| e.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn ttl(home: &Home) -> Result<Duration, String> {
    let seconds = if let Some(raw) = std::env::var_os("PRAETORE_MCP_APPROVAL_TTL_SECONDS") {
        let raw = raw
            .to_str()
            .ok_or("PRAETORE_MCP_APPROVAL_TTL_SECONDS is not UTF-8")?;
        parse_ttl(raw, "PRAETORE_MCP_APPROVAL_TTL_SECONDS")?
    } else if let Some(raw) = read_ttl_file(home)? {
        parse_ttl(raw.trim(), "approvals/ttl-seconds")?
    } else {
        DEFAULT_TTL_SECONDS
    };
    Ok(Duration::seconds(seconds))
}

fn parse_ttl(raw: &str, source: &str) -> Result<i64, String> {
    let seconds: i64 = raw
        .parse()
        .map_err(|_| format!("{source} {raw:?} is not an integer number of seconds"))?;
    if !(1..=MAX_TTL_SECONDS).contains(&seconds) {
        return Err(format!(
            "{source} must be from 1 to {MAX_TTL_SECONDS} seconds, got {seconds}"
        ));
    }
    Ok(seconds)
}

fn read_ttl_file(home: &Home) -> Result<Option<String>, String> {
    let path = approvals_dir(home).join("ttl-seconds");
    match fs::read_to_string(&path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot read {}: {error}", path.display())),
    }
}

fn now_utc() -> Result<OffsetDateTime, String> {
    OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|e| e.to_string())
}

fn timestamp(value: OffsetDateTime) -> Result<String, String> {
    value
        .replace_nanosecond(0)
        .map_err(|e| e.to_string())?
        .format(&Rfc3339)
        .map_err(|e| e.to_string())
}

fn parse_time(value: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| format!("time {value:?} is not RFC 3339"))
}

fn read_approver_pin(home: &Home) -> Result<VerifiedPublicKey, String> {
    store::read_attester_pin(&home.approver_pin())
}

struct ApprovalLock {
    _file: fs::File,
}

fn with_lock<T>(home: &Home, body: impl FnOnce(&Path) -> Result<T, String>) -> Result<T, String> {
    store::ensure_dir(&approvals_dir(home), false)?;
    let _lock = ApprovalLock::acquire(home)?;
    body(&journal_path(home))
}

impl ApprovalLock {
    fn acquire(home: &Home) -> Result<Self, String> {
        let path = approvals_dir(home).join(".lock");
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            options.custom_flags(crate::journal::nofollow_flag());
        }
        let file = options
            .open(&path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: flock on a descriptor this function owns.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                return Err(format!(
                    "cannot lock {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(Self { _file: file })
    }
}

fn read_journal(path: &Path) -> Result<Vec<JournalEntry>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        entries.push(
            parse_journal_text(line)
                .map_err(|e| format!("{}:{}: {e}", path.display(), index + 1))?,
        );
    }
    let mut expected_seq = 0u64;
    let mut expected_prev = GENESIS.to_owned();
    for entry in &entries {
        if entry.seq != expected_seq || entry.prev != expected_prev {
            return Err(format!(
                "{}: approval journal seq {} does not follow the previous record; run `praetore-mcp verify`",
                path.display(),
                entry.seq
            ));
        }
        expected_prev = hex::encode(link_bytes(entry.seq, &entry.prev, &entry.canonical));
        expected_seq = expected_seq.saturating_add(1);
    }
    Ok(entries)
}

fn read_journal_unlocked(home: &Home) -> Result<Vec<JournalEntry>, String> {
    let path = journal_path(home);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text =
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        match parse_journal_text(line) {
            Ok(entry) => entries.push(entry),
            Err(error) => {
                return Err(format!("{}:{}: {error}", path.display(), index + 1));
            }
        }
    }
    Ok(entries)
}

fn parse_journal_text(text: &str) -> Result<JournalEntry, String> {
    let value = praetore_core::canonical::parse_json_rejecting_duplicates(text)
        .map_err(|e| format!("not JSON: {e}"))?;
    let object = value
        .as_object()
        .ok_or("approval journal line is not an object")?;
    if object.len() != 3
        || !object.contains_key("seq")
        || !object.contains_key("prev")
        || !object.contains_key("record")
    {
        return Err("approval journal line must contain only seq, prev and record".into());
    }
    let seq = object["seq"].as_u64().ok_or("seq is not an integer")?;
    let prev = object["prev"]
        .as_str()
        .filter(|prev| {
            prev.len() == 64 && prev.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
        .ok_or("prev is not 64 lowercase hex characters")?
        .to_owned();
    let canonical = canonical_bytes(&object["record"])?;
    let canonical_text = std::str::from_utf8(&canonical)
        .map_err(|_| "canonical approval record is not UTF-8".to_owned())?;
    let expected = format!("{{\"seq\":{seq},\"prev\":\"{prev}\",\"record\":{canonical_text}}}");
    if text != expected {
        return Err("approval journal line is not in canonical form".into());
    }
    Ok(JournalEntry {
        seq,
        prev,
        record: object["record"].clone(),
        canonical,
    })
}

fn link_bytes(seq: u64, prev: &str, canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(JOURNAL_DOMAIN);
    hasher.update(seq.to_be_bytes());
    hasher.update(prev.as_bytes());
    hasher.update(canonical);
    hasher.finalize().into()
}

fn append_line(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        options.custom_flags(crate::journal::nofollow_flag());
    }
    let (mut file, created) = match options.open(path) {
        Ok(file) => (file, false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            options
                .create_new(true)
                .open(path)
                .map_err(|e| format!("cannot create {}: {e}", path.display()))?,
            true,
        ),
        Err(error) => return Err(format!("cannot open {}: {error}", path.display())),
    };
    file.write_all(bytes)
        .and_then(|()| file.sync_data())
        .map_err(|e| format!("cannot append to {}: {e}", path.display()))?;
    if created && let Some(dir) = path.parent() {
        crate::fsutil::sync_dir(dir).map_err(|e| format!("cannot sync {}: {e}", dir.display()))?;
    }
    Ok(())
}

fn write_private(path: &Path, contents: &str) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    if let Some(dir) = path.parent() {
        crate::fsutil::sync_dir(dir).map_err(|e| format!("cannot sync {}: {e}", dir.display()))?;
    }
    Ok(())
}

fn approvals_dir(home: &Home) -> PathBuf {
    home.root.join("approvals")
}

fn pending_dir(home: &Home) -> PathBuf {
    approvals_dir(home).join("pending")
}

fn pending_path(home: &Home, approval_id: &str) -> PathBuf {
    pending_dir(home).join(format!("{approval_id}.json"))
}

fn journal_path(home: &Home) -> PathBuf {
    approvals_dir(home).join("journal.jsonl")
}
