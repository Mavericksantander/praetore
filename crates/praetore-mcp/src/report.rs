//! Session reports: a read-only view of what one `wrap` session recorded.
//!
//! When a session ends, two files are written under `DIR/reports/`:
//!
//! * `session-<start UTC>-<id>.json`: a header (praetore-mcp version, agent,
//!   server, mode, seq range, the heads of the receipts and approval
//!   journals, the result of `verify`) and the session's receipts. Each
//!   receipt is the journal line itself, copied byte for byte on a line of
//!   its own, never parsed and written again.
//! * `session-<start UTC>-<id>.pdf`: the same session for a person to read
//!   ([`crate::report_pdf`]).
//!
//! The report is a view. It writes nothing to the journals, signs nothing
//! and takes no part in any policy decision. A failure here is reported on
//! stderr by the caller and changes nothing else.
//!
//! A report file is never replaced. `praetore-mcp report` writes a new pair
//! next to the one written at close,
//! `session-<start UTC>-<id>.regen-<now UTC>.json` and `.pdf`, whose header
//! names the close report in `regenerated_from`.

use crate::shown::Show;
use crate::{
    approvals,
    receipts::{self, VerifyReport},
    store::{self, Home},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

pub const SCHEMA: &str = "praetore-mcp.session-report/1";
/// What the report says about itself. No stronger claim is made anywhere.
pub const STATEMENT: &str =
    "Tamper-evident on this machine; verify against an external copy of the heads.";
/// Failures copied into the JSON header and the PDF (the count is exact).
const MAX_LISTED_FAILURES: usize = 50;
/// First sentence of [`EMPTY_JOURNAL_SUMMARY`], drawn on its own PDF line.
pub const EMPTY_JOURNAL_SUMMARY_JOURNAL: &str =
    "The journal is empty or was deleted or truncated after these receipts were written.";
/// Second sentence of [`EMPTY_JOURNAL_SUMMARY`], drawn on its own PDF line.
pub const EMPTY_JOURNAL_SUMMARY_RECEIPTS: &str = "Every receipt this session named is gone.";
/// PDF headline, JSON `verify.summary` and CLI summary when the receipts
/// journal has no entries and every receipt this session named is gone.
/// `failures_total` does not include those missing ids (it is the count
/// from `verify` of the journal itself, which is 0 for an empty journal),
/// so `failures_total + missing.len()` would read as one problem per
/// missing receipt.
pub const EMPTY_JOURNAL_SUMMARY: &str = "The journal is empty or was deleted or truncated after these receipts were written. Every receipt this session named is gone.";

/// The version in the report header: the crate version for a release
/// build, `<version>-dev+<short commit>` (or `<version>-dev`) for any other
/// build. Set by `build.rs`.
pub const BUILD_VERSION: &str = env!("PRAETORE_MCP_BUILD_VERSION");

pub fn reports_dir(home: &Home) -> PathBuf {
    home.root.join("reports")
}

/// A report file name, as `wrap` and `report` write it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportName {
    /// `session-<start UTC>-<id>`, the stem of the report written at close.
    pub close_stem: String,
    /// The session id, eight lowercase hex characters.
    pub session_id: String,
    /// `<now UTC>` of a `.regen-<now UTC>` file; `None` for the close one.
    pub regenerated_at: Option<String>,
    /// `.pdf` rather than `.json`.
    pub pdf: bool,
}

/// `YYYYMMDDTHHMMSSZ`, digits only where digits go.
fn is_compact_utc(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 16
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 => *byte == b'T',
            15 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

/// Parses exactly `session-<UTC>-<id>.json|.pdf` or
/// `session-<UTC>-<id>.regen-<UTC>.json|.pdf`. Anything else (another
/// prefix or extension, a separator, `..`, upper case, a missing or extra
/// part) is `None`.
pub fn parse_report_name(name: &str) -> Option<ReportName> {
    let (rest, pdf) = match (name.strip_suffix(".json"), name.strip_suffix(".pdf")) {
        (Some(rest), _) => (rest, false),
        (None, Some(rest)) => (rest, true),
        (None, None) => return None,
    };
    let (close_stem, regenerated_at) = match rest.split_once(REGEN_MARK) {
        Some((stem, at)) => (stem, Some(at)),
        None => (rest, None),
    };
    if regenerated_at.is_some_and(|at| !is_compact_utc(at)) {
        return None;
    }
    let body = close_stem.strip_prefix("session-")?;
    let (start, id) = body.split_at_checked(16)?;
    let id = id.strip_prefix('-')?;
    if !is_compact_utc(start) || !valid_session_id(id) {
        return None;
    }
    Some(ReportName {
        close_stem: close_stem.to_owned(),
        session_id: id.to_owned(),
        regenerated_at: regenerated_at.map(str::to_owned),
        pdf,
    })
}

/// Evidence ids of the receipts one `wrap` session journaled, in order.
#[derive(Clone, Default)]
pub struct SessionLog(Arc<Mutex<Vec<String>>>);

impl SessionLog {
    pub fn record(&self, evidence_id: &uuid::Uuid) {
        if let Ok(mut ids) = self.0.lock() {
            ids.push(evidence_id.to_string());
        }
    }

    pub fn ids(&self) -> Vec<String> {
        self.0.lock().map(|ids| ids.clone()).unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct SessionMeta {
    /// Eight lowercase hex characters.
    pub id: String,
    pub server: String,
    pub mode: String,
    pub started_at: OffsetDateTime,
    pub ended_at: OffsetDateTime,
}

pub fn new_session_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
}

pub fn valid_session_id(id: &str) -> bool {
    id.len() == 8 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The heads of both journals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Heads {
    /// Next sequence number and link after the last chained receipt.
    pub receipt: Option<(u64, String)>,
    pub approval: Option<String>,
}

impl Heads {
    /// The `verify` command that checks both journals still end at these
    /// heads, one argument group per line, to be run as one line. `DIR`
    /// stands for the home, which reports never print.
    pub fn verify_command_lines(&self) -> Vec<String> {
        let mut lines = vec!["praetore-mcp verify --dir DIR".to_owned()];
        if let Some((_, head)) = &self.receipt {
            lines.push(format!("  --expected-head {head}"));
        }
        if let Some(head) = &self.approval {
            lines.push(format!("  --expected-approval-head {head}"));
        }
        lines
    }

    /// [`Heads::verify_command_lines`] on one line.
    pub fn verify_command(&self) -> String {
        self.verify_command_lines()
            .iter()
            .map(|line| line.trim())
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn of(report: &VerifyReport) -> Self {
        Self {
            receipt: report.head.map(|head| (head.seq, head.prev.to_string())),
            approval: report.approval_head.clone(),
        }
    }
}

/// What a report is built from.
pub struct Source {
    pub meta: SessionMeta,
    pub evidence_ids: Vec<String>,
    /// Heads recorded when the session closed; `None` to take them now.
    pub close_heads: Option<Heads>,
    /// Agent recorded by an earlier report, used when no receipt names it.
    pub agent: Option<String>,
    /// For `praetore-mcp report`: the file name of the report written at
    /// close. `None` when the session closes.
    pub regenerated_from: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    Allow,
    Deny,
    /// Enforce `REQUIRE_APPROVAL`, not forwarded.
    Held,
    /// Enforce `REQUIRE_APPROVAL`, forwarded once with a signed approval.
    Approved,
    /// Observe `REQUIRE_APPROVAL`: recorded, not held.
    WouldAsk,
    /// The line is in the journal but its decision cannot be read.
    Unreadable,
}

impl Label {
    pub fn text(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Deny => "DENY",
            Self::Held => "HELD",
            Self::Approved => "APPROVED",
            Self::WouldAsk => "WOULD ASK",
            Self::Unreadable => "UNREADABLE",
        }
    }
}

/// One receipt of the session, as the PDF shows it.
#[derive(Debug, Clone)]
pub struct Row {
    pub seq: Option<u64>,
    pub evidence_id: String,
    pub decided_at: Option<OffsetDateTime>,
    pub tool: String,
    pub label: Label,
    pub rule: String,
    pub reason: String,
    /// Whether `verify` counts this journal line as verified.
    pub verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStatus {
    Approved,
    Rejected,
    Pending,
    Expired,
}

impl ApprovalStatus {
    pub fn text(self) -> &'static str {
        match self {
            Self::Approved => "APPROVED",
            Self::Rejected => "REJECTED",
            Self::Pending => "PENDING",
            Self::Expired => "EXPIRED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApprovalRow {
    pub approval_id: String,
    pub tool: String,
    pub status: ApprovalStatus,
    /// Key id that signed the decision (`None` while undecided).
    pub approver: Option<String>,
    /// When it was decided; for an undecided one, when it expires.
    pub at: Option<OffsetDateTime>,
    /// When the approval was used to forward a call.
    pub used_at: Option<OffsetDateTime>,
    /// Whether that call belongs to this session.
    pub used_here: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub allow: usize,
    pub deny: usize,
    pub held: usize,
    pub forwarded: usize,
    pub would_ask: usize,
    pub unreadable: usize,
    pub approved: usize,
    pub rejected: usize,
    pub pending: usize,
    pub expired: usize,
}

#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    pub passed: bool,
    pub checked_at: OffsetDateTime,
    pub journal_receipts: usize,
    pub journal_verified: usize,
    pub failures_total: usize,
    /// At most [`MAX_LISTED_FAILURES`], without the home path.
    pub failures: Vec<String>,
    pub session_receipts: usize,
    pub session_verified: usize,
    /// Evidence ids the session recorded that are not in the journal.
    pub missing: Vec<String>,
    pub heads: Heads,
    pub approval_decisions: usize,
    pub approval_executions: usize,
}

impl VerifyOutcome {
    /// The live journal has no receipts and every evidence id the session
    /// recorded is absent. `failures_total == 0` keeps this distinct from
    /// "verify could not run", which also sets `journal_receipts` to 0.
    pub fn empty_journal_with_all_session_receipts_gone(&self) -> bool {
        self.journal_receipts == 0
            && self.session_receipts == 0
            && !self.missing.is_empty()
            && self.failures_total == 0
    }

    /// Cover headline, JSON `verify.summary` and the CLI summary when
    /// verify failed. `None` when it passed.
    pub fn failure_summary(&self) -> Option<String> {
        if self.passed {
            return None;
        }
        Some(if self.empty_journal_with_all_session_receipts_gone() {
            EMPTY_JOURNAL_SUMMARY.to_owned()
        } else if self.journal_receipts == 0 && self.failures_total > 0 {
            "The journal could not be verified.".to_owned()
        } else {
            format!(
                "{} problem(s) found. {} of {} receipts in the journal verified; {} of {} in this session.",
                self.failures_total + self.missing.len(),
                self.journal_verified,
                self.journal_receipts,
                self.session_verified,
                self.session_receipts
            )
        })
    }
}

/// Everything the PDF shows.
#[derive(Debug, Clone)]
pub struct Report {
    pub version: &'static str,
    pub meta: SessionMeta,
    pub agent: String,
    pub generated_at: OffsetDateTime,
    pub regenerated: bool,
    /// File name of the close report this one was regenerated from.
    pub regenerated_from: Option<String>,
    /// Why the approval journal could not be read, if it could not.
    pub approval_journal_error: Option<String>,
    pub rows: Vec<Row>,
    pub approvals: Vec<ApprovalRow>,
    pub summary: Summary,
    pub seq: Option<(u64, u64)>,
    pub close_heads: Heads,
    pub verify: VerifyOutcome,
    pub json_name: String,
    pub json_sha256: String,
}

#[derive(Debug, Clone)]
pub struct Generated {
    pub json: PathBuf,
    pub pdf: PathBuf,
    pub verify_passed: bool,
    /// When verify failed, the same wording as the PDF headline and
    /// `header.verify.summary`.
    pub verify_summary: Option<String>,
}

pub fn file_stem(meta: &SessionMeta) -> String {
    format!("session-{}-{}", compact_utc(meta.started_at), meta.id)
}

/// `20261115T144207Z`.
fn compact_utc(at: OffsetDateTime) -> String {
    let at = at.to_offset(UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

/// The marker in the file name of a regenerated report.
const REGEN_MARK: &str = ".regen-";

fn rfc3339(at: OffsetDateTime) -> String {
    at.to_offset(UtcOffset::UTC)
        .replace_nanosecond(0)
        .ok()
        .and_then(|at| at.format(&Rfc3339).ok())
        .unwrap_or_default()
}

fn parse_time(value: &Value) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value.as_str()?, &Rfc3339).ok()
}

/// One journal line that belongs to the session.
struct SessionLine {
    text: String,
    value: Value,
    verified: bool,
}

/// The evidence object of a journal line: chained (`evidence` member) or
/// bare (a line written before the chain existed).
fn evidence_of(value: &Value) -> &Value {
    value.get("evidence").unwrap_or(value)
}

fn evidence_id_of(value: &Value) -> Option<&str> {
    evidence_of(value).get("evidence_id")?.as_str()
}

fn strip_home(home: &Home, text: &str) -> String {
    let root = home.root.to_string_lossy().into_owned();
    text.replace(&format!("{root}/"), "")
        .replace(&format!("{root}\\"), "")
}

fn decision_rule(evidence: &Value) -> String {
    let decision = &evidence["decision"];
    let outcome = &decision["outcome"];
    let rules: Vec<&str> = decision["contributions"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter(|c| &c["outcome"] == outcome)
                .filter_map(|c| c["rule_id"].as_str())
                .collect()
        })
        .unwrap_or_default();
    if !rules.is_empty() {
        return rules.join(",");
    }
    match decision["decided_by"]["kind"].as_str() {
        Some("default_deny") => "(default deny)".into(),
        Some(kind) => format!("({})", kind.replace('_', " ")),
        None => "-".into(),
    }
}

fn row_of(line: &SessionLine, executed: &BTreeMap<&str, &Value>) -> Row {
    let evidence = evidence_of(&line.value);
    let evidence_id = evidence["evidence_id"].as_str().unwrap_or_default();
    let mode = evidence["context"][crate::gate::MODE_CONTEXT_KEY].as_str();
    let label = match evidence["decision"]["outcome"].as_str() {
        Some("Allow") => Label::Allow,
        Some("Deny") => Label::Deny,
        Some("RequireApproval") if mode == Some("enforce") => {
            if executed.contains_key(evidence_id) {
                Label::Approved
            } else {
                Label::Held
            }
        }
        Some("RequireApproval") => Label::WouldAsk,
        _ => Label::Unreadable,
    };
    let tool = match &evidence["action"]["parameters"]["tool"] {
        Value::String(tool) => tool.clone(),
        Value::Null => "(omitted)".into(),
        other => other.to_string(),
    };
    // A short reason for the table; the full text is in the JSON file.
    let mut reason = match evidence["decision"]["decided_by"]["kind"].as_str() {
        Some("rule") => "Rule matched".to_owned(),
        Some("default_deny") => "No rule matched".to_owned(),
        _ => evidence["decision"]["reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    };
    match label {
        Label::Approved => reason = "Forwarded with a signed approval".into(),
        Label::Held => reason = "Not forwarded; needs approval".into(),
        Label::WouldAsk => reason = "Observe: enforce would ask".into(),
        _ => {}
    }
    Row {
        seq: line.value.get("seq").and_then(Value::as_u64),
        evidence_id: evidence_id.to_owned(),
        decided_at: parse_time(&evidence["decided_at"]),
        tool,
        label,
        rule: decision_rule(evidence),
        reason,
        verified: line.verified,
    }
}

fn approval_rows(
    home: &Home,
    records: &[Value],
    ids: &BTreeSet<&str>,
    as_of: OffsetDateTime,
) -> Vec<ApprovalRow> {
    let execution_of: BTreeMap<&str, &Value> = records
        .iter()
        .filter(|record| record["kind"] == "execution")
        .filter_map(|record| Some((record["approval_id"].as_str()?, record)))
        .collect();
    let mut rows = Vec::new();
    for record in records.iter().filter(|record| record["kind"] == "decision") {
        let Some(approval_id) = record["approval_id"].as_str() else {
            continue;
        };
        let execution = execution_of.get(approval_id);
        let used_here = execution
            .and_then(|e| e["evidence_id"].as_str())
            .is_some_and(|id| ids.contains(id));
        let asked_here = record["pending_evidence_id"]
            .as_str()
            .is_some_and(|id| ids.contains(id));
        if !used_here && !asked_here {
            continue;
        }
        rows.push(ApprovalRow {
            approval_id: approval_id.to_owned(),
            tool: record["tool"].as_str().unwrap_or("?").to_owned(),
            status: if record["outcome"] == "approve" {
                ApprovalStatus::Approved
            } else {
                ApprovalStatus::Rejected
            },
            approver: record["approver_key_id"].as_str().map(str::to_owned),
            at: parse_time(&record["decided_at"]),
            used_at: execution.and_then(|e| parse_time(&e["executed_at"])),
            used_here,
        });
    }
    for (pending, decision) in approvals::pending_decisions(home, as_of).unwrap_or_default() {
        if !ids.contains(pending.evidence_id.as_str()) {
            continue;
        }
        let status = match decision {
            // Its decision record is already a row above.
            approvals::PendingDecision::Decided(_) => continue,
            approvals::PendingDecision::Expired => ApprovalStatus::Expired,
            approvals::PendingDecision::Open(_) => ApprovalStatus::Pending,
        };
        #[expect(clippy::disallowed_methods, reason = "display only")]
        let at = pending.expiry.at();
        rows.push(ApprovalRow {
            approval_id: pending.approval_id,
            tool: pending.tool,
            status,
            approver: None,
            at,
            used_at: None,
            used_here: false,
        });
    }
    rows
}

fn summarize(rows: &[Row], approvals: &[ApprovalRow]) -> Summary {
    let mut summary = Summary::default();
    for row in rows {
        match row.label {
            Label::Allow => summary.allow += 1,
            Label::Deny => summary.deny += 1,
            Label::Held => summary.held += 1,
            Label::Approved => summary.forwarded += 1,
            Label::WouldAsk => summary.would_ask += 1,
            Label::Unreadable => summary.unreadable += 1,
        }
    }
    for approval in approvals {
        match approval.status {
            ApprovalStatus::Approved => summary.approved += 1,
            ApprovalStatus::Rejected => summary.rejected += 1,
            ApprovalStatus::Pending => summary.pending += 1,
            ApprovalStatus::Expired => summary.expired += 1,
        }
    }
    summary
}

fn heads_json(heads: &Heads) -> (Value, Value) {
    (
        heads.receipt.as_ref().map_or(
            Value::Null,
            |(next_seq, head)| json!({"next_seq": next_seq, "head": head}),
        ),
        heads.approval.as_ref().map_or(Value::Null, |h| json!(h)),
    )
}

fn header_json(report: &Report) -> Value {
    let (close_receipt, close_approval) = heads_json(&report.close_heads);
    let (verify_receipt, verify_approval) = heads_json(&report.verify.heads);
    let summary = &report.summary;
    json!({
        "praetore_mcp_version": report.version,
        "session_id": report.meta.id,
        "agent": report.agent,
        "server": report.meta.server,
        "mode": report.meta.mode,
        "started_at": rfc3339(report.meta.started_at),
        "ended_at": rfc3339(report.meta.ended_at),
        "generated_at": rfc3339(report.generated_at),
        "regenerated": report.regenerated,
        "regenerated_from": report.regenerated_from,
        "approval_journal_error": report.approval_journal_error,
        "seq": {
            "first": report.seq.map(|(first, _)| first),
            "last": report.seq.map(|(_, last)| last),
            "count": report.rows.len(),
        },
        "receipt_journal_head": close_receipt,
        "approval_journal_head": close_approval,
        "verify_command": report.close_heads.verify_command(),
        "verify": {
            "result": if report.verify.passed { "passed" } else { "failed" },
            "checked_at": rfc3339(report.verify.checked_at),
            "journal_receipts": report.verify.journal_receipts,
            "journal_verified": report.verify.journal_verified,
            "failures_total": report.verify.failures_total,
            "failures": report.verify.failures,
            "session_receipts": report.verify.session_receipts,
            "session_verified": report.verify.session_verified,
            "missing_evidence_ids": report.verify.missing,
            "receipt_journal_head": verify_receipt,
            "approval_journal_head": verify_approval,
            "approval_decisions": report.verify.approval_decisions,
            "approval_executions": report.verify.approval_executions,
            "summary": report.verify.failure_summary(),
        },
        "summary": {
            "allow": summary.allow,
            "deny": summary.deny,
            "held": summary.held,
            "forwarded_with_approval": summary.forwarded,
            "observe_would_ask": summary.would_ask,
            "unreadable": summary.unreadable,
            "approved": summary.approved,
            "rejected": summary.rejected,
            "pending": summary.pending,
            "expired": summary.expired,
        },
        "statement": STATEMENT,
    })
}

/// The JSON file: one line of header and approvals, then each receipt on
/// its own line. Receipts and approval records are the journal lines
/// exactly as written (an approval line is `{seq, prev, record}`).
fn render_json(report: &Report, approvals: &[&str], lines: &[SessionLine]) -> String {
    let mut out = format!(
        "{{\"schema\":{},\"header\":{},\"approvals\":[{}],\"receipts\":[\n",
        json!(SCHEMA),
        header_json(report),
        approvals.join(",")
    );
    for (index, line) in lines.iter().enumerate() {
        out.push_str(&line.text);
        if index + 1 < lines.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("]}\n");
    out
}

/// `bytes` in a private (0600) temporary file next to `path`.
fn write_temp(path: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("report path has no file name")?;
    let temp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&temp);
    let written = crate::fsutil::create_new(&temp, 0o600).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    match written {
        Ok(()) => Ok(temp),
        Err(error) => {
            let _ = fs::remove_file(&temp);
            Err(format!("cannot write {}: {error}", path.shown()))
        }
    }
}

/// Gives `temp` the name `path`. A hard link, not a rename: an existing
/// `path` is never replaced (`AlreadyExists` is an error).
fn publish(temp: &Path, path: &Path) -> Result<(), String> {
    let linked = fs::hard_link(temp, path);
    let _ = fs::remove_file(temp);
    linked.map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            format!("{} already exists; it was not replaced", path.shown())
        } else {
            format!("cannot write {}: {error}", path.shown())
        }
    })
}

/// Writes both files of a report, or neither: both temporary files are
/// written first, and both are published only if both were written.
fn write_pair(json: (&Path, &[u8]), pdf: (&Path, &[u8])) -> Result<(), String> {
    let json_temp = write_temp(json.0, json.1)?;
    let pdf_temp = match write_temp(pdf.0, pdf.1) {
        Ok(temp) => temp,
        Err(error) => {
            let _ = fs::remove_file(&json_temp);
            return Err(error);
        }
    };
    if let Err(error) = publish(&json_temp, json.0) {
        let _ = fs::remove_file(&pdf_temp);
        return Err(error);
    }
    if let Err(error) = publish(&pdf_temp, pdf.0) {
        // The JSON was published by this call a moment ago: take it back so
        // no half pair is left.
        let _ = fs::remove_file(json.0);
        return Err(error);
    }
    Ok(())
}

/// Makes `DIR/reports/` exist with mode 0700, also when it already existed.
fn ensure_reports_dir(dir: &Path) -> Result<(), String> {
    store::ensure_dir(dir, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot set the mode of {}: {e}", dir.shown()))?;
    }
    Ok(())
}

/// Builds and writes both files of one session.
pub fn generate(home: &Home, source: Source) -> Result<Generated, String> {
    let now = OffsetDateTime::now_utc();
    let ids: BTreeSet<&str> = source.evidence_ids.iter().map(String::as_str).collect();

    // `verify` reads the whole journal; its lines are the ones copied. If it
    // cannot run at all, the journal is read directly and the report says
    // that verify failed.
    let verified = receipts::verify_journal(home, None);
    let mut journal_lines: Vec<(String, bool)> = match &verified {
        Ok(report) => report
            .lines
            .iter()
            .map(|line| (line.text.clone(), line.verified))
            .collect(),
        Err(_) => receipts::read_journal(home)?
            .into_iter()
            .map(|line| (line.text, false))
            .collect(),
    };
    let lines: Vec<SessionLine> = journal_lines
        .drain(..)
        .filter_map(|(text, verified)| {
            let value: Value = serde_json::from_str(&text).ok()?;
            ids.contains(evidence_id_of(&value)?)
                .then_some(SessionLine {
                    text,
                    value,
                    verified,
                })
        })
        .collect();
    let found: BTreeSet<&str> = lines
        .iter()
        .filter_map(|line| evidence_id_of(&line.value))
        .collect();
    let missing: Vec<String> = source
        .evidence_ids
        .iter()
        .filter(|id| !found.contains(id.as_str()))
        .cloned()
        .collect();

    // The approval journal: each line as written, with its record. If it
    // cannot be read the report says so and lists no approval record.
    let (raw_approvals, approval_journal_error) = match approvals::raw_records(home) {
        Ok(lines) => (lines, None),
        Err(error) => (Vec::new(), Some(strip_home(home, &error))),
    };
    let records: Vec<Value> = raw_approvals
        .iter()
        .map(|(_, record)| record.clone())
        .collect();
    let executed: BTreeMap<&str, &Value> = records
        .iter()
        .filter(|record| record["kind"] == "execution")
        .filter_map(|record| Some((record["evidence_id"].as_str()?, record)))
        .collect();
    let rows: Vec<Row> = lines.iter().map(|line| row_of(line, &executed)).collect();
    let approval_rows = approval_rows(home, &records, &ids, now);
    let shown: BTreeSet<&str> = approval_rows
        .iter()
        .map(|row| row.approval_id.as_str())
        .collect();
    let approval_lines: Vec<&str> = raw_approvals
        .iter()
        .filter(|(_, record)| {
            record["approval_id"]
                .as_str()
                .is_some_and(|id| shown.contains(id))
        })
        .map(|(line, _)| line.as_str())
        .collect();

    let session_verified = rows.iter().filter(|row| row.verified).count();
    let verify = match &verified {
        Ok(report) => VerifyOutcome {
            passed: report.failures.is_empty()
                && missing.is_empty()
                && session_verified == rows.len(),
            checked_at: now,
            journal_receipts: report.total,
            journal_verified: report.ok,
            failures_total: report.failures.len(),
            failures: report
                .failures
                .iter()
                .take(MAX_LISTED_FAILURES)
                .map(|failure| strip_home(home, failure))
                .collect(),
            session_receipts: rows.len(),
            session_verified,
            missing,
            heads: Heads::of(report),
            approval_decisions: report.approval_decisions,
            approval_executions: report.approval_executions,
        },
        Err(error) => VerifyOutcome {
            passed: false,
            checked_at: now,
            journal_receipts: 0,
            journal_verified: 0,
            failures_total: 1,
            failures: vec![format!("verify could not run: {}", strip_home(home, error))],
            session_receipts: rows.len(),
            session_verified: 0,
            missing,
            heads: Heads::default(),
            approval_decisions: 0,
            approval_executions: 0,
        },
    };

    let agent = lines
        .iter()
        .find_map(|line| evidence_of(&line.value)["agent"]["id"].as_str())
        .map(str::to_owned)
        .or(source.agent)
        .or_else(|| {
            let text = fs::read_to_string(home.agent()).ok()?;
            let value: Value = serde_json::from_str(&text).ok()?;
            value["id"].as_str().map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".into());
    let seqs: Vec<u64> = rows.iter().filter_map(|row| row.seq).collect();
    let stem = match &source.regenerated_from {
        None => file_stem(&source.meta),
        Some(_) => format!(
            "{}{REGEN_MARK}{}",
            file_stem(&source.meta),
            compact_utc(now)
        ),
    };
    let mut report = Report {
        version: BUILD_VERSION,
        meta: source.meta,
        agent,
        generated_at: now,
        regenerated: source.regenerated_from.is_some(),
        regenerated_from: source.regenerated_from,
        approval_journal_error,
        summary: summarize(&rows, &approval_rows),
        rows,
        approvals: approval_rows,
        seq: seqs.iter().min().copied().zip(seqs.iter().max().copied()),
        close_heads: source.close_heads.unwrap_or_else(|| verify.heads.clone()),
        verify,
        json_name: format!("{stem}.json"),
        json_sha256: String::new(),
    };

    let json_text = render_json(&report, &approval_lines, &lines);
    report.json_sha256 = hex::encode(Sha256::digest(json_text.as_bytes()));
    let pdf_bytes = crate::report_pdf::render(&report);

    let dir = reports_dir(home);
    ensure_reports_dir(&dir)?;
    let json = dir.join(&report.json_name);
    let pdf = dir.join(format!("{stem}.pdf"));
    write_pair((&json, json_text.as_bytes()), (&pdf, &pdf_bytes))?;
    let _ = crate::fsutil::sync_dir(&dir);
    Ok(Generated {
        json,
        pdf,
        verify_passed: report.verify.passed,
        verify_summary: report.verify.failure_summary(),
    })
}

/// Called by `wrap` when the session ends. A session that journaled no
/// receipt writes no report.
pub fn close_session(
    home: &Home,
    meta: SessionMeta,
    log: &SessionLog,
) -> Result<Option<Generated>, String> {
    let evidence_ids = log.ids();
    if evidence_ids.is_empty() {
        return Ok(None);
    }
    generate(
        home,
        Source {
            meta,
            evidence_ids,
            close_heads: None,
            agent: None,
            regenerated_from: None,
        },
    )
    .map(Some)
}

/// Which session `report` regenerates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Last,
    Session(String),
}

/// The JSON files written at close in `DIR/reports/` (not the regenerated
/// ones), oldest first.
fn session_files(home: &Home) -> Result<Vec<PathBuf>, String> {
    let dir = reports_dir(home);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("cannot read {}: {error}", dir.shown())),
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("session-")
                        && name.ends_with(".json")
                        && !name.contains(REGEN_MARK)
                })
        })
        .collect();
    files.sort();
    Ok(files)
}

/// The header of a session JSON file. It is the first line of the file,
/// which the receipts follow one per line, so only that line is read.
pub fn read_header(path: &Path) -> Option<Value> {
    use std::io::BufRead;
    let mut first = String::new();
    std::io::BufReader::new(fs::File::open(path).ok()?)
        .read_line(&mut first)
        .ok()?;
    header_of_first_line(&first)
}

/// The header in the first line of a session JSON file (the line ends with
/// `"receipts":[`, so `]}` closes the document).
pub fn header_of_first_line(line: &str) -> Option<Value> {
    let document: Value = serde_json::from_str(&format!("{}]}}", line.trim_end())).ok()?;
    (document["schema"] == SCHEMA).then(|| document["header"].clone())
}

/// The session that closed last (file name order breaks a tie).
fn last_closed(files: &[PathBuf]) -> Option<&PathBuf> {
    files
        .iter()
        .filter_map(|path| {
            let header = read_header(path)?;
            Some((parse_time(&header["ended_at"])?, path))
        })
        .max_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(b.1)))
        .map(|(_, path)| path)
}

/// Writes a new report of a session from the JSON file written at close
/// (which names the session's receipts and any evidence ids already
/// missing at close) and the journal as it is now.
/// `Last` is the session that closed last. The heads recorded at close are
/// kept; `verify` runs again. The new pair is written next to the close
/// report, which is never replaced.
pub fn regenerate(home: &Home, selector: &Selector) -> Result<Generated, String> {
    let files = session_files(home)?;
    let path = match selector {
        Selector::Last => last_closed(&files),
        Selector::Session(id) => {
            let suffix = format!("-{id}.json");
            files.iter().rev().find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(&suffix))
            })
        }
    }
    .ok_or_else(|| {
        format!(
            "no session report found in {}; a report can only be regenerated for a session that wrote one",
            reports_dir(home).shown()
        )
    })?;
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.shown()))?;
    let bad = |what: &str| format!("{} is not a session report ({what})", path.shown());
    let document: Value = serde_json::from_str(&text).map_err(|e| bad(&e.to_string()))?;
    if document["schema"] != SCHEMA {
        return Err(bad("unknown schema"));
    }
    let header = &document["header"];
    let field = |key: &str| {
        header[key]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| bad(&format!("header has no {key}")))
    };
    let id = field("session_id")?;
    if !valid_session_id(&id) {
        return Err(bad("invalid session id"));
    }
    let meta = SessionMeta {
        id,
        server: field("server")?,
        mode: field("mode")?,
        started_at: parse_time(&header["started_at"]).ok_or_else(|| bad("invalid started_at"))?,
        ended_at: parse_time(&header["ended_at"]).ok_or_else(|| bad("invalid ended_at"))?,
    };
    let mut evidence_ids: Vec<String> = document["receipts"]
        .as_array()
        .ok_or_else(|| bad("no receipts"))?
        .iter()
        .filter_map(|receipt| evidence_id_of(receipt).map(str::to_owned))
        .collect();
    // Receipts copied at close omit ids already gone from the journal.
    // Those ids are in the header; keep them so regenerate still fails.
    let mut seen: BTreeSet<String> = evidence_ids.iter().cloned().collect();
    if let Some(missing) = header["verify"]["missing_evidence_ids"].as_array() {
        for id in missing.iter().filter_map(|id| id.as_str()) {
            if seen.insert(id.to_owned()) {
                evidence_ids.push(id.to_owned());
            }
        }
    }
    let close_heads = Heads {
        receipt: header["receipt_journal_head"]["next_seq"]
            .as_u64()
            .zip(header["receipt_journal_head"]["head"].as_str())
            .map(|(seq, head)| (seq, head.to_owned())),
        approval: header["approval_journal_head"].as_str().map(str::to_owned),
    };
    generate(
        home,
        Source {
            meta,
            evidence_ids,
            close_heads: Some(close_heads),
            agent: header["agent"].as_str().map(str::to_owned),
            regenerated_from: path.file_name().and_then(|n| n.to_str()).map(str::to_owned),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_eight_hex_characters() {
        let id = new_session_id();
        assert!(valid_session_id(&id), "{id}");
        assert!(!valid_session_id("ABCDEF12"));
        assert!(!valid_session_id("abc"));
        assert!(!valid_session_id("../../ab"));
    }

    #[test]
    fn file_stem_uses_the_utc_start() {
        let meta = SessionMeta {
            id: "a41f9c2e".into(),
            server: "s".into(),
            mode: "enforce".into(),
            started_at: OffsetDateTime::parse("2026-11-15T11:42:07-03:00", &Rfc3339).unwrap(),
            ended_at: OffsetDateTime::parse("2026-11-15T12:00:00-03:00", &Rfc3339).unwrap(),
        };
        assert_eq!(file_stem(&meta), "session-20261115T144207Z-a41f9c2e");
    }

    fn outcome(
        passed: bool,
        journal_receipts: usize,
        journal_verified: usize,
        failures_total: usize,
        session_receipts: usize,
        session_verified: usize,
        missing: &[&str],
    ) -> VerifyOutcome {
        VerifyOutcome {
            passed,
            checked_at: OffsetDateTime::from_unix_timestamp(1_794_000_000).unwrap(),
            journal_receipts,
            journal_verified,
            failures_total,
            failures: Vec::new(),
            session_receipts,
            session_verified,
            missing: missing.iter().map(|id| (*id).to_owned()).collect(),
            heads: Heads::default(),
            approval_decisions: 0,
            approval_executions: 0,
        }
    }

    #[test]
    fn empty_journal_with_all_session_receipts_gone_has_plain_wording() {
        let verify = outcome(false, 0, 0, 0, 0, 0, &["a", "b"]);
        assert!(verify.empty_journal_with_all_session_receipts_gone());
        assert_eq!(
            EMPTY_JOURNAL_SUMMARY,
            format!("{EMPTY_JOURNAL_SUMMARY_JOURNAL} {EMPTY_JOURNAL_SUMMARY_RECEIPTS}")
        );
        assert_eq!(
            verify.failure_summary().as_deref(),
            Some(EMPTY_JOURNAL_SUMMARY)
        );
        assert!(
            !verify
                .failure_summary()
                .unwrap()
                .contains("problem(s) found")
        );
    }

    #[test]
    fn a_non_empty_journal_with_a_missing_receipt_keeps_the_count_headline() {
        let verify = outcome(false, 2, 1, 0, 1, 1, &["gone"]);
        assert!(!verify.empty_journal_with_all_session_receipts_gone());
        assert_eq!(
            verify.failure_summary().as_deref(),
            Some(
                "1 problem(s) found. 1 of 2 receipts in the journal verified; 1 of 1 in this session."
            )
        );
    }

    #[test]
    fn a_passed_verify_has_no_failure_summary() {
        let verify = outcome(true, 2, 2, 0, 2, 2, &[]);
        assert_eq!(verify.failure_summary(), None);
    }

    #[test]
    fn verify_that_could_not_run_keeps_its_headline() {
        // journal_receipts is 0 on this path, but failures_total is not.
        let verify = outcome(false, 0, 0, 1, 0, 0, &["a"]);
        assert!(!verify.empty_journal_with_all_session_receipts_gone());
        assert_eq!(
            verify.failure_summary().as_deref(),
            Some("The journal could not be verified.")
        );
    }
}
