//! Reading, displaying and verifying the receipts journal. Verification is
//! delegated to `praetore-core` (`Evidence::from_json` integrity,
//! `verify_attester_signature`, `verify_agent_intent`, issuer pins).

use crate::journal::{self, Chain, ChainLine, Position};
use crate::shown::Show;
use crate::{
    gate::MODE_CONTEXT_KEY,
    store::{self, AUDIENCE, Home},
};
use praetore_core::{DecisionOutcome, Evidence, TrustedAuthorityIssuer, VerifiedPublicKey};
use std::{collections::BTreeMap, fs, path::PathBuf};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub struct JournalLine {
    pub file: PathBuf,
    pub line_number: usize,
    pub text: String,
}

/// All journal lines in file-name (date) order, then line order.
pub fn read_journal(home: &Home) -> Result<Vec<JournalLine>, String> {
    let mut lines = Vec::new();
    for file in journal::journal_files(&home.receipts_dir())? {
        let text =
            fs::read_to_string(&file).map_err(|e| format!("cannot read {}: {e}", file.shown()))?;
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            lines.push(JournalLine {
                file: file.clone(),
                line_number: index + 1,
                text: line.to_owned(),
            });
        }
    }
    Ok(lines)
}

pub fn mode_of(evidence: &Evidence) -> Option<&str> {
    evidence
        .context
        .get(MODE_CONTEXT_KEY)
        .and_then(|v| v.as_str())
}

pub fn decision_label(outcome: DecisionOutcome) -> &'static str {
    match outcome {
        DecisionOutcome::Allow => "ALLOW",
        DecisionOutcome::Deny => "DENY",
        DecisionOutcome::RequireApproval => "REQUIRE_APPROVAL",
    }
}

fn truncate(value: &str, width: usize) -> String {
    let value = crate::proxy::display_safe(value);
    if value.chars().count() <= width {
        value
    } else {
        let mut out: String = value.chars().take(width.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Renders the last `tail` receipts as a compact table. Lines are parsed
/// (integrity-checked) but not signature-verified; use `verify` for that.
/// `approval_status` is keyed by evidence id (`pending`, `approve by …`,
/// `executed once`). An observe `REQUIRE_APPROVAL` receipt with no entry
/// is labeled `enforce would ask`.
pub fn render_table(
    lines: &[JournalLine],
    tail: usize,
    approval_status: &BTreeMap<String, String>,
) -> String {
    let start = lines.len().saturating_sub(tail);
    let mut out = format!(
        "{:<20} {:<7} {:<16} {:<22} {:<18} {:<24} {:<36} {}\n",
        "TIME (UTC)", "MODE", "SERVER", "TOOL", "DECISION", "RULE", "EVIDENCE ID", "APPROVAL"
    );
    for line in &lines[start..] {
        match journal::parse_line(&line.text) {
            Ok(journal::Entry { evidence, .. }) => {
                let time = evidence
                    .decided_at
                    .as_deref()
                    .map(|t| t.chars().take(19).collect::<String>().replace('T', " "))
                    .unwrap_or_else(|| "-".into());
                let tool = crate::unparsed::reader_label(
                    &evidence.action.action_type,
                    &evidence.action.parameters,
                )
                .or_else(|| {
                    evidence.action.parameters.get("tool").map(|t| {
                        t.as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| t.to_string())
                    })
                })
                .unwrap_or_else(|| "(omitted)".into());
                let outcome = evidence.decision.outcome;
                let rule = evidence
                    .decision
                    .contributions
                    .iter()
                    .filter(|c| c.outcome == outcome)
                    .map(|c| c.rule_id.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                let mode = mode_of(&evidence).unwrap_or("?");
                let approval = approval_status
                    .get(&evidence.evidence_id.to_string())
                    .cloned()
                    .unwrap_or_else(|| {
                        if outcome == DecisionOutcome::RequireApproval && mode == "observe" {
                            "enforce would ask".into()
                        } else if outcome == DecisionOutcome::RequireApproval {
                            "held".into()
                        } else {
                            "-".into()
                        }
                    });
                out.push_str(&format!(
                    "{:<20} {:<7} {:<16} {:<22} {:<18} {:<24} {:<36} {}\n",
                    truncate(&time, 20),
                    truncate(mode, 7),
                    truncate(evidence.action.target.as_deref().unwrap_or("-"), 16),
                    truncate(&tool, 22),
                    decision_label(outcome),
                    truncate(
                        if rule.is_empty() {
                            "(default deny)"
                        } else {
                            &rule
                        },
                        24
                    ),
                    evidence.evidence_id,
                    truncate(&approval, 40)
                ));
            }
            Err(error) => out.push_str(&format!(
                "INVALID {}:{}: {error}\n",
                line.file.shown(),
                line.line_number
            )),
        }
    }
    out
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub total: usize,
    pub ok: usize,
    pub failures: Vec<String>,
    /// Entries written before the journal was chained (bare evidence lines).
    pub unchained: u64,
    /// Chained entries.
    pub chained: u64,
    /// Position after the last chained entry: `seq` is the next sequence
    /// number (the last entry's `seq` + 1, not a count of the entries
    /// present, see `chained`) and `prev` the link to keep somewhere the
    /// journal's writers cannot change and pass back as `expected_head`.
    pub head: Option<Position>,
    pub by_mode: BTreeMap<String, usize>,
    pub by_decision: BTreeMap<&'static str, usize>,
    pub approval_decisions: usize,
    pub approval_executions: usize,
    pub approval_head: Option<String>,
    /// One verdict per journal line, in journal order.
    pub lines: Vec<LineVerdict>,
    /// Which journals were compared with a head given by the caller.
    pub anchors: Anchors,
}

/// Which journals `verify` compared with a state kept by the caller: a
/// head printed earlier, or `none` for a journal that must not exist yet.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Anchors {
    pub receipts: bool,
    pub approvals: bool,
}

/// What a `verify` result is worth.
///
/// The keys that sign receipts and approvals are files in the home. A
/// process that can read them can write a different journal from the first
/// entry to a new head, and every check that reads only the home passes on
/// it. The only thing such a process cannot change is a head kept somewhere
/// it cannot write. So a result without both heads is not a pass: it is
/// its own state, with its own exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assurance {
    /// Every check passed, and both journals end exactly at the states the
    /// caller gave.
    Anchored,
    /// Every check that reads only the home passed. `missing` names the
    /// options that were not given.
    Unanchored { missing: Vec<&'static str> },
    /// A check failed.
    Failed,
}

impl Assurance {
    /// Exit code of `verify`: 0 only for [`Assurance::Anchored`].
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Anchored => 0,
            Self::Failed => 1,
            Self::Unanchored { .. } => UNANCHORED_EXIT,
        }
    }

    /// First word of the summary line of `verify`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Anchored => "OK",
            Self::Failed => "FAIL",
            Self::Unanchored { .. } => "UNANCHORED",
        }
    }
}

/// Exit code of `verify` when nothing failed but a head is missing. Not 0:
/// a script that only checks for success must not take it for a pass. Not
/// 1 or 2: those are a failed check and a usage error.
pub const UNANCHORED_EXIT: i32 = 3;

/// The value of `--expected-head` and `--expected-approval-head` for a
/// journal that must be empty or absent.
pub const NO_JOURNAL: &str = "none";

impl VerifyReport {
    pub fn assurance(&self) -> Assurance {
        if !self.failures.is_empty() {
            return Assurance::Failed;
        }
        let mut missing = Vec::new();
        if !self.anchors.receipts {
            missing.push("--expected-head");
        }
        if !self.anchors.approvals {
            missing.push("--expected-approval-head");
        }
        if missing.is_empty() {
            Assurance::Anchored
        } else {
            Assurance::Unanchored { missing }
        }
    }
}

/// A state the caller expects a journal to be in.
#[derive(Clone, Copy)]
enum Expected<T> {
    /// The journal ends at this head.
    Head(T),
    /// The journal is empty or absent.
    Nothing,
}

/// Verifies one journal line against the local pins. Returns the evidence.
pub fn verify_line(
    text: &str,
    attester: &VerifiedPublicKey,
    issuer_pins: &[TrustedAuthorityIssuer],
) -> Result<Evidence, String> {
    let evidence = journal::parse_line(text)?.evidence;
    verify_evidence(&evidence, attester, issuer_pins)?;
    Ok(evidence)
}

/// Result of one check of a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    Ok,
    Fail(String),
    /// Not run: the receipt does not have the HighAssurance shape.
    NotRun,
}

impl Check {
    fn from_result(result: Result<(), String>) -> Self {
        match result {
            Ok(()) => Self::Ok,
            Err(error) => Self::Fail(error),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Fail(_) => "fail",
            Self::NotRun => "not_run",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Fail(error) => Some(error),
            _ => None,
        }
    }
}

/// The checks `verify` runs on one receipt, each with its own result, in
/// the order `verify` reports them. The first failure is what `verify`
/// prints ([`ReceiptChecks::first_failure`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptChecks {
    /// HighAssurance (v2) evidence shape.
    pub shape: Check,
    /// Attester signature, against the local attester pin.
    pub attester_signature: Check,
    /// Agent signature over the intent.
    pub agent_intent: Check,
    /// The authority names the agent that signed.
    pub authority_subject: Check,
    /// Authority signature, against the issuer pins at `decided_at`.
    pub authority_signature: Check,
    /// Intent audience is praetore-mcp.
    pub audience: Check,
    /// `praetore.mode` is observe or enforce.
    pub mode: Check,
}

impl ReceiptChecks {
    /// `(name, result)` in the order `verify` runs them.
    pub fn named(&self) -> [(&'static str, &Check); 7] {
        [
            ("shape", &self.shape),
            ("attester_signature", &self.attester_signature),
            ("agent_intent", &self.agent_intent),
            ("authority_subject", &self.authority_subject),
            ("authority_signature", &self.authority_signature),
            ("audience", &self.audience),
            ("mode", &self.mode),
        ]
    }

    /// The error `verify` reports for this receipt, if any.
    pub fn first_failure(&self) -> Option<&str> {
        self.named()
            .into_iter()
            .find_map(|(_, check)| check.detail())
    }
}

/// Runs every check of one parsed receipt against the local pins. This is
/// the only implementation: `verify` and `dashboard` both use it.
pub fn check_evidence(
    evidence: &Evidence,
    attester: &VerifiedPublicKey,
    issuer_pins: &[TrustedAuthorityIssuer],
) -> ReceiptChecks {
    if !evidence.is_high_assurance_shape() {
        return ReceiptChecks {
            shape: Check::Fail("not HighAssurance (v2) evidence".into()),
            attester_signature: Check::NotRun,
            agent_intent: Check::NotRun,
            authority_subject: Check::NotRun,
            authority_signature: Check::NotRun,
            audience: Check::NotRun,
            mode: Check::NotRun,
        };
    }
    let attester_signature = Check::from_result(
        evidence
            .verify_attester_signature(attester)
            .map_err(|e| format!("attester signature: {}", e.code())),
    );
    let agent_intent = Check::from_result(
        evidence
            .verify_agent_intent()
            .map_err(|e| format!("agent intent: {}", e.code())),
    );
    let authority_subject = Check::from_result(
        evidence
            .authority
            .verify_subject_identity(&evidence.agent)
            .map_err(|e| format!("authority subject: {}", e.code())),
    );
    let authority_signature = Check::from_result(authority_signature(evidence, issuer_pins));
    let audience = Check::from_result(
        if evidence.intent_v2.as_ref().map(|i| i.audience.as_str()) == Some(AUDIENCE) {
            Ok(())
        } else {
            Err("intent audience is not praetore-mcp".into())
        },
    );
    let mode = Check::from_result(match mode_of(evidence) {
        Some("observe" | "enforce") => Ok(()),
        _ => Err(format!("missing or invalid {MODE_CONTEXT_KEY}")),
    });
    ReceiptChecks {
        shape: Check::Ok,
        attester_signature,
        agent_intent,
        authority_subject,
        authority_signature,
        audience,
        mode,
    }
}

/// Historical check: the authority must have been valid and pinned at the
/// signed decision time, not necessarily now.
fn authority_signature(
    evidence: &Evidence,
    issuer_pins: &[TrustedAuthorityIssuer],
) -> Result<(), String> {
    let decided_at = evidence
        .decided_at
        .as_deref()
        .and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok())
        .ok_or("missing decided_at")?;
    let pin = issuer_pins
        .iter()
        .find(|pin| {
            pin.issuer() == evidence.authority.issuer
                && evidence.authority.issuer_key_id.as_deref() == Some(pin.key_id())
        })
        .ok_or("authority issuer is not pinned")?;
    pin.verify_authority_at(&evidence.authority, decided_at)
        .map_err(|e| format!("authority: {}", e.code()))
}

/// Verifies one parsed receipt against the local pins.
fn verify_evidence(
    evidence: &Evidence,
    attester: &VerifiedPublicKey,
    issuer_pins: &[TrustedAuthorityIssuer],
) -> Result<(), String> {
    match check_evidence(evidence, attester, issuer_pins).first_failure() {
        None => Ok(()),
        Some(error) => Err(error.to_owned()),
    }
}

/// What `verify` found for one journal line.
#[derive(Debug, Clone)]
pub struct LineVerdict {
    pub file: PathBuf,
    pub line_number: usize,
    pub text: String,
    /// The parse error, when the line is not a readable receipt.
    pub parse_error: Option<String>,
    /// Every check of the receipt (absent when the line could not be parsed).
    pub checks: Option<ReceiptChecks>,
    /// Journal order problem (seq / prev / duplicate), if any.
    pub order: Option<String>,
    /// Whether `verify` counts this line as verified.
    pub verified: bool,
}

/// Heads printed by an earlier `verify` and kept where the journals'
/// writers cannot change them. Each journal must still end at its head.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExpectedHeads<'a> {
    /// `--expected-head`: the receipts journal.
    pub receipts: Option<&'a str>,
    /// `--expected-approval-head`: `approvals/journal.jsonl`.
    pub approvals: Option<&'a str>,
}

impl<'a> ExpectedHeads<'a> {
    /// The usage error of `verify` for a malformed head, before any journal
    /// is read. `report` checks it first so both exit 2 on it.
    pub fn check(&self) -> Result<(), String> {
        self.parse().map(|_| ())
    }

    #[allow(clippy::type_complexity)]
    fn parse(
        &self,
    ) -> Result<
        (
            Option<Expected<praetore_core::journal_chain::ChainLink>>,
            Option<Expected<&'a str>>,
        ),
        String,
    > {
        let expected_approval_head = self
            .approvals
            .map(|text| {
                if text == NO_JOURNAL {
                    return Ok(Expected::Nothing);
                }
                (text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
                    .then_some(Expected::Head(text))
                    .ok_or(
                        "--expected-approval-head must be 64 lowercase hex characters, or `none`",
                    )
            })
            .transpose()?;
        let expected_head = self
            .receipts
            .map(|text| {
                if text == NO_JOURNAL {
                    return Ok(Expected::Nothing);
                }
                praetore_core::journal_chain::ChainLink::from_hex(text)
                    .map(Expected::Head)
                    .ok_or("--expected-head must be 64 lowercase hex characters, or `none`")
            })
            .transpose()?;
        Ok((expected_head, expected_approval_head))
    }
}

/// [`verify_journal_with`] with only the receipts head.
pub fn verify_journal(home: &Home, expected_head: Option<&str>) -> Result<VerifyReport, String> {
    verify_journal_with(
        home,
        ExpectedHeads {
            receipts: expected_head,
            approvals: None,
        },
    )
}

/// Verifies every receipt and the order of the journal: no entry removed,
/// duplicated or reordered between the first and the last chained entry.
/// Entries removed at the end are only detected with an expected head:
/// `expected.receipts` for the receipts journal, `expected.approvals` for
/// the approval journal.
pub fn verify_journal_with(
    home: &Home,
    expected: ExpectedHeads<'_>,
) -> Result<VerifyReport, String> {
    let (expected_head, expected_approval_head) = expected.parse()?;
    let attester = store::read_attester_pin(&home.attester_pin())?;
    let pins = store::read_issuer_pins(&home.issuer_pins())?;
    let mut report = VerifyReport::default();
    let lines = read_journal(home)?;
    let parsed: Vec<Result<journal::Entry, String>> = lines
        .iter()
        .map(|line| journal::parse_line(&line.text))
        .collect();
    let entries: Vec<ChainLine<'_>> = parsed
        .iter()
        .zip(&lines)
        .map(|(entry, line)| match entry {
            Ok(entry) => ChainLine::Entry(entry),
            Err(_) => ChainLine::Unreadable(journal::claimed_position(&line.text)),
        })
        .collect();
    // The one check of the journal's shape: its lines are exactly the chain
    // that ends at the head (the expected one, or the last line's).
    // #217's Expected<ChainLink> maps onto #216's Option<ChainLink>:
    // Some(link) only for Expected::Head; Nothing or no option is None.
    let rebuild_head = match expected_head {
        Some(Expected::Head(link)) => Some(link),
        Some(Expected::Nothing) | None => None,
    };
    let chain = Chain::rebuild(&entries, rebuild_head);
    let mut parsed_evidence = Vec::new();
    for ((line, entry), order) in lines.into_iter().zip(&parsed).zip(&chain.problems) {
        report.total += 1;
        let at = format!("{}:{}", line.file.shown(), line.line_number);
        let mut verdict = LineVerdict {
            file: line.file,
            line_number: line.line_number,
            text: line.text,
            parse_error: None,
            checks: None,
            order: None,
            verified: false,
        };
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                report.failures.push(format!("FAIL {at}: {error}"));
                verdict.parse_error = Some(error.clone());
                report.lines.push(verdict);
                continue;
            }
        };
        parsed_evidence.push(entry.evidence.clone());
        let checks = check_evidence(&entry.evidence, &attester, &pins);
        match checks.first_failure() {
            None if order.is_none() => {
                report.ok += 1;
                verdict.verified = true;
                *report
                    .by_mode
                    .entry(mode_of(&entry.evidence).unwrap_or("?").to_owned())
                    .or_default() += 1;
                *report
                    .by_decision
                    .entry(decision_label(entry.evidence.decision.outcome))
                    .or_default() += 1;
            }
            None => {}
            Some(error) => report.failures.push(format!("FAIL {at}: {error}")),
        }
        if let Some(problem) = order {
            report
                .failures
                .push(format!("FAIL {at}: journal order: {problem}"));
        }
        verdict.checks = Some(checks);
        verdict.order = order.clone();
        report.lines.push(verdict);
    }
    report.chained = chain.chained;
    report.unchained = chain.unchained;
    report.head = chain.head;
    report.anchors = Anchors {
        receipts: expected_head.is_some(),
        approvals: expected_approval_head.is_some(),
    };
    if let Some(Expected::Nothing) = expected_head
        && report.total > 0
    {
        report.failures.push(format!(
            "FAIL journal has {} line(s), but --expected-head {NO_JOURNAL} says it was empty: entries were added",
            report.total
        ));
    }
    // chain.missing (#216) and Expected::Head mismatch (#217) both become
    // failures. Failed beats Unanchored. Do not report the same mismatch twice.
    if let Some(missing) = &chain.missing {
        report.failures.push(match (expected_head, report.head) {
            (Some(Expected::Head(expected)), Some(head)) if head.prev != expected => format!(
                "FAIL journal head {} ({} chained entries present, next seq {}) does not match the expected head {expected}: entries were removed or added ({missing})",
                head.prev, report.chained, head.seq
            ),
            (Some(Expected::Head(expected)), None) => format!(
                "FAIL journal has no verifiable head; expected {expected} ({missing})"
            ),
            _ => format!("FAIL journal: {missing}"),
        });
    } else if let Some(Expected::Head(expected)) = expected_head {
        match report.head {
            Some(head) if head.prev == expected => {}
            Some(head) => report.failures.push(format!(
                "FAIL journal head {} ({} chained entries present, next seq {}) does not match the expected head {expected}: entries were removed or added",
                head.prev, report.chained, head.seq
            )),
            None => report.failures.push(format!(
                "FAIL journal has no verifiable head; expected {expected}"
            )),
        }
    }
    let approvals = crate::approvals::verify(home, &parsed_evidence)?;
    report.failures.extend(approvals.failures);
    if let (Some(Expected::Nothing), Some(head)) = (expected_approval_head, &approvals.head) {
        report.failures.push(format!(
            "FAIL approval journal exists (head {head}, {} decision(s), {} execution(s)), but --expected-approval-head {NO_JOURNAL} says there was none: records were added",
            approvals.decisions, approvals.executions
        ));
    }
    if let Some(Expected::Head(expected)) = expected_approval_head {
        match approvals.head.as_deref() {
            Some(head) if head == expected => {}
            Some(head) => report.failures.push(format!(
                "FAIL approval journal head {head} ({} decision(s), {} execution(s)) does not match the expected approval head {expected}: records were removed or added",
                approvals.decisions, approvals.executions
            )),
            None => report.failures.push(format!(
                "FAIL approval journal has no head (absent or empty); expected {expected}: records were removed"
            )),
        }
    }
    report.approval_decisions = approvals.decisions;
    report.approval_executions = approvals.executions;
    report.approval_head = approvals.head;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use praetore_core::{Action, AgentId, AgentIdentity, Authority, DecidedBy, Decision};
    use uuid::Uuid;

    #[test]
    fn render_table_escapes_mode() {
        let id = AgentId::new();
        let agent = AgentIdentity::new(id.clone(), b"test-public-key".to_vec(), "ed25519").unwrap();
        let authority = Authority::new(
            id,
            "praetore-root",
            vec![crate::store::CAPABILITY.to_owned()],
        );
        let action = Action::new(
            crate::store::ACTION_TYPE,
            Some("srv".into()),
            serde_json::json!({"server": "srv", "tool": "echo", "arguments": {}}),
        )
        .unwrap();
        let decision = Decision::allow(
            "ok",
            DecidedBy::Rule {
                rule_id: "r1".into(),
            },
        );
        let context = BTreeMap::from([(
            MODE_CONTEXT_KEY.to_owned(),
            serde_json::json!("m\x1b[2K\r\n\u{202e}\u{200b}"),
        )]);
        let evidence = Evidence::new_with_context(
            Uuid::nil(),
            agent,
            authority,
            action,
            decision,
            None,
            context,
        )
        .unwrap();
        let evidence_json = evidence.to_json().unwrap();
        let line = JournalLine {
            file: PathBuf::from("2026-11-24.jsonl"),
            line_number: 1,
            text: format!(
                "{{\"seq\":0,\"prev\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"evidence\":{evidence_json}}}"
            ),
        };
        let table = render_table(&[line], 10, &BTreeMap::new());
        for forbidden in ["\x1b", "\r", "\u{202e}", "\u{200b}", "[2K\n"] {
            assert!(
                !table.contains(forbidden),
                "raw {forbidden:?} in render_table:\n{table:?}"
            );
        }
        assert!(table.contains("\\u{1b"), "{table}");
    }
}
