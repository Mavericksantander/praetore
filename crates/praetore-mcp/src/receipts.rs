//! Reading, displaying and verifying the receipts journal. Verification is
//! delegated to `praetore-core` (`Evidence::from_json` integrity,
//! `verify_attester_signature`, `verify_agent_intent`, issuer pins).

use crate::journal::{self, ChainCheck, Position};
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
        let text = fs::read_to_string(&file)
            .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
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
                let tool = evidence
                    .action
                    .parameters
                    .get("tool")
                    .map(|t| {
                        t.as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| t.to_string())
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
                    time,
                    mode,
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
                line.file.display(),
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

/// Verifies every receipt and the order of the journal: no entry removed,
/// duplicated or reordered between the first and the last chained entry.
/// Entries removed at the end are only detected with `expected_head`.
pub fn verify_journal(home: &Home, expected_head: Option<&str>) -> Result<VerifyReport, String> {
    let expected_head = expected_head
        .map(|text| {
            praetore_core::journal_chain::ChainLink::from_hex(text)
                .ok_or("--expected-head must be 64 lowercase hex characters")
        })
        .transpose()?;
    let attester = store::read_attester_pin(&home.attester_pin())?;
    let pins = store::read_issuer_pins(&home.issuer_pins())?;
    let mut report = VerifyReport::default();
    let mut chain = ChainCheck::default();
    let mut parsed_evidence = Vec::new();
    for line in read_journal(home)? {
        report.total += 1;
        let at = format!("{}:{}", line.file.display(), line.line_number);
        let mut verdict = LineVerdict {
            file: line.file,
            line_number: line.line_number,
            text: line.text,
            parse_error: None,
            checks: None,
            order: None,
            verified: false,
        };
        let entry = match journal::parse_line(&verdict.text) {
            Ok(entry) => entry,
            Err(error) => {
                chain.push_unreadable();
                report.failures.push(format!("FAIL {at}: {error}"));
                verdict.parse_error = Some(error);
                report.lines.push(verdict);
                continue;
            }
        };
        parsed_evidence.push(entry.evidence.clone());
        let order = chain.push(&entry);
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
        if let Some(problem) = &order {
            report
                .failures
                .push(format!("FAIL {at}: journal order: {problem}"));
        }
        verdict.checks = Some(checks);
        verdict.order = order;
        report.lines.push(verdict);
    }
    report.chained = chain.chained;
    report.unchained = chain.unchained;
    report.head = chain.head();
    if let Some(expected) = expected_head {
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
    report.approval_decisions = approvals.decisions;
    report.approval_executions = approvals.executions;
    report.approval_head = approvals.head;
    Ok(report)
}
