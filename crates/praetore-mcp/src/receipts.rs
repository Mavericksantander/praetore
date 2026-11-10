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
pub fn render_table(lines: &[JournalLine], tail: usize) -> String {
    let start = lines.len().saturating_sub(tail);
    let mut out = format!(
        "{:<20} {:<7} {:<16} {:<22} {:<16} {:<24} {}\n",
        "TIME (UTC)", "MODE", "SERVER", "TOOL", "DECISION", "RULE", "EVIDENCE ID"
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
                out.push_str(&format!(
                    "{:<20} {:<7} {:<16} {:<22} {:<16} {:<24} {}\n",
                    time,
                    mode_of(&evidence).unwrap_or("?"),
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
                    evidence.evidence_id
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
    /// Entry count and link after the last chained entry, to keep somewhere
    /// the journal's writers cannot change and pass back as `expected_head`.
    pub head: Option<Position>,
    pub by_mode: BTreeMap<String, usize>,
    pub by_decision: BTreeMap<&'static str, usize>,
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

/// Verifies one parsed receipt against the local pins.
fn verify_evidence(
    evidence: &Evidence,
    attester: &VerifiedPublicKey,
    issuer_pins: &[TrustedAuthorityIssuer],
) -> Result<(), String> {
    if !evidence.is_high_assurance_shape() {
        return Err("not HighAssurance (v2) evidence".into());
    }
    evidence
        .verify_attester_signature(attester)
        .map_err(|e| format!("attester signature: {}", e.code()))?;
    evidence
        .verify_agent_intent()
        .map_err(|e| format!("agent intent: {}", e.code()))?;
    evidence
        .authority
        .verify_subject_identity(&evidence.agent)
        .map_err(|e| format!("authority subject: {}", e.code()))?;
    // Historical check: the authority must have been valid and pinned at the
    // signed decision time, not necessarily now.
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
        .map_err(|e| format!("authority: {}", e.code()))?;
    if evidence.intent_v2.as_ref().map(|i| i.audience.as_str()) != Some(AUDIENCE) {
        return Err("intent audience is not praetore-mcp".into());
    }
    match mode_of(evidence) {
        Some("observe" | "enforce") => Ok(()),
        _ => Err(format!("missing or invalid {MODE_CONTEXT_KEY}")),
    }
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
    for line in read_journal(home)? {
        report.total += 1;
        let at = format!("{}:{}", line.file.display(), line.line_number);
        let entry = match journal::parse_line(&line.text) {
            Ok(entry) => entry,
            Err(error) => {
                chain.push_unreadable();
                report.failures.push(format!("FAIL {at}: {error}"));
                continue;
            }
        };
        let order = chain.push(&entry);
        match verify_evidence(&entry.evidence, &attester, &pins) {
            Ok(()) if order.is_none() => {
                report.ok += 1;
                *report
                    .by_mode
                    .entry(mode_of(&entry.evidence).unwrap_or("?").to_owned())
                    .or_default() += 1;
                *report
                    .by_decision
                    .entry(decision_label(entry.evidence.decision.outcome))
                    .or_default() += 1;
            }
            Ok(()) => {}
            Err(error) => report.failures.push(format!("FAIL {at}: {error}")),
        }
        if let Some(problem) = order {
            report
                .failures
                .push(format!("FAIL {at}: journal order: {problem}"));
        }
    }
    report.chained = chain.chained;
    report.unchained = chain.unchained;
    report.head = chain.head();
    if let Some(expected) = expected_head {
        match report.head {
            Some(head) if head.prev == expected => {}
            Some(head) => report.failures.push(format!(
                "FAIL journal head {} ({} entries) does not match the expected head {expected}: entries were removed or added",
                head.prev, head.seq
            )),
            None => report.failures.push(format!(
                "FAIL journal has no verifiable head; expected {expected}"
            )),
        }
    }
    Ok(report)
}
