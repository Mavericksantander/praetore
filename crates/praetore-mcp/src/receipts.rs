//! Reading, displaying and verifying the receipts journal. Verification is
//! delegated to `praetore-core` (`Evidence::from_json` integrity,
//! `verify_attester_signature`, `verify_agent_intent`, issuer pins).

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
    let dir = home.receipts_dir();
    let mut files: Vec<PathBuf> = match fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(format!("cannot read {}: {error}", dir.display())),
    };
    files.sort();
    let mut lines = Vec::new();
    for file in files {
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
        match Evidence::from_json(&line.text) {
            Ok(evidence) => {
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
    pub by_mode: BTreeMap<String, usize>,
    pub by_decision: BTreeMap<&'static str, usize>,
}

/// Verifies one journal line against the local pins. Returns the evidence.
pub fn verify_line(
    text: &str,
    attester: &VerifiedPublicKey,
    issuer_pins: &[TrustedAuthorityIssuer],
) -> Result<Evidence, String> {
    let evidence = Evidence::from_json(text).map_err(|e| format!("{}: {e}", e.code()))?;
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
    match mode_of(&evidence) {
        Some("observe" | "enforce") => {}
        _ => return Err(format!("missing or invalid {MODE_CONTEXT_KEY}")),
    }
    Ok(evidence)
}

pub fn verify_journal(home: &Home) -> Result<VerifyReport, String> {
    let attester = store::read_attester_pin(&home.attester_pin())?;
    let pins = store::read_issuer_pins(&home.issuer_pins())?;
    let mut report = VerifyReport::default();
    for line in read_journal(home)? {
        report.total += 1;
        match verify_line(&line.text, &attester, &pins) {
            Ok(evidence) => {
                report.ok += 1;
                *report
                    .by_mode
                    .entry(mode_of(&evidence).unwrap_or("?").to_owned())
                    .or_default() += 1;
                *report
                    .by_decision
                    .entry(decision_label(evidence.decision.outcome))
                    .or_default() += 1;
            }
            Err(error) => report.failures.push(format!(
                "FAIL {}:{}: {error}",
                line.file.display(),
                line.line_number
            )),
        }
    }
    Ok(report)
}
