//! What the hook tells Claude Code. A DENY with a receipt shows only its
//! reason class and the evidence id, never a rule id or rule text; a
//! RequireApproval shows the evidence id too.

use super::*;
use crate::tests_high_assurance::State;

fn reason_text(verdict: &Verdict) -> String {
    hook_output(verdict).unwrap()["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn no_deny_message_contains_a_rule_id() {
    let s = State::new("deny-messages");
    let outside = json!({ "file_path": "/etc/passwd" });
    let git = json!({ "file_path": format!("{}/.git/config", s.root.display()) });
    let cases = [
        (
            s.input(Some("planner"), "Bash", json!({ "command": "ls" })),
            DenyClass::Capability,
        ),
        (s.input(Some("explorer"), "Read", outside), DenyClass::Path),
        (s.input(Some("coder"), "Write", git), DenyClass::Path),
        (s.read(Some("general-purpose")), DenyClass::Unregistered),
        (
            s.input(None, "safety:hold", json!({})),
            DenyClass::Unclassified,
        ),
        (
            s.input(
                Some("coder"),
                "Bash",
                json!({ "command": "$(echo git) push" }),
            ),
            DenyClass::UnanalyzableCommand,
        ),
    ];
    let rule_ids: Vec<String> = load_policy(&s.state)
        .unwrap()
        .rules
        .iter()
        .map(|rule| rule.id.clone())
        .collect();
    for (input, class) in cases {
        let verdict = authorize(&s.state, &input).unwrap();
        assert_eq!(verdict.outcome, DecisionOutcome::Deny, "{class:?}");
        assert_eq!(verdict.deny_class, Some(class));
        let evidence_id = verdict.evidence_id.clone().unwrap();
        let shown = [reason_text(&verdict), stderr_line(&verdict).unwrap()];
        assert_eq!(
            shown[0],
            format!(
                "PRÆTORE denied this tool call: {} (evidence {evidence_id})",
                class.text()
            )
        );
        for text in &shown {
            assert!(text.contains(&evidence_id), "{text}");
            assert!(!text.contains("rule"), "{text}");
            for id in &rule_ids {
                assert!(!text.contains(id.as_str()), "{text} names rule {id}");
            }
            if let Some(rule) = &verdict.rule {
                assert!(!text.contains(rule.as_str()), "{text}");
            }
        }
    }
    verify_receipts(&s.state).unwrap();
}

#[test]
fn require_approval_message_includes_the_evidence_id() {
    let s = State::new("approval-message");
    let verdict = authorize(
        &s.state,
        &s.input(None, "Bash", json!({ "command": "git push" })),
    )
    .unwrap();
    assert_eq!(verdict.outcome, DecisionOutcome::RequireApproval);
    let output = hook_output(&verdict).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "ask");
    let evidence_id = s.receipts()[0].evidence_id.to_string();
    assert_eq!(verdict.evidence_id.as_deref(), Some(evidence_id.as_str()));
    assert!(
        reason_text(&verdict).ends_with(&format!("(evidence {evidence_id})")),
        "{}",
        reason_text(&verdict)
    );
}
