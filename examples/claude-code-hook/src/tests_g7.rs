//! G7: the hook never sends a safety action to the engine.
//!
//! An AI-enabled system whose executor runs safety actions (`safety:halt`,
//! `safety:stop_all`) without waiting for PRÆTORE must not be held by the hook,
//! even when the receipts journal is down. These tests count engine and
//! policy evaluations (praetore-core `test-probe`, enabled only for tests),
//! intent signatures and receipt appends.

use std::{
    cell::Cell,
    path::PathBuf,
    time::{Duration as StdDuration, Instant},
};

use praetore_core::{ActionClass, probe};

use super::*;

thread_local! {
    /// Requests built for signing on this thread.
    pub(super) static SIGNATURES: Cell<usize> = const { Cell::new(0) };
    /// Receipts appended on this thread.
    pub(super) static APPENDS: Cell<usize> = const { Cell::new(0) };
}

/// Upper bound for the answer to a safety action.
const BOUND: StdDuration = StdDuration::from_millis(100);

struct State {
    root: PathBuf,
    state: PathBuf,
    policy_id: String,
}

impl State {
    /// Initialized hook state with its own policy id (the probe counters are
    /// per policy id), `safety:halt` and `safety:stop_all` declared Safety, and
    /// the receipts journal down: `receipts.jsonl` is a directory.
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "praetore-claude-hook-g7-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let root = fs::canonicalize(&base).unwrap();
        let state = root.join("state");
        initialize(&state, &root, 30).unwrap();
        let policy_id = format!("g7-hook-{name}");
        let mut policy = load_policy(&state)
            .unwrap()
            .with_action_class("safety:halt", ActionClass::Safety)
            .with_action_class("safety:stop_all", ActionClass::Safety);
        policy.id = policy_id.clone();
        fs::write(
            state.join(POLICY_FILE),
            serde_json::to_vec_pretty(&policy).unwrap(),
        )
        .unwrap();
        fs::create_dir(state.join(RECEIPTS_FILE)).unwrap();
        SIGNATURES.with(|count| count.set(0));
        APPENDS.with(|count| count.set(0));
        Self {
            root,
            state,
            policy_id,
        }
    }

    fn input(&self, tool: &str, tool_input: Value) -> HookInput {
        serde_json::from_value(json!({
            "tool_name": tool,
            "tool_input": tool_input,
            "tool_use_id": "toolu_g7",
            "cwd": self.root.display().to_string(),
        }))
        .unwrap()
    }

    fn assert_nothing_recorded(&self) {
        assert_eq!(probe::engine_calls(&self.policy_id), 0, "engine calls");
        assert_eq!(
            probe::policy_evaluations(&self.policy_id),
            0,
            "policy evaluations"
        );
        assert_eq!(SIGNATURES.with(Cell::get), 0, "requests signed");
        assert_eq!(APPENDS.with(Cell::get), 0, "receipts appended");
        let journal = self.state.join(RECEIPTS_FILE);
        assert!(journal.is_dir());
        assert_eq!(fs::read_dir(journal).unwrap().count(), 0);
    }
}

impl Drop for State {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn safety_action_gets_no_decision_and_no_receipt_with_the_journal_down() {
    for tool in ["safety:halt", "safety:stop_all"] {
        let s = State::new(&tool.replace(':', "-"));
        // PRÆTORE's agent keys are gone too: the answer does not need them.
        fs::remove_dir_all(s.state.join(AGENTS_DIR)).unwrap();

        let started = Instant::now();
        let verdict = authorize(&s.state, &s.input(tool, json!({}))).unwrap();
        let elapsed = started.elapsed();

        assert!(verdict.not_governed, "{verdict:?}");
        assert!(
            verdict.reason.starts_with("SAFETY_ACTION_NOT_GOVERNED"),
            "{}",
            verdict.reason
        );
        // The hook adds no permission decision: it neither allows nor denies.
        assert_eq!(hook_output(&verdict), None);
        s.assert_nothing_recorded();
        assert!(elapsed < BOUND, "answered in {elapsed:?}");
    }
}

/// G7: an undeclared `safety:` tool is refused by the engine with a signed
/// DENY (reason `unclassified`) that the hook appends and `verify` accepts.
/// No policy rule is evaluated. The model sees the same text as for any
/// DENY with a receipt.
#[test]
fn undeclared_safety_tool_gets_a_signed_unclassified_deny() {
    let s = State::new("unclassified");
    fs::remove_dir(s.state.join(RECEIPTS_FILE)).unwrap(); // journal up
    let verdict = authorize(&s.state, &s.input("safety:hold", json!({}))).unwrap();
    assert!(!verdict.not_governed);
    assert_eq!(verdict.outcome, DecisionOutcome::Deny);
    assert_eq!(verdict.reason, praetore_core::UNCLASSIFIED_DENY_REASON);
    assert_eq!(probe::engine_calls(&s.policy_id), 1);
    assert_eq!(
        probe::policy_evaluations(&s.policy_id),
        0,
        "no rule evaluated"
    );
    assert_eq!(APPENDS.with(Cell::get), 1);

    let line: Value = serde_json::from_str(
        fs::read_to_string(s.state.join(RECEIPTS_FILE))
            .unwrap()
            .trim(),
    )
    .unwrap();
    let evidence = Evidence::from_json(&line["evidence"].to_string()).unwrap();
    assert_eq!(evidence.action.action_type, "safety:hold");
    assert_eq!(evidence.decision.reason, praetore_core::UNCLASSIFIED_DENY_REASON);
    assert_eq!(
        evidence.decision.decided_by(),
        Some(&praetore_core::DecidedBy::engine_guard(praetore_core::UNCLASSIFIED_ACTION_GUARD))
    );
    verify_receipts(&s.state).unwrap();

    // Same client text as a DENY decided by a rule (here: no capability).
    let output = hook_output(&verdict).unwrap();
    let text = output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert_eq!(
        text,
        format!(
            "PRÆTORE denied this tool call (evidence {})",
            evidence.evidence_id
        )
    );
    let ruled = authorize(&s.state, &s.input("Write", json!({"file_path": "/etc/x"}))).unwrap();
    let ruled_text = hook_output(&ruled).unwrap()["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(ruled.outcome, DecisionOutcome::Deny);
    assert!(ruled_text.starts_with("PRÆTORE denied this tool call (evidence "));
    assert!(!ruled_text.contains("rule"), "{ruled_text}");
}

/// G7: when the agent key does not match its issued identity, an undeclared
/// tool call is refused before anything is signed: no receipt.
#[test]
fn mismatched_key_leaves_no_unclassified_receipt() {
    let s = State::new("forged");
    fs::remove_dir(s.state.join(RECEIPTS_FILE)).unwrap();
    // The main key no longer matches the main identity.
    fs::write(
        s.state.join(AGENTS_DIR).join("main.key"),
        hex::encode([5u8; 32]),
    )
    .unwrap();
    assert!(authorize(&s.state, &s.input("safety:hold", json!({}))).is_err());
    assert!(!s.state.join(RECEIPTS_FILE).exists());
    assert_eq!(probe::engine_calls(&s.policy_id), 0);
}

/// Control: a mission tool call in the same state reaches the engine and is
/// signed, and the journal really is down, so the hook fails closed.
#[test]
fn mission_tool_call_is_evaluated_and_fails_closed_with_the_journal_down() {
    let s = State::new("mission-control");
    let file = format!("{}/notes.txt", s.root.display());
    let result = authorize(&s.state, &s.input("Read", json!({ "file_path": file })));
    assert!(result.is_err(), "the receipt could not be appended");
    assert_eq!(probe::engine_calls(&s.policy_id), 1);
    assert_eq!(SIGNATURES.with(Cell::get), 1);
    assert_eq!(APPENDS.with(Cell::get), 1);
}

/// G7 limit: without a readable policy nothing can be classified, so the
/// hook denies every tool call, `safety:*` included (fail closed).
#[test]
fn unreadable_policy_denies_a_safety_tool_call() {
    for broken in ["not json", "directory", "missing"] {
        let s = State::new(&format!("unreadable-{}", broken.replace(' ', "-")));
        let policy = s.state.join(POLICY_FILE);
        fs::remove_file(&policy).unwrap();
        match broken {
            "not json" => fs::write(&policy, "{not a policy").unwrap(),
            "directory" => fs::create_dir(&policy).unwrap(),
            _ => {}
        }
        let verdict =
            authorize(&s.state, &s.input("safety:halt", json!({}))).unwrap_or_else(fail_closed);
        assert!(!verdict.not_governed, "{broken}");
        assert_eq!(verdict.outcome, DecisionOutcome::Deny, "{broken}");
        let output = hook_output(&verdict).expect("a deny decision");
        assert_eq!(
            output["hookSpecificOutput"]["permissionDecision"], "deny",
            "{broken}"
        );
        s.assert_nothing_recorded();
    }
}

/// State written before G7 has a format 1 policy: every call is denied and
/// the error names the migration step.
#[test]
fn format_1_policy_denies_and_points_to_the_migration() {
    let s = State::new("format-1");
    fs::write(
        s.state.join(POLICY_FILE),
        r#"{"id":"claude-code-agents","version":1,"canonical_version":1,"semantics_version":2,"rules":[]}"#,
    )
    .unwrap();
    let error = authorize(&s.state, &s.input("safety:halt", json!({}))).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("policy format 1"), "{message}");
    assert!(
        message.contains("praetore policy classify --policy"),
        "{message}"
    );
    assert_eq!(fail_closed(error).outcome, DecisionOutcome::Deny);
    s.assert_nothing_recorded();
}

#[test]
fn tool_mapping_agrees_with_action_type_of() {
    for tool in [
        "Read",
        "Grep",
        "Glob",
        "Edit",
        "MultiEdit",
        "Write",
        "NotebookEdit",
        "Bash",
        "WebFetch",
        "WebSearch",
        "Agent",
        "Task",
        "mcp__server__tool",
        "safety:halt",
    ] {
        let (action_type, ..) = classify(tool, &json!({}), None);
        assert_eq!(action_type, action_type_of(tool), "{tool}");
    }
}

#[test]
fn default_policy_is_format_2_and_declares_every_mapped_action_type() {
    let policy = default_policy("/project", "/home/user");
    policy.validate().unwrap();
    for tool in ["Read", "Write", "Bash", "WebFetch", "Agent", "Other"] {
        assert_eq!(
            policy.action_classes.get(&action_type_of(tool)),
            Some(&ActionClass::Mission),
            "{tool}"
        );
    }
    assert!(
        policy
            .action_classes
            .values()
            .all(|class| *class == ActionClass::Mission)
    );
}
