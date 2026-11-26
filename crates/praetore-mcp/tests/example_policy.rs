//! `examples/claude-code-mcp-policy/policy.json`: a praetore-mcp policy for
//! the filesystem MCP server as Claude Code starts it after
//! `praetore-mcp install --client claude-code` (server name `filesystem`).
//! Read-only tools are allowed, the write tools are denied by name, and
//! every other tool falls to the default deny. No rule needs an approval.
//!
//! The test runs what `praetore-mcp policy check` runs on the file, then
//! evaluates calls with the gate of a fresh home that uses it.

use praetore_core::{DecisionOutcome, Policy, PolicyEffect};
use praetore_mcp::{
    gate::{Gate, Mode},
    store::{self, Home},
};
use serde_json::json;
use std::{fs, path::PathBuf};

const SERVER: &str = "filesystem";

fn example() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/claude-code-mcp-policy/policy.json")
}

fn gate_with_example() -> (tempfile::TempDir, Gate) {
    let temp = tempfile::tempdir().unwrap();
    let home = Home::new(temp.path().join("home"));
    store::init(&home).unwrap();
    fs::copy(example(), home.policy()).unwrap();
    let gate = Gate::load(&home, Mode::Enforce).unwrap();
    (temp, gate)
}

/// The outcome and the rules that decided it.
fn decide(gate: &Gate, tool: &str) -> (DecisionOutcome, Vec<String>) {
    let params = json!({"name": tool, "arguments": {"path": "/tmp/praetore-example/a.txt"}});
    let evidence = gate.evaluate_evidence(SERVER, &params).unwrap();
    let outcome = evidence.decision.outcome;
    let rules = evidence
        .decision
        .contributions
        .iter()
        .filter(|c| c.outcome == outcome)
        .map(|c| c.rule_id.clone())
        .collect();
    (outcome, rules)
}

#[test]
fn the_example_policy_passes_policy_check() {
    let text = fs::read_to_string(example()).unwrap();
    let policy = Policy::from_json(&text).unwrap();
    policy.digest().unwrap();
    let warnings = praetore_mcp::policy::lint(&policy, "praetore-mcp", "");
    assert!(warnings.is_empty(), "{warnings:?}");
    assert!(
        !policy.rules.iter().any(praetore_mcp::policy::is_allow_all),
        "the example has no allow-all rule"
    );
    assert!(
        policy
            .rules
            .iter()
            .all(|rule| rule.effect != PolicyEffect::RequireApproval),
        "the example needs no approval"
    );
}

#[test]
fn the_example_policy_allows_a_read_and_denies_a_write() {
    let (_temp, gate) = gate_with_example();
    assert_eq!(
        decide(&gate, "read_text_file"),
        (DecisionOutcome::Allow, vec!["allow-read-text-file".into()])
    );
    assert_eq!(
        decide(&gate, "write_file"),
        (DecisionOutcome::Deny, vec!["deny-write-file".into()])
    );
    // Not named in the example: the default deny, no rule.
    assert_eq!(
        decide(&gate, "create_directory"),
        (DecisionOutcome::Deny, vec![])
    );
}
