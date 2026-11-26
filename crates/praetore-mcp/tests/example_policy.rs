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
    gate_with_example_in(Mode::Enforce)
}

fn gate_with_example_in(mode: Mode) -> (tempfile::TempDir, Gate) {
    let temp = tempfile::tempdir().unwrap();
    let home = Home::new(temp.path().join("home"));
    store::init(&home).unwrap();
    fs::copy(example(), home.policy()).unwrap();
    let gate = Gate::load(&home, mode).unwrap();
    (temp, gate)
}

/// The outcome and the rules that decided it.
fn decide(gate: &Gate, tool: &str) -> (DecisionOutcome, Vec<String>) {
    decide_on(gate, SERVER, tool, "/tmp/praetore-example/a.txt")
}

fn decide_on(gate: &Gate, server: &str, tool: &str, path: &str) -> (DecisionOutcome, Vec<String>) {
    let params = json!({"name": tool, "arguments": {"path": path}});
    let evidence = gate.evaluate_evidence(server, &params).unwrap();
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

/// The two conditions examples/claude-code-mcp-policy/README.md states.
#[test]
fn the_example_policy_needs_the_server_name_and_sets_no_path_condition() {
    let (_temp, gate) = gate_with_example();
    // Under another server name no rule matches: the default deny.
    assert_eq!(
        decide_on(
            &gate,
            "files",
            "read_text_file",
            "/tmp/praetore-example/a.txt"
        ),
        (DecisionOutcome::Deny, vec![])
    );
    // By tool name only: an allowed tool is allowed on any path.
    for path in ["/tmp/praetore-example/a.txt", "/home/user/other/b.txt"] {
        assert_eq!(
            decide_on(&gate, SERVER, "read_text_file", path),
            (DecisionOutcome::Allow, vec!["allow-read-text-file".into()]),
            "{path}"
        );
    }
    let text = fs::read_to_string(example()).unwrap();
    let policy = Policy::from_json(&text).unwrap();
    for rule in &policy.rules {
        assert_eq!(rule.target.as_deref(), Some(SERVER), "{}", rule.id);
        assert!(
            rule.parameter_conditions.iter().all(|c| c.key == "tool"),
            "{}: a condition other than the tool name",
            rule.id
        );
    }
}

/// What the README says about modes: a write the example denies is blocked
/// only in enforce mode. In observe (what `install` writes by default) it
/// is forwarded unchanged, and its receipt records the DENY.
#[test]
fn the_example_blocks_a_denied_write_only_in_enforce() {
    let line = br#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/praetore-example/a.txt","content":"x"}}}
"#;
    for mode in [Mode::Enforce, Mode::Observe] {
        let (_temp, mut gate) = gate_with_example_in(mode);
        let out = praetore_mcp::proxy::handle_client_line(line, mode, SERVER, &mut gate);
        match mode {
            Mode::Enforce => {
                assert!(out.to_server.is_none(), "enforce forwarded a denied write");
                let reply: serde_json::Value =
                    serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
                assert_eq!(reply["result"]["isError"], true, "{reply}");
            }
            Mode::Observe => {
                assert_eq!(out.to_server.as_deref(), Some(&line[..]));
                assert!(out.to_client.is_none());
                assert!(
                    out.warnings
                        .iter()
                        .any(|w| w.contains("would be DENIED by rule deny-write-file")),
                    "{:?}",
                    out.warnings
                );
            }
        }
    }
}
