//! Path traversal fix for `Prefix` and the new `PathPrefix` operator.
//!
//! Found while porting Canopy's `test_safe_paths` (#19): a lexical prefix
//! let `/srv/agent/../../etc/passwd` satisfy an allow rule for `/srv/agent/`.

use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, DecisionOutcome, Policy, PolicyCondition,
    PolicyEffect, PolicyRule,
};
use serde_json::{Value, json};

fn outcome(policy: &Policy, path: Value) -> DecisionOutcome {
    let agent = AgentKeyPair::from_secret_bytes(&[9; 32]).identity(AgentId::new());
    let authority = Authority::new(agent.id.clone(), "path-issuer", vec![]);
    let action = Action::new("modify_file", None, json!({ "path": path })).unwrap();
    policy
        .evaluate(&agent, &authority, &action)
        .unwrap()
        .outcome
}

fn allow_with(condition: PolicyCondition) -> Policy {
    Policy::new(
        "path-policy",
        1,
        vec![
            PolicyRule::new("safe", "modify_file", PolicyEffect::Allow)
                .with_parameter_condition(condition),
        ],
    )
}

// Same case as #19's ignored `safe_path_prefix_rejects_dot_dot_traversal`
// (tests/canopy_port.rs), which can drop its #[ignore] once both land.
#[test]
fn safe_path_prefix_rejects_dot_dot_traversal() {
    let policy = allow_with(PolicyCondition::prefix("path", "/srv/agent/"));
    assert_eq!(
        outcome(&policy, json!("/srv/agent/../../etc/passwd")),
        DecisionOutcome::Deny
    );
}

#[test]
fn prefix_mitigation_rejects_any_dot_dot_segment_but_keeps_valid_matches() {
    let policy = allow_with(PolicyCondition::prefix("path", "/srv/agent/"));
    for bad in [
        "/srv/agent/..",
        "/srv/agent/x/../../../etc",
        "/srv/agent/..\\..\\etc",
    ] {
        assert_eq!(outcome(&policy, json!(bad)), DecisionOutcome::Deny, "{bad}");
    }
    for good in ["/srv/agent/x.txt", "/srv/agent/a..b", "/srv/agent/.hidden"] {
        assert_eq!(
            outcome(&policy, json!(good)),
            DecisionOutcome::Allow,
            "{good}"
        );
    }
}

#[test]
fn path_prefix_allows_only_normalized_paths_inside_prefix() {
    let policy = allow_with(PolicyCondition::path_prefix("path", "/srv/agent"));
    for good in [
        "/srv/agent",
        "/srv/agent/",
        "/srv/agent/x.txt",
        "/srv/agent/a/b..c",
    ] {
        assert_eq!(
            outcome(&policy, json!(good)),
            DecisionOutcome::Allow,
            "{good}"
        );
    }
    for bad in [
        "/srv/agent/../../etc/passwd",
        "/srv/agent/..",
        "/srv/agent/x/..",
        "/srv/agent/./x",
        "/srv/agent/.",
        "/srv/agent//x",
        "/srv/agent/x//",
        "srv/agent/x",
        "./srv/agent/x",
        "",
        "/srv/agentx",
        "/srv",
        "/etc/passwd",
        "/srv/agent/%2e%2e/etc",
        "/srv/agent/%2E%2E/etc",
        "/srv/agent/%2e%2E/etc",
        "/srv/agent/.%2e/etc",
        "/srv/agent%2fx",
        "/srv/agent/x\\..\\..",
        "/srv/agent/x\u{0}",
    ] {
        assert_eq!(
            outcome(&policy, json!(bad)),
            DecisionOutcome::Deny,
            "{bad:?}"
        );
    }
    assert_eq!(outcome(&policy, json!(42)), DecisionOutcome::Deny);
}

#[test]
fn path_prefix_invalid_value_triggers_restrictive_rule_under_v2() {
    let policy = Policy::new_v2(
        "path-policy",
        1,
        vec![
            PolicyRule::new("safe", "modify_file", PolicyEffect::Allow)
                .with_parameter_condition(PolicyCondition::path_prefix("path", "/srv/agent")),
            PolicyRule::new("guard", "modify_file", PolicyEffect::RequireApproval)
                .with_parameter_condition(PolicyCondition::path_prefix("path", "/srv/agent")),
        ],
    );
    // Malformed path: the allow rule does not match, the restrictive one does.
    assert_eq!(
        outcome(&policy, json!("/srv/agent/../x")),
        DecisionOutcome::RequireApproval
    );
}

#[test]
fn path_prefix_rule_prefix_is_validated_on_load() {
    for bad in [
        "",
        "srv/agent",
        "/srv/../etc",
        "/srv/./agent",
        "/srv//agent",
        "/srv/%2e%2e",
        "/srv\\agent",
        "/srv/agent//",
    ] {
        assert!(
            allow_with(PolicyCondition::path_prefix("path", bad))
                .validate()
                .is_err(),
            "{bad:?}"
        );
    }
    for good in ["/", "/srv", "/srv/agent/"] {
        assert!(
            allow_with(PolicyCondition::path_prefix("path", good))
                .validate()
                .is_ok()
        );
    }
    let json = serde_json::to_string(&allow_with(PolicyCondition::path_prefix("path", "/srv")))
        .unwrap()
        .replace("\"/srv\"", "\"/srv/../etc\"");
    assert!(Policy::from_json(&json).is_err());
}
