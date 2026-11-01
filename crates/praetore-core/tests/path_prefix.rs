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
        .evaluate(&agent, &authority, &mission((action).clone()))
        .unwrap()
        .outcome
}

fn allow_with(condition: PolicyCondition) -> Policy {
    mission_policy(Policy::new(
        "path-policy",
        1,
        vec![
            PolicyRule::new("safe", "modify_file", PolicyEffect::Allow)
                .with_parameter_condition(condition),
        ],
    ))
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
    let policy = mission_policy(Policy::new_v2(
        "path-policy",
        1,
        vec![
            PolicyRule::new("safe", "modify_file", PolicyEffect::Allow)
                .with_parameter_condition(PolicyCondition::path_prefix("path", "/srv/agent")),
            PolicyRule::new("guard", "modify_file", PolicyEffect::RequireApproval)
                .with_parameter_condition(PolicyCondition::path_prefix("path", "/srv/agent")),
        ],
    ));
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

// ---- Regression: unsafe values must match restrictive rules in v1 and v2 ----

fn allow_all_plus(restrictive: PolicyRule, v2: bool) -> Policy {
    let rules = vec![
        PolicyRule::new("allow-all", "modify_file", PolicyEffect::Allow),
        restrictive,
    ];
    if v2 {
        mission_policy(Policy::new_v2("path-policy", 1, rules))
    } else {
        mission_policy(Policy::new("path-policy", 1, rules))
    }
}

#[test]
fn prefix_deny_still_applies_to_dot_dot_values_in_v1_and_v2() {
    for v2 in [false, true] {
        let policy = allow_all_plus(
            PolicyRule::new("secret", "modify_file", PolicyEffect::Deny)
                .with_parameter_condition(PolicyCondition::prefix("path", "/srv/secret/")),
            v2,
        );
        for value in [
            "/srv/secret/../secret/key",
            "/srv/secret/x/../key",
            "/srv/secret%2fkey",
            "/srv/%2E%2e/secret",
            "/srv/secret\u{0}",
        ] {
            assert_eq!(
                outcome(&policy, json!(value)),
                DecisionOutcome::Deny,
                "v2={v2} {value}"
            );
        }
        assert_eq!(
            outcome(&policy, json!("/srv/public/x")),
            DecisionOutcome::Allow
        );
    }
}

#[test]
fn path_prefix_deny_applies_to_unsafe_values_in_v1_and_v2() {
    for v2 in [false, true] {
        let policy = allow_all_plus(
            PolicyRule::new("secret", "modify_file", PolicyEffect::Deny)
                .with_parameter_condition(PolicyCondition::path_prefix("path", "/srv/secret")),
            v2,
        );
        for value in [
            "/srv/secret/../x",
            "/srv/secret//key",
            "/srv/%73ecret/key",
            "/srv/x/../secret",
            "srv/secret/key",
        ] {
            assert_eq!(
                outcome(&policy, json!(value)),
                DecisionOutcome::Deny,
                "v2={v2} {value}"
            );
        }
        assert_eq!(
            outcome(&policy, json!("/srv/secret/key")),
            DecisionOutcome::Deny
        );
        assert_eq!(
            outcome(&policy, json!("/srv/public/key")),
            DecisionOutcome::Allow
        );
    }
}

#[test]
fn require_approval_holds_unsafe_values_in_v1_and_v2() {
    for v2 in [false, true] {
        for condition in [
            PolicyCondition::prefix("path", "/srv/agent/"),
            PolicyCondition::path_prefix("path", "/srv/agent"),
        ] {
            let policy = allow_all_plus(
                PolicyRule::new("review", "modify_file", PolicyEffect::RequireApproval)
                    .with_parameter_condition(condition),
                v2,
            );
            assert_eq!(
                outcome(&policy, json!("/srv/agent/../etc/passwd")),
                DecisionOutcome::RequireApproval,
                "v2={v2}"
            );
        }
    }
}

#[test]
fn allow_never_matches_unsafe_values_in_v1_and_v2() {
    for v2 in [false, true] {
        for condition in [
            PolicyCondition::prefix("path", "/srv/agent/"),
            PolicyCondition::path_prefix("path", "/srv/agent"),
        ] {
            let rules = vec![
                PolicyRule::new("safe", "modify_file", PolicyEffect::Allow)
                    .with_parameter_condition(condition),
            ];
            let policy = if v2 {
                mission_policy(Policy::new_v2("path-policy", 1, rules))
            } else {
                mission_policy(Policy::new("path-policy", 1, rules))
            };
            for value in [
                "/srv/agent/../etc",
                "/srv/agent/%2e%2e/etc",
                "/srv/agent/x\u{0}",
            ] {
                assert_eq!(
                    outcome(&policy, json!(value)),
                    DecisionOutcome::Deny,
                    "{value:?}"
                );
            }
        }
    }
}

// ---- Lexical limits: pin the current, documented behaviour ----
// Nothing below is normalized: these are ordinary characters for the engine.
// Downstream layers must not NFKC-normalize or percent-decode authorized paths.

#[test]
fn lexical_limits_are_not_normalized() {
    let policy = allow_with(PolicyCondition::path_prefix("path", "/srv/agent"));
    for literal in [
        "/srv/agent/\u{FF0E}\u{FF0E}/etc",   // fullwidth full stops "．．"
        "/srv/agent/x\u{2215}..\u{2215}etc", // U+2215 division slash
        "/srv/agent/ ../etc",
        "/srv/agent/.. /etc",
        "/srv/agent/.../etc",
    ] {
        assert_eq!(
            outcome(&policy, json!(literal)),
            DecisionOutcome::Allow,
            "{literal:?}"
        );
    }
    let prefix = allow_with(PolicyCondition::prefix("path", "/srv/agent/"));
    for literal in ["/srv/agent/\u{FF0E}\u{FF0E}/etc", "/srv/agent/.../etc"] {
        assert_eq!(
            outcome(&prefix, json!(literal)),
            DecisionOutcome::Allow,
            "{literal:?}"
        );
    }
}

/// G7 test helper: declares every action type a rule names as Mission.
#[allow(dead_code)]
fn mission_policy(mut policy: praetore_core::Policy) -> praetore_core::Policy {
    for rule in &policy.rules {
        policy
            .action_classes
            .entry(rule.action_type.clone())
            .or_insert(praetore_core::ActionClass::Mission);
    }
    policy
}

/// G7 test helper: classifies `action` as a Mission action. The engine still
/// checks it against its own policy's `action_classes`.
#[allow(dead_code)]
fn mission(action: praetore_core::Action) -> praetore_core::MissionAction {
    praetore_core::Policy::new("classify", 1, vec![])
        .with_mission_actions([action.action_type.clone()])
        .classify(action)
        .expect("classify")
        .into_mission()
        .expect("mission action")
}
