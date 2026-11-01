//! Follow-ups to #20: PathPrefix-aware conflict detection and the documented
//! over-restriction of unsafe values.

use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, DecisionOutcome, Policy, PolicyCondition,
    PolicyEffect, PolicyRule,
};
use serde_json::json;

fn policy_with(conditions: Vec<PolicyCondition>, effect: PolicyEffect) -> Policy {
    let rule = conditions.into_iter().fold(
        PolicyRule::new("r", "modify_file", effect),
        |rule, condition| rule.with_parameter_condition(condition),
    );
    mission_policy(Policy::new("followups", 1, vec![rule]))
}

fn valid(conditions: Vec<PolicyCondition>) -> bool {
    policy_with(conditions, PolicyEffect::Deny)
        .validate()
        .is_ok()
}

#[test]
fn path_prefix_pairs_conflict_by_segments() {
    let pp = PolicyCondition::path_prefix;
    assert!(!valid(vec![pp("path", "/a"), pp("path", "/b")]));
    // Lexically "/ab" starts with "/a" but is not under it by segments.
    assert!(!valid(vec![pp("path", "/a"), pp("path", "/ab")]));
    assert!(valid(vec![pp("path", "/a"), pp("path", "/a/b")]));
    assert!(valid(vec![pp("path", "/a/b/"), pp("path", "/a")]));
    // Different keys never conflict.
    assert!(valid(vec![pp("path", "/a"), pp("other", "/b")]));
}

#[test]
fn exact_and_path_prefix_conflict_when_exact_is_outside() {
    let pp = PolicyCondition::path_prefix;
    let exact = |value: &str| PolicyCondition::exact("path", json!(value));
    assert!(!valid(vec![exact("/b/x"), pp("path", "/a")]));
    assert!(!valid(vec![pp("path", "/a"), exact("/b/x")]));
    assert!(!valid(vec![exact("/ab/x"), pp("path", "/a")]));
    assert!(valid(vec![exact("/a/x"), pp("path", "/a")]));
    assert!(valid(vec![exact("/a"), pp("path", "/a")]));
    // An unsafe exact value is not a conflict (it still matches restrictive rules).
    assert!(valid(vec![exact("/b/../a/x"), pp("path", "/a")]));
}

#[test]
fn path_prefix_and_prefix_conflict_only_when_lexically_unrelated() {
    let pp = PolicyCondition::path_prefix;
    let px = PolicyCondition::prefix;
    assert!(!valid(vec![pp("path", "/a"), px("path", "/b")]));
    assert!(!valid(vec![px("path", "/b"), pp("path", "/a")]));
    assert!(valid(vec![pp("path", "/a"), px("path", "/a/")]));
    assert!(valid(vec![pp("path", "/a/b"), px("path", "/a")]));
}

fn outcome(policy: &Policy, path: &str) -> DecisionOutcome {
    let agent = AgentKeyPair::from_secret_bytes(&[9; 32]).identity(AgentId::new());
    let authority = Authority::new(agent.id.clone(), "i", vec![]);
    let action = Action::new("modify_file", None, json!({ "path": path })).unwrap();
    policy
        .evaluate(&agent, &authority, &mission((action).clone()))
        .unwrap()
        .outcome
}

fn allow_all_plus(restrictive: PolicyRule) -> Policy {
    mission_policy(Policy::new(
        "followups",
        1,
        vec![
            PolicyRule::new("allow-all", "modify_file", PolicyEffect::Allow),
            restrictive,
        ],
    ))
}

// Pins the accepted over-restriction: unsafe values outside the prefix still
// trigger the restrictive rule.
#[test]
fn unsafe_values_outside_prefix_still_trigger_restrictive_rules() {
    for (condition, effect, expected) in [
        (
            PolicyCondition::path_prefix("path", "/srv/secret"),
            PolicyEffect::Deny,
            DecisionOutcome::Deny,
        ),
        (
            PolicyCondition::prefix("path", "/srv/secret/"),
            PolicyEffect::Deny,
            DecisionOutcome::Deny,
        ),
        (
            PolicyCondition::path_prefix("path", "/srv/secret"),
            PolicyEffect::RequireApproval,
            DecisionOutcome::RequireApproval,
        ),
    ] {
        let policy = allow_all_plus(
            PolicyRule::new("restrict", "modify_file", effect).with_parameter_condition(condition),
        );
        assert_eq!(outcome(&policy, "/home/50%.txt"), expected);
        assert_eq!(outcome(&policy, "/home/a/../b"), expected);
        assert_eq!(outcome(&policy, "/home/fine.txt"), DecisionOutcome::Allow);
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
