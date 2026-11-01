//! Regression: integer against floating-point values must not bypass
//! restrictive rules. Previously v1 returned "no match" for every rule when
//! the representations differed, so `Deny if amount > 10000` was bypassed
//! with `50000.0`.

use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, DecisionOutcome, MatchOperator, Policy,
    PolicyCondition, PolicyEffect, PolicyRule,
};
use serde_json::{Value, json};

fn outcome(policy: &Policy, amount: Value) -> DecisionOutcome {
    let agent = AgentKeyPair::from_secret_bytes(&[7; 32]).identity(AgentId::new());
    let authority = Authority::new(agent.id.clone(), "issuer", vec![]);
    let action = Action::new("transfer", None, json!({ "amount": amount })).unwrap();
    policy
        .evaluate(&agent, &authority, &mission((action).clone()))
        .unwrap()
        .outcome
}

fn allow_all_plus(restrictive: PolicyRule, v2: bool) -> Policy {
    let rules = vec![
        PolicyRule::new("allow-all", "transfer", PolicyEffect::Allow),
        restrictive,
    ];
    if v2 {
        mission_policy(Policy::new_v2("mixed", 1, rules))
    } else {
        mission_policy(Policy::new("mixed", 1, rules))
    }
}

#[test]
fn deny_threshold_applies_to_float_amounts_in_v1_and_v2() {
    for v2 in [false, true] {
        let policy = allow_all_plus(
            PolicyRule::new("deny-large", "transfer", PolicyEffect::Deny)
                .with_parameter_condition(PolicyCondition::greater_than("amount", json!(10_000))),
            v2,
        );
        for amount in [json!(50_000.0), json!(5e4), json!(10_000.5), json!(1e15)] {
            assert_eq!(
                outcome(&policy, amount.clone()),
                DecisionOutcome::Deny,
                "v2={v2} {amount}"
            );
        }
        // The comparison is exact, so values on the safe side are not denied.
        for amount in [json!(10_000.0), json!(9_999.5), json!(-1e15), json!(5)] {
            assert_eq!(
                outcome(&policy, amount.clone()),
                DecisionOutcome::Allow,
                "v2={v2} {amount}"
            );
        }
    }
}

#[test]
fn float_threshold_applies_to_integer_amounts_in_v1_and_v2() {
    for v2 in [false, true] {
        let policy = allow_all_plus(
            PolicyRule::new("approve-large", "transfer", PolicyEffect::RequireApproval)
                .with_parameter_condition(PolicyCondition::new(
                    "amount",
                    MatchOperator::GreaterThanOrEqual,
                    json!(1000.5),
                )),
            v2,
        );
        assert_eq!(
            outcome(&policy, json!(1001)),
            DecisionOutcome::RequireApproval
        );
        assert_eq!(
            outcome(&policy, json!(9_007_199_254_740_991_u64)),
            DecisionOutcome::RequireApproval
        );
        assert_eq!(outcome(&policy, json!(1000)), DecisionOutcome::Allow);
    }
}

#[test]
fn exact_and_membership_deny_apply_to_numerically_equal_floats_in_v1_and_v2() {
    for v2 in [false, true] {
        for condition in [
            PolicyCondition::exact("amount", json!(10_000)),
            PolicyCondition::one_of("amount", vec![json!(1), json!(10_000)]),
        ] {
            let policy = allow_all_plus(
                PolicyRule::new("deny-exact", "transfer", PolicyEffect::Deny)
                    .with_parameter_condition(condition),
                v2,
            );
            assert_eq!(
                outcome(&policy, json!(10_000.0)),
                DecisionOutcome::Deny,
                "v2={v2}"
            );
            assert_eq!(
                outcome(&policy, json!(10_000.5)),
                DecisionOutcome::Allow,
                "v2={v2}"
            );
        }
    }
}

#[test]
fn allow_rules_never_match_a_mixed_numeric_representation() {
    for v2 in [false, true] {
        for condition in [
            PolicyCondition::new("amount", MatchOperator::LessThanOrEqual, json!(100)),
            PolicyCondition::exact("amount", json!(50)),
            PolicyCondition::one_of("amount", vec![json!(50)]),
        ] {
            let rules = vec![
                PolicyRule::new("allow-small", "transfer", PolicyEffect::Allow)
                    .with_parameter_condition(condition),
            ];
            let policy = if v2 {
                mission_policy(Policy::new_v2("mixed", 1, rules))
            } else {
                mission_policy(Policy::new("mixed", 1, rules))
            };
            assert_eq!(outcome(&policy, json!(50.0)), DecisionOutcome::Deny);
            assert_eq!(outcome(&policy, json!(50)), DecisionOutcome::Allow);
        }
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
