//! Regression: a restrictive rule's `required_capability` and `target` must
//! not let it silently stop applying. Previously an authority without the
//! rule capability skipped the approval rule, and an action without a target
//! skipped a target-scoped deny, so a broader Allow won.

use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, DecisionOutcome, Policy, PolicyCondition,
    PolicyEffect, PolicyRule,
};
use serde_json::json;

fn outcome(policy: &Policy, capabilities: &[&str], action: &Action) -> DecisionOutcome {
    let agent = AgentKeyPair::from_secret_bytes(&[5; 32]).identity(AgentId::new());
    let authority = Authority::new(
        agent.id.clone(),
        "issuer",
        capabilities.iter().map(|c| c.to_string()).collect(),
    );
    policy.evaluate(&agent, &authority, action).unwrap().outcome
}

fn versions(rules: Vec<PolicyRule>) -> [Policy; 2] {
    [
        Policy::new("scope", 1, rules.clone()),
        Policy::new_v2("scope", 1, rules),
    ]
}

#[test]
fn approval_rule_applies_when_authority_lacks_its_capability() {
    for policy in versions(vec![
        PolicyRule::new("approve-large", "transfer", PolicyEffect::RequireApproval)
            .with_capability("payments:large")
            .with_parameter_condition(PolicyCondition::greater_than("amount", json!(1000))),
        PolicyRule::new("allow-transfer", "transfer", PolicyEffect::Allow)
            .with_capability("payments:write"),
    ]) {
        let large = Action::new("transfer", None, json!({"amount": 5000})).unwrap();
        let small = Action::new("transfer", None, json!({"amount": 10})).unwrap();
        for capabilities in [
            &["payments:write"][..],
            &["payments:write", "payments:large"],
        ] {
            assert_eq!(
                outcome(&policy, capabilities, &large),
                DecisionOutcome::RequireApproval,
                "v{} {capabilities:?}",
                policy.semantics_version
            );
            assert_eq!(
                outcome(&policy, capabilities, &small),
                DecisionOutcome::Allow
            );
        }
    }
}

#[test]
fn deny_rule_applies_when_authority_lacks_its_capability() {
    for policy in versions(vec![
        PolicyRule::new("deny-drop", "admin_op", PolicyEffect::Deny).with_capability("admin"),
        PolicyRule::new("allow-op", "admin_op", PolicyEffect::Allow).with_capability("ops"),
    ]) {
        let action = Action::new("admin_op", None, json!({})).unwrap();
        assert_eq!(outcome(&policy, &["ops"], &action), DecisionOutcome::Deny);
    }
}

#[test]
fn target_scoped_deny_applies_when_action_target_is_omitted() {
    for policy in versions(vec![
        PolicyRule::new("deny-prod", "query", PolicyEffect::Deny).with_target("prod-db"),
        PolicyRule::new("allow-query", "query", PolicyEffect::Allow),
    ]) {
        let omitted = Action::new("query", None, json!({})).unwrap();
        let prod = Action::new("query", Some("prod-db".into()), json!({})).unwrap();
        let dev = Action::new("query", Some("dev-db".into()), json!({})).unwrap();
        // Targets are exact and case-sensitive: `PROD-DB` is another target.
        let other_case = Action::new("query", Some("PROD-DB".into()), json!({})).unwrap();
        assert_eq!(outcome(&policy, &[], &omitted), DecisionOutcome::Deny);
        assert_eq!(outcome(&policy, &[], &prod), DecisionOutcome::Deny);
        assert_eq!(outcome(&policy, &[], &dev), DecisionOutcome::Allow);
        assert_eq!(outcome(&policy, &[], &other_case), DecisionOutcome::Allow);
    }
}

#[test]
fn target_scoped_approval_applies_when_action_target_is_omitted() {
    for policy in versions(vec![
        PolicyRule::new("approve-prod", "deploy", PolicyEffect::RequireApproval)
            .with_target("prod"),
        PolicyRule::new("allow-deploy", "deploy", PolicyEffect::Allow),
    ]) {
        let omitted = Action::new("deploy", None, json!({})).unwrap();
        assert_eq!(
            outcome(&policy, &[], &omitted),
            DecisionOutcome::RequireApproval
        );
    }
}

#[test]
fn allow_rules_keep_requiring_capability_and_exact_target() {
    for policy in versions(vec![
        PolicyRule::new("allow-prod", "query", PolicyEffect::Allow)
            .with_capability("db:read")
            .with_target("prod-db"),
    ]) {
        let omitted = Action::new("query", None, json!({})).unwrap();
        let prod = Action::new("query", Some("prod-db".into()), json!({})).unwrap();
        assert_eq!(
            outcome(&policy, &["db:read"], &omitted),
            DecisionOutcome::Deny
        );
        assert_eq!(outcome(&policy, &[], &prod), DecisionOutcome::Deny);
        assert_eq!(
            outcome(&policy, &["db:read"], &prod),
            DecisionOutcome::Allow
        );
    }
}
