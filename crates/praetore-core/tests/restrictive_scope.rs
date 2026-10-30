//! Regression: a restrictive rule's `required_capability` and `target` must
//! not let it silently stop applying. Previously an authority without the
//! rule capability skipped the approval rule, and an action without a target
//! skipped a target-scoped deny, so a broader Allow won.
//!
//! A restrictive rule that applies only because the authority lacks its
//! capability or the action has no target is "unbound": it always denies, so
//! it never offers a path to dispatch (RequireApproval) or triggers a recovery
//! obligation (Recover) for an agent the rule was never scoped to.

use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, DecidedBy, Decision, DecisionOutcome, Policy,
    PolicyCondition, PolicyEffect, PolicyRule,
};
use serde_json::json;

fn decision(policy: &Policy, capabilities: &[&str], action: &Action) -> Decision {
    let agent = AgentKeyPair::from_secret_bytes(&[5; 32]).identity(AgentId::new());
    let authority = Authority::new(
        agent.id.clone(),
        "issuer",
        capabilities.iter().map(|c| c.to_string()).collect(),
    );
    policy.evaluate(&agent, &authority, action).unwrap()
}

fn outcome(policy: &Policy, capabilities: &[&str], action: &Action) -> DecisionOutcome {
    decision(policy, capabilities, action).outcome
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
        // Holding `payments:large` makes a large transfer approvable; without
        // it the unbound approval rule denies instead of falling through.
        for (capabilities, expected) in [
            (&["payments:write"][..], DecisionOutcome::Deny),
            (
                &["payments:write", "payments:large"],
                DecisionOutcome::RequireApproval,
            ),
        ] {
            assert_eq!(
                outcome(&policy, capabilities, &large),
                expected,
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

// Regression (review of the fix above): with no broader Allow, an approval
// rule the authority is not scoped to must stay a deny, not become an
// approval that a human could then dispatch.
#[test]
fn unbound_approval_rule_without_allow_denies() {
    for policy in versions(vec![
        PolicyRule::new("approve-prod", "deploy", PolicyEffect::RequireApproval)
            .with_capability("deploy:prod")
            .with_target("prod"),
    ]) {
        let prod = Action::new("deploy", Some("prod".into()), json!({})).unwrap();
        let omitted = Action::new("deploy", None, json!({})).unwrap();
        assert_eq!(
            outcome(&policy, &["data:read"], &prod),
            DecisionOutcome::Deny
        );
        assert_eq!(
            outcome(&policy, &["deploy:prod"], &omitted),
            DecisionOutcome::Deny
        );
        assert_eq!(
            outcome(&policy, &["deploy:prod"], &prod),
            DecisionOutcome::RequireApproval
        );
    }
}

#[test]
fn unbound_recover_rule_denies_without_a_recovery_obligation() {
    for policy in versions(vec![
        PolicyRule::new(
            "hold",
            "actuate",
            PolicyEffect::Recover {
                recovery_id: "safe-hold".into(),
                deadline_ms: 500,
            },
        )
        .with_capability("actuator:write"),
    ]) {
        let action = Action::new("actuate", None, json!({})).unwrap();
        let unbound = decision(&policy, &["data:read"], &action);
        assert_eq!(unbound.outcome, DecisionOutcome::Deny);
        assert!(unbound.recovery.is_none());
        let bound = decision(&policy, &["actuator:write"], &action);
        assert_eq!(bound.outcome, DecisionOutcome::Deny);
        assert!(bound.recovery.is_some());
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
        let prod = Action::new("deploy", Some("prod".into()), json!({})).unwrap();
        assert_eq!(outcome(&policy, &[], &omitted), DecisionOutcome::Deny);
        assert_eq!(
            outcome(&policy, &[], &prod),
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

// An unbound RequireApproval/Recover match did not apply its declared effect,
// so it is recorded as `UnboundRule`; an unbound Deny applied its effect and
// is an ordinary `Rule`. The same rule bound to the authority and target is
// a `Rule` with its declared effect.
#[test]
fn unbound_restrictive_match_records_unbound_rule_as_decider() {
    let recover = PolicyEffect::Recover {
        recovery_id: "safe-hold".into(),
        deadline_ms: 500,
    };
    for effect in [PolicyEffect::RequireApproval, recover, PolicyEffect::Deny] {
        for scoped in [
            PolicyRule::new("restrict", "deploy", effect.clone()).with_capability("deploy:prod"),
            PolicyRule::new("restrict", "deploy", effect.clone()).with_target("prod"),
        ] {
            for policy in versions(vec![
                scoped.clone(),
                PolicyRule::new("allow-deploy", "deploy", PolicyEffect::Allow)
                    .with_capability("deploy:write"),
            ]) {
                let no_target = Action::new("deploy", None, json!({})).unwrap();
                let prod = Action::new("deploy", Some("prod".into()), json!({})).unwrap();
                let unbound_capabilities: &[&str] = if scoped.target.is_some() {
                    &["deploy:write", "deploy:prod"]
                } else {
                    &["deploy:write"]
                };
                let unbound_action = if scoped.target.is_some() {
                    &no_target
                } else {
                    &prod
                };
                let unbound = decision(&policy, unbound_capabilities, unbound_action);
                assert_eq!(unbound.outcome, DecisionOutcome::Deny, "{effect:?}");
                assert_eq!(unbound.recovery, None, "{effect:?}");
                let expected = if effect == PolicyEffect::Deny {
                    DecidedBy::rule("restrict")
                } else {
                    DecidedBy::unbound_rule("restrict")
                };
                assert_eq!(unbound.decided_by, expected, "{effect:?}");
                unbound.validate().unwrap();

                let bound = decision(&policy, &["deploy:write", "deploy:prod"], &prod);
                assert_eq!(bound.decided_by, DecidedBy::rule("restrict"), "{effect:?}");
                assert_eq!(
                    bound.recovery.is_some(),
                    matches!(effect, PolicyEffect::Recover { .. })
                );
                bound.validate().unwrap();
            }
        }
    }
}
