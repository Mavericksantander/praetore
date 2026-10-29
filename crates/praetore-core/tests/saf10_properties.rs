//! SAF-10 property tests (docs/proposals/saf-10-recover-y-vencimiento-de-aprobaciones.md §8).
//!
//! Decision 5: the properties are written before the implementation.
//! - The `today` module runs against the current API (a797bea) and checks
//!   the parts of each property that already hold without `Recover`.
//! - The `pending` module targets the proposed API (`RecoveryObligation`,
//!   `Decision::recovery`, `compose`, `PolicyEffect::Recover`, rule `loop`
//!   / `delta_ms`). Those types do not exist yet, so it is gated behind the
//!   `saf10-pending` feature and is expected NOT to compile until step 3
//!   lands. Names there are provisional and must follow the implementation.

use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, DecisionOutcome, Policy, PolicyEffect, PolicyRule,
};
use proptest::prelude::*;
use serde_json::json;

fn outcome() -> impl Strategy<Value = DecisionOutcome> {
    prop_oneof![
        Just(DecisionOutcome::Allow),
        Just(DecisionOutcome::RequireApproval),
        Just(DecisionOutcome::Deny),
    ]
}

fn effect() -> impl Strategy<Value = PolicyEffect> {
    prop_oneof![
        Just(PolicyEffect::Allow),
        Just(PolicyEffect::RequireApproval),
        Just(PolicyEffect::Deny),
    ]
}

/// Current severity order: Deny > RequireApproval > Allow.
fn sev(outcome: DecisionOutcome) -> u8 {
    match outcome {
        DecisionOutcome::Allow => 0,
        DecisionOutcome::RequireApproval => 1,
        DecisionOutcome::Deny => 2,
    }
}

/// Rules over two action types; only rules for `"a"` match the action.
fn rules() -> impl Strategy<Value = Vec<(bool, PolicyEffect)>> {
    prop::collection::vec((any::<bool>(), effect()), 1..12)
}

fn policy(rules: &[(bool, PolicyEffect)]) -> Policy {
    Policy::new(
        "saf10",
        1,
        rules
            .iter()
            .enumerate()
            .map(|(i, (matches, effect))| {
                PolicyRule::new(format!("r{i}"), if *matches { "a" } else { "b" }, *effect)
            })
            .collect(),
    )
}

fn evaluate(policy: &Policy) -> DecisionOutcome {
    let agent = AgentKeyPair::from_secret_bytes(&[7; 32]).identity(AgentId::new());
    let authority = Authority::new(agent.id.clone(), "i", vec![]);
    let action = Action::new("a", None, json!({})).unwrap();
    policy
        .evaluate(&agent, &authority, &action)
        .unwrap()
        .outcome
}

mod today {
    use super::*;

    proptest! {
        /// Property 1 (current subset, no Recover): adding any layer never
        /// weakens: sev(strongest(a, b)) >= sev(a).
        #[test]
        fn p1_hardening_without_recover(a in outcome(), b in outcome()) {
            prop_assert!(sev(a.strongest(b)) >= sev(a));
        }

        /// Property 2 (admission part): if any matching rule denies, the
        /// policy decision is Deny; with no matching rule it is default deny.
        #[test]
        fn p2_deny_wins_in_admission(rules in rules()) {
            let got = evaluate(&policy(&rules));
            let matching: Vec<_> = rules.iter().filter(|(m, _)| *m).map(|(_, e)| *e).collect();
            if matching.is_empty() || matching.contains(&PolicyEffect::Deny) {
                prop_assert_eq!(got, DecisionOutcome::Deny);
            } else if matching.contains(&PolicyEffect::RequireApproval) {
                prop_assert_eq!(got, DecisionOutcome::RequireApproval);
            } else {
                prop_assert_eq!(got, DecisionOutcome::Allow);
            }
        }

        /// Property 7 (current subset): `strongest` on outcomes is
        /// associative, idempotent and commutative.
        #[test]
        fn p7_strongest_algebra(a in outcome(), b in outcome(), c in outcome()) {
            prop_assert_eq!(a.strongest(b).strongest(c), a.strongest(b.strongest(c)));
            prop_assert_eq!(a.strongest(a), a);
            prop_assert_eq!(a.strongest(b), b.strongest(a));
        }

        /// Property 7 (observable through policies): rule order does not
        /// change the outcome.
        #[test]
        fn p7_rule_order_is_irrelevant(rules in rules()) {
            let mut reversed = rules.clone();
            reversed.reverse();
            prop_assert_eq!(evaluate(&policy(&rules)), evaluate(&policy(&reversed)));
        }
    }
}

/// Written against the proposed SAF-10 API. Does not compile until step 3.
#[cfg(feature = "saf10-pending")]
mod pending {
    use super::*;
    use praetore_core::Decision;
    use praetore_core::decision::{RecoveryObligation, RecoverySource, compose};
    use std::time::Duration;

    fn recovery(source: RecoverySource) -> RecoveryObligation {
        RecoveryObligation {
            recovery_id: "safe-hold".into(),
            source_layer: source,
            rule_id: "r".into(),
            reason: "test".into(),
            deadline: Duration::from_millis(500),
        }
    }

    fn decision(source: RecoverySource) -> impl Strategy<Value = Decision> {
        (outcome(), any::<bool>()).prop_map(move |(o, rec)| {
            let mut d = match o {
                DecisionOutcome::Allow => Decision::allow("x"),
                DecisionOutcome::RequireApproval => Decision::require_approval("x"),
                DecisionOutcome::Deny => Decision::deny("x"),
            };
            if rec {
                d.outcome = DecisionOutcome::Deny;
                d.recovery = Some(recovery(source.clone()));
            }
            d
        })
    }

    /// Recover > Deny > RequireApproval > Allow.
    fn sev3(d: &Decision) -> u8 {
        if d.recovery.is_some() {
            3
        } else {
            sev(d.outcome)
        }
    }

    proptest! {
        #[test]
        fn p1_hardening(f in decision(RecoverySource::Floor), t in decision(RecoverySource::Tenant)) {
            prop_assert!(sev3(&compose(f.clone(), t)) >= sev3(&f));
        }

        #[test]
        fn p2_deny_wins_across_layers(f in decision(RecoverySource::Floor), t in decision(RecoverySource::Tenant)) {
            let any_deny = f.outcome == DecisionOutcome::Deny || t.outcome == DecisionOutcome::Deny;
            if any_deny {
                prop_assert_eq!(compose(f, t).outcome, DecisionOutcome::Deny);
            }
        }

        #[test]
        fn p3_floor_recover_is_never_suppressed(f in decision(RecoverySource::Floor), t in decision(RecoverySource::Tenant)) {
            if let Some(x) = f.recovery.clone() {
                prop_assert_eq!(compose(f, t).recovery, Some(x));
            }
        }

        #[test]
        fn p_invariant_recovery_implies_not_allow(f in decision(RecoverySource::Floor), t in decision(RecoverySource::Tenant)) {
            let d = compose(f, t);
            prop_assert!(d.recovery.is_none() || d.outcome != DecisionOutcome::Allow);
        }

        #[test]
        fn p7_compose_algebra(
            a in decision(RecoverySource::Floor),
            b in decision(RecoverySource::Tenant),
            c in decision(RecoverySource::Tenant),
        ) {
            prop_assert_eq!(
                compose(compose(a.clone(), b.clone()), c.clone()),
                compose(a.clone(), compose(b.clone(), c))
            );
            prop_assert_eq!(compose(a.clone(), a.clone()).outcome, a.outcome);
            prop_assert_eq!(compose(a.clone(), b.clone()).outcome, compose(b, a).outcome);
        }

        /// Property 9: RequireApproval is rejected on the fast loop or when
        /// delta_ms < T_approval_ms. Field names are provisional (`loop` is
        /// a Rust keyword; see review note 3).
        #[test]
        fn p9_validation_rejects_require_approval_on_fast_loop(delta in 0u64..10_000, t_approval in 1u64..10_000) {
            let fast = json!({"id":"p","version":1,"canonical_version":1,"rules":[{
                "id":"r","action_type":"a","effect":"RequireApproval",
                "required_capability":null,"target":null,
                "parameter_conditions":[],"context_conditions":[],
                "loop":"fast"}]});
            prop_assert!(Policy::from_json_with_approval_bound(&fast.to_string(), t_approval).is_err());
            let slow = json!({"id":"p","version":1,"canonical_version":1,"rules":[{
                "id":"r","action_type":"a","effect":"RequireApproval",
                "required_capability":null,"target":null,
                "parameter_conditions":[],"context_conditions":[],
                "loop":"slow","delta_ms":delta}]});
            let result = Policy::from_json_with_approval_bound(&slow.to_string(), t_approval);
            prop_assert_eq!(result.is_err(), delta < t_approval);
        }
    }
}
