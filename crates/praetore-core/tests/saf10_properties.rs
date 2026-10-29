//! SAF-10 property tests (docs/proposals/saf-10-recover-y-vencimiento-de-aprobaciones.md §8).
//!
//! Decision 5: the properties are written before the implementation.
//! - The `today` module runs against the current API (a797bea) and checks
//!   the parts of each property that already hold without `Recover`.
//! - The `pending` module targets the SAF-10 API decided by the CTO
//!   (29-oct-2026): one `Policy`, no layers; `Decision::recovery`,
//!   `RecoveryObligation`, `Severity`, `PolicyEffect::Recover`,
//!   `Policy::max_approval_ms`, rule `control_loop` / `delta_ms`. It is gated
//!   behind the `saf10-pending` feature and does NOT compile until step 3.

// `PolicyEffect` stops being `Copy` once `Recover` carries data (SAF-10 step 3).
#![allow(clippy::clone_on_copy)]

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
                PolicyRule::new(
                    format!("r{i}"),
                    if *matches { "a" } else { "b" },
                    effect.clone(),
                )
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

/// A policy whose first rule always matches action `"a"`, so the default deny
/// never applies and adding a rule can only be compared against a real match.
fn matched_policy(first: PolicyEffect, rest: &[(bool, PolicyEffect)]) -> Policy {
    let mut all = vec![(true, first)];
    all.extend_from_slice(rest);
    policy(&all)
}

/// Digest of `digest_vector_policy()` computed on main a797bea, before any
/// SAF-10 field existed.
const MAIN_A797BEA_DIGEST: &str =
    "784adb283f6a3446eaf2e47b380416781ca9257fea1258db8edf37417a31b69e";
const MAIN_A797BEA_JSON: &str = r#"{"id":"saf10-digest-vector","version":3,"canonical_version":1,"rules":[{"id":"allow-read","action_type":"read_data","effect":"Allow","required_capability":"read:data","target":null,"parameter_conditions":[],"context_conditions":[]},{"id":"approve-write","action_type":"write_data","effect":"RequireApproval","required_capability":"write:data","target":null,"parameter_conditions":[{"key":"table","operator":"Exact","expected":"users"}],"context_conditions":[]},{"id":"deny-drop","action_type":"drop_table","effect":"Deny","required_capability":null,"target":null,"parameter_conditions":[],"context_conditions":[]}]}"#;

fn digest_vector_policy() -> Policy {
    Policy::new(
        "saf10-digest-vector",
        3,
        vec![
            PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow)
                .with_capability("read:data"),
            PolicyRule::new("approve-write", "write_data", PolicyEffect::RequireApproval)
                .with_capability("write:data")
                .with_parameter_condition(praetore_core::PolicyCondition::exact(
                    "table",
                    json!("users"),
                )),
            PolicyRule::new("deny-drop", "drop_table", PolicyEffect::Deny),
        ],
    )
}

mod today {
    use super::*;

    proptest! {
        /// Property 1 (no Recover): adding a rule to a policy that already
        /// matches never lowers the severity of the decision.
        #[test]
        fn p1_hardening(first in effect(), rest in rules(), extra in (any::<bool>(), effect())) {
            let base = matched_policy(first.clone(), &rest);
            let mut more = rest.clone();
            more.push(extra);
            let hardened = matched_policy(first, &more);
            prop_assert!(sev(evaluate(&hardened)) >= sev(evaluate(&base)));
        }

        /// Property 2 (admission part): if any matching rule denies, the
        /// policy decision is Deny; with no matching rule it is default deny.
        #[test]
        fn p2_deny_wins_in_admission(rules in rules()) {
            let got = evaluate(&policy(&rules));
            let matching: Vec<_> = rules.iter().filter(|(m, _)| *m).map(|(_, e)| e.clone()).collect();
            if matching.is_empty() || matching.contains(&PolicyEffect::Deny) {
                prop_assert_eq!(got, DecisionOutcome::Deny);
            } else if matching.contains(&PolicyEffect::RequireApproval) {
                prop_assert_eq!(got, DecisionOutcome::RequireApproval);
            } else {
                prop_assert_eq!(got, DecisionOutcome::Allow);
            }
        }

        /// Property 7: `strongest` is associative, idempotent and commutative,
        /// and rule order does not change the outcome.
        #[test]
        fn p7_strongest_algebra(a in outcome(), b in outcome(), c in outcome()) {
            prop_assert_eq!(a.strongest(b).strongest(c), a.strongest(b.strongest(c)));
            prop_assert_eq!(a.strongest(a), a);
            prop_assert_eq!(a.strongest(b), b.strongest(a));
        }

        #[test]
        fn p7_rule_order_is_irrelevant(rules in rules()) {
            let mut reversed = rules.clone();
            reversed.reverse();
            prop_assert_eq!(evaluate(&policy(&rules)), evaluate(&policy(&reversed)));
        }
    }

    /// Property 8 (policy part): a policy without the new optional fields
    /// keeps the exact digest and JSON it had on main a797bea.
    #[test]
    fn p8_policy_digest_vector_is_unchanged() {
        let policy = digest_vector_policy();
        assert_eq!(policy.digest().unwrap(), MAIN_A797BEA_DIGEST);
        assert_eq!(serde_json::to_string(&policy).unwrap(), MAIN_A797BEA_JSON);
        let parsed = Policy::from_json(MAIN_A797BEA_JSON).unwrap();
        assert_eq!(parsed.digest().unwrap(), MAIN_A797BEA_DIGEST);
    }
}

/// Written against the SAF-10 API decided by the CTO. Does not compile until
/// step 3.
#[cfg(feature = "saf10-pending")]
mod pending {
    use super::*;
    use praetore_core::decision::Severity;

    fn recover(id: &str) -> PolicyEffect {
        PolicyEffect::Recover {
            recovery_id: id.into(),
            deadline_ms: 500,
        }
    }

    fn effect4() -> impl Strategy<Value = PolicyEffect> {
        prop_oneof![effect(), Just(recover("safe-hold"))]
    }

    fn rules4() -> impl Strategy<Value = Vec<(bool, PolicyEffect)>> {
        prop::collection::vec((any::<bool>(), effect4()), 1..12)
    }

    fn decide(policy: &Policy) -> praetore_core::Decision {
        let agent = AgentKeyPair::from_secret_bytes(&[7; 32]).identity(AgentId::new());
        let authority = Authority::new(agent.id.clone(), "i", vec![]);
        let action = Action::new("a", None, json!({})).unwrap();
        policy.evaluate(&agent, &authority, &action).unwrap()
    }

    proptest! {
        /// Property 1 with Recover: Recover > Deny > RequireApproval > Allow.
        #[test]
        fn p1_hardening_with_recover(first in effect4(), rest in rules4(), extra in (any::<bool>(), effect4())) {
            let base = matched_policy(first.clone(), &rest);
            let mut more = rest.clone();
            more.push(extra);
            let hardened = matched_policy(first, &more);
            prop_assert!(decide(&hardened).severity() >= decide(&base).severity());
        }

        /// Property 2 with Recover: any matching Deny or Recover gives Deny.
        #[test]
        fn p2_deny_wins_with_recover(rules in rules4()) {
            let d = decide(&policy(&rules));
            let restrictive = rules.iter().any(|(m, e)| {
                *m && matches!(e, PolicyEffect::Deny | PolicyEffect::Recover { .. })
            });
            if restrictive {
                prop_assert_eq!(d.outcome, DecisionOutcome::Deny);
            }
        }

        /// Property 3: a matching Recover rule keeps its obligation even when
        /// another rule denies; the invariant recovery => Deny holds.
        #[test]
        fn p3_recover_is_never_suppressed(rules in rules4()) {
            let d = decide(&policy(&rules));
            let first_recover = rules.iter().enumerate().find(|(_, (m, e))| {
                *m && matches!(e, PolicyEffect::Recover { .. })
            });
            match first_recover {
                Some((index, _)) => {
                    let recovery = d.recovery.as_ref().expect("recovery kept");
                    prop_assert_eq!(&recovery.rule_id, &format!("r{index}"));
                    prop_assert_eq!(&recovery.recovery_id, "safe-hold");
                    prop_assert_eq!(d.outcome, DecisionOutcome::Deny);
                    prop_assert_eq!(d.severity(), Severity::Recover);
                }
                None => prop_assert!(d.recovery.is_none()),
            }
        }

        /// Property 7 with Recover: rule order changes neither the outcome
        /// nor whether an obligation exists.
        #[test]
        fn p7_rule_order_with_recover(rules in rules4()) {
            let mut reversed = rules.clone();
            reversed.reverse();
            let a = decide(&policy(&rules));
            let b = decide(&policy(&reversed));
            prop_assert_eq!(a.outcome, b.outcome);
            prop_assert_eq!(a.severity(), b.severity());
            prop_assert_eq!(a.recovery.is_some(), b.recovery.is_some());
        }

        /// Property 9: RequireApproval with control_loop = fast and no
        /// max_approval_ms, or with delta_ms < max_approval_ms, fails to load.
        #[test]
        fn p9_load_validation(
            delta in 0u64..10_000,
            max in prop::option::of(1u64..10_000),
            fast in any::<bool>(),
        ) {
            let rule = json!({
                "id": "r", "action_type": "a", "effect": "RequireApproval",
                "required_capability": null, "target": null,
                "parameter_conditions": [], "context_conditions": [],
                "control_loop": if fast { "fast" } else { "slow" },
                "delta_ms": delta,
            });
            let mut doc = json!({"id": "p", "version": 1, "canonical_version": 1, "rules": [rule]});
            if let Some(max) = max {
                doc["max_approval_ms"] = json!(max);
            }
            let rejected = Policy::from_json(&doc.to_string()).is_err();
            let expected = (fast && max.is_none()) || max.is_some_and(|max| delta < max);
            prop_assert_eq!(rejected, expected);
        }
    }

    /// Decision JSON carrying recovery with outcome Allow is rejected.
    #[test]
    fn recovery_with_allow_is_unrepresentable() {
        let json = r#"{"outcome":"Allow","reason":"x","contributions":[],"recovery":{"recovery_id":"s","rule_id":"r","reason":"x","deadline_ms":1}}"#;
        assert!(serde_json::from_str::<praetore_core::Decision>(json).is_err());
    }
}
