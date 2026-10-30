//! SAF-10 property tests (docs/proposals/SAF-10-RECOVER-Y-VENCIMIENTO-DE-APROBACIONES.md §8).
//!
//! Decision 5: the properties are written before the implementation.
//! - The `today` module checks the parts that already held on a797bea.
//! - The `full` module covers the SAF-10 API decided by the CTO
//!   (29-oct-2026): one `Policy`, no layers; `Decision::recovery`,
//!   `RecoveryObligation`, `Severity`, `PolicyEffect::Recover`,
//!   `Policy::max_approval_ms`, rule `control_loop` / `delta_ms`.

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

/// SAF-10 properties that need the implementation (Recover, severity,
/// control-loop validation).
mod full {
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
            delta in prop::option::of(0u64..10_000),
            max in prop::option::of(1u64..10_000),
            fast in any::<bool>(),
        ) {
            prop_assert_eq!(
                Policy::from_json(&p9_doc(fast, max, delta)).is_err(),
                p9_expected_rejection(fast, max, delta)
            );
        }
    }

    fn p9_doc(fast: bool, max: Option<u64>, delta: Option<u64>) -> String {
        let mut rule = json!({
            "id": "r", "action_type": "a", "effect": "RequireApproval",
            "required_capability": null, "target": null,
            "parameter_conditions": [], "context_conditions": [],
            "control_loop": if fast { "fast" } else { "slow" },
        });
        if let Some(delta) = delta {
            rule["delta_ms"] = json!(delta);
        }
        let mut doc = json!({"id": "p", "version": 1, "canonical_version": 1, "rules": [rule]});
        if let Some(max) = max {
            doc["max_approval_ms"] = json!(max);
        }
        doc.to_string()
    }

    /// Fail closed on the fast loop: both bounds required and delta >= max.
    fn p9_expected_rejection(fast: bool, max: Option<u64>, delta: Option<u64>) -> bool {
        let below = matches!((max, delta), (Some(max), Some(delta)) if delta < max);
        below || (fast && (max.is_none() || delta.is_none()))
    }

    #[test]
    fn fast_loop_approval_without_max_is_a_load_error() {
        assert!(Policy::from_json(&p9_doc(true, None, Some(5_000))).is_err());
    }

    #[test]
    fn fast_loop_approval_without_delta_is_a_load_error() {
        assert!(Policy::from_json(&p9_doc(true, Some(5_000), None)).is_err());
    }

    #[test]
    fn fast_loop_approval_with_delta_below_max_is_a_load_error() {
        assert!(Policy::from_json(&p9_doc(true, Some(5_000), Some(4_999))).is_err());
    }

    #[test]
    fn fast_loop_approval_with_delta_covering_max_loads() {
        let policy = Policy::from_json(&p9_doc(true, Some(5_000), Some(5_000))).unwrap();
        assert_eq!(policy.max_approval_ms, Some(5_000));
        assert_eq!(policy.rules[0].delta_ms, Some(5_000));
    }

    /// Several matching Recover rules: the first in rule order keeps its
    /// obligation, regardless of other effects in between.
    #[test]
    fn first_matching_recover_rule_wins() {
        let policy = policy(&[
            (true, PolicyEffect::Allow),
            (false, recover("unmatched")),
            (true, recover("first")),
            (true, PolicyEffect::Deny),
            (true, recover("second")),
        ]);
        let decision = decide(&policy);
        let recovery = decision.recovery.expect("recovery");
        assert_eq!(recovery.recovery_id, "first");
        assert_eq!(recovery.rule_id, "r2");
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        // The Recover rule that produced the kept obligation decided it.
        assert_eq!(decision.decided_by, praetore_core::DecidedBy::rule("r2"));
    }

    fn evidence(decision: praetore_core::Decision) -> praetore_core::Evidence {
        let agent = AgentKeyPair::from_secret_bytes(&[7; 32]).identity(AgentId::new());
        let authority = Authority::new(agent.id.clone(), "i", vec![]);
        let action = Action::new("a", None, json!({})).unwrap();
        praetore_core::Evidence::new(
            uuid::Uuid::new_v4(),
            agent,
            authority,
            action,
            decision,
            None,
        )
        .unwrap()
    }

    fn obligation() -> praetore_core::RecoveryObligation {
        praetore_core::RecoveryObligation {
            recovery_id: "safe-hold".into(),
            rule_id: "r".into(),
            reason: "x".into(),
            deadline_ms: 500,
        }
    }

    /// Rebuilds `evidence` as a legacy receipt of `version` (v1-v3 predate
    /// `decided_by`): drops `decided_by` and recomputes the unkeyed context
    /// hash the way a pre-v4 engine did.
    fn legacy(evidence: &praetore_core::Evidence, version: u16) -> serde_json::Value {
        let mut value = serde_json::to_value(evidence).unwrap();
        value["decision"]
            .as_object_mut()
            .unwrap()
            .remove("decided_by");
        value["evidence_schema_version"] = json!(version);
        rehash(&mut value);
        value
    }

    fn rehash(value: &mut serde_json::Value) {
        use sha2::{Digest, Sha256};
        let mut payload = value.clone();
        let object = payload.as_object_mut().unwrap();
        object.remove("context_hash");
        object.remove("attester_signature");
        let canonical = praetore_core::canonical::canonicalize_json(&payload.to_string()).unwrap();
        value["context_hash"] = json!(hex::encode(Sha256::digest(canonical)));
    }

    fn parse(value: &serde_json::Value) -> praetore_core::Evidence {
        praetore_core::Evidence::from_json(&value.to_string()).unwrap()
    }

    /// Evidence v3: a recovery obligation is carried only by v3 among the
    /// legacy versions; v1 evidence keeps verifying, and recovery cannot be
    /// smuggled into v1 or removed from v3 without breaking integrity.
    /// New evidence is v4 (it records `decided_by`) with or without recovery.
    #[test]
    fn p8_evidence_v3_and_v1_coexist() {
        let deny = praetore_core::Decision::deny("x", praetore_core::DecidedBy::DefaultDeny);
        let v4_deny = evidence(deny);
        assert_eq!(v4_deny.evidence_schema_version, 4);
        assert!(v4_deny.verify_integrity());
        let v4_recover = evidence(praetore_core::Decision::recover("x", obligation()));
        assert_eq!(v4_recover.evidence_schema_version, 4);
        assert!(v4_recover.verify_integrity());
        assert_eq!(
            v4_recover.decision.decided_by(),
            Some(&praetore_core::DecidedBy::rule("r"))
        );

        let v1 = parse(&legacy(&v4_deny, 1));
        assert_eq!(v1.evidence_schema_version, 1);
        assert!(v1.verify_integrity());
        assert_eq!(v1.decision.decided_by(), None);
        let v1_json = serde_json::to_string(&v1).unwrap();
        assert!(!v1_json.contains("recovery"));
        assert!(praetore_core::Evidence::from_json(&v1_json).is_ok());

        let v3 = parse(&legacy(&v4_recover, 3));
        assert_eq!(v3.evidence_schema_version, 3);
        assert!(v3.verify_integrity());
        let v3_json = serde_json::to_string(&v3).unwrap();
        assert!(
            praetore_core::Evidence::from_json(&v3_json)
                .unwrap()
                .verify_integrity()
        );

        for (base, label) in [(&v1, "v1"), (&v4_deny, "v4")] {
            let mut smuggled = base.clone();
            smuggled.decision.recovery = Some(obligation());
            assert!(!smuggled.verify_integrity(), "{label}");
        }
        for (base, label) in [(&v3, "v3"), (&v4_recover, "v4")] {
            let mut relabeled = base.clone();
            relabeled.evidence_schema_version = 1;
            assert!(!relabeled.verify_integrity(), "{label}");
            let mut stripped = base.clone();
            stripped.decision.recovery = None;
            assert!(!stripped.verify_integrity(), "{label}");
        }

        // Even with a recomputed (unkeyed) hash, the version shape holds:
        // legacy versions cannot carry decided_by, v4 cannot omit it, and an
        // unknown version is rejected.
        let mut value = serde_json::to_value(&v4_recover).unwrap();
        for version in [1, 2, 3, 5] {
            value["evidence_schema_version"] = json!(version);
            rehash(&mut value);
            assert!(
                praetore_core::Evidence::from_json(&value.to_string()).is_err(),
                "v{version} with decided_by"
            );
        }
        let mut value = legacy(&v4_recover, 4);
        rehash(&mut value);
        assert!(praetore_core::Evidence::from_json(&value.to_string()).is_err());
    }

    /// Validation of the Recover effect itself at load time.
    #[test]
    fn recover_effect_requires_positive_deadline_and_identifier() {
        for (id, deadline) in [("", 500), (" x", 500), ("safe-hold", 0)] {
            let policy = Policy::new(
                "p",
                1,
                vec![PolicyRule::new(
                    "r",
                    "a",
                    PolicyEffect::Recover {
                        recovery_id: id.into(),
                        deadline_ms: deadline,
                    },
                )],
            );
            assert!(policy.validate().is_err(), "{id:?} {deadline}");
        }
    }

    /// Decision JSON carrying recovery with outcome Allow is rejected.
    #[test]
    fn recovery_with_allow_is_unrepresentable() {
        let json = r#"{"outcome":"Allow","reason":"x","contributions":[],"recovery":{"recovery_id":"s","rule_id":"r","reason":"x","deadline_ms":1}}"#;
        assert!(serde_json::from_str::<praetore_core::Decision>(json).is_err());
    }
}
