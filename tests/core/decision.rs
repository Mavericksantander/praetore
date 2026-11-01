//! Black-box tests of the decision layer (`praetore_core::decision`) and of how
//! the authorization engine produces decisions.
//!
//! Compiled as the `decision` integration test of `praetore-core` (see the
//! `[[test]]` entry in `crates/praetore-core/Cargo.toml`), so it runs under
//! `cargo test --workspace`. It uses only the public API.
//!
//! Two kinds of assertion live here.
//!
//! Documented contract (outcome, `decided_by`, the set of contributions,
//! recovery obligations), from:
//! * `docs/policy-language.md`, "Effects and precedence": the outcome is the
//!   strongest matching effect under DENY > REQUIRE_APPROVAL > ALLOW, the fold
//!   is independent of rule order, and no matching rule means DENY;
//! * `docs/crypto-and-policy.md`: `decided_by` kinds, the decider kept on
//!   combination (higher severity, ties keep the earlier-matching rule), and
//!   `decided_by` covered by the integrity hash and the attester signature;
//! * `docs/golden/trust-chain-v1.json`: the frozen legacy decision encoding.
//!
//! Current behaviour, pinned but NOT documented as a contract: the exact
//! `reason` strings (rule, default deny, unbound rule, engine guards) and the
//! document order of `contributions`. Both are part of the signed receipt
//! bytes, so a change must be deliberate, but `docs/` does not define them.
//! The one reason property that is documented is that a combined decision's
//! `reason` follows its decider (`docs/policy-language.md`, "Effects and
//! precedence"); `combined_reason_follows_the_decider_in_every_order` tests it.
//!
//! Unit tests in `src/decision.rs` and `src/engine.rs` already cover
//! `strongest` on hand-built decisions, `decided_by` consistency rules and
//! tampering with `decided_by` alone; this file does not repeat them.

use std::collections::BTreeSet;

use praetore_core::canonical::canonicalize_json;
use praetore_core::decision::DecisionContribution;
use praetore_core::engine::AuthorizationEngine;
use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, AuthorizationRequest, DecidedBy, Decision,
    DecisionOutcome, Evidence, EvidenceAttesterKey, Policy, PolicyCondition, PolicyEffect,
    PolicyRule, RecordedDecision, Severity,
};
use serde_json::{Value, json};

const GOLDEN_TRUST_CHAIN: &str = include_str!("../../docs/golden/trust-chain-v1.json");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn new_agent() -> praetore_core::AgentIdentity {
    AgentKeyPair::from_secret_bytes(&[42; 32]).identity(AgentId::new())
}

fn action(action_type: &str, target: Option<&str>, parameters: Value) -> Action {
    Action::new(action_type, target.map(str::to_string), parameters)
        .unwrap()
        .with_capability(action_type)
}

/// Evaluates `action` against `policy` through the development engine with an
/// authority granting `capabilities`, and returns the (unsigned) evidence.
fn evaluate(mut policy: Policy, capabilities: &[&str], action: Action) -> Evidence {
    // The action's type is a declared Mission action; whether a rule matches
    // it is what each test checks.
    policy
        .action_classes
        .entry(action.action_type.clone())
        .or_insert(praetore_core::ActionClass::Mission);
    let agent = new_agent();
    let authority = Authority::new(
        agent.id.clone(),
        "praetore-root",
        capabilities.iter().map(|c| (*c).to_string()).collect(),
    );
    let request = AuthorizationRequest::new(agent, authority, mission(action)).unwrap();
    AuthorizationEngine::development(policy)
        .evaluate(request)
        .unwrap()
}

fn evaluate_read(rules: Vec<PolicyRule>) -> Evidence {
    evaluate(
        mission_policy(Policy::new_v2("decision-tests", 3, rules)),
        &["read_data"],
        action("read_data", Some("db"), json!({})),
    )
}

fn allow(id: &str) -> PolicyRule {
    PolicyRule::new(id, "read_data", PolicyEffect::Allow).with_capability("read_data")
}

fn deny(id: &str) -> PolicyRule {
    PolicyRule::new(id, "read_data", PolicyEffect::Deny).with_capability("read_data")
}

fn approve(id: &str) -> PolicyRule {
    PolicyRule::new(id, "read_data", PolicyEffect::RequireApproval).with_capability("read_data")
}

fn recover(id: &str) -> PolicyRule {
    recover_to(id, "safe-hold", 250)
}

fn recover_to(id: &str, recovery_id: &str, deadline_ms: u64) -> PolicyRule {
    PolicyRule::new(
        id,
        "read_data",
        PolicyEffect::Recover {
            recovery_id: recovery_id.into(),
            deadline_ms,
        },
    )
    .with_capability("read_data")
}

fn matched(rule_id: &str) -> String {
    format!("Policy rule '{rule_id}' matched")
}

fn decider(evidence: &Evidence) -> DecidedBy {
    evidence
        .decision
        .decided_by()
        .cloned()
        .expect("every newly produced decision records decided_by")
}

fn contributed_rules(evidence: &Evidence) -> Vec<(String, DecisionOutcome)> {
    evidence
        .decision
        .contributions
        .iter()
        .map(|c| (c.rule_id.clone(), c.outcome))
        .collect()
}

/// All permutations of `items` (small inputs only).
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let head = rest.remove(i);
        for mut tail in permutations(&rest) {
            tail.insert(0, head.clone());
            out.push(tail);
        }
    }
    out
}

fn signed(evidence: &mut Evidence) -> EvidenceAttesterKey {
    let attester = EvidenceAttesterKey::from_secret_bytes(&[7; 32]);
    evidence.sign(&attester).unwrap();
    attester
}

// ---------------------------------------------------------------------------
// Outcomes, deciders and reasons produced by the engine
// ---------------------------------------------------------------------------

#[test]
fn each_effect_produces_its_outcome_decider_reason_and_single_contribution() {
    for (rule, outcome, severity) in [
        (allow("r-allow"), DecisionOutcome::Allow, Severity::Allow),
        (
            approve("r-approve"),
            DecisionOutcome::RequireApproval,
            Severity::RequireApproval,
        ),
        (deny("r-deny"), DecisionOutcome::Deny, Severity::Deny),
    ] {
        let id = rule.id.clone();
        let evidence = evaluate_read(vec![rule]);
        let decision = &evidence.decision;

        assert_eq!(evidence.outcome(), outcome, "{id}");
        assert_eq!(decision.severity(), severity, "{id}");
        assert_eq!(decider(&evidence), DecidedBy::rule(&id), "{id}");
        assert_eq!(decision.reason, matched(&id), "{id}");
        assert_eq!(
            decision.contributions,
            vec![DecisionContribution::new(&id, outcome, matched(&id))],
            "{id}"
        );
        assert_eq!(decision.recovery, None, "{id}");
        assert_eq!(outcome.is_allowed(), outcome == DecisionOutcome::Allow);
        assert_eq!(
            outcome.requires_approval(),
            outcome == DecisionOutcome::RequireApproval
        );
        assert_eq!(outcome.is_denied(), outcome == DecisionOutcome::Deny);
        // New evidence is schema v4 and carries a consistent decision.
        assert_eq!(evidence.evidence_schema_version, 4);
        decision.validate().unwrap();
        assert!(evidence.verify());
    }
}

#[test]
fn recover_effect_denies_with_an_obligation_decided_by_its_rule() {
    let evidence = evaluate_read(vec![recover("r-recover")]);
    let decision = &evidence.decision;
    assert_eq!(decision.outcome, DecisionOutcome::Deny);
    assert_eq!(decision.severity(), Severity::Recover);
    assert_eq!(decider(&evidence), DecidedBy::rule("r-recover"));
    assert_eq!(decision.reason, matched("r-recover"));
    let recovery = decision.recovery.as_ref().expect("recovery obligation");
    assert_eq!(recovery.rule_id, "r-recover");
    assert_eq!(recovery.recovery_id, "safe-hold");
    assert_eq!(recovery.deadline_ms, 250);
    assert_eq!(recovery.reason, matched("r-recover"));
    assert!(evidence.verify());
}

#[test]
fn no_matching_rule_is_a_default_deny_without_contributions() {
    // An empty policy, a policy for another action type, and a policy whose
    // only ALLOW rule does not match the target all deny by default.
    for rules in [
        vec![],
        vec![
            PolicyRule::new("allow-write", "write_data", PolicyEffect::Allow)
                .with_capability("write_data"),
        ],
        vec![allow("allow-other-target").with_target("other-db")],
        vec![
            allow("allow-small").with_parameter_condition(PolicyCondition::exact("rows", json!(1))),
        ],
    ] {
        let evidence = evaluate_read(rules);
        let decision = &evidence.decision;
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decider(&evidence), DecidedBy::DefaultDeny);
        assert!(decision.contributions.is_empty());
        assert_eq!(decision.recovery, None);
        assert_eq!(
            decision.reason,
            "Policy 'decision-tests' v3: no matching rule; default deny"
        );
        assert!(evidence.verify());
    }
}

#[test]
fn engine_guard_denials_record_the_guard_and_skip_policy_rules() {
    // The policy would allow; the engine denies before consulting it.
    let policy = || mission_policy(Policy::new_v2("guards", 1, vec![allow("allow-read")]));

    // authority_capability: the authority does not grant the capability.
    let evidence = evaluate(
        policy(),
        &["write_data"],
        action("read_data", Some("db"), json!({})),
    );
    assert_eq!(evidence.outcome(), DecisionOutcome::Deny);
    assert_eq!(
        decider(&evidence),
        DecidedBy::engine_guard("authority_capability")
    );
    assert_eq!(
        evidence.decision.reason,
        "authority does not permit capability: read_data"
    );
    assert!(evidence.decision.contributions.is_empty());

    // missing_capability: the action declares no capability.
    let agent = new_agent();
    let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
    let bare = Action::new("read_data", Some("db".into()), json!({})).unwrap();
    let request = AuthorizationRequest::new(agent, authority, mission(bare)).unwrap();
    let evidence = AuthorizationEngine::development(policy())
        .evaluate(request)
        .unwrap();
    assert_eq!(
        decider(&evidence),
        DecidedBy::engine_guard("missing_capability")
    );
    assert_eq!(
        evidence.decision.reason,
        "action does not declare a required capability"
    );

    // authority_constraint: a constraint on the authority is not satisfied.
    let agent = new_agent();
    let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
        .with_constraint("target", "other-db");
    let request = AuthorizationRequest::new(
        agent,
        authority,
        mission(action("read_data", Some("db"), json!({}))),
    )
    .unwrap();
    let evidence = AuthorizationEngine::development(policy())
        .evaluate(request)
        .unwrap();
    assert_eq!(
        decider(&evidence),
        DecidedBy::engine_guard("authority_constraint")
    );
    assert_eq!(
        evidence.decision.reason,
        "authority constraint 'target' was not satisfied"
    );
    assert!(evidence.verify());
    evidence.decision.validate().unwrap();
}

#[test]
fn unbound_restrictive_rule_denies_and_is_recorded_as_unbound() {
    // The authority lacks the approval rule's capability: the rule still
    // applies (it cannot be escaped) but denies instead of offering approval.
    let evidence = evaluate(
        mission_policy(Policy::new_v2(
            "unbound",
            1,
            vec![
                allow("allow-read"),
                PolicyRule::new("approve-read", "read_data", PolicyEffect::RequireApproval)
                    .with_capability("read_data:reviewed"),
            ],
        )),
        &["read_data"],
        action("read_data", Some("db"), json!({})),
    );
    assert_eq!(evidence.outcome(), DecisionOutcome::Deny);
    assert_eq!(decider(&evidence), DecidedBy::unbound_rule("approve-read"));
    assert_eq!(
        evidence.decision.reason,
        "Policy rule 'approve-read' matched without its required capability or target; denied"
    );
    assert_eq!(
        contributed_rules(&evidence),
        vec![
            ("allow-read".into(), DecisionOutcome::Allow),
            ("approve-read".into(), DecisionOutcome::Deny),
        ]
    );
}

#[test]
fn unbound_deny_rule_applies_its_effect_and_is_an_ordinary_rule() {
    // docs/policy-language.md: "an unbound DENY rule applied its declared
    // effect and is an ordinary `rule`". The authority lacks the rule's
    // capability, the rule still applies and is recorded as `rule`.
    for rules in [
        vec![
            allow("allow-read"),
            PolicyRule::new("deny-x", "read_data", PolicyEffect::Deny)
                .with_capability("read_data:x"),
        ],
        vec![
            PolicyRule::new("deny-x", "read_data", PolicyEffect::Deny)
                .with_capability("read_data:x"),
            allow("allow-read"),
        ],
        // Unbound through a missing action target.
        vec![allow("allow-read"), deny("deny-x").with_target("secrets")],
    ] {
        let target = if rules.iter().any(|r| r.target.is_some()) {
            None
        } else {
            Some("db")
        };
        let evidence = evaluate(
            mission_policy(Policy::new_v2("unbound-deny", 1, rules)),
            &["read_data"],
            action("read_data", target, json!({})),
        );
        assert_eq!(evidence.outcome(), DecisionOutcome::Deny);
        assert_eq!(decider(&evidence), DecidedBy::rule("deny-x"));
        assert_eq!(evidence.decision.reason, matched("deny-x"));
        assert!(contributed_rules(&evidence).contains(&("deny-x".into(), DecisionOutcome::Deny)));
    }
}

// ---------------------------------------------------------------------------
// Precedence
// ---------------------------------------------------------------------------

#[test]
fn precedence_is_deny_over_approval_over_allow_in_every_rule_order() {
    let cases: [(Vec<PolicyRule>, DecisionOutcome, &str); 4] = [
        (
            vec![allow("a"), approve("p"), deny("d")],
            DecisionOutcome::Deny,
            "d",
        ),
        (vec![allow("a"), deny("d")], DecisionOutcome::Deny, "d"),
        (vec![approve("p"), deny("d")], DecisionOutcome::Deny, "d"),
        (
            vec![allow("a"), approve("p")],
            DecisionOutcome::RequireApproval,
            "p",
        ),
    ];
    for (rules, outcome, winner) in cases {
        let expected_contributors: BTreeSet<String> = rules.iter().map(|r| r.id.clone()).collect();
        for order in permutations(&rules) {
            let ids: Vec<String> = order.iter().map(|r| r.id.clone()).collect();
            let evidence = evaluate_read(order);
            assert_eq!(evidence.outcome(), outcome, "order {ids:?}");
            assert_eq!(decider(&evidence), DecidedBy::rule(winner), "order {ids:?}");
            assert_eq!(evidence.decision.reason, matched(winner), "order {ids:?}");
            // Every matching rule is retained, in document order.
            let contributed: Vec<String> = contributed_rules(&evidence)
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            assert_eq!(contributed, ids, "order {ids:?}");
            assert_eq!(
                contributed.into_iter().collect::<BTreeSet<_>>(),
                expected_contributors
            );
            assert!(evidence.verify());
        }
    }
}

#[test]
fn recover_outranks_deny_in_either_order() {
    for rules in [
        vec![deny("d"), recover("r"), allow("a")],
        vec![recover("r"), deny("d"), allow("a")],
        vec![allow("a"), approve("p"), recover("r")],
    ] {
        let ids: Vec<String> = rules.iter().map(|r| r.id.clone()).collect();
        let evidence = evaluate_read(rules);
        assert_eq!(evidence.outcome(), DecisionOutcome::Deny, "{ids:?}");
        assert_eq!(evidence.decision.severity(), Severity::Recover, "{ids:?}");
        assert_eq!(decider(&evidence), DecidedBy::rule("r"), "{ids:?}");
        assert_eq!(
            evidence
                .decision
                .recovery
                .as_ref()
                .map(|r| r.rule_id.as_str()),
            Some("r"),
            "{ids:?}"
        );
        assert_eq!(evidence.decision.reason, matched("r"), "{ids:?}");
        assert!(evidence.verify());
    }
}

#[test]
fn equal_outcomes_are_decided_by_the_earliest_matching_rule() {
    for (rules, first) in [
        (vec![deny("d1"), deny("d2"), allow("a")], "d1"),
        (vec![allow("a"), deny("d2"), deny("d1")], "d2"),
        (vec![approve("p2"), approve("p1")], "p2"),
        (vec![allow("a1"), allow("a2"), allow("a3")], "a1"),
        (vec![allow("a3"), allow("a2"), allow("a1")], "a3"),
    ] {
        let evidence = evaluate_read(rules);
        assert_eq!(decider(&evidence), DecidedBy::rule(first));
        assert_eq!(evidence.decision.reason, matched(first));
    }
}

#[test]
fn combined_reason_follows_the_decider_in_every_order() {
    // The signed reason names the same rule as `decided_by` (and, for a
    // Recover decision, the recovery obligation), whatever the rule order.
    let rule_sets = [
        vec![deny("d"), recover("r")],
        vec![deny("d"), recover("r"), allow("a")],
        vec![allow("a"), approve("p"), deny("d")],
        vec![allow("a"), approve("p")],
        vec![deny("d1"), deny("d2")],
    ];
    for rules in rule_sets {
        for order in permutations(&rules) {
            let ids: Vec<String> = order.iter().map(|r| r.id.clone()).collect();
            let evidence = evaluate_read(order);
            let decision = &evidence.decision;
            let DecidedBy::Rule { rule_id } = decider(&evidence) else {
                panic!("expected a rule decider for {ids:?}");
            };
            assert_eq!(decision.reason, matched(&rule_id), "{ids:?}");
            let contribution = decision
                .contributions
                .iter()
                .find(|c| c.rule_id == rule_id)
                .expect("decider contributed");
            assert_eq!(decision.reason, contribution.reason, "{ids:?}");
            if let Some(recovery) = &decision.recovery {
                assert_eq!(recovery.rule_id, rule_id, "{ids:?}");
                assert_eq!(decision.reason, recovery.reason, "{ids:?}");
            }
        }
    }
}

#[test]
fn tie_between_recover_rules_keeps_the_first_obligation() {
    for (first, second) in [("r1", "r2"), ("r2", "r1")] {
        let safe = |id: &str| format!("safe-{id}");
        let deadline = |id: &str| if id == "r1" { 100 } else { 900 };
        let evidence = evaluate_read(vec![
            recover_to(first, &safe(first), deadline(first)),
            recover_to(second, &safe(second), deadline(second)),
        ]);
        let decision = &evidence.decision;
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.severity(), Severity::Recover);
        assert_eq!(decider(&evidence), DecidedBy::rule(first));
        assert_eq!(decision.reason, matched(first));
        let recovery = decision.recovery.as_ref().expect("recovery obligation");
        assert_eq!(recovery.rule_id, first);
        assert_eq!(recovery.recovery_id, safe(first));
        assert_eq!(recovery.deadline_ms, deadline(first));
        assert_eq!(
            contributed_rules(&evidence),
            vec![
                (first.to_string(), DecisionOutcome::Deny),
                (second.to_string(), DecisionOutcome::Deny),
            ]
        );
        assert!(evidence.verify());
    }
}

#[test]
fn receipt_with_the_previous_deny_then_recover_reason_still_verifies() {
    // Before the fix, `[deny d, recover r]` produced a decision whose reason
    // named `d` while `decided_by` and the obligation named `r`. The receipt
    // format did not change, so such a receipt (rebuilt here field by field)
    // still passes integrity, signature and import checks.
    let recovery = praetore_core::RecoveryObligation {
        recovery_id: "safe-hold".into(),
        rule_id: "r".into(),
        reason: matched("r"),
        deadline_ms: 250,
    };
    let old = Decision::recover(matched("d"), recovery)
        .with_contribution(DecisionContribution::new(
            "d",
            DecisionOutcome::Deny,
            matched("d"),
        ))
        .with_contribution(DecisionContribution::new(
            "r",
            DecisionOutcome::Deny,
            matched("r"),
        ));
    old.validate().unwrap();
    let agent = new_agent();
    let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
    let mut evidence = Evidence::new(
        uuid::Uuid::new_v4(),
        agent,
        authority,
        action("read_data", Some("db"), json!({})),
        old,
        None,
    )
    .unwrap();
    assert_eq!(evidence.evidence_schema_version, 4);
    let policy = mission_policy(Policy::new_v2(
        "decision-tests",
        3,
        vec![deny("d"), recover("r")],
    ));
    evidence
        .bind_policy_digest(policy.digest().unwrap())
        .unwrap();
    let attester = signed(&mut evidence);
    let key = attester.public_key().unwrap();
    let imported = Evidence::from_json(&evidence.to_json().unwrap()).unwrap();
    assert!(imported.verify());
    imported.verify_attester_signature(&key).unwrap();
    imported.verify_policy(&policy).unwrap();
    assert_eq!(imported.decision.reason, matched("d"));
    assert_eq!(imported.decision.decided_by(), Some(&DecidedBy::rule("r")));

    // A fresh evaluation of the same rules now records the decider's reason.
    let fresh = evaluate_read(vec![deny("d"), recover("r")]);
    assert_eq!(fresh.decision.reason, matched("r"));
}

#[test]
fn no_rule_specificity_a_narrow_allow_never_overrides_a_broad_deny() {
    // There is no specificity ordering: a rule with a target and conditions
    // does not take precedence over a broader rule. Only the effect counts.
    let narrow_allow = allow("narrow-allow")
        .with_target("db")
        .with_parameter_condition(PolicyCondition::exact("table", json!("users")));
    let broad_deny = deny("broad-deny");
    for rules in permutations(&[narrow_allow.clone(), broad_deny]) {
        let evidence = evaluate(
            mission_policy(Policy::new_v2("specificity", 1, rules)),
            &["read_data"],
            action("read_data", Some("db"), json!({"table": "users"})),
        );
        assert_eq!(evidence.outcome(), DecisionOutcome::Deny);
        assert_eq!(decider(&evidence), DecidedBy::rule("broad-deny"));
    }

    // A narrow DENY only applies where it matches; elsewhere the broad ALLOW
    // decides.
    let narrow_deny = deny("narrow-deny").with_target("secrets");
    let broad_allow = allow("broad-allow");
    for (target, outcome, winner) in [
        ("secrets", DecisionOutcome::Deny, "narrow-deny"),
        ("db", DecisionOutcome::Allow, "broad-allow"),
    ] {
        for rules in permutations(&[narrow_deny.clone(), broad_allow.clone()]) {
            let evidence = evaluate(
                mission_policy(Policy::new_v2("specificity", 1, rules)),
                &["read_data"],
                action("read_data", Some(target), json!({})),
            );
            assert_eq!(evidence.outcome(), outcome, "{target}");
            assert_eq!(decider(&evidence), DecidedBy::rule(winner), "{target}");
        }
    }
}

// ---------------------------------------------------------------------------
// Serialization and canonical form
// ---------------------------------------------------------------------------

#[test]
fn decided_by_wire_form_is_stable_for_every_kind() {
    for (decided_by, wire) in [
        (DecidedBy::rule("r1"), r#"{"kind":"rule","rule_id":"r1"}"#),
        (
            DecidedBy::unbound_rule("u1"),
            r#"{"kind":"unbound_rule","rule_id":"u1"}"#,
        ),
        (DecidedBy::DefaultDeny, r#"{"kind":"default_deny"}"#),
        (
            DecidedBy::engine_guard("authority_capability"),
            r#"{"kind":"engine_guard","guard":"authority_capability"}"#,
        ),
    ] {
        assert_eq!(serde_json::to_string(&decided_by).unwrap(), wire);
        assert_eq!(serde_json::from_str::<DecidedBy>(wire).unwrap(), decided_by);
    }
    for (outcome, wire) in [
        (DecisionOutcome::Allow, r#""Allow""#),
        (DecisionOutcome::RequireApproval, r#""RequireApproval""#),
        (DecisionOutcome::Deny, r#""Deny""#),
    ] {
        assert_eq!(serde_json::to_string(&outcome).unwrap(), wire);
        assert_eq!(
            serde_json::from_str::<DecisionOutcome>(wire).unwrap(),
            outcome
        );
    }
    for rejected in [
        r#""allow""#,
        r#""DENY""#,
        r#""require_approval""#,
        r#""Recover""#,
    ] {
        assert!(serde_json::from_str::<DecisionOutcome>(rejected).is_err());
    }
}

#[test]
fn engine_decisions_round_trip_and_have_a_stable_canonical_form() {
    let deny_rule = PolicyRule::new("deny-delete", "delete_data", PolicyEffect::Deny)
        .with_capability("delete_data");
    let evidence = evaluate(
        mission_policy(Policy::new_v2("golden-decision", 1, vec![deny_rule])),
        &["delete_data"],
        action("delete_data", Some("db"), json!({})),
    );

    // Golden canonical bytes of the decision object (keys sorted, no spaces).
    let golden = concat!(
        r#"{"contributions":[{"outcome":"Deny","reason":"Policy rule 'deny-delete' matched","#,
        r#""rule_id":"deny-delete"}],"decided_by":{"kind":"rule","rule_id":"deny-delete"},"#,
        r#""outcome":"Deny","reason":"Policy rule 'deny-delete' matched"}"#
    );
    let serialized = serde_json::to_string(&evidence.decision).unwrap();
    let canonical = String::from_utf8(canonicalize_json(&serialized).unwrap()).unwrap();
    assert_eq!(canonical, golden);

    // The exported receipt embeds exactly that canonical decision.
    let exported: Value = serde_json::from_str(&evidence.to_json().unwrap()).unwrap();
    assert_eq!(
        String::from_utf8(canonicalize_json(&exported["decision"].to_string()).unwrap()).unwrap(),
        golden
    );

    // Round trip through both the write-side and the read-side types.
    let as_decision: Decision = serde_json::from_str(golden).unwrap();
    assert_eq!(as_decision.decided_by, DecidedBy::rule("deny-delete"));
    assert_eq!(
        RecordedDecision::from(as_decision.clone()),
        evidence.decision
    );
    let as_recorded: RecordedDecision = serde_json::from_str(golden).unwrap();
    assert_eq!(as_recorded, evidence.decision);
    for reserialized in [
        serde_json::to_string(&as_decision).unwrap(),
        serde_json::to_string(&as_recorded).unwrap(),
    ] {
        assert_eq!(canonicalize_json(&reserialized).unwrap(), golden.as_bytes());
    }

    // Every decider kind survives a full evidence export/import unchanged.
    for evidence in [
        evaluate_read(vec![allow("a")]),
        evaluate_read(vec![approve("p")]),
        evaluate_read(vec![recover("r")]),
        evaluate_read(vec![]),
        evaluate(
            mission_policy(Policy::new_v2("g", 1, vec![allow("a")])),
            &[],
            action("read_data", None, json!({})),
        ),
    ] {
        let json = evidence.to_json().unwrap();
        let imported = Evidence::from_json(&json).unwrap();
        assert_eq!(imported.decision, evidence.decision);
        assert_eq!(imported.to_json().unwrap(), json);
    }
}

#[test]
fn golden_legacy_decision_keeps_its_exact_encoding() {
    let golden: Value = serde_json::from_str(GOLDEN_TRUST_CHAIN).unwrap();
    let evidence_json = golden["evidence_json"].as_str().unwrap();
    let evidence = Evidence::from_json(evidence_json).unwrap();
    assert!(evidence.verify());
    assert_eq!(evidence.evidence_schema_version, 1);

    let decision = &evidence.decision;
    assert_eq!(decision.outcome, DecisionOutcome::Allow);
    assert_eq!(decision.reason, "golden allow");
    assert!(decision.contributions.is_empty());
    assert_eq!(
        decision.decided_by(),
        None,
        "legacy receipts predate decided_by"
    );
    assert_eq!(decision.recovery, None);

    let encoded = serde_json::to_string(decision).unwrap();
    assert_eq!(
        canonicalize_json(&encoded).unwrap(),
        br#"{"contributions":[],"outcome":"Allow","reason":"golden allow"}"#
    );
    assert_eq!(evidence.to_json().unwrap(), evidence_json);
}

// ---------------------------------------------------------------------------
// Tampering
// ---------------------------------------------------------------------------

#[test]
fn tampered_decision_fields_fail_integrity_and_signature_checks() {
    let mut original = evaluate_read(vec![allow("a"), approve("p")]);
    let attester = signed(&mut original);
    let key = attester.public_key().unwrap();
    assert!(original.verify());
    original.verify_attester_signature(&key).unwrap();
    assert_eq!(original.outcome(), DecisionOutcome::RequireApproval);

    type Tamper = fn(&mut RecordedDecision);
    let tampers: [(&str, Tamper); 5] = [
        ("reason", |d| d.reason = "approved by policy".into()),
        ("contribution reason", |d| {
            d.contributions[1].reason = "edited".into()
        }),
        ("drop weaker contribution", |d| {
            d.contributions.remove(0);
        }),
        ("add contribution", |d| {
            d.contributions
                .push(DecisionContribution::new("a2", DecisionOutcome::Allow, "x"))
        }),
        ("reorder contributions", |d| d.contributions.reverse()),
    ];
    for (label, tamper) in tampers {
        let mut forged = original.clone();
        tamper(&mut forged.decision);
        assert!(!forged.verify(), "{label}");
        assert!(forged.verify_attester_signature(&key).is_err(), "{label}");
        assert!(forged.to_json().is_err(), "{label}");
    }

    // Downgrading the outcome to Allow, with or without a consistent trace,
    // is rejected on the exported JSON receipt.
    let exported: Value = serde_json::from_str(&original.to_json().unwrap()).unwrap();
    let mut forgeries = Vec::new();
    let mut outcome_only = exported.clone();
    outcome_only["decision"]["outcome"] = json!("Allow");
    forgeries.push(("outcome only", outcome_only));
    let mut consistent = exported.clone();
    consistent["decision"] = json!({
        "outcome": "Allow",
        "reason": matched("a"),
        "contributions": [{"rule_id": "a", "outcome": "Allow", "reason": matched("a")}],
        "decided_by": {"kind": "rule", "rule_id": "a"},
    });
    forgeries.push(("consistent rewrite", consistent));
    let mut recovery = exported.clone();
    recovery["decision"]["recovery"] = json!({
        "recovery_id": "x", "rule_id": "p", "reason": "x", "deadline_ms": 1
    });
    forgeries.push(("added recovery", recovery));
    for (label, document) in forgeries {
        let accepted = Evidence::from_json(&document.to_string())
            .map(|imported| imported.verify_attester_signature(&key).is_ok())
            .unwrap_or(false);
        assert!(!accepted, "forged decision accepted: {label}");
    }
}

#[test]
fn tampered_golden_legacy_decision_is_rejected() {
    let golden: Value = serde_json::from_str(GOLDEN_TRUST_CHAIN).unwrap();
    let document: Value = serde_json::from_str(golden["evidence_json"].as_str().unwrap()).unwrap();
    for (label, field, value) in [
        ("outcome", "outcome", json!("Deny")),
        ("reason", "reason", json!("golden deny")),
        (
            "decided_by injected into v1",
            "decided_by",
            json!({"kind": "default_deny"}),
        ),
    ] {
        let mut forged = document.clone();
        forged["decision"][field] = value;
        assert!(
            Evidence::from_json(&forged.to_string()).is_err(),
            "tampered golden decision accepted: {label}"
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
