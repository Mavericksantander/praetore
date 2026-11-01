//! Behaviour cases ported from Canopy's test suite
//! (github.com/Mavericksantander/Canopy @ 9afc0d8, Apache-2.0, `tests/`).
//!
//! Canopy is Python with a YAML policy language; these tests are rewritten
//! from the behaviour each Canopy test specifies, not copied. Every test names
//! its origin. Deliberate differences:
//!
//! * Canopy is default ALLOW ("Allowed by default"). PRAETORE is default deny:
//!   wherever Canopy expects ALLOW because no rule matched, the expected
//!   outcome here is a default deny (no contributing rule).
//! * Canopy's substring/regex heuristics (`deny_if: "rm -rf"`) are not ported;
//!   the equivalent here uses declarative exact/prefix/numeric conditions.
//! * Not ported: fixed-key HMAC witnesses, overwritable approvals, substring
//!   firewall/civil-code heuristics, reputation, shell execution.

use praetore_core::{
    Action, AgentId, AgentIdentity, AgentKeyPair, Authority, AuthorizationRequest, Decision,
    DecisionOutcome, Policy, PolicyCondition, PolicyEffect, PolicyRule,
    engine::AuthorizationEngine, policy::MatchOperator,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn agent() -> AgentIdentity {
    AgentKeyPair::from_secret_bytes(&[9; 32]).identity(AgentId::new())
}

fn authority(agent: &AgentIdentity, capabilities: &[&str]) -> Authority {
    Authority::new(
        agent.id.clone(),
        "canopy-port-issuer",
        capabilities.iter().map(|c| (*c).to_owned()).collect(),
    )
}

fn action(action_type: &str, parameters: Value) -> Action {
    Action::new(action_type, None, parameters).unwrap()
}

fn evaluate(policy: &Policy, action: &Action, context: &[(&str, Value)]) -> Decision {
    let agent = agent();
    let authority = authority(&agent, &[]);
    let context: BTreeMap<String, Value> = context
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    // The action's type is a declared Mission action of the policy; whether
    // a rule matches it is what each test checks.
    let mut policy = policy.clone();
    policy
        .action_classes
        .entry(action.action_type.clone())
        .or_insert(praetore_core::ActionClass::Mission);
    policy
        .evaluate_with_context(&agent, &authority, &mission((action).clone()), &context)
        .unwrap()
}

/// PRAETORE's default deny: denied and no policy rule contributed.
fn assert_default_deny(decision: &Decision) {
    assert_eq!(decision.outcome, DecisionOutcome::Deny);
    assert!(decision.contributions.is_empty(), "{decision:?}");
    assert!(
        decision.reason.contains("default deny"),
        "{}",
        decision.reason
    );
}

fn assert_rule(decision: &Decision, outcome: DecisionOutcome, rule_id: &str) {
    assert_eq!(decision.outcome, outcome, "{decision:?}");
    assert!(
        decision.contributions.iter().any(|c| c.rule_id == rule_id),
        "{decision:?}"
    );
}

// Origin: tests/test_authorize_action.py::test_deny_rm_rf.
// Canopy matches the substring "rm -rf" in the payload; PRAETORE has no
// substring heuristics, so the rule matches a declared parameter exactly.
#[test]
fn explicit_deny_rule_denies_matching_action() {
    let policy = mission_policy(Policy::new(
        "canopy-port",
        1,
        vec![
            PolicyRule::new("deny-wipe", "execute_shell", PolicyEffect::Deny)
                .with_parameter_condition(PolicyCondition::exact("program", json!("rm"))),
        ],
    ));
    let decision = evaluate(
        &policy,
        &action(
            "execute_shell",
            json!({"program": "rm", "args": ["-rf", "/"]}),
        ),
        &[],
    );
    assert_rule(&decision, DecisionOutcome::Deny, "deny-wipe");
}

// Origin: tests/test_authorize_action.py::test_require_approval.
#[test]
fn require_approval_rule_holds_action() {
    let policy = mission_policy(Policy::new(
        "canopy-port",
        1,
        vec![PolicyRule::new(
            "external-api",
            "call_external_api",
            PolicyEffect::RequireApproval,
        )],
    ));
    let decision = evaluate(
        &policy,
        &action("call_external_api", json!({"url": "https://example.com"})),
        &[],
    );
    assert_rule(&decision, DecisionOutcome::RequireApproval, "external-api");
}

// Origin: tests/test_authorize_action.py::test_conditions_when_all_agent_ctx_and_payload.
// Canopy: production → DENY, staging → ALLOW (by default).
// PRAETORE: production → DENY by the rule, staging → default deny.
#[test]
fn context_and_parameter_conditions_must_all_hold() {
    let policy = mission_policy(Policy::new(
        "canopy-port",
        1,
        vec![
            PolicyRule::new("prod-rm", "execute_shell", PolicyEffect::Deny)
                .with_context_condition(PolicyCondition::exact("env", json!("production")))
                .with_parameter_condition(PolicyCondition::exact("program", json!("rm"))),
        ],
    ));
    let shell = action("execute_shell", json!({"program": "rm"}));
    assert_rule(
        &evaluate(&policy, &shell, &[("env", json!("production"))]),
        DecisionOutcome::Deny,
        "prod-rm",
    );
    // Canopy expected ALLOW here; PRAETORE has no default allow.
    assert_default_deny(&evaluate(&policy, &shell, &[("env", json!("staging"))]));
}

fn safe_path_policy() -> Policy {
    mission_policy(Policy::new(
        "canopy-port",
        1,
        vec![
            PolicyRule::new("safe-paths", "modify_file", PolicyEffect::Allow)
                .with_parameter_condition(PolicyCondition::prefix("path", "/srv/agent/")),
        ],
    ))
}

// Origin: tests/test_authorize_action.py::test_safe_paths.
// Canopy: path under safe prefix → ALLOW; /etc/passwd → DENY ("unsafe path").
// PRAETORE: same allow; /etc/passwd is denied by default (no rule matched).
#[test]
fn safe_path_prefix_allows_only_inside_prefix() {
    let policy = safe_path_policy();
    assert_rule(
        &evaluate(
            &policy,
            &action("modify_file", json!({"path": "/srv/agent/x.txt"})),
            &[],
        ),
        DecisionOutcome::Allow,
        "safe-paths",
    );
    assert_default_deny(&evaluate(
        &policy,
        &action("modify_file", json!({"path": "/etc/passwd"})),
        &[],
    ));
    // A non-string path cannot satisfy a prefix condition.
    assert_default_deny(&evaluate(
        &policy,
        &action("modify_file", json!({"path": 7})),
        &[],
    ));
}

// Derived from test_safe_paths (not a Canopy test: Canopy's `startswith` has
// the same flaw). Fixed in #20: values with a `..` segment never satisfy an
// Allow `Prefix` rule. Duplicated in tests/path_prefix.rs on purpose.
#[test]
fn safe_path_prefix_rejects_dot_dot_traversal() {
    let decision = evaluate(
        &safe_path_policy(),
        &action(
            "modify_file",
            json!({"path": "/srv/agent/../../etc/passwd"}),
        ),
        &[],
    );
    assert_eq!(decision.outcome, DecisionOutcome::Deny);
}

// Origin: tests/test_authorize_action.py::test_policy_multiple_rules_same_action_type_all_evaluated.
// All matching rules are evaluated and the strongest outcome wins, in any order.
#[test]
fn all_matching_rules_are_evaluated_and_deny_wins() {
    let review = PolicyRule::new("review", "custom_action", PolicyEffect::RequireApproval);
    let block = PolicyRule::new("block", "custom_action", PolicyEffect::Deny);
    for rules in [
        vec![review.clone(), block.clone()],
        vec![block.clone(), review.clone()],
    ] {
        let decision = evaluate(
            &mission_policy(Policy::new("canopy-port", 1, rules)),
            &action("custom_action", json!({})),
            &[],
        );
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        let ids: Vec<_> = decision
            .contributions
            .iter()
            .map(|c| c.rule_id.as_str())
            .collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"review") && ids.contains(&"block"));
    }
}

// Origin: tests/test_authorize_action.py::test_load_policies_raises_on_empty_rules.
// Canopy raises on an empty rule list. PRAETORE accepts it as a valid policy
// that denies everything by default (fail closed either way).
#[test]
fn empty_policy_denies_everything() {
    let policy = mission_policy(Policy::new("canopy-port", 1, vec![]));
    assert!(policy.validate().is_ok());
    assert_default_deny(&evaluate(&policy, &action("execute_shell", json!({})), &[]));
}

// Origin: tests/test_authorize_action.py::test_unrecognized_predicate_warns.
// Canopy warns on an unknown predicate and still ALLOWs. PRAETORE rejects the
// policy document outright.
#[test]
fn unknown_policy_fields_or_operators_are_rejected() {
    let base = json!({
        "format_version": 2, "id": "canopy-port", "version": 1, "canonical_version": 1,
        "action_classes": {"execute_shell": "Mission"},
        "rules": [{
            "id": "r", "action_type": "execute_shell", "effect": "Deny",
            "required_capability": null, "target": null,
            "parameter_conditions": [], "context_conditions": []
        }]
    });
    assert!(Policy::from_json(&base.to_string()).is_ok());

    let mut unknown_field = base.clone();
    unknown_field["rules"][0]["when_all"] = json!(["agent_ctx.role = \"admin\""]);
    assert!(Policy::from_json(&unknown_field.to_string()).is_err());

    let mut unknown_operator = base.clone();
    unknown_operator["rules"][0]["context_conditions"] =
        json!([{"key": "role", "operator": "Assign", "expected": "admin"}]);
    assert!(Policy::from_json(&unknown_operator.to_string()).is_err());
}

// Origin: tests/test_policy_parser_minimal.py (basic parse; duplicate keys).
// YAML tab handling has no JSON equivalent; duplicate keys are the analogous
// ambiguity and are rejected.
#[test]
fn policy_documents_parse_and_reject_duplicate_keys() {
    let ok = r#"{"format_version":2,"id":"p","version":1,"canonical_version":1,"action_classes":{"execute_shell":"Mission"},"rules":[{"id":"r","action_type":"execute_shell","effect":"Deny","required_capability":null,"target":null,"parameter_conditions":[],"context_conditions":[]}]}"#;
    assert_eq!(
        Policy::from_json(ok).unwrap().rules[0].action_type,
        "execute_shell"
    );
    let duplicate = ok.replacen(r#""id":"p","#, r#""id":"p","id":"q","#, 1);
    assert!(Policy::from_json(&duplicate).is_err());
}

// Origin: tests/test_policy_parser_minimal.py::test_parse_minimal_yaml_when_any_all_empty_ok.
// Empty condition lists are valid and mean "no extra condition".
#[test]
fn empty_condition_lists_are_valid() {
    let policy = mission_policy(Policy::new(
        "canopy-port",
        1,
        vec![PolicyRule::new("r", "x", PolicyEffect::Deny)],
    ));
    assert!(policy.rules[0].parameter_conditions.is_empty());
    assert_rule(
        &evaluate(&policy, &action("x", json!({})), &[]),
        DecisionOutcome::Deny,
        "r",
    );
}

// Origin: tests/test_policy_guards.py::test_overlong_regex_is_ignored.
// Canopy silently ignores an overlong pattern and then ALLOWs by default.
// PRAETORE has no regex; an oversized rule value is rejected (fail closed).
#[test]
fn oversized_policy_text_is_rejected_not_ignored() {
    let policy = mission_policy(Policy::new(
        "canopy-port",
        1,
        vec![
            PolicyRule::new("r", "execute_shell", PolicyEffect::Deny)
                .with_parameter_condition(PolicyCondition::prefix("p", "x"))
                .with_target("a".repeat(2048)),
        ],
    ));
    assert!(policy.validate().is_err());
    let agent = agent();
    assert!(
        policy
            .evaluate(
                &agent,
                &authority(&agent, &[]),
                &mission((action("execute_shell", json!({}))).clone())
            )
            .is_err()
    );
}

// Origin: tests/test_policy_guards.py::test_agent_ctx_requires_public_key_and_created_at.
#[test]
fn agent_identity_requires_a_public_key() {
    assert!(AgentIdentity::new(AgentId::new(), vec![], "ed25519").is_err());
}

// Origin: tests/test_firewall_case_insensitive.py.
// Canopy lower-cases action names before matching. PRAETORE matches action
// types exactly; a differently-cased action matches no rule and is denied.
#[test]
fn action_type_match_is_exact_and_fails_closed() {
    let policy = mission_policy(Policy::new(
        "canopy-port",
        1,
        vec![PolicyRule::new(
            "allow-read",
            "read_file",
            PolicyEffect::Allow,
        )],
    ));
    assert_default_deny(&evaluate(&policy, &action("READ_FILE", json!({})), &[]));
    assert_rule(
        &evaluate(&policy, &action("read_file", json!({})), &[]),
        DecisionOutcome::Allow,
        "allow-read",
    );
}

// Origin: tests/test_civil_code.py::test_title_ii_spend_* (spend limit).
// Rewritten as declarative numeric conditions instead of a built-in title.
#[test]
fn spend_over_limit_requires_approval_and_missing_amount_fails_closed() {
    let rules = vec![
        PolicyRule::new("small-spend", "spend", PolicyEffect::Allow).with_parameter_condition(
            PolicyCondition::new("amount", MatchOperator::LessThanOrEqual, json!(10)),
        ),
        PolicyRule::new("large-spend", "spend", PolicyEffect::RequireApproval)
            .with_parameter_condition(PolicyCondition::greater_than("amount", json!(10))),
    ];
    let policy = mission_policy(Policy::new_v2("canopy-port", 1, rules));
    assert_rule(
        &evaluate(&policy, &action("spend", json!({"amount": 5})), &[]),
        DecisionOutcome::Allow,
        "small-spend",
    );
    assert_rule(
        &evaluate(&policy, &action("spend", json!({"amount": 50})), &[]),
        DecisionOutcome::RequireApproval,
        "large-spend",
    );
    // Semantics v2: an unknown amount satisfies the restrictive rule, not the allow.
    let missing = evaluate(&policy, &action("spend", json!({})), &[]);
    assert_rule(&missing, DecisionOutcome::RequireApproval, "large-spend");
    assert!(
        !missing
            .contributions
            .iter()
            .any(|c| c.rule_id == "small-spend")
    );
}

// Origin: tests/test_civil_code.py::test_title_vi_mining_{denied,allowed}_*.
// Canopy uses an `authorized_mining` context flag; PRAETORE uses a capability
// granted in the (signed) authority.
#[test]
fn capability_gated_rule_needs_the_capability() {
    let policy = mission_policy(Policy::new(
        "canopy-port",
        1,
        vec![PolicyRule::new("mine", "mine_crypto", PolicyEffect::Allow).with_capability("mining")],
    ));
    let agent = agent();
    let act = action("mine_crypto", json!({}));
    let without = policy
        .evaluate(&agent, &authority(&agent, &[]), &mission((act).clone()))
        .unwrap();
    assert_default_deny(&without);
    let with = policy
        .evaluate(
            &agent,
            &authority(&agent, &["mining"]),
            &mission((act).clone()),
        )
        .unwrap();
    assert_rule(&with, DecisionOutcome::Allow, "mine");
}

// Origin: tests/test_authorize_action.py::test_avid_mismatch_raises.
// Canopy recomputes the declared AVID; PRAETORE binds the authority to the
// agent id and refuses a request whose authority names another subject.
#[test]
fn authority_for_another_agent_is_rejected() {
    let policy = mission_policy(Policy::new(
        "canopy-port",
        1,
        vec![
            PolicyRule::new("read", "read_data", PolicyEffect::Allow).with_capability("data:read"),
        ],
    ));
    let agent = agent();
    let other = AgentKeyPair::from_secret_bytes(&[10; 32]).identity(AgentId::new());
    let foreign = authority(&other, &["data:read"]);
    let act = action("read_data", json!({})).with_capability("data:read");
    let result = AuthorizationRequest::new(agent, foreign, mission(act))
        .and_then(|request| AuthorizationEngine::development(policy).evaluate(request));
    assert!(result.is_err(), "{result:?}");
}

// Origin: tests/test_self_serve.py::test_gateway_is_safe_by_default (spirit).
// An engine with an empty policy denies a fully valid request.
#[test]
fn engine_with_no_rules_denies_valid_request() {
    let agent = agent();
    let auth = authority(&agent, &["data:read"]);
    let act = action("read_data", json!({})).with_capability("data:read");
    let request = AuthorizationRequest::new(agent, auth, mission(act)).unwrap();
    let evidence = AuthorizationEngine::development(
        Policy::new("canopy-port", 1, vec![]).with_mission_actions(["read_data"]),
    )
    .evaluate(request)
    .unwrap();
    assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
    assert!(evidence.verify_integrity());
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
