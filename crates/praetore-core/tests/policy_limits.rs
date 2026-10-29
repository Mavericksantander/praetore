//! Boundary tests: each policy limit accepts exactly N and rejects N + 1
//! with a typed `PolicyLimitExceeded` error, on both `validate` and
//! `from_json` (the document is rejected; nothing is ignored).

use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, MatchOperator, Policy, PolicyCondition, PolicyEffect,
    PolicyLimit, PolicyRule, PraetoreError,
    canonical::{MAX_JSON_VALUE_BYTES, canonicalize_json},
    policy::{
        MAX_CONDITION_SET_VALUES, MAX_CONDITION_STRING_BYTES, MAX_CONDITION_VALUE_DEPTH,
        MAX_CONDITIONS_PER_RULE, MAX_POLICY_RULES, MAX_POLICY_TEXT_BYTES,
    },
};
use serde_json::{Value, json};

fn rule() -> PolicyRule {
    PolicyRule::new("r", "a", PolicyEffect::Allow)
}

fn one(rule: PolicyRule) -> Policy {
    Policy::new("p", 1, vec![rule])
}

fn assert_ok(policy: &Policy) {
    policy.validate().unwrap();
    Policy::from_json(&serde_json::to_string(policy).unwrap()).unwrap();
}

fn assert_limit(policy: &Policy, expected: PolicyLimit) {
    match policy.validate() {
        Err(PraetoreError::PolicyLimitExceeded { limit, .. }) => assert_eq!(limit, expected),
        other => panic!("expected {expected:?}, got {other:?}"),
    }
    let json = serde_json::to_string(policy).unwrap();
    if json.len() <= MAX_JSON_VALUE_BYTES {
        assert!(matches!(
            Policy::from_json(&json),
            Err(PraetoreError::PolicyLimitExceeded { limit, .. }) if limit == expected
        ));
    } else {
        assert!(Policy::from_json(&json).is_err());
    }
    // Fail closed at evaluation time too: an error, never a decision.
    let agent = AgentKeyPair::from_secret_bytes(&[5; 32]).identity(AgentId::new());
    let authority = Authority::new(agent.id.clone(), "i", vec![]);
    let action = Action::new("a", None, json!({})).unwrap();
    assert!(policy.evaluate(&agent, &authority, &action).is_err());
}

fn edge(build: impl Fn(usize) -> Policy, max: usize, limit: PolicyLimit) {
    assert_ok(&build(max));
    assert_limit(&build(max + 1), limit);
}

#[test]
fn policy_id_bytes() {
    edge(
        |n| Policy::new("p".repeat(n), 1, vec![rule()]),
        MAX_POLICY_TEXT_BYTES,
        PolicyLimit::PolicyIdBytes,
    );
}

#[test]
fn rules_per_policy() {
    edge(
        |n| {
            Policy::new(
                "p",
                1,
                (0..n)
                    .map(|i| PolicyRule::new(format!("r{i}"), "a", PolicyEffect::Allow))
                    .collect(),
            )
        },
        MAX_POLICY_RULES,
        PolicyLimit::Rules,
    );
}

#[test]
fn rule_text_fields() {
    edge(
        |n| one(PolicyRule::new("r".repeat(n), "a", PolicyEffect::Allow)),
        MAX_POLICY_TEXT_BYTES,
        PolicyLimit::RuleIdBytes,
    );
    edge(
        |n| one(PolicyRule::new("r", "a".repeat(n), PolicyEffect::Allow)),
        MAX_POLICY_TEXT_BYTES,
        PolicyLimit::ActionTypeBytes,
    );
    edge(
        |n| one(rule().with_capability("c".repeat(n))),
        MAX_POLICY_TEXT_BYTES,
        PolicyLimit::CapabilityBytes,
    );
    edge(
        |n| one(rule().with_target("t".repeat(n))),
        MAX_POLICY_TEXT_BYTES,
        PolicyLimit::TargetBytes,
    );
}

#[test]
fn conditions_per_rule_scope() {
    edge(
        |n| {
            one((0..n).fold(rule(), |rule, i| {
                rule.with_parameter_condition(PolicyCondition::exact(format!("k{i}"), json!(1)))
            }))
        },
        MAX_CONDITIONS_PER_RULE,
        PolicyLimit::ConditionsPerRule,
    );
    edge(
        |n| {
            one((0..n).fold(rule(), |rule, i| {
                rule.with_context_condition(PolicyCondition::exact(format!("k{i}"), json!(1)))
            }))
        },
        MAX_CONDITIONS_PER_RULE,
        PolicyLimit::ConditionsPerRule,
    );
}

#[test]
fn condition_key_and_string_bytes() {
    edge(
        |n| one(rule().with_parameter_condition(PolicyCondition::exact("k".repeat(n), json!(1)))),
        MAX_POLICY_TEXT_BYTES,
        PolicyLimit::ConditionKeyBytes,
    );
    edge(
        |n| one(rule().with_parameter_condition(PolicyCondition::prefix("k", "v".repeat(n)))),
        MAX_CONDITION_STRING_BYTES,
        PolicyLimit::ConditionStringBytes,
    );
    edge(
        |n| {
            one(rule()
                .with_parameter_condition(PolicyCondition::exact("k", json!({ "x".repeat(n): 1 }))))
        },
        MAX_CONDITION_STRING_BYTES,
        PolicyLimit::ConditionStringBytes,
    );
    edge(
        |n| {
            one(rule()
                .with_parameter_condition(PolicyCondition::one_of("k", vec![json!("v".repeat(n))])))
        },
        MAX_CONDITION_STRING_BYTES,
        PolicyLimit::ConditionStringBytes,
    );
}

#[test]
fn path_prefix_counts_against_condition_string_bytes() {
    // "/" followed by n-1 bytes: a valid normalized path of exactly n bytes.
    edge(
        |n| {
            one(
                rule().with_parameter_condition(PolicyCondition::path_prefix(
                    "k",
                    format!("/{}", "p".repeat(n - 1)),
                )),
            )
        },
        MAX_CONDITION_STRING_BYTES,
        PolicyLimit::ConditionStringBytes,
    );
}

#[test]
fn values_in_set_condition() {
    edge(
        |n| {
            one(rule().with_parameter_condition(PolicyCondition::one_of(
                "k",
                (0..n).map(|i| json!(i)).collect(),
            )))
        },
        MAX_CONDITION_SET_VALUES,
        PolicyLimit::ConditionSetValues,
    );
}

#[test]
fn condition_value_depth() {
    // A scalar has depth 1; each enclosing array adds 1.
    let nested = |depth: usize| (1..depth).fold(json!(1), |value, _| json!([value]));
    edge(
        |n| {
            one(rule().with_parameter_condition(PolicyCondition::new(
                "k",
                MatchOperator::Exact,
                nested(n),
            )))
        },
        MAX_CONDITION_VALUE_DEPTH,
        PolicyLimit::ConditionValueDepth,
    );
}

/// Policy whose canonical JSON is exactly `target` bytes.
fn policy_with_canonical_len(target: usize) -> Policy {
    // Compact serde JSON has the same byte length as the canonical form
    // (only key order differs); checked below against `canonicalize_json`
    // wherever the input is small enough for it to accept.
    let canonical_len = |policy: &Policy| serde_json::to_string(policy).unwrap().len();
    let build = |conditions: &[usize]| {
        one(conditions
            .iter()
            .enumerate()
            .fold(rule(), |rule, (i, len)| {
                rule.with_parameter_condition(PolicyCondition::exact(
                    format!("k{i:03}"),
                    Value::String("v".repeat(*len)),
                ))
            }))
    };
    let mut lengths = vec![];
    loop {
        lengths.push(0);
        let base = canonical_len(&build(&lengths));
        let room = target.checked_sub(base).expect("overshot");
        if room <= MAX_CONDITION_STRING_BYTES {
            *lengths.last_mut().unwrap() = room;
            let policy = build(&lengths);
            assert_eq!(canonical_len(&policy), target);
            if target <= MAX_JSON_VALUE_BYTES {
                let json = serde_json::to_string(&policy).unwrap();
                assert_eq!(canonicalize_json(&json).unwrap().len(), target);
            }
            return policy;
        }
        *lengths.last_mut().unwrap() = MAX_CONDITION_STRING_BYTES;
    }
}

#[test]
fn canonical_policy_bytes() {
    assert_ok(&policy_with_canonical_len(MAX_JSON_VALUE_BYTES));
    let over = policy_with_canonical_len(MAX_JSON_VALUE_BYTES + 1);
    assert!(matches!(
        over.validate(),
        Err(PraetoreError::PolicyLimitExceeded {
            limit: PolicyLimit::CanonicalBytes,
            max: MAX_JSON_VALUE_BYTES
        })
    ));
    assert!(Policy::from_json(&serde_json::to_string(&over).unwrap()).is_err());
}

#[test]
fn limit_errors_keep_the_stable_policy_code() {
    let error = Policy::new("p".repeat(MAX_POLICY_TEXT_BYTES + 1), 1, vec![rule()])
        .validate()
        .unwrap_err();
    assert_eq!(error.code(), "POLICY_EVALUATION_FAIL");
    assert!(error.to_string().contains("policy id bytes"));
}
