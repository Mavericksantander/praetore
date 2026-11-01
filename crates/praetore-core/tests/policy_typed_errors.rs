//! Issue #23: every rejection of a policy document at load time is a typed
//! error. Each test matches the exact variant, never a message.

use praetore_core::{
    MatchOperator, Policy, PolicyCondition, PolicyDocumentError, PolicyEffect, PolicyLimit,
    PolicyRule, PraetoreError,
    canonical::{MAX_JSON_DEPTH, MAX_JSON_NODES, MAX_JSON_VALUE_BYTES},
    policy::{MAX_CONDITION_SET_VALUES, MAX_CONDITION_VALUE_DEPTH},
};
use serde_json::{Value, json};

fn policy_with(expected: Value) -> Policy {
    Policy::new(
        "p",
        1,
        vec![
            PolicyRule::new("r", "a", PolicyEffect::Allow).with_parameter_condition(
                PolicyCondition::new("k", MatchOperator::Exact, expected),
            ),
        ],
    )
}

/// The JSON document of `policy_with(expected)`, without validating it.
fn document(expected: Value) -> Value {
    serde_json::to_value(policy_with(expected)).unwrap()
}

fn from_value(document: &Value) -> praetore_core::Result<Policy> {
    Policy::from_json(&document.to_string())
}

fn nested(depth: usize, innermost: Value) -> Value {
    (1..depth).fold(innermost, |value, _| json!([value]))
}

#[test]
fn oversized_raw_input_is_an_input_bytes_limit() {
    let mut text = document(json!(1)).to_string();
    assert!(Policy::from_json(&text).is_ok());
    // Insignificant whitespace still counts: the raw text is bounded before
    // it is parsed.
    text.push_str(&" ".repeat(MAX_JSON_VALUE_BYTES + 1 - text.len()));
    assert!(matches!(
        Policy::from_json(&text),
        Err(PraetoreError::PolicyLimitExceeded {
            limit: PolicyLimit::InputBytes,
            max: MAX_JSON_VALUE_BYTES
        })
    ));
}

#[test]
fn oversized_decoded_value_is_a_canonical_bytes_limit() {
    // `1e15` is 4 raw bytes but `1000000000000000.0` once decoded, so the
    // raw input fits in 64 KiB while the canonical form does not.
    let values = vec!["1e15"; MAX_CONDITION_SET_VALUES].join(",");
    let conditions: Vec<String> = (0..20)
        .map(|i| format!(r#"{{"key":"k{i:02}","operator":"Exact","expected":[{values}]}}"#))
        .collect();
    let text = format!(
        r#"{{"id":"p","version":1,"canonical_version":1,"rules":[{{"id":"r","action_type":"a","effect":"Allow","required_capability":null,"target":null,"parameter_conditions":[{}],"context_conditions":[]}}]}}"#,
        conditions.join(",")
    );
    assert!(text.len() <= MAX_JSON_VALUE_BYTES);
    assert!(matches!(
        Policy::from_json(&text),
        Err(PraetoreError::PolicyLimitExceeded {
            limit: PolicyLimit::CanonicalBytes,
            max: MAX_JSON_VALUE_BYTES
        })
    ));
}

#[test]
fn excessive_json_depth_is_a_json_depth_limit() {
    // Depth is checked on the whole document before the schema, so the
    // per-condition depth limit is not reached first.
    let doc = document(nested(MAX_JSON_DEPTH, json!(0)));
    assert!(matches!(
        from_value(&doc),
        Err(PraetoreError::PolicyLimitExceeded {
            limit: PolicyLimit::JsonDepth,
            max: MAX_JSON_DEPTH
        })
    ));
}

#[test]
fn excessive_node_count_is_a_json_nodes_limit() {
    let doc = document(Value::Array(vec![json!(0); MAX_JSON_NODES]));
    assert!(matches!(
        from_value(&doc),
        Err(PraetoreError::PolicyLimitExceeded {
            limit: PolicyLimit::JsonNodes,
            max: MAX_JSON_NODES
        })
    ));
}

#[test]
fn unsafe_integer_is_a_typed_document_error() {
    let unsafe_integer = json!(9_007_199_254_740_992_u64);
    let unsafe_document = |result: praetore_core::Result<()>| {
        matches!(
            result,
            Err(PraetoreError::PolicyDocumentInvalid(
                PolicyDocumentError::UnsafeInteger
            ))
        )
    };
    assert!(unsafe_document(
        from_value(&document(unsafe_integer.clone())).map(drop)
    ));
    // Same variant when the policy is built in code and validated.
    assert!(unsafe_document(policy_with(unsafe_integer).validate()));
}

#[test]
fn duplicate_key_is_a_typed_document_error() {
    for text in [
        r#"{"id":"p","id":"q","version":1,"canonical_version":1,"rules":[]}"#,
        r#"{"id":"p","version":1,"canonical_version":1,"rules":[{"id":"r","id":"s"}]}"#,
    ] {
        assert!(
            matches!(
                Policy::from_json(text),
                Err(PraetoreError::PolicyDocumentInvalid(
                    PolicyDocumentError::DuplicateKey
                ))
            ),
            "{text}"
        );
    }
}

#[test]
fn malformed_json_is_a_typed_document_error_with_position() {
    let cases = [
        (r#"{"id":"p",}"#, 1, 11),
        ("{\"id\":\"p\",\n\"version\":}", 2, 11),
        (
            r#"{"id":"p","version":1,"canonical_version":1,"rules":[]} x"#,
            1,
            57,
        ),
        ("", 1, 0),
    ];
    for (text, line, column) in cases {
        match Policy::from_json(text) {
            Err(PraetoreError::PolicyDocumentInvalid(PolicyDocumentError::Malformed {
                line: got_line,
                column: got_column,
            })) => assert_eq!((got_line, got_column), (line, column), "{text}"),
            other => panic!("{text}: expected Malformed, got {other:?}"),
        }
    }
}

#[test]
fn unknown_field_is_a_typed_document_error_at_every_level() {
    let base = document(json!(1));
    assert!(from_value(&base).is_ok());

    let mut top = base.clone();
    top["future"] = json!(true);
    let mut rule = base.clone();
    rule["rules"][0]["priority"] = json!(1);
    let mut condition = base.clone();
    condition["rules"][0]["parameter_conditions"][0]["case_sensitive"] = json!(false);
    let mut context = base;
    context["rules"][0]["context_conditions"] =
        json!([{"key": "k", "operator": "Exact", "expected": 1, "note": "x"}]);

    for (doc, field) in [
        (top, "future"),
        (rule, "priority"),
        (condition, "case_sensitive"),
        (context, "note"),
    ] {
        match from_value(&doc) {
            Err(PraetoreError::PolicyDocumentInvalid(PolicyDocumentError::UnknownField {
                field: got,
            })) => assert_eq!(got, field),
            other => panic!("expected UnknownField({field}), got {other:?}"),
        }
    }
}

#[test]
fn known_optional_fields_are_not_reported_as_unknown() {
    let mut doc = document(json!(1));
    doc["semantics_version"] = json!(2);
    doc["max_approval_ms"] = json!(5_000);
    doc["rules"][0]["control_loop"] = json!("slow");
    doc["rules"][0]["delta_ms"] = json!(10);
    from_value(&doc).unwrap();
}

/// Issue #23 (c): the array-value cap counts every array in a condition's
/// expected value, at every depth, as one total.
#[test]
fn nested_arrays_share_one_total_cap_at_every_depth() {
    let is_set_limit = |result: praetore_core::Result<()>| {
        matches!(
            result,
            Err(PraetoreError::PolicyLimitExceeded {
                limit: PolicyLimit::ConditionSetValues,
                max: MAX_CONDITION_SET_VALUES
            })
        )
    };
    // The innermost array sits at `depth`, wrapped in `depth - 1`
    // single-element arrays, each of which adds one value to the total.
    for depth in [2, 3, 5, MAX_CONDITION_VALUE_DEPTH - 1] {
        let wrappers = depth - 1;
        let fits = Value::Array(vec![json!(0); MAX_CONDITION_SET_VALUES - wrappers]);
        let fits = nested(depth, fits);
        policy_with(fits.clone()).validate().unwrap();
        from_value(&document(fits)).unwrap();

        let over = Value::Array(vec![json!(0); MAX_CONDITION_SET_VALUES + 1 - wrappers]);
        let over = nested(depth, over);
        assert!(
            is_set_limit(policy_with(over.clone()).validate()),
            "{depth}"
        );
        assert!(
            is_set_limit(from_value(&document(over)).map(drop)),
            "{depth}"
        );
    }

    // Sibling arrays add up: two arrays of 128 under one array of 2 is 258.
    let half = Value::Array(vec![json!(0); MAX_CONDITION_SET_VALUES / 2]);
    let siblings = json!([half.clone(), half]);
    assert!(is_set_limit(policy_with(siblings.clone()).validate()));
    assert!(is_set_limit(from_value(&document(siblings)).map(drop)));

    // Arrays inside an object value count too.
    let in_object = json!({"a": Value::Array(vec![json!(0); MAX_CONDITION_SET_VALUES + 1])});
    assert!(is_set_limit(policy_with(in_object).validate()));

    // A flat `In` set keeps its previous bound.
    let flat = |n| {
        Policy::new(
            "p",
            1,
            vec![
                PolicyRule::new("r", "a", PolicyEffect::Allow).with_parameter_condition(
                    PolicyCondition::one_of("k", (0..n).map(|i| json!(i)).collect()),
                ),
            ],
        )
    };
    flat(MAX_CONDITION_SET_VALUES).validate().unwrap();
    assert!(is_set_limit(flat(MAX_CONDITION_SET_VALUES + 1).validate()));
}

#[test]
fn typed_policy_errors_keep_the_policy_evaluation_code() {
    let errors = [
        Policy::from_json("{").unwrap_err(),
        Policy::from_json(&" ".repeat(MAX_JSON_VALUE_BYTES + 1)).unwrap_err(),
        from_value(&document(json!(9_007_199_254_740_992_u64))).unwrap_err(),
    ];
    for error in errors {
        assert_eq!(error.code(), "POLICY_EVALUATION_FAIL", "{error:?}");
    }
}
