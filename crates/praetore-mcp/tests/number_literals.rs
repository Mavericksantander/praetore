//! End-to-end: a non-canonical JSON number is not executed as a different
//! value from the one the proxy evaluated.
//!
//! Table: five boundary literals, six operators, three effects. `wrap` runs
//! in enforce in front of `examples/number_probe`, which records each number
//! token it actually receives and the binary64 value of Rust's correctly
//! rounded parser. A case passes when that recorded value is the value the
//! proxy evaluated, or when the literal was refused as ambiguous. A
//! `RequireApproval` case must not complete.

use praetore_core::{
    ActionClass, MatchOperator, Policy, PolicyCondition, PolicyEffect, PolicyRule,
};
use praetore_mcp::store::{ACTION_TYPE, CAPABILITY, Home};
use serde_json::{Value, json};
use std::{
    cmp::Ordering,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const LITERALS: [&str; 5] = [
    "49.9999999999999965",
    "99.9999999999999929",
    "50.00000000000000001",
    "9007199254740993",
    "1e400",
];

const OPERATORS: [(&str, MatchOperator); 6] = [
    ("Exact", MatchOperator::Exact),
    ("In", MatchOperator::In),
    (">", MatchOperator::GreaterThan),
    (">=", MatchOperator::GreaterThanOrEqual),
    ("<", MatchOperator::LessThan),
    ("<=", MatchOperator::LessThanOrEqual),
];

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_praetore-mcp")
}

fn probe() -> PathBuf {
    let path = Path::new(bin())
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("number_probe{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.exists(),
        "{} missing: run via `cargo test` so examples are built",
        path.display()
    );
    path
}

fn run(args: &[&str], stdin: &str) -> std::process::Output {
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn init_home() -> (tempfile::TempDir, Home) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let out = run(&["init", "--dir", root.to_str().unwrap()], "");
    assert!(out.status.success(), "{out:?}");
    (temp, Home::new(root))
}

fn threshold_for(literal: &str) -> Value {
    let text = match literal {
        "49.9999999999999965" | "50.00000000000000001" => "50.0",
        "99.9999999999999929" => "100.0",
        // 2^53 itself is outside the policy's interoperable range (2^53 - 1).
        // Any in-range threshold compares the same way for the integer and
        // for the binary64 value; a forwarded call still disagrees on the
        // value the probe recorded.
        "9007199254740993" => "9007199254740991",
        "1e400" => "1",
        other => panic!("no threshold for {other}"),
    };
    serde_json::from_str(text).unwrap()
}

fn write_policy(home: &Home, effect: PolicyEffect, operator: MatchOperator, threshold: &Value) {
    let expected = if operator == MatchOperator::In {
        Value::Array(vec![threshold.clone()])
    } else {
        threshold.clone()
    };
    let numeric = PolicyRule::new("numeric", ACTION_TYPE, effect.clone())
        .with_capability(CAPABILITY)
        .with_parameter_condition(PolicyCondition::exact("tool", json!("pay")))
        .with_parameter_condition(PolicyCondition::new("arguments.amount", operator, expected));
    let mut rules = Vec::new();
    if effect != PolicyEffect::Allow {
        rules.push(
            PolicyRule::new("allow-pay", ACTION_TYPE, PolicyEffect::Allow)
                .with_capability(CAPABILITY)
                .with_parameter_condition(PolicyCondition::exact("tool", json!("pay"))),
        );
    }
    rules.push(numeric);
    let mut policy = Policy::new_v2("number-literals", 1, rules);
    policy
        .action_classes
        .insert(ACTION_TYPE.to_owned(), ActionClass::Mission);
    fs::write(
        home.policy(),
        serde_json::to_string_pretty(&policy).unwrap(),
    )
    .unwrap();
}

fn condition_holds(actual: f64, operator: MatchOperator, threshold: &Value) -> bool {
    let expected = threshold.as_f64().unwrap_or_else(|| {
        threshold
            .as_i64()
            .map(|value| value as f64)
            .or_else(|| threshold.as_u64().map(|value| value as f64))
            .unwrap_or(f64::NAN)
    });
    let Some(order) = actual.partial_cmp(&expected) else {
        return false;
    };
    match operator {
        MatchOperator::Exact | MatchOperator::In => order == Ordering::Equal,
        MatchOperator::GreaterThan => order == Ordering::Greater,
        MatchOperator::GreaterThanOrEqual => order != Ordering::Less,
        MatchOperator::LessThan => order == Ordering::Less,
        MatchOperator::LessThanOrEqual => order != Ordering::Greater,
        _ => false,
    }
}

/// `true` when enforce would forward a canonical literal with this effect.
fn would_forward(effect: &PolicyEffect, matches: bool) -> bool {
    match effect {
        PolicyEffect::Allow => matches,
        PolicyEffect::Deny | PolicyEffect::RequireApproval => !matches,
        PolicyEffect::Recover { .. } => false,
    }
}

fn values_agree(evaluated: &Value, executed: &str) -> bool {
    let Ok(executed) = executed.parse::<f64>() else {
        return false;
    };
    let Some(number) = evaluated.as_number() else {
        return false;
    };
    if number.is_i64() {
        let Some(integer) = number.as_i64() else {
            return false;
        };
        let as_float = integer as f64;
        return as_float as i64 == integer && as_float == executed;
    }
    if number.is_u64() {
        let Some(integer) = number.as_u64() else {
            return false;
        };
        let as_float = integer as f64;
        return as_float as u64 == integer && as_float == executed;
    }
    number.as_f64() == Some(executed)
}

fn wrap_pay(home: &Home, log: &Path, literal: &str) -> (String, String, bool) {
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"pay","arguments":{{"amount":{literal}}}}}}}"#
    );
    let probe = probe();
    let out = run(
        &[
            "wrap",
            "--dir",
            home.root.to_str().unwrap(),
            "--name",
            "probe",
            "--mode",
            "enforce",
            "--",
            probe.to_str().unwrap(),
            log.to_str().unwrap(),
        ],
        &format!("{line}\n"),
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "literal {literal} wrap failed: {stderr}"
    );
    let received = fs::read_to_string(log).unwrap_or_default();
    let forwarded = !received.trim().is_empty();
    (stderr, received, forwarded)
}

#[test]
fn boundary_literals_match_the_probe_or_are_ambiguous() {
    let (_temp, home) = init_home();
    let log_dir = tempfile::tempdir().unwrap();
    let mut index = 0;
    for literal in LITERALS {
        let threshold = threshold_for(literal);
        let correct = literal
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite());
        for (op_name, operator) in OPERATORS {
            for effect in [
                PolicyEffect::Deny,
                PolicyEffect::RequireApproval,
                PolicyEffect::Allow,
            ] {
                index += 1;
                let log = log_dir.path().join(format!("{index}.log"));
                write_policy(&home, effect.clone(), operator, &threshold);
                let (stderr, received, forwarded) = wrap_pay(&home, &log, literal);
                let label = format!("{literal} {op_name} {effect:?}");
                if forwarded {
                    let record: Value = serde_json::from_str(received.lines().next().unwrap())
                        .unwrap_or_else(|error| panic!("{label}: probe log {received:?}: {error}"));
                    let parsed = record["numbers"]
                        .as_array()
                        .and_then(|numbers| numbers.iter().find(|item| item["literal"] == literal))
                        .map(|item| item["parsed"].as_str().unwrap().to_owned())
                        .unwrap_or_else(|| {
                            panic!("{label}: probe did not record {literal}: {record}")
                        });
                    let journal = praetore_mcp::receipts::read_journal(&home).unwrap();
                    let evidence = praetore_mcp::journal::parse_line(&journal.last().unwrap().text)
                        .unwrap()
                        .evidence;
                    let evaluated = &evidence.action.parameters["arguments.amount"];
                    assert!(
                        values_agree(evaluated, &parsed),
                        "{label}: evaluated {evaluated} but the probe executed {parsed}"
                    );
                    let actual: f64 = parsed.parse().expect(&parsed);
                    assert!(
                        would_forward(&effect, condition_holds(actual, operator, &threshold)),
                        "{label}: forwarded, but the probe value {parsed} would not be forwarded"
                    );
                } else {
                    let ambiguous = stderr.contains("ambiguous") && stderr.contains(literal);
                    let consistent = correct.is_some_and(|actual| {
                        !would_forward(&effect, condition_holds(actual, operator, &threshold))
                    });
                    assert!(
                        ambiguous || consistent,
                        "{label}: not forwarded, not ambiguous, and not a decision on the \
                         correctly parsed value\n{stderr}"
                    );
                    if effect == PolicyEffect::RequireApproval {
                        assert!(
                            ambiguous
                                || correct.is_some_and(|actual| {
                                    condition_holds(actual, operator, &threshold)
                                }),
                            "{label}: REQUIRE_APPROVAL was neither held nor rejected\n{stderr}"
                        );
                    }
                }
            }
        }
    }
}

/// A literal that is canonical only when `float_roundtrip` is enabled.
/// Without that feature, `serde_json` rewrites it to `1.0`.
#[test]
fn canonical_roundtrip_float_is_forwarded_as_the_same_value() {
    let literal = "0.9999999999999999";
    let (_temp, home) = init_home();
    let log_dir = tempfile::tempdir().unwrap();
    let log = log_dir.path().join("control.log");
    let threshold: Value = serde_json::from_str(literal).unwrap();
    write_policy(&home, PolicyEffect::Allow, MatchOperator::Exact, &threshold);
    let (stderr, received, forwarded) = wrap_pay(&home, &log, literal);
    assert!(forwarded, "canonical literal was not forwarded\n{stderr}");
    assert!(
        !stderr.contains("not canonical"),
        "canonical literal was called non-canonical\n{stderr}"
    );
    let record: Value = serde_json::from_str(received.lines().next().unwrap()).unwrap();
    let parsed = record["numbers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["literal"] == literal)
        .unwrap()["parsed"]
        .as_str()
        .unwrap();
    assert_eq!(parsed, literal, "probe parsed {parsed}");
    let journal = praetore_mcp::receipts::read_journal(&home).unwrap();
    let evidence = praetore_mcp::journal::parse_line(&journal.last().unwrap().text)
        .unwrap()
        .evidence;
    let evaluated = &evidence.action.parameters["arguments.amount"];
    assert!(
        values_agree(evaluated, parsed),
        "evaluated {evaluated}, probe {parsed}"
    );
}

#[test]
fn observe_records_a_noncanonical_number() {
    let literal = "49.9999999999999965";
    let (_temp, home) = init_home();
    let log_dir = tempfile::tempdir().unwrap();
    let log = log_dir.path().join("observe.log");
    write_policy(
        &home,
        PolicyEffect::Deny,
        MatchOperator::GreaterThanOrEqual,
        &threshold_for(literal),
    );
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"pay","arguments":{{"amount":{literal}}}}}}}"#
    );
    let probe = probe();
    let out = run(
        &[
            "wrap",
            "--dir",
            home.root.to_str().unwrap(),
            "--name",
            "probe",
            "--mode",
            "observe",
            "--",
            probe.to_str().unwrap(),
            log.to_str().unwrap(),
        ],
        &format!("{line}\n"),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("ambiguous") && stderr.contains(literal),
        "observe did not record the ambiguity\n{stderr}"
    );
    let received = fs::read_to_string(&log).unwrap();
    assert!(
        received.contains(literal),
        "observe did not forward the literal: {received}"
    );
    let journal = praetore_mcp::receipts::read_journal(&home).unwrap();
    assert!(!journal.is_empty(), "observe did not journal the call");
}
