//! The number the gate decides on is the number the server reads.
//!
//! `wrap` forwards the client's bytes, so the server parses a number's text
//! itself. Each case sends boundary literals through `wrap --mode enforce`
//! to `fake_server`, which logs the value it read with the standard
//! library's parser, and checks the decision against that logged value:
//! a call the server ran must not satisfy a Deny or RequireApproval
//! condition, and must satisfy the Allow condition.

use praetore_core::{MatchOperator, PolicyCondition, PolicyEffect, PolicyRule};
use praetore_mcp::store::{self, ACTION_TYPE, CAPABILITY, Home};
use serde_json::{Value, json};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_praetore-mcp")
}

fn fake_server() -> PathBuf {
    let path = Path::new(bin())
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("fake_server{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.exists(),
        "{} missing: run via `cargo test` so examples are built",
        path.display()
    );
    path
}

fn run(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .env_remove("PRAETORE_MCP_APPROVAL_TTL_SECONDS")
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

/// `verify` against both anchors of a clean home (receipts head, or
/// `none` if the journal is empty, plus `--expected-approval-head none`).
fn verify_anchored(root: &Path) -> Output {
    let probe = run(&["verify", "--dir", root.to_str().unwrap()], "");
    let report = String::from_utf8_lossy(&probe.stdout).into_owned();
    let head = report
        .split(", head ")
        .nth(1)
        .and_then(|rest| rest.get(..64))
        .map(str::to_owned);
    let dir = root.to_str().unwrap();
    let head = head.as_deref().unwrap_or("none");
    run(
        &[
            "verify",
            "--dir",
            dir,
            "--expected-head",
            head,
            "--expected-approval-head",
            "none",
        ],
        "",
    )
}

/// A literal whose text an f64, a decimal or a bigint parser reads
/// differently, or reads differently from a parser that rounds wrongly.
const BOUNDARY: [&str; 5] = [
    "49.9999999999999965",  // 50.0 as f64; 49.99999999999999 if misrounded
    "99.9999999999999929",  // 100.0 as f64; 99.99999999999999 if misrounded
    "50.00000000000000001", // 50.0 as f64; above 50 as a decimal
    "9007199254740993",     // 2^53 + 1: 2^53 as f64; an unsafe integer for the policy
    "1e400",                // out of range for f64
];

/// Canonical literals around the same thresholds: these must be decided,
/// not refused, so the table cannot pass by refusing everything.
const CANONICAL: [&str; 7] = [
    "49",
    "50",
    "51",
    "100",
    "49.99999999999999",
    "50.5",
    "100.5",
];

/// Thresholds the rules compare against.
const THRESHOLDS: [i128; 2] = [50, 100];

const OPERATORS: [MatchOperator; 6] = [
    MatchOperator::Exact,
    MatchOperator::In,
    MatchOperator::GreaterThan,
    MatchOperator::GreaterThanOrEqual,
    MatchOperator::LessThan,
    MatchOperator::LessThanOrEqual,
];

const EFFECTS: [PolicyEffect; 3] = [
    PolicyEffect::Deny,
    PolicyEffect::RequireApproval,
    PolicyEffect::Allow,
];

/// What `fake_server` logged for one call.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Recorded {
    Int(i128),
    Float(f64),
}

impl Recorded {
    /// Exact order of the recorded value relative to an integer threshold.
    /// Every threshold is exact as an f64.
    fn cmp(self, threshold: i128) -> Ordering {
        match self {
            Recorded::Int(value) => value.cmp(&threshold),
            Recorded::Float(value) => value.partial_cmp(&(threshold as f64)).unwrap(),
        }
    }

    /// Whether the value the server read satisfies `operator threshold`,
    /// as a number (`50.0` equals `50`).
    fn satisfies(self, operator: &MatchOperator, threshold: i128) -> bool {
        let order = self.cmp(threshold);
        match operator {
            MatchOperator::Exact | MatchOperator::In => order == Ordering::Equal,
            MatchOperator::GreaterThan => order == Ordering::Greater,
            MatchOperator::GreaterThanOrEqual => order != Ordering::Less,
            MatchOperator::LessThan => order == Ordering::Less,
            MatchOperator::LessThanOrEqual => order != Ordering::Greater,
            other => panic!("not a numeric operator: {other:?}"),
        }
    }
}

/// `id -> value` from the `fake_server: RECORDED amount <id> <kind> <value>`
/// lines of the session's stderr.
fn recorded(stderr: &str) -> BTreeMap<i64, Recorded> {
    stderr
        .lines()
        .filter_map(|line| line.strip_prefix("fake_server: RECORDED amount "))
        .map(|rest| {
            let fields: Vec<&str> = rest.split(' ').collect();
            let value = match fields[1] {
                "int" => Recorded::Int(fields[2].parse().unwrap()),
                "float" => Recorded::Float(fields[2].parse().unwrap()),
                other => panic!("unknown kind {other}"),
            };
            (fields[0].parse().unwrap(), value)
        })
        .collect()
}

fn expected(operator: &MatchOperator, threshold: i128) -> Value {
    // i128 is not a JSON number here; every threshold fits in i64.
    let threshold = i64::try_from(threshold).unwrap();
    match operator {
        MatchOperator::In => json!([threshold, -1]),
        _ => json!(threshold),
    }
}

/// One rule `transfer` with `arguments.amount operator threshold` and
/// `effect`. For Deny and RequireApproval, a second rule allows every other
/// `transfer`; for Allow, everything else is denied by default.
fn write_policy(home: &Home, operator: &MatchOperator, threshold: i128, effect: &PolicyEffect) {
    let tool = PolicyCondition::exact("tool", json!("transfer"));
    let mut policy = store::default_policy();
    if *effect != PolicyEffect::Allow {
        policy.rules.push(
            PolicyRule::new("allow-transfer", ACTION_TYPE, PolicyEffect::Allow)
                .with_capability(CAPABILITY)
                .with_parameter_condition(tool.clone()),
        );
    }
    policy.rules.push(
        PolicyRule::new("amount-rule", ACTION_TYPE, effect.clone())
            .with_capability(CAPABILITY)
            .with_parameter_condition(tool)
            .with_parameter_condition(PolicyCondition::new(
                "arguments.amount",
                *operator,
                expected(operator, threshold),
            )),
    );
    fs::write(home.policy(), serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
}

/// The session's lines. The literal is spliced in as text: `json!` would
/// re-serialize the number and lose the boundary literal.
fn session(literals: &[&str]) -> String {
    let mut lines = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}).to_string(),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string(),
    ];
    for (index, literal) in literals.iter().enumerate() {
        lines.push(format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{"name":"transfer","arguments":{{"amount":{literal}}}}}}}"#,
            100 + index
        ));
    }
    lines.iter().map(|line| format!("{line}\n")).collect()
}

#[test]
fn the_decision_matches_the_value_the_server_recorded() {
    let literals: Vec<&str> = BOUNDARY.iter().chain(CANONICAL.iter()).copied().collect();
    let temp = tempfile::tempdir().unwrap();
    let mut executed_cases = 0;
    let mut blocked_canonical_cases = 0;
    for (case, ((operator, effect), threshold)) in OPERATORS
        .iter()
        .flat_map(|operator| EFFECTS.iter().map(move |effect| (operator, effect)))
        .flat_map(|pair| THRESHOLDS.iter().map(move |threshold| (pair, *threshold)))
        .enumerate()
    {
        let root = temp.path().join(format!("home-{case}"));
        let init = run(&["init", "--dir", root.to_str().unwrap()], "");
        assert!(init.status.success(), "{init:?}");
        let home = Home::new(root.clone());
        write_policy(&home, operator, threshold, effect);

        let server = fake_server();
        let out = run(
            &[
                "wrap",
                "--dir",
                root.to_str().unwrap(),
                "--name",
                "fake",
                "--mode",
                "enforce",
                "--no-report",
                "--",
                server.to_str().unwrap(),
            ],
            &session(&literals),
        );
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let seen = recorded(&stderr);

        for (index, literal) in literals.iter().enumerate() {
            let what = format!("{literal} {operator:?} {threshold} {effect:?}");
            let server_value = seen.get(&(100 + index as i64)).copied();
            if let Some(value) = server_value {
                // The server ran the call with `value`.
                let satisfied = value.satisfies(operator, threshold);
                let consistent = match effect {
                    PolicyEffect::Allow => satisfied,
                    _ => !satisfied,
                };
                assert!(
                    consistent,
                    "{what}: the server ran the call and recorded {value:?}, which {} the {effect:?} condition\n{stderr}",
                    if satisfied {
                        "satisfies"
                    } else {
                        "does not satisfy"
                    }
                );
                executed_cases += 1;
            } else if let Ok(integer) = literal.parse::<i128>()
                && index >= BOUNDARY.len()
            {
                // A canonical integer that did not run: the gate must have
                // had a reason, read from the same number. A float against
                // these integer thresholds is a mixed comparison, which the
                // policy engine may block either way (fail closed), so only
                // the direction above is checked for it.
                let satisfied = Recorded::Int(integer).satisfies(operator, threshold);
                let blocked_for_cause = match effect {
                    PolicyEffect::Allow => !satisfied,
                    _ => satisfied,
                };
                assert!(
                    blocked_for_cause,
                    "{what}: a canonical literal was not forwarded although the {effect:?} condition {}\n{stderr}",
                    if satisfied { "holds" } else { "does not hold" }
                );
                blocked_canonical_cases += 1;
            }
        }

        // No literal may leave a journal that verify cannot read.
        let verify = verify_anchored(&root);
        assert!(
            verify.status.success(),
            "{operator:?} {threshold} {effect:?}: verify failed\n{}{}",
            String::from_utf8_lossy(&verify.stdout),
            String::from_utf8_lossy(&verify.stderr)
        );
    }
    // The table decided calls both ways; it did not pass by refusing all.
    assert!(executed_cases > 50, "{executed_cases}");
    assert!(blocked_canonical_cases > 30, "{blocked_canonical_cases}");
}

/// No boundary literal reaches the server in enforce mode, even when no
/// rule's condition holds for it: three are refused for their form, `1e400`
/// is not a JSON number an f64 can hold, and `2^53 + 1` is an unsafe
/// integer, which the policy engine matches against every restrictive rule.
#[test]
fn a_non_canonical_literal_is_refused_in_enforce() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let init = run(&["init", "--dir", root.to_str().unwrap()], "");
    assert!(init.status.success(), "{init:?}");
    let home = Home::new(root.clone());
    // Deny below 0, allow the rest: no boundary value is below 0.
    write_policy(&home, &MatchOperator::LessThan, 0, &PolicyEffect::Deny);
    let server = fake_server();
    let out = run(
        &[
            "wrap",
            "--dir",
            root.to_str().unwrap(),
            "--name",
            "fake",
            "--mode",
            "enforce",
            "--no-report",
            "--",
            server.to_str().unwrap(),
        ],
        &session(&BOUNDARY),
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let seen = recorded(&stderr);
    assert_eq!(seen, BTreeMap::new(), "{stderr}");
    assert!(stderr.contains("number out of range"), "{stderr}");
    assert!(
        stderr.contains("fake/transfer DENIED by rule amount-rule"),
        "{stderr}"
    );
    for literal in [
        "49.9999999999999965",
        "99.9999999999999929",
        "50.00000000000000001",
    ] {
        assert!(
            stderr.contains(&format!(
                "number {literal} is not written in canonical form"
            )),
            "{literal}\n{stderr}"
        );
    }
}
