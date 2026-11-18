//! A receipt line is parsed and checked before it is written.
//!
//! Random numeric arguments, and the fixed literal 99.9999999999999929, are
//! appended and then `praetore-mcp verify` is run. Verify exits 0. When the
//! line does not re-parse, the call is not forwarded, the journal is
//! unchanged, and the next call in a new `wrap` process still runs.

use praetore_core::{Policy, PolicyEffect, PolicyRule};
use praetore_mcp::{
    gate::{Gate, Mode},
    proxy::handle_client_line,
    receipts,
    store::{self, ACTION_TYPE, CAPABILITY, Home, LEGACY_ALLOW_ALL_RULE},
};
use proptest::prelude::*;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const LITERAL: &str = "99.9999999999999929";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_praetore-mcp")
}

fn fake_server() -> PathBuf {
    let path = Path::new(bin())
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("fake_server{}", std::env::consts::EXE_SUFFIX));
    assert!(path.exists(), "{}", path.display());
    path
}

fn run(args: &[&str], stdin: &str) -> Output {
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

fn allow_all(home: &Home) {
    let mut policy = Policy::new_v2("test-policy", 1, vec![]).with_mission_actions([ACTION_TYPE]);
    policy.rules.push(
        PolicyRule::new(LEGACY_ALLOW_ALL_RULE, ACTION_TYPE, PolicyEffect::Allow)
            .with_capability(CAPABILITY),
    );
    fs::write(
        home.policy(),
        serde_json::to_string_pretty(&policy).unwrap(),
    )
    .unwrap();
}

fn verify_cli(home: &Home) -> Output {
    run(&["verify", "--dir", home.root.to_str().unwrap()], "")
}

fn session(calls: &[&str]) -> String {
    let mut input = String::from(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"0\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
    );
    for call in calls {
        input.push_str(call);
        input.push('\n');
    }
    input
}

fn call(id: &str, arguments: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":\"{id}\",\"method\":\"tools/call\",\"params\":{{\"name\":\"echo\",\"arguments\":{arguments}}}}}"
    )
}

fn wrap(home: &Home, mode: &str, input: &str) -> (Vec<Value>, String, Output) {
    let server = fake_server();
    let out = run(
        &[
            "wrap",
            "--dir",
            home.root.to_str().unwrap(),
            "--name",
            "fake",
            "--mode",
            mode,
            "--",
            server.to_str().unwrap(),
        ],
        input,
    );
    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    let responses = stdout
        .lines()
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|error| panic!("bad line {line:?}: {error}"))
        })
        .collect();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (responses, stderr, out)
}

fn by_id<'a>(responses: &'a [Value], id: &str) -> &'a Value {
    responses
        .iter()
        .find(|response| response["id"] == json!(id))
        .unwrap_or_else(|| panic!("no response for {id} in {responses:?}"))
}

/// Parsing `literal` and parsing that encoding again yield the same number.
fn json_number_round_trips(literal: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(literal) else {
        return false;
    };
    let encoded = serde_json::to_string(&value).unwrap();
    serde_json::from_str::<Value>(&encoded).ok().as_ref() == Some(&value)
}

fn assert_verify_ok(home: &Home, context: &str) -> String {
    let output = verify_cli(home);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    eprintln!(
        "verify {context} exit {:?}\n{stdout}{stderr}",
        output.status.code()
    );
    assert_eq!(output.status.code(), Some(0), "{context}\n{stdout}{stderr}");
    assert!(stdout.contains("OK"), "{context}\n{stdout}");
    stdout
}

#[test]
fn literal_then_a_new_wrap_session_verifies() {
    let round_trips = json_number_round_trips(LITERAL);
    eprintln!("literal {LITERAL} round-trips through serde_json: {round_trips}");
    for mode in ["observe", "enforce"] {
        let (_temp, home) = init_home();
        allow_all(&home);
        let poison = call("p", &format!("{{\"n\":{LITERAL}}}"));
        let (responses, stderr, out) = wrap(&home, mode, &session(&[&poison]));
        assert!(out.status.success(), "{mode}: {stderr}");
        let first = assert_verify_ok(&home, &format!("{mode} after the literal"));
        let executed = stderr.matches("EXECUTED echo").count();
        if !round_trips {
            assert_eq!(executed, 0, "{mode}: {stderr}");
            assert_eq!(
                by_id(&responses, "p")["result"]["isError"],
                true,
                "{stderr}"
            );
            assert!(stderr.contains("does not verify"), "{mode}: {stderr}");
            assert!(first.contains("OK 0 receipts"), "{first}");
        }
        let normal = call("n", r#"{"n":1}"#);
        let (responses, stderr, out) = wrap(&home, mode, &session(&[&normal]));
        assert!(out.status.success(), "{mode} next session: {stderr}");
        assert_eq!(
            stderr.matches("EXECUTED echo").count(),
            1,
            "{mode} next session: {stderr}"
        );
        assert_eq!(
            by_id(&responses, "n")["result"]["isError"],
            false,
            "{stderr}"
        );
        let second = assert_verify_ok(&home, &format!("{mode} after the next session"));
        assert!(second.contains("verified"), "{second}");
        let journal = receipts::read_journal(&home).unwrap();
        assert!(!journal.is_empty(), "{mode}");
    }
}

fn fresh_home() -> (tempfile::TempDir, Home) {
    let temp = tempfile::tempdir().unwrap();
    let home = Home::new(temp.path().join("home"));
    store::init(&home).unwrap();
    (temp, home)
}

fn try_literal(home: &Home, mode: Mode, literal: &str) -> (bool, Output) {
    let mut gate = Gate::load(home, mode).unwrap();
    let line = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"tools/call\",\"params\":{{\"name\":\"echo\",\"arguments\":{{\"n\":{literal}}}}}}}\n"
    );
    let outcome = handle_client_line(line.as_bytes(), mode, "s", &mut gate);
    drop(gate);
    let verify = verify_cli(home);
    (outcome.to_server.is_some(), verify)
}

fn numeric_literals() -> impl Strategy<Value = String> {
    let floats = any::<f64>()
        .prop_filter("finite", |value| value.is_finite())
        .prop_map(|value| serde_json::Number::from_f64(value).unwrap().to_string());
    let exponential =
        (0u32..10_000, -20i32..=20, any::<bool>()).prop_map(|(mantissa, exponent, negative)| {
            let sign = if negative { "-" } else { "" };
            format!("{sign}{mantissa}e{exponent}")
        });
    let many_digits = (
        1u8..=9,
        proptest::collection::vec(0u8..10, 0..=32),
        proptest::collection::vec(0u8..10, 0..=32),
        any::<bool>(),
    )
        .prop_map(|(lead, whole, fraction, negative)| {
            let mut text = if negative {
                format!("-{lead}")
            } else {
                lead.to_string()
            };
            for digit in whole {
                text.push(char::from(b'0' + digit));
            }
            if !fraction.is_empty() {
                text.push('.');
                for digit in fraction {
                    text.push(char::from(b'0' + digit));
                }
            }
            text
        });
    let large_integers = (
        1u8..=9,
        proptest::collection::vec(0u8..10, 0..=24),
        any::<bool>(),
    )
        .prop_map(|(lead, rest, negative)| {
            let mut text = if negative {
                format!("-{lead}")
            } else {
                lead.to_string()
            };
            for digit in rest {
                text.push(char::from(b'0' + digit));
            }
            text
        });
    prop_oneof![floats, exponential, many_digits, large_integers]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Append a call whose argument is a random f64 or a random numeric
    /// literal, then `verify`. The process exits 0. A refused call leaves
    /// the journal verifying as well.
    #[test]
    fn random_numeric_argument_appends_or_refuses_and_verify_exits_0(
        literal in numeric_literals()
    ) {
        for mode in [Mode::Enforce, Mode::Observe] {
            let (_temp, home) = fresh_home();
            let (forwarded, verify) = try_literal(&home, mode, &literal);
            let stdout = String::from_utf8_lossy(&verify.stdout);
            let stderr = String::from_utf8_lossy(&verify.stderr);
            prop_assert!(
                verify.status.success(),
                "literal {literal} mode {} forwarded {forwarded}\n{stdout}{stderr}",
                mode.as_str()
            );
            prop_assert!(stdout.contains("OK"), "{stdout}");
            if !forwarded {
                let report = receipts::verify_journal(&home, None).unwrap();
                prop_assert!(report.failures.is_empty(), "{:?}", report.failures);
            }
        }
    }
}
