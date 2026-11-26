//! H1 and H2 of the session report: `praetore-mcp report` has the levels
//! and the exit codes of `verify` (OK 0, UNANCHORED 3, FAIL 1), and the
//! verify command a report prints reaches OK on a home with no approval
//! journal. No approval is decided here: the session has one allowed call.

use praetore_mcp::{
    gate::{Gate, Journal, Mode},
    receipts,
    report::{self, SessionMeta, Source},
    store::{self, Home},
};
use serde_json::{Value, json};
use std::fs;
use time::OffsetDateTime;

const POLICY: &str = r#"{
  "format_version": 2,
  "id": "report-assurance",
  "version": 1,
  "canonical_version": 1,
  "semantics_version": 2,
  "action_classes": {"mcp.tools/call": "Mission"},
  "rules": [
    {
      "id": "allow-echo",
      "action_type": "mcp.tools/call",
      "effect": "Allow",
      "required_capability": "mcp:tools/call",
      "target": "fake",
      "parameter_conditions": [{"key": "tool", "operator": "Exact", "expected": "echo"}],
      "context_conditions": []
    }
  ]
}
"#;

/// A home with one allowed receipt and the report of its session, written
/// as `wrap` writes it at close. No approval journal.
fn home_with_a_report() -> (tempfile::TempDir, Home) {
    home_with_a_report_of(&[])
}

/// [`home_with_a_report`], with `gone` added to the session's ids: receipts
/// the session recorded that are no longer in the journal.
fn home_with_a_report_of(gone: &[&str]) -> (tempfile::TempDir, Home) {
    let temp = tempfile::tempdir().unwrap();
    let home = Home::new(temp.path().join("home"));
    store::init(&home).unwrap();
    fs::write(home.policy(), POLICY).unwrap();
    let gate = Gate::load(&home, Mode::Enforce).unwrap();
    let evidence = gate
        .evaluate_evidence("fake", &json!({"name": "echo", "arguments": {}}))
        .unwrap();
    Journal::new(&home).record(&evidence).unwrap();
    let now = OffsetDateTime::now_utc();
    report::generate(
        &home,
        Source {
            meta: SessionMeta {
                id: "0a1b2c3d".into(),
                server: "fake".into(),
                mode: "enforce".into(),
                started_at: now,
                ended_at: now,
            },
            evidence_ids: std::iter::once(evidence.evidence_id.to_string())
                .chain(gone.iter().map(|id| (*id).to_owned()))
                .collect(),
            close_heads: None,
            agent: None,
            regenerated_from: None,
        },
    )
    .unwrap();
    (temp, home)
}

fn report_exit(home: &Home, extra: &[&str]) -> i32 {
    let mut args = vec![
        "report".to_owned(),
        "--dir".to_owned(),
        home.root.to_str().unwrap().to_owned(),
    ];
    args.extend(extra.iter().map(|arg| (*arg).to_owned()));
    praetore_mcp::cli::run(&args)
}

fn receipts_head(home: &Home) -> String {
    receipts::verify_journal(home, None)
        .unwrap()
        .head
        .unwrap()
        .prev
        .to_string()
}

/// The newest regenerated report's JSON header.
fn last_header(home: &Home) -> Value {
    let mut files: Vec<_> = fs::read_dir(report::reports_dir(home))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    let text = fs::read_to_string(files.last().unwrap()).unwrap();
    serde_json::from_str::<Value>(&text).unwrap()["header"].clone()
}

/// H2: without heads kept elsewhere, the report is UNANCHORED, exit 3,
/// as `verify`; it does not say that verify passed.
#[test]
fn report_without_heads_is_unanchored_with_the_exit_code_of_verify() {
    let (_temp, home) = home_with_a_report();
    assert_eq!(report_exit(&home, &[]), receipts::UNANCHORED_EXIT);
    assert_eq!(last_header(&home)["verify"]["assurance"], "UNANCHORED");
}

/// H1: the verify command in a report of a home with no approval journal
/// names `--expected-approval-head none`, so running it can reach OK.
#[test]
fn report_verify_command_names_no_approval_journal() {
    let (_temp, home) = home_with_a_report();
    report_exit(&home, &[]);
    let command = last_header(&home)["verify_command"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        command.ends_with("--expected-approval-head none"),
        "{command}"
    );
}

/// With both heads the report is OK, exit 0; with a head the journal does
/// not end at it, FAIL, exit 1.
#[test]
fn report_with_both_heads_is_ok_and_with_a_wrong_head_fails() {
    let (_temp, home) = home_with_a_report();
    let head = receipts_head(&home);
    let ok = [
        "--expected-head",
        head.as_str(),
        "--expected-approval-head",
        "none",
    ];
    assert_eq!(report_exit(&home, &ok), 0);
    assert_eq!(last_header(&home)["verify"]["assurance"], "OK");
    // Regenerated file names carry the second: keep the two apart.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let wrong = "0".repeat(64);
    let failed = [
        "--expected-head",
        wrong.as_str(),
        "--expected-approval-head",
        "none",
    ];
    assert_eq!(report_exit(&home, &failed), 1);
    assert_eq!(last_header(&home)["verify"]["assurance"], "FAIL");
}

/// A malformed head is a usage error, exit 2 as for `verify`, and no
/// report is written for it.
#[test]
fn report_with_a_malformed_head_is_a_usage_error() {
    let (_temp, home) = home_with_a_report();
    let before = fs::read_dir(report::reports_dir(&home)).unwrap().count();
    assert_eq!(report_exit(&home, &["--expected-head", "not-hex"]), 2);
    assert_eq!(
        fs::read_dir(report::reports_dir(&home)).unwrap().count(),
        before
    );
}

/// Both heads match, but a receipt of the session is gone from the journal:
/// FAIL, exit 1, not OK.
#[test]
fn report_with_a_session_receipt_gone_fails_even_with_both_heads() {
    let (_temp, home) = home_with_a_report_of(&["00000000-0000-4000-8000-000000000000"]);
    let head = receipts_head(&home);
    let args = [
        "--expected-head",
        head.as_str(),
        "--expected-approval-head",
        "none",
    ];
    assert_eq!(report_exit(&home, &args), 1);
    assert_eq!(last_header(&home)["verify"]["assurance"], "FAIL");
}
