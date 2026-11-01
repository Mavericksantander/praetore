//! Per-agent attribution (SAF-14): each agent type signs with its own
//! issued identity, and a receipt cannot be re-attributed to another agent
//! by editing a field.
//!
//! These tests use only items that also exist before SAF-14 (and build the
//! hook input from JSON), so the same file compiles against the earlier
//! `main.rs` and shows which checks it lacked.

use std::path::PathBuf;

use super::*;

const PROFILE_KEY: &str = "praetore.agent_profile";

struct State {
    root: PathBuf,
    state: PathBuf,
}

impl State {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "praetore-claude-hook-attr-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let root = fs::canonicalize(&base).unwrap();
        let state = root.join("state");
        initialize(&state, &root, 30).unwrap();
        Self { root, state }
    }

    fn input(&self, agent: Option<&str>, tool: &str, file: &str, extra: Value) -> HookInput {
        let mut event = json!({
            "tool_name": tool,
            "tool_input": { "file_path": format!("{}/{file}", self.root.display()) },
            "tool_use_id": "toolu_attr",
            "cwd": self.root.display().to_string(),
        });
        if let Some(agent) = agent {
            event["agent_type"] = json!(agent);
        }
        for (key, value) in extra.as_object().into_iter().flatten() {
            event[key] = value.clone();
        }
        serde_json::from_value(event).unwrap()
    }

    fn decide(&self, agent: Option<&str>, tool: &str, file: &str) -> DecisionOutcome {
        authorize(&self.state, &self.input(agent, tool, file, json!({})))
            .unwrap()
            .outcome
    }

    fn receipts(&self) -> Vec<Value> {
        fs::read_to_string(self.state.join(RECEIPTS_FILE))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn write_receipts(&self, records: &[Value]) {
        let lines: String = records.iter().map(|r| format!("{r}\n")).collect();
        fs::write(self.state.join(RECEIPTS_FILE), lines).unwrap();
    }
}

impl Drop for State {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn each_agent_type_signs_with_its_own_issued_identity() {
    let s = State::new("ids");
    assert_eq!(
        s.decide(Some("coder"), "Write", "a.rs"),
        DecisionOutcome::Allow
    );
    assert_eq!(
        s.decide(Some("explorer"), "Write", "a.rs"),
        DecisionOutcome::Deny
    );
    let records = s.receipts();
    let (coder, explorer) = (&records[0]["evidence"], &records[1]["evidence"]);
    assert_ne!(coder["agent"]["id"], explorer["agent"]["id"]);
    assert_ne!(
        coder["agent"]["public_key"],
        explorer["agent"]["public_key"]
    );
    for (evidence, profile) in [(coder, "coder"), (explorer, "explorer")] {
        assert_eq!(evidence["authority"]["subject"], evidence["agent"]["id"]);
        assert_eq!(evidence["context"]["agent"], profile);
        // The issuer, not only the hook, says which profile this id is.
        assert_eq!(
            evidence["authority"]["constraints"],
            json!([{ "key": PROFILE_KEY, "value": profile }]),
            "{profile}"
        );
    }
    verify_receipts(&s.state).unwrap();
}

#[test]
fn editing_the_unsigned_agent_field_cannot_reattribute_a_receipt() {
    let s = State::new("wrapper");
    s.decide(Some("coder"), "Write", "a.rs");
    s.decide(Some("explorer"), "Write", "a.rs");
    verify_receipts(&s.state).unwrap();

    // Claim the explorer's denied write was the coder's.
    let mut records = s.receipts();
    records[1]["agent"] = json!("coder");
    records[1]["profile"] = json!("coder");
    s.write_receipts(&records);
    assert!(
        verify_receipts(&s.state).is_err(),
        "verify accepted a receipt whose unsigned agent field was edited"
    );
    let out = s.root.join("bundle");
    assert!(
        export_bundle(&s.state, &out).is_err(),
        "export wrote an index from an edited unsigned agent field"
    );
}

#[test]
fn editing_the_signed_agent_name_breaks_the_signatures() {
    let s = State::new("signed");
    s.decide(Some("explorer"), "Read", "README.md");
    let mut records = s.receipts();
    records[0]["agent"] = json!("coder");
    records[0]["profile"] = json!("coder");
    records[0]["evidence"]["context"]["agent"] = json!("coder");
    records[0]["evidence"]["context"]["profile"] = json!("coder");
    s.write_receipts(&records);
    assert!(verify_receipts(&s.state).is_err());
}

#[test]
fn a_profile_file_copied_over_another_fails_closed() {
    let s = State::new("swap");
    let agents = s.state.join(AGENTS_DIR);
    for ext in ["json", "key"] {
        let target = agents.join(format!("explorer.{ext}"));
        fs::remove_file(&target).unwrap();
        fs::copy(agents.join(format!("coder.{ext}")), &target).unwrap();
    }
    // Before SAF-14 the explorer signed as the coder and got its write.
    let verdict = authorize(
        &s.state,
        &s.input(Some("explorer"), "Write", "a.rs", json!({})),
    );
    assert!(
        verdict.is_err(),
        "explorer signed with the coder's identity: {verdict:?}"
    );
}

#[test]
fn the_exported_index_names_the_signing_agent_id() {
    let s = State::new("export");
    s.decide(Some("coder"), "Write", "a.rs");
    s.decide(Some("planner"), "Read", "README.md");
    let out = s.root.join("bundle");
    export_bundle(&s.state, &out).unwrap();
    let index: Vec<Value> =
        serde_json::from_slice(&fs::read(out.join("index.json")).unwrap()).unwrap();
    assert_eq!(index.len(), 2);
    for entry in &index {
        let evidence: Value =
            serde_json::from_slice(&fs::read(out.join(entry["file"].as_str().unwrap())).unwrap())
                .unwrap();
        assert_eq!(entry["agent_id"], evidence["agent"]["id"], "{entry}");
        assert_eq!(entry["agent"], evidence["context"]["agent"]);
    }
    assert_ne!(index[0]["agent_id"], index[1]["agent_id"]);
}

#[test]
fn instance_and_session_ids_are_signed_claims() {
    let s = State::new("instance");
    let extra = json!({ "agent_id": "agent-abc123", "session_id": "sess-1" });
    authorize(
        &s.state,
        &s.input(Some("explorer"), "Read", "README.md", extra),
    )
    .unwrap();
    let records = s.receipts();
    let context = &records[0]["evidence"]["context"];
    assert_eq!(context["claude.agent_id"], "agent-abc123");
    assert_eq!(context["claude.session_id"], "sess-1");
    verify_receipts(&s.state).unwrap();

    // A changed instance id is a changed signed field.
    let mut records = records;
    records[0]["evidence"]["context"]["claude.agent_id"] = json!("agent-other");
    s.write_receipts(&records);
    assert!(verify_receipts(&s.state).is_err());

    let too_long = json!({ "agent_id": "x".repeat(129) });
    let verdict = authorize(
        &s.state,
        &s.input(Some("explorer"), "Read", "README.md", too_long),
    )
    .unwrap();
    assert_eq!(verdict.outcome, DecisionOutcome::Deny);
}
