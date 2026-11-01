//! End-to-end rejection cases for chains built by the shared producer
//! (`praetore_core::journal_chain::ChainExporter`) and checked by
//! `praetore-verify journal`. Every rejection must exit non-zero with an
//! explicit code on stdout and a message on stderr.

use praetore_core::{
    action::Action,
    authority::Authority,
    authorization::AuthorizationRequest,
    decision::Decision,
    evidence::{Evidence, EvidenceAttesterKey},
    identity::{AgentId, AgentKeyPair},
    journal_chain::{ChainExporter, ChainHead},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "praetore-verify-chain-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> String {
        let path = self.0.join(name);
        fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn attester() -> EvidenceAttesterKey {
    EvidenceAttesterKey::from_secret_bytes(&[3; 32])
}

fn receipt(index: u8) -> Evidence {
    let agent_key = AgentKeyPair::from_secret_bytes(&[1; 32]);
    let issuer_key = AgentKeyPair::from_secret_bytes(&[2; 32]);
    let agent = agent_key.identity(AgentId::new());
    let mut authority = Authority::new(agent.id.clone(), "test-issuer", vec!["data:read".into()]);
    authority.sign_for_agent(&issuer_key, &agent).unwrap();
    let action = Action::new("read_data", Some("db".into()), json!({ "row": index }))
        .unwrap()
        .with_capability("data:read");
    let mut request = AuthorizationRequest::new(agent, authority, mission(action)).unwrap();
    request.sign_intent(&agent_key).unwrap();
    let mut evidence = request
        .attest(Decision::allow(
            "chain fixture",
            praetore_core::DecidedBy::rule("chain-fixture"),
        ))
        .unwrap();
    evidence.bind_policy_digest("ab".repeat(32)).unwrap();
    evidence.sign(&attester()).unwrap();
    evidence
}

/// What an attacker holding only the receipts (not the key) can do: rebuild
/// a chain over any list of validly signed receipts.
fn chain(receipts: &[Evidence]) -> (String, ChainHead) {
    let key = attester().public_key().unwrap();
    let mut exporter = ChainExporter::new(&key);
    for evidence in receipts {
        exporter.push(evidence).unwrap();
    }
    exporter.finish().unwrap()
}

struct Fixture {
    dir: Dir,
    pin: String,
    receipts: Vec<Evidence>,
    text: String,
    head: ChainHead,
}

impl Fixture {
    fn new() -> Self {
        let dir = Dir::new();
        let pin = dir.write(
            "pin.hex",
            format!(
                "{}\n",
                hex::encode(attester().public_key().unwrap().as_bytes())
            ),
        );
        let receipts: Vec<_> = (0..4).map(receipt).collect();
        let (text, head) = chain(&receipts);
        Self {
            dir,
            pin,
            receipts,
            text,
            head,
        }
    }

    fn lines(&self) -> Vec<String> {
        self.text.lines().map(str::to_owned).collect()
    }

    fn verify(&self, text: &str, expected_head: Option<&str>) -> Output {
        let path = self.dir.write("chain.jsonl", text);
        let mut args = vec!["journal", "--journal", &path, "--attester-pin", &self.pin];
        if let Some(head) = expected_head {
            args.extend(["--expected-head", head]);
        }
        args.extend(["--format", "json"]);
        Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
            .args(&args)
            .output()
            .unwrap()
    }

    fn expected(&self) -> String {
        self.head.head.to_hex()
    }
}

fn join(lines: &[String]) -> String {
    lines.iter().map(|line| format!("{line}\n")).collect()
}

fn assert_rejected(output: &Output, code: &str) {
    assert_ne!(output.status.code(), Some(0), "must fail with {code}");
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["ok"], false);
    assert_eq!(summary["code"], code);
    assert!(
        !output.stderr.is_empty(),
        "an explicit error message is expected on stderr"
    );
}

#[test]
fn producer_output_verifies_with_and_without_expected_head() {
    let fx = Fixture::new();
    assert_eq!(fx.head.entries.get(), 4);
    for expected in [None, Some(fx.expected())] {
        let output = fx.verify(&fx.text, expected.as_deref());
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(summary["details"]["entries"], 4);
        assert_eq!(summary["details"]["head"], fx.expected());
        assert_eq!(
            summary["details"]["expected_head_verified"],
            expected.is_some()
        );
    }
}

#[test]
fn deleted_receipt_is_rejected() {
    let fx = Fixture::new();
    let mut lines = fx.lines();
    lines.remove(1);
    assert_rejected(&fx.verify(&join(&lines), None), "JOURNAL_CHAIN_FAIL");

    // Re-linked after the deletion: only the anchored head catches it.
    let (relinked, _) = chain(&[
        fx.receipts[0].clone(),
        fx.receipts[2].clone(),
        fx.receipts[3].clone(),
    ]);
    assert!(fx.verify(&relinked, None).status.success());
    assert_rejected(
        &fx.verify(&relinked, Some(&fx.expected())),
        "JOURNAL_HEAD_MISMATCH",
    );
}

#[test]
fn reordered_receipts_are_rejected() {
    let fx = Fixture::new();
    let mut lines = fx.lines();
    lines.swap(1, 2);
    assert_rejected(&fx.verify(&join(&lines), None), "JOURNAL_CHAIN_FAIL");

    let mut swapped = fx.receipts.clone();
    swapped.swap(1, 2);
    let (relinked, _) = chain(&swapped);
    assert_rejected(
        &fx.verify(&relinked, Some(&fx.expected())),
        "JOURNAL_HEAD_MISMATCH",
    );
}

#[test]
fn truncated_tail_is_rejected_against_expected_head() {
    let fx = Fixture::new();
    let lines = fx.lines();
    let truncated = join(&lines[..3]);
    // A prefix of a valid chain is a valid chain: without the anchored head
    // the truncation passes. This is the documented limit.
    assert!(fx.verify(&truncated, None).status.success());
    assert_rejected(
        &fx.verify(&truncated, Some(&fx.expected())),
        "JOURNAL_HEAD_MISMATCH",
    );

    // A line cut in the middle (no final newline) is malformed.
    let cut = &fx.text[..fx.text.len() - 10];
    assert_rejected(&fx.verify(cut, None), "INVALID_REQUEST");
}

#[test]
fn repeated_seq_is_rejected() {
    let fx = Fixture::new();
    let mut lines = fx.lines();
    lines[2] = lines[2].replacen("{\"seq\":2,", "{\"seq\":1,", 1);
    assert_rejected(&fx.verify(&join(&lines), None), "JOURNAL_CHAIN_FAIL");

    let mut duplicated = fx.lines();
    duplicated.insert(2, duplicated[1].clone());
    assert_rejected(&fx.verify(&join(&duplicated), None), "JOURNAL_CHAIN_FAIL");
}

#[test]
fn altered_receipt_is_rejected() {
    let fx = Fixture::new();
    let mut lines = fx.lines();
    assert!(lines[1].contains("\"chain fixture\""));
    lines[1] = lines[1].replacen("\"chain fixture\"", "\"chain fixturf\"", 1);
    // Still valid JSON; the integrity hash over the signed content breaks.
    assert_rejected(&fx.verify(&join(&lines), None), "EVIDENCE_FAIL");

    // A forged signature on an otherwise intact receipt, chain rebuilt over it.
    let mut forged = fx.receipts.clone();
    forged[1].attester_signature = Some("00".repeat(64));
    let mut text = String::new();
    let mut prev = "0".repeat(64);
    for (seq, evidence) in forged.iter().enumerate() {
        let evidence_json: Value = serde_json::from_str(&evidence.to_json().unwrap()).unwrap();
        text.push_str(&json!({ "seq": seq, "prev": prev, "evidence": evidence_json }).to_string());
        text.push('\n');
        prev = link_for_test(seq as u64, &prev, evidence);
    }
    assert_rejected(&fx.verify(&text, None), "AUTH_FAIL");
}

#[test]
fn duplicate_evidence_id_is_rejected_even_when_correctly_linked() {
    let fx = Fixture::new();
    let receipts = [fx.receipts[0].clone(), fx.receipts[0].clone()];
    let mut text = String::new();
    let mut prev = "0".repeat(64);
    for (seq, evidence) in receipts.iter().enumerate() {
        let evidence_json: Value = serde_json::from_str(&evidence.to_json().unwrap()).unwrap();
        text.push_str(&json!({ "seq": seq, "prev": prev, "evidence": evidence_json }).to_string());
        text.push('\n');
        prev = link_for_test(seq as u64, &prev, evidence);
    }
    assert_rejected(&fx.verify(&text, None), "JOURNAL_CHAIN_FAIL");
}

#[test]
fn empty_blank_and_bad_expected_head_are_rejected() {
    let fx = Fixture::new();
    assert_rejected(&fx.verify("", None), "JOURNAL_CHAIN_FAIL");
    assert_rejected(&fx.verify("\n", None), "INVALID_REQUEST");
    let crlf = fx.text.replace('\n', "\r\n");
    assert_rejected(&fx.verify(&crlf, None), "INVALID_REQUEST");
    let upper = fx.expected().to_uppercase();
    let output = fx.verify(&fx.text, Some(&upper));
    assert_ne!(output.status.code(), Some(0));
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["code"], "INVALID_REQUEST");
}

/// Independent re-implementation of the documented link, so the tests do not
/// depend on the producer's own hashing.
fn link_for_test(seq: u64, prev: &str, evidence: &Evidence) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"PRAETORE_JOURNAL_LINK_V1\0");
    hasher.update(seq.to_be_bytes());
    hasher.update(prev.as_bytes());
    hasher.update(evidence.context_hash.as_bytes());
    hasher.update(evidence.attester_signature.as_deref().unwrap().as_bytes());
    hex::encode(hasher.finalize())
}

#[test]
fn producer_links_match_the_documented_formula() {
    let fx = Fixture::new();
    let mut prev = "0".repeat(64);
    for (seq, line) in fx.lines().iter().enumerate() {
        let entry: Value = serde_json::from_str(line).unwrap();
        assert_eq!(entry.as_object().unwrap().len(), 3);
        assert_eq!(entry["seq"], seq);
        assert_eq!(entry["prev"], prev);
        prev = link_for_test(seq as u64, &prev, &fx.receipts[seq]);
    }
    assert_eq!(prev, fx.expected());
}

fn storage_record() -> praetore_core::StorageRecord {
    storage_record_by(&attester())
}

fn storage_record_by(key: &EvidenceAttesterKey) -> praetore_core::StorageRecord {
    use praetore_core::StorageRecordSigner;
    key.sign_storage_record(praetore_core::StorageRecordPayload {
        schema_version: 1,
        kind: "legacy_baseline_adopted".into(),
        record_id: uuid::Uuid::new_v4(),
        recorded_at: "2026-11-01T12:00:00.000000Z".into(),
        database: "praetore".into(),
        database_oid: 16384,
        recorded_by: "mig".into(),
        migrations: vec![praetore_core::RecordedMigration {
            version: "0001_replay_claims".into(),
            checksum: "a".repeat(64),
        }],
        structure_sha256: "b".repeat(64),
        key_id: key.key_id(),
    })
    .unwrap()
}

fn run_verify(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .args(args)
        .output()
        .unwrap()
}

/// Storage records: the database chain verifies with `praetore-verify
/// journal`, a tenant chain's reference to its head verifies with
/// `--database-journal` or `--expected-database-head`, and a mismatch, an
/// altered record or a removed record fails.
#[test]
fn database_journal_and_tenant_reference_verify() {
    use praetore_core::journal_chain::DatabaseHead;
    let fx = Fixture::new();
    let key = attester().public_key().unwrap();
    let mut database = ChainExporter::new(&key);
    for _ in 0..3 {
        database.push_record(&storage_record()).unwrap();
    }
    let (database_text, database_head) = database.finish().unwrap();
    let database_path = fx.dir.write("database.jsonl", &database_text);
    let mut tenant = ChainExporter::new(&key);
    tenant
        .push_database_head(&DatabaseHead::from(database_head))
        .unwrap();
    for receipt in &fx.receipts {
        tenant.push(receipt).unwrap();
    }
    let (tenant_text, _) = tenant.finish().unwrap();
    let tenant_path = fx.dir.write("tenant.jsonl", &tenant_text);

    let output = run_verify(&[
        "journal",
        "--journal",
        &database_path,
        "--attester-pin",
        &fx.pin,
        "--format",
        "json",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["details"]["kind"], "database");
    assert_eq!(summary["details"]["head"], database_head.head.to_hex());

    for reference in [
        vec!["--database-journal", database_path.as_str()],
        vec!["--expected-database-head", &database_head.head.to_hex()],
    ] {
        let mut args = vec![
            "journal",
            "--journal",
            &tenant_path,
            "--attester-pin",
            &fx.pin,
        ];
        args.extend(reference.iter().copied());
        args.extend(["--format", "json"]);
        let output = run_verify(&args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(summary["details"]["kind"], "tenant");
        assert_eq!(summary["details"]["database_head_verified"], true);
        assert_eq!(
            summary["details"]["database_head"]["head"],
            database_head.head.to_hex()
        );
    }

    // A tenant chain checked against another database head fails.
    let other_head = "c".repeat(64);
    let output = run_verify(&[
        "journal",
        "--journal",
        &tenant_path,
        "--attester-pin",
        &fx.pin,
        "--expected-database-head",
        &other_head,
        "--format",
        "json",
    ]);
    assert_rejected(&output, "JOURNAL_HEAD_MISMATCH");
    // An old chain without a reference fails when one is required.
    let old_path = fx.dir.write("old.jsonl", &fx.text);
    let output = run_verify(&[
        "journal",
        "--journal",
        &old_path,
        "--attester-pin",
        &fx.pin,
        "--database-journal",
        &database_path,
        "--format",
        "json",
    ]);
    assert_rejected(&output, "JOURNAL_HEAD_MISMATCH");
    // An altered record fails; a removed record breaks the chain.
    let altered = database_text.replacen("\"recorded_by\":\"mig\"", "\"recorded_by\":\"xyz\"", 1);
    let output = run_verify(&[
        "journal",
        "--journal",
        &fx.dir.write("altered.jsonl", altered),
        "--attester-pin",
        &fx.pin,
        "--format",
        "json",
    ]);
    assert_rejected(&output, "EVIDENCE_FAIL");
    let lines: Vec<String> = database_text.lines().map(str::to_owned).collect();
    let removed = join(&[lines[0].clone(), lines[2].clone()]);
    let output = run_verify(&[
        "journal",
        "--journal",
        &fx.dir.write("removed.jsonl", removed),
        "--attester-pin",
        &fx.pin,
        "--format",
        "json",
    ]);
    assert_rejected(&output, "JOURNAL_CHAIN_FAIL");
    // The old chain alone still verifies unchanged.
    let output = fx.verify(&fx.text, Some(&fx.expected()));
    assert!(output.status.success());
}

/// B5-5: a database chain signed by a retired attester key and a tenant
/// chain signed by the current one verify with both pins (repeated
/// `--attester-pin`); with only the current pin the old record fails and
/// names the key that signed it. Nothing is re-signed.
#[test]
fn chains_across_an_attester_rotation_need_every_signing_key_pinned() {
    use praetore_core::journal_chain::DatabaseHead;
    let fx = Fixture::new();
    let old = EvidenceAttesterKey::from_secret_bytes(&[9; 32]);
    let old_pin = fx.dir.write(
        "old-pin.hex",
        hex::encode(old.public_key().unwrap().as_bytes()),
    );
    let old_public = old.public_key().unwrap();
    let mut database = ChainExporter::new(&old_public);
    database.push_record(&storage_record_by(&old)).unwrap();
    let (database_text, database_head) = database.finish().unwrap();
    let database_path = fx.dir.write("database.jsonl", &database_text);
    let pins = [old_public, attester().public_key().unwrap()];
    let mut tenant = ChainExporter::with_attesters(&pins);
    tenant
        .push_database_head(&DatabaseHead::from(database_head))
        .unwrap();
    for receipt in &fx.receipts {
        tenant.push(receipt).unwrap();
    }
    let (tenant_text, tenant_head) = tenant.finish().unwrap();
    let tenant_path = fx.dir.write("tenant.jsonl", &tenant_text);
    let both = ["--attester-pin", &old_pin, "--attester-pin", &fx.pin];
    let tenant_head = tenant_head.head.to_hex();

    for (journal, kind) in [(&database_path, "database"), (&tenant_path, "tenant")] {
        let mut args = vec!["journal", "--journal", journal.as_str()];
        args.extend(both);
        if kind == "tenant" {
            args.extend(["--database-journal", &database_path]);
            args.extend(["--expected-head", &tenant_head]);
        }
        args.extend(["--format", "json"]);
        let output = run_verify(&args);
        assert!(
            output.status.success(),
            "{kind}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(summary["details"]["kind"], kind);
    }

    // Only the current pin: the record signed by the retired key fails,
    // alone or as the database journal of the tenant chain.
    for args in [
        vec!["journal", "--journal", &database_path],
        vec![
            "journal",
            "--journal",
            &tenant_path,
            "--database-journal",
            &database_path,
        ],
    ] {
        let mut args = args;
        args.extend(["--attester-pin", &fx.pin, "--format", "json"]);
        let output = run_verify(&args);
        assert_rejected(&output, "EVIDENCE_FAIL");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!(
                "signed by attester key {}, not by a pinned key",
                old.key_id()
            )),
            "{stderr}"
        );
    }
    // The receipts are not signed by the retired key alone.
    let output = run_verify(&[
        "journal",
        "--journal",
        &tenant_path,
        "--attester-pin",
        &old_pin,
        "--format",
        "json",
    ]);
    assert_rejected(&output, "AUTH_FAIL");
    // The same key twice is refused; other commands take one pin.
    let output = run_verify(&[
        "journal",
        "--journal",
        &database_path,
        "--attester-pin",
        &old_pin,
        "--attester-pin",
        &old_pin,
        "--format",
        "json",
    ]);
    assert_rejected(&output, "TRUST_STORE_FAIL");
    let receipt = fx
        .dir
        .write("receipt.json", fx.receipts[0].to_json().unwrap());
    let output = run_verify(&[
        "evidence",
        "--evidence",
        &receipt,
        "--attester-pin",
        &fx.pin,
        "--attester-pin",
        &old_pin,
        "--format",
        "json",
    ]);
    assert!(!output.status.success());
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["code"], "USAGE");
}

/// B5-4: `--policy` on a database chain has no receipt to compare with, so
/// it fails instead of reporting `policy_verified: true`.
#[test]
fn policy_is_refused_for_a_database_journal() {
    let fx = Fixture::new();
    let key = attester().public_key().unwrap();
    let mut database = ChainExporter::new(&key);
    database.push_record(&storage_record()).unwrap();
    let (database_text, _) = database.finish().unwrap();
    let database_path = fx.dir.write("database.jsonl", &database_text);
    let policy = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/claude-code-hook/evidence/03-bundle-demo-reproducible/policy.json"
    );
    let output = run_verify(&[
        "journal",
        "--journal",
        &database_path,
        "--attester-pin",
        &fx.pin,
        "--policy",
        policy,
        "--format",
        "json",
    ]);
    assert_rejected(&output, "INVALID_REQUEST");
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(summary["details"]["policy_verified"].is_null(), "{summary}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no policy can be verified"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Without --policy the same file verifies.
    let output = run_verify(&[
        "journal",
        "--journal",
        &database_path,
        "--attester-pin",
        &fx.pin,
        "--format",
        "json",
    ]);
    assert!(output.status.success());
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["details"]["policy_verified"], false);
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
