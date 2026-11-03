//! G1: `praetore-verify safety-journal` verifies one exported chain of
//! post-hoc safety records and reports its counts.

use praetore_core::{
    ActionClass, EvidenceAttesterKey, Policy, SafetyNamespaceKey, SafetyNamespaceManifest,
    safety_ingest::{
        DEFAULT_MAX_SEQ_JUMP, IngestorConfig, LossReason, MemoryLookup, SafetyEventDraft,
        SafetyIngestKey, SafetyIngestor, SafetySourceKey, SourcePins,
    },
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::{Command, Output},
};
use time::OffsetDateTime;

const TENANT: uuid::Uuid = uuid::Uuid::from_u128(7);

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "praetore-verify-safety-journal-{}-{}",
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

fn source_key() -> SafetySourceKey {
    SafetySourceKey::from_secret_bytes(&[0x51; 32])
}

fn ingest_key() -> SafetyIngestKey {
    SafetyIngestKey::from_secret_bytes(&[0x52; 32])
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_793_577_600).unwrap()
}

/// Chains of `executor-1` and `_unattributed` as JSONL: accepted,
/// undeclared, invalid_name, a gap, a duplicate, a conflict, a rejected
/// input and a queue overflow.
fn chains() -> (String, String) {
    let namespace = SafetyNamespaceKey::from_secret_bytes(&[0x53; 32]);
    let policy =
        Policy::new_v2("ops", 1, vec![]).with_action_class("safety:halt", ActionClass::Safety);
    let manifest = SafetyNamespaceManifest::from_policy(&policy, now(), &namespace).unwrap();
    let mut sources = SourcePins::default();
    sources
        .insert("executor-1", source_key().public_key().unwrap())
        .unwrap();
    let mut ingestor = SafetyIngestor::new(IngestorConfig {
        ingest_key: ingest_key(),
        tenant_id: TENANT,
        manifest,
        namespace_pin: namespace.public_key().unwrap(),
        attester_pin: EvidenceAttesterKey::from_secret_bytes(&[0x54; 32])
            .public_key()
            .unwrap(),
        sources,
        heads: BTreeMap::new(),
        max_seq_jump: DEFAULT_MAX_SEQ_JUMP,
        max_clock_skew_seconds: praetore_core::safety_ingest::DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    })
    .unwrap();
    let mut lookup = MemoryLookup::default();
    let mut texts: BTreeMap<String, String> = BTreeMap::new();
    let event = |seq: u64, action: &str| {
        source_key()
            .sign_event(SafetyEventDraft {
                source_id: "executor-1".into(),
                source_epoch: 1,
                source_seq: seq,
                action: action.into(),
                occurred_at: now(),
                params: BTreeMap::new(),
            })
            .unwrap()
            .to_wire()
            .unwrap()
    };
    let inputs = vec![
        event(1, "safety:halt"),
        event(2, "safety:stop_all"),
        event(3, "safety:_x"),
        event(6, "safety:halt"),
        event(6, "safety:halt"),
        event(1, "safety:other"),
        b"{\"not\":\"an event\"}".to_vec(),
    ];
    let mut store = |prepared: praetore_core::safety_ingest::PreparedRecords,
                     ingestor: &mut SafetyIngestor,
                     lookup: &mut MemoryLookup| {
        ingestor.commit(&prepared);
        for record in &prepared.records {
            lookup.record(record);
            let text = texts.entry(prepared.chain.clone()).or_default();
            text.push_str(&record.to_json().unwrap());
            text.push('\n');
        }
    };
    for input in inputs {
        let prepared = ingestor.prepare(&input, now(), &mut lookup).unwrap();
        store(prepared, &mut ingestor, &mut lookup);
    }
    let dropped = ingestor
        .prepare_dropped(LossReason::QueueOverflow, 3, now())
        .unwrap();
    store(dropped, &mut ingestor, &mut lookup);
    (texts["executor-1"].clone(), texts["_unattributed"].clone())
}

fn pin_files(dir: &Dir) -> (String, String) {
    let ingest = dir.write(
        "ingest.pin",
        hex::encode(ingest_key().public_key().unwrap().as_bytes()) + "\n",
    );
    let sources = dir.write(
        "sources.jsonl",
        format!(
            "{{\"source_id\":\"executor-1\",\"public_key\":\"{}\"}}\n",
            hex::encode(source_key().public_key().unwrap().as_bytes())
        ),
    );
    (ingest, sources)
}

fn verify(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .arg("safety-journal")
        .args(args)
        .args(["--format", "json"])
        .output()
        .unwrap()
}

fn summary(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn a_source_chain_verifies_and_reports_every_status() {
    let dir = Dir::new();
    let (source, unattributed) = chains();
    let journal = dir.write("source.jsonl", &source);
    let (ingest, sources) = pin_files(&dir);
    let output = verify(&[
        "--journal",
        &journal,
        "--ingest-pin",
        &ingest,
        "--source-pins",
        &sources,
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = summary(&output);
    assert_eq!(value["code"], "OK");
    let details = &value["details"];
    assert_eq!(details["chain"], "executor-1");
    assert_eq!(details["tenant_id"], TENANT.to_string());
    assert_eq!(details["source_signatures_verified"], true);
    assert_eq!(details["high_water"], 6);
    let counts = &details["counts"];
    for (status, count) in [
        ("accepted", 2),
        ("undeclared", 1),
        ("invalid_name", 1),
        ("loss", 1),
        ("lost_events", 2),
        // The resent event 6 is an exact duplicate: counted by the
        // ingester, not stored.
        ("duplicate", 0),
        ("conflict", 1),
        ("rejected", 0),
    ] {
        assert_eq!(counts[status], count, "{status}");
    }
    // The head from this run, given as --expected-head, verifies; another
    // one does not.
    let head = details["head"].as_str().unwrap().to_owned();
    assert!(
        verify(&[
            "--journal",
            &journal,
            "--ingest-pin",
            &ingest,
            "--expected-head",
            &head
        ])
        .status
        .success()
    );
    let wrong = verify(&[
        "--journal",
        &journal,
        "--ingest-pin",
        &ingest,
        "--expected-head",
        &"a".repeat(64),
    ]);
    assert_eq!(summary(&wrong)["code"], "JOURNAL_HEAD_MISMATCH");

    let unattributed = dir.write("unattributed.jsonl", &unattributed);
    let output = verify(&["--journal", &unattributed, "--ingest-pin", &ingest]);
    assert!(output.status.success());
    let details = &summary(&output)["details"];
    assert_eq!(details["chain"], "_unattributed");
    assert_eq!(details["counts"]["rejected"], 1);
    assert_eq!(details["counts"]["dropped_messages"], 3);
    assert_eq!(details["source_signatures_verified"], false);
}

#[test]
fn a_tampered_chain_fails_with_a_code() {
    let dir = Dir::new();
    let (source, _) = chains();
    let (ingest, sources) = pin_files(&dir);
    let lines: Vec<String> = source.lines().map(|line| format!("{line}\n")).collect();
    let mut removed = lines.clone();
    removed.remove(1);
    let mut reordered = lines.clone();
    reordered.swap(1, 2);
    let mut edited = lines.clone();
    edited[0] = edited[0].replacen("\"recorded_at\":\"2026", "\"recorded_at\":\"2027", 1);
    assert_ne!(edited[0], lines[0]);
    let cases = [
        ("removed", removed.concat(), "SAFETY_CHAIN_FAIL"),
        ("reordered", reordered.concat(), "SAFETY_CHAIN_FAIL"),
        ("edited", edited.concat(), "EVIDENCE_FAIL"),
        (
            "not newline-terminated",
            source.trim_end().to_owned(),
            "INVALID_REQUEST",
        ),
    ];
    for (name, text, code) in cases {
        let journal = dir.write(&format!("{}.jsonl", name.replace(' ', "-")), text);
        let output = verify(&[
            "--journal",
            &journal,
            "--ingest-pin",
            &ingest,
            "--source-pins",
            &sources,
        ]);
        assert!(!output.status.success(), "{name} verified");
        assert_eq!(summary(&output)["code"], code, "{name}");
    }
    // Another ingestion key, and an unknown source pin set.
    let other = dir.write(
        "other.pin",
        hex::encode(
            SafetyIngestKey::from_secret_bytes(&[0x60; 32])
                .public_key()
                .unwrap()
                .as_bytes(),
        ),
    );
    let journal = dir.write("source.jsonl", &source);
    assert_eq!(
        summary(&verify(&["--journal", &journal, "--ingest-pin", &other]))["code"],
        "AUTH_FAIL"
    );
    let stranger = dir.write(
        "stranger.jsonl",
        format!(
            "{{\"source_id\":\"executor-1\",\"public_key\":\"{}\"}}\n",
            hex::encode(
                SafetySourceKey::from_secret_bytes(&[0x61; 32])
                    .public_key()
                    .unwrap()
                    .as_bytes()
            )
        ),
    );
    assert_eq!(
        summary(&verify(&[
            "--journal",
            &journal,
            "--ingest-pin",
            &ingest,
            "--source-pins",
            &stranger
        ]))["code"],
        "SAFETY_EVENT_SIGNATURE_INVALID"
    );
    // Usage errors: no pin, an unknown flag, a malformed expected head.
    assert_eq!(summary(&verify(&["--journal", &journal]))["code"], "USAGE");
    assert_eq!(
        summary(&verify(&[
            "--journal",
            &journal,
            "--ingest-pin",
            &ingest,
            "--policy",
            "p"
        ]))["code"],
        "USAGE"
    );
    assert_eq!(
        summary(&verify(&[
            "--journal",
            &journal,
            "--ingest-pin",
            &ingest,
            "--expected-head",
            "AB"
        ]))["code"],
        "USAGE"
    );
}
