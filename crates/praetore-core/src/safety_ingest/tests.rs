use super::*;
use crate::{
    ActionClass, EvidenceAttesterKey, Policy, SafetyNamespaceKey, SafetyNamespaceManifest,
};

const TENANT: Uuid = Uuid::from_u128(0x5afe);

fn namespace_key() -> SafetyNamespaceKey {
    SafetyNamespaceKey::from_secret_bytes(&[1; 32])
}

fn manifest() -> SafetyNamespaceManifest {
    let policy = Policy::new_v2("ops", 1, vec![])
        .with_action_class("safety:halt", ActionClass::Safety)
        .with_action_class("safety:stop_all", ActionClass::Safety);
    SafetyNamespaceManifest::from_policy(
        &policy,
        OffsetDateTime::from_unix_timestamp(1_793_491_200).unwrap(),
        &namespace_key(),
    )
    .unwrap()
}

fn ingest_key() -> SafetyIngestKey {
    SafetyIngestKey::from_secret_bytes(&[2; 32])
}

fn ingest_pin() -> VerifiedPublicKey {
    ingest_key().public_key().unwrap()
}

fn attester_pin() -> VerifiedPublicKey {
    EvidenceAttesterKey::from_secret_bytes(&[3; 32])
        .public_key()
        .unwrap()
}

fn source_key() -> SafetySourceKey {
    SafetySourceKey::from_secret_bytes(&[4; 32])
}

fn other_source_key() -> SafetySourceKey {
    SafetySourceKey::from_secret_bytes(&[5; 32])
}

fn pins() -> SourcePins {
    let mut pins = SourcePins::default();
    pins.insert("executor-1", source_key().public_key().unwrap())
        .unwrap();
    pins.insert("executor-2", other_source_key().public_key().unwrap())
        .unwrap();
    pins
}

fn config() -> IngestorConfig {
    IngestorConfig {
        ingest_key: ingest_key(),
        tenant_id: TENANT,
        manifest: manifest(),
        namespace_pin: namespace_key().public_key().unwrap(),
        attester_pin: attester_pin(),
        sources: pins(),
        heads: BTreeMap::new(),
        max_seq_jump: DEFAULT_MAX_SEQ_JUMP,
        max_clock_skew_seconds: DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_793_577_600).unwrap()
}

fn event(seq: u64, action: &str) -> SafetyEvent {
    event_by(&source_key(), "executor-1", seq, action)
}

fn event_by(key: &SafetySourceKey, source: &str, seq: u64, action: &str) -> SafetyEvent {
    key.sign_event(SafetyEventDraft {
        source_id: source.into(),
        source_seq: seq,
        action: action.into(),
        occurred_at: now() - time::Duration::seconds(5),
        params: BTreeMap::from([("reason".into(), ParamValue::String("operator".into()))]),
    })
    .unwrap()
}

fn wire(event: &SafetyEvent) -> Vec<u8> {
    event.to_wire().unwrap()
}

/// An ingester with storage in memory: every prepared record is committed
/// and appended to its chain's JSONL text.
struct Harness {
    ingestor: SafetyIngestor,
    lookup: MemoryLookup,
    chains: BTreeMap<String, String>,
}

impl Harness {
    fn new() -> Self {
        Self {
            ingestor: SafetyIngestor::new(config()).unwrap(),
            lookup: MemoryLookup::default(),
            chains: BTreeMap::new(),
        }
    }

    fn store(&mut self, prepared: PreparedRecords) -> Vec<SafetyRecord> {
        self.ingestor.commit(&prepared);
        let text = self.chains.entry(prepared.chain.clone()).or_default();
        for record in &prepared.records {
            self.lookup.record(record);
            text.push_str(&record.to_json().unwrap());
            text.push('\n');
        }
        prepared.records
    }

    fn ingest(&mut self, input: &[u8]) -> Vec<SafetyRecord> {
        let prepared = self
            .ingestor
            .prepare(input, now(), &mut self.lookup)
            .unwrap();
        self.store(prepared)
    }

    fn statuses(&mut self, input: &[u8]) -> Vec<SafetyRecordStatus> {
        self.ingest(input)
            .iter()
            .map(|record| record.payload().status)
            .collect()
    }

    fn chain(&self, chain: &str) -> &str {
        &self.chains[chain]
    }

    fn verify(&self, chain: &str) -> Result<SafetyChainReport, SafetyChainError> {
        verify_safety_chain(self.chain(chain), &[ingest_pin()], Some(&pins()), None)
    }
}

// ---------------------------------------------------------------------------
// Events and signature domains.

#[test]
fn a_signed_event_parses_and_verifies_and_any_change_fails() {
    let event = event(1, "safety:halt");
    let parsed = SafetyEvent::parse(&wire(&event)).unwrap();
    assert_eq!(parsed, event);
    parsed.verify(&source_key().public_key().unwrap()).unwrap();
    assert!(parsed.post_hoc);
    // Another key, and every signed field changed, fail.
    assert_eq!(
        parsed
            .verify(&other_source_key().public_key().unwrap())
            .unwrap_err()
            .reason,
        RejectReason::KeyMismatch
    );
    for edit in [
        |e: &mut SafetyEvent| e.source_seq += 1,
        |e: &mut SafetyEvent| e.action.push('x'),
        |e: &mut SafetyEvent| e.occurred_at = "2026-11-02T00:00:00Z".into(),
        |e: &mut SafetyEvent| e.params = None,
        |e: &mut SafetyEvent| e.source_id = "executor-2".into(),
    ] {
        let mut altered = event.clone();
        edit(&mut altered);
        assert_eq!(
            altered
                .verify(&source_key().public_key().unwrap())
                .unwrap_err()
                .reason,
            RejectReason::SignatureInvalid
        );
        assert_ne!(altered.event_hash(), event.event_hash());
    }
}

#[test]
fn event_hash_does_not_depend_on_the_wire_encoding() {
    let event = event(1, "safety:halt");
    let mut value: Value = serde_json::from_slice(&wire(&event)).unwrap();
    let pretty = serde_json::to_vec_pretty(&value).unwrap();
    let parsed = SafetyEvent::parse(&pretty).unwrap();
    assert_eq!(parsed.event_hash(), event.event_hash());
    // Unknown fields, duplicate keys, an empty params object, post_hoc
    // false and out-of-range values are refused.
    value["extra"] = Value::Bool(true);
    assert_eq!(
        SafetyEvent::parse(&serde_json::to_vec(&value).unwrap())
            .unwrap_err()
            .reason,
        RejectReason::Malformed
    );
    let text = String::from_utf8(wire(&event)).unwrap();
    let duplicated = text.replacen('{', "{\"source_seq\":2,", 1);
    assert_eq!(
        SafetyEvent::parse(duplicated.as_bytes())
            .unwrap_err()
            .reason,
        RejectReason::Malformed
    );
    for (field, replacement, reason) in [
        (
            "params",
            Value::Object(Default::default()),
            RejectReason::Malformed,
        ),
        ("post_hoc", Value::Bool(false), RejectReason::NotPostHoc),
        ("source_seq", Value::from(0), RejectReason::Malformed),
        (
            "occurred_at",
            Value::from("2026-11-02T01:00:00+01:00"),
            RejectReason::Malformed,
        ),
        (
            "source_id",
            Value::from("Executor"),
            RejectReason::Malformed,
        ),
        ("schema_version", Value::from(2), RejectReason::Malformed),
    ] {
        let mut altered: Value = serde_json::from_slice(&wire(&event)).unwrap();
        altered[field] = replacement;
        assert_eq!(
            SafetyEvent::parse(&serde_json::to_vec(&altered).unwrap())
                .unwrap_err()
                .reason,
            reason,
            "{field}"
        );
    }
}

#[test]
fn event_record_and_key_id_domains_are_distinct_and_do_not_cross() {
    let domains: [&[u8]; 4] = [
        SAFETY_EVENT_DOMAIN,
        SAFETY_RECORD_DOMAIN,
        SAFETY_SOURCE_KEY_ID_DOMAIN,
        SAFETY_INGEST_KEY_ID_DOMAIN,
    ];
    for (i, a) in domains.iter().enumerate() {
        assert!(a.ends_with(b"\0"), "domain {i} does not end in NUL");
        for (j, b) in domains.iter().enumerate() {
            assert!(i == j || !b.starts_with(a), "domain {i} is a prefix of {j}");
        }
    }
    // The same 32 secret bytes in two roles have different key ids.
    let source = SafetySourceKey::from_secret_bytes(&[9; 32]);
    let ingest = SafetyIngestKey::from_secret_bytes(&[9; 32]);
    let namespace = SafetyNamespaceKey::from_secret_bytes(&[9; 32]);
    let attester = EvidenceAttesterKey::from_secret_bytes(&[9; 32]);
    let ids = [
        source.key_id(),
        ingest.key_id(),
        namespace.key_id(),
        attester.key_id(),
    ];
    let unique: HashSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len());
    // An event signature does not verify as a record signature over the
    // same bytes, and the other way round.
    let event = event_by(&source, "executor-1", 1, "safety:halt");
    let payload = event.signing_payload().unwrap();
    let signature = hex::decode(event.signature()).unwrap();
    let pin = source.public_key().unwrap();
    pin.verify_domain_message(SAFETY_EVENT_DOMAIN, &payload, &signature)
        .unwrap();
    for other in [
        SAFETY_RECORD_DOMAIN,
        b"PRAETORE_SAFETY_NAMESPACE_V1\0",
        b"PRAETORE_EVIDENCE_V2\0",
    ] {
        assert!(
            pin.verify_domain_message(other, &payload, &signature)
                .is_err()
        );
    }
    let record_signature = sign_with(&ingest.signing_key, SAFETY_RECORD_DOMAIN, &payload);
    let ingest_pin = ingest.public_key().unwrap();
    assert!(
        ingest_pin
            .verify_domain_message(SAFETY_EVENT_DOMAIN, &payload, &record_signature)
            .is_err()
    );
}

#[test]
fn escape_bytes_is_printable_ascii_and_unambiguous() {
    assert_eq!(escape_bytes(b"safety:halt"), "safety:halt");
    assert_eq!(escape_bytes(b"a\\b"), "a\\\\b");
    assert_eq!(escape_bytes(b"\x00\n\xff"), "\\x00\\x0a\\xff");
    assert_eq!(
        escape_bytes("safety:h\u{200b}alt".as_bytes()),
        "safety:h\\xe2\\x80\\x8balt"
    );
    let raw = RawInput::of(&[b'x'; MAX_RAW_PREFIX_BYTES + 10]);
    assert!(raw.truncated);
    assert_eq!(raw.len as usize, MAX_RAW_PREFIX_BYTES + 10);
    assert_eq!(raw.escaped.len(), MAX_RAW_PREFIX_BYTES);
}

// ---------------------------------------------------------------------------
// Ingestion: statuses.

#[test]
fn declared_undeclared_and_invalid_names_are_recorded_with_their_class() {
    let mut harness = Harness::new();
    assert_eq!(
        harness.statuses(&wire(&event(1, "safety:halt"))),
        [SafetyRecordStatus::Accepted]
    );
    assert_eq!(
        harness.statuses(&wire(&event(2, "safety:freeze"))),
        [SafetyRecordStatus::Undeclared]
    );
    let long = format!("safety:{}", "a".repeat(200));
    let cases = [
        ("safety:", "invalid_name_start"),
        ("safety:_x", "invalid_name_start"),
        (long.as_str(), "too_long"),
        ("safety:h\u{e4}lt", "not_printable_ascii"),
        ("safety:halt\u{200b}", "not_printable_ascii"),
        ("SAFETY:halt", "missing_prefix"),
        ("fs:write_file", "missing_prefix"),
        ("", "empty"),
    ];
    for (offset, (action, code)) in cases.iter().enumerate() {
        let records = harness.ingest(&wire(&event(3 + offset as u64, action)));
        assert_eq!(records.len(), 1);
        let payload = records[0].payload();
        assert_eq!(
            payload.status,
            SafetyRecordStatus::InvalidName,
            "{action:?}"
        );
        assert_eq!(payload.name_class, Some(NameClass::InvalidName));
        assert_eq!(payload.reason.as_deref(), Some(*code), "{action:?}");
        // The raw name is kept exactly in the signed event, and the detail
        // is bounded printable ASCII.
        assert_eq!(payload.event.as_ref().unwrap().action(), *action);
        let detail = payload.detail.as_deref().unwrap();
        assert!(
            detail.bytes().all(|b| (b' '..=b'~').contains(&b)),
            "{detail}"
        );
        assert!(detail.len() <= 4 * MAX_DETAIL_INPUT_BYTES + 3);
    }
    let report = harness.verify("executor-1").unwrap();
    assert_eq!(report.counts.accepted, 1);
    assert_eq!(report.counts.undeclared, 1);
    assert_eq!(report.counts.invalid_name, cases.len() as u64);
    assert_eq!(report.high_water, 2 + cases.len() as u64);
}

#[test]
fn input_that_does_not_verify_is_recorded_as_rejected_never_dropped() {
    let mut harness = Harness::new();
    let good = event(1, "safety:halt");
    let mut forged: Value = serde_json::from_slice(&wire(&good)).unwrap();
    forged["signature"] = Value::from("00".repeat(64));
    let unknown = event_by(&source_key(), "executor-9", 1, "safety:halt");
    // Signed by executor-2's key but claiming executor-1.
    let wrong_key = event_by(&other_source_key(), "executor-1", 1, "safety:halt");
    let mut not_post_hoc: Value = serde_json::from_slice(&wire(&good)).unwrap();
    not_post_hoc["post_hoc"] = Value::Bool(false);
    let cases: Vec<(Vec<u8>, RejectReason)> = vec![
        (b"not json \x00\xff".to_vec(), RejectReason::Malformed),
        (
            vec![b'{'; MAX_SAFETY_EVENT_BYTES + 1],
            RejectReason::TooLarge,
        ),
        (
            serde_json::to_vec(&forged).unwrap(),
            RejectReason::SignatureInvalid,
        ),
        (wire(&unknown), RejectReason::UnknownSource),
        (wire(&wrong_key), RejectReason::KeyMismatch),
        (
            serde_json::to_vec(&not_post_hoc).unwrap(),
            RejectReason::NotPostHoc,
        ),
        (Vec::new(), RejectReason::Malformed),
    ];
    for (input, reason) in &cases {
        let records = harness.ingest(input);
        assert_eq!(records.len(), 1, "{reason:?}");
        let payload = records[0].payload();
        assert_eq!(payload.chain, UNATTRIBUTED_CHAIN);
        assert_eq!(payload.status, SafetyRecordStatus::Rejected);
        assert_eq!(payload.reason.as_deref(), Some(reason.as_str()));
        let raw = payload.raw.as_ref().unwrap();
        assert_eq!(raw.len as usize, input.len());
        assert_eq!(raw.sha256, hex::encode(Sha256::digest(input)));
        assert!(raw.escaped.bytes().all(|b| (b' '..=b'~').contains(&b)));
        assert!(raw.escaped.len() <= 4 * MAX_RAW_PREFIX_BYTES);
        assert!(payload.event.is_none());
    }
    // Nothing reached the source chain: its next event is still seq 1.
    assert_eq!(harness.ingestor.head("executor-1"), ChainHead::default());
    assert_eq!(
        harness.statuses(&wire(&good)),
        [SafetyRecordStatus::Accepted]
    );
    let report = verify_safety_chain(
        harness.chain(UNATTRIBUTED_CHAIN),
        &[ingest_pin()],
        None,
        None,
    )
    .unwrap();
    assert_eq!(report.counts.rejected, cases.len() as u64);
    assert_eq!(report.entries, cases.len() as u64);
}

#[test]
fn a_source_seq_gap_is_recorded_as_a_signed_loss_record() {
    let mut harness = Harness::new();
    harness.ingest(&wire(&event(1, "safety:halt")));
    let records = harness.ingest(&wire(&event(5, "safety:halt")));
    assert_eq!(records.len(), 2);
    let loss = records[0].payload();
    assert_eq!(loss.status, SafetyRecordStatus::Loss);
    assert_eq!(loss.reason.as_deref(), Some("source_seq_gap"));
    assert_eq!((loss.lost_from, loss.lost_to), (Some(2), Some(4)));
    records[0].verify(&[ingest_pin()]).unwrap();
    assert_eq!(records[1].payload().status, SafetyRecordStatus::Accepted);
    assert_eq!(
        records[1].payload().prev_record_hash,
        records[0].record_hash()
    );
    // A first event above 1 is a gap from 1.
    let first = harness.ingest(&wire(&event_by(
        &other_source_key(),
        "executor-2",
        3,
        "safety:halt",
    )));
    assert_eq!(
        (first[0].payload().lost_from, first[0].payload().lost_to),
        (Some(1), Some(2))
    );
    let report = harness.verify("executor-1").unwrap();
    assert_eq!(report.counts.loss, 1);
    assert_eq!(report.counts.lost_events, 3);
    assert_eq!(report.high_water, 5);
}

#[test]
fn a_resent_event_is_a_duplicate_and_another_event_with_its_seq_a_conflict() {
    let mut harness = Harness::new();
    let first = harness.ingest(&wire(&event(1, "safety:halt")));
    harness.ingest(&wire(&event(2, "safety:halt")));
    // The same event again, in another encoding: duplicate.
    let pretty = serde_json::to_vec_pretty(
        &serde_json::from_slice::<Value>(&wire(&event(1, "safety:halt"))).unwrap(),
    )
    .unwrap();
    let duplicate = harness.ingest(&pretty);
    assert_eq!(duplicate[0].payload().status, SafetyRecordStatus::Duplicate);
    assert_eq!(
        duplicate[0].payload().original_record_hash.as_deref(),
        Some(first[0].record_hash())
    );
    // Another validly signed event with source_seq 1: conflict.
    let conflict = harness.ingest(&wire(&event(1, "safety:stop_all")));
    assert_eq!(conflict[0].payload().status, SafetyRecordStatus::Conflict);
    assert_eq!(
        conflict[0].payload().original_record_hash.as_deref(),
        Some(first[0].record_hash())
    );
    // Neither moves the high-water mark.
    assert_eq!(harness.ingestor.head("executor-1").high_water, 2);
    assert_eq!(
        harness.statuses(&wire(&event(3, "safety:halt"))),
        [SafetyRecordStatus::Accepted]
    );
    let report = harness.verify("executor-1").unwrap();
    assert_eq!((report.counts.duplicate, report.counts.conflict), (1, 1));
}

#[test]
fn an_event_for_a_lost_seq_is_late_and_only_once() {
    let mut harness = Harness::new();
    harness.ingest(&wire(&event(1, "safety:halt")));
    harness.ingest(&wire(&event(4, "safety:halt")));
    assert_eq!(
        harness.statuses(&wire(&event(2, "safety:halt"))),
        [SafetyRecordStatus::Late]
    );
    assert_eq!(
        harness.statuses(&wire(&event(2, "safety:halt"))),
        [SafetyRecordStatus::Duplicate]
    );
    let report = harness.verify("executor-1").unwrap();
    assert_eq!(report.counts.late, 1);
    assert_eq!(report.counts.duplicate, 1);
}

#[test]
fn messages_dropped_inside_the_ingester_are_a_signed_unattributed_loss() {
    let mut harness = Harness::new();
    for (reason, count) in [
        (LossReason::QueueOverflow, 7),
        (LossReason::StorageError, 2),
    ] {
        let prepared = harness
            .ingestor
            .prepare_dropped(reason, count, now())
            .unwrap();
        let records = harness.store(prepared);
        assert_eq!(records[0].payload().dropped, Some(count));
        assert_eq!(
            records[0].payload().reason.as_deref(),
            Some(reason.as_str())
        );
    }
    assert!(
        harness
            .ingestor
            .prepare_dropped(LossReason::SourceSeqGap, 1, now())
            .is_err()
    );
    let report = verify_safety_chain(
        harness.chain(UNATTRIBUTED_CHAIN),
        &[ingest_pin()],
        None,
        None,
    )
    .unwrap();
    assert_eq!(report.counts.dropped_messages, 9);
    assert_eq!(report.counts.loss, 2);
}

// ---------------------------------------------------------------------------
// Setup: the manifest and distinct keys, without a flag.

#[test]
fn the_ingestor_refuses_a_manifest_that_does_not_verify() {
    let mut bad = config();
    bad.namespace_pin = SafetyNamespaceKey::from_secret_bytes(&[8; 32])
        .public_key()
        .unwrap();
    assert!(matches!(
        SafetyIngestor::new(bad),
        Err(IngestSetupError::Manifest(
            SafetyNamespaceError::KeyIdMismatch
        ))
    ));
}

#[test]
fn the_ingestor_refuses_any_two_roles_with_the_same_key() {
    let same = |edit: fn(&mut IngestorConfig)| {
        let mut config = config();
        edit(&mut config);
        match SafetyIngestor::new(config) {
            Err(IngestSetupError::SameKey { error, .. }) => {
                assert_eq!(error, SafetyNamespaceError::SameKeyForBothRoles)
            }
            other => panic!("expected SameKey, got {other:?}"),
        }
    };
    // ingestion == attester
    same(|c| c.attester_pin = ingest_pin());
    // ingestion == a source
    same(|c| c.ingest_key = SafetyIngestKey::from_secret_bytes(&[4; 32]));
    // attester == a source
    same(|c| c.attester_pin = source_key().public_key().unwrap());
    // namespace == attester (the manifest still verifies)
    same(|c| c.attester_pin = namespace_key().public_key().unwrap());
    // namespace == ingestion
    same(|c| c.ingest_key = SafetyIngestKey::from_secret_bytes(&[1; 32]));
    // namespace == a source
    same(|c| {
        let mut pins = SourcePins::default();
        pins.insert("executor-1", namespace_key().public_key().unwrap())
            .unwrap();
        c.sources = pins;
    });
    // Two sources cannot share a key either (refused when pinning).
    let mut pins = SourcePins::default();
    pins.insert("a", source_key().public_key().unwrap())
        .unwrap();
    assert!(
        pins.insert("b", source_key().public_key().unwrap())
            .is_err()
    );
    assert!(
        pins.insert("a", other_source_key().public_key().unwrap())
            .is_err()
    );
}

#[test]
fn source_pins_parse_strictly() {
    let key = hex::encode(source_key().public_key().unwrap().as_bytes());
    let pins = SourcePins::from_jsonl(&format!(
        "{{\"source_id\":\"executor-1\",\"public_key\":\"{key}\"}}\n"
    ))
    .unwrap();
    assert_eq!(pins.len(), 1);
    for bad in [
        String::new(),
        format!("{{\"source_id\":\"Executor\",\"public_key\":\"{key}\"}}"),
        format!("{{\"source_id\":\"_unattributed\",\"public_key\":\"{key}\"}}"),
        format!(
            "{{\"source_id\":\"e\",\"public_key\":\"{}\"}}",
            key.to_uppercase()
        ),
        format!("{{\"source_id\":\"e\",\"public_key\":\"{key}\",\"x\":1}}"),
        format!("{{\"source_id\":\"e\",\"source_id\":\"f\",\"public_key\":\"{key}\"}}"),
        format!("{{\"source_id\":\"e\",\"public_key\":\"{key}\"}}\n\n"),
    ] {
        assert!(SourcePins::from_jsonl(&bad).is_err(), "{bad}");
    }
}

// ---------------------------------------------------------------------------
// Canonical encoding of records.

#[test]
fn records_have_one_valid_encoding_and_reject_unknown_fields() {
    let mut harness = Harness::new();
    let record = harness.ingest(&wire(&event(1, "safety:halt"))).remove(0);
    let json = record.to_json().unwrap();
    assert_eq!(SafetyRecord::from_json(&json).unwrap(), record);
    let value: Value = serde_json::from_str(&json).unwrap();
    let pretty = serde_json::to_string_pretty(&value).unwrap();
    assert_eq!(
        SafetyRecord::from_json(&pretty).unwrap_err(),
        SafetyRecordError::NotCanonical
    );
    let extra = json.replacen('{', "{\"aaa\":1,", 1);
    assert!(SafetyRecord::from_json(&extra).is_err());
    // Status and fields must agree.
    let mut wrong = value.clone();
    wrong["status"] = Value::from("undeclared");
    assert!(
        SafetyRecord::from_json(
            &crate::canonical::canonicalize_json(&wrong.to_string())
                .map(|b| String::from_utf8(b).unwrap())
                .unwrap()
        )
        .is_err()
    );
    let mut rejected_on_source = value;
    rejected_on_source["status"] = Value::from("rejected");
    assert!(SafetyRecord::from_json(&rejected_on_source.to_string()).is_err());
}

#[test]
fn a_record_does_not_verify_after_any_change_or_under_another_key() {
    let mut harness = Harness::new();
    let record = harness.ingest(&wire(&event(1, "safety:halt"))).remove(0);
    record.verify(&[ingest_pin()]).unwrap();
    assert!(matches!(
        record.verify(&[SafetyIngestKey::from_secret_bytes(&[7; 32])
            .public_key()
            .unwrap()]),
        Err(SafetyRecordError::UnpinnedKey(_))
    ));
    let mut altered = record.clone();
    altered.payload.recorded_at = "2026-01-01T00:00:00Z".into();
    assert_eq!(
        altered.verify(&[ingest_pin()]),
        Err(SafetyRecordError::HashMismatch)
    );
    let mut resigned_hash = altered.clone();
    resigned_hash.record_hash = resigned_hash.recomputed_hash().unwrap();
    assert_eq!(
        resigned_hash.verify(&[ingest_pin()]),
        Err(SafetyRecordError::SignatureInvalid)
    );
}

// ---------------------------------------------------------------------------
// Chain verification and tampering.

fn lines(text: &str) -> Vec<String> {
    text.lines().map(|line| format!("{line}\n")).collect()
}

fn sample_chain() -> String {
    let mut harness = Harness::new();
    for seq in [1, 2, 5, 6] {
        harness.ingest(&wire(&event(seq, "safety:halt")));
    }
    harness.ingest(&wire(&event(6, "safety:halt")));
    harness.chain("executor-1").to_owned()
}

#[test]
fn an_exported_chain_verifies_with_its_head_and_counts() {
    let text = sample_chain();
    let report = verify_safety_chain(&text, &[ingest_pin()], Some(&pins()), None).unwrap();
    assert_eq!(report.chain, "executor-1");
    assert_eq!(report.tenant_id, TENANT);
    assert_eq!(report.entries, 6);
    assert_eq!(report.counts.accepted, 4);
    assert_eq!(report.counts.loss, 1);
    assert_eq!(report.counts.lost_events, 2);
    assert_eq!(report.counts.duplicate, 1);
    assert!(report.source_signatures_verified);
    assert_eq!(report.signed_by[&ingest_key().key_id()], 6);
    verify_safety_chain(&text, &[ingest_pin()], None, Some(&report.head)).unwrap();
    assert!(matches!(
        verify_safety_chain(&text, &[ingest_pin()], None, Some(&"0".repeat(64))),
        Err(SafetyChainError::HeadMismatch { .. })
    ));
}

#[test]
fn an_edited_removed_or_reordered_record_fails_verification() {
    let text = sample_chain();
    let original = lines(&text);
    let verify =
        |lines: &[String]| verify_safety_chain(&lines.concat(), &[ingest_pin()], None, None);
    // Edited: one byte of the occurred_at of record 1.
    let mut edited = original.clone();
    edited[1] = edited[1].replacen("\"occurred_at\":\"2026", "\"occurred_at\":\"2027", 1);
    assert_ne!(edited[1], original[1]);
    assert!(verify(&edited).is_err());
    // Removed: every single record (the head is truncation's only defense).
    for index in 0..original.len() - 1 {
        let mut removed = original.clone();
        removed.remove(index);
        let error = verify(&removed).unwrap_err();
        assert_eq!(
            error.code(),
            "SAFETY_CHAIN_FAIL",
            "removed {index}: {error}"
        );
    }
    let head = verify(&original).unwrap().head;
    let mut truncated = original.clone();
    truncated.pop();
    assert!(verify(&truncated).is_ok());
    assert!(matches!(
        verify_safety_chain(&truncated.concat(), &[ingest_pin()], None, Some(&head)),
        Err(SafetyChainError::HeadMismatch { .. })
    ));
    // Reordered: any two adjacent records swapped.
    for index in 0..original.len() - 1 {
        let mut reordered = original.clone();
        reordered.swap(index, index + 1);
        assert!(verify(&reordered).is_err(), "swapped {index}");
    }
    // An event signature replaced is caught with source pins.
    let mut value: Value = serde_json::from_str(original[0].trim_end()).unwrap();
    value["event"]["signature"] = Value::from("11".repeat(64));
    assert!(verify(&[format!("{value}\n")]).is_err());
}

/// A chain rebuilt with the ingestion key but without the loss record
/// (the gap check is in the verifier, not only in the ingester).
#[test]
fn a_gap_without_a_loss_record_fails_even_when_signed() {
    let ingestor = SafetyIngestor::new(config()).unwrap();
    let mut lookup = MemoryLookup::default();
    let first = ingestor
        .prepare(&wire(&event(1, "safety:halt")), now(), &mut lookup)
        .unwrap();
    let mut prepared = first.clone();
    // Sign seq 3 directly after seq 1 with no loss record.
    let next = ingestor
        .prepare(&wire(&event(3, "safety:halt")), now(), &mut lookup)
        .unwrap();
    let mut event_payload = next.records[1].payload().clone();
    event_payload.chain_seq = 1;
    event_payload.prev_record_hash = first.records[0].record_hash().to_owned();
    let forged = ingest_key().sign_record(event_payload).unwrap();
    prepared.records.push(forged);
    let text: String = prepared
        .records
        .iter()
        .map(|record| record.to_json().unwrap() + "\n")
        .collect();
    assert_eq!(
        verify_safety_chain(&text, &[ingest_pin()], None, None),
        Err(SafetyChainError::SequenceGap {
            line: 1,
            expected: 2,
            found: 3
        })
    );
}

#[test]
fn a_loss_record_must_be_followed_by_its_event() {
    let mut harness = Harness::new();
    harness.ingest(&wire(&event(1, "safety:halt")));
    harness.ingest(&wire(&event(4, "safety:halt")));
    let mut chain = lines(harness.chain("executor-1"));
    // Drop the event after the loss record: the chain ends on a loss.
    chain.pop();
    assert!(matches!(
        verify_safety_chain(&chain.concat(), &[ingest_pin()], None, None),
        Err(SafetyChainError::SequenceInconsistent { .. })
    ));
}

#[test]
fn a_duplicate_that_names_the_wrong_original_fails() {
    let mut harness = Harness::new();
    harness.ingest(&wire(&event(1, "safety:halt")));
    let second = harness.ingest(&wire(&event(2, "safety:halt")));
    let duplicate = harness.ingest(&wire(&event(1, "safety:halt")));
    let mut payload = duplicate[0].payload().clone();
    payload.original_record_hash = Some(second[0].record_hash().to_owned());
    let forged = ingest_key().sign_record(payload).unwrap();
    let mut chain = lines(harness.chain("executor-1"));
    chain[2] = forged.to_json().unwrap() + "\n";
    assert!(matches!(
        verify_safety_chain(&chain.concat(), &[ingest_pin()], None, None),
        Err(SafetyChainError::SequenceInconsistent { .. })
    ));
}

#[test]
fn chains_do_not_mix_and_source_pins_are_enforced() {
    let mut harness = Harness::new();
    harness.ingest(&wire(&event(1, "safety:halt")));
    harness.ingest(b"garbage");
    let mixed = format!(
        "{}{}",
        harness.chain("executor-1"),
        harness.chain(UNATTRIBUTED_CHAIN)
    );
    assert_eq!(
        verify_safety_chain(&mixed, &[ingest_pin()], None, None)
            .unwrap_err()
            .code(),
        "SAFETY_CHAIN_FAIL"
    );
    let mut only_other = SourcePins::default();
    only_other
        .insert("executor-2", other_source_key().public_key().unwrap())
        .unwrap();
    assert!(matches!(
        verify_safety_chain(
            harness.chain("executor-1"),
            &[ingest_pin()],
            Some(&only_other),
            None
        ),
        Err(SafetyChainError::UnpinnedSource { .. })
    ));
    assert_eq!(
        verify_safety_chain("", &[ingest_pin()], None, None),
        Err(SafetyChainError::Empty)
    );
    let without_newline = harness.chain("executor-1").trim_end();
    assert!(verify_safety_chain(without_newline, &[ingest_pin()], None, None).is_err());
}

#[test]
fn a_source_seq_too_far_ahead_is_rejected_and_does_not_move_the_high_water() {
    let mut harness = Harness::new();
    assert_eq!(
        harness.statuses(&wire(&event(1, "safety:halt"))),
        [SafetyRecordStatus::Accepted]
    );
    // One signed event at the end of the range (2^53 - 1).
    let records = harness.ingest(&wire(&event(MAX_SAFE_INTEGER, "safety:halt")));
    assert_eq!(records.len(), 1);
    let rejected = records[0].payload();
    assert_eq!(rejected.status, SafetyRecordStatus::Rejected);
    assert_eq!(rejected.chain, UNATTRIBUTED_CHAIN);
    assert_eq!(rejected.reason.as_deref(), Some("seq_jump_too_large"));
    assert!(
        rejected
            .detail
            .as_deref()
            .unwrap()
            .contains("high-water mark 1")
    );
    assert_eq!(harness.ingestor.head("executor-1").high_water, 1);
    // The chain keeps working: the next event is accepted, with no loss.
    assert_eq!(
        harness.statuses(&wire(&event(2, "safety:halt"))),
        [SafetyRecordStatus::Accepted]
    );
    let source = harness.verify("executor-1").unwrap();
    assert_eq!(source.high_water, 2);
    assert_eq!(source.counts.accepted, 2);
    assert_eq!(source.counts.loss, 0);
    let unattributed = harness.verify(UNATTRIBUTED_CHAIN).unwrap();
    assert_eq!(unattributed.counts.rejected, 1);
    assert_eq!(
        unattributed.counts.rejected_by_reason,
        BTreeMap::from([("seq_jump_too_large".to_owned(), 1)])
    );
}

#[test]
fn a_jump_up_to_the_maximum_is_a_loss_and_one_more_is_rejected() {
    let mut harness = Harness::new();
    harness.ingestor = SafetyIngestor::new(IngestorConfig {
        max_seq_jump: 10,
        ..config()
    })
    .unwrap();
    // From high-water 0, source_seq 10 is a step of 10: allowed.
    assert_eq!(
        harness.statuses(&wire(&event(10, "safety:halt"))),
        [SafetyRecordStatus::Loss, SafetyRecordStatus::Accepted]
    );
    // From 10, 21 is a step of 11: refused.
    assert_eq!(
        harness.statuses(&wire(&event(21, "safety:halt"))),
        [SafetyRecordStatus::Rejected]
    );
    assert_eq!(harness.ingestor.head("executor-1").high_water, 10);
    assert_eq!(
        harness.statuses(&wire(&event(20, "safety:halt"))),
        [SafetyRecordStatus::Loss, SafetyRecordStatus::Accepted]
    );
    harness.verify("executor-1").unwrap();
    harness.verify(UNATTRIBUTED_CHAIN).unwrap();
    for jump in [0, MAX_SAFE_INTEGER + 1] {
        assert_eq!(
            SafetyIngestor::new(IngestorConfig {
                max_seq_jump: jump,
                ..config()
            })
            .unwrap_err(),
            IngestSetupError::InvalidMaxSeqJump
        );
    }
}

fn event_at(seq: u64, occurred_at: OffsetDateTime) -> SafetyEvent {
    source_key()
        .sign_event(SafetyEventDraft {
            source_id: "executor-1".into(),
            source_seq: seq,
            action: "safety:halt".into(),
            occurred_at,
            params: BTreeMap::new(),
        })
        .unwrap()
}

#[test]
fn an_event_far_from_the_ingester_clock_is_marked_with_its_skew() {
    let mut harness = Harness::new();
    // Within the default 300 s: no mark.
    let near = harness.ingest(&wire(&event_at(1, now() - time::Duration::seconds(299))));
    assert_eq!(near[0].payload().clock_skew_seconds, None);
    // An hour in the future and in 1970: marked, status unchanged.
    let future = harness.ingest(&wire(&event_at(2, now() + time::Duration::hours(1))));
    assert_eq!(future[0].payload().status, SafetyRecordStatus::Accepted);
    assert_eq!(future[0].payload().clock_skew_seconds, Some(3600));
    let epoch = harness.ingest(&wire(&event_at(3, OffsetDateTime::UNIX_EPOCH)));
    assert_eq!(
        epoch[0].payload().clock_skew_seconds,
        Some(-now().unix_timestamp())
    );
    let report = harness.verify("executor-1").unwrap();
    assert_eq!(report.counts.clock_skew, 2);
    assert_eq!(report.counts.accepted, 3);
    // The mark is signed: removing it breaks the record.
    let mut payload = future[0].payload().clone();
    payload.clock_skew_seconds = None;
    assert_ne!(
        ingest_key().sign_record(payload).unwrap().record_hash(),
        future[0].record_hash()
    );
}
