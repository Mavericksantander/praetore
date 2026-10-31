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
    let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
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
