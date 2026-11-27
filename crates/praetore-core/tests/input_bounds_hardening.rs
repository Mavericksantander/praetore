//! Three input-bound defects found by the 2026-11-26 audit, each pinned
//! here: a range anchor whose `seq` sits next to `u64::MAX` overflowed the
//! chain counter (panic with overflow checks, a wrapped count without
//! them); a delegation document between 64 KiB and its documented 1 MiB
//! was refused as invalid; and unknown fields inside a `Recover` effect
//! were accepted, so two different policy files shared one digest.

use praetore_core::{
    AgentKeyPair, Policy, PolicyEffect, PolicyRule, VerifiedPublicKey,
    approval_delegation::{DelegationConfig, MAX_DELEGATION_DOCUMENT_BYTES},
    canonical::MAX_JSON_VALUE_BYTES,
    journal_chain::{
        ChainError, ChainLink, MAX_CHAIN_ENTRIES, receipt_link, verify_journal_range,
        verify_journal_receipts,
    },
};
use serde_json::json;
use uuid::Uuid;

const SET_03_CHAIN: &str = include_str!(
    "../../../examples/claude-code-hook/evidence/03-bundle-demo-reproducible/journal-chain.jsonl"
);
const SET_03_PIN: &str = include_str!(
    "../../../examples/claude-code-hook/evidence/03-bundle-demo-reproducible/attester-public-key.hex"
);
const GOLDEN_POLICY: &str = include_str!("../../../docs/golden/canonical-policy-v2.json");

fn set_03_pin() -> VerifiedPublicKey {
    VerifiedPublicKey::from_bytes(&hex::decode(SET_03_PIN.trim()).unwrap()).unwrap()
}

/// A range whose anchor claims `seq` `anchor_seq`: the anchor is receipt 0
/// of set 03 and the range holds receipts 1 and 2, linked from it.
fn range_anchored_at(anchor_seq: u64) -> String {
    let pins = [set_03_pin()];
    let (_, receipts) = verify_journal_receipts(SET_03_CHAIN, &pins, None).unwrap();
    let mut text = String::new();
    let mut prev = ChainLink::GENESIS;
    let mut seq = anchor_seq;
    for evidence in &receipts[..3] {
        text.push_str(&format!(
            "{{\"seq\":{seq},\"prev\":\"{prev}\",\"evidence\":{}}}\n",
            evidence.to_json().unwrap()
        ));
        prev = receipt_link(seq, &prev, evidence).unwrap();
        seq = seq.wrapping_add(1);
    }
    text
}

#[test]
fn a_range_anchor_next_to_u64_max_is_malformed_not_a_panic() {
    let pins = [set_03_pin()];
    for anchor_seq in [u64::MAX - 1, u64::MAX - MAX_CHAIN_ENTRIES as u64] {
        let text = range_anchored_at(anchor_seq);
        let error = verify_journal_range(&text, &pins, None, None, None).unwrap_err();
        assert!(
            matches!(error, ChainError::Malformed { line } if line == anchor_seq),
            "anchor {anchor_seq}: {error}"
        );
    }
    // The last anchor that leaves room for a full range still verifies, and
    // its counters are the real ones, not a wrapped value.
    let anchor_seq = u64::MAX - MAX_CHAIN_ENTRIES as u64 - 1;
    let report =
        verify_journal_range(&range_anchored_at(anchor_seq), &pins, None, None, None).unwrap();
    assert_eq!(
        report.summary.head.entries.get(),
        anchor_seq + 3,
        "{report:?}"
    );
    assert_eq!(report.signed_by.values().sum::<u64>(), 2, "{report:?}");
    assert_eq!(report.range.unwrap().start, anchor_seq + 1);
}

#[test]
fn a_delegation_document_up_to_its_documented_size_loads() {
    let roots: Vec<_> = (0..600u32)
        .map(|index| {
            let seed = index.to_le_bytes();
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&seed);
            bytes[4] = 1;
            json!({
                "tenant_id": Uuid::from_u128(u128::from(index) + 1),
                "key_id": format!("root-{index}"),
                "public_key_hex": hex::encode(AgentKeyPair::from_secret_bytes(&bytes).public_key().as_bytes()),
            })
        })
        .collect();
    let document = json!({"schema_version": 1, "roots": roots}).to_string();
    assert!(
        document.len() > MAX_JSON_VALUE_BYTES && document.len() < MAX_DELEGATION_DOCUMENT_BYTES,
        "{} bytes: the document must sit between the single-value cap and the documented limit",
        document.len()
    );
    DelegationConfig::from_json(&document).unwrap();
    // The documented byte cap still holds.
    let padded = format!("{}{}", document, " ".repeat(MAX_DELEGATION_DOCUMENT_BYTES));
    assert!(DelegationConfig::from_json(&padded).is_err());
}

#[test]
fn an_unknown_field_inside_a_recover_effect_is_refused() {
    let clean = Policy::from_json(GOLDEN_POLICY).unwrap();
    let mut document: serde_json::Value = serde_json::from_str(GOLDEN_POLICY).unwrap();
    let rule = PolicyRule::new(
        "recover-rule",
        clean.rules[0].action_type.clone(),
        PolicyEffect::Recover {
            recovery_id: "safe".into(),
            deadline_ms: 10,
        },
    );
    let mut rule_value = serde_json::to_value(&rule).unwrap();
    document["rules"]
        .as_array_mut()
        .unwrap()
        .push(rule_value.clone());
    let with_recover = Policy::from_json(&document.to_string()).unwrap();
    rule_value["effect"]["Recover"]["deadline_ms_"] = json!(99);
    document["rules"].as_array_mut().unwrap().pop();
    document["rules"].as_array_mut().unwrap().push(rule_value);
    let error = Policy::from_json(&document.to_string()).unwrap_err();
    assert!(
        error.to_string().contains("deadline_ms_"),
        "the unknown field is named: {error}"
    );
    // A policy with a clean Recover rule has the digest it always had.
    assert_ne!(with_recover.digest().unwrap(), clean.digest().unwrap());
}
