#![no_main]

use libfuzzer_sys::fuzz_target;
use praetore_core::safety_ingest::{
    MAX_SAFETY_EVENT_BYTES, SafetyEvent, SafetyIngestKey, SafetyRecord, SafetySourceKey,
    escape_bytes, verify_safety_chain,
};

fuzz_target!(|input: &[u8]| {
    // G1: an event parse never panics, an accepted event is in bounds,
    // re-encodes to an event with the same hash, and its verification
    // against an unrelated pin never succeeds by accident.
    if let Ok(event) = SafetyEvent::parse(input) {
        assert!(input.len() <= MAX_SAFETY_EVENT_BYTES);
        let wire = event.to_wire().expect("a parsed event encodes");
        let again = SafetyEvent::parse(&wire).expect("its canonical encoding parses");
        assert_eq!(again, event);
        assert_eq!(again.event_hash(), event.event_hash());
        let pin = SafetySourceKey::from_secret_bytes(&[1; 32])
            .public_key()
            .expect("fixed key");
        assert!(event.verify(&pin).is_err(), "a fuzzed signature verified");
    }
    // The escaped raw copy of any input is printable ASCII.
    assert!(
        escape_bytes(input)
            .bytes()
            .all(|b| (b' '..=b'~').contains(&b))
    );

    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    // Only the canonical encoding of a record parses, and verification and
    // chain verification never panic.
    if let Ok(record) = SafetyRecord::from_json(text) {
        assert_eq!(record.to_json().expect("a parsed record encodes"), text);
        let pin = SafetyIngestKey::from_secret_bytes(&[2; 32])
            .public_key()
            .expect("fixed key");
        let _ = record.verify(std::slice::from_ref(&pin));
    }
    let pin = SafetyIngestKey::from_secret_bytes(&[2; 32])
        .public_key()
        .expect("fixed key");
    let _ = verify_safety_chain(text, std::slice::from_ref(&pin), None, None);
});
