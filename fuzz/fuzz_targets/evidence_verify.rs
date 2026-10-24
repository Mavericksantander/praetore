#![no_main]

use libfuzzer_sys::fuzz_target;
use praetore_core::{evidence::Evidence, identity::VerifiedPublicKey};

fuzz_target!(|input: &[u8]| {
    let Some(separator) = input.iter().position(|byte| *byte == 0) else {
        return;
    };
    let Ok(evidence_text) = std::str::from_utf8(&input[..separator]) else {
        return;
    };
    let Ok(key_bytes) = hex::decode(&input[separator + 1..]) else {
        return;
    };
    let Ok(key) = VerifiedPublicKey::from_bytes(&key_bytes) else {
        return;
    };
    if let Ok(evidence) = Evidence::from_json(evidence_text) {
        let _ = evidence.verify_attester_signature(&key);
        let _ = evidence.verify_agent_intent();
    }
});
