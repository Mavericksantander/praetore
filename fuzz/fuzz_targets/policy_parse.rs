#![no_main]

use libfuzzer_sys::fuzz_target;
use praetore_core::policy::{Policy, RecordedPolicy};

fuzz_target!(|input: &[u8]| {
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    if let Ok(policy) = Policy::from_json(text) {
        // A policy that loads for evaluation has a digest, and its record
        // (the historical path) agrees with it.
        let digest = policy.digest().expect("a loaded policy has a digest");
        let recorded = RecordedPolicy::from_json(text).expect("format 2 records");
        assert_eq!(recorded.digest(), digest);
    }
    // Format 1 documents are only digested (G7).
    if let Ok(recorded) = RecordedPolicy::from_json(text) {
        let _ = recorded.propose_action_classes();
    }
});
