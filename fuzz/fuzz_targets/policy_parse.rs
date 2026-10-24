#![no_main]

use libfuzzer_sys::fuzz_target;
use praetore_core::policy::Policy;

fuzz_target!(|input: &[u8]| {
    if let Ok(text) = std::str::from_utf8(input)
        && let Ok(policy) = Policy::from_json(text)
    {
        let _ = policy.digest();
    }
});
