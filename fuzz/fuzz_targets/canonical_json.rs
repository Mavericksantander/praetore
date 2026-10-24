#![no_main]

use libfuzzer_sys::fuzz_target;
use praetore_core::canonical::canonicalize_json;

fuzz_target!(|input: &[u8]| {
    if let Ok(text) = std::str::from_utf8(input) {
        let _ = canonicalize_json(text);
    }
});
