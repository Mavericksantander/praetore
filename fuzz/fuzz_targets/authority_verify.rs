#![no_main]

use libfuzzer_sys::fuzz_target;
use praetore_core::{authority::Authority, engine::TrustedAuthorityIssuer};
use time::OffsetDateTime;

fuzz_target!(|input: &[u8]| {
    let Some(separator) = input.iter().position(|byte| *byte == 0) else {
        return;
    };
    let Ok(authority_text) = std::str::from_utf8(&input[..separator]) else {
        return;
    };
    let Ok(pin_text) = std::str::from_utf8(&input[separator + 1..]) else {
        return;
    };
    let Ok(authority) = Authority::from_json(authority_text) else {
        return;
    };
    let Ok(pin) = TrustedAuthorityIssuer::from_pin_json(pin_text) else {
        return;
    };
    let _ = pin.verify_authority_at(&authority, OffsetDateTime::UNIX_EPOCH);
});
