#![no_main]

use libfuzzer_sys::fuzz_target;
use praetore_core::{
    NamespaceMembership, SafetyActionName, SafetyNamespaceKey, SafetyNamespaceManifest,
    safety_namespace::{MAX_SAFETY_ACTION_NAME_BYTES, SAFETY_ACTION_PREFIX},
};

fuzz_target!(|input: &[u8]| {
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };

    // G2: an accepted name has every documented property.
    if let Ok(name) = SafetyActionName::parse(text) {
        assert_eq!(name.as_str(), text);
        assert!(text.len() <= MAX_SAFETY_ACTION_NAME_BYTES);
        assert!(text.bytes().all(|byte| byte.is_ascii_graphic()));
        assert!(text.starts_with(SAFETY_ACTION_PREFIX));
        assert!(name.name_after_prefix().as_bytes()[0].is_ascii_alphanumeric());
    }

    // A parsed manifest re-encodes to a document that parses to the same
    // manifest, and verification never panics.
    if let Ok(manifest) = SafetyNamespaceManifest::from_json(text) {
        let encoded = manifest.to_json().expect("a parsed manifest encodes");
        assert_eq!(
            SafetyNamespaceManifest::from_json(&encoded).expect("re-encoded manifest parses"),
            manifest
        );
        let pin = SafetyNamespaceKey::from_secret_bytes(&[1; 32])
            .public_key()
            .expect("fixed key");
        let _ = manifest.verify(&pin);
        for name in manifest.safety_actions() {
            assert_eq!(manifest.classify_name(name), NamespaceMembership::Declared);
        }
    }
});
