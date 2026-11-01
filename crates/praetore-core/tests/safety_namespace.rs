//! G2: the shared `safety:*` name validator and the signed safety namespace
//! manifest. Each test matches the exact error variant.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signer, SigningKey};
use praetore_core::{
    Action, ActionClass, ActionClassError, AgentId, AgentKeyPair, Authority, AuthorizationRequest,
    DecidedBy, Decision, EvidenceAttesterKey, ManifestField, NamespaceMembership, Policy,
    PolicyEffect, PolicyRule, PraetoreError, SafetyActionName, SafetyNameError,
    SafetyNamespaceError, SafetyNamespaceKey, SafetyNamespaceManifest, VerifiedPublicKey,
    canonical::JsonError,
    safety_namespace::{
        MAX_SAFETY_ACTION_NAME_BYTES, SAFETY_NAMESPACE_DOMAIN, SAFETY_NAMESPACE_KEY_ID_DOMAIN,
        safety_namespace_key_id,
    },
};
use serde_json::{Value, json};
use time::OffsetDateTime;

const NAMESPACE_SECRET: [u8; 32] = [0x47; 32];

/// 2026-11-01T00:00:00Z.
fn issued_at() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_793_491_200).unwrap()
}

fn key() -> SafetyNamespaceKey {
    SafetyNamespaceKey::from_secret_bytes(&NAMESPACE_SECRET)
}

fn pin() -> VerifiedPublicKey {
    key().public_key().unwrap()
}

fn policy() -> Policy {
    Policy::new_v2(
        "operations",
        3,
        vec![PolicyRule::new(
            "allow-writes",
            "fs:write_file",
            PolicyEffect::Allow,
        )],
    )
    .with_mission_actions(["fs:write_file"])
    .with_action_class("safety:stop_all", ActionClass::Safety)
    .with_action_class("safety:halt", ActionClass::Safety)
    .with_action_class("safety:hold", ActionClass::Safety)
}

fn manifest_of(policy: &Policy) -> SafetyNamespaceManifest {
    SafetyNamespaceManifest::from_policy(policy, issued_at(), &key()).unwrap()
}

fn manifest_json() -> String {
    manifest_of(&policy()).to_json().unwrap()
}

/// `json` with `edit` applied, re-serialized.
fn edited(json: &str, edit: impl FnOnce(&mut Value)) -> String {
    let mut value: Value = serde_json::from_str(json).unwrap();
    edit(&mut value);
    value.to_string()
}

fn parse_and_verify(json: &str) -> Result<SafetyNamespaceManifest, SafetyNamespaceError> {
    let manifest = SafetyNamespaceManifest::from_json(json)?;
    manifest.verify(&pin())?;
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// The shared validator.

fn name_cases() -> Vec<(String, Result<(), SafetyNameError>)> {
    let not_ascii = |name: &str| {
        Err(SafetyNameError::NotPrintableAscii {
            name: name.to_owned(),
        })
    };
    let missing = |name: &str| {
        Err(SafetyNameError::MissingPrefix {
            name: name.to_owned(),
        })
    };
    let bad_start = |name: &str| {
        Err(SafetyNameError::InvalidNameStart {
            name: name.to_owned(),
        })
    };
    let too_long = |bytes| {
        Err(SafetyNameError::TooLong {
            bytes,
            max: MAX_SAFETY_ACTION_NAME_BYTES,
        })
    };
    let longest = format!("safety:{}", "a".repeat(MAX_SAFETY_ACTION_NAME_BYTES - 7));
    let one_more = format!("safety:{}", "a".repeat(MAX_SAFETY_ACTION_NAME_BYTES - 6));
    // Multi-byte characters count in bytes: 61 x 2 bytes + 7 = 129.
    let long_non_ascii = format!("safety:{}", "\u{e9}".repeat(61));
    let short_non_ascii = format!("safety:{}", "\u{e9}".repeat(60));
    let long_zwsp = format!(
        "safety:{}\u{200b}",
        "a".repeat(MAX_SAFETY_ACTION_NAME_BYTES)
    );
    let mut cases: Vec<(String, Result<(), SafetyNameError>)> = vec![
        // Valid names.
        ("safety:halt".into(), Ok(())),
        ("safety:hold".into(), Ok(())),
        ("safety:pause".into(), Ok(())),
        ("safety:stop_all".into(), Ok(())),
        ("safety:0".into(), Ok(())),
        ("safety:H".into(), Ok(())),
        ("safety:halt:now/zone-1.a~b".into(), Ok(())),
        (longest.clone(), Ok(())),
        // Empty and over-length.
        (String::new(), Err(SafetyNameError::Empty)),
        (one_more.clone(), too_long(one_more.len())),
        (long_non_ascii.clone(), too_long(129)),
        (long_zwsp.clone(), too_long(long_zwsp.len())),
    ];
    for name in [
        "\u{455}afety:halt", // Cyrillic dze, a homoglyph of `s`
        "s\u{430}fety:halt", // Cyrillic a
        "safety:h\u{430}lt", // homoglyph after the prefix
        "safety:\u{3b7}alt", // Greek eta
        "\u{ff53}\u{ff41}\u{ff46}\u{ff45}\u{ff54}\u{ff59}:halt", // full-width letters
        "safety\u{ff1a}halt", // full-width colon
        "safety:\u{ff48}alt", // full-width letter in the name
        "safety:halt\u{200b}", // trailing zero-width space
        "saf\u{200b}ety:halt", // zero-width space inside the prefix
        "safety:\u{200b}",   // invisible name
        "safety:\u{200d}halt", // zero-width joiner
        "\u{feff}safety:halt", // leading byte order mark
        "safety:\u{feff}halt", // byte order mark after the prefix
        "safety:\u{202e}tlah", // bidi override
        "safety:halt\t",     // tab
        "safety:halt\n",     // newline
        "safety:\0halt",     // NUL
        "safety:halt\u{7f}", // DEL
        "safety:halt\u{1b}[0m", // escape sequence
        " safety:halt",      // leading space
        "safety: halt",      // inner space
        "safety:halt ",      // trailing space
        "safety:\u{a0}halt", // no-break space
        "safety:\u{3000}halt", // ideographic space
        "safety:caf\u{e9}",  // any other non-ASCII character
    ] {
        cases.push((name.into(), not_ascii(name)));
    }
    cases.push((short_non_ascii.clone(), not_ascii(&short_non_ascii)));
    for name in [
        "SAFETY:halt",
        "Safety:halt",
        "safety_halt",
        "safety-halt",
        "safety;halt",
        "safety.halt",
        "safety",
        "halt",
        ":safety:halt",
        "xsafety:halt",
        "safety/halt",
    ] {
        cases.push((name.into(), missing(name)));
    }
    for name in [
        "safety:",
        "safety::",
        "safety::x",
        "safety:_x",
        "safety:-x",
        "safety:.x",
        "safety:/x",
        "safety:~",
    ] {
        cases.push((name.into(), bad_start(name)));
    }
    cases
}

#[test]
fn safety_action_name_rules_are_pinned() {
    for (name, expected) in name_cases() {
        let parsed = SafetyActionName::parse(&name);
        assert_eq!(parsed.clone().map(drop), expected, "{name:?}");
        if let Ok(parsed) = parsed {
            assert_eq!(parsed.as_str(), name);
            assert_eq!(parsed.to_string(), name);
            assert_eq!(parsed.name_after_prefix(), &name["safety:".len()..]);
        }
    }
}

#[test]
fn safety_action_names_deserialize_only_through_the_validator() {
    let halt: SafetyActionName = serde_json::from_value(json!("safety:halt")).unwrap();
    assert_eq!(halt.as_str(), "safety:halt");
    assert_eq!(serde_json::to_value(&halt).unwrap(), json!("safety:halt"));
    for name in ["SAFETY:halt", "safety:halt\u{200b}", "safety:"] {
        assert!(serde_json::from_value::<SafetyActionName>(json!(name)).is_err());
    }
}

/// The policy and the validator cannot diverge: a `Safety` entry loads
/// exactly when `SafetyActionName::parse` accepts its key.
#[test]
fn policy_loading_accepts_a_safety_entry_exactly_when_the_shared_validator_does() {
    for (name, expected) in name_cases() {
        let policy =
            Policy::new_v2("p", 1, vec![]).with_action_class(name.as_str(), ActionClass::Safety);
        assert_eq!(
            policy.validate().is_ok(),
            expected.is_ok(),
            "validate {name:?}"
        );
        let document = serde_json::to_string(&policy).unwrap();
        assert_eq!(
            Policy::from_json(&document).is_ok(),
            expected.is_ok(),
            "from_json {name:?}"
        );
        if let Ok(()) = expected {
            let action = Action::new(name.as_str(), None, json!({})).unwrap();
            assert!(matches!(
                policy.classify(action),
                Ok(praetore_core::ClassifiedAction::Safety(_))
            ));
        }
    }
}

/// The length bound lives only in `SafetyActionName`; policy loading
/// enforces it through the shared validator.
#[test]
fn an_over_length_safety_entry_fails_to_load_with_a_typed_error() {
    let name = format!("safety:{}", "a".repeat(MAX_SAFETY_ACTION_NAME_BYTES - 6));
    let result = Policy::new_v2("p", 1, vec![])
        .with_action_class(name.as_str(), ActionClass::Safety)
        .validate();
    match result {
        Err(PraetoreError::PolicyActionClassInvalid(ActionClassError::SafetyNameTooLong {
            action_type,
            max,
        })) => {
            assert_eq!(action_type, name);
            assert_eq!(max, MAX_SAFETY_ACTION_NAME_BYTES);
        }
        other => panic!("expected SafetyNameTooLong, got {other:?}"),
    }
    // A Mission name of the same length is still bounded only by the
    // general action type limit.
    let mission = format!("ops:{}", "a".repeat(MAX_SAFETY_ACTION_NAME_BYTES));
    assert!(
        Policy::new_v2("p", 1, vec![])
            .with_mission_actions([mission])
            .validate()
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// Deterministic build.

#[test]
fn the_same_policy_gives_the_same_bytes() {
    let first = manifest_json();
    let second = manifest_json();
    assert_eq!(first, second);

    // Declaration order does not matter (the table is keyed by name)...
    let reordered = Policy::new_v2(
        "operations",
        3,
        vec![PolicyRule::new(
            "allow-writes",
            "fs:write_file",
            PolicyEffect::Allow,
        )],
    )
    .with_action_class("safety:hold", ActionClass::Safety)
    .with_action_class("safety:halt", ActionClass::Safety)
    .with_action_class("safety:stop_all", ActionClass::Safety)
    .with_mission_actions(["fs:write_file"]);
    assert_eq!(manifest_of(&reordered).to_json().unwrap(), first);

    // ...and neither does the JSON layout of the policy file.
    let pretty = serde_json::to_string_pretty(&policy()).unwrap();
    let loaded = Policy::from_json(&pretty).unwrap();
    assert_eq!(manifest_of(&loaded).to_json().unwrap(), first);

    // The list is sorted by byte value, without duplicates.
    let manifest = SafetyNamespaceManifest::from_json(&first).unwrap();
    let names: Vec<&str> = manifest
        .safety_actions()
        .iter()
        .map(SafetyActionName::as_str)
        .collect();
    assert_eq!(names, ["safety:halt", "safety:hold", "safety:stop_all"]);
    assert_eq!(manifest.policy_id(), "operations");
    assert_eq!(manifest.policy_version(), 3);
    assert_eq!(manifest.policy_digest(), policy().digest().unwrap());
    assert_eq!(manifest.issued_at(), "2026-11-01T00:00:00Z");
    assert_eq!(manifest.key_id(), key().key_id());
    assert_eq!(manifest.schema_version(), 1);

    // The file is canonical JSON: parsing and re-encoding is the identity.
    assert_eq!(manifest.to_json().unwrap(), first);

    // Another instant gives another manifest.
    let later = SafetyNamespaceManifest::from_policy(
        &policy(),
        issued_at() + time::Duration::seconds(1),
        &key(),
    )
    .unwrap();
    assert_ne!(later.to_json().unwrap(), first);
}

#[test]
fn a_policy_without_safety_actions_has_an_empty_namespace() {
    let policy = Policy::new_v2("p", 1, vec![]).with_mission_actions(["fs:write_file"]);
    let manifest = parse_and_verify(&manifest_of(&policy).to_json().unwrap()).unwrap();
    assert!(manifest.safety_actions().is_empty());
    manifest.verify_matches_policy(&policy).unwrap();
}

#[test]
fn an_invalid_policy_yields_no_manifest() {
    let invalid = Policy::new_v2(
        "p",
        1,
        vec![PolicyRule::new("r", "safety:halt", PolicyEffect::Deny)],
    )
    .with_action_class("safety:halt", ActionClass::Safety);
    match SafetyNamespaceManifest::from_policy(&invalid, issued_at(), &key()) {
        Err(SafetyNamespaceError::PolicyRejected { code, .. }) => {
            assert_eq!(code, "POLICY_EVALUATION_FAIL");
        }
        other => panic!("expected PolicyRejected, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Golden vector.

#[test]
fn manifest_matches_the_committed_golden_vector() {
    let golden: Value = serde_json::from_str(include_str!(
        "../../../docs/golden/safety-namespace-manifest-v1.json"
    ))
    .unwrap();
    let policy =
        Policy::from_json(include_str!("../../../docs/golden/canonical-policy-v2.json").trim())
            .unwrap();
    let manifest = manifest_of(&policy);
    assert_eq!(
        hex::encode(pin().as_bytes()),
        golden["namespace_public_key_hex"].as_str().unwrap()
    );
    assert_eq!(manifest.key_id(), golden["key_id"].as_str().unwrap());
    assert_eq!(
        String::from_utf8(manifest.signing_payload().unwrap()).unwrap(),
        golden["signing_payload"].as_str().unwrap()
    );
    assert_eq!(
        manifest.signature(),
        golden["signature_hex"].as_str().unwrap()
    );
    assert_eq!(
        manifest.to_json().unwrap(),
        golden["manifest"].as_str().unwrap()
    );
    // Pinned, so a regenerated vector cannot follow a format change
    // unnoticed.
    assert_eq!(
        manifest.policy_digest(),
        "77821c2735152448004f6780288dbb793bc1a78c204c5d0e460e859e89753cd0"
    );
    let parsed = parse_and_verify(golden["manifest"].as_str().unwrap()).unwrap();
    parsed.verify_matches_policy(&policy).unwrap();
}

// ---------------------------------------------------------------------------
// Signature verification.

#[test]
fn a_manifest_verifies_only_under_its_pinned_key() {
    let json = manifest_json();
    parse_and_verify(&json).unwrap();

    let other = SafetyNamespaceKey::from_secret_bytes(&[0x48; 32]);
    let manifest = SafetyNamespaceManifest::from_json(&json).unwrap();
    assert_eq!(
        manifest.verify(&other.public_key().unwrap()),
        Err(SafetyNamespaceError::KeyIdMismatch)
    );
    // Claiming the other key's id does not help: the signature is checked.
    let claimed = edited(&json, |value| value["key_id"] = json!(other.key_id()));
    assert_eq!(
        SafetyNamespaceManifest::from_json(&claimed)
            .unwrap()
            .verify(&other.public_key().unwrap()),
        Err(SafetyNamespaceError::SignatureInvalid)
    );
    // And the original key no longer matches the claimed id.
    assert_eq!(
        parse_and_verify(&claimed).unwrap_err(),
        SafetyNamespaceError::KeyIdMismatch
    );
}

#[test]
fn tampering_with_any_signed_field_is_rejected() {
    let json = manifest_json();
    let signature_invalid = Err(SafetyNamespaceError::SignatureInvalid);
    type Edit = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, Edit)> = vec![
        (
            "a name added",
            Box::new(|v| {
                v["safety_actions"] = json!([
                    "safety:halt",
                    "safety:hold",
                    "safety:pause",
                    "safety:stop_all"
                ])
            }),
        ),
        (
            "a name removed",
            Box::new(|v| v["safety_actions"] = json!(["safety:halt", "safety:stop_all"])),
        ),
        (
            "a name replaced",
            Box::new(|v| {
                v["safety_actions"] = json!(["safety:halt", "safety:hole", "safety:stop_all"])
            }),
        ),
        (
            "an empty list",
            Box::new(|v| v["safety_actions"] = json!([])),
        ),
        (
            "the digest",
            Box::new(|v| v["policy_digest"] = json!("ab".repeat(32))),
        ),
        (
            "the policy id",
            Box::new(|v| v["policy_id"] = json!("operations-2")),
        ),
        (
            "the policy version",
            Box::new(|v| v["policy_version"] = json!(4)),
        ),
        (
            "the issue time",
            Box::new(|v| v["issued_at"] = json!("2026-11-02T00:00:00Z")),
        ),
        (
            "the signature",
            Box::new(|v| {
                let mut signature = v["signature"].as_str().unwrap().to_owned();
                let flipped = if signature.starts_with('0') { "1" } else { "0" };
                signature.replace_range(0..1, flipped);
                v["signature"] = json!(signature);
            }),
        ),
    ];
    for (what, edit) in cases {
        let tampered = edited(&json, |value| edit(value));
        assert_eq!(
            parse_and_verify(&tampered).map(drop),
            signature_invalid,
            "{what}"
        );
    }
}

#[test]
fn a_reordered_or_duplicated_list_is_rejected() {
    let json = manifest_json();
    for list in [
        json!(["safety:hold", "safety:halt", "safety:stop_all"]),
        json!(["safety:stop_all", "safety:hold", "safety:halt"]),
        json!([
            "safety:halt",
            "safety:halt",
            "safety:hold",
            "safety:stop_all"
        ]),
    ] {
        let tampered = edited(&json, |value| value["safety_actions"] = list.clone());
        assert_eq!(
            SafetyNamespaceManifest::from_json(&tampered),
            Err(SafetyNamespaceError::SafetyActionsNotCanonical),
            "{list}"
        );
    }
}

#[test]
fn manifest_documents_are_parsed_strictly() {
    let json = manifest_json();
    let field = |field| Err(SafetyNamespaceError::InvalidField { field });
    let cases: Vec<(Value, Result<(), SafetyNamespaceError>)> = vec![
        (
            json!({"schema_version": 2}),
            Err(SafetyNamespaceError::UnsupportedSchemaVersion { found: 2 }),
        ),
        (
            json!({"schema_version": 0}),
            Err(SafetyNamespaceError::UnsupportedSchemaVersion { found: 0 }),
        ),
        (
            json!({"policy_digest": "AB".repeat(32)}),
            field("policy_digest"),
        ),
        (
            json!({"policy_digest": "ab".repeat(31)}),
            field("policy_digest"),
        ),
        (json!({"policy_id": ""}), field("policy_id")),
        (json!({"policy_id": " operations"}), field("policy_id")),
        (json!({"policy_version": 0}), field("policy_version")),
        (
            json!({"issued_at": "2026-11-01T00:00:00+00:00"}),
            field("issued_at"),
        ),
        (
            json!({"issued_at": "2026-11-01T01:00:00+01:00"}),
            field("issued_at"),
        ),
        (json!({"issued_at": "yesterday"}), field("issued_at")),
        (json!({"key_id": "AB".repeat(32)}), field("key_id")),
        (json!({"signature": "AB".repeat(64)}), field("signature")),
        (json!({"signature": "ab".repeat(63)}), field("signature")),
        (
            json!({"safety_actions": ["safety:halt", "safety:h\u{430}lt"]}),
            Err(SafetyNamespaceError::InvalidSafetyName {
                index: 1,
                error: SafetyNameError::NotPrintableAscii {
                    name: "safety:h\u{430}lt".into(),
                },
            }),
        ),
        (
            json!({"safety_actions": ["SAFETY:halt"]}),
            Err(SafetyNamespaceError::InvalidSafetyName {
                index: 0,
                error: SafetyNameError::MissingPrefix {
                    name: "SAFETY:halt".into(),
                },
            }),
        ),
    ];
    for (patch, expected) in cases {
        let tampered = edited(&json, |value| {
            for (key, field) in patch.as_object().unwrap() {
                value[key] = field.clone();
            }
        });
        assert_eq!(
            SafetyNamespaceManifest::from_json(&tampered).map(drop),
            expected,
            "{patch}"
        );
    }

    let too_many: Vec<String> = (0..513).map(|i| format!("safety:a{i:04}")).collect();
    let tampered = edited(&json, |value| value["safety_actions"] = json!(too_many));
    assert_eq!(
        SafetyNamespaceManifest::from_json(&tampered),
        Err(SafetyNamespaceError::TooManySafetyActions { max: 512 })
    );

    let unknown = edited(&json, |value| value["note"] = json!("x"));
    assert!(matches!(
        SafetyNamespaceManifest::from_json(&unknown),
        Err(SafetyNamespaceError::Schema(_))
    ));
    let missing = edited(&json, |value| {
        value.as_object_mut().unwrap().remove("issued_at");
    });
    assert!(matches!(
        SafetyNamespaceManifest::from_json(&missing),
        Err(SafetyNamespaceError::Schema(_))
    ));
    let duplicate = json.replacen("{", r#"{"schema_version":1,"#, 1);
    assert_eq!(
        SafetyNamespaceManifest::from_json(&duplicate),
        Err(SafetyNamespaceError::Json(JsonError::DuplicateKey))
    );
    assert!(matches!(
        SafetyNamespaceManifest::from_json(&" ".repeat(70_000)),
        Err(SafetyNamespaceError::Json(JsonError::InputTooLarge))
    ));
}

#[test]
fn error_codes_are_stable() {
    for (error, code) in [
        (
            SafetyNamespaceError::SignatureInvalid,
            "SAFETY_MANIFEST_SIGNATURE_INVALID",
        ),
        (
            SafetyNamespaceError::KeyIdMismatch,
            "SAFETY_MANIFEST_KEY_MISMATCH",
        ),
        (
            SafetyNamespaceError::UnsupportedSchemaVersion { found: 2 },
            "SAFETY_MANIFEST_VERSION_UNSUPPORTED",
        ),
        (
            SafetyNamespaceError::SafetyActionsNotCanonical,
            "SAFETY_MANIFEST_INVALID",
        ),
        (
            SafetyNamespaceError::PolicyMismatch {
                field: ManifestField::PolicyDigest,
            },
            "POLICY_MISMATCH",
        ),
    ] {
        assert_eq!(error.code(), code);
    }
}

// ---------------------------------------------------------------------------
// Domain separation.

/// Every `PRAETORE_..._V<n>\0...` literal in the repository's sources and
/// docs, with `\0` (or `\x00`) decoded.
fn repository_domains() -> BTreeSet<Vec<u8>> {
    fn walk(path: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            if path.is_dir() {
                if !matches!(
                    name.to_str(),
                    Some("target" | "node_modules" | ".git" | "corpus")
                ) {
                    walk(&path, out);
                }
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("rs" | "py" | "ts" | "js" | "mjs" | "md")
            ) {
                out.push(path);
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    // Docs too: a proposal may reserve a domain before any code uses it.
    for dir in ["crates", "examples", "packages", "fuzz", "tests", "docs"] {
        walk(&root.join(dir), &mut files);
    }
    let mut domains = BTreeSet::new();
    for file in files {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        let mut rest = text.as_str();
        while let Some(start) = rest.find("PRAETORE_") {
            let candidate = &rest[start..];
            let end = candidate
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '\\'))
                .unwrap_or(candidate.len());
            let literal = &candidate[..end];
            rest = &candidate["PRAETORE_".len()..];
            let decoded = literal.replace("\\x00", "\0").replace("\\0", "\0");
            let Some(nul) = decoded.find('\0') else {
                continue;
            };
            let name = &decoded[..nul];
            let is_domain = name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                && name.contains("_V");
            if is_domain && !decoded.contains('\\') {
                domains.insert(decoded.into_bytes());
            }
        }
    }
    domains
}

#[test]
fn no_domain_is_a_prefix_of_another() {
    let domains = repository_domains();
    // The scan finds every known domain, the new ones included.
    for known in [
        &b"PRAETORE_EVIDENCE_V1\0"[..],
        b"PRAETORE_EVIDENCE_V2\0",
        b"PRAETORE_AUTHORITY_V1\0",
        b"PRAETORE_INTENT_V1\0",
        b"PRAETORE_INTENT_V2\0",
        b"PRAETORE_KEY_ROTATION_V1\0",
        b"PRAETORE_STORAGE_RECORD_V1\0",
        b"PRAETORE_JOURNAL_LINK_V1\0",
        b"PRAETORE_JOURNAL_RECORD_V1\0",
        b"PRAETORE_JOURNAL_DATABASE_HEAD_V1\0",
        b"PRAETORE_EXECUTION_ACTION_V1\0",
        b"PRAETORE_EXECUTION_ATTESTATION_V1\0",
        b"PRAETORE_EXECUTION_OUTPUT_V1\0",
        b"PRAETORE_EXECUTION_REQUEST_V1\0",
        b"PRAETORE_HUMAN_APPROVAL_V1\0",
        b"PRAETORE_APPROVAL_EXPIRED_V1\0",
        b"PRAETORE_AGENT_KEY_V1\0ed25519\0",
        b"PRAETORE_ATTESTER_KEY_V1\0ed25519\0",
        b"PRAETORE_ISSUER_KEY_V1\0ed25519\0",
        b"PRAETORE_HEAD_STATEMENT_V1\0", // proposed in SAF-13
        SAFETY_NAMESPACE_DOMAIN,
        SAFETY_NAMESPACE_KEY_ID_DOMAIN,
    ] {
        assert!(
            domains.contains(known),
            "{} not found by the scan",
            String::from_utf8_lossy(known)
        );
    }
    for a in &domains {
        for b in &domains {
            assert!(
                a == b || !b.starts_with(a),
                "{:?} is a prefix of {:?}",
                String::from_utf8_lossy(a),
                String::from_utf8_lossy(b)
            );
        }
    }
}

/// A signature under any other domain, by the same key bytes, over the same
/// payload, is not a manifest signature; and a manifest signature does not
/// verify under any other domain.
#[test]
fn manifest_signatures_do_not_cross_domains() {
    let manifest = manifest_of(&policy());
    let payload = manifest.signing_payload().unwrap();
    let signature = hex::decode(manifest.signature()).unwrap();
    let raw = SigningKey::from_bytes(&NAMESPACE_SECRET);
    let others: Vec<Vec<u8>> = repository_domains()
        .into_iter()
        .filter(|domain| domain.as_slice() != SAFETY_NAMESPACE_DOMAIN)
        .collect();
    assert!(others.len() >= 20);
    for domain in &others {
        assert!(
            pin()
                .verify_domain_message(domain, &payload, &signature)
                .is_err(),
            "accepted under {}",
            String::from_utf8_lossy(domain)
        );
        let mut message = domain.clone();
        message.extend_from_slice(&payload);
        let foreign = hex::encode(raw.sign(&message).to_bytes());
        let forged = edited(&manifest.to_json().unwrap(), |value| {
            value["signature"] = json!(foreign)
        });
        assert_eq!(
            parse_and_verify(&forged).map(drop),
            Err(SafetyNamespaceError::SignatureInvalid),
            "{}",
            String::from_utf8_lossy(domain)
        );
    }
    // The control: the same construction under the manifest domain verifies.
    let mut message = SAFETY_NAMESPACE_DOMAIN.to_vec();
    message.extend_from_slice(&payload);
    assert_eq!(
        hex::encode(raw.sign(&message).to_bytes()),
        manifest.signature()
    );
}

/// The same key bytes in the attester role: the key ids differ, a receipt
/// signature is not a manifest signature, and a manifest signature is not
/// a receipt signature.
#[test]
fn manifest_and_receipt_signatures_are_not_interchangeable() {
    let attester = EvidenceAttesterKey::from_secret_bytes(&NAMESPACE_SECRET);
    assert_ne!(attester.key_id(), key().key_id());
    assert_eq!(safety_namespace_key_id(&pin()), key().key_id());

    let agent_key = AgentKeyPair::from_secret_bytes(&[1; 32]);
    let agent = agent_key.identity(AgentId::new());
    let authority = Authority::new(agent.id.clone(), "issuer", vec!["c".into()]);
    let policy = Policy::new_v2("p", 1, vec![]).with_mission_actions(["read_data"]);
    let action = Action::new("read_data", None, json!({}))
        .unwrap()
        .with_capability("c");
    let action = policy.classify(action).unwrap().into_mission().unwrap();
    let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
    request.sign_intent(&agent_key).unwrap();
    let mut evidence = request
        .attest(Decision::allow("ok", DecidedBy::rule("r")))
        .unwrap();
    evidence
        .bind_policy_digest(policy.digest().unwrap())
        .unwrap();
    evidence.sign(&attester).unwrap();
    let attester_pin = attester.public_key().unwrap();
    evidence.verify_attester_signature(&attester_pin).unwrap();
    assert_eq!(attester_pin, pin());

    // A receipt signature as a manifest signature.
    let receipt_signature = evidence.attester_signature.clone().unwrap();
    let forged = edited(&manifest_json(), |value| {
        value["signature"] = json!(receipt_signature)
    });
    assert_eq!(
        parse_and_verify(&forged).map(drop),
        Err(SafetyNamespaceError::SignatureInvalid)
    );

    // A manifest signature as a receipt signature.
    let mut forged_receipt = evidence.clone();
    forged_receipt.attester_signature = Some(manifest_of(&policy).signature().to_owned());
    assert!(
        forged_receipt
            .verify_attester_signature(&attester_pin)
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Policy match.

#[test]
fn a_manifest_matches_only_the_policy_it_was_derived_from() {
    let manifest = parse_and_verify(&manifest_json()).unwrap();
    manifest.verify_matches_policy(&policy()).unwrap();

    let mismatch = |policy: &Policy| manifest.verify_matches_policy(policy);
    let field = |field| Err(SafetyNamespaceError::PolicyMismatch { field });

    let mut renamed = policy();
    renamed.id = "operations-2".into();
    assert_eq!(mismatch(&renamed), field(ManifestField::PolicyId));

    // An executor holding the manifest of version 3 detects version 4.
    let mut next = policy();
    next.version = 4;
    assert_eq!(mismatch(&next), field(ManifestField::PolicyVersion));

    // Same id and version, another Safety namespace.
    let extra = policy().with_action_class("safety:pause", ActionClass::Safety);
    assert_eq!(mismatch(&extra), field(ManifestField::PolicyDigest));

    // Same Safety namespace, another policy: the digest still binds it.
    let mission_change = policy().with_mission_actions(["fs:read_file"]);
    assert_eq!(
        mismatch(&mission_change),
        field(ManifestField::PolicyDigest)
    );

    // A list that does not match a matching digest is caught too (the
    // signature check is separate).
    let tampered = edited(&manifest_json(), |value| {
        value["safety_actions"] = json!(["safety:halt", "safety:hold"])
    });
    assert_eq!(
        SafetyNamespaceManifest::from_json(&tampered)
            .unwrap()
            .verify_matches_policy(&policy()),
        field(ManifestField::SafetyActions)
    );

    // A policy that is not valid format 2 cannot be matched.
    let mut format_1 = policy();
    format_1.format_version = 1;
    assert!(matches!(
        mismatch(&format_1),
        Err(SafetyNamespaceError::PolicyRejected {
            code: "POLICY_EVALUATION_FAIL",
            ..
        })
    ));
}

// ---------------------------------------------------------------------------
// Undeclared names (for the ingestion path).

#[test]
fn undeclared_names_are_a_value_not_an_error() {
    let manifest = parse_and_verify(&manifest_json()).unwrap();
    let membership = |name: &str| manifest.classify_name(&SafetyActionName::parse(name).unwrap());
    assert_eq!(membership("safety:halt"), NamespaceMembership::Declared);
    assert_eq!(membership("safety:stop_all"), NamespaceMembership::Declared);
    assert_eq!(membership("safety:pause"), NamespaceMembership::Undeclared);
    assert_eq!(membership("safety:halt2"), NamespaceMembership::Undeclared);
    assert_eq!(membership("safety:Halt"), NamespaceMembership::Undeclared);
    assert_eq!(
        serde_json::to_value(NamespaceMembership::Undeclared).unwrap(),
        json!("undeclared")
    );
    assert_eq!(NamespaceMembership::Declared.as_str(), "declared");
}
