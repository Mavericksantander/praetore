//! G7: mission actions and safety actions are separated in the policy
//! (`action_classes`, policy format 2) and in the types (`MissionAction`,
//! `SafetyAction`). Each test matches the exact error variant.

use praetore_core::{
    Action, ActionClass, ActionClassError, AgentId, AgentKeyPair, Authority, AuthorizationRequest,
    ClassifiedAction, EvidenceAttesterKey, HighAssuranceConfig, Policy, PolicyEffect, PolicyRule,
    PraetoreError, RecordedPolicy, TrustedAuthorityIssuer, authority::Validity,
    engine::AuthorizationEngine,
};
use serde_json::{Value, json};

fn rule(action_type: &str) -> PolicyRule {
    PolicyRule::new("r", action_type, PolicyEffect::Allow).with_capability("c")
}

fn class_error(result: praetore_core::Result<()>) -> ActionClassError {
    match result {
        Err(PraetoreError::PolicyActionClassInvalid(error)) => error,
        other => panic!("expected PolicyActionClassInvalid, got {other:?}"),
    }
}

fn document(policy: &Policy) -> Value {
    serde_json::to_value(policy).unwrap()
}

fn action(action_type: &str) -> Action {
    Action::new(action_type, None, json!({}))
        .unwrap()
        .with_capability("c")
}

#[test]
fn mission_action_types_may_have_any_prefix_but_must_be_declared() {
    for action_type in ["fs:write_file", "mcp.tools/call", "read_data", "deploy"] {
        let policy = Policy::new_v2("p", 1, vec![rule(action_type)]);
        assert_eq!(
            class_error(policy.validate()),
            ActionClassError::UndeclaredActionType {
                rule_id: "r".into(),
                action_type: action_type.into(),
            }
        );
        assert!(
            policy
                .with_mission_actions([action_type])
                .validate()
                .is_ok()
        );
    }
}

#[test]
fn safety_prefix_and_class_must_agree() {
    let mission_with_prefix = Policy::new_v2("p", 1, vec![])
        .with_mission_actions(["safety:halt"])
        .validate();
    assert_eq!(
        class_error(mission_with_prefix),
        ActionClassError::SafetyPrefixNotSafety {
            action_type: "safety:halt".into()
        }
    );
    for action_type in [
        "halt",
        "emergency:stop",
        "safety:",
        "safety::x",
        "safety:_x",
    ] {
        let safety_without_prefix = Policy::new_v2("p", 1, vec![])
            .with_action_class(action_type, ActionClass::Safety)
            .validate();
        assert_eq!(
            class_error(safety_without_prefix),
            ActionClassError::SafetyWithoutPrefix {
                action_type: action_type.into()
            },
            "{action_type}"
        );
    }
    for action_type in [
        "safety:halt",
        "safety:hold",
        "safety:stop_all",
        "safety:pause",
    ] {
        assert!(
            Policy::new_v2("p", 1, vec![])
                .with_action_class(action_type, ActionClass::Safety)
                .validate()
                .is_ok()
        );
    }
}

#[test]
fn a_name_containing_safety_without_the_prefix_is_rejected() {
    for action_type in [
        "safety_halt",
        "Safety:halt",
        "SAFETY:halt",
        "ops:override-safety",
        "unsafety",
        "mcp.SafetyCheck",
    ] {
        let result = Policy::new_v2("p", 1, vec![])
            .with_mission_actions([action_type])
            .validate();
        assert_eq!(
            class_error(result),
            ActionClassError::AmbiguousSafetyName {
                action_type: action_type.into()
            },
            "{action_type}"
        );
    }
}

/// Names that read alike must not classify differently: only printable
/// ASCII without whitespace is accepted, in either class.
#[test]
fn action_classes_keys_must_be_printable_ascii() {
    for action_type in [
        "\u{455}afety:halt", // Cyrillic dze, a homoglyph of `s`
        "s\u{430}fety:halt", // Cyrillic a
        "\u{ff53}\u{ff41}\u{ff46}\u{ff45}\u{ff54}\u{ff59}:halt", // full-width letters
        "safety:halt\u{200b}", // trailing zero-width space
        "saf\u{200b}ety:halt", // zero-width space inside
        "safety:\u{200b}",   // invisible name
        "safety:\u{feff}halt", // byte order mark (format character)
        "safety: halt",      // inner space
        "fs:write\tfile",    // control character
        "caf\u{e9}:order",   // any other non-ASCII character
    ] {
        for class in [ActionClass::Mission, ActionClass::Safety] {
            let result = Policy::new_v2("p", 1, vec![])
                .with_action_class(action_type, class)
                .validate();
            assert_eq!(
                class_error(result),
                ActionClassError::NotPrintableAscii {
                    action_type: action_type.into()
                },
                "{action_type:?} as {class:?}"
            );
        }
    }
    // A rule cannot use such a name either: it would have to be declared.
    let policy = Policy::new_v2("p", 1, vec![rule("s\u{430}fety:halt")]);
    assert!(matches!(
        class_error(policy.validate()),
        ActionClassError::UndeclaredActionType { .. }
    ));
}

#[test]
fn no_rule_may_target_a_safety_action() {
    for effect in [
        PolicyEffect::Allow,
        PolicyEffect::Deny,
        PolicyEffect::RequireApproval,
    ] {
        let policy = Policy::new_v2(
            "p",
            1,
            vec![PolicyRule::new("on-halt", "safety:halt", effect)],
        )
        .with_action_class("safety:halt", ActionClass::Safety);
        assert_eq!(
            class_error(policy.validate()),
            ActionClassError::RuleTargetsSafetyAction {
                rule_id: "on-halt".into(),
                action_type: "safety:halt".into(),
            }
        );
    }
}

#[test]
fn action_classes_keys_must_be_canonical() {
    for action_type in ["", " ", " fs:read", "fs:read "] {
        let result = Policy::new_v2("p", 1, vec![])
            .with_mission_actions([action_type])
            .validate();
        assert_eq!(
            class_error(result),
            ActionClassError::InvalidActionType {
                action_type: action_type.into()
            }
        );
    }
}

#[test]
fn format_1_documents_are_rejected_for_evaluation_with_a_typed_error() {
    let v1 = r#"{"id":"p","version":1,"canonical_version":1,"rules":[]}"#;
    assert!(matches!(
        Policy::from_json(v1),
        Err(PraetoreError::PolicyFormatUnsupported {
            found: 1,
            supported: 2
        })
    ));
    // An explicit format 1 marker is not a format 1 document either.
    let explicit = r#"{"format_version":1,"id":"p","version":1,"canonical_version":1,"action_classes":{},"rules":[]}"#;
    assert!(matches!(
        Policy::from_json(explicit),
        Err(PraetoreError::PolicyFormatUnsupported { found: 1, .. })
    ));
    let future = r#"{"format_version":3,"id":"p","version":1,"canonical_version":1,"action_classes":{},"rules":[]}"#;
    assert!(matches!(
        Policy::from_json(future),
        Err(PraetoreError::PolicyFormatUnsupported { found: 3, .. })
    ));
    // Format 2 without the table.
    let missing = r#"{"format_version":2,"id":"p","version":1,"canonical_version":1,"rules":[]}"#;
    assert!(matches!(
        Policy::from_json(missing),
        Err(PraetoreError::PolicyActionClassInvalid(
            ActionClassError::MissingTable
        ))
    ));
}

#[test]
fn a_format_1_policy_value_is_rejected_in_every_mode() {
    let mut policy =
        Policy::new_v2("p", 1, vec![rule("read_data")]).with_mission_actions(["read_data"]);
    let mission = policy
        .classify(action("read_data"))
        .unwrap()
        .into_mission()
        .unwrap();
    policy.format_version = 1;
    let unsupported = |result: praetore_core::Result<_>| {
        matches!(
            result,
            Err(PraetoreError::PolicyFormatUnsupported {
                found: 1,
                supported: 2
            })
        )
    };
    assert!(unsupported(policy.validate()));
    assert!(unsupported(policy.digest().map(|_| ())));
    assert!(unsupported(
        policy.classify(action("read_data")).map(|_| ())
    ));

    let agent_key = AgentKeyPair::from_secret_bytes(&[3; 32]);
    let agent = agent_key.identity(AgentId::new());
    let authority = Authority::new(agent.id.clone(), "issuer", vec!["c".into()]);
    let request = AuthorizationRequest::new(agent, authority, mission).unwrap();

    // Development and Strict construct, then refuse to evaluate.
    assert!(unsupported(
        AuthorizationEngine::development(policy.clone())
            .evaluate(request.clone())
            .map(|_| ())
    ));
    let issuer = AgentKeyPair::from_secret_bytes(&[4; 32]);
    let pin = TrustedAuthorityIssuer::new("issuer", issuer.public_key()).unwrap();
    assert!(unsupported(
        AuthorizationEngine::strict(policy.clone(), vec![pin.clone()])
            .unwrap()
            .evaluate(request)
            .map(|_| ())
    ));
    // HighAssurance refuses to construct.
    let pin = pin
        .with_validity(Validity {
            not_before: Some("2026-01-01T00:00:00Z".into()),
            not_after: Some("2027-01-01T00:00:00Z".into()),
        })
        .unwrap();
    let config = HighAssuranceConfig::new(
        "a".repeat(64),
        vec![pin],
        EvidenceAttesterKey::from_secret_bytes(&[5; 32]),
    )
    .unwrap();
    assert!(unsupported(
        AuthorizationEngine::production(policy, config).map(|_| ())
    ));
}

#[test]
fn format_1_documents_still_digest_for_historical_verification() {
    let v1 = include_str!("../../../docs/golden/canonical-policy-v1.json");
    let recorded = RecordedPolicy::from_json(v1).unwrap();
    assert_eq!(recorded.format_version(), 1);
    assert_eq!(recorded.id(), "golden");
    assert_eq!(
        recorded.digest(),
        "5d45f213fc1f9fcfa17bf0a462169ea9e14efa028d873b79841924eae90ddd1f"
    );
    // The historical path still validates the document as before G7.
    let duplicate = r#"{"id":"p","version":1,"canonical_version":1,"rules":[{"id":"r","action_type":"a","effect":"Allow","required_capability":null,"target":null,"parameter_conditions":[],"context_conditions":[]},{"id":"r","action_type":"a","effect":"Allow","required_capability":null,"target":null,"parameter_conditions":[],"context_conditions":[]}]}"#;
    assert!(RecordedPolicy::from_json(duplicate).is_err());
    let unknown = r#"{"id":"p","version":1,"canonical_version":1,"rules":[],"action_classes":{}}"#;
    assert!(RecordedPolicy::from_json(unknown).is_err());

    // A format 2 document records the same digest Policy computes.
    let policy =
        Policy::new_v2("p", 1, vec![rule("read_data")]).with_mission_actions(["read_data"]);
    let text = serde_json::to_string(&policy).unwrap();
    let recorded = RecordedPolicy::from_json(&text).unwrap();
    assert_eq!(recorded.format_version(), 2);
    assert_eq!(recorded.digest(), policy.digest().unwrap());
}

#[test]
fn classify_separates_mission_safety_and_unclassified() {
    let policy = Policy::new_v2("p", 1, vec![rule("fs:write_file")])
        .with_mission_actions(["fs:write_file"])
        .with_action_class("safety:halt", ActionClass::Safety);
    assert!(matches!(
        policy.classify(action("fs:write_file")),
        Ok(ClassifiedAction::Mission(mission)) if mission.action_type == "fs:write_file"
    ));
    let ClassifiedAction::Safety(halt) = policy.classify(action("safety:halt")).unwrap() else {
        panic!("safety:halt must classify as Safety");
    };
    assert!(matches!(
        halt.not_governed(),
        PraetoreError::SafetyActionNotGoverned { action_type } if action_type == "safety:halt"
    ));
    assert!(matches!(
        policy
            .classify(action("safety:halt"))
            .unwrap()
            .into_mission(),
        Err(PraetoreError::SafetyActionNotGoverned { .. })
    ));
    // Undeclared, including an undeclared `safety:` action.
    for action_type in ["fs:delete", "safety:stop_all"] {
        assert!(matches!(
            policy.classify(action(action_type)),
            Err(PraetoreError::UnclassifiedAction { action_type: found }) if found == action_type
        ));
    }
}

#[test]
fn the_engine_rechecks_the_class_against_its_own_policy() {
    // A Mission action classified by one policy is refused by an engine whose
    // policy does not declare it, before any evaluation.
    let other = Policy::new_v2("other", 1, vec![]).with_mission_actions(["fs:delete"]);
    let mission = other
        .classify(action("fs:delete"))
        .unwrap()
        .into_mission()
        .unwrap();
    let agent = AgentKeyPair::from_secret_bytes(&[6; 32]).identity(AgentId::new());
    let authority = Authority::new(agent.id.clone(), "issuer", vec!["c".into()]);
    let request = AuthorizationRequest::new(agent, authority, mission).unwrap();
    let engine = AuthorizationEngine::development(
        Policy::new_v2("engine", 1, vec![rule("read_data")]).with_mission_actions(["read_data"]),
    );
    assert!(matches!(
        engine.evaluate(request),
        Err(PraetoreError::UnclassifiedAction { action_type }) if action_type == "fs:delete"
    ));
}

#[test]
fn a_format_1_document_proposes_an_action_classes_table() {
    let v1 = json!({
        "id": "p", "version": 1, "canonical_version": 1,
        "rules": [
            {"id": "w", "action_type": "fs:write_file", "effect": "Allow",
             "required_capability": "fs:write", "target": null,
             "parameter_conditions": [], "context_conditions": []},
            {"id": "w2", "action_type": "fs:write_file", "effect": "Deny",
             "required_capability": null, "target": null,
             "parameter_conditions": [], "context_conditions": []},
            {"id": "h", "action_type": "safety:halt", "effect": "Allow",
             "required_capability": null, "target": null,
             "parameter_conditions": [], "context_conditions": []},
            {"id": "o", "action_type": "ops:override_safety", "effect": "Allow",
             "required_capability": null, "target": null,
             "parameter_conditions": [], "context_conditions": []}
        ]
    });
    let proposal = RecordedPolicy::from_json(&v1.to_string())
        .unwrap()
        .propose_action_classes();
    assert_eq!(
        proposal.action_classes.into_iter().collect::<Vec<_>>(),
        vec![
            ("fs:write_file".to_string(), ActionClass::Mission),
            ("safety:halt".to_string(), ActionClass::Safety),
        ]
    );
    assert_eq!(
        proposal.problems,
        vec![
            ActionClassError::RuleTargetsSafetyAction {
                rule_id: "h".into(),
                action_type: "safety:halt".into()
            },
            ActionClassError::AmbiguousSafetyName {
                action_type: "ops:override_safety".into()
            },
        ]
    );
}

#[test]
fn format_2_digests_cover_the_action_classes_table() {
    let base = Policy::new_v2("p", 1, vec![rule("read_data")]).with_mission_actions(["read_data"]);
    let with_safety = base
        .clone()
        .with_action_class("safety:halt", ActionClass::Safety);
    assert_ne!(base.digest().unwrap(), with_safety.digest().unwrap());
    let document = document(&with_safety);
    assert_eq!(document["format_version"], 2);
    assert_eq!(document["action_classes"]["safety:halt"], "Safety");
    assert_eq!(document["action_classes"]["read_data"], "Mission");
}

/// The policy example in docs/policy-language.md loads as written, and its
/// MCP entry is the action type praetore-mcp uses (`mcp.tools/call`; the
/// capability is `mcp:tools/call`).
#[test]
fn the_documented_action_classes_example_loads() {
    let doc = include_str!("../../../docs/policy-language.md");
    let section = &doc[doc.find("## Action classes (policy format 2)").unwrap()..];
    let start = section.find("```json\n").unwrap() + "```json\n".len();
    let example = &section[start..start + section[start..].find("```").unwrap()];
    let policy = Policy::from_json(example).expect("documented example loads");
    assert_eq!(
        policy.action_classes.get("mcp.tools/call"),
        Some(&ActionClass::Mission)
    );
    assert!(!policy.action_classes.contains_key("mcp:tools/call"));
    assert_eq!(
        policy.action_classes.get("safety:halt"),
        Some(&ActionClass::Safety)
    );
}

struct Strict {
    engine: AuthorizationEngine,
    policy: Policy,
    agent_key: AgentKeyPair,
    issuer: AgentKeyPair,
}

fn strict(policy_id: &str) -> Strict {
    let policy = Policy::new_v2(policy_id, 1, vec![rule("read_data")])
        .with_mission_actions(["read_data"])
        .with_action_class("safety:halt", ActionClass::Safety);
    let issuer = AgentKeyPair::from_secret_bytes(&[21; 32]);
    let pin = TrustedAuthorityIssuer::new("issuer", issuer.public_key()).unwrap();
    Strict {
        engine: AuthorizationEngine::strict(policy.clone(), vec![pin]).unwrap(),
        policy,
        agent_key: AgentKeyPair::from_secret_bytes(&[22; 32]),
        issuer,
    }
}

fn unclassified_request(
    fixture: &Strict,
    signer: &AgentKeyPair,
    action_type: &str,
) -> praetore_core::authorization::UnclassifiedRequest {
    let agent = fixture.agent_key.identity(AgentId::new());
    let mut authority = Authority::new(agent.id.clone(), "issuer", vec!["c".into()]);
    authority.sign_for_agent(signer, &agent).unwrap();
    let action = fixture.policy.unclassified(action(action_type)).unwrap();
    let mut request = AuthorizationRequest::new_unclassified(agent, authority, action).unwrap();
    request.sign_intent(&fixture.agent_key).unwrap();
    request
}

/// G7: an undeclared action is refused by the engine with a DENY decided by
/// the engine guard `unclassified_action`, reason `unclassified`, no rule
/// contribution.
#[test]
fn an_unclassified_action_is_refused_with_an_engine_guard_deny() {
    let fixture = strict("g7-core-unclassified");
    for action_type in ["fs:delete", "safety:hold"] {
        let request = unclassified_request(&fixture, &fixture.issuer, action_type);
        let evidence = fixture.engine.refuse_unclassified(request).unwrap();
        assert_eq!(
            evidence.decision.outcome,
            praetore_core::DecisionOutcome::Deny
        );
        assert_eq!(evidence.decision.reason, "unclassified");
        assert_eq!(
            evidence.decision.decided_by(),
            Some(&praetore_core::DecidedBy::engine_guard(
                "unclassified_action"
            ))
        );
        assert!(evidence.decision.contributions.is_empty());
        assert_eq!(evidence.action.action_type, action_type);
        assert_eq!(
            evidence.policy_digest.as_deref(),
            Some(fixture.policy.digest().unwrap().as_str())
        );
        evidence.verify_agent_intent().unwrap();
    }
}

/// G7: the refusal verifies the request exactly like a mission request: a
/// forged intent or an authority from an unpinned issuer gets no evidence.
#[test]
fn an_unclassified_refusal_verifies_the_request_first() {
    let fixture = strict("g7-core-unclassified-forged");
    let mut forged = unclassified_request(&fixture, &fixture.issuer, "fs:delete");
    forged.context.insert("injected".into(), json!(true));
    assert!(matches!(
        fixture.engine.refuse_unclassified(forged),
        Err(PraetoreError::IntentInvalid)
    ));

    let rogue = AgentKeyPair::from_secret_bytes(&[23; 32]);
    let unpinned = unclassified_request(&fixture, &rogue, "fs:delete");
    assert!(matches!(
        fixture.engine.refuse_unclassified(unpinned),
        Err(PraetoreError::AuthorityVerificationFailed | PraetoreError::TrustStoreFailure)
    ));

    let mut unsigned = unclassified_request(&fixture, &fixture.issuer, "fs:delete");
    unsigned.agent_signature = None;
    assert!(fixture.engine.refuse_unclassified(unsigned).is_err());
}

/// G7: only an undeclared type can be wrapped, and the engine checks again
/// against its own policy.
#[test]
fn only_undeclared_action_types_are_unclassified() {
    let fixture = strict("g7-core-unclassified-declared");
    assert!(matches!(
        fixture.policy.unclassified(action("read_data")),
        Err(PraetoreError::InvalidRequest(_))
    ));
    assert!(matches!(
        fixture.policy.unclassified(action("safety:halt")),
        Err(PraetoreError::SafetyActionNotGoverned { .. })
    ));
    // Wrapped against another policy, declared Mission in the engine's.
    let other = Policy::new_v2("other", 1, vec![]);
    let agent = fixture.agent_key.identity(AgentId::new());
    let mut authority = Authority::new(agent.id.clone(), "issuer", vec!["c".into()]);
    authority.sign_for_agent(&fixture.issuer, &agent).unwrap();
    let mut request = AuthorizationRequest::new_unclassified(
        agent,
        authority,
        other.unclassified(action("read_data")).unwrap(),
    )
    .unwrap();
    request.sign_intent(&fixture.agent_key).unwrap();
    assert!(matches!(
        fixture.engine.refuse_unclassified(request),
        Err(PraetoreError::InvalidRequest(_))
    ));
}
