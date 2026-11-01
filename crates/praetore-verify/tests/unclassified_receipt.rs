//! G7: the signed DENY that the engine records for an action type the policy
//! does not declare is an ordinary receipt: `praetore-verify` accepts it with
//! the issuer pin, the attester pin, the signed intent and the policy.

use praetore_core::{
    Action, ActionClass, AgentId, AgentKeyPair, Authority, AuthorizationRequest,
    EvidenceAttesterKey, Policy, PolicyEffect, PolicyRule, TrustedAuthorityIssuer,
    engine::AuthorizationEngine,
};
use serde_json::{Value, json};
use std::{fs, process::Command};

#[test]
fn an_unclassified_deny_receipt_verifies_with_praetore_verify() {
    let policy = Policy::new_v2(
        "g7-verify-unclassified",
        1,
        vec![
            PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow)
                .with_capability("data:read"),
        ],
    )
    .with_mission_actions(["read_data"])
    .with_action_class("safety:halt", ActionClass::Safety);
    let issuer = AgentKeyPair::from_secret_bytes(&[41; 32]);
    let agent_key = AgentKeyPair::from_secret_bytes(&[42; 32]);
    let attester = EvidenceAttesterKey::from_secret_bytes(&[43; 32]);
    let pin = TrustedAuthorityIssuer::new("g7-issuer", issuer.public_key()).unwrap();
    let engine = AuthorizationEngine::strict(policy.clone(), vec![pin.clone()]).unwrap();

    let agent = agent_key.identity(AgentId::new());
    let mut authority = Authority::new(agent.id.clone(), "g7-issuer", vec!["data:read".into()]);
    authority.sign_for_agent(&issuer, &agent).unwrap();
    let action = Action::new("data:purge", None, json!({}))
        .unwrap()
        .with_capability("data:read");
    let mut request = AuthorizationRequest::new_unclassified(
        agent,
        authority,
        policy.unclassified(action).unwrap(),
    )
    .unwrap();
    request.sign_intent(&agent_key).unwrap();
    let mut evidence = engine.refuse_unclassified(request).unwrap();
    evidence.sign(&attester).unwrap();
    assert_eq!(
        evidence.decision.reason,
        praetore_core::UNCLASSIFIED_DENY_REASON
    );

    let dir = std::env::temp_dir().join(format!(
        "praetore-verify-unclassified-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, contents: String| {
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    };
    let evidence_file = write("evidence.json", evidence.to_json().unwrap());
    let attester_pin = write(
        "attester.hex",
        format!(
            "{}\n",
            hex::encode(attester.public_key().unwrap().as_bytes())
        ),
    );
    let issuer_pins = write(
        "pins.jsonl",
        format!("{}\n", pin.export_pin_json().unwrap()),
    );
    let policy_file = write("policy.json", serde_json::to_string(&policy).unwrap());

    let output = Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .args(["evidence", "--evidence", &evidence_file])
        .args([
            "--attester-pin",
            &attester_pin,
            "--issuer-pins",
            &issuer_pins,
        ])
        .args([
            "--require-intent",
            "--policy",
            &policy_file,
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let _ = fs::remove_dir_all(&dir);
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(output.status.success(), "{summary}");
    assert_eq!(summary["ok"], true);
    assert_eq!(summary["details"]["policy_verified"], true);
    assert_eq!(summary["details"]["intent_verified"], true);
}

/// G7: `--format text` escapes characters that render invisibly or reorder
/// text in the action type and the tool name; JSON output stays exact.
#[test]
fn text_output_escapes_invisible_characters_and_json_stays_exact() {
    let issuer = AgentKeyPair::from_secret_bytes(&[51; 32]);
    let agent_key = AgentKeyPair::from_secret_bytes(&[52; 32]);
    let attester = EvidenceAttesterKey::from_secret_bytes(&[53; 32]);
    let pin = TrustedAuthorityIssuer::new("g7-issuer", issuer.public_key()).unwrap();
    let policy =
        Policy::new_v2("g7-verify-escape", 1, vec![]).with_mission_actions(["local:set_value"]);
    let engine = AuthorizationEngine::strict(policy.clone(), vec![pin]).unwrap();
    let agent = agent_key.identity(AgentId::new());
    let mut authority = Authority::new(agent.id.clone(), "g7-issuer", vec!["local:write".into()]);
    authority.sign_for_agent(&issuer, &agent).unwrap();
    let action_type = "local:set_value\u{200b}";
    let tool = "rm\u{202e}txt.exe";
    let action = Action::new(action_type, None, json!({"tool": tool}))
        .unwrap()
        .with_capability("local:write");
    let mut request = AuthorizationRequest::new_unclassified(
        agent,
        authority,
        policy.unclassified(action).unwrap(),
    )
    .unwrap();
    request.sign_intent(&agent_key).unwrap();
    let mut evidence = engine.refuse_unclassified(request).unwrap();
    evidence.sign(&attester).unwrap();

    let dir = std::env::temp_dir().join(format!("praetore-verify-escape-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let evidence_file = dir.join("evidence.json");
    fs::write(&evidence_file, evidence.to_json().unwrap()).unwrap();
    let pin_file = dir.join("attester.hex");
    fs::write(
        &pin_file,
        format!(
            "{}\n",
            hex::encode(attester.public_key().unwrap().as_bytes())
        ),
    )
    .unwrap();
    let run = |format: &str| {
        Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
            .arg("evidence")
            .arg("--evidence")
            .arg(&evidence_file)
            .arg("--attester-pin")
            .arg(&pin_file)
            .args(["--format", format])
            .output()
            .unwrap()
    };
    let text_output = run("text");
    let json_output = run("json");
    let _ = fs::remove_dir_all(&dir);

    let text = String::from_utf8(text_output.stdout).unwrap();
    assert!(text_output.status.success(), "{text}");
    println!("{text}");
    assert!(
        text.contains(r#"receipt_action_type="local:set_value\u{200b}""#),
        "{text}"
    );
    assert!(
        text.contains(r#"receipt_tool="rm\u{202e}txt.exe""#),
        "{text}"
    );
    assert!(
        !text.contains('\u{200b}') && !text.contains('\u{202e}'),
        "{text}"
    );
    assert!(
        text.contains(
            r#"receipt_decided_by={"guard":"unclassified_action","kind":"engine_guard"}"#
        ),
        "{text}"
    );

    let summary: Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(summary["details"]["receipt_action_type"], action_type);
    assert_eq!(summary["details"]["receipt_tool"], tool);
}
