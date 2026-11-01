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
    assert_eq!(evidence.decision.reason, "unclassified");

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
