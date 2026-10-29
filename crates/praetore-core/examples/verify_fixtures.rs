//! Writes the `praetore-verify` README fixtures into the directory given as
//! the first argument. Uses fixed TEST-ONLY keys (secret bytes [1; 32] agent,
//! [2; 32] issuer, [3; 32] attester); they are public and must never be used
//! for anything else. Regenerate with `scripts/gen-verify-fixtures.sh`.

use praetore_core::{
    action::Action,
    authority::{Authority, Validity},
    authorization::AuthorizationRequest,
    decision::Decision,
    engine::TrustedAuthorityIssuer,
    evidence::EvidenceAttesterKey,
    identity::{AgentId, AgentKeyPair},
    policy::{Policy, PolicyEffect, PolicyRule},
};
use std::{fs, path::PathBuf};

fn main() {
    let out = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: verify_fixtures <dir>"),
    );
    fs::create_dir_all(&out).unwrap();

    let agent_key = AgentKeyPair::from_secret_bytes(&[1; 32]);
    let issuer_key = AgentKeyPair::from_secret_bytes(&[2; 32]);
    let attester = EvidenceAttesterKey::from_secret_bytes(&[3; 32]);
    let agent_id: AgentId =
        serde_json::from_str("\"00000000-0000-0000-0000-0000000000b1\"").unwrap();
    let agent = agent_key.identity(agent_id);

    let mut authority =
        Authority::new(agent.id.clone(), "example-issuer", vec!["data:read".into()]).with_validity(
            Validity {
                not_before: Some("2026-01-01T00:00:00Z".into()),
                not_after: Some("2036-01-01T00:00:00Z".into()),
            },
        );
    authority.id = serde_json::from_str("\"00000000-0000-0000-0000-0000000000b2\"").unwrap();
    authority.sign_for_agent(&issuer_key, &agent).unwrap();

    let policy = Policy::new(
        "example-verify-policy",
        1,
        vec![
            PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow)
                .with_capability("data:read"),
        ],
    );

    let action = Action::new(
        "read_data",
        Some("example-dataset".into()),
        serde_json::json!({}),
    )
    .unwrap()
    .with_capability("data:read");
    let mut request = AuthorizationRequest::new(agent.clone(), authority.clone(), action).unwrap();
    request.request_id = "00000000-0000-0000-0000-0000000000b3".parse().unwrap();
    request.sign_intent(&agent_key).unwrap();
    let mut evidence = request.attest(Decision::allow("example allow")).unwrap();
    evidence
        .bind_policy_digest(policy.digest().unwrap())
        .unwrap();
    evidence.sign(&attester).unwrap();

    let mut tampered = evidence.clone();
    tampered.decision.reason.push_str(" (tampered)");

    let issuer_pin = TrustedAuthorityIssuer::new("example-issuer", issuer_key.public_key())
        .unwrap()
        .export_pin_json()
        .unwrap();

    let write = |name: &str, contents: String| fs::write(out.join(name), contents).unwrap();
    write("evidence.json", evidence.to_json().unwrap());
    write(
        "evidence-tampered.json",
        serde_json::to_string(&tampered).unwrap(),
    );
    write(
        "attester-public-key.hex",
        format!(
            "{}\n",
            hex::encode(attester.public_key().unwrap().as_bytes())
        ),
    );
    write("issuer-pins.jsonl", format!("{issuer_pin}\n"));
    write("authority.json", serde_json::to_string(&authority).unwrap());
    write("agent.json", serde_json::to_string(&agent).unwrap());
    write("policy.json", serde_json::to_string(&policy).unwrap());
}
