//! Writes the DEMO evidence bundle for `examples/third-party-verification/`
//! into the directory given as the first argument.
//!
//! DEMO KEYS ONLY: the secret bytes below are public and fixed ([0xd1; 32]
//! agent, [0xd2; 32] issuer, [0xd3; 32] attester). They authorize nothing
//! and must never be used outside this demo. All identifiers and timestamps
//! are fixed and Ed25519 signatures are deterministic, so the output is
//! byte-for-byte reproducible. Regenerate with
//! `examples/third-party-verification/regenerate.sh`.

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
            .expect("usage: third_party_bundle <dir>"),
    );
    fs::create_dir_all(&out).unwrap();

    let agent_key = AgentKeyPair::from_secret_bytes(&[0xd1; 32]);
    let issuer_key = AgentKeyPair::from_secret_bytes(&[0xd2; 32]);
    let attester = EvidenceAttesterKey::from_secret_bytes(&[0xd3; 32]);
    let agent_id: AgentId =
        serde_json::from_str("\"00000000-0000-0000-0000-00000000d001\"").unwrap();
    let agent = agent_key.identity(agent_id);

    let mut authority =
        Authority::new(agent.id.clone(), "DEMO-issuer", vec!["reports:read".into()]).with_validity(
            Validity {
                not_before: Some("2026-01-01T00:00:00Z".into()),
                not_after: Some("2036-01-01T00:00:00Z".into()),
            },
        );
    authority.id = serde_json::from_str("\"00000000-0000-0000-0000-00000000d002\"").unwrap();
    authority.sign_for_agent(&issuer_key, &agent).unwrap();

    let policy = Policy::new(
        "DEMO-third-party-policy",
        1,
        vec![
            PolicyRule::new("allow-read-report", "read_report", PolicyEffect::Allow)
                .with_capability("reports:read"),
        ],
    );

    let action = Action::new(
        "read_report",
        Some("DEMO-quarterly-report".into()),
        serde_json::json!({ "report": "DEMO-2026-Q3" }),
    )
    .unwrap()
    .with_capability("reports:read");
    let mut request = AuthorizationRequest::new(agent.clone(), authority.clone(), action).unwrap();
    request.request_id = "00000000-0000-0000-0000-00000000d003".parse().unwrap();
    request.sign_intent(&agent_key).unwrap();
    let mut evidence = request
        .attest(Decision::allow("DEMO allow: capability reports:read"))
        .unwrap();
    evidence.evidence_id = "00000000-0000-0000-0000-00000000d004".parse().unwrap();
    // Recomputes the context hash, which also covers the fixed evidence_id.
    evidence
        .bind_policy_digest(policy.digest().unwrap())
        .unwrap();
    evidence.sign(&attester).unwrap();

    let issuer_pin = TrustedAuthorityIssuer::new("DEMO-issuer", issuer_key.public_key())
        .unwrap()
        .export_pin_json()
        .unwrap();

    let write = |name: &str, contents: String| fs::write(out.join(name), contents).unwrap();
    write("evidence.json", evidence.to_json().unwrap());
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
