// Built against praetore-core at 3db7b5e (before the policy digest was
// required for signing). Copied in as an example by
// scripts/regen-legacy-evidence-fixture.sh; not compiled in this tree.
use praetore_core::{
    action::Action,
    authority::Authority,
    authorization::AuthorizationRequest,
    decision::Decision,
    evidence::EvidenceAttesterKey,
    identity::{AgentId, AgentKeyPair},
};

fn main() {
    // Test-only fixed keys: agent [1; 32], issuer [2; 32], attester [3; 32].
    let agent_key = AgentKeyPair::from_secret_bytes(&[1; 32]);
    let issuer_key = AgentKeyPair::from_secret_bytes(&[2; 32]);
    let attester = EvidenceAttesterKey::from_secret_bytes(&[3; 32]);
    let agent_id: AgentId =
        serde_json::from_str("\"00000000-0000-0000-0000-0000000000a1\"").unwrap();
    let agent = agent_key.identity(agent_id);
    let mut authority = Authority::new(agent.id.clone(), "test-issuer", vec!["data:read".into()]);
    authority.id = serde_json::from_str("\"00000000-0000-0000-0000-0000000000a2\"").unwrap();
    authority.sign_for_agent(&issuer_key, &agent).unwrap();
    let action = Action::new("read_data", Some("db".into()), serde_json::json!({"table": "users"}))
        .unwrap()
        .with_capability("data:read");
    let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
    request.request_id = "00000000-0000-0000-0000-0000000000a3".parse().unwrap();
    request.sign_intent(&agent_key).unwrap();
    let mut evidence = request
        .attest(Decision::allow("legacy receipt before policy digest was required"))
        .unwrap();
    evidence.sign(&attester).unwrap();
    assert!(evidence.policy_digest.is_none());
    println!("{}", evidence.to_json().unwrap());
}
