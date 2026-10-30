//! Regression: signatures, digests and key ids have a single valid textual
//! form, lowercase hex. `hex::decode` also accepts uppercase, which made the
//! same signed document parse in several encodings.

use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, AuthorizationRequest, Decision, Evidence,
    EvidenceAttesterKey, TrustedAuthorityIssuer,
};

/// Uppercases the hex letters of `value`; panics if there are none, so each
/// test really exercises a case change.
fn upper(value: &str) -> String {
    assert!(value.bytes().any(|b| (b'a'..=b'f').contains(&b)));
    value.to_ascii_uppercase()
}

/// Uppercases only the first hex letter.
fn mixed(value: &str) -> String {
    let index = value.find(|c: char| ('a'..='f').contains(&c)).unwrap();
    let mut mixed = value.to_owned();
    mixed.replace_range(index..=index, &value[index..=index].to_ascii_uppercase());
    mixed
}

struct Fixture {
    issuer_key: AgentKeyPair,
    authority: Authority,
    request: AuthorizationRequest,
}

fn fixture() -> Fixture {
    let agent_key = AgentKeyPair::from_secret_bytes(&[3; 32]);
    let agent = agent_key.identity(AgentId::new());
    let issuer_key = AgentKeyPair::from_secret_bytes(&[4; 32]);
    let mut authority = Authority::new(agent.id.clone(), "issuer", vec!["data:read".into()]);
    authority.sign_for_agent(&issuer_key, &agent).unwrap();
    let action = Action::new("read_data", None, serde_json::json!({}))
        .unwrap()
        .with_capability("data:read");
    let mut request = AuthorizationRequest::new(agent, authority.clone(), action).unwrap();
    request.sign_intent(&agent_key).unwrap();
    Fixture {
        issuer_key,
        authority,
        request,
    }
}

#[test]
fn authority_signature_must_be_lowercase() {
    let Fixture {
        issuer_key,
        authority,
        ..
    } = fixture();
    let key = issuer_key.public_key();
    authority.verify_signature(&key).unwrap();
    let signature = authority.signature.clone().unwrap();
    for altered in [upper(&signature), mixed(&signature)] {
        let mut authority = authority.clone();
        authority.signature = Some(altered);
        assert!(authority.verify_signature(&key).is_err());
    }
}

#[test]
fn authority_subject_key_hash_and_issuer_key_id_must_be_lowercase() {
    let authority = fixture().authority;
    authority.validate().unwrap();
    let hash = authority.subject_key_hash.clone().unwrap();
    let key_id = authority.issuer_key_id.clone().unwrap();
    for altered in [upper(&hash), mixed(&hash)] {
        let mut authority = authority.clone();
        authority.subject_key_hash = Some(altered);
        assert!(authority.validate().is_err());
    }
    for altered in [upper(&key_id), mixed(&key_id)] {
        let mut authority = authority.clone();
        authority.issuer_key_id = Some(altered);
        assert!(authority.validate().is_err());
    }
}

#[test]
fn request_intent_signature_must_be_lowercase() {
    let request = fixture().request;
    request.verify_intent_signature().unwrap();
    let signature = request.agent_signature.clone().unwrap();
    for altered in [upper(&signature), mixed(&signature)] {
        let mut request = request.clone();
        request.agent_signature = Some(altered);
        assert!(request.verify_intent_signature().is_err());
    }
}

#[test]
fn evidence_attester_signature_must_be_lowercase() {
    let attester = EvidenceAttesterKey::from_secret_bytes(&[6; 32]);
    let mut evidence: Evidence = fixture().request.attest(Decision::allow("ok")).unwrap();
    evidence.sign(&attester).unwrap();
    let key = attester.public_key().unwrap();
    evidence.verify_attester_signature(&key).unwrap();
    let signature = evidence.attester_signature.clone().unwrap();
    for altered in [upper(&signature), mixed(&signature)] {
        let mut evidence = evidence.clone();
        evidence.attester_signature = Some(altered);
        assert!(evidence.verify_attester_signature(&key).is_err());
    }
}

#[test]
fn evidence_policy_digest_must_be_lowercase() {
    let digest = "ab".repeat(32);
    let mut evidence = fixture().request.attest(Decision::allow("ok")).unwrap();
    for altered in [upper(&digest), mixed(&digest)] {
        assert!(evidence.clone().bind_policy_digest(altered).is_err());
    }
    evidence.bind_policy_digest(digest).unwrap();
}

#[test]
fn issuer_pin_public_key_must_be_lowercase() {
    let key = AgentKeyPair::from_secret_bytes(&[8; 32]).public_key();
    let json = TrustedAuthorityIssuer::new("issuer", key)
        .unwrap()
        .export_pin_json()
        .unwrap();
    TrustedAuthorityIssuer::from_pin_json(&json).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let public_key = value["public_key"].as_str().unwrap().to_owned();
    for altered in [upper(&public_key), mixed(&public_key)] {
        let altered = json.replace(&public_key, &altered);
        assert_ne!(altered, json);
        assert!(TrustedAuthorityIssuer::from_pin_json(&altered).is_err());
    }
}
