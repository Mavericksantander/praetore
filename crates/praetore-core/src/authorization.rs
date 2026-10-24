use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::{
    Result,
    action::Action,
    authority::Authority,
    canonical::{MAX_JSON_VALUE_BYTES, canonical_json, validate_json_value},
    decision::Decision,
    evidence::Evidence,
    identity::{AgentIdentity, AgentKeyPair, REQUEST_INTENT_DOMAIN},
};

const MAX_CONTEXT_KEYS: usize = 128;
const MAX_CONTEXT_KEY_BYTES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// An agent's request to authorize one action under one delegated authority.
///
/// Strict and HighAssurance engines require the agent to sign the intent with
/// the key bound to the authority's subject. See the runnable
/// `quickstart` example for issuance, signing, evaluation, and verification.
pub struct AuthorizationRequest {
    pub request_id: Uuid,
    pub agent: AgentIdentity,
    pub authority: Authority,
    pub action: Action,
    pub trace_id: Option<String>,
    pub context: BTreeMap<String, Value>,
    pub agent_signature: Option<String>,
}

impl AuthorizationRequest {
    pub fn new(agent: AgentIdentity, authority: Authority, action: Action) -> Result<Self> {
        agent.validate()?;

        if agent.id != authority.subject {
            return Err(crate::PraetoreError::InvalidRequest(
                "authority subject does not match agent identity".into(),
            ));
        }

        authority.validate()?;
        action.validate()?;

        Ok(Self {
            request_id: Uuid::new_v4(),
            agent,
            authority,
            action,
            trace_id: None,
            context: BTreeMap::new(),
            agent_signature: None,
        })
    }

    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    pub fn with_context(mut self, key: impl Into<String>, value: Value) -> Self {
        self.context.insert(key.into(), value);
        self
    }

    pub fn sign_intent(&mut self, agent_key: &AgentKeyPair) -> Result<()> {
        self.validate()?;

        let verified_key = self.agent.verified_public_key()?;
        if verified_key != agent_key.public_key() {
            return Err(crate::PraetoreError::IdentityVerificationFailed);
        }

        let payload = self.canonical_intent_bytes()?;
        self.agent_signature = Some(hex::encode(
            agent_key.sign_domain_message(REQUEST_INTENT_DOMAIN, &payload),
        ));
        Ok(())
    }

    pub fn verify_intent_signature(&self) -> Result<()> {
        self.validate()?;
        let signature = self
            .agent_signature
            .as_deref()
            .ok_or(crate::PraetoreError::IdentityVerificationFailed)
            .and_then(|value| {
                hex::decode(value).map_err(|_| crate::PraetoreError::IdentityVerificationFailed)
            })?;
        let payload = self.canonical_intent_bytes()?;

        self.agent.verified_public_key()?.verify_domain_message(
            REQUEST_INTENT_DOMAIN,
            &payload,
            &signature,
        )
    }

    fn canonical_intent_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(&RequestIntentPayload {
            canonical_version: crate::canonical::CANONICAL_VERSION,
            schema_version: 1,
            request_id: self.request_id,
            agent: &self.agent,
            authority: &self.authority,
            action: &self.action,
            trace_id: &self.trace_id,
            context: &self.context,
        })
        .map_err(|error| crate::PraetoreError::InvalidRequest(error.to_string()))
    }

    fn validate(&self) -> Result<()> {
        self.agent.validate()?;
        self.authority.validate()?;
        self.action.validate()?;

        if self.agent.id != self.authority.subject {
            return Err(crate::PraetoreError::InvalidRequest(
                "authority subject does not match agent identity".into(),
            ));
        }

        if self
            .trace_id
            .as_deref()
            .is_some_and(|trace_id| trace_id.trim().is_empty())
        {
            return Err(crate::PraetoreError::InvalidRequest(
                "trace id cannot be empty".into(),
            ));
        }
        if self
            .trace_id
            .as_deref()
            .is_some_and(|trace_id| trace_id.len() > 1024)
        {
            return Err(crate::PraetoreError::InvalidRequest(
                "trace id exceeds maximum length".into(),
            ));
        }

        if self.context.keys().any(|key| key.trim().is_empty()) {
            return Err(crate::PraetoreError::InvalidRequest(
                "request context keys cannot be empty".into(),
            ));
        }

        if self.context.len() > MAX_CONTEXT_KEYS {
            return Err(crate::PraetoreError::InvalidRequest(
                "request context has too many keys".into(),
            ));
        }

        let mut context_bytes = 0usize;
        for (key, value) in &self.context {
            if key.len() > MAX_CONTEXT_KEY_BYTES || key != key.trim() {
                return Err(crate::PraetoreError::InvalidRequest(
                    "request context key is too long or not canonical".into(),
                ));
            }
            context_bytes += key.len();
            context_bytes += validate_json_value(value)
                .map_err(|message| crate::PraetoreError::InvalidRequest(message.into()))?;
            if context_bytes > MAX_JSON_VALUE_BYTES {
                return Err(crate::PraetoreError::InvalidRequest(
                    "request context exceeds maximum size".into(),
                ));
            }
        }

        Ok(())
    }

    pub fn attest(self, decision: Decision) -> Result<Evidence> {
        self.validate()?;

        Evidence::new_with_context(
            self.request_id,
            self.agent,
            self.authority,
            self.action,
            decision,
            self.trace_id,
            self.context,
        )?
        .with_agent_signature(self.agent_signature)
    }
}

#[derive(Serialize)]
struct RequestIntentPayload<'a> {
    canonical_version: u8,
    schema_version: u8,
    request_id: Uuid,
    agent: &'a AgentIdentity,
    authority: &'a Authority,
    action: &'a Action,
    trace_id: &'a Option<String>,
    context: &'a BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::Action,
        authority::Authority,
        decision::DecisionOutcome,
        identity::{AgentId, AgentIdentity},
    };
    use serde_json::json;

    fn test_agent() -> AgentIdentity {
        AgentIdentity::new(AgentId::new(), b"test-public-key".to_vec(), "ed25519").unwrap()
    }

    fn test_action() -> Action {
        Action::new(
            "read_data",
            Some("database".into()),
            json!({"table": "users"}),
        )
        .unwrap()
    }

    fn test_request() -> AuthorizationRequest {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        AuthorizationRequest::new(agent, authority, test_action()).unwrap()
    }

    #[test]
    fn creates_authorization_request() {
        let request = test_request();

        assert!(!request.request_id.is_nil());
        assert_eq!(request.agent.id, request.authority.subject);
    }

    #[test]
    fn creates_unique_request_ids() {
        let first = test_request();
        let second = test_request();

        assert_ne!(first.request_id, second.request_id);
    }

    #[test]
    fn rejects_mismatched_authority() {
        let agent = test_agent();
        let other_agent = test_agent();

        let authority = Authority::new(
            other_agent.id.clone(),
            "praetore-root",
            vec!["read:data".into()],
        );

        let result = AuthorizationRequest::new(agent, authority, test_action());

        assert!(matches!(
            result,
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn rejects_invalid_authority() {
        let agent = test_agent();

        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        authority.issuer = String::new();

        let result = AuthorizationRequest::new(agent, authority, test_action());

        assert!(matches!(
            result,
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn rejects_invalid_action() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let action = Action {
            action_type: "   ".into(),
            capability: None,
            target: None,
            parameters: json!({}),
        };

        let result = AuthorizationRequest::new(agent, authority, action);

        assert!(matches!(
            result,
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn trace_id_can_be_attached() {
        let request = test_request().with_trace_id("trace-001");

        assert_eq!(request.trace_id.as_deref(), Some("trace-001"));
    }

    #[test]
    fn trace_id_is_optional() {
        let request = test_request();

        assert!(request.trace_id.is_none());
    }

    #[test]
    fn attest_creates_verifiable_evidence() {
        let request = test_request();

        let evidence = request
            .attest(Decision::allow("policy permitted action"))
            .unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Allow);
        assert!(evidence.verify());
    }

    #[test]
    fn attest_preserves_request_id() {
        let request = test_request();
        let request_id = request.request_id;

        let evidence = request
            .attest(Decision::deny("policy rejected action"))
            .unwrap();

        assert_eq!(evidence.request_id, request_id);
    }

    #[test]
    fn attest_preserves_trace_id() {
        let request = test_request().with_trace_id("trace-001");

        let evidence = request
            .attest(Decision::allow("policy permitted action"))
            .unwrap();

        assert_eq!(evidence.trace_id.as_deref(), Some("trace-001"));
        assert!(evidence.verify());
    }

    #[test]
    fn attest_rejects_tampered_subject_binding() {
        let mut request = test_request();
        request.agent.id = AgentId::new();

        assert!(matches!(
            request.attest(Decision::allow("policy permitted action")),
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn attest_rejects_empty_trace_id() {
        let mut request = test_request();
        request.trace_id = Some("   ".into());

        assert!(matches!(
            request.attest(Decision::allow("policy permitted action")),
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn signed_request_intent_verifies_and_binds_context() {
        let keypair = AgentKeyPair::generate();
        let agent = keypair.identity(AgentId::new());
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);
        let mut request = AuthorizationRequest::new(agent, authority, test_action())
            .unwrap()
            .with_context("region", serde_json::json!("santiago"));

        request.sign_intent(&keypair).unwrap();
        assert!(request.verify_intent_signature().is_ok());

        request
            .context
            .insert("region".into(), serde_json::json!("north"));
        assert!(request.verify_intent_signature().is_err());
    }

    #[test]
    fn request_rejects_signature_from_other_agent_key() {
        let keypair = AgentKeyPair::generate();
        let other_keypair = AgentKeyPair::generate();
        let agent = keypair.identity(AgentId::new());
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);
        let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        assert!(matches!(
            request.sign_intent(&other_keypair),
            Err(crate::PraetoreError::IdentityVerificationFailed)
        ));
    }

    #[test]
    fn request_intent_matches_v1_golden_vector() {
        let golden: serde_json::Value =
            serde_json::from_str(include_str!("../../../docs/golden/trust-chain-v1.json")).unwrap();
        let agent_key = AgentKeyPair::from_secret_bytes(&[7; 32]);
        let agent_id: AgentId =
            serde_json::from_str("\"00000000-0000-0000-0000-000000000002\"").unwrap();
        let agent = agent_key.identity(agent_id);
        let mut authority =
            Authority::new(agent.id.clone(), "golden-issuer", vec!["data:read".into()])
                .with_validity(crate::authority::Validity {
                    not_before: Some("2026-01-01T00:00:00Z".into()),
                    not_after: Some("2027-01-01T00:00:00Z".into()),
                });
        authority.id = serde_json::from_str("\"00000000-0000-0000-0000-000000000001\"").unwrap();
        authority
            .sign_for_agent(&AgentKeyPair::from_secret_bytes(&[8; 32]), &agent)
            .unwrap();
        let action = Action::new("read_data", Some("dataset".into()), json!({}))
            .unwrap()
            .with_capability("data:read");
        let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
        request.request_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();

        assert_eq!(
            String::from_utf8(request.canonical_intent_bytes().unwrap()).unwrap(),
            golden["intent_signing_payload"].as_str().unwrap()
        );
        request.sign_intent(&agent_key).unwrap();
        assert_eq!(
            request.agent_signature.as_deref(),
            golden["intent_signature_hex"].as_str()
        );
    }
}
