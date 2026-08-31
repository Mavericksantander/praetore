use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Result, action::Action, authority::Authority, decision::Decision, evidence::Evidence,
    identity::AgentIdentity,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub request_id: Uuid,
    pub agent: AgentIdentity,
    pub authority: Authority,
    pub action: Action,
    pub trace_id: Option<String>,
}

impl AuthorizationRequest {
    pub fn new(agent: AgentIdentity, authority: Authority, action: Action) -> Result<Self> {
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
        })
    }

    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Result<Self> {
        let trace_id = trace_id.into();

        if trace_id.trim().is_empty() {
            return Err(crate::PraetoreError::InvalidRequest(
                "trace id cannot be empty".into(),
            ));
        }

        self.trace_id = Some(trace_id);
        Ok(self)
    }

    pub fn attest(self, decision: Decision) -> Result<Evidence> {
        self.agent.validate()?;
        self.authority.validate()?;
        self.action.validate()?;

        if self.agent.id != self.authority.subject {
            return Err(crate::PraetoreError::InvalidRequest(
                "authority subject does not match agent identity".into(),
            ));
        }

        if let Some(trace_id) = &self.trace_id {
            if trace_id.trim().is_empty() {
                return Err(crate::PraetoreError::InvalidRequest(
                    "trace id cannot be empty".into(),
                ));
            }
        }

        Ok(Evidence::new(
            self.request_id,
            self.agent,
            self.authority,
            self.action,
            decision,
            self.trace_id,
        ))
    }
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
        let request = test_request().with_trace_id("trace-001").unwrap();

        let evidence = request
            .attest(Decision::allow("policy permitted action"))
            .unwrap();

        assert_eq!(evidence.trace_id.as_deref(), Some("trace-001"));
        assert!(evidence.verify());
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

        assert!(result.is_err());
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
        let request = test_request().with_trace_id("trace-001").unwrap();

        assert_eq!(request.trace_id.as_deref(), Some("trace-001"));
    }

    #[test]
    fn rejects_empty_trace_id() {
        let result = test_request().with_trace_id("");

        assert!(matches!(
            result,
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn rejects_whitespace_trace_id() {
        let result = test_request().with_trace_id("   ");

        assert!(matches!(
            result,
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn attest_rejects_tampered_identity() {
        let mut request = test_request();
        request.agent.public_key.clear();

        let result = request.attest(Decision::allow("policy permitted action"));

        assert!(matches!(
            result,
            Err(crate::PraetoreError::InvalidIdentity(_))
        ));
    }

    #[test]
    fn attest_rejects_tampered_authority() {
        let mut request = test_request();
        request.authority.issuer.clear();

        let result = request.attest(Decision::allow("policy permitted action"));

        assert!(matches!(
            result,
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn attest_rejects_tampered_action() {
        let mut request = test_request();
        request.action.action_type = "   ".into();

        let result = request.attest(Decision::allow("policy permitted action"));

        assert!(matches!(
            result,
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn attest_rejects_tampered_subject_binding() {
        let mut request = test_request();
        request.agent.id = AgentId::new();

        let result = request.attest(Decision::allow("policy permitted action"));

        assert!(matches!(
            result,
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn attest_rejects_tampered_trace_id() {
        let mut request = test_request().with_trace_id("trace-001").unwrap();
        request.trace_id = Some("   ".into());

        let result = request.attest(Decision::allow("policy permitted action"));

        assert!(matches!(
            result,
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }
}
