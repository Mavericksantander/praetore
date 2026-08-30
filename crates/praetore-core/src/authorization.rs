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

        Ok(Self {
            request_id: Uuid::new_v4(),
            agent,
            authority,
            action,
            trace_id: None,
        })
    }

    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    pub fn attest(self, decision: Decision) -> Evidence {
        Evidence::new(
            self.request_id,
            self.agent,
            self.authority,
            self.action,
            decision,
            self.trace_id,
        )
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
    fn attest_creates_verifiable_evidence() {
        let request = test_request();

        let evidence = request.attest(Decision::allow("policy permitted action"));

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Allow);
        assert!(evidence.verify());
    }

    #[test]
    fn attest_preserves_request_id() {
        let request = test_request();
        let request_id = request.request_id;

        let evidence = request.attest(Decision::deny("policy rejected action"));

        assert_eq!(evidence.request_id, request_id);
    }

    #[test]
    fn attest_preserves_trace_id() {
        let request = test_request().with_trace_id("trace-001");

        let evidence = request.attest(Decision::allow("policy permitted action"));

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
    fn trace_id_can_be_attached() {
        let request = test_request().with_trace_id("trace-001");

        assert_eq!(request.trace_id.as_deref(), Some("trace-001"));
    }
}
