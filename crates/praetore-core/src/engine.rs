use crate::{
    authorization::AuthorizationRequest,
    decision::{Decision, DecisionOutcome},
    evidence::Evidence,
    policy::Policy,
    Result,
};

#[derive(Debug, Clone)]
pub struct AuthorizationEngine {
    policy: Policy,
}

impl AuthorizationEngine {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn evaluate(&self, request: AuthorizationRequest) -> Result<Evidence> {
        let decision = self.evaluate_request(&request)?;

        Ok(request.attest(decision))
    }

    fn evaluate_request(&self, request: &AuthorizationRequest) -> Result<Decision> {
        if !request.authority.permits(&request.action.action_type) {
            return Ok(Decision::deny(format!(
                "authority does not permit action type: {}",
                request.action.action_type
            )));
        }

        self.policy.evaluate(&request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::Action,
        authority::Authority,
        identity::{AgentId, AgentIdentity},
        policy::{Policy, PolicyRule},
    };
    use serde_json::json;

    fn test_agent() -> AgentIdentity {
        AgentIdentity::new(
            AgentId::new(),
            b"test-public-key".to_vec(),
            "ed25519",
        )
        .unwrap()
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

        let authority = Authority::new(
            agent.id.clone(),
            "praetore-root",
            vec!["read_data".into()],
        );

        AuthorizationRequest::new(agent, authority, test_action()).unwrap()
    }

    fn allow_policy() -> Policy {
        Policy::new(
            "test-policy",
            1,
            vec![PolicyRule::allow_action("read_data")],
        )
        .unwrap()
    }

    fn deny_policy() -> Policy {
        Policy::new(
            "test-policy",
            1,
            vec![PolicyRule::deny_action("read_data")],
        )
        .unwrap()
    }

    fn approval_policy() -> Policy {
        Policy::new(
            "test-policy",
            1,
            vec![PolicyRule::require_approval("read_data")],
        )
        .unwrap()
    }

    #[test]
    fn engine_allows_authorized_action() {
        let engine = AuthorizationEngine::new(allow_policy());
        let evidence = engine.evaluate(test_request()).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Allow);
        assert!(evidence.verify());
    }

    #[test]
    fn engine_denies_policy_rejection() {
        let engine = AuthorizationEngine::new(deny_policy());
        let evidence = engine.evaluate(test_request()).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
        assert!(evidence.verify());
    }

    #[test]
    fn engine_requires_approval_when_policy_requires_it() {
        let engine = AuthorizationEngine::new(approval_policy());
        let evidence = engine.evaluate(test_request()).unwrap();

        assert_eq!(
            evidence.decision.outcome,
            DecisionOutcome::RequireApproval
        );
        assert!(evidence.verify());
    }

    #[test]
    fn engine_preserves_policy_contributions() {
        let agent = test_agent();

        let authority = Authority::new(
            agent.id.clone(),
            "praetore-root",
            vec!["read_data".into()],
        );

        let request =
            AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let policy = Policy::new(
            "test-policy",
            1,
            vec![
                PolicyRule::allow_action("read_data"),
                PolicyRule::deny_action("read_data"),
            ],
        )
        .unwrap();

        let engine = AuthorizationEngine::new(policy);
        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
        assert_eq!(evidence.decision.contributions.len(), 2);

        assert_eq!(
            evidence.decision.contributions[0].rule_id,
            "allow-read_data"
        );
        assert_eq!(
            evidence.decision.contributions[1].rule_id,
            "deny-read_data"
        );

        assert!(evidence.verify());
    }

    #[test]
    fn engine_denies_undeclared_capability() {
        let agent = test_agent();

        let authority = Authority::new(
            agent.id.clone(),
            "praetore-root",
            vec!["write_data".into()],
        );

        let request =
            AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());
        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
        assert!(evidence.verify());
    }
}
