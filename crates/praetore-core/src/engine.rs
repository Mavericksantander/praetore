use crate::{
    PraetoreError, Result, authorization::AuthorizationRequest, decision::Decision,
    evidence::Evidence, policy::Policy,
};

use std::sync::Arc;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

#[derive(Debug, Clone)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[derive(Debug, Clone)]
pub struct FixedClock {
    instant: OffsetDateTime,
}

impl FixedClock {
    pub fn new(timestamp: &str) -> Self {
        Self {
            instant: OffsetDateTime::parse(timestamp, &Rfc3339).unwrap(),
        }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.instant
    }
}

#[derive(Clone)]
pub struct AuthorizationEngine {
    policy: Policy,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for AuthorizationEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationEngine")
            .field("policy", &self.policy)
            .finish()
    }
}

impl AuthorizationEngine {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            clock: Arc::new(SystemClock),
        }
    }

    pub fn with_clock(policy: Policy, clock: impl Clock + 'static) -> Self {
        Self {
            policy,
            clock: Arc::new(clock),
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn evaluate(&self, request: AuthorizationRequest) -> Result<Evidence> {
        let decision = self.evaluate_request(&request)?;
        Ok(request.attest(decision))
    }

    fn evaluate_request(&self, request: &AuthorizationRequest) -> Result<Decision> {
        request.authority.validate()?;

        let now = self.clock.now();

        if !request.authority.validity.is_active_at(now)? {
            return Err(PraetoreError::AuthorityVerificationFailed);
        }

        for constraint in &request.authority.constraints {
            let satisfied = if constraint.key == "target" {
                request.action.target.as_deref() == Some(constraint.value.as_str())
            } else {
                request
                    .action
                    .parameters
                    .get(&constraint.key)
                    .and_then(|v| v.as_str())
                    == Some(constraint.value.as_str())
            };

            if !satisfied {
                return Ok(Decision::deny(format!(
                    "authority constraint '{}' was not satisfied",
                    constraint.key
                )));
            }
        }

        if !request.authority.permits(&request.action.action_type) {
            return Ok(Decision::deny(format!(
                "authority does not permit action type: {}",
                request.action.action_type
            )));
        }

        self.policy
            .evaluate(&request.agent, &request.authority, &request.action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::Action,
        authority::{Authority, Validity},
        decision::DecisionOutcome,
        identity::{AgentId, AgentIdentity},
        policy::{Policy, PolicyRule},
    };
    use serde_json::json;

    fn test_agent() -> AgentIdentity {
        AgentIdentity::new(AgentId::new(), b"test-public-key".to_vec(), "ed25519").unwrap()
    }

    fn test_action() -> Action {
        Action::new(
            "read_data",
            Some("database".into()),
            json!({"table":"users","environment":"production"}),
        )
        .unwrap()
    }

    fn allow_policy() -> Policy {
        Policy::new(
            "test-policy",
            1,
            vec![PolicyRule::new(
                "allow-read-data",
                "read_data",
                crate::policy::PolicyEffect::Allow,
            )],
        )
    }

    #[test]
    fn engine_allows_authorized_action() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());
        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Allow);
        assert!(evidence.verify());
    }

    #[test]
    fn authority_within_validity_is_accepted() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_validity(Validity {
                not_before: Some("2026-01-01T00:00:00Z".into()),
                not_after: Some("2026-12-31T23:59:59Z".into()),
            });

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::with_clock(
            allow_policy(),
            FixedClock::new("2026-06-01T12:00:00Z"),
        );

        assert!(engine.evaluate(request).is_ok());
    }

    #[test]
    fn authority_target_constraint_is_enforced() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_constraint("target", "database");

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());

        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Allow);
    }

    #[test]
    fn authority_parameter_constraint_is_enforced() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_constraint("environment", "production");

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());

        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Allow);
    }

    #[test]
    fn authority_constraint_mismatch_denies() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_constraint("environment", "staging");

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());

        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn authority_target_constraint_mismatch_denies() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_constraint("target", "other-database");

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());
        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn authority_missing_parameter_constraint_denies() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_constraint("region", "santiago");

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());
        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn authority_requires_all_constraints() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_constraint("target", "database")
            .with_constraint("environment", "staging");

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());
        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn engine_preserves_policy_contributions() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let policy = Policy::new(
            "test-policy",
            1,
            vec![
                PolicyRule::new(
                    "allow-read-data",
                    "read_data",
                    crate::policy::PolicyEffect::Allow,
                ),
                PolicyRule::new(
                    "deny-read-data",
                    "read_data",
                    crate::policy::PolicyEffect::Deny,
                ),
            ],
        );

        let engine = AuthorizationEngine::new(policy);
        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
        assert_eq!(evidence.decision.contributions.len(), 2);
        assert!(evidence.verify());
    }

    #[test]
    fn engine_rejects_invalid_authority() {
        let agent = test_agent();

        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);

        authority.issuer = String::new();

        let result = AuthorizationRequest::new(agent, authority, test_action());

        assert!(matches!(result, Err(PraetoreError::InvalidRequest(_))));
    }

    #[test]
    fn engine_denies_undeclared_capability() {
        let agent = test_agent();

        let authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["write_data".into()]);

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());
        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
        assert!(evidence.verify());
    }

    #[test]
    fn authority_not_yet_valid_is_rejected() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_validity(Validity {
                not_before: Some("2026-07-01T00:00:00Z".into()),
                not_after: None,
            });

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::with_clock(
            allow_policy(),
            FixedClock::new("2026-06-01T12:00:00Z"),
        );

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::AuthorityVerificationFailed)
        ));
    }

    #[test]
    fn authority_expired_is_rejected() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_validity(Validity {
                not_before: None,
                not_after: Some("2026-05-01T00:00:00Z".into()),
            });

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::with_clock(
            allow_policy(),
            FixedClock::new("2026-06-01T12:00:00Z"),
        );

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::AuthorityVerificationFailed)
        ));
    }
}
