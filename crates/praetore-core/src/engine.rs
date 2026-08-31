use crate::{
    authorization::AuthorizationRequest,
    decision::Decision,
    evidence::Evidence,
    policy::Policy,
    PraetoreError,
    Result,
};

use std::sync::Arc;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

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

        if let Some(not_before) = &request.authority.validity.not_before {
            let ts = OffsetDateTime::parse(not_before, &Rfc3339)
                .map_err(|_| PraetoreError::AuthorityVerificationFailed)?;

            if now < ts {
                return Err(PraetoreError::AuthorityVerificationFailed);
            }
        }

        if let Some(not_after) = &request.authority.validity.not_after {
            let ts = OffsetDateTime::parse(not_after, &Rfc3339)
                .map_err(|_| PraetoreError::AuthorityVerificationFailed)?;

            if now > ts {
                return Err(PraetoreError::AuthorityVerificationFailed);
            }
        }

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
        authority::{Authority, Validity},
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
            json!({"table":"users"}),
        )
        .unwrap()
    }

    fn allow_policy() -> Policy {
        Policy::new(
            "test-policy",
            1,
            vec![PolicyRule::allow_action("read_data")],
        )
    }

    fn authority_with_validity(validity: Validity) -> crate::authority::Authority {
        let agent = test_agent();

        Authority::new(
            agent.id.clone(),
            "praetore-root",
            vec!["read_data".into()],
        )
        .with_validity(validity)
    }

    #[test]
    fn authority_within_validity_is_accepted() {
        let agent = test_agent();

        let authority = Authority::new(
            agent.id.clone(),
            "praetore-root",
            vec!["read_data".into()],
        )
        .with_validity(Validity {
            not_before: Some("2026-01-01T00:00:00Z".into()),
            not_after: Some("2026-12-31T23:59:59Z".into()),
        });

        let request =
            crate::AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::with_clock(
            allow_policy(),
            FixedClock::new("2026-06-01T12:00:00Z"),
        );

        assert!(engine.evaluate(request).is_ok());
    }

    #[test]
    fn authority_at_not_before_is_accepted() {
        let agent = test_agent();

        let authority = Authority::new(
            agent.id.clone(),
            "praetore-root",
            vec!["read_data".into()],
        )
        .with_validity(Validity {
            not_before: Some("2026-07-01T00:00:00Z".into()),
            not_after: None,
        });

        let request =
            crate::AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::with_clock(
            allow_policy(),
            FixedClock::new("2026-07-01T00:00:00Z"),
        );

        assert!(engine.evaluate(request).is_ok());
    }

    #[test]
    fn authority_at_not_after_is_accepted() {
        let agent = test_agent();

        let authority = Authority::new(
            agent.id.clone(),
            "praetore-root",
            vec!["read_data".into()],
        )
        .with_validity(Validity {
            not_before: None,
            not_after: Some("2026-07-01T00:00:00Z".into()),
        });

        let request =
            crate::AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::with_clock(
            allow_policy(),
            FixedClock::new("2026-07-01T00:00:00Z"),
        );

        assert!(engine.evaluate(request).is_ok());
    }

    #[test]
    fn authority_not_yet_valid_is_rejected() {
        let agent = test_agent();

        let authority = Authority::new(
            agent.id.clone(),
            "praetore-root",
            vec!["read_data".into()],
        )
        .with_validity(Validity {
            not_before: Some("2026-07-01T00:00:00Z".into()),
            not_after: None,
        });

        let request =
            crate::AuthorizationRequest::new(agent, authority, test_action()).unwrap();

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

        let authority = Authority::new(
            agent.id.clone(),
            "praetore-root",
            vec!["read_data".into()],
        )
        .with_validity(Validity {
            not_before: None,
            not_after: Some("2026-05-01T00:00:00Z".into()),
        });

        let request =
            crate::AuthorizationRequest::new(agent, authority, test_action()).unwrap();

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
