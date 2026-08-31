use serde::{Deserialize, Serialize};

use crate::{
    action::Action,
    authority::Authority,
    decision::{Decision, DecisionContribution},
    error::{PraetoreError, Result},
    identity::AgentIdentity,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub id: String,
    pub version: u32,
    pub rules: Vec<PolicyRule>,
}

impl Policy {
    pub fn new(id: impl Into<String>, version: u32, rules: Vec<PolicyRule>) -> Self {
        Self {
            id: id.into(),
            version,
            rules,
        }
    }

    pub fn evaluate(
        &self,
        agent: &AgentIdentity,
        authority: &Authority,
        action: &Action,
    ) -> Result<Decision> {
        self.validate()?;

        let mut decision = Decision::allow(format!(
            "Policy '{}' v{}: no matching rule",
            self.id, self.version
        ));

        let mut matched = false;

        for rule in &self.rules {
            if !rule.matches(agent, authority, action) {
                continue;
            }

            matched = true;

            let rule_decision = rule.decision()?;

            let contribution = DecisionContribution::new(
                rule.id.clone(),
                rule_decision.outcome,
                rule_decision.reason.clone(),
            );

            let rule_decision = rule_decision.with_contribution(contribution);

            decision = decision.strongest(rule_decision);
        }

        if !matched {
            return Ok(Decision::deny(format!(
                "Policy '{}' v{}: no matching rule; default deny",
                self.id, self.version
            )));
        }

        Ok(decision)
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(PraetoreError::PolicyEvaluationFailed(
                "policy id cannot be empty".into(),
            ));
        }

        if self.version == 0 {
            return Err(PraetoreError::PolicyEvaluationFailed(
                "policy version must be greater than zero".into(),
            ));
        }

        for rule in &self.rules {
            rule.validate()?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRule {
    pub id: String,
    pub action_type: String,
    pub effect: PolicyEffect,
    pub required_capability: Option<String>,
    pub target: Option<String>,
}

impl PolicyRule {
    pub fn new(
        id: impl Into<String>,
        action_type: impl Into<String>,
        effect: PolicyEffect,
    ) -> Self {
        Self {
            id: id.into(),
            action_type: action_type.into(),
            effect,
            required_capability: None,
            target: None,
        }
    }

    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.required_capability = Some(capability.into());
        self
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    fn matches(&self, _agent: &AgentIdentity, authority: &Authority, action: &Action) -> bool {
        if self.action_type != action.action_type {
            return false;
        }

        if let Some(required_capability) = &self.required_capability {
            if !authority.permits(required_capability) {
                return false;
            }
        }

        if let Some(required_target) = &self.target {
            if action.target.as_deref() != Some(required_target.as_str()) {
                return false;
            }
        }

        true
    }

    fn decision(&self) -> Result<Decision> {
        let reason = format!("Policy rule '{}' matched", self.id);

        match self.effect {
            PolicyEffect::Allow => Ok(Decision::allow(reason)),
            PolicyEffect::Deny => Ok(Decision::deny(reason)),
            PolicyEffect::RequireApproval => Ok(Decision::require_approval(reason)),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(PraetoreError::PolicyEvaluationFailed(
                "policy rule id cannot be empty".into(),
            ));
        }

        if self.action_type.trim().is_empty() {
            return Err(PraetoreError::PolicyEvaluationFailed(format!(
                "policy rule '{}' has empty action_type",
                self.id
            )));
        }

        if let Some(capability) = &self.required_capability {
            if capability.trim().is_empty() {
                return Err(PraetoreError::PolicyEvaluationFailed(format!(
                    "policy rule '{}' has empty capability",
                    self.id
                )));
            }
        }

        if let Some(target) = &self.target {
            if target.trim().is_empty() {
                return Err(PraetoreError::PolicyEvaluationFailed(format!(
                    "policy rule '{}' has empty target",
                    self.id
                )));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyEffect {
    Allow,
    Deny,
    RequireApproval,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::Action, authority::Authority, decision::DecisionOutcome, identity::AgentIdentity,
    };
    use serde_json::json;

    fn test_agent() -> AgentIdentity {
        let id = crate::identity::AgentId::new();

        AgentIdentity::new(id, b"test-public-key".to_vec(), "ed25519").unwrap()
    }

    fn test_action() -> Action {
        Action::new(
            "read_data",
            Some("database".into()),
            json!({"table": "users"}),
        )
        .unwrap()
    }

    #[test]
    fn policy_allows_matching_rule() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = Policy::new(
            "production",
            1,
            vec![PolicyRule::new(
                "allow-read",
                "read_data",
                PolicyEffect::Allow,
            )],
        );

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        assert_eq!(decision.contributions.len(), 1);
        assert_eq!(decision.contributions[0].rule_id, "allow-read");
    }

    #[test]
    fn policy_denies_matching_rule() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = Policy::new(
            "production",
            1,
            vec![PolicyRule::new(
                "deny-read",
                "read_data",
                PolicyEffect::Deny,
            )],
        );

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.contributions.len(), 1);
        assert_eq!(decision.contributions[0].rule_id, "deny-read");
    }

    #[test]
    fn policy_requires_approval() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = Policy::new(
            "production",
            1,
            vec![PolicyRule::new(
                "approval-read",
                "read_data",
                PolicyEffect::RequireApproval,
            )],
        );

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::RequireApproval);
        assert_eq!(decision.contributions.len(), 1);
        assert_eq!(decision.contributions[0].rule_id, "approval-read");
    }

    #[test]
    fn unmatched_rule_denies_by_default() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = Policy::new(
            "production",
            1,
            vec![PolicyRule::new(
                "allow-write",
                "write_data",
                PolicyEffect::Allow,
            )],
        );

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert!(decision.contributions.is_empty());
    }

    #[test]
    fn capability_constraint_denies_when_capability_is_missing() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow)
                    .with_capability("admin:data"),
            ],
        );

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert!(decision.contributions.is_empty());
    }

    #[test]
    fn target_constraint_is_enforced() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("deny-database", "read_data", PolicyEffect::Deny)
                    .with_target("database"),
            ],
        );

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.contributions.len(), 1);
    }

    #[test]
    fn deny_beats_allow_when_multiple_rules_match() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow),
                PolicyRule::new("deny-read", "read_data", PolicyEffect::Deny),
            ],
        );

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.contributions.len(), 2);
    }

    #[test]
    fn approval_beats_allow_when_multiple_rules_match() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow),
                PolicyRule::new("approval-read", "read_data", PolicyEffect::RequireApproval),
            ],
        );

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::RequireApproval);
        assert_eq!(decision.contributions.len(), 2);
    }

    #[test]
    fn deny_beats_approval_when_multiple_rules_match() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("approval-read", "read_data", PolicyEffect::RequireApproval),
                PolicyRule::new("deny-read", "read_data", PolicyEffect::Deny),
            ],
        );

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.contributions.len(), 2);
    }

    #[test]
    fn decision_is_independent_of_rule_order() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let first = Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow),
                PolicyRule::new("deny-read", "read_data", PolicyEffect::Deny),
            ],
        );

        let second = Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("deny-read", "read_data", PolicyEffect::Deny),
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow),
            ],
        );

        let first_decision = first.evaluate(&agent, &authority, &test_action()).unwrap();
        let second_decision = second.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(first_decision.outcome, DecisionOutcome::Deny);
        assert_eq!(second_decision.outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn allow_combined_with_allow_remains_allow() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("allow-read-1", "read_data", PolicyEffect::Allow),
                PolicyRule::new("allow-read-2", "read_data", PolicyEffect::Allow),
            ],
        );

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        assert_eq!(decision.contributions.len(), 2);
    }

    #[test]
    fn deny_combined_with_deny_remains_deny() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("deny-read-1", "read_data", PolicyEffect::Deny),
                PolicyRule::new("deny-read-2", "read_data", PolicyEffect::Deny),
            ],
        );

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.contributions.len(), 2);
    }

    #[test]
    fn policy_rejects_empty_id() {
        let policy = Policy::new("", 1, vec![]);

        assert!(policy.validate().is_err());
    }

    #[test]
    fn policy_rejects_zero_version() {
        let policy = Policy::new("production", 0, vec![]);

        assert!(policy.validate().is_err());
    }

    #[test]
    fn policy_evaluate_rejects_empty_id() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = Policy::new(
            "",
            1,
            vec![PolicyRule::new(
                "allow-read",
                "read_data",
                PolicyEffect::Allow,
            )],
        );

        let result = policy.evaluate(&agent, &authority, &test_action());

        assert!(matches!(
            result,
            Err(PraetoreError::PolicyEvaluationFailed(_))
        ));
    }

    #[test]
    fn policy_evaluate_rejects_zero_version() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = Policy::new(
            "production",
            0,
            vec![PolicyRule::new(
                "allow-read",
                "read_data",
                PolicyEffect::Allow,
            )],
        );

        let result = policy.evaluate(&agent, &authority, &test_action());

        assert!(matches!(
            result,
            Err(PraetoreError::PolicyEvaluationFailed(_))
        ));
    }
}
