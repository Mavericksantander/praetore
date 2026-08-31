use serde::{Deserialize, Serialize};

/// The outcome of an authorization decision.
///
/// Ordering is intentional:
/// DENY > REQUIRE_APPROVAL > ALLOW
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionOutcome {
    Allow,
    RequireApproval,
    Deny,
}

impl DecisionOutcome {
    /// Returns the strongest outcome between two decisions.
    pub fn strongest(self, other: Self) -> Self {
        use DecisionOutcome::*;

        match (self, other) {
            (Deny, _) | (_, Deny) => Deny,
            (RequireApproval, _) | (_, RequireApproval) => RequireApproval,
            (Allow, Allow) => Allow,
        }
    }

    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn requires_approval(self) -> bool {
        matches!(self, Self::RequireApproval)
    }

    pub fn is_denied(self) -> bool {
        matches!(self, Self::Deny)
    }
}

/// A single policy rule that contributed to a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionContribution {
    pub rule_id: String,
    pub outcome: DecisionOutcome,
    pub reason: String,
}

impl DecisionContribution {
    pub fn new(
        rule_id: impl Into<String>,
        outcome: DecisionOutcome,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            outcome,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub outcome: DecisionOutcome,
    pub reason: String,
    pub contributions: Vec<DecisionContribution>,
}

impl Decision {
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            outcome: DecisionOutcome::Allow,
            reason: reason.into(),
            contributions: Vec::new(),
        }
    }

    pub fn require_approval(reason: impl Into<String>) -> Self {
        Self {
            outcome: DecisionOutcome::RequireApproval,
            reason: reason.into(),
            contributions: Vec::new(),
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            outcome: DecisionOutcome::Deny,
            reason: reason.into(),
            contributions: Vec::new(),
        }
    }

    pub fn with_contribution(mut self, contribution: DecisionContribution) -> Self {
        self.contributions.push(contribution);
        self
    }

    pub fn strongest(self, other: Self) -> Self {
        let outcome = self.outcome.strongest(other.outcome);

        let reason = if self.outcome == outcome {
            self.reason.clone()
        } else {
            other.reason.clone()
        };

        let mut contributions = self.contributions;
        contributions.extend(other.contributions);

        Self {
            outcome,
            reason,
            contributions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_beats_everything() {
        assert_eq!(
            DecisionOutcome::Deny.strongest(DecisionOutcome::Allow),
            DecisionOutcome::Deny
        );

        assert_eq!(
            DecisionOutcome::Deny.strongest(DecisionOutcome::RequireApproval),
            DecisionOutcome::Deny
        );
    }

    #[test]
    fn approval_beats_allow() {
        assert_eq!(
            DecisionOutcome::RequireApproval.strongest(DecisionOutcome::Allow),
            DecisionOutcome::RequireApproval
        );
    }

    #[test]
    fn allow_does_not_override_approval() {
        assert_eq!(
            DecisionOutcome::Allow.strongest(DecisionOutcome::RequireApproval),
            DecisionOutcome::RequireApproval
        );
    }

    #[test]
    fn allow_combined_with_allow_remains_allow() {
        assert_eq!(
            DecisionOutcome::Allow.strongest(DecisionOutcome::Allow),
            DecisionOutcome::Allow
        );
    }

    #[test]
    fn decision_preserves_reason() {
        let decision = Decision::deny("Policy violation");

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.reason, "Policy violation");
    }

    #[test]
    fn decision_helpers_construct_expected_outcomes() {
        assert!(Decision::allow("ok").outcome.is_allowed());
        assert!(
            Decision::require_approval("review")
                .outcome
                .requires_approval()
        );
        assert!(Decision::deny("blocked").outcome.is_denied());
    }

    #[test]
    fn decision_can_record_contribution() {
        let decision = Decision::deny("blocked").with_contribution(DecisionContribution::new(
            "deny-delete",
            DecisionOutcome::Deny,
            "delete operations are forbidden",
        ));

        assert_eq!(decision.contributions.len(), 1);
        assert_eq!(decision.contributions[0].rule_id, "deny-delete");
        assert_eq!(decision.contributions[0].outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn strongest_combines_contributions_for_equal_outcomes() {
        let first = Decision::allow("first").with_contribution(DecisionContribution::new(
            "allow-read",
            DecisionOutcome::Allow,
            "read permitted",
        ));

        let second = Decision::allow("second").with_contribution(DecisionContribution::new(
            "allow-users",
            DecisionOutcome::Allow,
            "users permitted",
        ));

        let combined = first.strongest(second);

        assert_eq!(combined.outcome, DecisionOutcome::Allow);
        assert_eq!(combined.contributions.len(), 2);
    }

    #[test]
    fn strongest_preserves_reason_of_stronger_decision() {
        let allow = Decision::allow("read operation permitted").with_contribution(
            DecisionContribution::new(
                "allow-read",
                DecisionOutcome::Allow,
                "read operation permitted",
            ),
        );

        let deny = Decision::deny("read operation forbidden").with_contribution(
            DecisionContribution::new(
                "deny-read",
                DecisionOutcome::Deny,
                "read operation forbidden",
            ),
        );

        let combined = allow.strongest(deny);

        assert_eq!(combined.outcome, DecisionOutcome::Deny);
        assert_eq!(combined.reason, "read operation forbidden");
        assert_eq!(combined.contributions.len(), 2);
    }

    #[test]
    fn strongest_is_associative_for_outcome_and_contributions() {
        let allow = Decision::allow("allowed").with_contribution(DecisionContribution::new(
            "allow-read",
            DecisionOutcome::Allow,
            "allowed",
        ));

        let approval = Decision::require_approval("approval required").with_contribution(
            DecisionContribution::new(
                "approval-read",
                DecisionOutcome::RequireApproval,
                "approval required",
            ),
        );

        let deny = Decision::deny("denied").with_contribution(DecisionContribution::new(
            "deny-read",
            DecisionOutcome::Deny,
            "denied",
        ));

        let left = allow
            .clone()
            .strongest(approval.clone())
            .strongest(deny.clone());
        let right = allow.strongest(approval.strongest(deny));

        assert_eq!(left.outcome, right.outcome);
        assert_eq!(left.reason, right.reason);

        let left_rule_ids: std::collections::HashSet<_> = left
            .contributions
            .iter()
            .map(|c| c.rule_id.as_str())
            .collect();

        let right_rule_ids: std::collections::HashSet<_> = right
            .contributions
            .iter()
            .map(|c| c.rule_id.as_str())
            .collect();

        assert_eq!(left_rule_ids, right_rule_ids);
    }

    #[test]
    fn strongest_is_commutative_for_outcome_and_contributions() {
        let allow = Decision::allow("allowed").with_contribution(DecisionContribution::new(
            "allow-read",
            DecisionOutcome::Allow,
            "allowed",
        ));

        let deny = Decision::deny("denied").with_contribution(DecisionContribution::new(
            "deny-read",
            DecisionOutcome::Deny,
            "denied",
        ));

        let first = allow.clone().strongest(deny.clone());
        let second = deny.strongest(allow);

        assert_eq!(first.outcome, second.outcome);
        assert_eq!(first.reason, second.reason);

        let first_rule_ids: std::collections::HashSet<_> = first
            .contributions
            .iter()
            .map(|c| c.rule_id.as_str())
            .collect();
        let second_rule_ids: std::collections::HashSet<_> = second
            .contributions
            .iter()
            .map(|c| c.rule_id.as_str())
            .collect();

        assert_eq!(first_rule_ids, second_rule_ids);
    }
}
