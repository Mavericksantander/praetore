use serde::{Deserialize, Serialize};

/// The outcome of an authorization decision.
///
/// Ordering is intentional:
/// DENY > REQUIRE_APPROVAL > ALLOW. A `Deny` carrying a
/// [`RecoveryObligation`] ranks above a plain `Deny` (see [`Severity`]).
///
/// ```
/// use praetore_core::DecisionOutcome;
///
/// assert_eq!(
///     DecisionOutcome::Allow.strongest(DecisionOutcome::Deny),
///     DecisionOutcome::Deny,
/// );
/// ```
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
#[serde(deny_unknown_fields)]
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

/// Effective severity of a decision (SAF-10):
/// `Recover > Deny > RequireApproval > Allow`.
///
/// `Recover` is not a fourth [`DecisionOutcome`]: it is a `Deny` that also
/// carries a [`RecoveryObligation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Allow,
    RequireApproval,
    Deny,
    Recover,
}

/// Obligation to enter a predeclared safe mode, produced by a policy rule
/// with effect `Recover`. It never authorizes the proposed action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryObligation {
    /// Safe mode predeclared in the policy.
    pub recovery_id: String,
    /// Rule that produced the obligation.
    pub rule_id: String,
    pub reason: String,
    /// Maximum time to reach the safe mode (`T_recover_max`), in ms; > 0.
    pub deadline_ms: u64,
}

impl RecoveryObligation {
    /// Checks the structural bounds shared by policy loading and evidence.
    pub fn validate(&self) -> Result<(), &'static str> {
        let canonical = |value: &str| !value.trim().is_empty() && value == value.trim();
        if !canonical(&self.recovery_id) || self.recovery_id.len() > 1024 {
            return Err("recovery_id must be a non-empty canonical identifier");
        }
        if !canonical(&self.rule_id) || self.rule_id.len() > 1024 {
            return Err("recovery rule_id must be a non-empty canonical identifier");
        }
        if self.reason.len() > 4096 {
            return Err("recovery reason is too long");
        }
        if self.deadline_ms == 0 || self.deadline_ms > crate::canonical::MAX_SAFE_INTEGER {
            return Err("recovery deadline_ms must be positive and canonically representable");
        }
        Ok(())
    }
}

/// An authorization decision.
///
/// Invariant: `recovery.is_some()` implies `outcome == Deny`. Deserialization
/// rejects any document that violates it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DecisionWire")]
pub struct Decision {
    pub outcome: DecisionOutcome,
    pub reason: String,
    pub contributions: Vec<DecisionContribution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryObligation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionWire {
    outcome: DecisionOutcome,
    reason: String,
    contributions: Vec<DecisionContribution>,
    #[serde(default)]
    recovery: Option<RecoveryObligation>,
}

impl TryFrom<DecisionWire> for Decision {
    type Error = &'static str;

    fn try_from(wire: DecisionWire) -> Result<Self, Self::Error> {
        let decision = Self {
            outcome: wire.outcome,
            reason: wire.reason,
            contributions: wire.contributions,
            recovery: wire.recovery,
        };
        decision.validate_recovery()?;
        Ok(decision)
    }
}

impl Decision {
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            outcome: DecisionOutcome::Allow,
            reason: reason.into(),
            contributions: Vec::new(),

            recovery: None,
        }
    }

    pub fn require_approval(reason: impl Into<String>) -> Self {
        Self {
            outcome: DecisionOutcome::RequireApproval,
            reason: reason.into(),
            contributions: Vec::new(),

            recovery: None,
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            outcome: DecisionOutcome::Deny,
            reason: reason.into(),
            contributions: Vec::new(),

            recovery: None,
        }
    }

    pub fn with_contribution(mut self, contribution: DecisionContribution) -> Self {
        self.contributions.push(contribution);
        self
    }

    /// A `Deny` that carries a recovery obligation.
    pub fn recover(reason: impl Into<String>, recovery: RecoveryObligation) -> Self {
        Self {
            outcome: DecisionOutcome::Deny,
            reason: reason.into(),
            contributions: Vec::new(),
            recovery: Some(recovery),
        }
    }

    /// Effective severity: `Recover` when an obligation is present.
    pub fn severity(&self) -> Severity {
        match (&self.recovery, self.outcome) {
            (Some(_), _) => Severity::Recover,
            (None, DecisionOutcome::Allow) => Severity::Allow,
            (None, DecisionOutcome::RequireApproval) => Severity::RequireApproval,
            (None, DecisionOutcome::Deny) => Severity::Deny,
        }
    }

    /// Checks the recovery invariant and bounds.
    pub fn validate_recovery(&self) -> Result<(), &'static str> {
        match &self.recovery {
            None => Ok(()),
            Some(_) if self.outcome != DecisionOutcome::Deny => {
                Err("a decision with a recovery obligation must deny")
            }
            Some(recovery) => recovery.validate(),
        }
    }

    /// Combines two matching decisions. Admission follows
    /// `DecisionOutcome::strongest` (deny wins). A recovery obligation is never
    /// discarded: the left one is kept if both carry one, and any obligation
    /// forces `Deny`.
    pub fn strongest(self, other: Self) -> Self {
        let recovery = self.recovery.or(other.recovery);
        let outcome = if recovery.is_some() {
            DecisionOutcome::Deny
        } else {
            self.outcome.strongest(other.outcome)
        };

        let reason = if self.outcome == outcome {
            self.reason
        } else {
            other.reason
        };

        let mut contributions = self.contributions;
        contributions.extend(other.contributions);

        Self {
            outcome,
            reason,
            contributions,
            recovery,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obligation(rule_id: &str) -> RecoveryObligation {
        RecoveryObligation {
            recovery_id: "safe-hold".into(),
            rule_id: rule_id.into(),
            reason: "enter safe hold".into(),
            deadline_ms: 500,
        }
    }

    #[test]
    fn recovery_survives_a_deny_and_forces_deny_over_allow() {
        let recover = Decision::recover("recover", obligation("r1"));
        let combined = Decision::allow("ok").strongest(recover.clone());
        assert_eq!(combined.outcome, DecisionOutcome::Deny);
        assert_eq!(combined.recovery, Some(obligation("r1")));
        let combined = recover.clone().strongest(Decision::deny("no"));
        assert_eq!(combined.recovery, Some(obligation("r1")));
        assert_eq!(combined.severity(), Severity::Recover);
        let both = recover.strongest(Decision::recover("x", obligation("r2")));
        assert_eq!(both.recovery, Some(obligation("r1")));
    }

    #[test]
    fn severity_order_is_recover_deny_approval_allow() {
        assert!(Severity::Recover > Severity::Deny);
        assert!(Severity::Deny > Severity::RequireApproval);
        assert!(Severity::RequireApproval > Severity::Allow);
    }

    #[test]
    fn decision_without_recovery_serializes_as_before() {
        let json = serde_json::to_string(&Decision::deny("x")).unwrap();
        assert_eq!(
            json,
            r#"{"outcome":"Deny","reason":"x","contributions":[]}"#
        );
        let parsed: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.recovery, None);
    }

    #[test]
    fn decision_rejects_illegal_recovery_states() {
        let allow = r#"{"outcome":"Allow","reason":"x","contributions":[],"recovery":{"recovery_id":"s","rule_id":"r","reason":"x","deadline_ms":1}}"#;
        assert!(serde_json::from_str::<Decision>(allow).is_err());
        let zero = r#"{"outcome":"Deny","reason":"x","contributions":[],"recovery":{"recovery_id":"s","rule_id":"r","reason":"x","deadline_ms":0}}"#;
        assert!(serde_json::from_str::<Decision>(zero).is_err());
        let unknown = r#"{"outcome":"Deny","reason":"x","contributions":[],"extra":1}"#;
        assert!(serde_json::from_str::<Decision>(unknown).is_err());
    }

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
