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

/// What determined the final outcome of a decision.
///
/// Recorded inside [`Decision`], so it is covered by the evidence context
/// hash and the Ed25519 attester signature (evidence schema v4 onwards).
/// Unknown `kind` values and unknown fields are rejected (fail closed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", from = "DecidedByWire")]
pub enum DecidedBy {
    /// A policy rule matched and its declared effect (Allow, Deny,
    /// RequireApproval or Recover) determined the outcome. For a Recover
    /// rule the outcome is `Deny` and `rule_id` equals the recovery
    /// obligation's `rule_id`.
    Rule { rule_id: String },
    /// A restrictive RequireApproval or Recover rule matched only because the
    /// authority lacks its `required_capability` or the action has no target
    /// (`RuleMatch::Unbound`). Its declared effect was NOT applied: the engine
    /// denied instead (fail closed).
    UnboundRule { rule_id: String },
    /// No policy rule matched; the policy denied by default.
    DefaultDeny,
    /// An engine check outside the policy rules denied the request
    /// (for example an unsatisfied authority constraint).
    EngineGuard { guard: String },
}

/// Deserialization form of [`DecidedBy`]. `DefaultDeny` is a struct variant
/// here because serde's `deny_unknown_fields` ignores extra fields on unit
/// variants of an internally tagged enum.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum DecidedByWire {
    Rule { rule_id: String },
    UnboundRule { rule_id: String },
    DefaultDeny {},
    EngineGuard { guard: String },
}

impl From<DecidedByWire> for DecidedBy {
    fn from(wire: DecidedByWire) -> Self {
        match wire {
            DecidedByWire::Rule { rule_id } => Self::Rule { rule_id },
            DecidedByWire::UnboundRule { rule_id } => Self::UnboundRule { rule_id },
            DecidedByWire::DefaultDeny {} => Self::DefaultDeny,
            DecidedByWire::EngineGuard { guard } => Self::EngineGuard { guard },
        }
    }
}

/// Absent means `None`; an explicit `null` is rejected, so a legacy receipt
/// has exactly one encoding.
fn present_decided_by<'de, D>(deserializer: D) -> Result<Option<DecidedBy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    DecidedBy::deserialize(deserializer).map(Some)
}

impl DecidedBy {
    pub fn rule(rule_id: impl Into<String>) -> Self {
        Self::Rule {
            rule_id: rule_id.into(),
        }
    }

    pub fn unbound_rule(rule_id: impl Into<String>) -> Self {
        Self::UnboundRule {
            rule_id: rule_id.into(),
        }
    }

    pub fn engine_guard(guard: impl Into<String>) -> Self {
        Self::EngineGuard {
            guard: guard.into(),
        }
    }

    fn validate(&self) -> Result<(), &'static str> {
        let identifier =
            |value: &str| !value.trim().is_empty() && value == value.trim() && value.len() <= 1024;
        match self {
            Self::Rule { rule_id } | Self::UnboundRule { rule_id } if !identifier(rule_id) => {
                Err("decided_by rule_id must be a non-empty canonical identifier")
            }
            Self::EngineGuard { guard } if !identifier(guard) => {
                Err("decided_by guard must be a non-empty canonical identifier")
            }
            _ => Ok(()),
        }
    }
}

/// Checks that `decided_by` is consistent with the rest of the decision, so a
/// receipt cannot name a decider that did not produce its outcome.
///
/// Contributions are the evaluation trace. A decision built directly by an
/// integrator may carry none; when present, a `Rule`/`UnboundRule` decider
/// must be one of them with the final outcome, and that outcome must be the
/// strongest contributed one.
fn validate_decided_by(
    outcome: DecisionOutcome,
    contributions: &[DecisionContribution],
    recovery: Option<&RecoveryObligation>,
    decided_by: &DecidedBy,
) -> Result<(), &'static str> {
    decided_by.validate()?;
    let contributed = |rule_id: &str, outcome: DecisionOutcome| {
        contributions.is_empty()
            || contributions.iter().any(|contribution| {
                contribution.rule_id == rule_id && contribution.outcome == outcome
            })
    };
    match decided_by {
        DecidedBy::Rule { rule_id } => {
            if recovery.is_some_and(|recovery| recovery.rule_id != *rule_id) {
                return Err("decided_by must name the rule that produced the recovery obligation");
            }
            if !contributed(rule_id, outcome) {
                return Err("decided_by rule has no contribution with the decision outcome");
            }
            let strongest = contributions
                .iter()
                .map(|contribution| contribution.outcome)
                .reduce(DecisionOutcome::strongest);
            if strongest.is_some_and(|strongest| strongest != outcome) {
                return Err("decision outcome is not the strongest contribution");
            }
            Ok(())
        }
        _ if recovery.is_some() => Err("a recovery obligation must be decided by its rule"),
        _ if outcome != DecisionOutcome::Deny => {
            Err("only a policy rule can decide a non-deny outcome")
        }
        DecidedBy::UnboundRule { rule_id } if !contributed(rule_id, DecisionOutcome::Deny) => {
            Err("decided_by unbound rule has no deny contribution")
        }
        DecidedBy::DefaultDeny if !contributions.is_empty() => {
            Err("a default deny cannot have rule contributions")
        }
        _ => Ok(()),
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

fn severity(outcome: DecisionOutcome, recovery: Option<&RecoveryObligation>) -> Severity {
    match (recovery, outcome) {
        (Some(_), _) => Severity::Recover,
        (None, DecisionOutcome::Allow) => Severity::Allow,
        (None, DecisionOutcome::RequireApproval) => Severity::RequireApproval,
        (None, DecisionOutcome::Deny) => Severity::Deny,
    }
}

fn validate_recovery(
    outcome: DecisionOutcome,
    recovery: Option<&RecoveryObligation>,
) -> Result<(), &'static str> {
    match recovery {
        None => Ok(()),
        Some(_) if outcome != DecisionOutcome::Deny => {
            Err("a decision with a recovery obligation must deny")
        }
        Some(recovery) => recovery.validate(),
    }
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

/// A decision produced by evaluation. This is the only type that can be
/// attested into new evidence, and it cannot exist without `decided_by`:
/// every constructor requires it and the field is not optional.
///
/// Invariants (checked on deserialization, by [`Decision::validate`] and when
/// the decision is attested): `recovery.is_some()` implies `outcome == Deny`
/// and `decided_by == Rule { rule_id: recovery.rule_id }`; `decided_by` is
/// consistent with `contributions` (see [`DecidedBy`]).
///
/// ```compile_fail
/// // A new decision cannot be built without saying who decided it.
/// let _ = praetore_core::Decision::allow("ok");
/// ```
///
/// ```compile_fail
/// // Nor can a recorded decision be stripped of it outside praetore-core.
/// fn strip(evidence: &mut praetore_core::Evidence) {
///     evidence.decision.decided_by = None;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DecisionWire")]
pub struct Decision {
    pub outcome: DecisionOutcome,
    pub reason: String,
    pub contributions: Vec<DecisionContribution>,
    /// What determined `outcome`. Always present on newly produced decisions.
    pub decided_by: DecidedBy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryObligation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionWire {
    outcome: DecisionOutcome,
    reason: String,
    contributions: Vec<DecisionContribution>,
    decided_by: DecidedBy,
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
            decided_by: wire.decided_by,
            recovery: wire.recovery,
        };
        decision.validate()?;
        Ok(decision)
    }
}

impl Decision {
    pub fn new(outcome: DecisionOutcome, reason: impl Into<String>, decided_by: DecidedBy) -> Self {
        Self {
            outcome,
            reason: reason.into(),
            contributions: Vec::new(),
            decided_by,
            recovery: None,
        }
    }

    pub fn allow(reason: impl Into<String>, decided_by: DecidedBy) -> Self {
        Self::new(DecisionOutcome::Allow, reason, decided_by)
    }

    pub fn require_approval(reason: impl Into<String>, decided_by: DecidedBy) -> Self {
        Self::new(DecisionOutcome::RequireApproval, reason, decided_by)
    }

    pub fn deny(reason: impl Into<String>, decided_by: DecidedBy) -> Self {
        Self::new(DecisionOutcome::Deny, reason, decided_by)
    }

    pub fn with_contribution(mut self, contribution: DecisionContribution) -> Self {
        self.contributions.push(contribution);
        self
    }

    /// A `Deny` that carries a recovery obligation. It is decided by the rule
    /// that produced the obligation (`DecidedBy::Rule { recovery.rule_id }`).
    pub fn recover(reason: impl Into<String>, recovery: RecoveryObligation) -> Self {
        Self {
            outcome: DecisionOutcome::Deny,
            reason: reason.into(),
            contributions: Vec::new(),
            decided_by: DecidedBy::rule(recovery.rule_id.clone()),
            recovery: Some(recovery),
        }
    }

    /// Effective severity: `Recover` when an obligation is present.
    pub fn severity(&self) -> Severity {
        severity(self.outcome, self.recovery.as_ref())
    }

    /// Checks the recovery invariant and bounds.
    pub fn validate_recovery(&self) -> Result<(), &'static str> {
        validate_recovery(self.outcome, self.recovery.as_ref())
    }

    /// Checks every invariant: recovery, and `decided_by` against the
    /// outcome, the recovery obligation and the contributions.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.validate_recovery()?;
        validate_decided_by(
            self.outcome,
            &self.contributions,
            self.recovery.as_ref(),
            &self.decided_by,
        )
    }

    /// Combines two matching decisions. Admission follows
    /// `DecisionOutcome::strongest` (deny wins). A recovery obligation is never
    /// discarded: the left one is kept if both carry one, and any obligation
    /// forces `Deny`.
    ///
    /// `decided_by` comes from the decision with the higher [`Severity`]
    /// (`Recover > Deny > RequireApproval > Allow`); on a tie the left-hand
    /// (earlier) decision keeps it. This agrees with the kept obligation: a
    /// combined Recover decision is always decided by the obligation's rule.
    pub fn strongest(self, other: Self) -> Self {
        let decided_by = if self.severity() >= other.severity() {
            self.decided_by
        } else {
            other.decided_by
        };
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
            decided_by,
            recovery,
        }
    }
}

/// The decision as recorded inside a receipt (`Evidence`). This is the read
/// side: receipts produced before `decided_by` existed (evidence schema
/// v1-v3) deserialize with it absent and keep verifying, because `None` is
/// omitted from the canonical form. Evidence v4 requires it. A
/// `RecordedDecision` can only be obtained from a [`Decision`] (which always
/// carries `decided_by`) or by deserializing an existing receipt;
/// `decided_by` is crate-private, so callers outside `praetore-core` cannot
/// strip it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RecordedDecisionWire")]
pub struct RecordedDecision {
    pub outcome: DecisionOutcome,
    pub reason: String,
    pub contributions: Vec<DecisionContribution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) decided_by: Option<DecidedBy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryObligation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedDecisionWire {
    outcome: DecisionOutcome,
    reason: String,
    contributions: Vec<DecisionContribution>,
    #[serde(default, deserialize_with = "present_decided_by")]
    decided_by: Option<DecidedBy>,
    #[serde(default)]
    recovery: Option<RecoveryObligation>,
}

impl TryFrom<RecordedDecisionWire> for RecordedDecision {
    type Error = &'static str;

    fn try_from(wire: RecordedDecisionWire) -> Result<Self, Self::Error> {
        let decision = Self {
            outcome: wire.outcome,
            reason: wire.reason,
            contributions: wire.contributions,
            decided_by: wire.decided_by,
            recovery: wire.recovery,
        };
        decision.validate()?;
        Ok(decision)
    }
}

impl RecordedDecision {
    /// `None` only for legacy receipts (evidence schema v1-v3) produced
    /// before the field existed.
    pub fn decided_by(&self) -> Option<&DecidedBy> {
        self.decided_by.as_ref()
    }

    /// Effective severity: `Recover` when an obligation is present.
    pub fn severity(&self) -> Severity {
        severity(self.outcome, self.recovery.as_ref())
    }

    /// Checks the recovery invariant and bounds.
    pub fn validate_recovery(&self) -> Result<(), &'static str> {
        validate_recovery(self.outcome, self.recovery.as_ref())
    }

    /// Checks the recovery invariant and, when present, `decided_by`
    /// consistency (see [`Decision::validate`]).
    pub fn validate(&self) -> Result<(), &'static str> {
        self.validate_recovery()?;
        match &self.decided_by {
            None => Ok(()),
            Some(decided_by) => validate_decided_by(
                self.outcome,
                &self.contributions,
                self.recovery.as_ref(),
                decided_by,
            ),
        }
    }
}

impl RecordedDecision {
    /// True when this recorded decision is what `decision` would record.
    /// A legacy record (no `decided_by`, evidence v1-v3) is compared on every
    /// other field, so an approval pending across the upgrade to v4 can still
    /// be revalidated against a fresh evaluation.
    pub(crate) fn records(&self, decision: Decision) -> bool {
        let mut fresh = Self::from(decision);
        if self.decided_by.is_none() {
            fresh.decided_by = None;
        }
        fresh == *self
    }
}

impl From<Decision> for RecordedDecision {
    fn from(decision: Decision) -> Self {
        Self {
            outcome: decision.outcome,
            reason: decision.reason,
            contributions: decision.contributions,
            decided_by: Some(decision.decided_by),
            recovery: decision.recovery,
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

    fn rule_decision(decision: Decision, rule_id: &str) -> Decision {
        let contribution =
            DecisionContribution::new(rule_id, decision.outcome, decision.reason.clone());
        decision.with_contribution(contribution)
    }

    #[test]
    fn recovery_survives_a_deny_and_forces_deny_over_allow() {
        let recover = Decision::recover("recover", obligation("r1"));
        let combined = Decision::allow("ok", DecidedBy::rule("a")).strongest(recover.clone());
        assert_eq!(combined.outcome, DecisionOutcome::Deny);
        assert_eq!(combined.recovery, Some(obligation("r1")));
        let combined = recover
            .clone()
            .strongest(Decision::deny("no", DecidedBy::rule("d")));
        assert_eq!(combined.recovery, Some(obligation("r1")));
        assert_eq!(combined.severity(), Severity::Recover);
        let both = recover.strongest(Decision::recover("x", obligation("r2")));
        assert_eq!(both.recovery, Some(obligation("r1")));
    }

    #[test]
    fn recover_is_decided_by_the_obligation_rule_in_any_combination() {
        let recover = || rule_decision(Decision::recover("recover", obligation("r1")), "r1");
        let allow = || rule_decision(Decision::allow("ok", DecidedBy::rule("a")), "a");
        let deny = || rule_decision(Decision::deny("no", DecidedBy::rule("d")), "d");
        let approve = || {
            rule_decision(
                Decision::require_approval("review", DecidedBy::rule("p")),
                "p",
            )
        };
        assert_eq!(recover().decided_by, DecidedBy::rule("r1"));
        for other in [allow(), deny(), approve()] {
            for combined in [
                recover().strongest(other.clone()),
                other.clone().strongest(recover()),
            ] {
                assert_eq!(combined.decided_by, DecidedBy::rule("r1"));
                assert_eq!(combined.severity(), Severity::Recover);
                combined.validate().unwrap();
            }
        }
        // First Recover wins, and so does its decider.
        let second = rule_decision(Decision::recover("x", obligation("r2")), "r2");
        let both = recover().strongest(second);
        assert_eq!(both.decided_by, DecidedBy::rule("r1"));
        assert_eq!(both.recovery.as_ref().unwrap().rule_id, "r1");
        both.validate().unwrap();
    }

    #[test]
    fn decided_by_follows_severity_and_ties_keep_the_left_decider() {
        let allow = |id: &str| rule_decision(Decision::allow("ok", DecidedBy::rule(id)), id);
        let deny = |id: &str| rule_decision(Decision::deny("no", DecidedBy::rule(id)), id);
        assert_eq!(
            allow("a").strongest(deny("d")).decided_by,
            DecidedBy::rule("d")
        );
        assert_eq!(
            deny("d").strongest(allow("a")).decided_by,
            DecidedBy::rule("d")
        );
        assert_eq!(
            deny("d1").strongest(deny("d2")).decided_by,
            DecidedBy::rule("d1")
        );
        assert_eq!(
            allow("a1").strongest(allow("a2")).decided_by,
            DecidedBy::rule("a1")
        );
    }

    #[test]
    fn severity_order_is_recover_deny_approval_allow() {
        assert!(Severity::Recover > Severity::Deny);
        assert!(Severity::Deny > Severity::RequireApproval);
        assert!(Severity::RequireApproval > Severity::Allow);
    }

    #[test]
    fn decision_without_recovery_serializes_without_recovery_field() {
        let decision = Decision::deny("x", DecidedBy::DefaultDeny);
        let json = serde_json::to_string(&decision).unwrap();
        assert_eq!(
            json,
            r#"{"outcome":"Deny","reason":"x","contributions":[],"decided_by":{"kind":"default_deny"}}"#
        );
        let parsed: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.recovery, None);
        // A legacy recorded decision (no decided_by, no recovery) keeps its
        // exact serialization.
        let legacy = r#"{"outcome":"Deny","reason":"x","contributions":[]}"#;
        let recorded: RecordedDecision = serde_json::from_str(legacy).unwrap();
        assert_eq!(serde_json::to_string(&recorded).unwrap(), legacy);
    }

    #[test]
    fn decision_rejects_illegal_recovery_states() {
        let allow = r#"{"outcome":"Allow","reason":"x","contributions":[{"rule_id":"r","outcome":"Allow","reason":"x"}],"decided_by":{"kind":"rule","rule_id":"r"},"recovery":{"recovery_id":"s","rule_id":"r","reason":"x","deadline_ms":1}}"#;
        assert!(serde_json::from_str::<Decision>(allow).is_err());
        assert!(serde_json::from_str::<RecordedDecision>(allow).is_err());
        let zero = r#"{"outcome":"Deny","reason":"x","contributions":[{"rule_id":"r","outcome":"Deny","reason":"x"}],"decided_by":{"kind":"rule","rule_id":"r"},"recovery":{"recovery_id":"s","rule_id":"r","reason":"x","deadline_ms":0}}"#;
        assert!(serde_json::from_str::<Decision>(zero).is_err());
        assert!(serde_json::from_str::<RecordedDecision>(zero).is_err());
        let unknown = r#"{"outcome":"Deny","reason":"x","contributions":[],"decided_by":{"kind":"default_deny"},"extra":1}"#;
        assert!(serde_json::from_str::<Decision>(unknown).is_err());
        assert!(serde_json::from_str::<RecordedDecision>(unknown).is_err());
        let valid = zero.replace(r#""deadline_ms":0"#, r#""deadline_ms":1"#);
        serde_json::from_str::<Decision>(&valid).unwrap();
        serde_json::from_str::<RecordedDecision>(&valid).unwrap();
    }

    #[test]
    fn decided_by_rejects_unknown_kinds_and_fields() {
        for decided_by in [
            r#"{"kind":"operator_override"}"#,
            r#"{"kind":"Rule","rule_id":"r"}"#,
            r#"{"kind":"rule","rule_id":"r","extra":1}"#,
            r#"{"kind":"engine_guard","guard":"g","rule_id":"r"}"#,
            r#"{"kind":"rule"}"#,
            r#"{"rule_id":"r"}"#,
            r#""default_deny""#,
            r#"null"#,
        ] {
            assert!(
                serde_json::from_str::<DecidedBy>(decided_by).is_err(),
                "{decided_by}"
            );
            let decision = format!(
                r#"{{"outcome":"Deny","reason":"x","contributions":[],"decided_by":{decided_by}}}"#
            );
            assert!(
                serde_json::from_str::<Decision>(&decision).is_err(),
                "{decision}"
            );
            assert!(
                serde_json::from_str::<RecordedDecision>(&decision).is_err(),
                "{decision}"
            );
        }
    }

    #[test]
    fn decided_by_unit_variant_rejects_extra_fields() {
        assert!(serde_json::from_str::<DecidedBy>(r#"{"kind":"default_deny","x":1}"#).is_err());
        assert_eq!(
            serde_json::from_str::<DecidedBy>(r#"{"kind":"default_deny"}"#).unwrap(),
            DecidedBy::DefaultDeny
        );
    }

    #[test]
    fn decided_by_must_be_consistent_with_the_decision() {
        let c = |id: &str, outcome| DecisionContribution::new(id, outcome, "r");
        let allow_a = c("a", DecisionOutcome::Allow);
        let deny_d = c("d", DecisionOutcome::Deny);
        let mut rejected = vec![
            // Rule absent from the contributions, or with a different outcome.
            Decision::allow("x", DecidedBy::rule("a"))
                .with_contribution(c("b", DecisionOutcome::Allow)),
            Decision::deny("x", DecidedBy::rule("a")).with_contribution(allow_a.clone()),
            // Outcome weaker than a contribution: hides a deny.
            Decision::allow("x", DecidedBy::rule("a"))
                .with_contribution(deny_d.clone())
                .with_contribution(allow_a.clone()),
            // Non-rule deciders only deny.
            Decision::allow("x", DecidedBy::DefaultDeny),
            Decision::require_approval("x", DecidedBy::engine_guard("g")),
            Decision::allow("x", DecidedBy::unbound_rule("a")).with_contribution(allow_a.clone()),
            // Default deny means nothing matched.
            Decision::deny("x", DecidedBy::DefaultDeny).with_contribution(deny_d.clone()),
            // Unbound rule must have contributed its deny.
            Decision::deny("x", DecidedBy::unbound_rule("u")).with_contribution(deny_d.clone()),
            // Malformed identifiers.
            Decision::deny("x", DecidedBy::rule(""))
                .with_contribution(c("", DecisionOutcome::Deny)),
            Decision::deny("x", DecidedBy::rule(" d"))
                .with_contribution(c(" d", DecisionOutcome::Deny)),
            Decision::deny("x", DecidedBy::engine_guard("")),
            Decision::deny("x", DecidedBy::rule("d".repeat(1025)))
                .with_contribution(c(&"d".repeat(1025), DecisionOutcome::Deny)),
        ];
        // A recovery obligation decided by another rule, or by a non-rule.
        let mut wrong_rule = Decision::recover("x", obligation("r1"))
            .with_contribution(c("r1", DecisionOutcome::Deny))
            .with_contribution(deny_d.clone());
        wrong_rule.decided_by = DecidedBy::rule("d");
        rejected.push(wrong_rule);
        let mut guard = Decision::recover("x", obligation("r1"))
            .with_contribution(c("r1", DecisionOutcome::Deny));
        guard.decided_by = DecidedBy::engine_guard("g");
        rejected.push(guard);
        for decision in rejected {
            assert!(decision.validate().is_err(), "{decision:?}");
            let json = serde_json::to_string(&decision).unwrap();
            assert!(serde_json::from_str::<Decision>(&json).is_err(), "{json}");
            assert!(
                serde_json::from_str::<RecordedDecision>(&json).is_err(),
                "{json}"
            );
            assert!(RecordedDecision::from(decision).validate().is_err());
        }

        for decision in [
            // No evaluation trace: nothing to contradict.
            Decision::allow("x", DecidedBy::rule("a")),
            Decision::deny("x", DecidedBy::unbound_rule("u")),
            Decision::allow("x", DecidedBy::rule("a")).with_contribution(allow_a.clone()),
            Decision::deny("x", DecidedBy::rule("d"))
                .with_contribution(allow_a.clone())
                .with_contribution(deny_d.clone()),
            Decision::deny("x", DecidedBy::unbound_rule("u"))
                .with_contribution(c("u", DecisionOutcome::Deny)),
            Decision::deny("x", DecidedBy::DefaultDeny),
            Decision::deny("x", DecidedBy::engine_guard("authority_capability")),
            Decision::recover("x", obligation("r1"))
                .with_contribution(deny_d.clone())
                .with_contribution(c("r1", DecisionOutcome::Deny)),
        ] {
            decision.validate().unwrap();
            let json = serde_json::to_string(&decision).unwrap();
            assert_eq!(serde_json::from_str::<Decision>(&json).unwrap(), decision);
            RecordedDecision::from(decision).validate().unwrap();
        }
    }

    #[test]
    fn new_decision_json_requires_decided_by() {
        let legacy = r#"{"outcome":"Allow","reason":"ok","contributions":[]}"#;
        assert!(serde_json::from_str::<Decision>(legacy).is_err());
        let recorded: RecordedDecision = serde_json::from_str(legacy).unwrap();
        assert_eq!(recorded.decided_by(), None);
        // Legacy form round-trips byte-identically (keeps signatures valid).
        assert_eq!(serde_json::to_string(&recorded).unwrap(), legacy);
    }

    #[test]
    fn recorded_decision_from_new_decision_always_has_decided_by() {
        for decision in [
            Decision::allow("a", DecidedBy::rule("r")),
            Decision::require_approval("b", DecidedBy::rule("p")),
            Decision::deny("c", DecidedBy::DefaultDeny),
            Decision::deny("d", DecidedBy::engine_guard("g")),
            Decision::deny("e", DecidedBy::unbound_rule("u")),
            Decision::recover("f", obligation("r1")),
        ] {
            let expected = decision.decided_by.clone();
            let recorded = RecordedDecision::from(decision);
            assert_eq!(recorded.decided_by(), Some(&expected));
            let json = serde_json::to_value(&recorded).unwrap();
            assert!(json.get("decided_by").is_some());
        }
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
        let decision = Decision::deny("Policy violation", DecidedBy::rule("test-rule"));

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.reason, "Policy violation");
    }

    #[test]
    fn decision_helpers_construct_expected_outcomes() {
        assert!(
            Decision::allow("ok", DecidedBy::rule("test-rule"))
                .outcome
                .is_allowed()
        );
        assert!(
            Decision::require_approval("review", DecidedBy::rule("test-rule"))
                .outcome
                .requires_approval()
        );
        assert!(
            Decision::deny("blocked", DecidedBy::rule("test-rule"))
                .outcome
                .is_denied()
        );
    }

    #[test]
    fn decision_can_record_contribution() {
        let decision = Decision::deny("blocked", DecidedBy::rule("test-rule")).with_contribution(
            DecisionContribution::new(
                "deny-delete",
                DecisionOutcome::Deny,
                "delete operations are forbidden",
            ),
        );

        assert_eq!(decision.contributions.len(), 1);
        assert_eq!(decision.contributions[0].rule_id, "deny-delete");
        assert_eq!(decision.contributions[0].outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn strongest_combines_contributions_for_equal_outcomes() {
        let first = Decision::allow("first", DecidedBy::rule("test-rule")).with_contribution(
            DecisionContribution::new("allow-read", DecisionOutcome::Allow, "read permitted"),
        );

        let second = Decision::allow("second", DecidedBy::rule("test-rule")).with_contribution(
            DecisionContribution::new("allow-users", DecisionOutcome::Allow, "users permitted"),
        );

        let combined = first.strongest(second);

        assert_eq!(combined.outcome, DecisionOutcome::Allow);
        assert_eq!(combined.contributions.len(), 2);
    }

    #[test]
    fn strongest_preserves_reason_of_stronger_decision() {
        let allow = Decision::allow("read operation permitted", DecidedBy::rule("test-rule"))
            .with_contribution(DecisionContribution::new(
                "allow-read",
                DecisionOutcome::Allow,
                "read operation permitted",
            ));

        let deny = Decision::deny("read operation forbidden", DecidedBy::rule("test-rule"))
            .with_contribution(DecisionContribution::new(
                "deny-read",
                DecisionOutcome::Deny,
                "read operation forbidden",
            ));

        let combined = allow.strongest(deny);

        assert_eq!(combined.outcome, DecisionOutcome::Deny);
        assert_eq!(combined.reason, "read operation forbidden");
        assert_eq!(combined.contributions.len(), 2);
    }

    #[test]
    fn strongest_is_associative_for_outcome_and_contributions() {
        let allow = Decision::allow("allowed", DecidedBy::rule("test-rule")).with_contribution(
            DecisionContribution::new("allow-read", DecisionOutcome::Allow, "allowed"),
        );

        let approval =
            Decision::require_approval("approval required", DecidedBy::rule("test-rule"))
                .with_contribution(DecisionContribution::new(
                    "approval-read",
                    DecisionOutcome::RequireApproval,
                    "approval required",
                ));

        let deny = Decision::deny("denied", DecidedBy::rule("test-rule")).with_contribution(
            DecisionContribution::new("deny-read", DecisionOutcome::Deny, "denied"),
        );

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
        let allow = Decision::allow("allowed", DecidedBy::rule("test-rule")).with_contribution(
            DecisionContribution::new("allow-read", DecisionOutcome::Allow, "allowed"),
        );

        let deny = Decision::deny("denied", DecidedBy::rule("test-rule")).with_contribution(
            DecisionContribution::new("deny-read", DecisionOutcome::Deny, "denied"),
        );

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
