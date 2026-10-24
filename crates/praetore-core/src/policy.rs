use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, collections::BTreeMap};

use crate::{
    action::Action,
    authority::Authority,
    canonical::{
        MAX_JSON_VALUE_BYTES, canonical_json, parse_json_rejecting_duplicates, validate_json_value,
    },
    decision::{Decision, DecisionContribution},
    error::{PraetoreError, Result},
    identity::AgentIdentity,
};

const MAX_POLICY_RULES: usize = 1024;
const MAX_CONDITIONS_PER_RULE: usize = 128;
const MAX_POLICY_TEXT_BYTES: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// A versioned set of declarative authorization rules.
///
/// No matching rule produces a DENY decision. Matching effects are combined
/// using DENY > REQUIRE_APPROVAL > ALLOW.
///
/// ```
/// use praetore_core::{Policy, PolicyCondition, PolicyEffect, PolicyRule};
/// use serde_json::json;
///
/// let policy = Policy::new(
///     "read-policy",
///     1,
///     vec![PolicyRule::new("allow-public", "read_data", PolicyEffect::Allow)
///         .with_parameter_condition(PolicyCondition::exact("classification", json!("public")))],
/// );
/// policy.validate().expect("valid policy");
/// assert_eq!(policy.digest().expect("canonical digest").len(), 64);
/// ```
pub struct Policy {
    pub id: String,
    pub version: u32,
    pub canonical_version: u8,
    #[serde(
        default = "legacy_policy_semantics_version",
        skip_serializing_if = "is_legacy_policy_semantics_version"
    )]
    pub semantics_version: u8,
    pub rules: Vec<PolicyRule>,
}

fn legacy_policy_semantics_version() -> u8 {
    1
}

fn is_legacy_policy_semantics_version(version: &u8) -> bool {
    *version == 1
}

impl Policy {
    pub fn new(id: impl Into<String>, version: u32, rules: Vec<PolicyRule>) -> Self {
        Self {
            id: id.into(),
            version,
            canonical_version: crate::canonical::CANONICAL_VERSION,
            semantics_version: 1,
            rules,
        }
    }

    /// Creates a policy using conservative unknown-condition semantics.
    ///
    /// For DENY and REQUIRE_APPROVAL rules, a missing or type-incompatible
    /// condition value counts as a match. The semantics version is included in
    /// the policy digest, so this does not change the meaning of v1 policies.
    pub fn new_v2(id: impl Into<String>, version: u32, rules: Vec<PolicyRule>) -> Self {
        Self {
            semantics_version: 2,
            ..Self::new(id, version, rules)
        }
    }

    pub fn evaluate(
        &self,
        agent: &AgentIdentity,
        authority: &Authority,
        action: &Action,
    ) -> Result<Decision> {
        self.evaluate_with_context(agent, authority, action, &BTreeMap::new())
    }

    pub fn evaluate_with_context(
        &self,
        agent: &AgentIdentity,
        authority: &Authority,
        action: &Action,
        context: &BTreeMap<String, Value>,
    ) -> Result<Decision> {
        self.validate()?;

        let mut decision: Option<Decision> = None;

        for rule in &self.rules {
            if !rule.matches(agent, authority, action, context, self.semantics_version) {
                continue;
            }

            let rule_decision = rule.decision()?;

            let contribution = DecisionContribution::new(
                rule.id.clone(),
                rule_decision.outcome,
                rule_decision.reason.clone(),
            );

            let rule_decision = rule_decision.with_contribution(contribution);

            decision = Some(match decision {
                Some(current) => current.strongest(rule_decision),
                None => rule_decision,
            });
        }

        Ok(decision.unwrap_or_else(|| {
            Decision::deny(format!(
                "Policy '{}' v{}: no matching rule; default deny",
                self.id, self.version
            ))
        }))
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let canonical = canonical_json(self).map_err(|error| {
            PraetoreError::PolicyEvaluationFailed(format!(
                "could not serialize policy for digest: {error}"
            ))
        })?;
        Ok(hex::encode(Sha256::digest(canonical)))
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let value =
            parse_json_rejecting_duplicates(json).map_err(PraetoreError::PolicyEvaluationFailed)?;
        let policy: Self = serde_json::from_value(value)
            .map_err(|error| PraetoreError::PolicyEvaluationFailed(error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.canonical_version != crate::canonical::CANONICAL_VERSION {
            return Err(PraetoreError::PolicyEvaluationFailed(
                "unsupported policy canonical version".into(),
            ));
        }
        if !matches!(self.semantics_version, 1 | 2) {
            return Err(PraetoreError::PolicyEvaluationFailed(
                "unsupported policy semantics version".into(),
            ));
        }

        if self.id.trim().is_empty() || self.id != self.id.trim() {
            return Err(PraetoreError::PolicyEvaluationFailed(
                "policy id must be a non-empty canonical identifier".into(),
            ));
        }

        if self.version == 0 {
            return Err(PraetoreError::PolicyEvaluationFailed(
                "policy version must be greater than zero".into(),
            ));
        }

        if self.id.len() > MAX_POLICY_TEXT_BYTES || self.rules.len() > MAX_POLICY_RULES {
            return Err(PraetoreError::PolicyEvaluationFailed(
                "policy exceeds configured input limits".into(),
            ));
        }

        for rule in &self.rules {
            rule.validate()?;
        }

        for (index, rule) in self.rules.iter().enumerate() {
            if self.rules[..index]
                .iter()
                .any(|previous| previous.id == rule.id)
            {
                return Err(PraetoreError::PolicyEvaluationFailed(format!(
                    "policy '{}' contains duplicate rule id '{}'",
                    self.id, rule.id
                )));
            }
        }

        let canonical = canonical_json(self).map_err(|error| {
            PraetoreError::PolicyEvaluationFailed(format!(
                "policy exceeds canonical input limits: {error}"
            ))
        })?;
        if canonical.len() > MAX_JSON_VALUE_BYTES {
            return Err(PraetoreError::PolicyEvaluationFailed(
                "policy exceeds maximum canonical size".into(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub id: String,
    pub action_type: String,
    pub effect: PolicyEffect,
    pub required_capability: Option<String>,
    pub target: Option<String>,
    pub parameter_conditions: Vec<PolicyCondition>,
    pub context_conditions: Vec<PolicyCondition>,
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
            parameter_conditions: Vec::new(),
            context_conditions: Vec::new(),
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

    pub fn with_parameter_condition(mut self, condition: PolicyCondition) -> Self {
        self.parameter_conditions.push(condition);
        self
    }

    pub fn with_context_condition(mut self, condition: PolicyCondition) -> Self {
        self.context_conditions.push(condition);
        self
    }

    fn matches(
        &self,
        _agent: &AgentIdentity,
        authority: &Authority,
        action: &Action,
        context: &BTreeMap<String, Value>,
        semantics_version: u8,
    ) -> bool {
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

        let restrictive = semantics_version >= 2 && self.effect != PolicyEffect::Allow;
        self.parameter_conditions.iter().all(|condition| {
            condition.matches(&action.parameters, restrictive) != ConditionMatch::False
        }) && self
            .context_conditions
            .iter()
            .all(|condition| condition.matches_map(context, restrictive) != ConditionMatch::False)
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
        if self.id.trim().is_empty() || self.id != self.id.trim() {
            return Err(PraetoreError::PolicyEvaluationFailed(
                "policy rule id must be a non-empty canonical identifier".into(),
            ));
        }

        if self.action_type.trim().is_empty() || self.action_type != self.action_type.trim() {
            return Err(PraetoreError::PolicyEvaluationFailed(format!(
                "policy rule '{}' has invalid action_type",
                self.id
            )));
        }
        if self.id.len() > MAX_POLICY_TEXT_BYTES || self.action_type.len() > MAX_POLICY_TEXT_BYTES {
            return Err(PraetoreError::PolicyEvaluationFailed(format!(
                "policy rule '{}' exceeds maximum text length",
                self.id
            )));
        }

        if let Some(capability) = &self.required_capability {
            if capability.trim().is_empty() || capability != capability.trim() {
                return Err(PraetoreError::PolicyEvaluationFailed(format!(
                    "policy rule '{}' has invalid capability",
                    self.id
                )));
            }
        }

        if let Some(target) = &self.target {
            if target.trim().is_empty() || target != target.trim() {
                return Err(PraetoreError::PolicyEvaluationFailed(format!(
                    "policy rule '{}' has invalid target",
                    self.id
                )));
            }
            if target.len() > MAX_POLICY_TEXT_BYTES {
                return Err(PraetoreError::PolicyEvaluationFailed(format!(
                    "policy rule '{}' target exceeds maximum length",
                    self.id
                )));
            }
        }

        if self.parameter_conditions.len() > MAX_CONDITIONS_PER_RULE
            || self.context_conditions.len() > MAX_CONDITIONS_PER_RULE
        {
            return Err(PraetoreError::PolicyEvaluationFailed(format!(
                "policy rule '{}' has too many conditions",
                self.id
            )));
        }

        validate_conditions(&self.id, "parameter", &self.parameter_conditions)?;
        validate_conditions(&self.id, "context", &self.context_conditions)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyCondition {
    pub key: String,
    pub operator: MatchOperator,
    pub expected: Value,
}

impl PolicyCondition {
    pub fn new(key: impl Into<String>, operator: MatchOperator, expected: Value) -> Self {
        Self {
            key: key.into(),
            operator,
            expected,
        }
    }

    pub fn exact(key: impl Into<String>, expected: Value) -> Self {
        Self::new(key, MatchOperator::Exact, expected)
    }

    pub fn prefix(key: impl Into<String>, expected: impl Into<String>) -> Self {
        Self::new(key, MatchOperator::Prefix, Value::String(expected.into()))
    }

    pub fn one_of(key: impl Into<String>, expected: Vec<Value>) -> Self {
        Self::new(key, MatchOperator::In, Value::Array(expected))
    }

    pub fn greater_than(key: impl Into<String>, expected: Value) -> Self {
        Self::new(key, MatchOperator::GreaterThan, expected)
    }

    fn matches(&self, object: &Value, restrictive: bool) -> ConditionMatch {
        let actual = object.as_object().and_then(|values| values.get(&self.key));
        self.matches_optional_value(actual, restrictive)
    }

    fn matches_map(&self, values: &BTreeMap<String, Value>, restrictive: bool) -> ConditionMatch {
        self.matches_optional_value(values.get(&self.key), restrictive)
    }

    fn matches_optional_value(&self, actual: Option<&Value>, restrictive: bool) -> ConditionMatch {
        let Some(actual) = actual else {
            return if restrictive {
                ConditionMatch::Unknown
            } else {
                ConditionMatch::False
            };
        };
        let result = match self.operator {
            MatchOperator::Exact => {
                if actual == &self.expected {
                    ConditionMatch::True
                } else if same_json_type(actual, &self.expected) {
                    ConditionMatch::False
                } else {
                    ConditionMatch::Unknown
                }
            }
            MatchOperator::Prefix => match (actual.as_str(), self.expected.as_str()) {
                (Some(actual), Some(prefix)) if actual.starts_with(prefix) => ConditionMatch::True,
                (Some(_), Some(_)) => ConditionMatch::False,
                _ => ConditionMatch::Unknown,
            },
            MatchOperator::In => {
                let Some(values) = self.expected.as_array() else {
                    return ConditionMatch::Unknown;
                };
                if values.contains(actual) {
                    ConditionMatch::True
                } else if values.iter().any(|value| same_json_type(actual, value)) {
                    ConditionMatch::False
                } else {
                    ConditionMatch::Unknown
                }
            }
            MatchOperator::GreaterThan
            | MatchOperator::GreaterThanOrEqual
            | MatchOperator::LessThan
            | MatchOperator::LessThanOrEqual => {
                let Some(order) = compare_numeric(actual, &self.expected) else {
                    return if restrictive {
                        ConditionMatch::Unknown
                    } else {
                        ConditionMatch::False
                    };
                };
                let matches = match self.operator {
                    MatchOperator::GreaterThan => order == Ordering::Greater,
                    MatchOperator::GreaterThanOrEqual => order != Ordering::Less,
                    MatchOperator::LessThan => order == Ordering::Less,
                    MatchOperator::LessThanOrEqual => order != Ordering::Greater,
                    _ => unreachable!(),
                };
                if matches {
                    ConditionMatch::True
                } else {
                    ConditionMatch::False
                }
            }
        };
        if result == ConditionMatch::Unknown && !restrictive {
            ConditionMatch::False
        } else {
            result
        }
    }

    fn validate(&self, rule_id: &str, scope: &str) -> Result<()> {
        if self.key.trim().is_empty()
            || self.key != self.key.trim()
            || self.key.len() > MAX_POLICY_TEXT_BYTES
        {
            return Err(PraetoreError::PolicyEvaluationFailed(format!(
                "policy rule '{rule_id}' has invalid {scope} condition key"
            )));
        }

        validate_json_value(&self.expected).map_err(|message| {
            PraetoreError::PolicyEvaluationFailed(format!(
                "policy rule '{rule_id}' has invalid {scope} condition value: {message}"
            ))
        })?;

        match self.operator {
            MatchOperator::Prefix
                if self
                    .expected
                    .as_str()
                    .is_none_or(|prefix| prefix.is_empty()) =>
            {
                return Err(PraetoreError::PolicyEvaluationFailed(format!(
                    "policy rule '{rule_id}' prefix condition must use a non-empty string"
                )));
            }
            MatchOperator::In
                if self
                    .expected
                    .as_array()
                    .is_none_or(|values| values.is_empty()) =>
            {
                return Err(PraetoreError::PolicyEvaluationFailed(format!(
                    "policy rule '{rule_id}' membership condition must use a non-empty array"
                )));
            }
            MatchOperator::GreaterThan
            | MatchOperator::GreaterThanOrEqual
            | MatchOperator::LessThan
            | MatchOperator::LessThanOrEqual
                if !self.expected.is_number() =>
            {
                return Err(PraetoreError::PolicyEvaluationFailed(format!(
                    "policy rule '{rule_id}' numeric condition must use a number"
                )));
            }
            _ => {}
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConditionMatch {
    True,
    False,
    Unknown,
}

fn same_json_type(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Null, Value::Null)
        | (Value::Bool(_), Value::Bool(_))
        | (Value::String(_), Value::String(_))
        | (Value::Array(_), Value::Array(_))
        | (Value::Object(_), Value::Object(_)) => true,
        (Value::Number(left), Value::Number(right)) => {
            left.is_i64() && right.is_i64()
                || left.is_u64() && right.is_u64()
                || left.is_f64() && right.is_f64()
        }
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MatchOperator {
    Exact,
    Prefix,
    In,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
}

fn compare_numeric(actual: &Value, expected: &Value) -> Option<Ordering> {
    let actual = actual.as_number()?;
    let expected = expected.as_number()?;

    if let (Some(actual), Some(expected)) = (actual.as_i64(), expected.as_i64()) {
        return Some(actual.cmp(&expected));
    }

    if let (Some(actual), Some(expected)) = (actual.as_u64(), expected.as_u64()) {
        return Some(actual.cmp(&expected));
    }

    if let (Some(actual), Some(expected)) = (actual.as_i64(), expected.as_u64()) {
        return Some(if actual < 0 {
            Ordering::Less
        } else {
            (actual as u64).cmp(&expected)
        });
    }

    if let (Some(actual), Some(expected)) = (actual.as_u64(), expected.as_i64()) {
        return Some(if expected < 0 {
            Ordering::Greater
        } else {
            actual.cmp(&(expected as u64))
        });
    }

    let actual_is_float = actual.as_i64().is_none() && actual.as_u64().is_none();
    let expected_is_float = expected.as_i64().is_none() && expected.as_u64().is_none();
    if !actual_is_float || !expected_is_float {
        return None;
    }

    actual.as_f64()?.partial_cmp(&expected.as_f64()?)
}

fn validate_conditions(rule_id: &str, scope: &str, conditions: &[PolicyCondition]) -> Result<()> {
    for (index, condition) in conditions.iter().enumerate() {
        condition.validate(rule_id, scope)?;

        if conditions[..index]
            .iter()
            .any(|previous| conditions_conflict(previous, condition))
        {
            return Err(PraetoreError::PolicyEvaluationFailed(format!(
                "policy rule '{rule_id}' contains contradictory {scope} conditions for '{}'",
                condition.key
            )));
        }
    }

    Ok(())
}

fn conditions_conflict(left: &PolicyCondition, right: &PolicyCondition) -> bool {
    if left.key != right.key {
        return false;
    }

    match (left.operator, right.operator) {
        (MatchOperator::Exact, MatchOperator::Exact) => left.expected != right.expected,
        (MatchOperator::Exact, MatchOperator::In) => right
            .expected
            .as_array()
            .is_some_and(|values| !values.contains(&left.expected)),
        (MatchOperator::In, MatchOperator::Exact) => left
            .expected
            .as_array()
            .is_some_and(|values| !values.contains(&right.expected)),
        (MatchOperator::In, MatchOperator::In) => {
            let left_values = left.expected.as_array();
            let right_values = right.expected.as_array();
            left_values
                .zip(right_values)
                .is_some_and(|(left, right)| left.iter().all(|value| !right.contains(value)))
        }
        (MatchOperator::Prefix, MatchOperator::Prefix) => left
            .expected
            .as_str()
            .zip(right.expected.as_str())
            .is_some_and(|(left, right)| !left.starts_with(right) && !right.starts_with(left)),
        (MatchOperator::Exact, MatchOperator::Prefix) => left
            .expected
            .as_str()
            .zip(right.expected.as_str())
            .is_some_and(|(exact, prefix)| !exact.starts_with(prefix)),
        (MatchOperator::Prefix, MatchOperator::Exact) => left
            .expected
            .as_str()
            .zip(right.expected.as_str())
            .is_some_and(|(prefix, exact)| !exact.starts_with(prefix)),
        _ => false,
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
    fn policy_import_rejects_duplicate_json_fields() {
        assert!(Policy::from_json(r#"{"policy_id":"a","policy_id":"b"}"#).is_err());
    }

    #[test]
    fn policy_import_rejects_unknown_fields_and_versions() {
        assert!(
            Policy::from_json(
                r#"{"id":"p","version":1,"canonical_version":1,"rules":[],"future":true}"#
            )
            .is_err()
        );
        assert!(
            Policy::from_json(r#"{"id":"p","version":1,"canonical_version":2,"rules":[]}"#)
                .is_err()
        );
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
        assert_eq!(
            decision.reason,
            "Policy 'production' v1: no matching rule; default deny"
        );
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
    fn allow_decision_reason_comes_from_matching_rule() {
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
        assert_eq!(decision.reason, "Policy rule 'allow-read' matched");
        assert_eq!(decision.contributions.len(), 1);
        assert_eq!(decision.contributions[0].rule_id, "allow-read");
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
    fn multiple_allow_rules_preserve_a_real_rule_reason() {
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
        assert!(
            decision.reason == "Policy rule 'allow-read-1' matched"
                || decision.reason == "Policy rule 'allow-read-2' matched"
        );
        assert_ne!(decision.reason, "Policy 'production' v1: no matching rule");
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

    #[test]
    fn policy_precedence_is_deny_then_approval_then_allow() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);

        let effects = [
            PolicyEffect::Allow,
            PolicyEffect::RequireApproval,
            PolicyEffect::Deny,
        ];

        let expected = [
            [
                DecisionOutcome::Allow,
                DecisionOutcome::RequireApproval,
                DecisionOutcome::Deny,
            ],
            [
                DecisionOutcome::RequireApproval,
                DecisionOutcome::RequireApproval,
                DecisionOutcome::Deny,
            ],
            [
                DecisionOutcome::Deny,
                DecisionOutcome::Deny,
                DecisionOutcome::Deny,
            ],
        ];

        for (left_index, left_effect) in effects.iter().enumerate() {
            for (right_index, right_effect) in effects.iter().enumerate() {
                let policy = Policy::new(
                    "precedence-test",
                    1,
                    vec![
                        PolicyRule::new("rule-left", "read_data", *left_effect),
                        PolicyRule::new("rule-right", "read_data", *right_effect),
                    ],
                );

                let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

                assert_eq!(
                    decision.outcome, expected[left_index][right_index],
                    "unexpected precedence for {:?} + {:?}",
                    left_effect, right_effect
                );

                assert_eq!(decision.contributions.len(), 2);
            }
        }
    }

    #[test]
    fn policy_rejects_duplicate_rule_ids() {
        let policy = Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("read-rule", "read_data", PolicyEffect::Allow),
                PolicyRule::new("read-rule", "read_data", PolicyEffect::Deny),
            ],
        );

        let result = policy.validate();

        assert!(matches!(
            result,
            Err(PraetoreError::PolicyEvaluationFailed(_))
        ));
    }

    #[test]
    fn parameter_conditions_support_exact_prefix_membership_and_numeric_match() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);
        let action = Action::new(
            "read_data",
            None,
            json!({
                "resource": "users.private",
                "region": "south",
                "record_count": 12,
                "enabled": true
            }),
        )
        .unwrap();
        let policy = Policy::new(
            "typed-matches",
            1,
            vec![
                PolicyRule::new("allow-query", "read_data", PolicyEffect::Allow)
                    .with_parameter_condition(PolicyCondition::exact("enabled", json!(true)))
                    .with_parameter_condition(PolicyCondition::prefix("resource", "users."))
                    .with_parameter_condition(PolicyCondition::one_of(
                        "region",
                        vec![json!("north"), json!("south")],
                    ))
                    .with_parameter_condition(PolicyCondition::greater_than(
                        "record_count",
                        json!(10),
                    )),
            ],
        );

        let decision = policy.evaluate(&agent, &authority, &action).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Allow);
    }

    #[test]
    fn restrictive_conditions_fail_closed_when_values_are_missing_or_mistyped() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["data:read".into()]);
        let policy = Policy::new_v2(
            "restrictive-unknowns",
            1,
            vec![
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow),
                PolicyRule::new("deny-large-read", "read_data", PolicyEffect::Deny)
                    .with_parameter_condition(PolicyCondition::greater_than(
                        "record_count",
                        json!(1000),
                    )),
            ],
        );

        for parameters in [
            json!({}),
            json!({"record_count": "5000"}),
            json!({"record_count": 5000.0}),
            json!({"record_count": 5e3}),
        ] {
            let action = Action::new("read_data", None, parameters).unwrap();
            let decision = policy
                .evaluate(&agent, &authority, &action)
                .expect("policy is valid");
            assert_eq!(
                decision.outcome,
                DecisionOutcome::Deny,
                "unexpected allow for action parameters: {}",
                action.parameters
            );
            assert!(
                decision
                    .contributions
                    .iter()
                    .any(|contribution| contribution.rule_id == "deny-large-read"),
                "restrictive unknown condition must be attributed to its rule"
            );
        }
    }

    #[test]
    fn restrictive_conditions_do_not_match_when_another_condition_is_false() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["data:read".into()]);
        let policy = Policy::new_v2(
            "restrictive-false-condition",
            1,
            vec![
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow),
                PolicyRule::new(
                    "deny-large-production-read",
                    "read_data",
                    PolicyEffect::Deny,
                )
                .with_target("production")
                .with_parameter_condition(PolicyCondition::greater_than(
                    "record_count",
                    json!(1000),
                )),
            ],
        );
        let action = Action::new("read_data", Some("development".into()), json!({})).unwrap();

        let decision = policy.evaluate(&agent, &authority, &action).unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Allow);
    }

    #[test]
    fn typed_conditions_fail_closed_on_missing_or_wrong_json_types() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);
        let action = Action::new(
            "read_data",
            None,
            json!({"record_count": "12", "region": "south"}),
        )
        .unwrap();
        let policy = Policy::new(
            "typed-matches",
            1,
            vec![
                PolicyRule::new("allow-query", "read_data", PolicyEffect::Allow)
                    .with_parameter_condition(PolicyCondition::greater_than(
                        "record_count",
                        json!(10),
                    ))
                    .with_parameter_condition(PolicyCondition::exact("missing", json!(true))),
            ],
        );

        let decision = policy.evaluate(&agent, &authority, &action).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert!(decision.contributions.is_empty());
    }

    #[test]
    fn context_conditions_are_matched_independently_of_action_parameters() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);
        let mut context = BTreeMap::new();
        context.insert("risk_level".into(), json!(2));
        let policy = Policy::new(
            "context-policy",
            1,
            vec![
                PolicyRule::new("allow-low-risk", "read_data", PolicyEffect::Allow)
                    .with_context_condition(PolicyCondition::new(
                        "risk_level",
                        MatchOperator::LessThanOrEqual,
                        json!(3),
                    )),
            ],
        );

        let decision = policy
            .evaluate_with_context(&agent, &authority, &test_action(), &context)
            .unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Allow);
    }

    #[test]
    fn policy_validation_rejects_contradictory_conditions() {
        let policy = Policy::new(
            "invalid-policy",
            1,
            vec![
                PolicyRule::new("unreachable", "read_data", PolicyEffect::Allow)
                    .with_parameter_condition(PolicyCondition::exact("region", json!("north")))
                    .with_parameter_condition(PolicyCondition::exact("region", json!("south"))),
            ],
        );

        assert!(matches!(
            policy.validate(),
            Err(PraetoreError::PolicyEvaluationFailed(_))
        ));
    }

    #[test]
    fn policy_digest_is_stable_and_sensitive_to_policy_changes() {
        let policy = Policy::new(
            "digest-test",
            1,
            vec![
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow)
                    .with_parameter_condition(PolicyCondition::exact("enabled", json!(true))),
            ],
        );
        let same_policy = policy.clone();
        let changed_policy = Policy::new(
            "digest-test",
            1,
            vec![PolicyRule::new(
                "allow-read",
                "read_data",
                PolicyEffect::Deny,
            )],
        );

        assert_eq!(policy.digest().unwrap(), same_policy.digest().unwrap());
        assert_ne!(policy.digest().unwrap(), changed_policy.digest().unwrap());
    }

    #[test]
    fn policy_v2_changes_digest_and_preserves_v1_digest_bytes() {
        let rules = vec![PolicyRule::new(
            "allow-read",
            "read_data",
            PolicyEffect::Allow,
        )];
        let v1 = Policy::new("versioned-policy", 1, rules.clone());
        let v2 = Policy::new_v2("versioned-policy", 1, rules);

        assert_eq!(v1.semantics_version, 1);
        assert_eq!(v2.semantics_version, 2);
        assert_ne!(v1.digest().unwrap(), v2.digest().unwrap());
        assert_eq!(
            serde_json::to_value(&v1).unwrap().get("semantics_version"),
            None
        );
        assert_eq!(
            serde_json::to_value(&v2).unwrap()["semantics_version"],
            json!(2)
        );
    }

    #[test]
    fn numeric_comparison_preserves_integer_precision_and_rejects_mixed_types() {
        let greater_than = PolicyCondition::greater_than("count", json!(9_007_199_254_740_992_u64));
        let mixed_type = PolicyCondition::greater_than("count", json!(1.0));

        assert_eq!(
            greater_than.matches(&json!({"count": 9_007_199_254_740_993_u64}), false),
            ConditionMatch::True
        );
        assert_eq!(
            greater_than.matches(&json!({"count": 9_007_199_254_740_991_u64}), false),
            ConditionMatch::False
        );
        assert_eq!(
            mixed_type.matches(&json!({"count": 1}), false),
            ConditionMatch::False
        );
        assert_eq!(
            mixed_type.matches(&json!({"count": "2"}), true),
            ConditionMatch::Unknown
        );
    }

    #[test]
    fn policy_digest_matches_canonical_golden_value() {
        let policy = Policy::new(
            "golden",
            1,
            vec![PolicyRule::new(
                "allow-read",
                "read_data",
                PolicyEffect::Allow,
            )],
        );

        assert_eq!(
            policy.digest().unwrap(),
            "5d45f213fc1f9fcfa17bf0a462169ea9e14efa028d873b79841924eae90ddd1f"
        );
    }

    #[test]
    fn policy_canonical_bytes_match_committed_golden_vector() {
        let policy = Policy::new(
            "golden",
            1,
            vec![PolicyRule::new(
                "allow-read",
                "read_data",
                PolicyEffect::Allow,
            )],
        );
        let expected = include_str!("../../../docs/golden/canonical-policy-v1.json").trim();
        let canonical = canonical_json(&policy).unwrap();
        let expected_digest = hex::encode(Sha256::digest(expected.as_bytes()));

        assert_eq!(canonical, expected.as_bytes());
        assert_eq!(policy.digest().unwrap(), expected_digest);
    }
}
