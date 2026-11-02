use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, collections::BTreeMap};

use crate::{
    action::{Action, ClassifiedAction, MissionAction, SafetyAction, UnclassifiedAction},
    authority::Authority,
    canonical::{
        JsonError, MAX_JSON_DEPTH, MAX_JSON_NODES, MAX_JSON_VALUE_BYTES, canonical_json,
        parse_json_strict, validate_json_value,
    },
    decision::{DecidedBy, Decision, DecisionContribution, RecoveryObligation},
    error::{PraetoreError, Result},
    identity::AgentIdentity,
    safety_namespace::{SafetyActionName, SafetyNameError, mentions_safety},
};

// Policy size and complexity limits. A policy that exceeds any of them is
// rejected when it is built or loaded (`Policy::validate`, `Policy::from_json`)
// with `PraetoreError::PolicyLimitExceeded`; nothing is skipped or ignored.
// The policy engine has no regular expressions, so there is no pattern limit.

/// Maximum number of rules in a policy, checked before the canonical size.
/// Set above what fits in `MAX_JSON_VALUE_BYTES` (468 minimal rules with ids
/// `r0`..`r467`), so the canonical size stays the binding limit and no policy
/// that was valid before this constant became public is rejected by it.
pub const MAX_POLICY_RULES: usize = 512;
/// Maximum parameter conditions, and separately context conditions, per rule.
pub const MAX_CONDITIONS_PER_RULE: usize = 128;
/// Maximum UTF-8 bytes of a policy id, rule id, action type, capability,
/// target or condition key.
pub const MAX_POLICY_TEXT_BYTES: usize = 1024;
/// Maximum UTF-8 bytes of any string inside a condition's expected value.
pub const MAX_CONDITION_STRING_BYTES: usize = 1024;
/// Maximum number of array elements in one condition's expected value,
/// counted across every array at every depth (the top-level `In` set
/// included). A flat `In` set may therefore hold up to this many values.
pub const MAX_CONDITION_SET_VALUES: usize = 256;
/// Maximum nesting depth of a condition's expected value (a scalar is 1).
pub const MAX_CONDITION_VALUE_DEPTH: usize = 8;
/// Maximum number of entries in a policy's `action_classes` table.
pub const MAX_ACTION_CLASSES: usize = 512;

/// Policy document format evaluated by this release. Format 2 adds the
/// required `action_classes` table (G7). Format 1 documents carry no
/// `format_version` field; they are rejected for evaluation and are only
/// digested for historical verification (see [`RecordedPolicy`]).
pub const POLICY_FORMAT_VERSION: u8 = 2;
/// The prefix every safety action type carries, and only safety action
/// types carry. Defined with the shared validator,
/// [`SafetyActionName`](crate::safety_namespace::SafetyActionName) (G2).
pub use crate::safety_namespace::SAFETY_ACTION_PREFIX;

/// G7: how a policy classifies an exact `action_type`.
///
/// * `Mission`: an action PRÆTORE decides. Every mission action needs a
///   synchronously signed decision before it runs (fail closed).
/// * `Safety`: an action the executor of an AI-enabled system runs without
///   waiting for PRÆTORE (for example `safety:halt`, `safety:hold`,
///   `safety:stop_all`). PRÆTORE makes no decision about
///   it, and no policy rule may target it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActionClass {
    Mission,
    Safety,
}

/// Why a policy's `action_classes` table, or a rule's use of it, was
/// rejected. Raised as [`PraetoreError::PolicyActionClassInvalid`] when the
/// policy is loaded or validated (fail closed, the policy is never partially
/// applied).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActionClassError {
    /// A format 2 document has no `action_classes` field.
    #[error("policy format 2 requires an `action_classes` table")]
    MissingTable,
    /// An `action_classes` key is empty or has surrounding whitespace.
    #[error("action_classes key '{action_type}' is not a canonical action type")]
    InvalidActionType { action_type: String },
    /// An `action_classes` key has a character outside printable ASCII
    /// (`!` to `~`): whitespace, a control or format character such as a
    /// zero-width space, or any non-ASCII character such as a homoglyph or
    /// a full-width letter. Keeps names that read alike from classifying
    /// differently.
    #[error("action_classes key {action_type:?} must be printable ASCII without whitespace")]
    NotPrintableAscii { action_type: String },
    /// A rule names an action type the table does not declare.
    #[error(
        "rule '{rule_id}' uses action type '{action_type}', which action_classes does not declare"
    )]
    UndeclaredActionType {
        rule_id: String,
        action_type: String,
    },
    /// An action type starting with `safety:` is not declared `Safety`.
    #[error("action type '{action_type}' starts with `safety:` and must be declared Safety")]
    SafetyPrefixNotSafety { action_type: String },
    /// A `Safety` entry does not start with `safety:` followed by a name
    /// that starts with an ASCII letter or digit.
    #[error("Safety action type '{action_type}' must be `safety:` followed by a name")]
    SafetyWithoutPrefix { action_type: String },
    /// A `Safety` entry is longer than
    /// [`MAX_SAFETY_ACTION_NAME_BYTES`](crate::safety_namespace::MAX_SAFETY_ACTION_NAME_BYTES)
    /// bytes (G2).
    #[error("Safety action type '{action_type}' is longer than {max} bytes")]
    SafetyNameTooLong { action_type: String, max: usize },
    /// An action type without the `safety:` prefix contains "safety" (ASCII
    /// case-insensitive), so it could be mistaken for a safety action.
    #[error("action type '{action_type}' contains \"safety\" without the `safety:` prefix")]
    AmbiguousSafetyName { action_type: String },
    /// A rule targets a `Safety` action. PRÆTORE decides nothing about safety
    /// actions, so no rule may name one.
    #[error(
        "rule '{rule_id}' targets safety action '{action_type}'; rules may only target Mission actions"
    )]
    RuleTargetsSafetyAction {
        rule_id: String,
        action_type: String,
    },
}

fn class_error(error: ActionClassError) -> PraetoreError {
    PraetoreError::PolicyActionClassInvalid(error)
}

/// Maps a [`SafetyNameError`] for the `Safety` entry `action_type` to the
/// policy error G7 reports for it.
fn safety_entry_error(action_type: &str, error: SafetyNameError) -> ActionClassError {
    let action_type = action_type.to_owned();
    match error {
        SafetyNameError::Empty => ActionClassError::InvalidActionType { action_type },
        SafetyNameError::NotPrintableAscii { .. } => {
            ActionClassError::NotPrintableAscii { action_type }
        }
        SafetyNameError::MissingPrefix { .. } | SafetyNameError::InvalidNameStart { .. } => {
            ActionClassError::SafetyWithoutPrefix { action_type }
        }
        SafetyNameError::TooLong { max, .. } => {
            ActionClassError::SafetyNameTooLong { action_type, max }
        }
    }
}

/// Checks one `action_classes` entry: prefix and class must agree, and an
/// unprefixed name may not contain "safety". A `Safety` entry is valid
/// exactly when [`SafetyActionName::parse`] accepts it (G2), the validator
/// the safety namespace manifest and the ingestion path share.
fn validate_action_class_entry(action_type: &str, class: ActionClass) -> Result<()> {
    if action_type.trim().is_empty() || action_type != action_type.trim() {
        return Err(class_error(ActionClassError::InvalidActionType {
            action_type: action_type.to_owned(),
        }));
    }
    check_limit(
        PolicyLimit::ActionTypeBytes,
        action_type.len(),
        MAX_POLICY_TEXT_BYTES,
    )?;
    if !action_type.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(class_error(ActionClassError::NotPrintableAscii {
            action_type: action_type.to_owned(),
        }));
    }
    let owned = || action_type.to_owned();
    match class {
        ActionClass::Safety => SafetyActionName::parse(action_type)
            .map(drop)
            .map_err(|error| class_error(safety_entry_error(action_type, error))),
        ActionClass::Mission if action_type.starts_with(SAFETY_ACTION_PREFIX) => {
            Err(class_error(ActionClassError::SafetyPrefixNotSafety {
                action_type: owned(),
            }))
        }
        ActionClass::Mission if mentions_safety(action_type) => {
            Err(class_error(ActionClassError::AmbiguousSafetyName {
                action_type: owned(),
            }))
        }
        ActionClass::Mission => Ok(()),
    }
}

/// Which policy limit was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyLimit {
    PolicyIdBytes,
    Rules,
    RuleIdBytes,
    ActionTypeBytes,
    CapabilityBytes,
    TargetBytes,
    ConditionsPerRule,
    ConditionKeyBytes,
    ConditionStringBytes,
    ConditionSetValues,
    ConditionValueDepth,
    CanonicalBytes,
    /// Entries in `action_classes` (`MAX_ACTION_CLASSES`).
    ActionClasses,
    /// Raw policy text passed to `Policy::from_json`, before parsing.
    InputBytes,
    /// JSON nesting depth of the whole document (`MAX_JSON_DEPTH`).
    JsonDepth,
    /// JSON node count of the whole document (`MAX_JSON_NODES`).
    JsonNodes,
}

impl std::fmt::Display for PolicyLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PolicyIdBytes => "policy id bytes",
            Self::Rules => "rules per policy",
            Self::RuleIdBytes => "rule id bytes",
            Self::ActionTypeBytes => "action type bytes",
            Self::CapabilityBytes => "capability bytes",
            Self::TargetBytes => "target bytes",
            Self::ConditionsPerRule => "conditions per rule scope",
            Self::ConditionKeyBytes => "condition key bytes",
            Self::ConditionStringBytes => "condition string bytes",
            Self::ConditionSetValues => {
                "array elements in a condition's expected value (total across all nested arrays)"
            }
            Self::ConditionValueDepth => "condition value nesting depth",
            Self::CanonicalBytes => "canonical policy bytes",
            Self::ActionClasses => "action_classes entries",
            Self::InputBytes => "policy input bytes",
            Self::JsonDepth => "policy JSON nesting depth",
            Self::JsonNodes => "policy JSON nodes",
        })
    }
}

/// Why a policy document was rejected before any rule was considered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyDocumentError {
    /// Not a single well-formed JSON value.
    #[error("malformed JSON at line {line} column {column}")]
    Malformed { line: usize, column: usize },
    /// An object, at any depth, repeats a key.
    #[error("duplicate JSON object key")]
    DuplicateKey,
    /// A policy, rule or condition object has a field the schema does not
    /// define. `field` is the offending key.
    #[error("unknown field `{field}`")]
    UnknownField { field: String },
    /// An integer, or integral float, outside +/-2^53-1.
    #[error("integer exceeds interoperable safe range")]
    UnsafeInteger,
}

/// Maps a strict-JSON rejection to the policy error a caller can match on.
fn policy_json_error(error: JsonError) -> PraetoreError {
    let limit = |limit, max| PraetoreError::PolicyLimitExceeded { limit, max };
    match error {
        JsonError::InputTooLarge => limit(PolicyLimit::InputBytes, MAX_JSON_VALUE_BYTES),
        JsonError::ValueTooLarge | JsonError::CanonicalTooLarge => {
            limit(PolicyLimit::CanonicalBytes, MAX_JSON_VALUE_BYTES)
        }
        JsonError::TooDeep => limit(PolicyLimit::JsonDepth, MAX_JSON_DEPTH),
        JsonError::TooManyNodes => limit(PolicyLimit::JsonNodes, MAX_JSON_NODES),
        JsonError::Malformed { line, column } => {
            PraetoreError::PolicyDocumentInvalid(PolicyDocumentError::Malformed { line, column })
        }
        JsonError::DuplicateKey => {
            PraetoreError::PolicyDocumentInvalid(PolicyDocumentError::DuplicateKey)
        }
        JsonError::UnsafeInteger => {
            PraetoreError::PolicyDocumentInvalid(PolicyDocumentError::UnsafeInteger)
        }
        JsonError::Unrepresentable => {
            PraetoreError::PolicyEvaluationFailed(format!("policy is not valid JSON: {error}"))
        }
    }
}

/// The field names serde accepts for struct `T`, read from its derived
/// `Deserialize` impl so they cannot drift from the struct definition.
fn struct_fields<'de, T: Deserialize<'de>>() -> &'static [&'static str] {
    use serde::de::{Error as _, Visitor, value::Error};

    struct Introspect<'a>(&'a mut &'static [&'static str]);

    impl<'de> serde::Deserializer<'de> for Introspect<'_> {
        type Error = Error;

        fn deserialize_any<V: Visitor<'de>>(self, _: V) -> std::result::Result<V::Value, Error> {
            Err(Error::custom("not a struct"))
        }

        fn deserialize_struct<V: Visitor<'de>>(
            self,
            _: &'static str,
            fields: &'static [&'static str],
            _: V,
        ) -> std::result::Result<V::Value, Error> {
            *self.0 = fields;
            Err(Error::custom("introspection only"))
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map enum identifier ignored_any
        }
    }

    let mut fields: &'static [&'static str] = &[];
    let _ = T::deserialize(Introspect(&mut fields));
    fields
}

/// Rejects the first key of `object` that `T` does not define.
fn check_known_fields<'de, T: Deserialize<'de>>(object: &Value) -> Result<()> {
    let Some(object) = object.as_object() else {
        return Ok(());
    };
    let fields = struct_fields::<T>();
    match object.keys().find(|key| !fields.contains(&key.as_str())) {
        Some(field) => Err(PraetoreError::PolicyDocumentInvalid(
            PolicyDocumentError::UnknownField {
                field: field.clone(),
            },
        )),
        None => Ok(()),
    }
}

/// Reports unknown fields on the policy, its rules and their conditions as a
/// typed error. Values of the wrong shape are left for serde to reject.
fn check_policy_fields(document: &Value) -> Result<()> {
    check_known_fields::<Policy>(document)?;
    let rules = document.get("rules").and_then(Value::as_array);
    for rule in rules.into_iter().flatten() {
        check_known_fields::<PolicyRule>(rule)?;
        for scope in ["parameter_conditions", "context_conditions"] {
            let conditions = rule.get(scope).and_then(Value::as_array);
            for condition in conditions.into_iter().flatten() {
                check_known_fields::<PolicyCondition>(condition)?;
            }
        }
    }
    Ok(())
}

fn check_limit(limit: PolicyLimit, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        return Err(PraetoreError::PolicyLimitExceeded { limit, max });
    }
    Ok(())
}

/// Checks string length, nesting depth and the total number of array
/// elements of a condition value. `array_values` accumulates the elements
/// of every array seen so far in the same condition.
fn check_condition_value(value: &Value, depth: usize, array_values: &mut usize) -> Result<()> {
    check_limit(
        PolicyLimit::ConditionValueDepth,
        depth,
        MAX_CONDITION_VALUE_DEPTH,
    )?;
    match value {
        Value::String(text) => check_limit(
            PolicyLimit::ConditionStringBytes,
            text.len(),
            MAX_CONDITION_STRING_BYTES,
        ),
        Value::Array(values) => {
            *array_values = array_values.saturating_add(values.len());
            check_limit(
                PolicyLimit::ConditionSetValues,
                *array_values,
                MAX_CONDITION_SET_VALUES,
            )?;
            values
                .iter()
                .try_for_each(|value| check_condition_value(value, depth + 1, array_values))
        }
        Value::Object(values) => values.iter().try_for_each(|(key, value)| {
            check_limit(
                PolicyLimit::ConditionStringBytes,
                key.len(),
                MAX_CONDITION_STRING_BYTES,
            )?;
            check_condition_value(value, depth + 1, array_values)
        }),
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// A versioned set of declarative authorization rules (policy format 2).
///
/// No matching rule produces a DENY decision. Matching effects are combined
/// using DENY > REQUIRE_APPROVAL > ALLOW.
///
/// Every action type a rule names must be declared in `action_classes`, and
/// no rule may name a `Safety` action (G7).
///
/// ```
/// use praetore_core::{ActionClass, Policy, PolicyCondition, PolicyEffect, PolicyRule};
/// use serde_json::json;
///
/// let policy = Policy::new(
///     "read-policy",
///     1,
///     vec![PolicyRule::new("allow-public", "read_data", PolicyEffect::Allow)
///         .with_parameter_condition(PolicyCondition::exact("classification", json!("public")))],
/// )
/// .with_mission_actions(["read_data"])
/// .with_action_class("safety:halt", ActionClass::Safety);
/// policy.validate().expect("valid policy");
/// assert_eq!(policy.digest().expect("canonical digest").len(), 64);
/// ```
pub struct Policy {
    /// Policy document format; must be [`POLICY_FORMAT_VERSION`] (2).
    pub format_version: u8,
    pub id: String,
    pub version: u32,
    pub canonical_version: u8,
    #[serde(
        default = "legacy_policy_semantics_version",
        skip_serializing_if = "is_legacy_policy_semantics_version"
    )]
    pub semantics_version: u8,
    /// G7: the class of every action type this policy knows, by exact
    /// `action_type`. Required in format 2.
    pub action_classes: BTreeMap<String, ActionClass>,
    pub rules: Vec<PolicyRule>,
    /// SAF-10: upper bound for a human-approval window, in milliseconds.
    /// A RequireApproval request whose signed intent window is longer is
    /// rejected. Omitted when `None`, so existing digests do not change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_approval_ms: Option<u64>,
}

fn legacy_policy_semantics_version() -> u8 {
    1
}

fn is_legacy_policy_semantics_version(version: &u8) -> bool {
    *version == 1
}

impl Policy {
    /// Creates a format 2 policy with semantics version 1 and an empty
    /// `action_classes` table. Declare every action type its rules use with
    /// [`Self::with_action_class`] or [`Self::with_mission_actions`];
    /// [`Self::validate`] rejects an undeclared one.
    pub fn new(id: impl Into<String>, version: u32, rules: Vec<PolicyRule>) -> Self {
        Self {
            format_version: POLICY_FORMAT_VERSION,
            id: id.into(),
            version,
            canonical_version: crate::canonical::CANONICAL_VERSION,
            semantics_version: 1,
            action_classes: BTreeMap::new(),
            rules,
            max_approval_ms: None,
        }
    }

    /// Declares the class of one exact action type.
    pub fn with_action_class(mut self, action_type: impl Into<String>, class: ActionClass) -> Self {
        self.action_classes.insert(action_type.into(), class);
        self
    }

    /// Declares each of `action_types` as [`ActionClass::Mission`].
    pub fn with_mission_actions<I, S>(mut self, action_types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for action_type in action_types {
            self.action_classes
                .insert(action_type.into(), ActionClass::Mission);
        }
        self
    }

    /// Classifies `action` by its exact `action_type`.
    ///
    /// Returns [`PraetoreError::UnclassifiedAction`] when `action_classes`
    /// does not declare it, and a typed policy error when this policy is not
    /// format 2 or the entry itself is invalid (prefix and class disagree).
    /// This is the only way to obtain a [`MissionAction`] or a
    /// [`SafetyAction`]. It reads only the table: it evaluates no rule and
    /// performs no I/O.
    ///
    /// ```
    /// use praetore_core::{Action, ActionClass, ClassifiedAction, Policy, PraetoreError};
    /// use serde_json::json;
    ///
    /// let policy = Policy::new_v2("p", 1, vec![])
    ///     .with_mission_actions(["fs:write_file"])
    ///     .with_action_class("safety:halt", ActionClass::Safety);
    /// let halt = Action::new("safety:halt", None, json!({})).unwrap();
    /// assert!(matches!(policy.classify(halt), Ok(ClassifiedAction::Safety(_))));
    /// let unknown = Action::new("fs:delete", None, json!({})).unwrap();
    /// assert!(matches!(
    ///     policy.classify(unknown),
    ///     Err(PraetoreError::UnclassifiedAction { .. })
    /// ));
    /// ```
    pub fn classify(&self, action: Action) -> Result<ClassifiedAction> {
        self.check_format()?;
        action.validate()?;
        let Some(class) = self.action_classes.get(&action.action_type).copied() else {
            return Err(PraetoreError::UnclassifiedAction {
                action_type: action.action_type,
            });
        };
        validate_action_class_entry(&action.action_type, class)?;
        Ok(match class {
            ActionClass::Mission => ClassifiedAction::Mission(MissionAction::classified(action)),
            ActionClass::Safety => ClassifiedAction::Safety(SafetyAction::classified(action)),
        })
    }

    /// Wraps `action` as an [`UnclassifiedAction`]: an action whose type
    /// `action_classes` does not declare. Fails when the type is declared
    /// (`Mission` or `Safety`), when the action is invalid, and when this
    /// policy is not format 2. The result can only be refused, with a signed
    /// DENY, by
    /// [`AuthorizationEngine::refuse_unclassified`](crate::engine::AuthorizationEngine::refuse_unclassified).
    pub fn unclassified(&self, action: Action) -> Result<UnclassifiedAction> {
        self.check_format()?;
        action.validate()?;
        match self.action_classes.get(&action.action_type) {
            None => Ok(UnclassifiedAction::unclassified(action)),
            Some(ActionClass::Safety) => Err(PraetoreError::SafetyActionNotGoverned {
                action_type: action.action_type,
            }),
            Some(ActionClass::Mission) => Err(PraetoreError::InvalidRequest(format!(
                "action type '{}' is declared Mission; it is not unclassified",
                action.action_type
            ))),
        }
    }

    /// Re-checks, at refusal time, that `action` is still not declared by
    /// this policy (it may have been wrapped against another policy).
    pub(crate) fn require_unclassified(&self, action: &UnclassifiedAction) -> Result<()> {
        self.check_format()?;
        match self.action_classes.get(&action.action_type) {
            None => Ok(()),
            Some(ActionClass::Safety) => Err(PraetoreError::SafetyActionNotGoverned {
                action_type: action.action_type.clone(),
            }),
            Some(ActionClass::Mission) => Err(PraetoreError::InvalidRequest(format!(
                "action type '{}' is declared Mission; it is not unclassified",
                action.action_type
            ))),
        }
    }

    /// Re-checks, at evaluation time, that `action` is still a declared
    /// Mission action of this policy (it may have been classified by another
    /// policy).
    pub(crate) fn require_mission(&self, action: &MissionAction) -> Result<()> {
        self.check_format()?;
        match self.action_classes.get(&action.action_type).copied() {
            Some(class @ ActionClass::Mission) => {
                validate_action_class_entry(&action.action_type, class)
            }
            Some(ActionClass::Safety) => Err(PraetoreError::SafetyActionNotGoverned {
                action_type: action.action_type.clone(),
            }),
            None => Err(PraetoreError::UnclassifiedAction {
                action_type: action.action_type.clone(),
            }),
        }
    }

    fn check_format(&self) -> Result<()> {
        if self.format_version != POLICY_FORMAT_VERSION {
            return Err(unsupported_format(self.format_version));
        }
        Ok(())
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
        action: &MissionAction,
    ) -> Result<Decision> {
        self.evaluate_with_context(agent, authority, action, &BTreeMap::new())
    }

    pub fn evaluate_with_context(
        &self,
        agent: &AgentIdentity,
        authority: &Authority,
        action: &MissionAction,
        context: &BTreeMap<String, Value>,
    ) -> Result<Decision> {
        #[cfg(feature = "test-probe")]
        crate::probe::record_policy_evaluation(&self.id);
        self.validate()?;
        self.require_mission(action)?;
        let action = action.action();

        let mut decision: Option<Decision> = None;

        for rule in &self.rules {
            let rule_decision = match rule.matches(
                agent,
                authority,
                action,
                context,
                self.semantics_version,
            ) {
                RuleMatch::No => continue,
                RuleMatch::Bound => rule.decision()?,
                // A restrictive rule that applies only because the authority
                // lacks its capability or the action has no target must not
                // offer a path to dispatch (RequireApproval) or trigger a
                // recovery obligation (Recover): it denies (fail closed).
                RuleMatch::Unbound if rule.effect == PolicyEffect::Deny => rule.decision()?,
                // Recorded as `UnboundRule`, not `Rule`: the rule's declared
                // effect was not applied.
                RuleMatch::Unbound => Decision::deny(
                    format!(
                        "Policy rule '{}' matched without its required capability or target; denied",
                        rule.id
                    ),
                    DecidedBy::unbound_rule(rule.id.clone()),
                ),
            };

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
            Decision::deny(
                format!(
                    "Policy '{}' v{}: no matching rule; default deny",
                    self.id, self.version
                ),
                DecidedBy::DefaultDeny,
            )
        }))
    }

    /// SAF-10 decision 4 (CTO, 29-oct-2026): load-time coherence of human
    /// approval against the declared control loop. Checks declarations only;
    /// it does not measure real timings.
    fn validate_approval_loops(&self) -> Result<()> {
        if self.max_approval_ms == Some(0) {
            return Err(PraetoreError::PolicyEvaluationFailed(
                "max_approval_ms must be greater than zero".into(),
            ));
        }
        for rule in &self.rules {
            if rule.effect != PolicyEffect::RequireApproval {
                continue;
            }
            match (self.max_approval_ms, rule.control_loop, rule.delta_ms) {
                // Fail closed (CTO, 29-oct-2026): on the fast loop both bounds
                // must be declared, and delta_ms must cover max_approval_ms.
                (None, Some(ControlLoop::Fast), _) | (_, Some(ControlLoop::Fast), None) => {
                    return Err(PraetoreError::PolicyEvaluationFailed(format!(
                        "policy rule '{}' requires approval on the fast control loop without both max_approval_ms and delta_ms",
                        rule.id
                    )));
                }
                (Some(max), _, Some(delta)) if delta < max => {
                    return Err(PraetoreError::PolicyEvaluationFailed(format!(
                        "policy rule '{}' requires approval with delta_ms {delta} below max_approval_ms {max}",
                        rule.id
                    )));
                }
                _ => {}
            }
        }
        Ok(())
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

    /// Parses and validates a policy document.
    ///
    /// Oversized input and JSON structure limits are reported as
    /// `PolicyLimitExceeded`; malformed JSON, duplicate keys, unknown fields
    /// and unsafe integers as `PolicyDocumentInvalid`. Other schema errors
    /// (wrong types, missing fields, unknown enum values) remain
    /// `PolicyEvaluationFailed`.
    ///
    /// A document without `format_version` is policy format 1 and is
    /// rejected with [`PraetoreError::PolicyFormatUnsupported`]; to check
    /// historical evidence against one, use [`RecordedPolicy::from_json`].
    /// A format 2 document without `action_classes` is rejected with
    /// [`ActionClassError::MissingTable`].
    pub fn from_json(json: &str) -> Result<Self> {
        let value = parse_json_strict(json).map_err(policy_json_error)?;
        match document_format(&value) {
            Ok(POLICY_FORMAT_VERSION) => {}
            Ok(found) | Err(found) => return Err(unsupported_format(found)),
        }
        if value.get("action_classes").is_none() {
            return Err(class_error(ActionClassError::MissingTable));
        }
        check_policy_fields(&value)?;
        let policy: Self = serde_json::from_value(value)
            .map_err(|error| PraetoreError::PolicyEvaluationFailed(error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        self.check_format()?;
        self.validate_body()?;
        self.validate_action_classes()?;
        let canonical = canonical_json(self).map_err(policy_json_error)?;
        check_limit(
            PolicyLimit::CanonicalBytes,
            canonical.len(),
            MAX_JSON_VALUE_BYTES,
        )?;
        Ok(())
    }

    /// G7 load-time checks of `action_classes` and of the rules against it.
    fn validate_action_classes(&self) -> Result<()> {
        check_limit(
            PolicyLimit::ActionClasses,
            self.action_classes.len(),
            MAX_ACTION_CLASSES,
        )?;
        for (action_type, class) in &self.action_classes {
            validate_action_class_entry(action_type, *class)?;
        }
        for rule in &self.rules {
            match self.action_classes.get(&rule.action_type) {
                Some(ActionClass::Mission) => {}
                Some(ActionClass::Safety) => {
                    return Err(class_error(ActionClassError::RuleTargetsSafetyAction {
                        rule_id: rule.id.clone(),
                        action_type: rule.action_type.clone(),
                    }));
                }
                None => {
                    return Err(class_error(ActionClassError::UndeclaredActionType {
                        rule_id: rule.id.clone(),
                        action_type: rule.action_type.clone(),
                    }));
                }
            }
        }
        Ok(())
    }

    /// Checks shared by format 1 and format 2 documents: identifiers, rules,
    /// approval loops and duplicate rule ids. Not the canonical size, which
    /// depends on the format.
    fn validate_body(&self) -> Result<()> {
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

        check_limit(
            PolicyLimit::PolicyIdBytes,
            self.id.len(),
            MAX_POLICY_TEXT_BYTES,
        )?;
        check_limit(PolicyLimit::Rules, self.rules.len(), MAX_POLICY_RULES)?;

        for rule in &self.rules {
            rule.validate()?;
        }
        self.validate_approval_loops()?;

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

        Ok(())
    }
}

/// The format a document declares: `Ok(1)` when `format_version` is absent
/// (format 1 never wrote the field), `Ok(n)` for a declared `n >= 2`, and
/// `Err(found)` otherwise: an explicit `1` (no format 1 document has it) or
/// a value that is not a small integer (reported as 0).
fn document_format(document: &Value) -> std::result::Result<u8, u8> {
    match document.get("format_version") {
        None => Ok(1),
        Some(value) => match value.as_u64().and_then(|v| u8::try_from(v).ok()) {
            Some(version) if version >= 2 => Ok(version),
            Some(version) => Err(version),
            None => Err(0),
        },
    }
}

fn unsupported_format(found: u8) -> PraetoreError {
    PraetoreError::PolicyFormatUnsupported {
        found,
        supported: POLICY_FORMAT_VERSION,
    }
}

/// The format 1 policy document, exactly as releases before G7 serialized
/// it. Used only to recompute historical digests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocumentV1 {
    id: String,
    version: u32,
    canonical_version: u8,
    #[serde(
        default = "legacy_policy_semantics_version",
        skip_serializing_if = "is_legacy_policy_semantics_version"
    )]
    semantics_version: u8,
    rules: Vec<PolicyRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_approval_ms: Option<u64>,
}

/// A policy document as historical evidence recorded it: format 1 or 2.
///
/// It exists to answer one question: does this document have the digest a
/// receipt recorded? It has no `evaluate` and does not convert into a
/// [`Policy`], so a format 1 document can be digested and compared but never
/// used to decide anything. Format 1 documents are validated as they were
/// before G7 (identifiers, rules, limits); they have no `action_classes`.
///
/// ```
/// use praetore_core::RecordedPolicy;
///
/// let v1 = include_str!("../../../docs/golden/canonical-policy-v1.json");
/// let recorded = RecordedPolicy::from_json(v1).unwrap();
/// assert_eq!(recorded.format_version(), 1);
/// assert_eq!(
///     recorded.digest(),
///     "5d45f213fc1f9fcfa17bf0a462169ea9e14efa028d873b79841924eae90ddd1f"
/// );
/// // The same document cannot be loaded for evaluation.
/// assert!(praetore_core::Policy::from_json(v1).is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedPolicy {
    format_version: u8,
    id: String,
    version: u32,
    digest: String,
    rules: Vec<PolicyRule>,
    action_classes: Option<BTreeMap<String, ActionClass>>,
}

/// A proposed `action_classes` table for a policy, from
/// [`RecordedPolicy::propose_action_classes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionClassProposal {
    /// One entry per action type the rules name, plus any entry the document
    /// already declares.
    pub action_classes: BTreeMap<String, ActionClass>,
    /// What prevents the document from loading as format 2 with this table
    /// (a rule on a `safety:` action, an ambiguous name). Empty when adding
    /// the table and `"format_version": 2` is enough.
    pub problems: Vec<ActionClassError>,
}

impl RecordedPolicy {
    /// Parses and validates a format 1 or format 2 policy document and
    /// computes its digest. Format 2 documents get the full
    /// [`Policy::from_json`] validation.
    pub fn from_json(json: &str) -> Result<Self> {
        let value = parse_json_strict(json).map_err(policy_json_error)?;
        match document_format(&value) {
            Ok(1) => Self::from_v1(value),
            Ok(POLICY_FORMAT_VERSION) => Self::from_policy(&Policy::from_json(json)?),
            Ok(found) | Err(found) => Err(unsupported_format(found)),
        }
    }

    /// The record of a format 2 policy.
    pub fn from_policy(policy: &Policy) -> Result<Self> {
        Ok(Self {
            format_version: policy.format_version,
            id: policy.id.clone(),
            version: policy.version,
            digest: policy.digest()?,
            rules: policy.rules.clone(),
            action_classes: Some(policy.action_classes.clone()),
        })
    }

    fn from_v1(value: Value) -> Result<Self> {
        check_known_fields::<PolicyDocumentV1>(&value)?;
        let rules = value.get("rules").and_then(Value::as_array);
        for rule in rules.into_iter().flatten() {
            check_known_fields::<PolicyRule>(rule)?;
            for scope in ["parameter_conditions", "context_conditions"] {
                let conditions = rule.get(scope).and_then(Value::as_array);
                for condition in conditions.into_iter().flatten() {
                    check_known_fields::<PolicyCondition>(condition)?;
                }
            }
        }
        let document: PolicyDocumentV1 = serde_json::from_value(value)
            .map_err(|error| PraetoreError::PolicyEvaluationFailed(error.to_string()))?;
        // The shared checks run on a format 2 view of the same fields; the
        // view is never returned and never evaluated.
        Policy {
            format_version: POLICY_FORMAT_VERSION,
            id: document.id.clone(),
            version: document.version,
            canonical_version: document.canonical_version,
            semantics_version: document.semantics_version,
            action_classes: BTreeMap::new(),
            rules: document.rules.clone(),
            max_approval_ms: document.max_approval_ms,
        }
        .validate_body()?;
        let canonical = canonical_json(&document).map_err(policy_json_error)?;
        check_limit(
            PolicyLimit::CanonicalBytes,
            canonical.len(),
            MAX_JSON_VALUE_BYTES,
        )?;
        Ok(Self {
            format_version: 1,
            id: document.id,
            version: document.version,
            digest: hex::encode(Sha256::digest(canonical)),
            rules: document.rules,
            action_classes: None,
        })
    }

    /// 1 or 2.
    pub fn format_version(&self) -> u8 {
        self.format_version
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    /// SHA-256 of the document's canonical JSON, lowercase hex: the value a
    /// receipt records as `policy_digest`.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Proposes an `action_classes` table for migrating this document to
    /// format 2. Action types starting with `safety:` are proposed as
    /// `Safety` (and every rule on one is reported, since format 2 rejects
    /// it); other action types are proposed as `Mission`, except a name that
    /// contains "safety" without the prefix, which is reported and left out.
    /// It reads only this document and changes nothing.
    pub fn propose_action_classes(&self) -> ActionClassProposal {
        let mut action_classes = self.action_classes.clone().unwrap_or_default();
        let mut problems = Vec::new();
        for rule in &self.rules {
            let action_type = &rule.action_type;
            let class = action_classes.get(action_type).copied().unwrap_or(
                if action_type.starts_with(SAFETY_ACTION_PREFIX) {
                    ActionClass::Safety
                } else {
                    ActionClass::Mission
                },
            );
            if let Err(PraetoreError::PolicyActionClassInvalid(problem)) =
                validate_action_class_entry(action_type, class)
            {
                if !problems.contains(&problem) {
                    problems.push(problem);
                }
                continue;
            }
            if class == ActionClass::Safety {
                problems.push(ActionClassError::RuleTargetsSafetyAction {
                    rule_id: rule.id.clone(),
                    action_type: action_type.clone(),
                });
            }
            action_classes.insert(action_type.clone(), class);
        }
        ActionClassProposal {
            action_classes,
            problems,
        }
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
    /// SAF-10: control loop the rule governs. Omitted when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_loop: Option<ControlLoop>,
    /// SAF-10: declared reaction budget δ of the governed loop, in ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_ms: Option<u64>,
}

/// SAF-10: the control loop a rule governs. Human approval is never
/// coherent on the fast loop without a declared approval bound.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlLoop {
    Fast,
    Slow,
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
            control_loop: None,
            delta_ms: None,
        }
    }

    pub fn with_control_loop(mut self, control_loop: ControlLoop) -> Self {
        self.control_loop = Some(control_loop);
        self
    }

    pub fn with_delta_ms(mut self, delta_ms: u64) -> Self {
        self.delta_ms = Some(delta_ms);
        self
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
    ) -> RuleMatch {
        if self.action_type != action.action_type {
            return RuleMatch::No;
        }

        // Deny and RequireApproval rules are "restrictive".
        let deny_like = self.effect != PolicyEffect::Allow;

        // A rule capability narrows Allow rules only. A restrictive rule keeps
        // applying when the authority lacks it, in every semantics version;
        // otherwise an authority without e.g. `payments:large` would skip the
        // approval rule and fall through to a broader Allow. Such a match is
        // `Unbound` and only ever denies (see `evaluate_with_context`).
        let mut bound = true;
        if let Some(required_capability) = &self.required_capability
            && !authority.permits(required_capability)
        {
            if !deny_like {
                return RuleMatch::No;
            }
            bound = false;
        }

        // Targets are exact, case-sensitive identifiers. A missing action
        // target is unknown: it matches restrictive rules in every semantics
        // version and never matches Allow rules.
        if let Some(required_target) = &self.target {
            match action.target.as_deref() {
                Some(target) if target == required_target => {}
                None if deny_like => bound = false,
                _ => return RuleMatch::No,
            }
        }
        let restrictive = semantics_version >= 2 && deny_like;
        let holds = |result: ConditionMatch| match result {
            ConditionMatch::True => true,
            ConditionMatch::False => false,
            // Missing or mistyped value: matches restrictive rules under v2 only.
            ConditionMatch::Unknown => restrictive,
            // Unsafe path-like value: always matches Deny/RequireApproval and
            // never matches Allow, in every semantics version (fail closed).
            ConditionMatch::UnsafeValue => deny_like,
            // Integer against floating-point representation: restrictive rules
            // use the exact numeric result in every semantics version; Allow
            // never matches a mixed representation (fail closed).
            ConditionMatch::MixedNumber(result) => deny_like && result,
        };
        let conditions_hold = self
            .parameter_conditions
            .iter()
            .all(|condition| holds(condition.matches(&action.parameters, restrictive)))
            && self
                .context_conditions
                .iter()
                .all(|condition| holds(condition.matches_map(context, restrictive)));
        match (conditions_hold, bound) {
            (false, _) => RuleMatch::No,
            (true, true) => RuleMatch::Bound,
            (true, false) => RuleMatch::Unbound,
        }
    }

    fn decision(&self) -> Result<Decision> {
        let reason = format!("Policy rule '{}' matched", self.id);
        let decided_by = DecidedBy::rule(self.id.clone());

        match &self.effect {
            PolicyEffect::Allow => Ok(Decision::allow(reason, decided_by)),
            PolicyEffect::Deny => Ok(Decision::deny(reason, decided_by)),
            PolicyEffect::RequireApproval => Ok(Decision::require_approval(reason, decided_by)),
            PolicyEffect::Recover {
                recovery_id,
                deadline_ms,
            } => {
                let recovery = RecoveryObligation {
                    recovery_id: recovery_id.clone(),
                    rule_id: self.id.clone(),
                    reason: reason.clone(),
                    deadline_ms: *deadline_ms,
                };
                recovery
                    .validate()
                    .map_err(|message| PraetoreError::PolicyEvaluationFailed(message.into()))?;
                // Decided by this rule (`DecidedBy::Rule`, from the obligation).
                Ok(Decision::recover(reason, recovery))
            }
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
        check_limit(
            PolicyLimit::RuleIdBytes,
            self.id.len(),
            MAX_POLICY_TEXT_BYTES,
        )?;
        check_limit(
            PolicyLimit::ActionTypeBytes,
            self.action_type.len(),
            MAX_POLICY_TEXT_BYTES,
        )?;
        if let Some(capability) = &self.required_capability {
            check_limit(
                PolicyLimit::CapabilityBytes,
                capability.len(),
                MAX_POLICY_TEXT_BYTES,
            )?;
        }

        if let Some(capability) = &self.required_capability
            && (capability.trim().is_empty() || capability != capability.trim())
        {
            return Err(PraetoreError::PolicyEvaluationFailed(format!(
                "policy rule '{}' has invalid capability",
                self.id
            )));
        }

        if let Some(target) = &self.target {
            if target.trim().is_empty() || target != target.trim() {
                return Err(PraetoreError::PolicyEvaluationFailed(format!(
                    "policy rule '{}' has invalid target",
                    self.id
                )));
            }
            check_limit(
                PolicyLimit::TargetBytes,
                target.len(),
                MAX_POLICY_TEXT_BYTES,
            )?;
        }

        check_limit(
            PolicyLimit::ConditionsPerRule,
            self.parameter_conditions
                .len()
                .max(self.context_conditions.len()),
            MAX_CONDITIONS_PER_RULE,
        )?;

        validate_conditions(&self.id, "parameter", &self.parameter_conditions)?;
        validate_conditions(&self.id, "context", &self.context_conditions)?;

        if let PolicyEffect::Recover {
            recovery_id,
            deadline_ms,
        } = &self.effect
        {
            check_limit(
                PolicyLimit::RuleIdBytes,
                recovery_id.len(),
                MAX_POLICY_TEXT_BYTES,
            )?;
            RecoveryObligation {
                recovery_id: recovery_id.clone(),
                rule_id: self.id.clone(),
                reason: String::new(),
                deadline_ms: *deadline_ms,
            }
            .validate()
            .map_err(|message| {
                PraetoreError::PolicyEvaluationFailed(format!(
                    "policy rule '{}': {message}",
                    self.id
                ))
            })?;
        }

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

    /// Path-aware prefix match. See [`MatchOperator::PathPrefix`].
    pub fn path_prefix(key: impl Into<String>, expected: impl Into<String>) -> Self {
        Self::new(
            key,
            MatchOperator::PathPrefix,
            Value::String(expected.into()),
        )
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
                } else if let Some((order, true)) = compare_numeric(actual, &self.expected) {
                    ConditionMatch::MixedNumber(order == Ordering::Equal)
                } else if same_json_type(actual, &self.expected) {
                    ConditionMatch::False
                } else {
                    ConditionMatch::Unknown
                }
            }
            MatchOperator::Prefix => match (actual.as_str(), self.expected.as_str()) {
                // Mitigation: values that may escape the prefix as a path
                // (`..` segment, any `%`, NUL) are unsafe, see `holds`.
                (Some(actual), Some(_)) if is_unsafe_prefix_value(actual) => {
                    ConditionMatch::UnsafeValue
                }
                (Some(actual), Some(prefix)) if actual.starts_with(prefix) => ConditionMatch::True,
                (Some(_), Some(_)) => ConditionMatch::False,
                _ => ConditionMatch::Unknown,
            },
            MatchOperator::PathPrefix => match (actual.as_str(), self.expected.as_str()) {
                (Some(actual), Some(prefix)) => {
                    match (path_segments(actual), path_segments(prefix)) {
                        (Some(actual), Some(prefix)) if actual.starts_with(&prefix) => {
                            ConditionMatch::True
                        }
                        (Some(_), Some(_)) => ConditionMatch::False,
                        (None, _) => ConditionMatch::UnsafeValue,
                        // Rule prefixes are validated on load; unreachable in
                        // a validated policy, and never matches Allow.
                        (Some(_), None) => ConditionMatch::Unknown,
                    }
                }
                _ => ConditionMatch::Unknown,
            },
            MatchOperator::In => {
                let Some(values) = self.expected.as_array() else {
                    return ConditionMatch::Unknown;
                };
                let mixed = |equal: bool| {
                    values.iter().any(|value| {
                        compare_numeric(actual, value).is_some_and(|(order, mixed)| {
                            mixed && (order == Ordering::Equal) == equal
                        })
                    })
                };
                if values.contains(actual) {
                    ConditionMatch::True
                } else if mixed(true) {
                    ConditionMatch::MixedNumber(true)
                } else if values.iter().any(|value| same_json_type(actual, value)) {
                    ConditionMatch::False
                } else if mixed(false) {
                    ConditionMatch::MixedNumber(false)
                } else {
                    ConditionMatch::Unknown
                }
            }
            MatchOperator::GreaterThan
            | MatchOperator::GreaterThanOrEqual
            | MatchOperator::LessThan
            | MatchOperator::LessThanOrEqual => {
                let Some((order, mixed)) = compare_numeric(actual, &self.expected) else {
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
                if mixed {
                    ConditionMatch::MixedNumber(matches)
                } else if matches {
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
        check_limit(
            PolicyLimit::ConditionKeyBytes,
            self.key.len(),
            MAX_POLICY_TEXT_BYTES,
        )?;
        check_condition_value(&self.expected, 1, &mut 0)?;
        if self.key.trim().is_empty() || self.key != self.key.trim() {
            return Err(PraetoreError::PolicyEvaluationFailed(format!(
                "policy rule '{rule_id}' has invalid {scope} condition key"
            )));
        }

        validate_json_value(&self.expected).map_err(policy_json_error)?;

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
            MatchOperator::PathPrefix
                if self.expected.as_str().and_then(path_segments).is_none() =>
            {
                return Err(PraetoreError::PolicyEvaluationFailed(format!(
                    "policy rule '{rule_id}' path prefix must be an absolute, normalized path \
                     without '.', '..', empty segments, '\\', '%' or NUL"
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

/// How a rule matched an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleMatch {
    No,
    /// The authority holds the rule's capability and the action names its
    /// target (when the rule declares them).
    Bound,
    /// A restrictive rule matched although the authority lacks its capability
    /// or the action has no target.
    Unbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConditionMatch {
    True,
    False,
    Unknown,
    /// A string value that is unsafe for a path-like operator.
    UnsafeValue,
    /// Exact numeric result of comparing an integer with a floating-point
    /// number; see `holds` in `PolicyRule::matches`.
    MixedNumber(bool),
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
#[non_exhaustive]
pub enum MatchOperator {
    Exact,
    /// Lexical string prefix. Not path-aware: use [`Self::PathPrefix`] for
    /// paths.
    ///
    /// Mitigation against path traversal: a value with a `..` segment (split
    /// on `/` or `\\`), any `%` (upper, lower or mixed case escapes; the
    /// engine does not percent-decode) or a NUL is treated as unsafe. An
    /// unsafe value always matches `Deny` and `RequireApproval` rules and
    /// never matches `Allow` rules, under every semantics version.
    ///
    /// See [`Self::PathPrefix`] for the lexical limits that also apply here.
    Prefix,
    In,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    /// Path prefix on whole segments, purely lexical.
    ///
    /// Both the rule prefix and the value must be absolute (`/`-rooted) and
    /// already normalized: no `.` or `..` segments, no empty segments
    /// (`//`), no `\\`, no NUL and no `%` at all. A single trailing `/` is
    /// allowed. `/srv/agent` matches `/srv/agent` and `/srv/agent/x`, not
    /// `/srv/agentx`.
    ///
    /// The string `//` on its own is the one exception to the empty-segment
    /// rule: it is read as the root `/` plus the allowed trailing `/`, so it
    /// is accepted, as a rule prefix and as a value, and means the root. Other
    /// repeated separators are not: `///`, `//srv`, `/srv//x` and `/srv//`
    /// contain an empty segment and are rejected (as a prefix) or unsafe (as
    /// a value). A rule prefix that breaks these rules is rejected when
    /// the policy loads. A value that breaks them is unsafe: it always
    /// matches `Deny` and `RequireApproval` rules and never matches `Allow`
    /// rules, under every semantics version.
    ///
    /// Lexical limits (the check is byte/char based, nothing is normalized):
    /// - the filesystem is never consulted, so symlinks are out of scope;
    /// - Unicode look-alikes are not folded: fullwidth `．．` (U+FF0E),
    ///   division slash `∕` (U+2215) and similar are ordinary characters;
    /// - spaces are significant (`" .."` and `".. "` are not `..`);
    /// - `...` is an ordinary segment name.
    ///
    /// Callers must therefore pass the exact path that will be used, and no
    /// downstream layer may apply NFKC normalization or percent-decoding to
    /// a value after it was authorized.
    ///
    /// Over-restriction (accepted, fail closed): the unsafe check runs before
    /// the prefix comparison, so an unsafe value matches a `Deny` or
    /// `RequireApproval` rule even when it lies outside the rule's prefix.
    /// For example a deny rule on `/srv/secret` also denies `/home/50%.txt`
    /// and `/home/a/../b`. The same applies to [`Self::Prefix`].
    PathPrefix,
}

fn path_prefix_segments(condition: &PolicyCondition) -> Option<Vec<&str>> {
    condition.expected.as_str().and_then(path_segments)
}

/// An `Exact` value that is a safe path outside the `PathPrefix` can never
/// satisfy both conditions. Unsafe exact values are not a conflict: they make
/// the path condition unsafe, which still matches restrictive rules.
fn exact_outside_path_prefix(exact: &PolicyCondition, prefix: &PolicyCondition) -> bool {
    let Some(prefix) = path_prefix_segments(prefix) else {
        return false;
    };
    exact
        .expected
        .as_str()
        .and_then(path_segments)
        .is_some_and(|exact| !exact.starts_with(&prefix))
}

fn is_unsafe_prefix_value(value: &str) -> bool {
    has_dot_dot_segment(value) || value.contains(['%', '\0'])
}

fn has_dot_dot_segment(value: &str) -> bool {
    value.split(['/', '\\']).any(|segment| segment == "..")
}

/// Segments of an absolute, normalized path, or `None` if it is not one.
fn path_segments(path: &str) -> Option<Vec<&str>> {
    if !path.starts_with('/') || path.contains(['\\', '%', '\0']) {
        return None;
    }
    let body = &path[1..];
    let body = body.strip_suffix('/').unwrap_or(body);
    if body.is_empty() {
        return Some(Vec::new());
    }
    let segments: Vec<&str> = body.split('/').collect();
    if segments
        .iter()
        .any(|segment| segment.is_empty() || *segment == "." || *segment == "..")
    {
        return None;
    }
    Some(segments)
}

/// Exact numeric ordering of two JSON numbers, and whether one side is an
/// integer and the other a floating-point number. No lossy cast is used: an
/// integer is never converted to `f64`.
fn compare_numeric(actual: &Value, expected: &Value) -> Option<(Ordering, bool)> {
    match (json_number(actual)?, json_number(expected)?) {
        (JsonNumber::Integer(actual), JsonNumber::Integer(expected)) => {
            Some((actual.cmp(&expected), false))
        }
        (JsonNumber::Float(actual), JsonNumber::Float(expected)) => {
            Some((actual.partial_cmp(&expected)?, false))
        }
        (JsonNumber::Integer(actual), JsonNumber::Float(expected)) => {
            Some((compare_integer_float(actual, expected)?, true))
        }
        (JsonNumber::Float(actual), JsonNumber::Integer(expected)) => {
            Some((compare_integer_float(expected, actual)?.reverse(), true))
        }
    }
}

enum JsonNumber {
    Integer(i128),
    Float(f64),
}

fn json_number(value: &Value) -> Option<JsonNumber> {
    let number = value.as_number()?;
    if let Some(integer) = number.as_i64() {
        Some(JsonNumber::Integer(integer.into()))
    } else if let Some(integer) = number.as_u64() {
        Some(JsonNumber::Integer(integer.into()))
    } else {
        number.as_f64().map(JsonNumber::Float)
    }
}

/// Exact ordering of `integer` relative to `float`.
fn compare_integer_float(integer: i128, float: f64) -> Option<Ordering> {
    // 2^127; every finite f64 in [-2^127, 2^127) has an integral part that
    // fits in i128 exactly, so the cast below is lossless.
    const LIMIT: f64 = 170_141_183_460_469_231_731_687_303_715_884_105_728.0;
    if float.is_nan() {
        return None;
    }
    if float >= LIMIT {
        return Some(Ordering::Less);
    }
    if float < -LIMIT {
        return Some(Ordering::Greater);
    }
    let whole = float.trunc();
    // `float - whole` is exact for f64; only its sign matters.
    let fraction = float - whole;
    Some(integer.cmp(&(whole as i128)).then(if fraction > 0.0 {
        Ordering::Less
    } else if fraction < 0.0 {
        Ordering::Greater
    } else {
        Ordering::Equal
    }))
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
        (MatchOperator::PathPrefix, MatchOperator::PathPrefix) => path_prefix_segments(left)
            .zip(path_prefix_segments(right))
            .is_some_and(|(left, right)| !left.starts_with(&right) && !right.starts_with(&left)),
        (MatchOperator::Exact, MatchOperator::PathPrefix) => exact_outside_path_prefix(left, right),
        (MatchOperator::PathPrefix, MatchOperator::Exact) => exact_outside_path_prefix(right, left),
        // Conservative: only flag prefixes that are lexically unrelated, so a
        // policy is never rejected for a satisfiable pair.
        (MatchOperator::PathPrefix, MatchOperator::Prefix)
        | (MatchOperator::Prefix, MatchOperator::PathPrefix) => left
            .expected
            .as_str()
            .zip(right.expected.as_str())
            .is_some_and(|(left, right)| !left.starts_with(right) && !right.starts_with(left)),
        _ => false,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyEffect {
    Allow,
    Deny,
    RequireApproval,
    /// SAF-10: deny the proposed action and oblige entry into the
    /// predeclared safe mode `recovery_id` within `deadline_ms`.
    Recover {
        recovery_id: String,
        deadline_ms: u64,
    },
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

    fn test_action() -> MissionAction {
        crate::test_support::mission(
            Action::new(
                "read_data",
                Some("database".into()),
                json!({"table": "users"}),
            )
            .unwrap(),
        )
    }

    #[test]
    fn policy_allows_matching_rule() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![PolicyRule::new(
                "allow-read",
                "read_data",
                PolicyEffect::Allow,
            )],
        ));

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        assert_eq!(decision.contributions.len(), 1);
        assert_eq!(decision.contributions[0].rule_id, "allow-read");
    }

    #[test]
    fn policy_import_rejects_duplicate_json_fields() {
        assert!(matches!(
            Policy::from_json(r#"{"policy_id":"a","policy_id":"b"}"#),
            Err(PraetoreError::PolicyDocumentInvalid(
                PolicyDocumentError::DuplicateKey
            ))
        ));
    }

    #[test]
    fn policy_import_rejects_unknown_fields_and_versions() {
        assert!(matches!(
            Policy::from_json(
                r#"{"format_version":2,"id":"p","version":1,"canonical_version":1,"action_classes":{},"rules":[],"future":true}"#
            ),
            Err(PraetoreError::PolicyDocumentInvalid(
                PolicyDocumentError::UnknownField { field }
            )) if field == "future"
        ));
        assert!(
            Policy::from_json(r#"{"format_version":2,"id":"p","version":1,"canonical_version":2,"action_classes":{},"rules":[]}"#)
                .is_err()
        );
    }

    #[test]
    fn policy_denies_matching_rule() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![PolicyRule::new(
                "deny-read",
                "read_data",
                PolicyEffect::Deny,
            )],
        ));

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.contributions.len(), 1);
        assert_eq!(decision.contributions[0].rule_id, "deny-read");
    }

    #[test]
    fn policy_requires_approval() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![PolicyRule::new(
                "approval-read",
                "read_data",
                PolicyEffect::RequireApproval,
            )],
        ));

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::RequireApproval);
        assert_eq!(decision.contributions.len(), 1);
        assert_eq!(decision.contributions[0].rule_id, "approval-read");
    }

    #[test]
    fn unmatched_rule_denies_by_default() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![PolicyRule::new(
                "allow-write",
                "write_data",
                PolicyEffect::Allow,
            )],
        ))
        .with_mission_actions(["read_data"]);

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

        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow)
                    .with_capability("admin:data"),
            ],
        ));

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert!(decision.contributions.is_empty());
    }

    #[test]
    fn target_constraint_is_enforced() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("deny-database", "read_data", PolicyEffect::Deny)
                    .with_target("database"),
            ],
        ));

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.contributions.len(), 1);
    }

    #[test]
    fn deny_beats_allow_when_multiple_rules_match() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow),
                PolicyRule::new("deny-read", "read_data", PolicyEffect::Deny),
            ],
        ));

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.contributions.len(), 2);
    }

    #[test]
    fn approval_beats_allow_when_multiple_rules_match() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow),
                PolicyRule::new("approval-read", "read_data", PolicyEffect::RequireApproval),
            ],
        ));

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::RequireApproval);
        assert_eq!(decision.contributions.len(), 2);
    }

    #[test]
    fn deny_beats_approval_when_multiple_rules_match() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("approval-read", "read_data", PolicyEffect::RequireApproval),
                PolicyRule::new("deny-read", "read_data", PolicyEffect::Deny),
            ],
        ));

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.contributions.len(), 2);
    }

    #[test]
    fn decision_is_independent_of_rule_order() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let first = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow),
                PolicyRule::new("deny-read", "read_data", PolicyEffect::Deny),
            ],
        ));

        let second = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("deny-read", "read_data", PolicyEffect::Deny),
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow),
            ],
        ));

        let first_decision = first.evaluate(&agent, &authority, &test_action()).unwrap();
        let second_decision = second.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(first_decision.outcome, DecisionOutcome::Deny);
        assert_eq!(second_decision.outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn allow_decision_reason_comes_from_matching_rule() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![PolicyRule::new(
                "allow-read",
                "read_data",
                PolicyEffect::Allow,
            )],
        ));

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

        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("allow-read-1", "read_data", PolicyEffect::Allow),
                PolicyRule::new("allow-read-2", "read_data", PolicyEffect::Allow),
            ],
        ));

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        assert_eq!(decision.contributions.len(), 2);
    }

    #[test]
    fn deny_combined_with_deny_remains_deny() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("deny-read-1", "read_data", PolicyEffect::Deny),
                PolicyRule::new("deny-read-2", "read_data", PolicyEffect::Deny),
            ],
        ));

        let decision = policy.evaluate(&agent, &authority, &test_action()).unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.contributions.len(), 2);
    }

    #[test]
    fn policy_rejects_empty_id() {
        let policy = crate::test_support::mission_policy(Policy::new("", 1, vec![]));

        assert!(policy.validate().is_err());
    }

    #[test]
    fn policy_rejects_zero_version() {
        let policy = crate::test_support::mission_policy(Policy::new("production", 0, vec![]));

        assert!(policy.validate().is_err());
    }

    #[test]
    fn policy_evaluate_rejects_empty_id() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let policy = crate::test_support::mission_policy(Policy::new(
            "",
            1,
            vec![PolicyRule::new(
                "allow-read",
                "read_data",
                PolicyEffect::Allow,
            )],
        ));

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

        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("allow-read-1", "read_data", PolicyEffect::Allow),
                PolicyRule::new("allow-read-2", "read_data", PolicyEffect::Allow),
            ],
        ));

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

        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            0,
            vec![PolicyRule::new(
                "allow-read",
                "read_data",
                PolicyEffect::Allow,
            )],
        ));

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
                let policy = crate::test_support::mission_policy(Policy::new(
                    "precedence-test",
                    1,
                    vec![
                        PolicyRule::new("rule-left", "read_data", left_effect.clone()),
                        PolicyRule::new("rule-right", "read_data", right_effect.clone()),
                    ],
                ));

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
        let policy = crate::test_support::mission_policy(Policy::new(
            "production",
            1,
            vec![
                PolicyRule::new("read-rule", "read_data", PolicyEffect::Allow),
                PolicyRule::new("read-rule", "read_data", PolicyEffect::Deny),
            ],
        ));

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
        let policy = crate::test_support::mission_policy(Policy::new(
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
        ));

        let decision = policy
            .evaluate(
                &agent,
                &authority,
                &crate::test_support::mission(action.clone()),
            )
            .unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Allow);
    }

    #[test]
    fn restrictive_conditions_fail_closed_when_values_are_missing_or_mistyped() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["data:read".into()]);
        let policy = crate::test_support::mission_policy(Policy::new_v2(
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
        ));

        for parameters in [
            json!({}),
            json!({"record_count": "5000"}),
            json!({"record_count": 5000.0}),
            json!({"record_count": 5e3}),
        ] {
            let action = Action::new("read_data", None, parameters).unwrap();
            let decision = policy
                .evaluate(
                    &agent,
                    &authority,
                    &crate::test_support::mission(action.clone()),
                )
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
        let policy = crate::test_support::mission_policy(Policy::new_v2(
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
        ));
        let action = Action::new("read_data", Some("development".into()), json!({})).unwrap();

        let decision = policy
            .evaluate(
                &agent,
                &authority,
                &crate::test_support::mission(action.clone()),
            )
            .unwrap();
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
        let policy = crate::test_support::mission_policy(Policy::new(
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
        ));

        let decision = policy
            .evaluate(
                &agent,
                &authority,
                &crate::test_support::mission(action.clone()),
            )
            .unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert!(decision.contributions.is_empty());
    }

    #[test]
    fn context_conditions_are_matched_independently_of_action_parameters() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);
        let mut context = BTreeMap::new();
        context.insert("risk_level".into(), json!(2));
        let policy = crate::test_support::mission_policy(Policy::new(
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
        ));

        let decision = policy
            .evaluate_with_context(&agent, &authority, &test_action(), &context)
            .unwrap();

        assert_eq!(decision.outcome, DecisionOutcome::Allow);
    }

    #[test]
    fn policy_validation_rejects_contradictory_conditions() {
        let policy = crate::test_support::mission_policy(Policy::new(
            "invalid-policy",
            1,
            vec![
                PolicyRule::new("unreachable", "read_data", PolicyEffect::Allow)
                    .with_parameter_condition(PolicyCondition::exact("region", json!("north")))
                    .with_parameter_condition(PolicyCondition::exact("region", json!("south"))),
            ],
        ));

        assert!(matches!(
            policy.validate(),
            Err(PraetoreError::PolicyEvaluationFailed(_))
        ));
    }

    #[test]
    fn policy_digest_is_stable_and_sensitive_to_policy_changes() {
        let policy = crate::test_support::mission_policy(Policy::new(
            "digest-test",
            1,
            vec![
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow)
                    .with_parameter_condition(PolicyCondition::exact("enabled", json!(true))),
            ],
        ));
        let same_policy = policy.clone();
        let changed_policy = crate::test_support::mission_policy(Policy::new(
            "digest-test",
            1,
            vec![PolicyRule::new(
                "allow-read",
                "read_data",
                PolicyEffect::Deny,
            )],
        ));

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
        let v1 =
            crate::test_support::mission_policy(Policy::new("versioned-policy", 1, rules.clone()));
        let v2 = crate::test_support::mission_policy(Policy::new_v2("versioned-policy", 1, rules));

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
            ConditionMatch::MixedNumber(false)
        );
        assert_eq!(
            mixed_type.matches(&json!({"count": 2}), false),
            ConditionMatch::MixedNumber(true)
        );
        assert_eq!(
            mixed_type.matches(&json!({"count": "2"}), true),
            ConditionMatch::Unknown
        );
    }

    #[test]
    fn integer_float_comparison_is_exact_without_lossy_casts() {
        let cases: &[(i128, f64, Ordering)] = &[
            (10_000, 10_000.0, Ordering::Equal),
            (10_000, 10_000.5, Ordering::Less),
            (10_001, 10_000.5, Ordering::Greater),
            (-3, -2.5, Ordering::Less),
            (-2, -2.5, Ordering::Greater),
            (0, -0.0, Ordering::Equal),
            // 2^53 + 1 is not representable as f64; a lossy cast would say Equal.
            (
                9_007_199_254_740_993,
                9_007_199_254_740_992.0,
                Ordering::Greater,
            ),
            (i64::MAX.into(), 9_223_372_036_854_775_808.0, Ordering::Less),
            (
                u64::MAX.into(),
                18_446_744_073_709_551_616.0,
                Ordering::Less,
            ),
            (
                i64::MIN.into(),
                -9_223_372_036_854_775_808.0,
                Ordering::Equal,
            ),
            (u64::MAX.into(), 1e300, Ordering::Less),
            (i64::MIN.into(), -1e300, Ordering::Greater),
            (0, f64::MIN_POSITIVE, Ordering::Less),
        ];
        for &(integer, float, expected) in cases {
            assert_eq!(
                compare_integer_float(integer, float),
                Some(expected),
                "{integer} vs {float}"
            );
        }
        assert_eq!(compare_integer_float(0, f64::NAN), None);
    }

    fn golden_v2_policy() -> Policy {
        Policy::new(
            "golden",
            1,
            vec![PolicyRule::new(
                "allow-read",
                "read_data",
                PolicyEffect::Allow,
            )],
        )
        .with_mission_actions(["read_data"])
        .with_action_class("safety:halt", ActionClass::Safety)
    }

    #[test]
    fn format_1_golden_vector_keeps_its_historical_digest() {
        let v1 = include_str!("../../../docs/golden/canonical-policy-v1.json").trim();
        let recorded = RecordedPolicy::from_json(v1).unwrap();
        assert_eq!(recorded.format_version(), 1);
        assert_eq!(
            recorded.digest(),
            "5d45f213fc1f9fcfa17bf0a462169ea9e14efa028d873b79841924eae90ddd1f"
        );
        assert_eq!(
            recorded.digest(),
            hex::encode(Sha256::digest(v1.as_bytes()))
        );
        // Loading it for evaluation is refused, in every mode.
        assert!(matches!(
            Policy::from_json(v1),
            Err(PraetoreError::PolicyFormatUnsupported {
                found: 1,
                supported: 2
            })
        ));
    }

    #[test]
    fn policy_canonical_bytes_match_committed_golden_v2_vector() {
        let policy = golden_v2_policy();
        let expected = include_str!("../../../docs/golden/canonical-policy-v2.json").trim();
        let canonical = canonical_json(&policy).unwrap();
        let expected_digest = hex::encode(Sha256::digest(expected.as_bytes()));

        assert_eq!(String::from_utf8(canonical).unwrap(), expected);
        assert_eq!(policy.digest().unwrap(), expected_digest);
        // Pinned, so a regenerated vector cannot follow a canonicalization
        // change unnoticed.
        assert_eq!(
            policy.digest().unwrap(),
            "77821c2735152448004f6780288dbb793bc1a78c204c5d0e460e859e89753cd0"
        );
        assert_eq!(
            RecordedPolicy::from_json(expected).unwrap().digest(),
            expected_digest
        );
        assert_eq!(Policy::from_json(expected).unwrap(), policy);
    }
}
