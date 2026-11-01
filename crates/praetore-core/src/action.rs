use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    canonical::{MAX_JSON_VALUE_BYTES, validate_json_value},
    error::{PraetoreError, Result},
};

const MAX_ACTION_NAME_BYTES: usize = 256;
const MAX_ACTION_TARGET_BYTES: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// An operation presented for authorization.
///
/// Set the required capability explicitly for Strict and HighAssurance
/// evaluation.
///
/// ```
/// use praetore_core::Action;
/// use serde_json::json;
///
/// let action = Action::new("read_data", Some("dataset-1".into()), json!({}))
///     .expect("valid action")
///     .with_capability("data:read");
/// assert_eq!(action.capability.as_deref(), Some("data:read"));
/// ```
pub struct Action {
    pub action_type: String,
    pub capability: Option<String>,
    pub target: Option<String>,
    pub parameters: Value,
}

impl Action {
    pub fn new(
        action_type: impl Into<String>,
        target: Option<String>,
        parameters: Value,
    ) -> Result<Self> {
        let action_type = action_type.into();

        if action_type.trim().is_empty() {
            return Err(PraetoreError::InvalidRequest(
                "action type cannot be empty".into(),
            ));
        }

        let target = target.map(|value| value.trim().to_string());

        if target.as_deref() == Some("") {
            return Err(PraetoreError::InvalidRequest(
                "action target cannot be empty".into(),
            ));
        }

        let action = Self {
            action_type,
            capability: None,
            target,
            parameters,
        };
        action.validate()?;
        Ok(action)
    }

    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.capability = Some(capability.into());
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.action_type.trim().is_empty() {
            return Err(PraetoreError::InvalidRequest(
                "action type cannot be empty".into(),
            ));
        }

        if self.action_type != self.action_type.trim() {
            return Err(PraetoreError::InvalidRequest(
                "action type cannot have leading or trailing whitespace".into(),
            ));
        }

        if self.action_type.len() > MAX_ACTION_NAME_BYTES {
            return Err(PraetoreError::InvalidRequest(
                "action type exceeds maximum length".into(),
            ));
        }

        if self.capability.as_deref().is_some_and(|capability| {
            capability.trim().is_empty() || capability != capability.trim()
        }) {
            return Err(PraetoreError::InvalidRequest(
                "action capability must be a non-empty canonical name".into(),
            ));
        }

        if self
            .capability
            .as_deref()
            .is_some_and(|capability| capability.len() > MAX_ACTION_NAME_BYTES)
        {
            return Err(PraetoreError::InvalidRequest(
                "action capability exceeds maximum length".into(),
            ));
        }

        if self.target.as_deref() == Some("") {
            return Err(PraetoreError::InvalidRequest(
                "action target cannot be empty".into(),
            ));
        }

        if self
            .target
            .as_deref()
            .is_some_and(|target| target.trim().is_empty())
        {
            return Err(PraetoreError::InvalidRequest(
                "action target cannot be whitespace".into(),
            ));
        }

        if self
            .target
            .as_deref()
            .is_some_and(|target| target != target.trim())
        {
            return Err(PraetoreError::InvalidRequest(
                "action target cannot have leading or trailing whitespace".into(),
            ));
        }

        if self
            .target
            .as_deref()
            .is_some_and(|target| target.len() > MAX_ACTION_TARGET_BYTES)
        {
            return Err(PraetoreError::InvalidRequest(
                "action target exceeds maximum length".into(),
            ));
        }

        if !self.parameters.is_object() {
            return Err(PraetoreError::InvalidRequest(
                "action parameters must be a JSON object".into(),
            ));
        }

        let parameter_bytes = validate_json_value(&self.parameters)
            .map_err(|error| PraetoreError::InvalidRequest(error.to_string()))?;
        if parameter_bytes > MAX_JSON_VALUE_BYTES {
            return Err(PraetoreError::InvalidRequest(
                "action parameters exceed maximum size".into(),
            ));
        }

        Ok(())
    }
}

/// A mission action: an [`Action`] that the policy's `action_classes`
/// declares [`ActionClass::Mission`](crate::policy::ActionClass::Mission).
///
/// The only public constructor is [`Policy::classify`](crate::Policy::classify), so
/// an [`AuthorizationRequest`](crate::AuthorizationRequest) (whose `action`
/// is a `MissionAction`) cannot carry a safety action. It serializes exactly
/// like the wrapped [`Action`], so signed intents and receipts keep their
/// bytes. It implements no `Deserialize` and no mutable access: the wrapped
/// action cannot be replaced or edited after classification.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct MissionAction(Action);

/// A safety action: an [`Action`] whose type starts with `safety:` and that
/// the policy declares [`ActionClass::Safety`](crate::policy::ActionClass::Safety).
///
/// PRÆTORE makes no decision about it. The authorization engine cannot
/// receive one: nothing converts a `SafetyAction` into a [`MissionAction`].
/// Entry points answer it with
/// [`PraetoreError::SafetyActionNotGoverned`] before any replay claim,
/// journal write or signature.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct SafetyAction(Action);

/// An action whose type the policy's `action_classes` does not declare,
/// built only by [`Policy::unclassified`](crate::Policy::unclassified).
///
/// It is never evaluated against policy rules. The engine accepts it only in
/// [`AuthorizationEngine::refuse_unclassified`](crate::engine::AuthorizationEngine::refuse_unclassified),
/// which verifies the request like a mission request (identity, authority,
/// intent signature and, in HighAssurance, freshness and replay) and then
/// records a signed DENY decided by the engine guard `unclassified_action`.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct UnclassifiedAction(Action);

impl UnclassifiedAction {
    pub(crate) fn unclassified(action: Action) -> Self {
        Self(action)
    }

    pub fn action(&self) -> &Action {
        &self.0
    }

    pub fn into_action(self) -> Action {
        self.0
    }
}

impl std::ops::Deref for UnclassifiedAction {
    type Target = Action;

    fn deref(&self) -> &Action {
        &self.0
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::MissionAction {}
    impl Sealed for super::UnclassifiedAction {}
}

/// The action types an [`AuthorizationRequest`](crate::AuthorizationRequest)
/// can carry: [`MissionAction`] (evaluated against the policy) and
/// [`UnclassifiedAction`] (refused by the engine without evaluation). The
/// trait is sealed; [`SafetyAction`] does not implement it.
pub trait RequestAction:
    sealed::Sealed + Serialize + Clone + std::fmt::Debug + Send + Sync
{
    /// The wrapped action.
    fn action(&self) -> &Action;
    /// `Some` only for a mission action: the only kind that reaches policy
    /// rules.
    #[doc(hidden)]
    fn as_mission(&self) -> Option<&MissionAction>;
    /// Checks that `policy` still gives the action this kind (declared
    /// Mission, or not declared at all).
    #[doc(hidden)]
    fn check_class(&self, policy: &crate::Policy) -> Result<()>;
}

impl RequestAction for MissionAction {
    fn action(&self) -> &Action {
        &self.0
    }

    fn as_mission(&self) -> Option<&MissionAction> {
        Some(self)
    }

    fn check_class(&self, policy: &crate::Policy) -> Result<()> {
        policy.require_mission(self)
    }
}

impl RequestAction for UnclassifiedAction {
    fn action(&self) -> &Action {
        &self.0
    }

    fn as_mission(&self) -> Option<&MissionAction> {
        None
    }

    fn check_class(&self, policy: &crate::Policy) -> Result<()> {
        policy.require_unclassified(self)
    }
}

/// The result of [`Policy::classify`](crate::Policy::classify).
#[derive(Debug, Clone)]
pub enum ClassifiedAction {
    Mission(MissionAction),
    Safety(SafetyAction),
}

impl MissionAction {
    /// Wraps an action the policy declared Mission. Only
    /// `Policy::classify` calls it.
    pub(crate) fn classified(action: Action) -> Self {
        Self(action)
    }

    /// Rebuilds a recorded action only to check a signature over its
    /// recorded bytes ([`crate::Evidence::verify_agent_intent`]). Never
    /// evaluated.
    pub(crate) fn recorded_for_signature_check(action: Action) -> Self {
        Self(action)
    }

    pub fn action(&self) -> &Action {
        &self.0
    }

    pub fn into_action(self) -> Action {
        self.0
    }
}

impl SafetyAction {
    pub(crate) fn classified(action: Action) -> Self {
        Self(action)
    }

    pub fn action(&self) -> &Action {
        &self.0
    }

    pub fn into_action(self) -> Action {
        self.0
    }

    /// The refusal an entry point returns for this action.
    pub fn not_governed(&self) -> PraetoreError {
        PraetoreError::SafetyActionNotGoverned {
            action_type: self.0.action_type.clone(),
        }
    }
}

impl std::ops::Deref for MissionAction {
    type Target = Action;

    fn deref(&self) -> &Action {
        &self.0
    }
}

impl std::ops::Deref for SafetyAction {
    type Target = Action;

    fn deref(&self) -> &Action {
        &self.0
    }
}

impl ClassifiedAction {
    /// The mission action, or [`PraetoreError::SafetyActionNotGoverned`] for
    /// a safety action.
    pub fn into_mission(self) -> Result<MissionAction> {
        match self {
            Self::Mission(action) => Ok(action),
            Self::Safety(action) => Err(action.not_governed()),
        }
    }

    pub fn action(&self) -> &Action {
        match self {
            Self::Mission(action) => action.action(),
            Self::Safety(action) => action.action(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn creates_valid_action() {
        let action =
            Action::new("read:data", None, json!({"resource": "users"})).expect("valid action");

        assert_eq!(action.action_type, "read:data");
        assert_eq!(action.target, None);
    }

    #[test]
    fn preserves_valid_target() {
        let action = Action::new(
            "read:data",
            Some("database".into()),
            json!({"resource": "users"}),
        )
        .expect("valid action");

        assert_eq!(action.target.as_deref(), Some("database"));
    }

    #[test]
    fn normalizes_target_whitespace() {
        let action = Action::new(
            "read:data",
            Some("  database  ".into()),
            json!({"resource": "users"}),
        )
        .expect("valid action");

        assert_eq!(action.target.as_deref(), Some("database"));
    }

    #[test]
    fn action_can_declare_an_explicit_authority_capability() {
        let action = Action::new("read_data", None, json!({}))
            .unwrap()
            .with_capability("read:data");

        assert_eq!(action.capability.as_deref(), Some("read:data"));
        assert!(action.validate().is_ok());
    }

    #[test]
    fn rejects_empty_explicit_capability() {
        let action = Action::new("read_data", None, json!({}))
            .unwrap()
            .with_capability("   ");

        assert!(action.validate().is_err());
    }

    #[test]
    fn rejects_empty_action_type() {
        let result = Action::new("", None, Value::Null);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_whitespace_action_type() {
        let result = Action::new("   ", None, Value::Null);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_action_type_with_surrounding_whitespace() {
        let result = Action::new(" read_data ", None, json!({}));

        assert!(result.is_err());
    }

    #[test]
    fn rejects_non_object_parameters() {
        let result = Action::new("read_data", None, json!(["users"]));

        assert!(matches!(result, Err(PraetoreError::InvalidRequest(_))));
    }

    #[test]
    fn rejects_empty_target() {
        let result = Action::new("read:data", Some(String::new()), Value::Null);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_whitespace_target() {
        let result = Action::new("read:data", Some("   ".into()), Value::Null);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_action_after_construction() {
        let action = Action {
            action_type: "   ".into(),
            capability: None,
            target: None,
            parameters: Value::Null,
        };

        assert!(action.validate().is_err());
    }

    #[test]
    fn rejects_invalid_target_after_construction() {
        let action = Action {
            action_type: "read:data".into(),
            capability: None,
            target: Some("   ".into()),
            parameters: Value::Null,
        };

        assert!(action.validate().is_err());
    }
}
