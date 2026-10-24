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
            .map_err(|message| PraetoreError::InvalidRequest(message.into()))?;
        if parameter_bytes > MAX_JSON_VALUE_BYTES {
            return Err(PraetoreError::InvalidRequest(
                "action parameters exceed maximum size".into(),
            ));
        }

        Ok(())
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
