use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{PraetoreError, Result};

/// A concrete operation an agent is requesting authorization to perform.
///
/// The action itself describes intent and context. Whether that action is
/// permitted is determined by authority and policy evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub action_type: String,
    pub target: Option<String>,
    pub parameters: Value,
}

impl Action {
    pub fn new(
        action_type: impl Into<String>,
        target: Option<String>,
        parameters: Value,
    ) -> Result<Self> {
        let action = Self {
            action_type: action_type.into(),
            target,
            parameters,
        };

        action.validate()?;

        Ok(action)
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

        if let Some(target) = &self.target {
            if target.trim().is_empty() {
                return Err(PraetoreError::InvalidRequest(
                    "action target cannot be empty when provided".into(),
                ));
            }

            if target != target.trim() {
                return Err(PraetoreError::InvalidRequest(
                    "action target cannot have leading or trailing whitespace".into(),
                ));
            }
        }

        if !self.parameters.is_object() {
            return Err(PraetoreError::InvalidRequest(
                "action parameters must be a JSON object".into(),
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
        let action = Action::new(
            "read_data",
            Some("database".into()),
            json!({"table": "users"}),
        )
        .expect("valid action");

        assert_eq!(action.action_type, "read_data");
        assert_eq!(action.target.as_deref(), Some("database"));
        assert_eq!(action.parameters["table"], "users");
        assert!(action.validate().is_ok());
    }

    #[test]
    fn rejects_empty_action_type() {
        let result = Action::new("", None, json!({}));

        assert!(matches!(result, Err(PraetoreError::InvalidRequest(_))));
    }

    #[test]
    fn rejects_whitespace_action_type() {
        let result = Action::new("   ", None, json!({}));

        assert!(matches!(result, Err(PraetoreError::InvalidRequest(_))));
    }

    #[test]
    fn rejects_action_type_with_surrounding_whitespace() {
        let result = Action::new(" read_data ", None, json!({}));

        assert!(matches!(result, Err(PraetoreError::InvalidRequest(_))));
    }

    #[test]
    fn rejects_empty_target() {
        let result = Action::new("read_data", Some(String::new()), json!({}));

        assert!(matches!(result, Err(PraetoreError::InvalidRequest(_))));
    }

    #[test]
    fn rejects_whitespace_target() {
        let result = Action::new("read_data", Some("   ".into()), json!({}));

        assert!(matches!(result, Err(PraetoreError::InvalidRequest(_))));
    }

    #[test]
    fn rejects_target_with_surrounding_whitespace() {
        let result = Action::new("read_data", Some(" database ".into()), json!({}));

        assert!(matches!(result, Err(PraetoreError::InvalidRequest(_))));
    }

    #[test]
    fn accepts_action_without_target() {
        let action = Action::new("health_check", None, json!({})).expect("valid action");

        assert!(action.validate().is_ok());
    }

    #[test]
    fn accepts_object_parameters() {
        let action = Action::new(
            "query",
            Some("database".into()),
            json!({
                "table": "users",
                "limit": 10,
                "active": true
            }),
        )
        .expect("valid action");

        assert!(action.validate().is_ok());
    }

    #[test]
    fn rejects_non_object_parameters() {
        let result = Action::new("query", None, json!(["users", "orders"]));

        assert!(matches!(result, Err(PraetoreError::InvalidRequest(_))));
    }

    #[test]
    fn validate_rejects_tampered_action() {
        let mut action = Action::new(
            "read_data",
            Some("database".into()),
            json!({"table": "users"}),
        )
        .unwrap();

        action.action_type.clear();

        assert!(matches!(
            action.validate(),
            Err(PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn validate_rejects_tampered_parameters() {
        let mut action = Action::new(
            "read_data",
            Some("database".into()),
            json!({"table": "users"}),
        )
        .unwrap();

        action.parameters = json!("not-an-object");

        assert!(matches!(
            action.validate(),
            Err(PraetoreError::InvalidRequest(_))
        ));
    }
}
