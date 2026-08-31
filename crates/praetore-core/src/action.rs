use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{PraetoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let action_type = action_type.into();

        if action_type.trim().is_empty() {
            return Err(PraetoreError::InvalidRequest(
                "action type cannot be empty".into(),
            ));
        }

        Ok(Self {
            action_type,
            target,
            parameters,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.action_type.trim().is_empty() {
            return Err(PraetoreError::InvalidRequest(
                "action type cannot be empty".into(),
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
    fn rejects_invalid_action_after_construction() {
        let action = Action {
            action_type: "   ".into(),
            target: None,
            parameters: Value::Null,
        };

        assert!(action.validate().is_err());
    }
}
