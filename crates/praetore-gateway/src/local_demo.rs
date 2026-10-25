use crate::{ActionDispatcher, DispatchError, DispatchReport, ExecutionKey, ReconciliationReport};
use praetore_core::Action;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
struct DemoState {
    values: HashMap<String, String>,
    executions: HashMap<ExecutionKey, (String, Value)>,
}

/// An in-memory demonstration adapter for a single local key/value tool.
///
/// It accepts only `demo:set_value` calls against `demo-state`. It has no
/// network access or connection to production systems. Its state and
/// reconciliation records are lost on process restart.
#[derive(Default)]
pub struct LocalDemoDispatcher {
    state: Mutex<DemoState>,
}

impl LocalDemoDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn value(&self, key: &str) -> Option<String> {
        self.state.lock().ok()?.values.get(key).cloned()
    }
}

impl ActionDispatcher for LocalDemoDispatcher {
    fn dispatch(
        &self,
        key: ExecutionKey,
        action: &Action,
        action_digest: &str,
    ) -> Result<DispatchReport, DispatchError> {
        if crate::action_digest(action).map_or(true, |digest| digest != action_digest)
            || action.action_type != "demo:set_value"
            || action.capability.as_deref() != Some("demo:write")
            || action.target.as_deref() != Some("demo-state")
        {
            return Err(DispatchError);
        }
        let parameters = action.parameters.as_object().ok_or(DispatchError)?;
        if parameters.len() != 2 {
            return Err(DispatchError);
        }
        let name = parameters
            .get("key")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty() && name.len() <= 128)
            .ok_or(DispatchError)?;
        let value = parameters
            .get("value")
            .and_then(Value::as_str)
            .filter(|value| value.len() <= 1024)
            .ok_or(DispatchError)?;

        let mut state = self.state.lock().map_err(|_| DispatchError)?;
        if let Some((existing_digest, output)) = state.executions.get(&key) {
            if existing_digest == action_digest {
                return Ok(DispatchReport::Confirmed(output.clone()));
            }
            return Err(DispatchError);
        }

        let output = json!({"key": name, "value": value});
        state.values.insert(name.to_owned(), value.to_owned());
        state
            .executions
            .insert(key, (action_digest.to_owned(), output.clone()));
        Ok(DispatchReport::Confirmed(output))
    }

    fn reconcile(
        &self,
        key: ExecutionKey,
        _action: &Action,
        action_digest: &str,
    ) -> ReconciliationReport {
        let Ok(state) = self.state.lock() else {
            return ReconciliationReport::Unknown;
        };
        match state.executions.get(&key) {
            Some((recorded_digest, output)) if recorded_digest == action_digest => {
                ReconciliationReport::Applied(output.clone())
            }
            _ => ReconciliationReport::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    fn action(name: &str, value: &str) -> Action {
        Action::new(
            "demo:set_value",
            Some("demo-state".into()),
            json!({"key": name, "value": value}),
        )
        .unwrap()
        .with_capability("demo:write")
    }

    fn key() -> ExecutionKey {
        ExecutionKey {
            agent_id: Uuid::from_u128(1),
            request_id: Uuid::from_u128(2),
        }
    }

    #[test]
    fn dispatch_changes_only_local_demo_state_and_reconciles_exact_digest() {
        let dispatcher = LocalDemoDispatcher::new();
        let action = action("mode", "safe");
        let key = key();
        let digest = crate::action_digest(&action).unwrap();

        assert_eq!(
            dispatcher.dispatch(key, &action, &digest).unwrap(),
            DispatchReport::Confirmed(json!({"key": "mode", "value": "safe"}))
        );
        assert_eq!(dispatcher.value("mode").as_deref(), Some("safe"));
        assert_eq!(
            dispatcher.reconcile(key, &action, &digest),
            ReconciliationReport::Applied(json!({"key": "mode", "value": "safe"}))
        );
        assert_eq!(
            dispatcher.reconcile(key, &action, "different-digest"),
            ReconciliationReport::Unknown
        );
    }

    #[test]
    fn repeated_dispatch_is_idempotent_and_conflicting_reuse_fails() {
        let dispatcher = LocalDemoDispatcher::new();
        let action = action("mode", "safe");
        let key = key();
        let digest = crate::action_digest(&action).unwrap();

        let first = dispatcher.dispatch(key, &action, &digest).unwrap();
        let second = dispatcher.dispatch(key, &action, &digest).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            dispatcher.dispatch(key, &action, "different-digest"),
            Err(DispatchError)
        );
        assert_eq!(dispatcher.value("mode").as_deref(), Some("safe"));
    }

    #[test]
    fn unsupported_actions_are_rejected_without_effect() {
        let dispatcher = LocalDemoDispatcher::new();
        let invalid = Action::new(
            "demo:delete_all",
            Some("demo-state".into()),
            json!({"key": "mode", "value": "unsafe"}),
        )
        .unwrap()
        .with_capability("demo:write");

        assert_eq!(
            dispatcher.dispatch(key(), &invalid, &crate::action_digest(&invalid).unwrap()),
            Err(DispatchError)
        );
        assert_eq!(dispatcher.value("mode"), None);
    }
}
