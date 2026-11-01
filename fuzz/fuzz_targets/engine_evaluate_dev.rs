#![no_main]

use libfuzzer_sys::fuzz_target;
use praetore_core::{
    ClassifiedAction,
    action::Action,
    authority::Authority,
    authorization::AuthorizationRequest,
    engine::AuthorizationEngine,
    identity::{AgentId, AgentIdentity},
    policy::{ActionClass, Policy},
};
use serde_json::Value;

fuzz_target!(|input: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(input) else {
        return;
    };
    let Some(parameters) = value.get("parameters").filter(|value| value.is_object()) else {
        return;
    };
    let agent = match AgentIdentity::new(AgentId::new(), vec![1; 32], "ed25519") {
        Ok(agent) => agent,
        Err(_) => return,
    };
    let action_type = value
        .get("action_type")
        .and_then(Value::as_str)
        .unwrap_or("fuzz_action");
    let Ok(action) = Action::new(action_type, None, parameters.clone()) else {
        return;
    };
    let authority = Authority::new(agent.id.clone(), "fuzz-issuer", vec![]);
    let policy = Policy::new("fuzz-policy", 1, vec![])
        .with_mission_actions(["fuzz_action"])
        .with_action_class("safety:halt", ActionClass::Safety);
    // G7: only a Mission action reaches the engine, and an action type with
    // the `safety:` prefix is never one.
    let classified = policy.classify(action);
    if action_type.starts_with("safety:") {
        assert!(!matches!(classified, Ok(ClassifiedAction::Mission(_))));
    }
    let Ok(ClassifiedAction::Mission(action)) = classified else {
        return;
    };
    let Ok(request) = AuthorizationRequest::new(agent, authority, action) else {
        return;
    };
    let engine = AuthorizationEngine::development(policy);
    let _ = engine.evaluate(request);
});
