#![no_main]

//! `PathPrefix` confinement. Invariants checked on every input:
//! - evaluation never panics;
//! - a path with a `..` segment, a NUL byte, or that is not absolute is never
//!   allowed;
//! - an allowed path, after independent lexical normalization, lies inside
//!   the rule prefix on whole segments.

use libfuzzer_sys::fuzz_target;
use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, DecisionOutcome, Policy, PolicyCondition,
    PolicyEffect, PolicyRule,
};
use serde_json::json;

const FIXED_PREFIXES: [&str; 4] = ["/srv/agent", "/srv/agent/", "/", "/a/b/c"];

/// Lexical normalization independent of the engine: drops empty and `.`
/// segments and resolves `..`. Returns `None` for relative paths or for `..`
/// escaping the root.
fn normalize(path: &str) -> Option<Vec<&str>> {
    let rest = path.strip_prefix('/')?;
    let mut out = Vec::new();
    for segment in rest.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                out.pop()?;
            }
            other => out.push(other),
        }
    }
    Some(out)
}

fn has_dot_dot(path: &str) -> bool {
    path.split(['/', '\\']).any(|segment| segment == "..")
}

fuzz_target!(|input: &[u8]| {
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    // `prefix\npath` fuzzes both sides; a bare input uses fixed prefixes.
    let (prefixes, path): (Vec<&str>, &str) = match text.split_once('\n') {
        Some((prefix, path)) => (vec![prefix], path),
        None => (FIXED_PREFIXES.to_vec(), text),
    };

    let agent = AgentKeyPair::from_secret_bytes(&[9; 32]).identity(AgentId::new());
    let authority = Authority::new(agent.id.clone(), "fuzz-issuer", vec![]);
    let Ok(action) = Action::new("modify_file", None, json!({ "path": path })) else {
        return;
    };

    for prefix in prefixes {
        let policy = Policy::new(
            "fuzz-path-prefix",
            1,
            vec![
                PolicyRule::new("safe", "modify_file", PolicyEffect::Allow)
                    .with_parameter_condition(PolicyCondition::path_prefix("path", prefix)),
            ],
        );
        let Ok(decision) = policy.evaluate(&agent, &authority, &action) else {
            continue;
        };
        if decision.outcome != DecisionOutcome::Allow {
            continue;
        }
        assert!(
            !has_dot_dot(path),
            "allowed '..': {path:?} under {prefix:?}"
        );
        assert!(
            !path.contains('\0'),
            "allowed NUL: {path:?} under {prefix:?}"
        );
        let normalized_path = normalize(path)
            .unwrap_or_else(|| panic!("allowed non-absolute or escaping path: {path:?}"));
        let normalized_prefix =
            normalize(prefix).unwrap_or_else(|| panic!("allowed under invalid prefix: {prefix:?}"));
        assert!(
            normalized_path.starts_with(&normalized_prefix),
            "allowed path outside prefix: {path:?} under {prefix:?}"
        );
    }
});
