#![no_main]

//! `PathPrefix` confinement, checked against an independent oracle.
//!
//! Input format: `prefix\npath` fuzzes both sides; an input without `\n` is a
//! path checked against a fixed set of prefixes.
//!
//! Invariants checked on every input, under semantics v1 and v2 (the
//! documented `PathPrefix` contract in `crates/praetore-core/src/policy.rs`):
//! - evaluation never panics;
//! - a rule prefix is accepted on load iff it is absolute and normalized (no
//!   `.`, `..` or empty segments, no `\`, `%` or NUL; one trailing `/` is
//!   allowed);
//! - an `Allow` rule allows exactly the safe paths that lie inside the prefix
//!   on whole segments, byte for byte (no case or Unicode folding);
//! - a `Deny` or `RequireApproval` rule applies to every path that is inside
//!   the prefix and to every unsafe path, and to nothing else (checked with a
//!   catch-all `Allow` rule beside it);
//! - defence in depth: an allowed path never contains a `..` segment or NUL,
//!   and after independent lexical normalization it lies inside the prefix.

use libfuzzer_sys::fuzz_target;
use praetore_core::{
    Action, AgentId, AgentIdentity, AgentKeyPair, Authority, DecisionOutcome, Policy,
    PolicyCondition, PolicyEffect, PolicyRule,
};
use serde_json::json;
use std::sync::OnceLock;

const FIXED_PREFIXES: [&str; 5] = ["/srv/agent", "/srv/agent/", "/", "/a/b/c", "/SRV/Ägent"];

/// Canonical body of an absolute, normalized path (without the leading `/`
/// and without one trailing `/`), or `None` if the path is unsafe. Written
/// as a whole-string check, independently of the engine's segment split.
fn canonical(path: &str) -> Option<&str> {
    let body = path.strip_prefix('/')?;
    if path.contains(['\\', '%', '\0']) {
        return None;
    }
    // As in the engine, `//` reads as the root plus one trailing `/`.
    let body = body.strip_suffix('/').unwrap_or(body);
    if body.is_empty() {
        return Some(body);
    }
    let framed = format!("/{body}/");
    if framed.contains("//") || framed.contains("/./") || framed.contains("/../") {
        return None;
    }
    Some(body)
}

/// Whether a safe `path` lies inside a valid `prefix` on whole segments.
fn inside(prefix: &str, path: &str) -> bool {
    prefix.is_empty()
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Lexical normalization: drops empty and `.` segments and resolves `..`.
/// Returns `None` for relative paths or for `..` escaping the root.
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

fn condition(prefix: &str) -> PolicyCondition {
    PolicyCondition::path_prefix("path", prefix)
}

fn policy(semantics: u8, rules: Vec<PolicyRule>) -> Policy {
    if semantics == 2 {
        Policy::new_v2("fuzz-path-prefix", 1, rules)
    } else {
        Policy::new("fuzz-path-prefix", 1, rules)
    }
}

fn check_allowed_path(prefix: &str, path: &str) {
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

fn check(agent: &AgentIdentity, authority: &Authority, action: &Action, prefix: &str, path: &str) {
    let canonical_prefix = canonical(prefix);
    // `None`: unsafe path. `Some(inside)`: safe path, inside the prefix or not.
    let expected = canonical(path).map(|path| canonical_prefix.is_some_and(|p| inside(p, path)));

    for semantics in [1, 2] {
        let allow = policy(
            semantics,
            vec![
                PolicyRule::new("confined", "modify_file", PolicyEffect::Allow)
                    .with_parameter_condition(condition(prefix)),
            ],
        );
        let result = allow.evaluate(agent, authority, action);
        let Some(canonical_prefix) = canonical_prefix else {
            assert!(
                result.is_err(),
                "invalid prefix accepted: {prefix:?} (v{semantics})"
            );
            continue;
        };
        // Valid prefixes can still fail on size limits; nothing to compare.
        let Ok(decision) = result else {
            continue;
        };
        let should_allow = expected == Some(true);
        assert_eq!(
            decision.outcome == DecisionOutcome::Allow,
            should_allow,
            "Allow rule: {path:?} under {prefix:?} (canonical {canonical_prefix:?}, v{semantics}) gave {:?}",
            decision.outcome
        );
        if should_allow {
            check_allowed_path(prefix, path);
        }

        // Restrictive rules next to a catch-all Allow: each must apply to
        // every inside path and every unsafe path, and only to those. One
        // policy checks both effects through the per-rule contributions.
        let restricted = expected != Some(false);
        let restrictive = policy(
            semantics,
            vec![
                PolicyRule::new("anything", "modify_file", PolicyEffect::Allow),
                PolicyRule::new("deny", "modify_file", PolicyEffect::Deny)
                    .with_parameter_condition(condition(prefix)),
                PolicyRule::new("approval", "modify_file", PolicyEffect::RequireApproval)
                    .with_parameter_condition(condition(prefix)),
            ],
        );
        let decision = restrictive
            .evaluate(agent, authority, action)
            .unwrap_or_else(|error| {
                panic!("restrictive policy failed after Allow policy loaded: {error}")
            });
        let mut matched: Vec<(&str, DecisionOutcome)> = decision
            .contributions
            .iter()
            .map(|contribution| (contribution.rule_id.as_str(), contribution.outcome))
            .collect();
        matched.sort_by_key(|(rule_id, _)| *rule_id);
        let wanted: &[(&str, DecisionOutcome)] = if restricted {
            &[
                ("anything", DecisionOutcome::Allow),
                ("approval", DecisionOutcome::RequireApproval),
                ("deny", DecisionOutcome::Deny),
            ]
        } else {
            &[("anything", DecisionOutcome::Allow)]
        };
        assert_eq!(
            matched, wanted,
            "restrictive rules: {path:?} under {prefix:?} (v{semantics})"
        );
        let outcome = if restricted {
            DecisionOutcome::Deny
        } else {
            DecisionOutcome::Allow
        };
        assert_eq!(
            decision.outcome, outcome,
            "restrictive outcome: {path:?} under {prefix:?} (v{semantics})"
        );
    }
}

fuzz_target!(|input: &[u8]| {
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    let (prefixes, path): (Vec<&str>, &str) = match text.split_once('\n') {
        Some((prefix, path)) => (vec![prefix], path),
        None => (FIXED_PREFIXES.to_vec(), text),
    };

    // Built once: key derivation per input would dominate the run time.
    static PRINCIPAL: OnceLock<(AgentIdentity, Authority)> = OnceLock::new();
    let (agent, authority) = PRINCIPAL.get_or_init(|| {
        let agent = AgentKeyPair::from_secret_bytes(&[9; 32]).identity(AgentId::new());
        let authority = Authority::new(agent.id.clone(), "fuzz-issuer", vec![]);
        (agent, authority)
    });
    let Ok(action) = Action::new("modify_file", None, json!({ "path": path })) else {
        return;
    };

    for prefix in prefixes {
        check(agent, authority, &action, prefix, path);
    }
});
