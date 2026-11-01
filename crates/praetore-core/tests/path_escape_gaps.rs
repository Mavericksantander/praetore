//! T-014 path-restriction escapes against `PathPrefix`.
//!
//! A symlink whose path string stays inside the prefix is still allowed by
//! core; that test is ignored because running it fails. It is an accepted
//! limitation of core: praetore-mcp resolves the arguments before evaluation
//! and has the end-to-end version of this case in its `tests/wrap.rs`. The lexical `..` and
//! absolute-path-outside-the-prefix cases are covered on main by
//! `tests/path_prefix.rs` (`path_prefix_allows_only_normalized_paths_inside_prefix`,
//! `safe_path_prefix_rejects_dot_dot_traversal`), so they are not repeated here.

use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, DecisionOutcome, Policy, PolicyCondition,
    PolicyEffect, PolicyRule,
};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

struct TempTree(PathBuf);

impl TempTree {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("praetore-t014-{}", uuid_name()));
        fs::create_dir_all(root.join("sandbox")).unwrap();
        fs::create_dir_all(root.join("outside")).unwrap();
        fs::write(root.join("outside").join("secret"), b"secret").unwrap();
        Self(root)
    }

    fn root(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn uuid_name() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{nanos}")
}

fn outcome(prefix: &str, path: &str) -> DecisionOutcome {
    let agent = AgentKeyPair::from_secret_bytes(&[9; 32]).identity(AgentId::new());
    let authority = Authority::new(agent.id.clone(), "path-issuer", vec![]);
    let action = Action::new("modify_file", None, json!({ "path": path })).unwrap();
    let policy = mission_policy(Policy::new(
        "path-policy",
        1,
        vec![
            PolicyRule::new("safe", "modify_file", PolicyEffect::Allow)
                .with_parameter_condition(PolicyCondition::path_prefix("path", prefix)),
        ],
    ));
    policy
        .evaluate(&agent, &authority, &mission((action).clone()))
        .unwrap()
        .outcome
}

#[test]
#[ignore = "T-014 ACCEPTED LIMITATION of core, not a regression: PathPrefix is lexical by design (deterministic evaluation). praetore-mcp resolves covered arguments before evaluation; the same case is checked there by crates/praetore-mcp/tests/wrap.rs::allow_path_prefix_does_not_allow_a_symlink_that_leaves_it. Running this fails with Allow."]
fn path_prefix_allow_rejects_symlink_that_leaves_the_prefix() {
    let tree = TempTree::new();
    let sandbox = tree.root().join("sandbox");
    let target = tree.root().join("outside").join("secret");
    let link = sandbox.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let lexical = link.to_str().unwrap();
    let resolved = fs::canonicalize(&link).unwrap();
    let sandbox_canon = fs::canonicalize(&sandbox).unwrap();
    assert!(
        !resolved.starts_with(&sandbox_canon),
        "fixture symlink must leave the prefix"
    );
    assert_eq!(
        outcome(sandbox.to_str().unwrap(), lexical),
        DecisionOutcome::Deny,
        "symlink {lexical} resolves to {} and must not match an allow PathPrefix",
        resolved.display()
    );
}

/// G7 test helper: declares every action type a rule names as Mission.
#[allow(dead_code)]
fn mission_policy(mut policy: praetore_core::Policy) -> praetore_core::Policy {
    for rule in &policy.rules {
        policy
            .action_classes
            .entry(rule.action_type.clone())
            .or_insert(praetore_core::ActionClass::Mission);
    }
    policy
}

/// G7 test helper: classifies `action` as a Mission action. The engine still
/// checks it against its own policy's `action_classes`.
#[allow(dead_code)]
fn mission(action: praetore_core::Action) -> praetore_core::MissionAction {
    praetore_core::Policy::new("classify", 1, vec![])
        .with_mission_actions([action.action_type.clone()])
        .classify(action)
        .expect("classify")
        .into_mission()
        .expect("mission action")
}
