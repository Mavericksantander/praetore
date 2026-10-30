//! T-014 path-restriction escapes against `PathPrefix`.
//!
//! A symlink whose path string stays inside the prefix is still allowed; that
//! test is ignored because running it fails. The lexical `..` and
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
    let policy = Policy::new(
        "path-policy",
        1,
        vec![
            PolicyRule::new("safe", "modify_file", PolicyEffect::Allow)
                .with_parameter_condition(PolicyCondition::path_prefix("path", prefix)),
        ],
    );
    policy
        .evaluate(&agent, &authority, &action)
        .unwrap()
        .outcome
}

#[test]
#[ignore = "T-014 KNOWN LIMITATION, not a regression: PathPrefix is lexical and allows a symlink inside the prefix whose target is outside. Documented as out of scope on main (README 'Symlinks are out of scope', MatchOperator::PathPrefix docs); confinement must happen in the dispatcher. Running this fails with Allow."]
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
