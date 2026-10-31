//! `praetore-mcp policy ...`: list, add, remove and check rules in the local
//! v2 policy without hand-writing JSON.
//!
//! Generated rules always have every field, `action_type` `mcp.tools/call`
//! and `required_capability` `mcp:tools/call`. Core denies when a restrictive
//! match is *unbound* (the authority lacks the rule's capability, or the
//! action has no target). The local authority grants `mcp:tools/call` and the
//! proxy always sets the target, so generated rules are always bound and a
//! REQUIRE_APPROVAL rule really yields REQUIRE_APPROVAL.

use crate::store::{ACTION_TYPE, CAPABILITY};
use praetore_core::{MatchOperator, Policy, PolicyCondition, PolicyEffect, PolicyRule};
use serde_json::Value;

/// Printed after every policy command.
pub const RESTART_REMINDER: &str = "note: running `praetore-mcp wrap` processes load policy.json when they start; restart your MCP client (or the wrapped servers) to apply policy changes.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgOperator {
    Exact,
    PathPrefix,
    Prefix,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArgCondition {
    pub key: String,
    pub operator: ArgOperator,
    pub value: Value,
}

/// A rule request from the command line.
#[derive(Debug, Clone, Default)]
pub struct RuleSpec {
    pub id: String,
    pub server: Option<String>,
    pub tool: Option<String>,
    pub args: Vec<ArgCondition>,
    pub any_tool: bool,
}

/// Parses `KEY=VALUE`. For `Exact`, VALUE is read as JSON when it is valid
/// JSON (`5`, `true`, `"5"`, `[1]`), otherwise as a plain string.
pub fn parse_arg(spec: &str, operator: ArgOperator) -> Result<ArgCondition, String> {
    let (key, raw) = spec
        .split_once('=')
        .ok_or_else(|| format!("expected KEY=VALUE, got {spec:?}"))?;
    if key.is_empty() || key != key.trim() {
        return Err(format!("invalid argument key in {spec:?}"));
    }
    if key.contains('.') {
        // Only top-level argument fields are flattened. A rule on
        // `arguments.opts.path` would match a literal top-level key
        // "opts.path", which a caller controls, not the nested field.
        return Err(format!(
            "argument key {key:?} contains '.': nested argument fields are not supported, only top-level ones"
        ));
    }
    let value = match operator {
        ArgOperator::Exact => {
            serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_owned()))
        }
        ArgOperator::PathPrefix | ArgOperator::Prefix => {
            if raw.is_empty() {
                return Err(format!("empty prefix in {spec:?}"));
            }
            Value::String(raw.to_owned())
        }
    };
    Ok(ArgCondition {
        key: key.to_owned(),
        operator,
        value,
    })
}

pub fn parse_effect(name: &str) -> Option<PolicyEffect> {
    match name {
        "deny" => Some(PolicyEffect::Deny),
        "require-approval" => Some(PolicyEffect::RequireApproval),
        "allow" => Some(PolicyEffect::Allow),
        _ => None,
    }
}

/// Builds a fully-formed v2 rule, refusing selector-less argument rules.
pub fn build_rule(effect: PolicyEffect, spec: &RuleSpec) -> Result<PolicyRule, String> {
    if spec.id.trim().is_empty() || spec.id != spec.id.trim() {
        return Err("--id must be a non-empty identifier without surrounding spaces".into());
    }
    let scoped = spec.server.is_some() || spec.tool.is_some();
    if !scoped && !spec.any_tool {
        return Err(if spec.args.is_empty() {
            "this rule has no --server, --tool or --arg-*; it would match EVERY tool call. Pass --any-tool if that is intended".into()
        } else {
            "--arg-* without --tool or --server: in v2 policies a call that lacks the argument counts as \"unknown\", which matches DENY/REQUIRE_APPROVAL rules, so this rule would also hit every call of every tool that has no such argument. Add --tool/--server, or pass --any-tool if that is intended".into()
        });
    }
    let mut rule =
        PolicyRule::new(spec.id.clone(), ACTION_TYPE, effect).with_capability(CAPABILITY);
    if let Some(server) = &spec.server {
        rule = rule.with_target(server.clone());
    }
    if let Some(tool) = &spec.tool {
        rule = rule
            .with_parameter_condition(PolicyCondition::exact("tool", Value::String(tool.clone())));
    }
    for arg in &spec.args {
        let key = format!("arguments.{}", arg.key);
        let operator = match arg.operator {
            ArgOperator::Exact => MatchOperator::Exact,
            ArgOperator::PathPrefix => MatchOperator::PathPrefix,
            ArgOperator::Prefix => MatchOperator::Prefix,
        };
        rule =
            rule.with_parameter_condition(PolicyCondition::new(key, operator, arg.value.clone()));
    }
    Ok(rule)
}

/// Serializes and re-parses with `Policy::from_json`, so the exact bytes that
/// will be written are known to be valid.
pub fn render_validated(policy: &Policy) -> Result<String, String> {
    let text = serde_json::to_string_pretty(policy)
        .map(|text| text + "\n")
        .map_err(|e| format!("cannot serialize policy: {e}"))?;
    Policy::from_json(&text).map_err(|e| format!("resulting policy is invalid: {e}"))?;
    Ok(text)
}

fn bump(policy: &mut Policy) -> Result<(), String> {
    policy.version = policy
        .version
        .checked_add(1)
        .ok_or("policy version overflow")?;
    Ok(())
}

/// Appends a rule; returns the new file contents.
pub fn add_rule(policy: &Policy, rule: PolicyRule) -> Result<String, String> {
    if policy.semantics_version != 2 {
        return Err(
            "policy.json is not a v2 policy; praetore-mcp requires semantics_version 2".into(),
        );
    }
    if policy.rules.iter().any(|r| r.id == rule.id) {
        return Err(format!("a rule with id {:?} already exists", rule.id));
    }
    let mut updated = policy.clone();
    updated.rules.push(rule);
    bump(&mut updated)?;
    render_validated(&updated)
}

/// Removes a rule by id; returns the new file contents.
pub fn remove_rule(policy: &Policy, id: &str) -> Result<String, String> {
    let mut updated = policy.clone();
    let before = updated.rules.len();
    updated.rules.retain(|r| r.id != id);
    if updated.rules.len() == before {
        return Err(format!("no rule with id {id:?}"));
    }
    bump(&mut updated)?;
    render_validated(&updated)
}

fn effect_label(effect: &PolicyEffect) -> &'static str {
    match effect {
        PolicyEffect::Allow => "ALLOW",
        PolicyEffect::Deny => "DENY",
        PolicyEffect::RequireApproval => "REQUIRE_APPROVAL",
        _ => "OTHER",
    }
}

fn condition_label(prefix: &str, condition: &PolicyCondition) -> String {
    format!(
        "{prefix}{} {:?} {}",
        condition.key, condition.operator, condition.expected
    )
}

fn cell(value: &str, width: usize) -> String {
    let value = crate::proxy::display_safe(value);
    if value.chars().count() <= width {
        value
    } else {
        let mut out: String = value.chars().take(width.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

pub fn render_list(policy: &Policy) -> String {
    let mut out = format!(
        "policy {} v{} (semantics v{}), {} rule(s)\n{:<28} {:<16} {:<16} {:<20} CONDITIONS\n",
        policy.id,
        policy.version,
        policy.semantics_version,
        policy.rules.len(),
        "ID",
        "EFFECT",
        "SERVER",
        "TOOL"
    );
    for rule in &policy.rules {
        let mut tool = "*".to_owned();
        let mut conditions = Vec::new();
        for condition in &rule.parameter_conditions {
            match (
                &condition.operator,
                condition.key.as_str(),
                &condition.expected,
            ) {
                (MatchOperator::Exact, "tool", Value::String(name)) if tool == "*" => {
                    tool = name.clone();
                }
                _ => conditions.push(condition_label("", condition)),
            }
        }
        conditions.extend(
            rule.context_conditions
                .iter()
                .map(|c| condition_label("context.", c)),
        );
        if rule.action_type != ACTION_TYPE {
            conditions.push(format!(
                "action_type={} (never matches MCP calls)",
                rule.action_type
            ));
        }
        match rule.required_capability.as_deref() {
            Some(CAPABILITY) => {}
            Some(other) => conditions.push(format!("capability={other}")),
            None => conditions.push("no required_capability".into()),
        }
        out.push_str(&format!(
            "{:<28} {:<16} {:<16} {:<20} {}\n",
            cell(&rule.id, 28),
            effect_label(&rule.effect),
            cell(rule.target.as_deref().unwrap_or("*"), 16),
            cell(&tool, 20),
            if conditions.is_empty() {
                "-".to_owned()
            } else {
                crate::proxy::display_safe(&conditions.join("; "))
            }
        ));
    }
    out
}

/// Non-fatal findings that predict surprising decisions in HighAssurance.
pub fn lint(policy: &Policy) -> Vec<String> {
    let mut warnings = Vec::new();
    if policy.semantics_version != 2 {
        warnings.push(
            "semantics_version is not 2: HighAssurance (and praetore-mcp) will refuse this policy"
                .into(),
        );
    }
    if !policy.rules.iter().any(|r| r.effect == PolicyEffect::Allow) {
        warnings.push("no ALLOW rule: every tools/call is denied by default".into());
    }
    for rule in &policy.rules {
        if rule.action_type != ACTION_TYPE {
            warnings.push(format!(
                "rule {:?}: action_type {:?} never matches MCP calls ({ACTION_TYPE})",
                rule.id, rule.action_type
            ));
        }
        match (&rule.effect, rule.required_capability.as_deref()) {
            (PolicyEffect::Allow | PolicyEffect::RequireApproval, None) => warnings.push(format!(
                "rule {:?}: ALLOW/REQUIRE_APPROVAL without required_capability is denied in HighAssurance; use {CAPABILITY}",
                rule.id
            )),
            (_, Some(capability)) if capability != CAPABILITY => warnings.push(format!(
                "rule {:?}: required_capability {capability:?} is not granted by the local authority ({CAPABILITY}); restrictive rules then always DENY, ALLOW rules never match",
                rule.id
            )),
            _ => {}
        }
        let has_selector = rule.target.is_some()
            || rule
                .parameter_conditions
                .iter()
                .any(|c| c.key == "tool" || c.key == "server");
        let has_arg = rule
            .parameter_conditions
            .iter()
            .any(|c| c.key.starts_with("arguments"));
        for condition in &rule.parameter_conditions {
            if condition.operator == MatchOperator::PathPrefix
                && let Some(prefix) = condition.expected.as_str()
                && let (crate::gate::PathCheck::Differs, Some(resolved)) =
                    crate::gate::resolve_path(prefix)
            {
                warnings.push(format!(
                    "rule {:?}: path prefix {prefix:?} resolves to {resolved:?}; a DENY/REQUIRE_APPROVAL rule does not cover arguments under {resolved:?} and an ALLOW rule never matches (arguments are resolved first), so use {resolved:?}",
                    rule.id
                ));
            }
            if let Some(field) = condition.key.strip_prefix("arguments.")
                && field.contains('.')
            {
                warnings.push(format!(
                    "rule {:?}: {:?} does not address a nested field; it matches a literal top-level argument key {field:?}, which the caller controls (nested fields are unsupported)",
                    rule.id, condition.key
                ));
            }
        }
        if rule.effect != PolicyEffect::Allow && has_arg && !has_selector {
            warnings.push(format!(
                "rule {:?}: argument conditions without a tool/server selector also match calls that lack the argument (v2 unknown = match)",
                rule.id
            ));
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::default_policy;
    use serde_json::json;

    fn spec(id: &str) -> RuleSpec {
        RuleSpec {
            id: id.into(),
            ..RuleSpec::default()
        }
    }

    #[test]
    fn parses_arguments() {
        let exact = parse_arg("count=5", ArgOperator::Exact).unwrap();
        assert_eq!(exact.value, json!(5));
        let exact = parse_arg("count=\"5\"", ArgOperator::Exact).unwrap();
        assert_eq!(exact.value, json!("5"));
        let exact = parse_arg("mode=read only", ArgOperator::Exact).unwrap();
        assert_eq!(exact.value, json!("read only"));
        let exact = parse_arg("q=a=b", ArgOperator::Exact).unwrap();
        assert_eq!((exact.key.as_str(), exact.value), ("q", json!("a=b")));
        assert!(parse_arg("novalue", ArgOperator::Exact).is_err());
        assert!(parse_arg("=x", ArgOperator::Exact).is_err());
        assert!(parse_arg("p=", ArgOperator::PathPrefix).is_err());
        assert!(
            parse_arg("opts.path=/x", ArgOperator::PathPrefix)
                .unwrap_err()
                .contains("nested")
        );
    }

    #[test]
    fn generated_rule_is_fully_formed_and_bound() {
        let rule = build_rule(
            PolicyEffect::RequireApproval,
            &RuleSpec {
                server: Some("fs".into()),
                tool: Some("read_file".into()),
                args: vec![parse_arg("path=/secret", ArgOperator::PathPrefix).unwrap()],
                ..spec("approve-secret")
            },
        )
        .unwrap();
        let value = serde_json::to_value(&rule).unwrap();
        assert_eq!(value["required_capability"], CAPABILITY);
        assert_eq!(value["action_type"], ACTION_TYPE);
        assert_eq!(value["target"], "fs");
        assert_eq!(value["context_conditions"], json!([]));
        assert_eq!(value["parameter_conditions"][1]["key"], "arguments.path");
        assert_eq!(value["parameter_conditions"][1]["operator"], "PathPrefix");
        let text = add_rule(&default_policy(), rule).unwrap();
        let policy = Policy::from_json(&text).unwrap();
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.version, 2);
        assert!(lint(&policy).is_empty(), "{:?}", lint(&policy));
    }

    #[test]
    fn refuses_unscoped_rules_unless_any_tool() {
        let args = vec![parse_arg("path=/x", ArgOperator::PathPrefix).unwrap()];
        let unscoped = RuleSpec {
            args: args.clone(),
            ..spec("r")
        };
        assert!(
            build_rule(PolicyEffect::Deny, &unscoped)
                .unwrap_err()
                .contains("--any-tool")
        );
        assert!(
            build_rule(PolicyEffect::Deny, &spec("r"))
                .unwrap_err()
                .contains("EVERY")
        );
        let explicit = RuleSpec {
            args,
            any_tool: true,
            ..spec("r")
        };
        assert!(build_rule(PolicyEffect::Deny, &explicit).is_ok());
        let server_only = RuleSpec {
            server: Some("fs".into()),
            ..spec("r")
        };
        assert!(build_rule(PolicyEffect::Deny, &server_only).is_ok());
    }

    #[test]
    fn refuses_duplicates_and_invalid_values() {
        let policy = default_policy();
        let dup = build_rule(
            PolicyEffect::Deny,
            &RuleSpec {
                tool: Some("x".into()),
                ..spec(crate::store::DEFAULT_ALLOW_RULE)
            },
        )
        .unwrap();
        assert!(
            add_rule(&policy, dup)
                .unwrap_err()
                .contains("already exists")
        );
        // Relative path prefixes are rejected by core validation.
        let bad = build_rule(
            PolicyEffect::Deny,
            &RuleSpec {
                tool: Some("x".into()),
                args: vec![parse_arg("path=relative/dir", ArgOperator::PathPrefix).unwrap()],
                ..spec("bad")
            },
        )
        .unwrap();
        assert!(add_rule(&policy, bad).unwrap_err().contains("invalid"));
    }

    #[test]
    fn remove_and_list() {
        let rule = build_rule(
            PolicyEffect::Deny,
            &RuleSpec {
                tool: Some("delete_file".into()),
                ..spec("deny-delete")
            },
        )
        .unwrap();
        let policy = Policy::from_json(&add_rule(&default_policy(), rule).unwrap()).unwrap();
        let listing = render_list(&policy);
        assert!(
            listing.contains("deny-delete")
                && listing.contains("DENY")
                && listing.contains("delete_file")
        );
        let policy = Policy::from_json(&remove_rule(&policy, "deny-delete").unwrap()).unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.version, 3);
        assert!(remove_rule(&policy, "nope").is_err());
    }

    #[test]
    fn lint_flags_hand_written_mistakes() {
        let mut policy = default_policy();
        policy.rules.push(PolicyRule::new(
            "ra",
            ACTION_TYPE,
            PolicyEffect::RequireApproval,
        ));
        policy.rules.push(
            PolicyRule::new("args", ACTION_TYPE, PolicyEffect::Deny)
                .with_parameter_condition(PolicyCondition::prefix("arguments.path", "/x")),
        );
        policy.rules.push(
            PolicyRule::new("dotted", ACTION_TYPE, PolicyEffect::Deny)
                .with_target("fs")
                .with_parameter_condition(PolicyCondition::exact(
                    "arguments.opts.path",
                    json!("/x"),
                )),
        );
        let warnings = lint(&policy).join("\n");
        assert!(
            warnings.contains("\"dotted\"") && warnings.contains("nested"),
            "{warnings}"
        );
        assert!(warnings.contains("\"ra\"") && warnings.contains("without required_capability"));
        assert!(warnings.contains("\"args\"") && warnings.contains("selector"));
    }

    #[cfg(unix)]
    #[test]
    fn lint_flags_path_prefixes_that_do_not_resolve_to_themselves() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::create_dir(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("alias")).unwrap();
        let rule = |id: &str, prefix: std::path::PathBuf| {
            PolicyRule::new(id, ACTION_TYPE, PolicyEffect::Deny)
                .with_target("fs")
                .with_parameter_condition(PolicyCondition::path_prefix(
                    "arguments.path",
                    prefix.to_str().unwrap(),
                ))
        };
        let mut policy = default_policy();
        policy.rules.push(rule("via-alias", root.join("alias")));
        policy.rules.push(rule("canonical", root.join("real")));
        policy.rules.push(rule("not-yet", root.join("missing")));
        let warnings = lint(&policy).join("\n");
        assert!(
            warnings.contains("\"via-alias\"") && warnings.contains("resolves to"),
            "{warnings}"
        );
        assert!(!warnings.contains("\"canonical\""), "{warnings}");
        assert!(!warnings.contains("\"not-yet\""), "{warnings}");
    }
}
