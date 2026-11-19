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
pub const RESTART_REMINDER: &str = "note: each praetore-mcp wrap process reads policy.json when it starts; restart your MCP client (or the wrapped servers) to apply policy changes.";

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
    // Generated rules always use the MCP action type, a mission action (G7).
    updated
        .action_classes
        .entry(ACTION_TYPE.to_owned())
        .or_insert(praetore_core::ActionClass::Mission);
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

/// The field after `arguments.` when that field itself contains `.`.
/// A condition on `arguments.a.b` matches a literal top-level argument key
/// `"a.b"`, which the caller chooses, not the nested field `a.b`.
pub fn dotted_argument_field(key: &str) -> Option<&str> {
    let field = key.strip_prefix("arguments.")?;
    field.contains('.').then_some(field)
}

/// Rules whose parameter conditions use [`dotted_argument_field`].
pub fn literal_dotted_argument_rules(policy: &Policy) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for rule in &policy.rules {
        for condition in &rule.parameter_conditions {
            if dotted_argument_field(&condition.key).is_some() {
                found.push((rule.id.clone(), condition.key.clone()));
            }
        }
    }
    found
}

/// Non-fatal findings that predict surprising decisions in HighAssurance.
/// `program` starts each printed command and `dir_suffix` ends it (see
/// [`crate::commands`]).
pub fn lint(policy: &Policy, program: &str, dir_suffix: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    if policy.semantics_version != 2 {
        warnings.push(
            "semantics_version is not 2: HighAssurance (and praetore-mcp) will refuse this policy"
                .into(),
        );
    }
    if !policy.rules.iter().any(|r| r.effect == PolicyEffect::Allow) {
        warnings.push(format!(
            "no ALLOW rule: in enforce mode every tools/call is denied by default; allow a tool with `{program} policy allow --id ID --server NAME --tool NAME{dir_suffix}`"
        ));
    }
    if let Some(warning) = allow_all_warning(policy, program, dir_suffix) {
        warnings.push(warning);
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
                    "rule {:?}: path prefix {prefix:?} resolves to {resolved:?}; arguments spelled {prefix:?} go through a symlink and arguments under {resolved:?} are ambiguous, so a DENY/REQUIRE_APPROVAL rule refuses both and an ALLOW rule matches neither; use {resolved:?}",
                    rule.id
                ));
            }
            if condition.operator == MatchOperator::PathPrefix
                && let Some(prefix) = condition.expected.as_str()
                && let Some(warning) = crate::gate::firmlink_prefix_warning(prefix)
            {
                warnings.push(format!(
                    "rule {:?}: path prefix {prefix:?} {warning}",
                    rule.id
                ));
            }
            if let Some(field) = dotted_argument_field(&condition.key) {
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

/// An ALLOW rule that matches every tool call, of every server or of one
/// server, whatever the tool and its arguments: no tool condition, no
/// argument or context condition.
pub fn is_allow_all(rule: &PolicyRule) -> bool {
    rule.effect == PolicyEffect::Allow
        && rule.action_type == ACTION_TYPE
        && rule.required_capability.as_deref() == Some(CAPABILITY)
        && rule.context_conditions.is_empty()
        && rule.parameter_conditions.iter().all(|condition| {
            condition.key == "server"
                && condition.operator == MatchOperator::Exact
                && condition.expected.is_string()
        })
}

/// The tool a rule names with an exact `tool` condition, if any.
fn named_tool(rule: &PolicyRule) -> Option<&str> {
    rule.parameter_conditions.iter().find_map(|condition| {
        match (
            condition.key.as_str(),
            &condition.operator,
            &condition.expected,
        ) {
            ("tool", MatchOperator::Exact, Value::String(name)) => Some(name.as_str()),
            _ => None,
        }
    })
}

/// Warns when an allow-all rule sits next to DENY or REQUIRE_APPROVAL rules
/// that name tools: every tool those rules do not name is allowed. Printed
/// commands are built as in [`lint`].
pub fn allow_all_warning(policy: &Policy, program: &str, dir_suffix: &str) -> Option<String> {
    let allow_all: Vec<&str> = policy
        .rules
        .iter()
        .filter(|rule| is_allow_all(rule))
        .map(|rule| rule.id.as_str())
        .collect();
    let mut named: Vec<String> = policy
        .rules
        .iter()
        .filter(|rule| rule.effect != PolicyEffect::Allow)
        .filter_map(named_tool)
        .map(crate::proxy::display_safe)
        .collect();
    named.sort_unstable();
    named.dedup();
    if allow_all.is_empty() || named.is_empty() {
        return None;
    }
    let ids = allow_all
        .iter()
        .map(|id| format!("{:?}", crate::proxy::display_safe(id)))
        .collect::<Vec<_>>()
        .join(", ");
    let remove = allow_all
        .iter()
        .map(|id| {
            format!(
                "`{program} policy remove --id {}{dir_suffix}`",
                crate::proxy::display_safe(id)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "allow-all rule {ids} with DENY/REQUIRE_APPROVAL rules for specific tools ({}): every tool those rules do not name is ALLOWED, including tools a server adds later. Run `{program} policy coverage{dir_suffix} -- <server command>` to list them; to deny by default instead, allow the tools you want and run {remove}",
        named.join(", ")
    ))
}

/// Precedence of an effect when rules are folded: DENY > REQUIRE_APPROVAL >
/// ALLOW, and DENY when nothing matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    Allow,
    RequireApproval,
    Deny,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::RequireApproval => "REQUIRE_APPROVAL",
            Self::Deny => "DENY",
        }
    }
}

/// The effect a rule contributes when it matches. An ALLOW rule without the
/// local capability never matches; a restrictive one denies (unbound).
fn contributed(rule: &PolicyRule) -> Option<Outcome> {
    let bound = rule.required_capability.as_deref() == Some(CAPABILITY);
    match (&rule.effect, bound) {
        (PolicyEffect::Allow, true) => Some(Outcome::Allow),
        (PolicyEffect::Allow, false) => None,
        (PolicyEffect::RequireApproval, true) => Some(Outcome::RequireApproval),
        _ => Some(Outcome::Deny),
    }
}

enum Scope {
    No,
    Always,
    /// Matches depending on these conditions (arguments, context).
    Conditional(Vec<String>),
}

/// Whether `rule` applies to a call of `tool` on `server`, from the rule's
/// selectors alone.
fn scope(rule: &PolicyRule, server: &str, tool: &str) -> Scope {
    if rule.action_type != ACTION_TYPE {
        return Scope::No;
    }
    if rule
        .target
        .as_deref()
        .is_some_and(|target| target != server)
    {
        return Scope::No;
    }
    let mut conditions = Vec::new();
    for condition in &rule.parameter_conditions {
        match (
            condition.key.as_str(),
            &condition.operator,
            &condition.expected,
        ) {
            ("tool", MatchOperator::Exact, Value::String(name)) => {
                if name != tool {
                    return Scope::No;
                }
            }
            ("server", MatchOperator::Exact, Value::String(name)) => {
                if name != server {
                    return Scope::No;
                }
            }
            _ => conditions.push(condition_label("", condition)),
        }
    }
    conditions.extend(
        rule.context_conditions
            .iter()
            .map(|c| condition_label("context.", c)),
    );
    if conditions.is_empty() {
        Scope::Always
    } else {
        Scope::Conditional(conditions)
    }
}

/// What the policy decides for one tool, read from the rules alone.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCoverage {
    pub tool: String,
    /// `None` for a `safety*` tool name, which the gate handles before any
    /// rule (see `note`).
    pub outcome: Option<Outcome>,
    /// Rules without conditions that give `outcome`; empty means default deny.
    pub rules: Vec<String>,
    /// Rules whose match depends on the call's arguments or context:
    /// (rule id, effect, conditions).
    pub conditional: Vec<(String, Outcome, String)>,
    /// Allowed, and every rule that allows it is an allow-all rule.
    pub only_allow_all: bool,
    pub note: Option<&'static str>,
}

/// Per-tool decision for `server`. A rule whose match depends on arguments
/// is listed apart and does not change `outcome`, which is the decision for
/// a call where no such rule matches.
pub fn coverage(policy: &Policy, server: &str, tools: &[String]) -> Vec<ToolCoverage> {
    tools
        .iter()
        .map(|tool| {
            if crate::gate::is_safety_named(&serde_json::json!({ "name": tool })) {
                let declared = policy.action_classes.get(tool.as_str())
                    == Some(&praetore_core::ActionClass::Safety);
                return ToolCoverage {
                    tool: tool.clone(),
                    outcome: None,
                    rules: Vec::new(),
                    conditional: Vec::new(),
                    only_allow_all: false,
                    note: Some(if declared {
                        "declared Safety: forwarded without evaluation or receipt"
                    } else {
                        "safety* name not declared Safety: refused in both modes"
                    }),
                };
            }
            let mut outcome: Option<Outcome> = None;
            let mut by: Vec<&PolicyRule> = Vec::new();
            let mut conditional = Vec::new();
            for rule in &policy.rules {
                let Some(effect) = contributed(rule) else {
                    continue;
                };
                match scope(rule, server, tool) {
                    Scope::No => {}
                    Scope::Always => {
                        if outcome < Some(effect) {
                            outcome = Some(effect);
                            by.clear();
                        }
                        if outcome == Some(effect) {
                            by.push(rule);
                        }
                    }
                    Scope::Conditional(conditions) => {
                        conditional.push((rule.id.clone(), effect, conditions.join("; ")));
                    }
                }
            }
            let only_allow_all =
                outcome == Some(Outcome::Allow) && by.iter().all(|rule| is_allow_all(rule));
            ToolCoverage {
                tool: tool.clone(),
                outcome: Some(outcome.unwrap_or(Outcome::Deny)),
                rules: by.iter().map(|rule| rule.id.clone()).collect(),
                conditional,
                only_allow_all,
                note: None,
            }
        })
        .collect()
}

/// A tool name `policy coverage` prints inside a suggested command without
/// quoting: the MCP tool name characters, 1 to 128 of them.
fn plain_tool_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// `value` as one POSIX shell word: unchanged when it only has characters
/// a shell does not interpret, otherwise in single quotes.
pub(crate) fn shell_word(value: &str) -> String {
    if !value.is_empty()
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b':' | b'=')
        })
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', r"'\''"))
    }
}

/// The part of a rule id taken from a name: MCP tool name characters, at
/// most 48, `x` when nothing is left.
fn id_part(name: &str) -> String {
    let part: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .take(48)
        .collect();
    if part.is_empty() { "x".into() } else { part }
}

/// For each tool denied only because no rule names it, the `policy allow`
/// command that allows it. Tools with an argument-dependent rule are left
/// out: an unconditional ALLOW would widen what that rule allows. Nothing is
/// written; the person running it decides which lines to run.
fn render_allow_suggestions(
    policy: &Policy,
    server: &str,
    report: &[ToolCoverage],
    program: &str,
    dir_suffix: &str,
) -> String {
    let denied: Vec<&ToolCoverage> = report
        .iter()
        .filter(|item| {
            item.note.is_none()
                && item.rules.is_empty()
                && item.conditional.is_empty()
                && matches!(item.outcome, None | Some(Outcome::Deny))
        })
        .collect();
    if denied.is_empty() {
        return String::new();
    }
    let mut taken: std::collections::BTreeSet<String> =
        policy.rules.iter().map(|rule| rule.id.clone()).collect();
    let mut out = format!(
        "\ndenied because no rule names them ({}). To allow one, run its line (each allows every call to that tool in enforce mode):\n",
        denied.len()
    );
    let mut unusual = Vec::new();
    for item in denied {
        if !plain_tool_name(&item.tool) {
            unusual.push(cell(&item.tool, 60));
            continue;
        }
        let base = format!("allow-{}-{}", id_part(server), item.tool);
        let mut id = base.clone();
        let mut n = 2;
        while taken.contains(&id) {
            id = format!("{base}-{n}");
            n += 1;
        }
        taken.insert(id.clone());
        out.push_str(&format!(
            "  {program} policy allow --id {id} --server {} --tool {}{dir_suffix}\n",
            shell_word(server),
            item.tool
        ));
    }
    if !unusual.is_empty() {
        out.push_str(&format!(
            "  not suggested (characters outside A-Z a-z 0-9 _ - .): {}\n",
            unusual.join(", ")
        ));
    }
    out
}

/// `program` starts each printed command and `dir_suffix` ends it (see
/// [`crate::commands`]).
pub fn render_coverage(
    policy: &Policy,
    server: &str,
    report: &[ToolCoverage],
    program: &str,
    dir_suffix: &str,
) -> String {
    let mut out = format!(
        "policy {} v{}, server {:?}: {} tool(s)\n{:<28} {:<17} {:<28} DEPENDS ON ARGUMENT\n",
        policy.id,
        policy.version,
        crate::proxy::display_safe(server),
        report.len(),
        "TOOL",
        "DECISION",
        "RULE",
    );
    for item in report {
        let (decision, rule) = match (item.outcome, item.note) {
            (None, Some(note)) => ("-".to_owned(), note.to_owned()),
            (outcome, _) => (
                outcome.unwrap_or(Outcome::Deny).label().to_owned(),
                if item.rules.is_empty() {
                    "default deny".to_owned()
                } else {
                    item.rules.join(", ")
                },
            ),
        };
        let depends = if item.conditional.is_empty() {
            "no".to_owned()
        } else {
            let parts: Vec<String> = item
                .conditional
                .iter()
                .map(|(id, effect, conditions)| {
                    format!(
                        "{} ({}) when {}",
                        crate::proxy::display_safe(id),
                        effect.label(),
                        crate::proxy::display_safe(conditions)
                    )
                })
                .collect();
            format!("yes: {}", parts.join(" | "))
        };
        out.push_str(&format!(
            "{:<28} {:<17} {:<28} {}\n",
            cell(&item.tool, 28),
            decision,
            cell(&rule, 28),
            depends
        ));
    }
    out.push_str(&render_allow_suggestions(
        policy, server, report, program, dir_suffix,
    ));
    let loose: Vec<&ToolCoverage> = report.iter().filter(|item| item.only_allow_all).collect();
    out.push('\n');
    if loose.is_empty() {
        out.push_str("no tool is allowed only by an allow-all rule\n");
    } else {
        out.push_str(&format!(
            "allowed only by an allow-all rule ({}):\n",
            loose.len()
        ));
        for item in &loose {
            out.push_str(&format!(
                "  {:<28} {}\n",
                cell(&item.tool, 28),
                cell(&item.rules.join(", "), 60)
            ));
        }
        let mut ids: Vec<&str> = loose
            .iter()
            .flat_map(|item| item.rules.iter().map(String::as_str))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        out.push_str(&format!(
            "  allow the tools you want with `{program} policy allow --id ID --server NAME --tool NAME{dir_suffix}`, then remove the allow-all rule:\n",
        ));
        for id in ids {
            out.push_str(&format!(
                "  {program} policy remove --id {}{dir_suffix}\n",
                crate::proxy::display_safe(id)
            ));
        }
    }
    out.push_str(
        "note: decisions are read from the rules for a call where no argument condition matches; observe mode records a DENY and forwards the call.\n",
    );
    out
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
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.version, 2);
        // The only finding is that nothing is allowed (default deny).
        let warnings = lint(&policy, "praetore-mcp", "");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].starts_with("no ALLOW rule"), "{warnings:?}");
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
        let first = build_rule(
            PolicyEffect::Allow,
            &RuleSpec {
                tool: Some("x".into()),
                ..spec("allow-x")
            },
        )
        .unwrap();
        let policy = Policy::from_json(&add_rule(&default_policy(), first).unwrap()).unwrap();
        let dup = build_rule(
            PolicyEffect::Deny,
            &RuleSpec {
                tool: Some("y".into()),
                ..spec("allow-x")
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
        assert_eq!(policy.rules.len(), 0);
        assert_eq!(policy.version, 3);
        assert!(remove_rule(&policy, "nope").is_err());
    }

    #[test]
    fn dotted_argument_field_is_only_a_dot_inside_the_field() {
        assert_eq!(dotted_argument_field("arguments.a.b"), Some("a.b"));
        assert_eq!(
            dotted_argument_field("arguments.opts.path"),
            Some("opts.path")
        );
        assert_eq!(dotted_argument_field("arguments.path"), None);
        assert_eq!(dotted_argument_field("arguments."), None);
        assert_eq!(dotted_argument_field("tool"), None);
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
        let warnings = lint(&policy, "praetore-mcp", "").join("\n");
        assert!(
            warnings.contains("\"dotted\"") && warnings.contains("nested"),
            "{warnings}"
        );
        assert!(warnings.contains("\"ra\"") && warnings.contains("without required_capability"));
        assert!(warnings.contains("\"args\"") && warnings.contains("selector"));
    }

    #[test]
    fn coverage_folds_rules_per_tool() {
        let mut policy = default_policy();
        let tools: Vec<String> = ["read", "write", "copy", "safety:halt"]
            .iter()
            .map(|t| t.to_string())
            .collect();
        // Nothing allowed: every tool is default deny.
        let report = coverage(&policy, "fs", &tools);
        assert!(report[..3].iter().all(|item| {
            item.outcome == Some(Outcome::Deny) && item.rules.is_empty() && !item.only_allow_all
        }));
        assert_eq!(report[3].outcome, None);
        assert!(report[3].note.unwrap().contains("refused"));

        // A server-scoped allow-all, a DENY for one tool, an ALLOW for another,
        // a conditional REQUIRE_APPROVAL, and an ALLOW without the capability.
        let allow_server = build_rule(
            PolicyEffect::Allow,
            &RuleSpec {
                server: Some("fs".into()),
                any_tool: true,
                ..spec("allow-fs")
            },
        )
        .unwrap();
        assert!(is_allow_all(&allow_server));
        policy.rules.push(allow_server);
        let tool_rule = |effect, id: &str, tool: &str| {
            build_rule(
                effect,
                &RuleSpec {
                    server: Some("fs".into()),
                    tool: Some(tool.into()),
                    ..spec(id)
                },
            )
            .unwrap()
        };
        policy
            .rules
            .push(tool_rule(PolicyEffect::Deny, "deny-write", "write"));
        let allow_read = tool_rule(PolicyEffect::Allow, "allow-read", "read");
        assert!(!is_allow_all(&allow_read));
        policy.rules.push(allow_read);
        policy.rules.push(
            build_rule(
                PolicyEffect::RequireApproval,
                &RuleSpec {
                    tool: Some("copy".into()),
                    args: vec![parse_arg("path=/srv", ArgOperator::PathPrefix).unwrap()],
                    ..spec("approve-copy")
                },
            )
            .unwrap(),
        );
        policy.rules.push(
            PolicyRule::new("no-capability", ACTION_TYPE, PolicyEffect::Allow)
                .with_parameter_condition(PolicyCondition::exact("tool", json!("copy"))),
        );
        let report = coverage(&policy, "fs", &tools);
        let by_tool = |name: &str| report.iter().find(|item| item.tool == name).unwrap();
        let read = by_tool("read");
        assert_eq!(read.outcome, Some(Outcome::Allow));
        assert_eq!(read.rules, ["allow-fs", "allow-read"]);
        assert!(!read.only_allow_all);
        let write = by_tool("write");
        assert_eq!(
            (write.outcome, write.rules.as_slice()),
            (Some(Outcome::Deny), &["deny-write".to_owned()][..])
        );
        let copy = by_tool("copy");
        assert_eq!(copy.outcome, Some(Outcome::Allow));
        assert!(copy.only_allow_all);
        assert_eq!(copy.conditional.len(), 1);
        assert_eq!(copy.conditional[0].0, "approve-copy");
        assert_eq!(copy.conditional[0].1, Outcome::RequireApproval);
        // Another server: the server-scoped rules do not apply.
        let other = coverage(&policy, "git", &tools);
        assert_eq!(other[0].outcome, Some(Outcome::Deny));
        assert!(other[0].rules.is_empty());
        // The lint names the allow-all rule and the denied tool.
        let warning = allow_all_warning(&policy, "praetore-mcp", "").unwrap();
        assert!(
            warning.contains("\"allow-fs\"") && warning.contains("write"),
            "{warning}"
        );
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
        let warnings = lint(&policy, "praetore-mcp", "").join("\n");
        assert!(
            warnings.contains("\"via-alias\"") && warnings.contains("resolves to"),
            "{warnings}"
        );
        assert!(!warnings.contains("\"canonical\""), "{warnings}");
        assert!(!warnings.contains("\"not-yet\""), "{warnings}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lint_flags_firmlink_spellings_of_path_prefixes() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let data = format!("/System/Volumes/Data{}", root.display());
        let mut policy = default_policy();
        for (id, prefix) in [
            ("data-spelling", data.as_str()),
            ("usual", root.to_str().unwrap()),
        ] {
            policy.rules.push(
                PolicyRule::new(id, ACTION_TYPE, PolicyEffect::Deny)
                    .with_target("fs")
                    .with_parameter_condition(PolicyCondition::path_prefix(
                        "arguments.path",
                        prefix,
                    )),
            );
        }
        let warnings = lint(&policy, "praetore-mcp", "").join("\n");
        assert!(
            warnings.contains("\"data-spelling\"") && warnings.contains("firmlinked"),
            "{warnings}"
        );
        assert!(!warnings.contains("\"usual\""), "{warnings}");
    }

    #[test]
    fn shell_word_quotes_what_a_shell_would_interpret() {
        assert_eq!(shell_word("filesystem"), "filesystem");
        assert_eq!(shell_word("/srv/a-b_c.d"), "/srv/a-b_c.d");
        assert_eq!(shell_word("my fs"), "'my fs'");
        assert_eq!(shell_word("it's"), r"'it'\''s'");
        assert_eq!(shell_word("$(id)"), "'$(id)'");
        assert_eq!(shell_word(""), "''");
    }

    #[test]
    fn coverage_suggests_allow_lines_only_for_tools_no_rule_names() {
        let mut policy = default_policy();
        // Same id the suggestion for `read` would take, on another server.
        policy.rules.push(
            build_rule(
                PolicyEffect::Allow,
                &RuleSpec {
                    server: Some("other".into()),
                    tool: Some("read".into()),
                    ..spec("allow-myfs-read")
                },
            )
            .unwrap(),
        );
        policy.rules.push(
            build_rule(
                PolicyEffect::Deny,
                &RuleSpec {
                    server: Some("my fs".into()),
                    tool: Some("write".into()),
                    ..spec("deny-write")
                },
            )
            .unwrap(),
        );
        let tools: Vec<String> = ["read", "write", "x;rm -rf ~", "safety:halt"]
            .iter()
            .map(|t| t.to_string())
            .collect();
        let report = coverage(&policy, "my fs", &tools);
        let text = render_coverage(&policy, "my fs", &report, "praetore-mcp", " --dir '/h h'");
        assert!(
            text.contains("denied because no rule names them (2)"),
            "{text}"
        );
        assert!(
            text.contains(
                "  praetore-mcp policy allow --id allow-myfs-read-2 --server 'my fs' --tool read --dir '/h h'\n"
            ),
            "{text}"
        );
        assert!(!text.contains("--tool write"), "{text}");
        assert!(!text.contains("--tool x"), "{text}");
        assert!(!text.contains("--tool safety"), "{text}");
        assert!(text.contains("not suggested"), "{text}");

        // Nothing denied by default: no section.
        let report = coverage(&policy, "my fs", &["write".to_owned()]);
        let text = render_coverage(&policy, "my fs", &report, "praetore-mcp", "");
        assert!(!text.contains("no rule names"), "{text}");
    }

    /// F1-3: a `tool` condition that is not Exact still names the tool. The
    /// engine allows `write` under `tool` Prefix `wr`. `coverage` parks that
    /// condition in `conditional` and reports default DENY for the call it
    /// claims to describe (no argument condition involved).
    #[test]
    fn coverage_decision_matches_engine_for_a_tool_prefix() {
        use praetore_core::{Action, AgentId, AgentIdentity, Authority, DecisionOutcome};

        let mut policy = default_policy();
        policy.rules.push(
            PolicyRule::new("allow-wr", ACTION_TYPE, PolicyEffect::Allow)
                .with_capability(CAPABILITY)
                .with_target("fs")
                .with_parameter_condition(PolicyCondition::prefix("tool", "wr")),
        );
        let id = AgentId::new();
        let agent = AgentIdentity::new(id.clone(), b"test-public-key".to_vec(), "ed25519").unwrap();
        let authority = Authority::new(id, "praetore-root", vec![CAPABILITY.to_owned()]);
        let action = Action::new(
            ACTION_TYPE,
            Some("fs".into()),
            json!({"server": "fs", "tool": "write", "arguments": {}}),
        )
        .unwrap();
        let mission = policy.classify(action).unwrap().into_mission().unwrap();
        let decision = policy.evaluate(&agent, &authority, &mission).unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Allow);

        let report = coverage(&policy, "fs", &["write".to_owned()]);
        assert_eq!(
            report[0].outcome,
            Some(Outcome::Allow),
            "coverage reports {:?} while the engine allows write; conditional {:?}",
            report[0].outcome,
            report[0].conditional
        );
    }
}
