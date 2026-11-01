//! Claude Code `PreToolUse` hook that authorizes every tool call with PRÆTORE.
//!
//! Each agent (the main session and each subagent in `.claude/agents/`) gets
//! its own Ed25519 key and an authority signed by a local issuer that grants
//! only that agent's capabilities. For every tool call the hook builds a
//! signed `AuthorizationRequest`, evaluates it with a HighAssurance engine
//! against `policy.json` (signed intent window, local freshness and a durable
//! replay claim, see [`high_assurance`]), which signs the evidence with a
//! local attester key and records its decision time (`decided_at`), appends
//! it to `receipts.jsonl`, and answers Claude Code: `deny` and `requires approval`
//! are enforced; `allow` adds no decision, so Claude Code's own permission
//! rules still apply.
//!
//! Enforcement is cooperative: it holds only for tool calls that pass through
//! the hook, and only while the hook is configured.

mod high_assurance;
mod shell;

#[cfg(test)]
mod attribution_tests;
#[cfg(test)]
mod tests_g7;
#[cfg(test)]
mod tests_high_assurance;

use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    path::Path,
    process::ExitCode,
};

use praetore_core::{
    Action, AgentId, AgentIdentity, AgentKeyPair, Authority, AuthorizationRequest,
    ClassifiedAction, DecisionOutcome, Evidence, EvidenceAttesterKey, Policy, PolicyCondition,
    PolicyEffect, PolicyRule, PraetoreError, RecordedPolicy, TrustedAuthorityIssuer,
    authority::Validity,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const ISSUER: &str = "praetore-claude-hook-issuer";
const POLICY_FILE: &str = "policy.json";
const ISSUER_PIN_FILE: &str = "issuer-pin.json";
const ATTESTER_KEY_FILE: &str = "attester.key";
const ATTESTER_PIN_FILE: &str = "attester-public-key.hex";
const AGENTS_DIR: &str = "agents";
const RECEIPTS_FILE: &str = "receipts.jsonl";
const MAIN_AGENT: &str = "main";
/// Profile for any agent without an authority of its own: it holds no
/// capability, so every request is denied, but with a signed receipt.
const UNREGISTERED: &str = "unregistered";
const SUBAGENTS: [&str; 3] = ["planner", "coder", "explorer"];
const MAX_HOOK_INPUT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
/// Longest `agent_id` or `session_id` recorded in a receipt.
const MAX_CLAIM_BYTES: usize = 128;
const AUTHORITY_LIFETIME_DAYS: i64 = 90;
/// Authority constraint naming the profile an agent key was issued for.
/// The issuer signs it, so a verifier that pins only the issuer can tell
/// which profile an agent id belongs to. The engine enforces it: the
/// request must carry the same value as an action parameter.
const PROFILE_CONSTRAINT: &str = "praetore.agent_profile";

/// Capabilities granted to each agent's authority at `init`.
const PROFILES: [(&str, &[&str]); 6] = [
    (
        MAIN_AGENT,
        &[
            "fs:read",
            "fs:write",
            "process:execute",
            "network:invoke",
            "agent:delegate",
            "tool:invoke",
        ],
    ),
    ("planner", &["fs:read"]),
    ("explorer", &["fs:read"]),
    ("coder", &["fs:read", "fs:write", "process:execute"]),
    // Claude Code's built-in web reader: network only, no file access.
    ("web-fetch", &["network:invoke"]),
    (UNREGISTERED, &[]),
];

type BoxError = Box<dyn std::error::Error>;

#[derive(Serialize, Deserialize)]
struct AgentProfile {
    identity: Value,
    authority: Value,
}

#[derive(Deserialize)]
struct HookInput {
    tool_name: String,
    #[serde(default)]
    tool_input: Value,
    #[serde(default)]
    tool_use_id: Option<String>,
    #[serde(default)]
    agent_type: Option<String>,
    /// Claude Code's id for the subagent instance the hook fires in. It is
    /// recorded in the signed context; it does not select a key.
    #[serde(default)]
    agent_id: Option<Value>,
    #[serde(default)]
    session_id: Option<Value>,
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(Debug)]
struct Verdict {
    outcome: DecisionOutcome,
    rule: Option<String>,
    reason: String,
    /// G7: the tool call is a safety action. PRÆTORE made no decision: the
    /// hook adds none (Claude Code's own permission rules apply), and
    /// nothing was signed or appended to `receipts.jsonl`.
    not_governed: bool,
    /// The signed receipt behind the decision, when there is one.
    evidence_id: Option<String>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [command, directory, options @ ..] if command == "init" => parse_init_options(options)
            .and_then(|(root, days)| initialize(Path::new(directory), Path::new(&root), days)),
        [command, directory] if command == "hook" => {
            run_hook(Path::new(directory));
            Ok(())
        }
        [command, directory] if command == "verify" => verify_receipts(Path::new(directory)),
        [command, directory, out] if command == "export" => {
            export_bundle(Path::new(directory), Path::new(out))
        }
        _ => {
            eprintln!(
                "Usage:\n  praetore-claude-hook init <directory> [--root <project-root>] [--valid-days <days>]\n  praetore-claude-hook hook <directory>     (reads PreToolUse JSON on stdin)\n  praetore-claude-hook verify <directory>\n  praetore-claude-hook export <directory> <bundle-directory>"
            );
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_init_options(options: &[String]) -> Result<(String, i64), BoxError> {
    let mut root = std::env::current_dir()?
        .to_str()
        .ok_or("cwd must be UTF-8")?
        .to_string();
    let mut days = AUTHORITY_LIFETIME_DAYS;
    let mut options = options.iter();
    while let Some(flag) = options.next() {
        let value = options.next().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--root" => root = value.clone(),
            "--valid-days" => {
                days = value.parse()?;
                if !(1..=high_assurance::MAX_VALID_DAYS).contains(&days) {
                    return Err(format!(
                        "--valid-days must be between 1 and {}",
                        high_assurance::MAX_VALID_DAYS
                    )
                    .into());
                }
            }
            _ => return Err(format!("unknown option {flag}").into()),
        }
    }
    Ok((root, days))
}

fn initialize(directory: &Path, root: &Path, valid_days: i64) -> Result<(), BoxError> {
    let root = fs::canonicalize(root)?;
    let root = root.to_str().ok_or("project root must be valid UTF-8")?;
    let home = std::env::var("HOME").map_err(|_| "HOME is not set")?;
    create_private_directory(directory)?;
    create_private_directory(&directory.join(AGENTS_DIR))?;
    // HighAssurance replay store: one claim file per evaluated request.
    create_private_directory(&directory.join(high_assurance::REPLAY_DIR))?;

    let now = OffsetDateTime::now_utc();
    let validity = Validity {
        not_before: Some((now - Duration::minutes(5)).format(&Rfc3339)?),
        not_after: Some((now + Duration::days(valid_days)).format(&Rfc3339)?),
    };
    // The issuer key signs the authorities and is then dropped: only its
    // public pin is stored, so the hook cannot mint new authority. Re-run
    // `init` into a fresh directory to re-issue.
    let issuer_key = AgentKeyPair::from_secret_bytes(&random_secret()?);
    let pin = TrustedAuthorityIssuer::new(ISSUER, issuer_key.public_key())?
        .with_validity(validity.clone())?;
    write_private_file(
        &directory.join(ISSUER_PIN_FILE),
        pin.export_pin_json()?.as_bytes(),
    )?;
    let attester_secret = random_secret()?;
    write_private_file(
        &directory.join(ATTESTER_KEY_FILE),
        hex::encode(attester_secret).as_bytes(),
    )?;
    write_private_file(
        &directory.join(ATTESTER_PIN_FILE),
        hex::encode(
            EvidenceAttesterKey::from_secret_bytes(&attester_secret)
                .public_key()?
                .as_bytes(),
        )
        .as_bytes(),
    )?;

    for (name, capabilities) in PROFILES {
        let secret = random_secret()?;
        let identity = AgentKeyPair::from_secret_bytes(&secret).identity(AgentId::new());
        let mut authority = Authority::new(
            identity.id.clone(),
            ISSUER,
            capabilities.iter().map(|c| (*c).to_string()).collect(),
        )
        .with_constraint(PROFILE_CONSTRAINT, name)
        .with_validity(validity.clone());
        authority.sign_for_agent(&issuer_key, &identity)?;
        let profile = AgentProfile {
            identity: serde_json::to_value(&identity)?,
            authority: serde_json::to_value(&authority)?,
        };
        let agents = directory.join(AGENTS_DIR);
        write_private_file(
            &agents.join(format!("{name}.key")),
            hex::encode(secret).as_bytes(),
        )?;
        write_private_file(
            &agents.join(format!("{name}.json")),
            &serde_json::to_vec_pretty(&profile)?,
        )?;
    }

    let policy = default_policy(root, &home);
    policy.validate()?;
    write_private_file(
        &directory.join(POLICY_FILE),
        &serde_json::to_vec_pretty(&policy)?,
    )?;

    println!("Initialized PRÆTORE hook state at {}", directory.display());
    println!("Project root: {root}");
    println!("Policy digest: {}", policy.digest()?);
    for (name, capabilities) in PROFILES {
        println!("  {name:<9} {}", capabilities.join(", "));
    }
    Ok(())
}

fn default_policy(root: &str, home: &str) -> Policy {
    let subagents = SUBAGENTS.iter().map(|a| json!(a)).collect::<Vec<_>>();
    // Conditions match the profile whose key signs, not the raw agent_type:
    // an unregistered request may carry any agent_type, including `main`.
    let main_only = || PolicyCondition::exact("profile", json!(MAIN_AGENT));
    Policy::new_v2(
        "claude-code-agents",
        1,
        vec![
            PolicyRule::new("deny-git-internals", "claude:write", PolicyEffect::Deny)
                .with_parameter_condition(PolicyCondition::path_prefix(
                    "path",
                    format!("{root}/.git"),
                )),
            PolicyRule::new(
                "deny-subagent-governance-writes",
                "claude:write",
                PolicyEffect::Deny,
            )
            .with_parameter_condition(PolicyCondition::path_prefix(
                "path",
                format!("{root}/.claude"),
            ))
            .with_context_condition(PolicyCondition::one_of("profile", subagents)),
            PolicyRule::new(
                "approval-main-governance-writes",
                "claude:write",
                PolicyEffect::RequireApproval,
            )
            .with_capability("fs:write")
            .with_parameter_condition(PolicyCondition::path_prefix(
                "path",
                format!("{root}/.claude"),
            ))
            .with_context_condition(main_only()),
            PolicyRule::new(
                "approval-git-push",
                "claude:exec",
                PolicyEffect::RequireApproval,
            )
            .with_capability("process:execute")
            // `git_push` exists only for analyzable commands. Without this
            // condition, an unanalyzable command (no `git_push` key) matched
            // this rule as unknown under policy semantics v2 and was reported
            // as a git push. The unanalyzable rule below still holds it.
            .with_parameter_condition(PolicyCondition::exact("analyzable", json!(true)))
            .with_parameter_condition(PolicyCondition::exact("git_push", json!(true))),
            // A command the scanner cannot analyze lexically might push, so it
            // is held for approval instead of allowed.
            PolicyRule::new(
                "approval-unanalyzable-command",
                "claude:exec",
                PolicyEffect::RequireApproval,
            )
            .with_capability("process:execute")
            .with_parameter_condition(PolicyCondition::exact("analyzable", json!(false))),
            PolicyRule::new("allow-read-project", "claude:read", PolicyEffect::Allow)
                .with_capability("fs:read")
                .with_parameter_condition(PolicyCondition::path_prefix("path", root)),
            PolicyRule::new("allow-read-main", "claude:read", PolicyEffect::Allow)
                .with_capability("fs:read")
                .with_context_condition(main_only()),
            PolicyRule::new("allow-write-project", "claude:write", PolicyEffect::Allow)
                .with_capability("fs:write")
                .with_parameter_condition(PolicyCondition::path_prefix("path", root)),
            PolicyRule::new(
                "allow-write-main-claude-home",
                "claude:write",
                PolicyEffect::Allow,
            )
            .with_capability("fs:write")
            .with_parameter_condition(PolicyCondition::path_prefix(
                "path",
                format!("{home}/.claude/projects"),
            ))
            .with_context_condition(main_only()),
            PolicyRule::new("allow-write-main-tmp", "claude:write", PolicyEffect::Allow)
                .with_capability("fs:write")
                .with_parameter_condition(PolicyCondition::path_prefix("path", "/private/tmp"))
                .with_context_condition(main_only()),
            PolicyRule::new("allow-exec", "claude:exec", PolicyEffect::Allow)
                .with_capability("process:execute"),
            PolicyRule::new("allow-network", "claude:network", PolicyEffect::Allow)
                .with_capability("network:invoke"),
            PolicyRule::new("allow-delegate", "claude:delegate", PolicyEffect::Allow)
                .with_capability("agent:delegate"),
            PolicyRule::new("allow-other-tools", "claude:tool", PolicyEffect::Allow)
                .with_capability("tool:invoke"),
        ],
    )
    // G7 (policy format 2): every action type the hook produces, declared.
    // No safety action is declared by default, so a `safety:*` tool is
    // refused as unclassified until the policy declares it Safety.
    .with_mission_actions([
        "claude:read",
        "claude:write",
        "claude:exec",
        "claude:network",
        "claude:delegate",
        "claude:tool",
    ])
}

/// Maps a Claude Code tool call onto a PRÆTORE action type (the same as
/// [`action_type_of`]), the capability it requires, and the parameters the
/// policy matches on. Unknown tools map to `claude:tool`, which only the main
/// session's authority grants.
///
/// A path is resolved through the filesystem first (see [`resolve_path`]).
/// Unless it resolves to itself, the policy sees [`PATH_CHECK_FAILED`]
/// instead: not an absolute path, so the engine treats it as unsafe and it
/// matches every restrictive `PathPrefix` rule and no ALLOW one. The fourth
/// value records the check for the signed request context.
fn classify(
    tool_name: &str,
    input: &Value,
    cwd: Option<&str>,
) -> (String, &'static str, Value, Option<Value>) {
    let field = |key: &str| input.get(key).and_then(Value::as_str);
    let path_param = |path: Option<&str>| match path.or(cwd) {
        Some(path) => {
            let lexical = absolute(path, cwd);
            let (status, resolved) = resolve_path(&lexical);
            let seen = if status == PathStatus::Same {
                lexical.clone()
            } else {
                PATH_CHECK_FAILED.to_string()
            };
            let check =
                json!({ "lexical": lexical, "resolved": resolved, "status": status.as_str() });
            (json!({ "path": seen }), Some(check))
        }
        // No path: the parameter is absent, so no path-scoped ALLOW matches.
        None => (json!({}), None),
    };
    let with_path = |action: &str, capability: &'static str, path: Option<&str>| {
        let (parameters, check) = path_param(path);
        (action.to_string(), capability, parameters, check)
    };
    match tool_name {
        "Read" => with_path("claude:read", "fs:read", field("file_path")),
        "Grep" | "Glob" => with_path("claude:read", "fs:read", field("path")),
        "Edit" | "MultiEdit" | "Write" => with_path("claude:write", "fs:write", field("file_path")),
        "NotebookEdit" => with_path("claude:write", "fs:write", field("notebook_path")),
        "Bash" => {
            let command = field("command").unwrap_or_default();
            let parameters = match shell::scan(command) {
                shell::Scan::Analyzed { git_push } => {
                    json!({ "command": command, "analyzable": true, "git_push": git_push })
                }
                shell::Scan::Unanalyzable(reason) => json!({
                    "command": command,
                    "analyzable": false,
                    "unanalyzable_reason": reason,
                }),
            };
            ("claude:exec".into(), "process:execute", parameters, None)
        }
        "WebFetch" | "WebSearch" => (
            "claude:network".into(),
            "network:invoke",
            json!({ "target": field("url").or(field("query")).unwrap_or_default() }),
            None,
        ),
        "Agent" | "Task" => (
            "claude:delegate".into(),
            "agent:delegate",
            json!({ "subagent_type": field("subagent_type").unwrap_or_default() }),
            None,
        ),
        // G7: `authorize` answers safety actions before it gets here; this
        // arm keeps the type in step with `action_type_of`.
        name if name.starts_with(praetore_core::policy::SAFETY_ACTION_PREFIX) => (
            action_type_of(name),
            "tool:invoke",
            json!({ "tool": name }),
            None,
        ),
        other => (
            "claude:tool".into(),
            "tool:invoke",
            json!({ "tool": other }),
            None,
        ),
    }
}

/// What the policy sees in place of a path that does not resolve to itself.
const PATH_CHECK_FAILED: &str = "praetore-claude-hook:path-check-failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathStatus {
    /// The path resolves to exactly itself: no symlink, `.` or `..` in it.
    Same,
    /// The path resolves somewhere else.
    Differs,
    /// The path cannot be resolved: relative, a dangling symlink, a `..`
    /// below a missing directory, a component under a file, or not UTF-8.
    Unresolved,
}

impl PathStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Same => "same",
            Self::Differs => "differs",
            Self::Unresolved => "unresolved",
        }
    }
}

/// Resolves `lexical` with `fs::canonicalize`. For a path that does not
/// exist yet (a new file, possibly in new directories), it resolves the
/// deepest existing ancestor and appends the missing names. Those names
/// cannot be symlinks because nothing exists there yet. Whatever exists at
/// a missing name but cannot be resolved (a dangling symlink) is unresolved.
fn resolve_path(lexical: &str) -> (PathStatus, Option<String>) {
    use std::path::PathBuf;
    let path = Path::new(lexical);
    if !path.is_absolute() {
        return (PathStatus::Unresolved, None);
    }
    let mut existing = path;
    let mut missing = Vec::new();
    let resolved: PathBuf = loop {
        match fs::canonicalize(existing) {
            Ok(base) => {
                let mut resolved = base;
                resolved.extend(missing.iter().rev());
                break resolved;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if fs::symlink_metadata(existing).is_ok() {
                    return (PathStatus::Unresolved, None);
                }
                let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) else {
                    return (PathStatus::Unresolved, None);
                };
                missing.push(name);
                existing = parent;
            }
            Err(_) => return (PathStatus::Unresolved, None),
        }
    };
    let Ok(resolved) = resolved.into_os_string().into_string() else {
        return (PathStatus::Unresolved, None);
    };
    let normalized = match lexical.strip_suffix('/') {
        Some(stripped) if !stripped.is_empty() => stripped,
        _ => lexical,
    };
    let status = if resolved == normalized {
        PathStatus::Same
    } else {
        PathStatus::Differs
    };
    (status, Some(resolved))
}

/// Joins a relative path onto `cwd` without normalizing it. A `..` or `.`
/// segment stays in the value; [`resolve_path`] then reports it as `differs`
/// or `unresolved`, so it fails closed.
fn absolute(path: &str, cwd: Option<&str>) -> String {
    match cwd {
        Some(cwd) if !path.starts_with('/') => format!("{}/{path}", cwd.trim_end_matches('/')),
        _ => path.to_string(),
    }
}

fn run_hook(directory: &Path) {
    let verdict = read_hook_input()
        .and_then(|input| authorize(directory, &input))
        .unwrap_or_else(fail_closed);
    // stderr is for people: invisible, bidi and control characters in tool
    // names and reasons are escaped (`praetore_core::display`).
    let shown = praetore_core::display::escape_for_display;
    if verdict.not_governed {
        eprintln!("PRÆTORE: {}", shown(&verdict.reason));
    }
    if verdict.outcome == DecisionOutcome::Deny && verdict.evidence_id.is_some() {
        // The model only sees the uniform text (see `hook_output`); the rule
        // and reason are in the signed receipt and here.
        eprintln!(
            "PRÆTORE{}: {}",
            verdict
                .rule
                .as_deref()
                .map(|rule| format!(" [rule {}]", shown(rule)))
                .unwrap_or_default(),
            shown(&verdict.reason)
        );
    }
    if let Some(output) = hook_output(&verdict) {
        println!("{output}");
    }
}

/// Any error denies, including an unreadable `policy.json`: without a policy
/// no tool call can be classified, `safety:*` included (G7 limit).
fn fail_closed(error: BoxError) -> Verdict {
    Verdict {
        outcome: DecisionOutcome::Deny,
        rule: None,
        reason: format!("hook error, failing closed: {error}"),
        not_governed: false,
        evidence_id: None,
    }
}

fn read_hook_input() -> Result<HookInput, BoxError> {
    let mut buffer = Vec::new();
    io::stdin()
        .take(MAX_HOOK_INPUT_BYTES + 1)
        .read_to_end(&mut buffer)?;
    if buffer.len() as u64 > MAX_HOOK_INPUT_BYTES {
        return Err("hook input exceeds 32 MiB".into());
    }
    Ok(serde_json::from_slice(&buffer)?)
}

fn hook_output(verdict: &Verdict) -> Option<Value> {
    if verdict.not_governed {
        return None;
    }
    let decision = match verdict.outcome {
        DecisionOutcome::Allow => return None,
        DecisionOutcome::RequireApproval => "ask",
        DecisionOutcome::Deny => "deny",
    };
    // G7: every DENY with a receipt gets the same text, whatever decided it
    // (a rule, an engine guard or an action type the policy does not
    // declare), so the reason cannot reveal what the policy declares.
    if decision == "deny"
        && let Some(evidence_id) = &verdict.evidence_id
    {
        return Some(json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": format!("PRÆTORE denied this tool call (evidence {evidence_id})"),
            }
        }));
    }
    let rule = verdict
        .rule
        .as_deref()
        .map(|rule| format!(" [rule {rule}]"))
        .unwrap_or_default();
    Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": format!("PRÆTORE{rule}: {}", verdict.reason),
        }
    }))
}

/// Instance and session ids as Claude Code reports them, ready for the
/// signed context, or why one was rejected. A string is kept as is; a number
/// becomes its canonical JSON text, so a future numeric id does not deny
/// every call. The rejection names the key, the JSON type and the length,
/// never the value.
fn instance_claims(input: &HookInput) -> (Vec<(&'static str, String)>, Option<Value>) {
    let mut claims = Vec::new();
    for (key, value) in [
        ("claude.agent_id", &input.agent_id),
        ("claude.session_id", &input.session_id),
    ] {
        let text = match value {
            None | Some(Value::Null) => continue,
            Some(Value::String(text)) => text.clone(),
            Some(Value::Number(number)) => number.to_string(),
            Some(other) => {
                let kind = match other {
                    Value::Bool(_) => "boolean",
                    Value::Array(_) => "array",
                    _ => "object",
                };
                return (
                    Vec::new(),
                    Some(json!({ "key": key, "reason": "not a string or number", "type": kind })),
                );
            }
        };
        if text.len() > MAX_CLAIM_BYTES {
            return (
                Vec::new(),
                Some(json!({
                    "key": key,
                    "reason": format!("longer than {MAX_CLAIM_BYTES} bytes (UTF-8)"),
                    "bytes": text.len(),
                })),
            );
        }
        if !text.is_empty() {
            claims.push((key, text));
        }
    }
    (claims, None)
}

/// G7: tools whose name starts with `safety:` are safety actions of that
/// exact type; the policy must declare them `Safety`. Every other tool maps
/// to a `claude:*` mission action (see [`classify`]).
fn action_type_of(tool_name: &str) -> String {
    match tool_name {
        "Read" | "Grep" | "Glob" => "claude:read".into(),
        "Edit" | "MultiEdit" | "Write" | "NotebookEdit" => "claude:write".into(),
        "Bash" => "claude:exec".into(),
        "WebFetch" | "WebSearch" => "claude:network".into(),
        "Agent" | "Task" => "claude:delegate".into(),
        // A name that is not a valid action type (surrounding whitespace,
        // for example) is recorded under a fixed type that can never be
        // declared, so it is refused as unclassified with a receipt.
        name if name.starts_with(praetore_core::policy::SAFETY_ACTION_PREFIX) => {
            if Action::new(name, None, json!({})).is_ok() {
                name.into()
            } else {
                UNCLASSIFIED_TOOL_ACTION_TYPE.into()
            }
        }
        _ => "claude:tool".into(),
    }
}

/// Recorded action type for a `safety:` tool name that is not a valid action
/// type. Its inner spaces make it impossible to declare in `action_classes`.
const UNCLASSIFIED_TOOL_ACTION_TYPE: &str = "praetore-claude-hook unclassified tool name";

fn load_policy(directory: &Path) -> Result<Policy, BoxError> {
    let path = directory.join(POLICY_FILE);
    Policy::from_json(&String::from_utf8(read_bounded(&path)?)?).map_err(|error| {
        let hint = match error {
            PraetoreError::PolicyFormatUnsupported { found: 1, .. } => format!(
                "; this state was written before G7 (policy format 1): migrate {} to format 2 (`praetore policy classify --policy {}` proposes the action_classes table) or run `praetore-claude-hook init` into a new directory",
                path.display(),
                path.display()
            ),
            _ => String::new(),
        };
        format!("{}: {error}{hint}", path.display()).into()
    })
}

fn authorize(directory: &Path, input: &HookInput) -> Result<Verdict, BoxError> {
    // G7: classify the call against the policy before anything else: before
    // any agent key or profile is read, anything is signed or evaluated, or
    // a receipt is appended. A safety action gets no decision from PRÆTORE,
    // so a PRÆTORE failure after this point cannot hold it.
    let policy = load_policy(directory)?;
    let action_type = action_type_of(&input.tool_name);
    let unclassified = match policy.classify(Action::new(action_type, None, json!({}))?) {
        Ok(ClassifiedAction::Mission(_)) => false,
        Ok(ClassifiedAction::Safety(action)) => {
            return Ok(Verdict {
                outcome: DecisionOutcome::Deny,
                rule: None,
                reason: format!(
                    "{}: {}",
                    action.not_governed().code(),
                    action.not_governed()
                ),
                not_governed: true,
                evidence_id: None,
            });
        }
        // Not declared: the engine refuses it with a signed DENY (engine
        // guard `unclassified_action`) after verifying the request like a
        // mission request; no policy rule is evaluated.
        Err(PraetoreError::UnclassifiedAction { .. }) => true,
        Err(error) => return Err(error.into()),
    };
    // Only the absence of `agent_type` is the main session. An explicit
    // `main` (a subagent defined with `name: main`) or `unregistered` is a
    // reserved name and is evaluated as `unregistered`.
    let agent = input.agent_type.as_deref().unwrap_or(MAIN_AGENT);
    let reserved = input.agent_type.is_some() && (agent == MAIN_AGENT || agent == UNREGISTERED);
    if agent.len() > 64 {
        return Ok(denied(format!(
            "agent name longer than 64 bytes: {agent:?}"
        )));
    }
    let (claims, rejected_claim) = instance_claims(input);
    // Only a well-formed name can select a profile file; anything else, any
    // agent without an issued authority, and any request whose instance or
    // session id is rejected, is evaluated as `unregistered`: no capability,
    // so it is denied, with a signed receipt.
    let well_formed = !agent.is_empty()
        && !reserved
        && rejected_claim.is_none()
        && agent
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    let profile_name = if well_formed
        && directory
            .join(AGENTS_DIR)
            .join(format!("{agent}.json"))
            .exists()
    {
        agent
    } else {
        UNREGISTERED
    };
    let profile_path = directory
        .join(AGENTS_DIR)
        .join(format!("{profile_name}.json"));
    let profile: AgentProfile = serde_json::from_slice(&read_bounded(&profile_path)?)?;
    let identity = AgentIdentity::from_json(&profile.identity.to_string())?;
    let authority = Authority::from_json(&profile.authority.to_string())?;
    let key = AgentKeyPair::from_secret_bytes(&read_secret(
        &directory
            .join(AGENTS_DIR)
            .join(format!("{profile_name}.key")),
    )?);
    if key.public_key() != identity.verified_public_key()? {
        return Err(format!("key for profile '{profile_name}' does not match its identity").into());
    }
    // A profile file copied over another (say `coder.*` saved as
    // `explorer.*`) would sign as the wrong agent; the issuer-signed profile
    // name catches it. State created before SAF-14 has no such name and
    // cannot catch it, so it is refused (fail closed) until re-initialized.
    match profile_constraint(&authority) {
        Some(issued_for) if issued_for == profile_name => {}
        Some(issued_for) => {
            return Err(format!(
                "authority in profile '{profile_name}' was issued for profile '{issued_for}'"
            )
            .into());
        }
        None => {
            return Err(format!(
                "hook state at {} predates SAF-14: the authority of profile '{profile_name}' does not name its profile ({PROFILE_CONSTRAINT}). Run `praetore-claude-hook init` into a new directory and point the hook at it; receipts already written still verify with `verify`",
                directory.display()
            )
            .into());
        }
    }

    let pin = TrustedAuthorityIssuer::from_pin_json(&String::from_utf8(read_bounded(
        &directory.join(ISSUER_PIN_FILE),
    )?)?)?;
    let attester =
        EvidenceAttesterKey::from_secret_bytes(&read_secret(&directory.join(ATTESTER_KEY_FILE))?);
    // State created before HighAssurance receipts has no replay store and is
    // refused here (fail closed) until re-initialized.
    let engine = high_assurance::engine(directory, policy, pin, attester)?;

    let (action_type, capability, mut parameters, path_check) =
        classify(&input.tool_name, &input.tool_input, input.cwd.as_deref());
    // The engine requires every authority constraint to appear among the
    // action parameters, so an authority issued for one profile cannot be
    // used in a request made as another.
    if let Some(parameters) = parameters.as_object_mut() {
        parameters.insert(PROFILE_CONSTRAINT.into(), json!(profile_name));
    }
    let action = Action::new(action_type, None, parameters)?.with_capability(capability);
    let context = RequestContext {
        agent,
        profile: profile_name,
        tool: &input.tool_name,
        path_check,
        claims,
        rejected_claim: rejected_claim.clone(),
    };
    #[cfg(test)]
    tests_g7::SIGNATURES.with(|count| count.set(count.get() + 1));
    // The engine signs the evidence with the attester key (HighAssurance)
    // after the replay claim inputs are fixed; the claim is the last step.
    let evidence = if unclassified {
        let action = engine.policy().unclassified(action)?;
        let mut request = context.apply(AuthorizationRequest::new_unclassified(
            identity, authority, action,
        )?);
        sign_intent(&mut request, &key, engine.policy())?;
        engine.refuse_unclassified(request)?
    } else {
        let action = engine.policy().classify(action)?.into_mission()?;
        let mut request = context.apply(AuthorizationRequest::new(identity, authority, action)?);
        sign_intent(&mut request, &key, engine.policy())?;
        engine.evaluate(request)?
    };

    append_receipt(directory, input, agent, profile_name, &evidence)?;
    let outcome = evidence.decision.outcome;
    let reason = match &rejected_claim {
        Some(rejected) => format!(
            "{} {}; evaluated as '{UNREGISTERED}': {}",
            rejected["key"].as_str().unwrap_or_default(),
            rejected["reason"].as_str().unwrap_or_default(),
            evidence.decision.reason
        ),
        None if reserved => format!(
            "agent_type {agent:?} is reserved; evaluated as '{UNREGISTERED}': {}",
            evidence.decision.reason
        ),
        None => evidence.decision.reason.clone(),
    };
    Ok(Verdict {
        outcome,
        rule: deciding_rules(&evidence),
        reason,
        not_governed: false,
        evidence_id: Some(evidence.evidence_id.to_string()),
    })
}

/// Signs a HighAssurance (v2) intent: for the hook's audience, under the
/// digest of the policy being evaluated, valid from now for
/// [`high_assurance::INTENT_LIFETIME`].
fn sign_intent<A: praetore_core::RequestAction>(
    request: &mut AuthorizationRequest<A>,
    key: &AgentKeyPair,
    policy: &Policy,
) -> Result<(), BoxError> {
    let now = OffsetDateTime::now_utc();
    request.sign_intent_v2(
        key,
        high_assurance::AUDIENCE,
        now,
        now + high_assurance::INTENT_LIFETIME,
        policy.digest()?,
    )?;
    Ok(())
}

/// The signed context every hook request carries.
struct RequestContext<'a> {
    agent: &'a str,
    profile: &'a str,
    tool: &'a str,
    path_check: Option<Value>,
    claims: Vec<(&'static str, String)>,
    rejected_claim: Option<Value>,
}

impl RequestContext<'_> {
    fn apply<A: praetore_core::RequestAction>(
        self,
        request: AuthorizationRequest<A>,
    ) -> AuthorizationRequest<A> {
        let mut request = request
            .with_context("agent", json!(self.agent))
            .with_context("profile", json!(self.profile))
            .with_context("tool", json!(self.tool));
        if let Some(check) = self.path_check {
            request = request.with_context("praetore.path_check", check);
        }
        // Signed claims made with the profile key, not separate keys (SAF-14).
        for (key, value) in self.claims {
            request = request.with_context(key, json!(value));
        }
        if let Some(rejected) = self.rejected_claim {
            request = request.with_context("praetore.claim_rejected", rejected);
        }
        request
    }
}

/// The rules whose contribution produced the final outcome, comma-separated.
fn deciding_rules(evidence: &Evidence) -> Option<String> {
    let outcome = evidence.decision.outcome;
    let rules: Vec<&str> = evidence
        .decision
        .contributions
        .iter()
        .filter(|c| c.outcome == outcome)
        .map(|c| c.rule_id.as_str())
        .collect();
    (!rules.is_empty()).then(|| rules.join(", "))
}

fn denied(reason: String) -> Verdict {
    Verdict {
        outcome: DecisionOutcome::Deny,
        rule: None,
        reason,
        not_governed: false,
        evidence_id: None,
    }
}

fn append_receipt(
    directory: &Path,
    input: &HookInput,
    agent: &str,
    profile: &str,
    evidence: &Evidence,
) -> Result<(), BoxError> {
    #[cfg(test)]
    tests_g7::APPENDS.with(|count| count.set(count.get() + 1));
    let line = json!({
        "tool_use_id": input.tool_use_id,
        "tool_name": input.tool_name,
        "agent": agent,
        "profile": profile,
        "evidence": serde_json::from_str::<Value>(&evidence.to_json()?)?,
    });
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(directory.join(RECEIPTS_FILE))?;
    file.write_all(format!("{line}\n").as_bytes())?;
    Ok(())
}

/// The issuer-signed profile name of an authority, if it carries one.
fn profile_constraint(authority: &Authority) -> Option<&str> {
    authority
        .constraints
        .iter()
        .find(|c| c.key == PROFILE_CONSTRAINT)
        .map(|c| c.value.as_str())
}

/// Who a receipt attributes the request to, read only from signed fields.
struct Attribution {
    /// `context.agent`: the `agent_type` Claude Code sent (or `main`).
    agent: String,
    /// `context.profile`: the profile whose key signed the intent.
    profile: String,
    /// The profile is also named in the issuer-signed authority.
    issuer_bound: bool,
}

impl Attribution {
    /// How the summaries name the agent. A registered profile is shown by
    /// its name (always `[a-z0-9_-]`). Any other `agent_type` is shown under
    /// `unregistered`, escaped to ASCII, so `"coder "` or a Cyrillic `о`
    /// cannot be read as the `coder` profile.
    fn label(&self) -> String {
        if self.profile == UNREGISTERED {
            format!(
                "unregistered(agent_type=\"{}\")",
                self.agent.escape_default()
            )
        } else {
            self.profile.clone()
        }
    }
}

/// Reads the attribution from the signed request context and checks it
/// against the issuer-signed authority. Call it only on evidence whose
/// signatures were verified; unsigned copies of these names (the
/// `receipts.jsonl` wrapper, `index.json`) are checked against it.
fn signed_attribution(evidence: &Evidence) -> Result<Attribution, BoxError> {
    let agent = evidence
        .context
        .get("agent")
        .and_then(Value::as_str)
        .ok_or("receipt does not sign an agent name")?;
    // Receipts from before the `profile` context key (set 04) name only the
    // agent, which was then also the profile.
    let profile = match evidence.context.get("profile") {
        Some(profile) => profile.as_str().ok_or("signed profile is not a string")?,
        None => agent,
    };
    if profile != UNREGISTERED && profile != agent {
        return Err(
            format!("signed agent '{agent}' does not match signed profile '{profile}'").into(),
        );
    }
    let issued_for = profile_constraint(&evidence.authority);
    if let Some(issued_for) = issued_for {
        let requested_as = evidence
            .action
            .parameters
            .get(PROFILE_CONSTRAINT)
            .and_then(Value::as_str);
        if issued_for != profile || requested_as != Some(profile) {
            return Err(format!(
                "authority was issued for profile '{issued_for}', receipt names '{profile}' (action parameter {requested_as:?})"
            )
            .into());
        }
    }
    Ok(Attribution {
        agent: agent.to_string(),
        profile: profile.to_string(),
        issuer_bound: issued_for.is_some(),
    })
}

/// Fails if an unsigned copy of a name disagrees with the signed one.
fn check_unsigned(record: &Value, field: &str, signed: &str) -> Result<(), BoxError> {
    match record.get(field) {
        None | Some(Value::Null) => Ok(()),
        Some(value) if value.as_str() == Some(signed) => Ok(()),
        Some(value) => Err(format!(
            "unsigned field {field}={value} disagrees with the signed receipt ({signed:?})"
        )
        .into()),
    }
}

/// Re-verifies every receipt offline: evidence integrity, the attester
/// signature, the intent signed with the agent profile's key, the
/// issuer-signed authority, and the policy digest. It also checks who the
/// receipt is attributed to: the signed agent and profile names, the
/// profile named in the authority, that the signing identity is the one in
/// `agents/<profile>.json`, and that the unsigned `agent`/`profile` fields
/// of the line agree. The tally is built from the signed names only.
fn verify_receipts(directory: &Path) -> Result<(), BoxError> {
    let pin = TrustedAuthorityIssuer::from_pin_json(&String::from_utf8(read_bounded(
        &directory.join(ISSUER_PIN_FILE),
    )?)?)?;
    let attester = read_attester_pin(directory)?;
    // Historical: hook state created before G7 has a policy format 1
    // document. It is only digested here, never evaluated.
    let policy_digest = RecordedPolicy::from_json(&String::from_utf8(read_bounded(
        &directory.join(POLICY_FILE),
    )?)?)?
    .digest()
    .to_owned();
    let receipts = fs::read_to_string(directory.join(RECEIPTS_FILE))?;
    let now = OffsetDateTime::now_utc();
    let mut tally: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut identities: BTreeMap<String, String> = BTreeMap::new();
    let mut issuer_bound = 0usize;
    let mut decision_timed = 0usize;
    let mut failures = 0usize;
    // One decision per receipt: a line copied or replayed into the journal
    // would count one decision twice.
    let mut seen_evidence: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen_request: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (index, line) in receipts.lines().enumerate().filter(|(_, l)| !l.is_empty()) {
        let mut check = || -> Result<(Attribution, String, DecisionOutcome, bool), BoxError> {
            let record: Value = serde_json::from_str(line)?;
            let evidence = Evidence::from_json(&record["evidence"].to_string())?;
            if !evidence.verify_integrity() {
                return Err("integrity hash mismatch".into());
            }
            evidence.verify_attester_signature(&attester)?;
            evidence.verify_agent_intent()?;
            // HighAssurance receipts record the signed decision time: the
            // authority and the pin are checked at it. Older receipts have
            // none and are checked at this clock, as before.
            let checked_at = decision_time(&evidence)?;
            pin.verify_authority_at(&evidence.authority, checked_at.unwrap_or(now))?;
            evidence
                .authority
                .verify_subject_identity(&evidence.agent)?;
            if evidence.policy_digest.as_deref() != Some(policy_digest.as_str()) {
                return Err("evaluated under a different policy".into());
            }
            let attribution = signed_attribution(&evidence)?;
            check_unsigned(&record, "agent", &attribution.agent)?;
            check_unsigned(&record, "profile", &attribution.profile)?;
            let profile_path = directory
                .join(AGENTS_DIR)
                .join(format!("{}.json", attribution.profile));
            let profile: AgentProfile = serde_json::from_slice(&read_bounded(&profile_path)?)?;
            if AgentIdentity::from_json(&profile.identity.to_string())? != evidence.agent {
                // The comparison is with the current file: replacing or
                // re-issuing agents/<profile>.json makes the receipts signed
                // before it fail here (third parties check pins instead).
                return Err(format!(
                    "signed by an identity that is not the current one in agents/{}.json (was that file replaced or re-issued after this receipt?)",
                    attribution.profile
                )
                .into());
            }
            let agent_id = evidence.agent.id.as_uuid().to_string();
            let line_number = index + 1;
            if let Some(first) = seen_evidence.insert(evidence.evidence_id.to_string(), line_number)
            {
                return Err(format!("evidence_id repeated (first on line {first})").into());
            }
            if let Some(first) = seen_request.insert(
                (agent_id.clone(), evidence.request_id.to_string()),
                line_number,
            ) {
                return Err(
                    format!("(agent id, request_id) repeated (first on line {first})").into(),
                );
            }
            Ok((
                attribution,
                agent_id,
                evidence.decision.outcome,
                checked_at.is_some(),
            ))
        };
        match check() {
            Ok((attribution, agent_id, outcome, timed)) => {
                issuer_bound += usize::from(attribution.issuer_bound);
                decision_timed += usize::from(timed);
                *tally
                    .entry((attribution.label(), format!("{outcome:?}")))
                    .or_default() += 1;
                identities.insert(attribution.profile, agent_id);
            }
            Err(error) => {
                failures += 1;
                println!("line {}: FAILED: {error}", index + 1);
            }
        }
    }
    for ((agent, outcome), count) in &tally {
        println!("{agent:<16} {outcome:<16} {count}");
    }
    for (profile, agent_id) in &identities {
        println!("profile {profile:<12} agent id {agent_id}");
    }
    let verified: usize = tally.values().sum();
    println!(
        "{verified} receipts verified, {failures} failed; {issuer_bound} name their profile in the issuer-signed authority"
    );
    println!(
        "{decision_timed} record a signed decision time (decided_at, HighAssurance); their authority was checked at it"
    );
    if failures > 0 {
        return Err(format!("{failures} receipts failed verification").into());
    }
    Ok(())
}

/// The signed decision time of a HighAssurance receipt, `None` for receipts
/// without HighAssurance metadata. Call it only on verified evidence.
fn decision_time(evidence: &Evidence) -> Result<Option<OffsetDateTime>, BoxError> {
    if !evidence.is_high_assurance_shape() {
        return Ok(None);
    }
    let decided_at = evidence
        .decided_at
        .as_deref()
        .ok_or("HighAssurance receipt without decided_at")?;
    Ok(Some(OffsetDateTime::parse(decided_at, &Rfc3339)?))
}

/// Writes the receipts as a bundle that `praetore-verify` checks without any
/// private key: one evidence file per tool call, the issuer pin, the attester
/// public key, the policy, and an index.
fn export_bundle(directory: &Path, out: &Path) -> Result<(), BoxError> {
    let pin = String::from_utf8(read_bounded(&directory.join(ISSUER_PIN_FILE))?)?;
    let pin: Value = serde_json::from_str(&pin)?;
    let policy = read_bounded(&directory.join(POLICY_FILE))?;
    let attester = fs::read_to_string(directory.join(ATTESTER_PIN_FILE))?;
    let receipts = fs::read_to_string(directory.join(RECEIPTS_FILE))?;

    fs::create_dir(out)?;
    fs::create_dir(out.join("evidence"))?;
    fs::write(out.join("issuer-pins.jsonl"), format!("{pin}\n"))?;
    fs::write(out.join(ATTESTER_PIN_FILE), attester)?;
    fs::write(out.join(POLICY_FILE), policy)?;

    let mut index = Vec::new();
    for (number, line) in receipts.lines().filter(|l| !l.is_empty()).enumerate() {
        let record: Value = serde_json::from_str(line)?;
        let evidence = Evidence::from_json(&record["evidence"].to_string())?;
        // The index is unsigned: its names come from the signed receipt, and
        // a line whose wrapper disagrees is not exported.
        let attribution = signed_attribution(&evidence)
            .map_err(|error| format!("receipt {}: {error}", number + 1))?;
        check_unsigned(&record, "agent", &attribution.agent)
            .and_then(|()| check_unsigned(&record, "profile", &attribution.profile))
            .map_err(|error| format!("receipt {}: {error}", number + 1))?;
        let agent = attribution.agent.as_str();
        let tool = record["tool_name"].as_str().unwrap_or("unknown");
        let outcome = evidence.decision.outcome;
        let file = format!(
            "evidence/{:04}-{}-{}-{outcome:?}.json",
            number + 1,
            agent.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-', "_"),
            tool.replace(|c: char| !c.is_ascii_alphanumeric(), "_"),
        );
        fs::write(out.join(&file), evidence.to_json()?)?;
        index.push(json!({
            "file": file,
            "agent": agent,
            "agent_id": evidence.agent.id.as_uuid().to_string(),
            "tool_name": tool,
            "profile": attribution.profile,
            "tool_use_id": record["tool_use_id"],
            "outcome": outcome,
            "rule": deciding_rules(&evidence),
            "reason": evidence.decision.reason,
        }));
    }
    fs::write(out.join("index.json"), serde_json::to_vec_pretty(&index)?)?;
    println!("Exported {} receipts to {}", index.len(), out.display());
    Ok(())
}

fn read_attester_pin(directory: &Path) -> Result<praetore_core::VerifiedPublicKey, BoxError> {
    let encoded = String::from_utf8(read_bounded(&directory.join(ATTESTER_PIN_FILE))?)?;
    Ok(praetore_core::VerifiedPublicKey::from_bytes(&hex::decode(
        encoded.trim(),
    )?)?)
}

fn random_secret() -> Result<[u8; 32], io::Error> {
    let mut secret = [0u8; 32];
    OsRng.try_fill_bytes(&mut secret).map_err(|error| {
        io::Error::other(format!("operating-system key generation failed: {error}"))
    })?;
    Ok(secret)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, BoxError> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err(format!(
            "{} must be a regular file no larger than 1 MiB",
            path.display()
        )
        .into());
    }
    Ok(fs::read(path)?)
}

fn read_secret(path: &Path) -> Result<[u8; 32], BoxError> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > 128 {
        return Err(format!(
            "{} must be a regular file no larger than 128 bytes",
            path.display()
        )
        .into());
    }
    check_private_permissions(path, &metadata)?;
    let bytes = hex::decode(fs::read_to_string(path)?.trim())?;
    bytes
        .try_into()
        .map_err(|_| format!("{} must contain exactly 32 key bytes", path.display()).into())
}

#[cfg(unix)]
fn check_private_permissions(path: &Path, metadata: &fs::Metadata) -> Result<(), BoxError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "secret file {} is accessible by group/others; set permissions to 600",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<(), BoxError> {
    Err("secret file permissions cannot be verified on this platform".into())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), BoxError> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_directory(_path: &Path) -> Result<(), BoxError> {
    Err("secure owner-only key storage is currently supported only on Unix".into())
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), BoxError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    struct Fixture {
        root: PathBuf,
        state: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let base = std::env::temp_dir().join(format!(
                "praetore-claude-hook-{name}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(&base).unwrap();
            let root = fs::canonicalize(&base).unwrap();
            let state = root.join("state");
            initialize(&state, &root, AUTHORITY_LIFETIME_DAYS).unwrap();
            Self { root, state }
        }

        fn path(&self, relative: &str) -> String {
            format!("{}/{relative}", self.root.display())
        }

        fn decide(&self, agent: Option<&str>, tool: &str, input: Value) -> Verdict {
            let input = HookInput {
                tool_name: tool.into(),
                tool_input: input,
                tool_use_id: Some("toolu_test".into()),
                agent_type: agent.map(str::to_string),
                agent_id: None,
                session_id: None,
                cwd: Some(self.root.display().to_string()),
            };
            authorize(&self.state, &input).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn each_agent_is_bounded_by_its_signed_authority() {
        let f = Fixture::new("authority");
        let read = json!({ "file_path": f.path("README.md") });
        let write = json!({ "file_path": f.path("src/lib.rs") });

        for agent in [None, Some("planner"), Some("explorer"), Some("coder")] {
            assert_eq!(
                f.decide(agent, "Read", read.clone()).outcome,
                DecisionOutcome::Allow,
                "{agent:?} reads the project"
            );
        }
        assert_eq!(
            f.decide(Some("coder"), "Write", write.clone()).outcome,
            DecisionOutcome::Allow
        );
        for agent in ["planner", "explorer"] {
            let verdict = f.decide(Some(agent), "Write", write.clone());
            assert_eq!(verdict.outcome, DecisionOutcome::Deny);
            assert!(verdict.reason.contains("fs:write"), "{}", verdict.reason);
            let verdict = f.decide(Some(agent), "Bash", json!({ "command": "ls" }));
            assert_eq!(verdict.outcome, DecisionOutcome::Deny);
        }
        let verdict = f.decide(
            Some("coder"),
            "WebFetch",
            json!({ "url": "https://x.test" }),
        );
        assert_eq!(verdict.outcome, DecisionOutcome::Deny);
        let verdict = f.decide(Some("coder"), "Agent", json!({ "subagent_type": "coder" }));
        assert_eq!(verdict.outcome, DecisionOutcome::Deny);

        // The built-in web reader may use the network and nothing else.
        let verdict = f.decide(
            Some("web-fetch"),
            "WebFetch",
            json!({ "url": "https://x.test" }),
        );
        assert_eq!(verdict.outcome, DecisionOutcome::Allow);
        for (tool, input) in [("Read", read.clone()), ("Write", write.clone())] {
            let verdict = f.decide(Some("web-fetch"), tool, input);
            assert_eq!(verdict.outcome, DecisionOutcome::Deny, "{tool}");
        }
    }

    #[test]
    fn subagents_cannot_rewrite_governance_and_main_must_ask() {
        let f = Fixture::new("governance");
        let agent_file = json!({ "file_path": f.path(".claude/agents/coder.md") });
        let verdict = f.decide(Some("coder"), "Edit", agent_file.clone());
        assert_eq!(verdict.outcome, DecisionOutcome::Deny);
        assert_eq!(
            verdict.rule.as_deref(),
            Some("deny-subagent-governance-writes")
        );
        let verdict = f.decide(None, "Edit", agent_file);
        assert_eq!(verdict.outcome, DecisionOutcome::RequireApproval);

        let git = json!({ "file_path": f.path(".git/config") });
        assert_eq!(f.decide(None, "Write", git).outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn git_push_requires_approval() {
        let f = Fixture::new("push");
        let verdict = f.decide(
            Some("coder"),
            "Bash",
            json!({ "command": "git push origin main" }),
        );
        assert_eq!(verdict.outcome, DecisionOutcome::RequireApproval);
        assert_eq!(
            hook_output(&verdict).unwrap()["hookSpecificOutput"]["permissionDecision"],
            "ask"
        );
        let verdict = f.decide(Some("coder"), "Bash", json!({ "command": "cargo test" }));
        assert_eq!(verdict.outcome, DecisionOutcome::Allow);
        assert!(hook_output(&verdict).is_none());

        for (command, rule) in [
            ("cd x && git push", "approval-git-push"),
            ("git -C ../repo push --force", "approval-git-push"),
            ("$(echo git) push", "approval-unanalyzable-command"),
            ("bash -c 'git push'", "approval-unanalyzable-command"),
        ] {
            let verdict = f.decide(Some("coder"), "Bash", json!({ "command": command }));
            assert_eq!(
                verdict.outcome,
                DecisionOutcome::RequireApproval,
                "{command}"
            );
            assert!(
                verdict.rule.as_deref().unwrap_or_default().contains(rule),
                "{command}: {:?}",
                verdict.rule
            );
        }
    }

    #[test]
    fn unanalyzable_command_without_push_is_not_reported_as_git_push() {
        // Shape of receipt 0093 in evidence/05-sesion-real-final: a heredoc
        // with no `git push`, held only because it cannot be analyzed.
        let f = Fixture::new("heredoc");
        let command = "cd docs && python3 - <<'E'\nprint('hola')\nE\ngrep -n x 01.md";
        let verdict = f.decide(Some("coder"), "Bash", json!({ "command": command }));
        assert_eq!(verdict.outcome, DecisionOutcome::RequireApproval);
        assert_eq!(
            verdict.rule.as_deref(),
            Some("approval-unanalyzable-command")
        );

        // An analyzable push still names approval-git-push.
        let verdict = f.decide(Some("coder"), "Bash", json!({ "command": "git push" }));
        assert_eq!(verdict.rule.as_deref(), Some("approval-git-push"));
    }

    #[test]
    fn paths_outside_the_project_or_unsafe_paths_are_denied_to_subagents() {
        let f = Fixture::new("paths");
        for path in ["/etc/passwd", "../outside.txt", "src/../../outside.txt"] {
            let verdict = f.decide(Some("explorer"), "Read", json!({ "file_path": path }));
            assert_eq!(verdict.outcome, DecisionOutcome::Deny, "{path}");
        }
        let sibling = format!("{}-sibling/x", f.root.display());
        let verdict = f.decide(Some("coder"), "Write", json!({ "file_path": sibling }));
        assert_eq!(verdict.outcome, DecisionOutcome::Deny);
        // A relative path inside the project resolves against cwd.
        let verdict = f.decide(Some("explorer"), "Grep", json!({ "path": "src" }));
        assert_eq!(verdict.outcome, DecisionOutcome::Allow);
    }

    #[cfg(unix)]
    #[test]
    fn paths_are_resolved_before_evaluation() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new("symlinks");
        let outside = Fixture::new("symlinks-outside");
        fs::write(outside.root.join("secret.txt"), "x").unwrap();
        fs::create_dir(f.root.join("src")).unwrap();
        fs::write(f.root.join("src/lib.rs"), "x").unwrap();
        symlink(&outside.root, f.root.join("link")).unwrap();
        symlink(f.root.join("src/lib.rs"), f.root.join("inside-link")).unwrap();
        symlink(f.root.join("missing"), f.root.join("dangling")).unwrap();

        let check = |agent: &str, tool: &str, path: String| {
            let verdict = f.decide(Some(agent), tool, json!({ "file_path": path }));
            let receipts = fs::read_to_string(f.state.join(RECEIPTS_FILE)).unwrap();
            let last: Value = serde_json::from_str(receipts.lines().last().unwrap()).unwrap();
            let context = &last["evidence"]["context"];
            (
                verdict.outcome,
                context["praetore.path_check"]["status"].clone(),
            )
        };
        let deny = DecisionOutcome::Deny;
        let allow = DecisionOutcome::Allow;
        // The symlink that leads out of the project no longer lets a read through.
        assert_eq!(
            check("explorer", "Read", f.path("link/secret.txt")),
            (deny, json!("differs"))
        );
        assert_eq!(
            check("coder", "Write", f.path("link/new.txt")),
            (deny, json!("differs"))
        );
        // A symlink that stays inside is still refused: only resolved paths are allowed.
        assert_eq!(
            check("explorer", "Read", f.path("inside-link")),
            (deny, json!("differs"))
        );
        assert_eq!(
            check("coder", "Write", f.path("dangling")),
            (deny, json!("unresolved"))
        );
        assert_eq!(
            check("coder", "Write", f.path("src/lib.rs/x")),
            (deny, json!("unresolved"))
        );
        assert_eq!(
            check("explorer", "Read", f.path("src/../src/lib.rs")),
            (deny, json!("differs"))
        );
        // Existing files, new files and new files in new directories resolve to themselves.
        assert_eq!(
            check("explorer", "Read", f.path("src/lib.rs")),
            (allow, json!("same"))
        );
        assert_eq!(
            check("coder", "Write", f.path("src/new.rs")),
            (allow, json!("same"))
        );
        assert_eq!(
            check("coder", "Write", f.path("docs/a/b.md")),
            (allow, json!("same"))
        );
        verify_receipts(&f.state).unwrap();
    }

    #[test]
    fn unknown_or_malformed_agents_are_denied() {
        let f = Fixture::new("unknown");
        let read = json!({ "file_path": f.path("README.md") });
        for agent in ["general-purpose", "../main", "Main", "", "unregistered"] {
            let verdict = f.decide(Some(agent), "Read", read.clone());
            assert_eq!(verdict.outcome, DecisionOutcome::Deny, "{agent:?}");
            assert!(verdict.reason.contains("fs:read"), "{}", verdict.reason);
        }
        // Every one of those denials left a signed receipt under the
        // `unregistered` profile that still names the requested agent.
        let receipts = fs::read_to_string(f.state.join(RECEIPTS_FILE)).unwrap();
        let records: Vec<Value> = receipts
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(records.len(), 5);
        assert!(records.iter().all(|r| r["profile"] == UNREGISTERED));
        assert_eq!(records[1]["agent"], "../main");
        verify_receipts(&f.state).unwrap();
    }

    #[test]
    fn committed_receipts_keep_their_signed_attribution() {
        // Sets 04 and 05 predate the issuer-signed profile name; set 04 also
        // predates the `profile` context key. Both still read back.
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence");
        for (file, agent, profile) in [
            (
                "04-sesion-real-bloqueada-web-fetch/evidence/0001-main-Glob-Allow.json",
                "main",
                "main",
            ),
            (
                "05-sesion-real-final/evidence/0093-coder-Bash-RequireApproval.json",
                "coder",
                "coder",
            ),
            (
                "03-bundle-demo-reproducible/evidence/0020-general-purpose-Read-Deny.json",
                "general-purpose",
                UNREGISTERED,
            ),
        ] {
            let evidence =
                Evidence::from_json(&fs::read_to_string(dir.join(file)).unwrap()).unwrap();
            let attribution = signed_attribution(&evidence).unwrap();
            assert_eq!(attribution.agent, agent, "{file}");
            assert_eq!(attribution.profile, profile, "{file}");
            assert!(!attribution.issuer_bound, "{file}");
        }
    }

    #[test]
    fn summaries_escape_unregistered_agent_types() {
        let label = |agent: &str, profile: &str| {
            Attribution {
                agent: agent.into(),
                profile: profile.into(),
                issuer_bound: true,
            }
            .label()
        };
        assert_eq!(label("coder", "coder"), "coder");
        assert_eq!(
            label("c\u{43e}der", UNREGISTERED),
            "unregistered(agent_type=\"c\\u{43e}der\")"
        );
        assert_eq!(
            label("coder ", UNREGISTERED),
            "unregistered(agent_type=\"coder \")"
        );
    }

    #[test]
    fn receipts_verify_and_detect_tampering() {
        let f = Fixture::new("receipts");
        f.decide(
            Some("coder"),
            "Write",
            json!({ "file_path": f.path("a.rs") }),
        );
        f.decide(
            Some("explorer"),
            "Write",
            json!({ "file_path": f.path("a.rs") }),
        );
        verify_receipts(&f.state).unwrap();

        let path = f.state.join(RECEIPTS_FILE);
        let tampered = fs::read_to_string(&path)
            .unwrap()
            .replacen("\"Deny\"", "\"Allow\"", 1);
        fs::write(&path, tampered).unwrap();
        assert!(verify_receipts(&f.state).is_err());
    }
}
