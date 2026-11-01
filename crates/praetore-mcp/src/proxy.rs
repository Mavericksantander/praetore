//! Classification and gating of client→server MCP stdio lines.
//!
//! Everything except client→server `tools/call` is forwarded byte-for-byte.
//! This module is pure (no I/O) apart from the `Evaluator` it is handed.

use crate::{
    gate::{Evaluator, GateError, Mode, Verdict},
    json::JsonValue,
};
use praetore_core::DecisionOutcome;
use serde_json::{Value, json};

pub const TOOLS_CALL: &str = "tools/call";

/// Keys other parsers may match case-insensitively at the message and
/// `params` levels (Go `encoding/json`, used by mcp-go, folds field names).
const RESERVED_KEYS: [&str; 6] = ["method", "params", "id", "jsonrpc", "name", "arguments"];

/// One `tools/call` request or notification found in a client line.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    /// `None` for a notification (no `id` member): nothing is replied.
    pub id: Option<Value>,
    pub params: Value,
}

/// One element of a JSON-RPC batch.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchItem {
    pub id: Option<Value>,
    pub call: Option<ToolCall>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Classified {
    /// Forward unchanged (not a `tools/call`, or blank).
    Passthrough,
    ToolCall(ToolCall),
    /// A JSON-RPC batch containing at least one `tools/call`.
    Batch(Vec<BatchItem>),
    /// Not UTF-8, not JSON, or JSON with duplicate keys.
    Unparseable(String),
    /// Valid here, but another MCP server parser could read it differently
    /// (bare `\r` line splitting, case-insensitive keys, nested batches).
    /// `candidates` are every `tools/call` reading found, for observe.
    Ambiguous {
        reason: String,
        candidates: Vec<ToolCall>,
    },
}

/// Simple case folding, at least as broad as Go's `unicode.SimpleFold` /
/// `strings.EqualFold`: lower∘upper∘lower maps every member of a simple-fold
/// orbit (e.g. `s`/`S`/`ſ`, `k`/`K`/`K`, `ß`/`ẞ`, `σ`/`ς`/`Σ`) to one string.
/// It may fold some extra pairs (e.g. `ß`/`ss`), which only makes enforce
/// stricter.
pub fn fold(key: &str) -> String {
    key.chars()
        .flat_map(char::to_lowercase)
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .collect()
}

fn entries(value: &JsonValue) -> &[(String, JsonValue)] {
    match value {
        JsonValue::Object(entries) => entries,
        _ => &[],
    }
}

/// Keys that collide under case folding, or that fold to a reserved name
/// without being it.
fn fold_problem(value: &JsonValue, check_reserved: bool) -> Option<String> {
    let mut seen = std::collections::HashMap::new();
    for (key, _) in entries(value) {
        let folded = fold(key);
        if let Some(previous) = seen.insert(folded.clone(), key) {
            return Some(format!(
                "keys {previous:?} and {key:?} are equal under case folding"
            ));
        }
        if check_reserved
            && RESERVED_KEYS.contains(&folded.as_str())
            && !RESERVED_KEYS.contains(&key.as_str())
        {
            return Some(format!("key {key:?} is a case variant of {folded:?}"));
        }
    }
    None
}

/// Case-fold collisions anywhere inside tool arguments (tools may decode
/// nested structs case-insensitively too).
fn nested_fold_problem(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::Object(entries) => fold_problem(value, false)
            .or_else(|| entries.iter().find_map(|(_, v)| nested_fold_problem(v))),
        JsonValue::Array(items) => items.iter().find_map(nested_fold_problem),
        _ => None,
    }
}

/// Exact-key reading (what this proxy and most JSON parsers see).
fn tool_call_of(value: &JsonValue) -> Option<ToolCall> {
    if value.get("method").and_then(JsonValue::as_str) != Some(TOOLS_CALL) {
        return None;
    }
    Some(ToolCall {
        id: value.get("id").map(JsonValue::to_value),
        params: value.get("params").map_or(Value::Null, JsonValue::to_value),
    })
}

/// Last member whose key folds to `key` (Go assigns every case-insensitive
/// match in document order, so the last one wins).
fn get_folded<'a>(value: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    entries(value)
        .iter()
        .rev()
        .find(|(k, _)| fold(k) == key)
        .map(|(_, v)| v)
}

/// Case-insensitive reading (Go `encoding/json` into structs).
fn folded_tool_call_of(value: &JsonValue) -> Option<ToolCall> {
    if get_folded(value, "method").and_then(JsonValue::as_str) != Some(TOOLS_CALL) {
        return None;
    }
    let params = get_folded(value, "params").map(|params| {
        let mut out = serde_json::Map::new();
        if let JsonValue::Object(_) = params {
            for key in ["name", "arguments"] {
                if let Some(v) = get_folded(params, key) {
                    out.insert(key.into(), v.to_value());
                }
            }
            Value::Object(out)
        } else {
            params.to_value()
        }
    });
    Some(ToolCall {
        id: get_folded(value, "id").map(JsonValue::to_value),
        params: params.unwrap_or(Value::Null),
    })
}

struct Ambiguity {
    reason: String,
    candidates: Vec<ToolCall>,
}

fn push_unique(candidates: &mut Vec<ToolCall>, call: Option<ToolCall>) {
    if let Some(call) = call
        && !candidates.contains(&call)
    {
        candidates.push(call);
    }
}

/// Every exact or case-folded `tools/call` reading anywhere in `value`.
fn collect_calls(value: &JsonValue, out: &mut Vec<ToolCall>) {
    match value {
        JsonValue::Array(items) => items.iter().for_each(|item| collect_calls(item, out)),
        JsonValue::Object(_) => {
            push_unique(out, tool_call_of(value));
            push_unique(out, folded_tool_call_of(value));
        }
        _ => {}
    }
}

/// Checks one message object for case-folding ambiguity.
fn check_message(value: &JsonValue) -> Result<Option<ToolCall>, Ambiguity> {
    let exact = tool_call_of(value);
    let mut problem = fold_problem(value, true);
    if problem.is_none()
        && exact.is_some()
        && let Some(params) = value.get("params")
    {
        problem = fold_problem(params, true)
            .or_else(|| params.get("arguments").and_then(nested_fold_problem));
    }
    match problem {
        None => Ok(exact),
        Some(reason) => {
            let mut candidates = Vec::new();
            push_unique(&mut candidates, exact);
            push_unique(&mut candidates, folded_tool_call_of(value));
            Err(Ambiguity { reason, candidates })
        }
    }
}

/// Classifies one line (without or with its trailing newline).
pub fn classify(line: &[u8]) -> Classified {
    let Ok(text) = std::str::from_utf8(line) else {
        return Classified::Unparseable("line is not valid UTF-8".into());
    };
    let body = text.strip_suffix('\n').unwrap_or(text);
    let body = body.strip_suffix('\r').unwrap_or(body);
    if body.contains('\r') {
        // Python's TextIOWrapper (universal newlines, used by the MCP Python
        // SDK) and Node's readline end a line at `\r`, `\n` or `\r\n`, while
        // JSON treats `\r` as whitespace. Collect what such a reader sees.
        let mut candidates = Vec::new();
        let segments: Vec<&str> = body.split('\r').collect();
        for segment in &segments {
            match classify_text(segment) {
                Classified::ToolCall(call) => push_unique(&mut candidates, Some(call)),
                Classified::Batch(items) => {
                    for item in items {
                        push_unique(&mut candidates, item.call);
                    }
                }
                Classified::Ambiguous {
                    candidates: inner, ..
                } => {
                    for call in inner {
                        push_unique(&mut candidates, Some(call));
                    }
                }
                Classified::Passthrough | Classified::Unparseable(_) => {}
            }
        }
        if let Classified::ToolCall(call) = classify_text(body) {
            push_unique(&mut candidates, Some(call));
        }
        return Classified::Ambiguous {
            reason: format!(
                "bare carriage return: universal-newline readers would split this line into {} messages",
                segments.len()
            ),
            candidates,
        };
    }
    classify_text(body)
}

fn classify_text(text: &str) -> Classified {
    if text.trim().is_empty() {
        return Classified::Passthrough;
    }
    let value = match JsonValue::parse(text) {
        Ok(value) => value,
        Err(error) => return Classified::Unparseable(error),
    };
    match &value {
        JsonValue::Object(_) => match check_message(&value) {
            Ok(Some(call)) => Classified::ToolCall(call),
            Ok(None) => Classified::Passthrough,
            Err(Ambiguity { reason, candidates }) => Classified::Ambiguous { reason, candidates },
        },
        JsonValue::Array(elements) => {
            let mut items = Vec::new();
            let mut ambiguous: Option<String> = None;
            let mut candidates = Vec::new();
            for element in elements {
                match element {
                    JsonValue::Array(_) => {
                        ambiguous.get_or_insert_with(|| "nested array inside a batch".into());
                        collect_calls(element, &mut candidates);
                    }
                    JsonValue::Object(_) => match check_message(element) {
                        Ok(call) => {
                            push_unique(&mut candidates, call.clone());
                            items.push(BatchItem {
                                id: element.get("id").map(JsonValue::to_value),
                                call,
                            });
                        }
                        Err(Ambiguity {
                            reason,
                            candidates: inner,
                        }) => {
                            ambiguous.get_or_insert(reason);
                            for call in inner {
                                push_unique(&mut candidates, Some(call));
                            }
                        }
                    },
                    _ => items.push(BatchItem {
                        id: None,
                        call: None,
                    }),
                }
            }
            if let Some(reason) = ambiguous {
                Classified::Ambiguous { reason, candidates }
            } else if items.iter().any(|item| item.call.is_some()) {
                Classified::Batch(items)
            } else {
                Classified::Passthrough
            }
        }
        _ => Classified::Passthrough,
    }
}

/// What the relay must do with one client line.
#[derive(Debug, Default, PartialEq)]
pub struct Outcome {
    /// Bytes to write to the server's stdin (already newline-terminated).
    pub to_server: Option<Vec<u8>>,
    /// Bytes to write to the client's stdout (already newline-terminated).
    pub to_client: Option<Vec<u8>>,
    /// Human diagnostics for stderr.
    pub warnings: Vec<String>,
}

enum CallDecision {
    Forward,
    Block(String),
}

fn decide(
    mode: Mode,
    server: &str,
    call: &ToolCall,
    evaluator: &mut dyn Evaluator,
    warnings: &mut Vec<String>,
) -> CallDecision {
    let tool = call
        .params
        .get("name")
        .and_then(Value::as_str)
        .map_or_else(|| "?".to_owned(), display_safe);
    match evaluator.evaluate(server, &call.params) {
        // G7: a safety action that the policy declares Safety is
        // not governed by PRÆTORE. It was not evaluated, signed or recorded,
        // and it is forwarded to the wrapped server without a receipt in both
        // modes; its record is left to a separate ingestion path.
        Err(error @ GateError::SafetyActionNotGoverned { .. }) => {
            warnings.push(format!(
                "praetore-mcp: {server}/{tool}: {error}; forwarded WITHOUT a receipt ({})",
                mode.as_str()
            ));
            CallDecision::Forward
        }
        // An action type the policy does not declare (for example an
        // undeclared `safety:*` tool) is refused in both modes: it cannot be
        // classified, so it is neither decided nor passed through.
        Err(error @ GateError::UnclassifiedAction { .. }) => {
            warnings.push(format!(
                "praetore-mcp: {server}/{tool}: {error}; call REFUSED ({})",
                mode.as_str()
            ));
            CallDecision::Block(format!(
                "PRÆTORE refused this tool call because the policy does not classify it: {error}"
            ))
        }
        Err(error) => match mode {
            Mode::Enforce => {
                warnings.push(format!(
                    "praetore-mcp: ERROR evaluating {server}/{tool}: {error}; call REFUSED (enforce, fail closed)"
                ));
                CallDecision::Block(format!(
                    "PRÆTORE could not evaluate this tool call, so it was refused (fail closed): {error}"
                ))
            }
            Mode::Observe => {
                warnings.push(format!(
                    "praetore-mcp: WARNING evaluating {server}/{tool} failed: {error}; call forwarded WITHOUT a receipt (observe mode)"
                ));
                CallDecision::Forward
            }
        },
        Ok(verdict) => decide_verdict(mode, server, &tool, &verdict, warnings),
    }
}

fn decide_verdict(
    mode: Mode,
    server: &str,
    tool: &str,
    verdict: &Verdict,
    warnings: &mut Vec<String>,
) -> CallDecision {
    if let Err(error) = &verdict.journaled {
        match mode {
            Mode::Enforce => {
                warnings.push(format!(
                    "praetore-mcp: ERROR receipt for {server}/{tool} could not be written: {error}; call REFUSED (enforce)"
                ));
                return CallDecision::Block(format!(
                    "PRÆTORE could not record a receipt for this tool call, so it was refused (fail closed). Evidence id: {}",
                    verdict.evidence_id
                ));
            }
            Mode::Observe => warnings.push(format!(
                "praetore-mcp: WARNING !!! receipt for {server}/{tool} (evidence {}) could NOT be written: {error}; call forwarded anyway (observe mode) !!!",
                verdict.evidence_id
            )),
        }
    }
    let rules = if verdict.rule_ids.is_empty() {
        "none (default deny)".to_owned()
    } else {
        verdict.rule_ids.join(", ")
    };
    // Every DENY gets the same client-facing text, whatever decided it, so
    // the client cannot tell from it what the policy declares or which rule
    // matched. The details go to stderr and to the signed receipt.
    let denied = || format!("Denied by PRÆTORE. Evidence id: {}", verdict.evidence_id);
    if verdict.unclassified {
        // G7: an action type the policy does not declare is refused in both
        // modes, with its signed DENY receipt.
        warnings.push(format!(
            "praetore-mcp: {server}/{tool}: action type not declared in the policy; signed DENY (evidence {}); call REFUSED ({})",
            verdict.evidence_id,
            mode.as_str()
        ));
        return CallDecision::Block(denied());
    }
    match (mode, verdict.outcome) {
        (_, DecisionOutcome::Allow) => CallDecision::Forward,
        (Mode::Observe, outcome) => {
            warnings.push(format!(
                "praetore-mcp: observe: {server}/{tool} would be {} by rule {rules} (evidence {}); forwarded",
                outcome_label(outcome),
                verdict.evidence_id
            ));
            CallDecision::Forward
        }
        (Mode::Enforce, DecisionOutcome::Deny) => {
            warnings.push(format!(
                "praetore-mcp: {server}/{tool} DENIED by rule {rules}: {} (evidence {})",
                display_safe(&verdict.reason),
                verdict.evidence_id
            ));
            CallDecision::Block(denied())
        }
        (Mode::Enforce, DecisionOutcome::RequireApproval) => CallDecision::Block(format!(
            "This tool call requires human approval (not supported by praetore-mcp yet), so it was not executed. Rule: {rules}. Evidence id: {}",
            verdict.evidence_id
        )),
    }
}

/// Replaces control characters (terminal escapes) in untrusted text and
/// bounds its length before it is printed.
pub fn display_safe(value: &str) -> String {
    let mut out: String = value
        .chars()
        .take(200)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if value.chars().count() > 200 {
        out.push('…');
    }
    out
}

pub fn outcome_label(outcome: DecisionOutcome) -> &'static str {
    match outcome {
        DecisionOutcome::Allow => "ALLOWED",
        DecisionOutcome::Deny => "DENIED",
        DecisionOutcome::RequireApproval => "held for APPROVAL",
    }
}

/// MCP tool result with `isError: true` for the given request id.
pub fn blocked_response(id: &Value, text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{"type": "text", "text": text}],
            "isError": true
        }
    })
}

fn parse_error_response(message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": {"code": -32700, "message": message}
    })
}

fn line(value: &impl serde::Serialize) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// Ensures forwarded bytes end with exactly the original terminator; a final
/// line without a newline (EOF) is given one so the server can frame it.
fn forward_unchanged(raw: &[u8]) -> Vec<u8> {
    let mut bytes = raw.to_vec();
    if !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    bytes
}

fn refuse_unparseable(out: &mut Outcome, what: &str, reason: &str) {
    out.warnings.push(format!(
        "praetore-mcp: REFUSED {what} client line in enforce mode ({reason}); it could hide a tools/call"
    ));
    out.to_client = Some(line(&parse_error_response(&format!(
        "praetore-mcp (enforce): {what} message was not forwarded"
    ))));
}

fn batch_refused_error(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32600,
            "message": "praetore-mcp (enforce): batch not forwarded because another element was blocked"
        }
    })
}

/// Handles one raw client line (including its newline, if any).
pub fn handle_client_line(
    raw: &[u8],
    mode: Mode,
    server: &str,
    evaluator: &mut dyn Evaluator,
) -> Outcome {
    let mut out = Outcome::default();
    match classify(raw) {
        Classified::Passthrough => out.to_server = Some(forward_unchanged(raw)),
        Classified::Unparseable(reason) => match mode {
            Mode::Observe => out.to_server = Some(forward_unchanged(raw)),
            Mode::Enforce => refuse_unparseable(&mut out, "an unparseable", &reason),
        },
        Classified::Ambiguous { reason, candidates } => match mode {
            Mode::Enforce => refuse_unparseable(&mut out, "an ambiguous", &reason),
            Mode::Observe => {
                out.warnings.push(format!(
                    "praetore-mcp: WARNING ambiguous client line ({reason}); forwarded unchanged (observe), recording {} possible tools/call reading(s)",
                    candidates.len()
                ));
                let mut refused = None;
                for call in &candidates {
                    // Observe forwards and only records receipts, except a
                    // reading named `safety*` that is not a declared Safety
                    // action (G7): then the line is refused.
                    let decision = decide(mode, server, call, evaluator, &mut out.warnings);
                    if let CallDecision::Block(text) = decision
                        && crate::gate::is_safety_named(&call.params)
                    {
                        refused.get_or_insert((call.id.clone(), text));
                    }
                }
                match refused {
                    None => out.to_server = Some(forward_unchanged(raw)),
                    Some((id, text)) => {
                        out.warnings.push(
                            "praetore-mcp: ambiguous line with an unclassified safety* tool call REFUSED (observe)".into(),
                        );
                        out.to_client = Some(match id {
                            Some(id) => line(&blocked_response(&id, &text)),
                            None => line(&parse_error_response(
                                "praetore-mcp: an ambiguous message naming a safety* tool was not forwarded",
                            )),
                        });
                    }
                }
            }
        },
        Classified::ToolCall(call) => {
            match decide(mode, server, &call, evaluator, &mut out.warnings) {
                CallDecision::Forward => out.to_server = Some(forward_unchanged(raw)),
                CallDecision::Block(text) => {
                    if let Some(id) = &call.id {
                        out.to_client = Some(line(&blocked_response(id, &text)));
                    }
                }
            }
        }
        Classified::Batch(items) => {
            // All or nothing: if any tools/call is blocked, nothing in the
            // batch is forwarded and every request in it gets a reply. The
            // forwarded bytes are therefore always the original bytes.
            let mut blocked: Vec<Option<String>> = Vec::with_capacity(items.len());
            for item in &items {
                blocked.push(match &item.call {
                    Some(call) => match decide(mode, server, call, evaluator, &mut out.warnings) {
                        CallDecision::Forward => None,
                        CallDecision::Block(text) => Some(text),
                    },
                    None => None,
                });
            }
            if blocked.iter().all(Option::is_none) {
                out.to_server = Some(forward_unchanged(raw));
            } else {
                let replies: Vec<Value> = items
                    .iter()
                    .zip(&blocked)
                    .filter_map(|(item, text)| {
                        let id = item.id.as_ref()?;
                        Some(match (text, &item.call) {
                            (Some(text), _) => blocked_response(id, text),
                            (None, Some(_)) => blocked_response(
                                id,
                                "Not executed: praetore-mcp refused the whole batch because another tool call in it was blocked.",
                            ),
                            (None, None) => batch_refused_error(id),
                        })
                    })
                    .collect();
                if !replies.is_empty() {
                    out.to_client = Some(line(&replies));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    struct Fixed {
        result: Result<DecisionOutcome, String>,
        journal_ok: bool,
        calls: Vec<(String, Value)>,
    }

    impl Fixed {
        fn new(result: Result<DecisionOutcome, String>) -> Self {
            Self {
                result,
                journal_ok: true,
                calls: Vec::new(),
            }
        }
    }

    impl Evaluator for Fixed {
        fn evaluate(&mut self, server: &str, params: &Value) -> Result<Verdict, GateError> {
            self.calls.push((server.into(), params.clone()));
            let outcome = self.result.clone()?;
            Ok(Verdict {
                unclassified: false,
                outcome,
                evidence_id: Uuid::nil(),
                rule_ids: vec!["rule-x".into()],
                reason: "Policy rule 'rule-x' matched".into(),
                journaled: if self.journal_ok {
                    Ok(PathBuf::from("/j"))
                } else {
                    Err("disk full".into())
                },
            })
        }
    }

    const CALL: &[u8] =
        br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"rm","arguments":{"path":"/"}}}
"#;

    #[test]
    fn classifies_messages() {
        assert_eq!(classify(b"\n"), Classified::Passthrough);
        assert_eq!(
            classify(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
            Classified::Passthrough
        );
        assert_eq!(
            classify(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Classified::Passthrough
        );
        assert_eq!(
            classify(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
            Classified::Passthrough
        );
        match classify(CALL) {
            Classified::ToolCall(call) => {
                assert_eq!(call.id, Some(json!(7)));
                assert_eq!(call.params["name"], "rm");
            }
            other => panic!("unexpected {other:?}"),
        }
        match classify(br#"{"jsonrpc":"2.0","id":"abc","method":"tools/call"}"#) {
            Classified::ToolCall(call) => {
                assert_eq!(call.id, Some(json!("abc")));
                assert_eq!(call.params, Value::Null);
            }
            other => panic!("unexpected {other:?}"),
        }
        match classify(br#"{"jsonrpc":"2.0","method":"tools/call","params":{}}"#) {
            Classified::ToolCall(call) => assert_eq!(call.id, None),
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(classify(b"not json"), Classified::Unparseable(_)));
        assert!(matches!(classify(b"\xff\xfe"), Classified::Unparseable(_)));
        assert!(matches!(
            classify(br#"{"method":"tools/list","method":"tools/call","id":1}"#),
            Classified::Unparseable(_)
        ));
        assert!(matches!(
            classify(br#"[{"jsonrpc":"2.0","id":1,"method":"tools/call"}]"#),
            Classified::Batch(_)
        ));
        assert_eq!(
            classify(br#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#),
            Classified::Passthrough
        );
    }

    #[test]
    fn display_safe_strips_escapes() {
        assert_eq!(display_safe("rm\u{1b}[2J\n"), "rm?[2J?");
    }

    #[test]
    fn passthrough_is_byte_for_byte() {
        let raw = b"{ \"jsonrpc\" : \"2.0\", \"id\":1,\"method\":\"tools/list\" }\r\n";
        let mut eval = Fixed::new(Ok(DecisionOutcome::Deny));
        let out = handle_client_line(raw, Mode::Enforce, "s", &mut eval);
        assert_eq!(out.to_server.as_deref(), Some(&raw[..]));
        assert!(out.to_client.is_none());
        assert!(eval.calls.is_empty());
    }

    #[test]
    fn observe_forwards_denied_call_unchanged() {
        let mut eval = Fixed::new(Ok(DecisionOutcome::Deny));
        let out = handle_client_line(CALL, Mode::Observe, "fs", &mut eval);
        assert_eq!(out.to_server.as_deref(), Some(CALL));
        assert!(out.to_client.is_none());
        assert_eq!(eval.calls[0].0, "fs");
        assert!(out.warnings[0].contains("would be DENIED"));
    }

    #[test]
    fn enforce_blocks_deny_with_is_error_and_same_id() {
        let mut eval = Fixed::new(Ok(DecisionOutcome::Deny));
        let out = handle_client_line(CALL, Mode::Enforce, "fs", &mut eval);
        assert!(out.to_server.is_none());
        let reply: Value = serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
        assert_eq!(reply["id"], 7);
        assert_eq!(reply["result"]["isError"], true);
        let text = reply["result"]["content"][0]["text"].as_str().unwrap();
        // The client-facing text is the same for every DENY (G7); the rule
        // is reported on stderr only.
        assert_eq!(
            text,
            format!("Denied by PRÆTORE. Evidence id: {}", Uuid::nil())
        );
        assert!(out.warnings.iter().any(|w| w.contains("rule-x")));
    }

    #[test]
    fn enforce_blocks_require_approval() {
        let mut eval = Fixed::new(Ok(DecisionOutcome::RequireApproval));
        let out = handle_client_line(CALL, Mode::Enforce, "fs", &mut eval);
        assert!(out.to_server.is_none());
        let reply: Value = serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
        assert!(
            reply["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("requires human approval (not supported by praetore-mcp yet)")
        );
    }

    #[test]
    fn enforce_allows() {
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(CALL, Mode::Enforce, "fs", &mut eval);
        assert_eq!(out.to_server.as_deref(), Some(CALL));
    }

    #[test]
    fn evaluation_errors_fail_closed_only_in_enforce() {
        let mut eval = Fixed::new(Err("KEY_LOAD".into()));
        let out = handle_client_line(CALL, Mode::Enforce, "fs", &mut eval);
        assert!(out.to_server.is_none());
        assert!(out.to_client.is_some());
        let out = handle_client_line(CALL, Mode::Observe, "fs", &mut eval);
        assert_eq!(out.to_server.as_deref(), Some(CALL));
        assert!(out.warnings[0].contains("WITHOUT a receipt"));
    }

    #[test]
    fn journal_failure_refuses_in_enforce_and_warns_in_observe() {
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        eval.journal_ok = false;
        let out = handle_client_line(CALL, Mode::Enforce, "fs", &mut eval);
        assert!(out.to_server.is_none());
        assert!(out.to_client.is_some());
        let out = handle_client_line(CALL, Mode::Observe, "fs", &mut eval);
        assert_eq!(out.to_server.as_deref(), Some(CALL));
        assert!(out.warnings[0].contains("could NOT be written"));
    }

    #[test]
    fn unparseable_lines_refused_in_enforce_forwarded_in_observe() {
        let raw = b"{\"method\":\"tools/call\",\n";
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(raw, Mode::Observe, "s", &mut eval);
        assert_eq!(out.to_server.as_deref(), Some(&raw[..]));
        let out = handle_client_line(raw, Mode::Enforce, "s", &mut eval);
        assert!(out.to_server.is_none());
        let reply: Value = serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
        assert_eq!(reply["error"]["code"], -32700);
        assert_eq!(reply["id"], Value::Null);
    }

    #[test]
    fn denied_notification_gets_no_reply() {
        let raw = br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}"#;
        let mut eval = Fixed::new(Ok(DecisionOutcome::Deny));
        let out = handle_client_line(raw, Mode::Enforce, "s", &mut eval);
        assert!(out.to_server.is_none());
        assert!(out.to_client.is_none());
    }

    #[test]
    fn enforce_batch_is_all_or_nothing() {
        let raw = br#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":"b","method":"tools/call","params":{"name":"rm"}},{"jsonrpc":"2.0","method":"notifications/x"}]"#;
        let mut eval = Fixed::new(Ok(DecisionOutcome::Deny));
        let out = handle_client_line(raw, Mode::Enforce, "s", &mut eval);
        assert!(out.to_server.is_none());
        let reply: Value = serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
        assert_eq!(reply.as_array().unwrap().len(), 2);
        assert_eq!(reply[0]["id"], 1);
        assert_eq!(reply[0]["error"]["code"], -32600);
        assert_eq!(reply[1]["id"], "b");
        assert_eq!(reply[1]["result"]["isError"], true);

        // Nothing blocked: original bytes (including number formatting).
        let raw = br#"[{"jsonrpc":"2.0","id":1.50,"method":"tools/call","params":{"name":"x","arguments":{"n":1e2}}}]"#;
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(raw, Mode::Enforce, "s", &mut eval);
        assert_eq!(
            out.to_server.as_deref().map(|b| &b[..b.len() - 1]),
            Some(&raw[..])
        );
    }

    #[test]
    fn nested_batch_is_refused_in_enforce() {
        let raw = br#"[[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rm"}}]]"#;
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(raw, Mode::Enforce, "s", &mut eval);
        assert!(out.to_server.is_none());
        assert!(eval.calls.is_empty());
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(raw, Mode::Observe, "s", &mut eval);
        assert!(out.to_server.is_some());
        assert_eq!(eval.calls.len(), 1, "observe still records the nested call");
    }

    /// Reviewer's repro: Python's universal-newline reader splits on bare CR.
    #[test]
    fn bare_carriage_return_is_refused_in_enforce_and_recorded_in_observe() {
        let raw = b"{\"a\":1,\"x\":\r{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"rm\"}}\r}\n";
        assert!(matches!(classify(raw), Classified::Ambiguous { .. }));
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(raw, Mode::Enforce, "s", &mut eval);
        assert!(out.to_server.is_none());
        assert!(eval.calls.is_empty());
        let reply: Value = serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
        assert_eq!(reply["error"]["code"], -32700);

        let mut eval = Fixed::new(Ok(DecisionOutcome::Deny));
        let out = handle_client_line(raw, Mode::Observe, "s", &mut eval);
        assert_eq!(out.to_server.as_deref(), Some(&raw[..]));
        assert_eq!(eval.calls.len(), 1);
        assert_eq!(eval.calls[0].1["name"], "rm");
        assert!(out.warnings[0].contains("carriage return"));
    }

    #[test]
    fn crlf_terminator_is_still_fine() {
        let raw = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\r\n";
        assert_eq!(classify(raw), Classified::Passthrough);
        let raw = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\r\r\n";
        assert!(matches!(classify(raw), Classified::Ambiguous { .. }));
    }

    #[test]
    fn unicode_line_separators_outside_strings_are_rejected_by_json() {
        // U+2028 / U+2029 / NEL are not JSON whitespace: serde_json rejects
        // them outside strings, and they are harmless inside strings.
        for sep in ["\u{2028}", "\u{2029}", "\u{85}", "\u{0b}", "\u{0c}"] {
            let line = format!("{{\"a\":1,{sep}\"b\":2}}");
            assert!(
                matches!(classify(line.as_bytes()), Classified::Unparseable(_)),
                "{sep:?}"
            );
            let inside =
                format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"p\":\"a{sep}b\"}}");
            // Raw C0 controls are invalid even inside strings (fail closed).
            let c0 = sep.chars().all(|c| (c as u32) < 0x20);
            assert_eq!(
                classify(inside.as_bytes()) == Classified::Passthrough,
                !c0,
                "{sep:?}"
            );
        }
    }

    #[test]
    fn folding_matches_go_simple_fold_orbits() {
        for (a, b) in [
            ("method", "METHOD"),
            ("s", "ſ"),
            ("k", "\u{212a}"),
            ("ß", "ẞ"),
            ("σ", "ς"),
            ("Σ", "ς"),
            ("ǅ", "ǆ"),
        ] {
            assert_eq!(fold(a), fold(b), "{a} {b}");
        }
        assert_ne!(fold("method"), fold("methods"));
    }

    #[test]
    fn case_variant_keys_are_ambiguous() {
        let cases: &[&[u8]] = &[
            // Go: last case-insensitive match wins -> tools/call
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","Method":"tools/call","params":{"name":"rm"}}"#,
            // Kelvin sign / long s variants of reserved keys
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"argument\u{17f}\":{\"p\":1}}}".as_bytes(),
            // Kelvin sign collision inside arguments
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"x\",\"arguments\":{\"k\":1,\"\u{212a}\":2}}}".as_bytes(),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/li\u{17f}t\"}".as_bytes(),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"METHOD\":\"tools/call\"}".as_bytes(),
            // params level
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","Name":"rm"}}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","Arguments":{"p":"/"}}}"#,
            // nested inside arguments
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"o":[{"path":"/ok","PATH":"/etc"}]}}}"#,
        ];
        for raw in &cases[..3] {
            assert!(
                matches!(classify(raw), Classified::Ambiguous { .. }),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
        // "tools/liſt" is a value, not a key: values are compared exactly.
        assert_eq!(classify(cases[3]), Classified::Passthrough);
        for raw in &cases[4..] {
            assert!(
                matches!(classify(raw), Classified::Ambiguous { .. }),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }

        let raw = cases[0];
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(raw, Mode::Enforce, "s", &mut eval);
        assert!(out.to_server.is_none() && eval.calls.is_empty());
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(raw, Mode::Observe, "s", &mut eval);
        assert_eq!(
            out.to_server.as_deref().map(|b| &b[..b.len() - 1]),
            Some(raw)
        );
        assert_eq!(
            eval.calls.len(),
            1,
            "the Go reading (tools/call rm) is recorded"
        );
        assert_eq!(eval.calls[0].1["name"], "rm");

        // Ordinary non-reserved keys with distinct folds stay fine.
        let ok = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"Path":"/a","mode":"r"}}}"#;
        assert!(matches!(classify(ok), Classified::ToolCall(_)));
    }
}
