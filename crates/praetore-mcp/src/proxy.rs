//! Classification and gating of client→server MCP stdio lines.
//!
//! Everything except client→server `tools/call` is forwarded byte-for-byte.
//! This module is pure (no I/O) apart from the `Evaluator` it is handed.

use crate::{
    gate::{Evaluator, Mode, Verdict},
    json::JsonValue,
};
use praetore_core::DecisionOutcome;
use serde_json::{Value, json};

pub const TOOLS_CALL: &str = "tools/call";

/// One `tools/call` request or notification found in a client line.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    /// `None` for a notification (no `id` member): nothing is replied.
    pub id: Option<Value>,
    pub params: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Classified {
    /// Forward unchanged (not a `tools/call`, or blank).
    Passthrough,
    ToolCall(ToolCall),
    /// A JSON-RPC batch containing at least one `tools/call`. Elements keep
    /// their original order; `Some` marks the gated ones.
    Batch(Vec<(JsonValue, Option<ToolCall>)>),
    /// Not UTF-8, not JSON, or JSON with duplicate keys.
    Unparseable(String),
}

fn tool_call_of(value: &JsonValue) -> Option<ToolCall> {
    if value.get("method").and_then(JsonValue::as_str) != Some(TOOLS_CALL) {
        return None;
    }
    Some(ToolCall {
        id: value.get("id").map(JsonValue::to_value),
        params: value.get("params").map_or(Value::Null, JsonValue::to_value),
    })
}

/// Classifies one line (without or with its trailing newline).
pub fn classify(line: &[u8]) -> Classified {
    let Ok(text) = std::str::from_utf8(line) else {
        return Classified::Unparseable("line is not valid UTF-8".into());
    };
    let text = text.trim_end_matches(['\n', '\r']);
    if text.trim().is_empty() {
        return Classified::Passthrough;
    }
    let value = match JsonValue::parse(text) {
        Ok(value) => value,
        Err(error) => return Classified::Unparseable(error),
    };
    match &value {
        JsonValue::Object(_) => match tool_call_of(&value) {
            Some(call) => Classified::ToolCall(call),
            None => Classified::Passthrough,
        },
        JsonValue::Array(items) => {
            let gated: Vec<_> = items
                .iter()
                .map(|item| (item.clone(), tool_call_of(item)))
                .collect();
            if gated.iter().any(|(_, call)| call.is_some()) {
                Classified::Batch(gated)
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
        (Mode::Enforce, DecisionOutcome::Deny) => CallDecision::Block(format!(
            "Denied by PRÆTORE policy. Rule: {rules}. Reason: {}. Evidence id: {}",
            verdict.reason, verdict.evidence_id
        )),
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
            Mode::Enforce => {
                out.warnings.push(format!(
                    "praetore-mcp: REFUSED an unparseable client line in enforce mode ({reason}); it could hide a tools/call"
                ));
                out.to_client = Some(line(&parse_error_response(
                    "praetore-mcp (enforce): unparseable message was not forwarded",
                )));
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
            let mut kept = Vec::new();
            let mut replies = Vec::new();
            let mut blocked_any = false;
            for (item, call) in items {
                match call {
                    None => kept.push(item),
                    Some(call) => match decide(mode, server, &call, evaluator, &mut out.warnings) {
                        CallDecision::Forward => kept.push(item),
                        CallDecision::Block(text) => {
                            blocked_any = true;
                            if let Some(id) = &call.id {
                                replies.push(blocked_response(id, &text));
                            }
                        }
                    },
                }
            }
            if !blocked_any {
                out.to_server = Some(forward_unchanged(raw));
            } else if !kept.is_empty() {
                out.to_server = Some(line(&JsonValue::Array(kept)));
            }
            if !replies.is_empty() {
                out.to_client = Some(line(&replies));
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
        fn evaluate(&mut self, server: &str, params: &Value) -> Result<Verdict, String> {
            self.calls.push((server.into(), params.clone()));
            let outcome = self.result.clone()?;
            Ok(Verdict {
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
        assert!(text.contains("rule-x"));
        assert!(text.contains(&Uuid::nil().to_string()));
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
        assert_eq!(
            out,
            Outcome {
                warnings: vec![],
                ..Outcome::default()
            }
        );
    }

    #[test]
    fn batch_removes_blocked_calls_and_replies_in_a_batch() {
        let raw = br#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":"b","method":"tools/call","params":{"name":"rm"}}]"#;
        let mut eval = Fixed::new(Ok(DecisionOutcome::Deny));
        let out = handle_client_line(raw, Mode::Enforce, "s", &mut eval);
        assert_eq!(
            out.to_server.as_deref(),
            Some(&b"[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}]\n"[..])
        );
        let reply: Value = serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
        assert_eq!(reply[0]["id"], "b");
        assert_eq!(reply[0]["result"]["isError"], true);

        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(raw, Mode::Enforce, "s", &mut eval);
        assert_eq!(
            out.to_server.as_deref().map(|b| &b[..b.len() - 1]),
            Some(&raw[..])
        );
    }
}
