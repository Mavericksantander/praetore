//! Classification and gating of client→server MCP stdio lines.
//!
//! Everything except client→server `tools/call` is forwarded byte-for-byte.
//! This module is pure (no I/O) apart from the `Evaluator` it is handed.

use crate::{
    gate::{Evaluator, GateError, Mode, Verdict},
    journal::JournalError,
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
    /// (bare `\r` line splitting, case-insensitive keys, nested batches, a
    /// number of a `tools/call` that is not in canonical form).
    /// `candidates` are every `tools/call` reading found, for observe.
    Ambiguous {
        reason: String,
        candidates: Vec<ToolCall>,
        /// Some part of the line (a segment between bare `\r`) could not be
        /// parsed, so `candidates` may miss a reading.
        unparsed: bool,
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

/// A number anywhere in `value` whose text is not the canonical form of the
/// value this proxy reads. The server gets the client's bytes and parses
/// that text itself: an f64 parser, a decimal parser and a bigint parser
/// only agree on a canonical literal, so the gate cannot decide on another.
fn number_problem(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::Number(number) if !number.is_canonical() => Some(format!(
            "number {} is not written in canonical form (read here as {}): the server may read another value; send it as {}",
            number.literal(),
            number.value(),
            number.value()
        )),
        JsonValue::Object(entries) => entries.iter().find_map(|(_, v)| number_problem(v)),
        JsonValue::Array(items) => items.iter().find_map(number_problem),
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
            .or_else(|| params.get("arguments").and_then(nested_fold_problem))
            .or_else(|| number_problem(params));
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
        let mut unparsed = false;
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
                Classified::Passthrough => {}
                Classified::Unparseable(_) => unparsed = true,
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
            unparsed,
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
            Err(Ambiguity { reason, candidates }) => Classified::Ambiguous {
                reason,
                candidates,
                unparsed: false,
            },
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
                Classified::Ambiguous {
                    reason,
                    candidates,
                    unparsed: false,
                }
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
    /// Refused because no receipt could be recorded (evaluation error, or a
    /// receipt the journal could not take). A line that holds such a call is
    /// never forwarded, in either mode: what cannot be recorded is not run.
    Unrecorded(String),
}

fn decide(
    mode: Mode,
    server: &str,
    call: &ToolCall,
    evaluator: &mut dyn Evaluator,
    warnings: &mut Vec<String>,
) -> CallDecision {
    let server_shown = display_safe(server);
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
                "praetore-mcp: {server_shown}/{tool}: {error}; forwarded WITHOUT a receipt ({})",
                mode.as_str()
            ));
            CallDecision::Forward
        }
        // An action type the policy does not declare (for example an
        // undeclared `safety:*` tool) is refused in both modes: it cannot be
        // classified, so it is neither decided nor passed through.
        Err(error @ GateError::UnclassifiedAction { .. }) => {
            warnings.push(format!(
                "praetore-mcp: {server_shown}/{tool}: {error}; call REFUSED ({})",
                mode.as_str()
            ));
            CallDecision::Block(format!(
                "PRÆTORE refused this tool call because the policy does not classify it: {error}"
            ))
        }
        // A call that could not be evaluated has no decision and no receipt.
        // It is refused in both modes: observe records decisions, and a call
        // forwarded without one would run with nothing to record.
        Err(error) => {
            warnings.push(format!(
                "praetore-mcp: ERROR evaluating {server_shown}/{tool}: {error}; call REFUSED ({}, fail closed: no receipt could be recorded)",
                mode.as_str()
            ));
            CallDecision::Unrecorded(format!(
                "PRÆTORE could not evaluate this tool call, so no receipt could be recorded and it was refused (fail closed): {error}"
            ))
        }
        Ok(verdict) => decide_verdict(mode, &server_shown, &tool, &verdict, warnings),
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
        // A receipt that would not verify when read back is never written,
        // and its call is not forwarded in either mode: the call would run
        // with no receipt, and no later repair of the journal could add one.
        if let JournalError::Unverifiable(_) = error {
            warnings.push(format!(
                "praetore-mcp: ERROR receipt for {server}/{tool} (evidence {}) was not written: {error}; call REFUSED ({mode}). A number in the arguments does not survive being written and read back; send it in the form it prints as",
                verdict.evidence_id,
                mode = match mode {
                    Mode::Enforce => "enforce",
                    Mode::Observe => "observe: this call cannot have a receipt",
                }
            ));
            return CallDecision::Unrecorded(format!(
                "PRÆTORE could not write a receipt for this tool call that verifies when read back, so it was refused. Evidence id: {}",
                verdict.evidence_id
            ));
        }
        // The journal could not take the receipt (a cut or blank last line,
        // a symlink, a read-only file, a held lock, a full disk). The call
        // is refused in both modes: a call forwarded without its receipt
        // leaves nothing for `verify` to check, and an observe journal that
        // still verifies would then say nothing about it.
        warnings.push(format!(
            "praetore-mcp: ERROR receipt for {server}/{tool} (evidence {}) could not be written: {error}; call REFUSED ({}, fail closed: no receipt could be recorded)",
            verdict.evidence_id,
            mode.as_str()
        ));
        return CallDecision::Unrecorded(format!(
            "PRÆTORE could not record a receipt for this tool call, so it was refused (fail closed). Evidence id: {}",
            verdict.evidence_id
        ));
    }
    let rules = if verdict.rule_ids.is_empty() {
        "none (default deny)".to_owned()
    } else {
        display_safe(&verdict.rule_ids.join(", "))
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
        (Mode::Enforce, DecisionOutcome::RequireApproval) => {
            if let Some(id) = &verdict.consumed_approval {
                warnings.push(format!(
                    "praetore-mcp: {server}/{tool} forwarded once under local approval {id} (evidence {})",
                    verdict.evidence_id
                ));
                CallDecision::Forward
            } else {
                let text = verdict.hold_message.clone().unwrap_or_else(|| {
                    format!(
                        "This tool call is waiting for local human approval and was not executed. Evidence id: {}",
                        verdict.evidence_id
                    )
                });
                warnings.push(format!(
                    "praetore-mcp: {server}/{tool} waiting for local approval (evidence {})",
                    verdict.evidence_id
                ));
                CallDecision::Block(text)
            }
        }
    }
}

/// Replaces control characters (terminal escapes) in untrusted text and
/// bounds its length before it is printed.
pub fn display_safe(value: &str) -> String {
    // Control, zero-width and bidi characters are written as `\u{XXXX}`
    // (G7), so a tool name cannot pass for another in a table or log line.
    crate::shown::bounded(value, 200)
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

/// `-32700` for a client line that was not forwarded. The `id` is the
/// line's top-level `id` when that value is complete and appears once
/// ([`extract_top_level_id`]), so the client can match the error to its
/// request; otherwise null.
fn parse_error_response(message: &str, raw: &[u8]) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": extract_top_level_id(raw).unwrap_or(Value::Null),
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

/// SHA-256 and length of a client line, to find it again in a capture.
fn fingerprint(raw: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "sha256 {}, {} bytes",
        hex::encode(Sha256::digest(raw)),
        raw.len()
    )
}

/// Whether a line this proxy cannot parse might name a `safety*` tool for
/// a more lenient parser (G7). True when the raw text contains `safety` in
/// any ASCII case, or when a JSON5 string or unquoted key does after its
/// escapes are decoded (lone surrogates become U+FFFD). Comments are skipped
/// while reading those names: an escape inside a comment is not a key.
/// Deliberately broad for the raw text. It only applies to lines that are
/// already malformed.
pub fn may_name_safety_tool(raw: &[u8]) -> bool {
    let text = String::from_utf8_lossy(raw);
    contains_safety(&text) || json5_texts(&text).iter().any(|s| contains_safety(s))
}

fn contains_safety(text: &str) -> bool {
    text.as_bytes()
        .windows(6)
        .any(|window| window.eq_ignore_ascii_case(b"safety"))
}

/// JSON5 strings (single or double quotes) and unquoted keys in `text`, in
/// source order, decoded leniently. An unknown escape keeps the escaped
/// character. An unterminated string runs to the end. A `//` or `/* */`
/// comment outside a string is not text. A trailing comma is not a token.
fn json5_texts(text: &str) -> Vec<String> {
    let mut scan = Json5::new(text);
    let mut texts = Vec::new();
    while !scan.done() {
        if scan.skip_comment() {
            continue;
        }
        match scan.peek() {
            Some('"' | '\'') => {
                let quote = scan.bump().expect("peeked quote");
                texts.push(scan.string(quote));
            }
            Some(c) if is_ident_start(c) || scan.rest().starts_with("\\u") => {
                if let Some(name) = scan.identifier() {
                    texts.push(name);
                } else {
                    scan.bump();
                }
            }
            Some(_) => {
                scan.bump();
            }
            None => break,
        }
    }
    texts
}

struct Json5<'a> {
    text: &'a str,
    at: usize,
}

impl<'a> Json5<'a> {
    fn new(text: &'a str) -> Self {
        Self { text, at: 0 }
    }

    fn done(&self) -> bool {
        self.at >= self.text.len()
    }

    fn rest(&self) -> &'a str {
        &self.text[self.at..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.at += c.len_utf8();
        Some(c)
    }

    /// A `//` or `/* */` comment at the cursor. An unclosed block comment
    /// runs to the end of the text.
    fn skip_comment(&mut self) -> bool {
        if self.rest().starts_with("//") {
            self.at += 2;
            while let Some(c) = self.bump() {
                if c == '\n' {
                    break;
                }
            }
            return true;
        }
        if self.rest().starts_with("/*") {
            self.at += 2;
            loop {
                if self.rest().starts_with("*/") {
                    self.at += 2;
                    break;
                }
                if self.bump().is_none() {
                    break;
                }
            }
            return true;
        }
        false
    }

    fn string(&mut self, quote: char) -> String {
        let mut units = Vec::new();
        while let Some(c) = self.peek() {
            if c == quote {
                self.bump();
                break;
            }
            self.bump();
            if c != '\\' {
                push_utf16(&mut units, c);
                continue;
            }
            let Some(esc) = self.bump() else {
                break;
            };
            match esc {
                'b' => units.push(0x08),
                'f' => units.push(0x0c),
                'n' => units.push(u16::from(b'\n')),
                'r' => units.push(u16::from(b'\r')),
                't' => units.push(u16::from(b'\t')),
                'v' => units.push(0x0b),
                '0' => units.push(0),
                '\n' | '\u{2028}' | '\u{2029}' => {}
                '\r' => {
                    if self.peek() == Some('\n') {
                        self.bump();
                    }
                }
                'x' => self.hex_byte(&mut units),
                'u' => self.hex_unit(&mut units),
                other => push_utf16(&mut units, other),
            }
        }
        String::from_utf16_lossy(&units)
    }

    /// `\xHH` as one code unit. Fewer than two hex digits are kept as text.
    fn hex_byte(&mut self, units: &mut Vec<u16>) {
        let hex = self.take_hex(2);
        match u8::from_str_radix(&hex, 16) {
            Ok(byte) if hex.len() == 2 => units.push(u16::from(byte)),
            _ => units.extend(hex.encode_utf16()),
        }
    }

    /// `\uXXXX` as one UTF-16 code unit, including a lone surrogate. Fewer
    /// than four hex digits are kept as text.
    fn hex_unit(&mut self, units: &mut Vec<u16>) {
        let hex = self.take_hex(4);
        match u16::from_str_radix(&hex, 16) {
            Ok(unit) if hex.len() == 4 => units.push(unit),
            _ => units.extend(hex.encode_utf16()),
        }
    }

    /// Up to `n` hex digits. Stops before a non-hex character, so a closing
    /// quote is left for [`Self::string`].
    fn take_hex(&mut self, n: usize) -> String {
        let mut hex = String::new();
        for _ in 0..n {
            match self.peek() {
                Some(c) if c.is_ascii_hexdigit() => {
                    hex.push(c);
                    self.bump();
                }
                _ => break,
            }
        }
        hex
    }

    /// An unquoted JSON5 key, including `\u` escapes in the identifier.
    /// `None` when the cursor is not an identifier (the caller advances).
    fn identifier(&mut self) -> Option<String> {
        let start = self.at;
        let mut units = Vec::new();
        loop {
            if self.rest().starts_with("\\u") {
                let saved = self.at;
                self.at += 2;
                let hex = self.take_hex(4);
                match u16::from_str_radix(&hex, 16) {
                    Ok(unit) if hex.len() == 4 && ident_unit(unit, units.is_empty()) => {
                        units.push(unit);
                    }
                    _ => {
                        self.at = saved;
                        break;
                    }
                }
            } else {
                match self.peek() {
                    Some(c) if units.is_empty() && is_ident_start(c) => {
                        self.bump();
                        push_utf16(&mut units, c);
                    }
                    Some(c) if !units.is_empty() && is_ident_part(c) => {
                        self.bump();
                        push_utf16(&mut units, c);
                    }
                    _ => break,
                }
            }
        }
        if self.at == start {
            None
        } else {
            Some(String::from_utf16_lossy(&units))
        }
    }
}

fn push_utf16(units: &mut Vec<u16>, c: char) {
    let mut buffer = [0; 2];
    units.extend_from_slice(c.encode_utf16(&mut buffer));
}

fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_' || c == '$'
}

fn is_ident_part(c: char) -> bool {
    is_ident_start(c) || c.is_ascii_digit()
}

/// A UTF-16 code unit from a JSON5 `\u` escape, as an identifier character.
fn ident_unit(unit: u16, first: bool) -> bool {
    let Some(c) = char::from_u32(u32::from(unit)) else {
        return false;
    };
    if first {
        is_ident_start(c)
    } else {
        is_ident_part(c)
    }
}

/// Refuses a malformed line that may name a `safety*` tool, in both modes
/// (G7): it cannot be checked against the declared Safety actions.
fn refuse_safety_unparseable(out: &mut Outcome, mode: Mode, what: &str, reason: &str, raw: &[u8]) {
    out.warnings.push(format!(
        "praetore-mcp: REFUSED {what} client line that may name a safety* tool ({reason}; {}); not forwarded ({})",
        fingerprint(raw),
        mode.as_str()
    ));
    out.to_client = Some(line(&parse_error_response(
        &format!("praetore-mcp: {what} message that may name a safety* tool was not forwarded"),
        raw,
    )));
}

fn refuse_unparseable(out: &mut Outcome, what: &str, reason: &str, raw: &[u8]) {
    out.warnings.push(format!(
        "praetore-mcp: REFUSED {what} client line in enforce mode ({reason}; {}); it could hide a tools/call",
        fingerprint(raw)
    ));
    out.to_client = Some(line(&parse_error_response(
        &format!("praetore-mcp (enforce): {what} message was not forwarded"),
        raw,
    )));
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
        // A line this proxy cannot parse is never forwarded silently: it is
        // refused if it may name a safety* tool (G7), refused in enforce,
        // and forwarded in observe with a warning that identifies it.
        Classified::Unparseable(reason) if may_name_safety_tool(raw) => {
            refuse_safety_unparseable(&mut out, mode, "an unparseable", &reason, raw);
        }
        Classified::Unparseable(reason) => match mode {
            Mode::Observe => {
                out.warnings.push(format!(
                    "praetore-mcp: WARNING unparseable client line ({reason}; {}); forwarded unchanged WITHOUT a receipt (observe)",
                    fingerprint(raw)
                ));
                out.to_server = Some(forward_unchanged(raw));
            }
            Mode::Enforce => refuse_unparseable(&mut out, "an unparseable", &reason, raw),
        },
        Classified::Ambiguous {
            reason,
            unparsed: true,
            ..
        } if may_name_safety_tool(raw) => {
            refuse_safety_unparseable(&mut out, mode, "an ambiguous", &reason, raw);
        }
        Classified::Ambiguous {
            reason, candidates, ..
        } => match mode {
            Mode::Enforce => refuse_unparseable(&mut out, "an ambiguous", &reason, raw),
            Mode::Observe => {
                out.warnings.push(format!(
                    "praetore-mcp: WARNING ambiguous client line ({reason}; {}); forwarded unchanged (observe), recording {} possible tools/call reading(s)",
                    fingerprint(raw),
                    candidates.len()
                ));
                let mut refused = None;
                for call in &candidates {
                    // Observe forwards and only records receipts, except a
                    // reading named `safety*` that is not a declared Safety
                    // action (G7), or a reading whose receipt could not be
                    // recorded: then the line is refused.
                    let decision = decide(mode, server, call, evaluator, &mut out.warnings);
                    let why = match decision {
                        CallDecision::Unrecorded(text) => Some((
                            text,
                            "a tools/call reading that could not be recorded",
                            "praetore-mcp: an ambiguous message with a tools/call that could not be recorded was not forwarded",
                        )),
                        CallDecision::Block(text) if crate::gate::is_safety_named(&call.params) => {
                            Some((
                                text,
                                "an unclassified safety* tool call",
                                "praetore-mcp: an ambiguous message naming a safety* tool was not forwarded",
                            ))
                        }
                        _ => None,
                    };
                    if let Some((text, what, unread)) = why {
                        refused.get_or_insert((call.id.clone(), text, what, unread));
                    }
                }
                match refused {
                    None => out.to_server = Some(forward_unchanged(raw)),
                    Some((id, text, what, unread)) => {
                        out.warnings.push(format!(
                            "praetore-mcp: ambiguous line with {what} REFUSED (observe)"
                        ));
                        out.to_client = Some(match id {
                            Some(id) => line(&blocked_response(&id, &text)),
                            None => line(&parse_error_response(unread, raw)),
                        });
                    }
                }
            }
        },
        Classified::ToolCall(call) => {
            match decide(mode, server, &call, evaluator, &mut out.warnings) {
                CallDecision::Forward => out.to_server = Some(forward_unchanged(raw)),
                CallDecision::Block(text) | CallDecision::Unrecorded(text) => {
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
                        CallDecision::Block(text) | CallDecision::Unrecorded(text) => Some(text),
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

/// JSON-RPC error for a client line longer than the bytes kept in `prefix`.
/// `-32600` carries the top-level `id` when that value is complete in
/// `prefix`. Otherwise `-32700` with `id` null (no id, a truncated id, a
/// second id, or a batch).
pub fn oversized_line_response(prefix: &[u8]) -> Vec<u8> {
    let (id, code) = match extract_top_level_id(prefix) {
        Some(id) => (id, -32600),
        None => (Value::Null, -32700),
    };
    line(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": "praetore-mcp: client message over 32 MiB was not forwarded"
        }
    }))
}

struct Scan<'a> {
    input: &'a [u8],
    i: usize,
}

impl Scan<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.i).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.i += 1;
        Some(byte)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn skip_string(&mut self) -> bool {
        if self.bump() != Some(b'"') {
            return false;
        }
        while let Some(byte) = self.bump() {
            match byte {
                b'"' => return true,
                b'\\' => match self.bump() {
                    Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {}
                    Some(b'u') => {
                        let end = self.i.saturating_add(4);
                        if end > self.input.len()
                            || !self.input[self.i..end]
                                .iter()
                                .all(|c| c.is_ascii_hexdigit())
                        {
                            return false;
                        }
                        self.i = end;
                    }
                    _ => return false,
                },
                _ => {}
            }
        }
        false
    }

    fn skip_literal(&mut self, literal: &[u8]) -> bool {
        if self.input[self.i..].starts_with(literal) {
            self.i += literal.len();
            true
        } else {
            false
        }
    }

    fn skip_digits(&mut self) -> bool {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i > start
    }

    fn skip_number(&mut self) -> bool {
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        if !self.skip_digits() {
            return false;
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !self.skip_digits() {
                return false;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !self.skip_digits() {
                return false;
            }
        }
        true
    }

    fn skip_value(&mut self) -> bool {
        match self.peek() {
            Some(b'"') => self.skip_string(),
            Some(b'{') => self.skip_container(b'{', b'}'),
            Some(b'[') => self.skip_container(b'[', b']'),
            Some(b't') => self.skip_literal(b"true"),
            Some(b'f') => self.skip_literal(b"false"),
            Some(b'n') => self.skip_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.skip_number(),
            _ => false,
        }
    }

    fn skip_container(&mut self, open: u8, close: u8) -> bool {
        if self.bump() != Some(open) {
            return false;
        }
        loop {
            self.skip_ws();
            if self.peek() == Some(close) {
                self.i += 1;
                return true;
            }
            if open == b'{' {
                if !self.skip_string() {
                    return false;
                }
                self.skip_ws();
                if self.bump() != Some(b':') {
                    return false;
                }
                self.skip_ws();
            }
            if !self.skip_value() {
                return false;
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(byte) if byte == close => {
                    self.i += 1;
                    return true;
                }
                _ => return false,
            }
        }
    }
}

/// Top-level JSON-RPC `id` when `prefix` holds a complete value for it.
/// `Some(Null)` means the document's id is JSON null (`-32600`). `None`
/// means the id cannot be taken from this prefix (`-32700`).
fn extract_top_level_id(input: &[u8]) -> Option<Value> {
    let mut scan = Scan { input, i: 0 };
    scan.skip_ws();
    if scan.bump() != Some(b'{') {
        return None;
    }
    let mut found = None;
    loop {
        scan.skip_ws();
        match scan.peek() {
            Some(b'}') => return found,
            Some(b'"') => {}
            None => return found,
            _ => return None,
        }
        let key_start = scan.i;
        if !scan.skip_string() {
            return None;
        }
        let key: String = serde_json::from_slice(&scan.input[key_start..scan.i]).ok()?;
        scan.skip_ws();
        if scan.bump() != Some(b':') {
            return None;
        }
        scan.skip_ws();
        let value_start = scan.i;
        let complete = scan.skip_value();
        if key == "id" {
            if !complete || found.is_some() {
                return None;
            }
            found = Some(serde_json::from_slice(&scan.input[value_start..scan.i]).ok()?);
        } else if !complete {
            return found;
        }
        scan.skip_ws();
        match scan.peek() {
            Some(b',') => scan.i += 1,
            Some(b'}') | None => return found,
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    struct Fixed {
        result: Result<DecisionOutcome, String>,
        journal_error: Option<JournalError>,
        calls: Vec<(String, Value)>,
    }

    impl Fixed {
        fn new(result: Result<DecisionOutcome, String>) -> Self {
            Self {
                result,
                journal_error: None,
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
                journaled: match &self.journal_error {
                    None => Ok(PathBuf::from("/j")),
                    Some(error) => Err(error.clone()),
                },
                consumed_approval: None,
                hold_message: None,
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
        assert_eq!(display_safe("rm\u{1b}[2J\n"), "rm\\u{1b}[2J\\u{a}");
        assert_eq!(
            display_safe("local:set_value\u{200b}"),
            "local:set_value\\u{200b}"
        );
        assert_eq!(display_safe("a\u{202e}b"), "a\\u{202e}b");
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
                .contains("waiting for local human approval")
        );
    }

    #[test]
    fn enforce_allows() {
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(CALL, Mode::Enforce, "fs", &mut eval);
        assert_eq!(out.to_server.as_deref(), Some(CALL));
    }

    /// A call the gate could not evaluate has no receipt: it is refused in
    /// both modes, with a reply the client can read and a stderr line that
    /// names the mode.
    #[test]
    fn evaluation_errors_fail_closed_in_both_modes() {
        for mode in [Mode::Enforce, Mode::Observe] {
            let mut eval = Fixed::new(Err("KEY_LOAD".into()));
            let out = handle_client_line(CALL, mode, "fs", &mut eval);
            assert!(out.to_server.is_none(), "{mode:?}");
            let reply: Value = serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
            assert_eq!(reply["result"]["isError"], true, "{mode:?}");
            assert!(
                reply["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("no receipt could be recorded"),
                "{reply}"
            );
            let warning = &out.warnings[0];
            assert!(
                warning.contains("REFUSED") && warning.contains(mode.as_str()),
                "{warning}"
            );
            assert!(!warning.contains("forwarded"), "{warning}");
        }
    }

    /// A receipt that would not verify when read back: the call is not
    /// forwarded in either mode, and the client gets a reply with its id.
    #[test]
    fn an_unverifiable_receipt_refuses_the_call_in_both_modes() {
        for mode in [Mode::Enforce, Mode::Observe] {
            let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
            eval.journal_error = Some(JournalError::Unverifiable("EVIDENCE_FAIL".into()));
            let out = handle_client_line(CALL, mode, "fs", &mut eval);
            assert!(out.to_server.is_none(), "{mode:?}");
            let reply: Value = serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
            assert_eq!(reply["result"]["isError"], true, "{mode:?}");
            assert!(
                reply["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("could not write a receipt"),
                "{reply}"
            );
            assert!(
                out.warnings[0].contains("was not written") && out.warnings[0].contains("REFUSED"),
                "{:?}",
                out.warnings
            );
        }
    }

    /// A receipt the journal could not take (`Unavailable`): the call is
    /// refused in both modes and the reply carries the evidence id, so the
    /// client can quote what was decided but not recorded.
    #[test]
    fn journal_failure_refuses_the_call_in_both_modes() {
        for mode in [Mode::Enforce, Mode::Observe] {
            let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
            eval.journal_error = Some(JournalError::Unavailable("disk full".into()));
            let out = handle_client_line(CALL, mode, "fs", &mut eval);
            assert!(out.to_server.is_none(), "{mode:?}");
            let reply: Value = serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
            assert_eq!(reply["result"]["isError"], true, "{mode:?}");
            let text = reply["result"]["content"][0]["text"].as_str().unwrap();
            assert!(
                text.contains("could not record a receipt") && text.contains("Evidence id: "),
                "{text}"
            );
            let warning = &out.warnings[0];
            assert!(
                warning.contains("could not be written")
                    && warning.contains("REFUSED")
                    && warning.contains(mode.as_str()),
                "{warning}"
            );
            assert!(!warning.contains("forwarded"), "{warning}");
        }
    }

    /// Unparseable client lines: observe forwards an unparseable line, but never silently:
    /// the warning names the reason, the SHA-256 and the length.
    #[test]
    fn unparseable_lines_refused_in_enforce_forwarded_with_warning_in_observe() {
        let raw = b"{\"method\":\"tools/call\",\n";
        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(raw));
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(raw, Mode::Observe, "s", &mut eval);
        assert_eq!(out.to_server.as_deref(), Some(&raw[..]));
        assert!(out.to_client.is_none());
        assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
        let warning = &out.warnings[0];
        assert!(warning.contains("unparseable client line"), "{warning}");
        assert!(warning.contains("WITHOUT a receipt (observe)"), "{warning}");
        assert!(
            warning.contains(&format!("sha256 {digest}, {} bytes", raw.len())),
            "{warning}"
        );
        let out = handle_client_line(raw, Mode::Enforce, "s", &mut eval);
        assert!(out.to_server.is_none());
        let reply: Value = serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
        assert_eq!(reply["error"]["code"], -32700);
        assert_eq!(reply["id"], Value::Null);
        assert!(out.warnings[0].contains(&digest), "{:?}", out.warnings);
        assert!(eval.calls.is_empty());
    }

    /// T-016-B6: the `-32700` for a refused line carries the line's `id`
    /// when it is complete and appears once, and null otherwise.
    #[test]
    fn refused_unparseable_line_names_its_id_when_it_can_be_read() {
        let cases: [(&[u8], Value); 5] = [
            (b"{\"id\":7,\"method\":\"tools/call\",\n", json!(7)),
            (b"{\"id\":\"a\",\"method\":\"tools/call\",\n", json!("a")),
            (b"{\"method\":\"tools/call\",\n", Value::Null),
            (
                b"{\"id\":1,\"id\":2,\"method\":\"tools/call\",\n",
                Value::Null,
            ),
            (b"{\"id\":\"tru", Value::Null),
        ];
        for (raw, id) in cases {
            let label = String::from_utf8_lossy(raw);
            let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
            let out = handle_client_line(raw, Mode::Enforce, "s", &mut eval);
            assert!(out.to_server.is_none(), "{label}");
            let reply: Value = serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
            assert_eq!(reply["error"]["code"], -32700, "{label}");
            assert_eq!(reply["id"], id, "{label}");
            assert!(eval.calls.is_empty(), "{label}");
        }
    }

    /// An ambiguous line in observe whose reading could not be recorded (the
    /// journal did not take the receipt, or the call could not be
    /// evaluated) is refused, not forwarded: what cannot be recorded is not
    /// run, whatever the tool is called. With a working journal the same
    /// line is forwarded, as before.
    #[test]
    fn an_ambiguous_line_is_refused_in_observe_when_a_reading_cannot_be_recorded() {
        let raw = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":{"n":1e2}}}
"#;
        assert!(matches!(
            classify(raw),
            Classified::Ambiguous {
                unparsed: false,
                ..
            }
        ));
        let mut recorded = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(raw, Mode::Observe, "fs", &mut recorded);
        assert_eq!(out.to_server.as_deref(), Some(&raw[..]));

        let mut journal_down = Fixed::new(Ok(DecisionOutcome::Allow));
        journal_down.journal_error = Some(JournalError::Unavailable("disk full".into()));
        let not_evaluated = Fixed::new(Err("KEY_LOAD".into()));
        for (label, mut eval) in [("journal", journal_down), ("evaluation", not_evaluated)] {
            let out = handle_client_line(raw, Mode::Observe, "fs", &mut eval);
            assert!(out.to_server.is_none(), "{label}: forwarded");
            let reply: Value = serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
            assert_eq!(reply["id"], 7, "{label}");
            assert_eq!(reply["result"]["isError"], true, "{label}");
            assert!(
                reply["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("no receipt could be recorded")
                    || reply["result"]["content"][0]["text"]
                        .as_str()
                        .unwrap()
                        .contains("could not record a receipt"),
                "{label}: {reply}"
            );
            assert!(
                out.warnings.iter().any(|w| w
                    .contains("ambiguous line with a tools/call reading that could not be recorded REFUSED (observe)")),
                "{label}: {:?}",
                out.warnings
            );
        }
    }

    /// Case 6 of F1, the only one with no trace on disk: another process
    /// holds the journal lock past its timeout. The real gate waits
    /// `LOCK_TIMEOUT`, writes nothing, and observe refuses the call; once
    /// the lock is let go the next call is recorded and forwarded.
    #[test]
    fn a_journal_lock_held_past_its_timeout_refuses_the_call_in_observe() {
        let temp = tempfile::tempdir().unwrap();
        let home =
            crate::store::Home::new(std::fs::canonicalize(temp.path()).unwrap().join("home"));
        crate::store::init(&home).unwrap();
        let mut gate = crate::gate::Gate::load(&home, Mode::Observe).unwrap();
        let held = crate::journal::JournalLock::acquire(&home.receipts_dir()).unwrap();
        let started = std::time::Instant::now();
        let out = handle_client_line(CALL, Mode::Observe, "fs", &mut gate);
        assert!(
            started.elapsed() >= crate::journal::LOCK_TIMEOUT,
            "{:?}",
            started.elapsed()
        );
        assert!(out.to_server.is_none(), "forwarded: {:?}", out.warnings);
        let reply: Value = serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
        assert_eq!(reply["id"], 7);
        assert_eq!(reply["result"]["isError"], true);
        assert!(
            reply["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("could not record a receipt"),
            "{reply}"
        );
        assert!(
            out.warnings.iter().any(|w| w.contains("lock")
                && w.contains("could not be written")
                && w.contains("REFUSED (observe")),
            "{:?}",
            out.warnings
        );
        assert!(crate::receipts::read_journal(&home).unwrap().is_empty());

        drop(held);
        let out = handle_client_line(CALL, Mode::Observe, "fs", &mut gate);
        assert_eq!(out.to_server.as_deref(), Some(CALL), "{:?}", out.warnings);
        assert_eq!(crate::receipts::read_journal(&home).unwrap().len(), 1);
    }

    /// Ambiguous client lines in observe: the warning names the raw line by
    /// its SHA-256 and length, the same fingerprint as the other line notices.
    #[test]
    fn observe_ambiguous_line_warning_includes_sha256() {
        let raw = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"Method\":\"tools/call\",\"params\":{\"name\":\"rm\"}}\n";
        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(raw));
        assert!(matches!(
            classify(raw),
            Classified::Ambiguous {
                unparsed: false,
                ..
            }
        ));
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(raw, Mode::Observe, "s", &mut eval);
        assert_eq!(out.to_server.as_deref(), Some(&raw[..]));
        assert!(out.to_client.is_none());
        assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
        let warning = &out.warnings[0];
        assert!(warning.contains("ambiguous client line"), "{warning}");
        assert!(warning.contains("(observe)"), "{warning}");
        assert!(
            warning.contains(&format!("sha256 {digest}, {} bytes", raw.len())),
            "{warning}"
        );
    }

    fn nested_call(name: &str, depth: usize) -> Vec<u8> {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{{\"name\":\"{name}\",\"arguments\":{{\"a\":{}1{}}}}}}}",
            "[".repeat(depth),
            "]".repeat(depth)
        )
        .into_bytes()
    }

    /// Lenient JSON: JSON that other parsers accept and this one rejects.
    /// For an ordinary tool, observe forwards with a warning and enforce
    /// refuses; the evaluator is never called (no reading to evaluate).
    #[test]
    fn lenient_json_for_an_ordinary_tool_warns_in_observe_and_is_refused_in_enforce() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "duplicate key",
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/a","path":"/b"}}}"#.to_vec(),
            ),
            (
                "lone surrogate",
                br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"\ud800"}}}"#.to_vec(),
            ),
            ("200 levels of nesting", nested_call("write_file", 200)),
        ];
        for (label, raw) in cases {
            assert!(
                matches!(classify(&raw), Classified::Unparseable(_)),
                "{label}"
            );
            let mut eval = Fixed::new(Ok(DecisionOutcome::Deny));
            let out = handle_client_line(&raw, Mode::Observe, "fs", &mut eval);
            assert_eq!(
                out.to_server.as_deref().map(|b| &b[..raw.len()]),
                Some(&raw[..]),
                "{label}"
            );
            assert!(out.to_client.is_none(), "{label}");
            assert_eq!(out.warnings.len(), 1, "{label}: {:?}", out.warnings);
            assert!(
                out.warnings[0].contains("WARNING unparseable client line")
                    && out.warnings[0].contains(&format!("{} bytes", raw.len())),
                "{label}: {:?}",
                out.warnings
            );
            let out = handle_client_line(&raw, Mode::Enforce, "fs", &mut eval);
            assert!(out.to_server.is_none(), "{label}");
            assert!(out.to_client.is_some(), "{label}");
            assert!(eval.calls.is_empty(), "{label}");
        }
    }

    /// Safety tool names in unparseable lines: a malformed line that may name a `safety*` tool is
    /// refused in both modes, never forwarded, and never evaluated.
    #[test]
    fn lenient_json_naming_a_safety_tool_is_refused_in_both_modes() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "undeclared safety:halt with a duplicate key",
                br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"safety:halt","arguments":{"x":1,"x":2}}}"#.to_vec(),
            ),
            (
                "duplicate name, safety reading first",
                br#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"safety:halt","name":"echo"}}"#.to_vec(),
            ),
            (
                "escaped name and a lone surrogate",
                br#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"\u0053AFETY:halt","arguments":{"p":"\ud800"}}}"#.to_vec(),
            ),
            ("200 levels of nesting", nested_call("Safety:stop_all", 200)),
            (
                "not JSON at all",
                b"{method: 'tools/call', params: {name: 'safety:halt'}}".to_vec(),
            ),
        ];
        for (label, raw) in cases {
            assert!(may_name_safety_tool(&raw), "{label}");
            for mode in [Mode::Observe, Mode::Enforce] {
                let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
                let out = handle_client_line(&raw, mode, "fs", &mut eval);
                assert!(out.to_server.is_none(), "{label} ({})", mode.as_str());
                let reply: Value =
                    serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
                assert_eq!(reply["error"]["code"], -32700, "{label}");
                assert!(
                    out.warnings[0].contains("may name a safety* tool"),
                    "{label}: {:?}",
                    out.warnings
                );
                assert!(eval.calls.is_empty(), "{label}");
            }
        }
    }

    /// A bare-CR line whose segments do not all parse, naming a safety tool
    /// in a segment that does not parse, is refused in observe too.
    #[test]
    fn ambiguous_line_with_an_unparsed_safety_segment_is_refused_in_observe() {
        let raw = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"safety:halt\",\"name\":\"x\"}}\n";
        assert!(matches!(
            classify(raw),
            Classified::Ambiguous { unparsed: true, .. }
        ));
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(raw, Mode::Observe, "s", &mut eval);
        assert!(out.to_server.is_none());
        assert!(out.to_client.is_some());
        assert!(eval.calls.is_empty());
    }

    #[test]
    fn string_literals_decode_escapes_leniently() {
        assert_eq!(
            json5_texts(r#"{"a":"\u0073afety","b":"x\ud800y","c":"unterminated"#),
            ["a", "safety", "b", "x\u{fffd}y", "c", "unterminated"]
        );
        assert!(!may_name_safety_tool(
            br#"{"name":"write_file","x":1,"x":2}"#
        ));
        assert!(may_name_safety_tool(br#"{"name":"\u0073\u0061fety:halt"}"#));
    }

    /// JSON5 can spell `safety` only after decoding: an unquoted key with
    /// `\u`, a single-quoted string, a `\x` escape, a comment that would
    /// swallow the next quote, a trailing comma, and a line continuation.
    /// The raw bytes do not contain the six letters. Those lines are refused
    /// in both modes, and the warning still names the line by its SHA-256.
    /// An escape that sits inside a comment is not a name.
    #[test]
    fn json5_safety_keys_are_refused_in_both_modes() {
        assert_eq!(
            json5_texts(r#"{'a':'\x73afety','b':"\x65",'c':'\u0073till'}"#),
            ["a", "safety", "b", "e", "c", "still"]
        );
        assert_eq!(json5_texts(r"{saf\u0065ty:1,}"), ["safety"]);
        assert_eq!(json5_texts(r#"{/* "\x73 */ "\x73afety"}"#), ["safety"]);
        assert_eq!(json5_texts(r#"{/* "\x73afety" */ "write"}"#), ["write"]);
        assert_eq!(json5_texts("{\"a\":\"saf\\\r\nety\"}"), ["a", "safety"]);

        let encoded: &[(&str, &[u8])] = &[
            ("unquoted key with unicode escapes", br#"{saf\u0065ty: 1,}"#),
            (
                "unquoted key made only of unicode escapes",
                br#"{\u0073\u0061\u0066\u0065\u0074\u0079: "halt"}"#,
            ),
            (
                "single-quoted unicode escape and a trailing comma",
                br#"{'name': '\u0073afety:halt',}"#,
            ),
            (
                "single-quoted hex escapes",
                br#"{'name': '\x73\x61\x66\x65\x74\x79:halt'}"#,
            ),
            (
                "double-quoted hex escape",
                br#"{"name":"\x73afety:halt","x":1,"x":2}"#,
            ),
            (
                "comment, unquoted key, single quotes, trailing comma",
                br#"{ /* policy */ name: '\x73afety:halt', }"#,
            ),
            (
                "a comment quote must not hide the next string",
                br#"{/* "\x73 */ "\x73afety:halt"}"#,
            ),
            (
                "a line comment must not hide the next string",
                b"{// \"\\x73\n\"\\x73afety:halt\"}",
            ),
            ("line continuation", b"{\"name\":\"saf\\\nety:halt\"}"),
        ];
        for (label, raw) in encoded {
            assert!(
                !raw.windows(6)
                    .any(|window| window.eq_ignore_ascii_case(b"safety")),
                "{label} contains the letters before decoding"
            );
            assert!(
                matches!(classify(raw), Classified::Unparseable(_)),
                "{label} parsed as JSON"
            );
            assert!(may_name_safety_tool(raw), "{label}");
            let mark = fingerprint(raw);
            for mode in [Mode::Observe, Mode::Enforce] {
                let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
                let out = handle_client_line(raw, mode, "fs", &mut eval);
                assert!(out.to_server.is_none(), "{label} {}", mode.as_str());
                let reply: Value =
                    serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
                assert_eq!(reply["error"]["code"], -32700, "{label}");
                let warning = &out.warnings[0];
                assert!(
                    warning.contains("may name a safety* tool") && warning.contains(&mark),
                    "{label} {}: {warning}",
                    mode.as_str()
                );
                assert!(eval.calls.is_empty(), "{label}");
            }
        }

        // The same JSON5 forms, with an ordinary tool, stay a warning in
        // observe: comments, single quotes and a trailing comma are not
        // themselves a safety name.
        let ordinary = br#"{ /* cfg */ method: 'tools/call', params: {name: 'write_file',}, }"#;
        assert!(!may_name_safety_tool(ordinary));
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(ordinary, Mode::Observe, "fs", &mut eval);
        assert_eq!(
            out.to_server.as_deref(),
            Some(forward_unchanged(ordinary).as_slice())
        );
        assert!(out.to_client.is_none());
        assert!(
            out.warnings[0].contains("WARNING unparseable client line")
                && out.warnings[0].contains(&fingerprint(ordinary)),
            "{:?}",
            out.warnings
        );
        assert!(eval.calls.is_empty());

        // `\x73afety` inside a comment is comment text, not a key or a string.
        let commented = br#"{/* "\x73afety:halt" */ "name": "write_file"}"#;
        assert!(
            !commented
                .windows(6)
                .any(|window| window.eq_ignore_ascii_case(b"safety"))
        );
        assert!(!may_name_safety_tool(commented));
        let line_comment = b"{// \"\\x73afety:halt\"\n\"name\": \"write_file\"}";
        assert!(
            !line_comment
                .windows(6)
                .any(|window| window.eq_ignore_ascii_case(b"safety"))
        );
        assert!(!may_name_safety_tool(line_comment));
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

        // Nothing blocked: original bytes (including the formatting of a
        // number outside `params`).
        let raw = br#"[{"jsonrpc":"2.0","id":1.50,"method":"tools/call","params":{"name":"x","arguments":{"n":100.0}}}]"#;
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(raw, Mode::Enforce, "s", &mut eval);
        assert_eq!(
            out.to_server.as_deref().map(|b| &b[..b.len() - 1]),
            Some(&raw[..])
        );
    }

    #[test]
    fn a_number_not_in_canonical_form_makes_a_tools_call_ambiguous() {
        let call = |number: &str| {
            format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"x","arguments":{{"a":[{{"n":{number}}}]}}}}}}"#
            )
        };
        for number in ["50", "50.0", "49.99999999999999", "-7", "0.1"] {
            assert!(
                matches!(classify(call(number).as_bytes()), Classified::ToolCall(_)),
                "{number}"
            );
        }
        for number in [
            "49.9999999999999965",
            "50.00000000000000001",
            "50.00",
            "1e2",
            "-0",
            "18446744073709551616",
        ] {
            let Classified::Ambiguous {
                reason, candidates, ..
            } = classify(call(number).as_bytes())
            else {
                panic!("{number} was not ambiguous");
            };
            assert!(
                reason.contains(&format!("number {number} is not written in canonical form")),
                "{reason}"
            );
            // Observe still records the reading this proxy has.
            assert_eq!(candidates.len(), 1, "{number}");
        }
        // In a batch element too, and enforce forwards none of it.
        let raw = format!("[{}]", call("1e2"));
        assert!(matches!(
            classify(raw.as_bytes()),
            Classified::Ambiguous { .. }
        ));
        let mut eval = Fixed::new(Ok(DecisionOutcome::Allow));
        let out = handle_client_line(call("1e2").as_bytes(), Mode::Enforce, "s", &mut eval);
        assert!(out.to_server.is_none());
        // A message that is not a tools/call is forwarded as written.
        let raw = br#"{"jsonrpc":"2.0","id":1,"method":"x/progress","params":{"progress":5e-1}}"#;
        assert_eq!(classify(raw), Classified::Passthrough);
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

    fn oversized(prefix: &str) -> Value {
        serde_json::from_slice(&oversized_line_response(prefix.as_bytes())).unwrap()
    }

    #[test]
    fn oversized_line_uses_32600_when_the_id_is_in_the_prefix() {
        for (prefix, id) in [
            (
                r#"{"jsonrpc":"2.0","id":"big","method":"tools/call","params":{"f":""#,
                json!("big"),
            ),
            (r#"{"id":7,"#, json!(7)),
            ("{ \"id\" : null }", json!(null)),
            (r#"{"params":{"id":1},"id":"late"}"#, json!("late")),
        ] {
            let reply = oversized(prefix);
            assert_eq!(reply["id"], id, "{prefix}");
            assert_eq!(reply["error"]["code"], -32600, "{prefix}");
        }
    }

    #[test]
    fn oversized_line_uses_32700_when_the_id_is_not_extractable() {
        for prefix in [
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"f":"xxxx"#,
            r#"{"id":"trun"#,
            r#"{"id":1,"id":2}"#,
            r#"[{"jsonrpc":"2.0","id":1}]"#,
            "not json",
            r#"{"method":"see \"id\" here"}"#,
        ] {
            let reply = oversized(prefix);
            assert_eq!(reply["id"], Value::Null, "{prefix}");
            assert_eq!(reply["error"]["code"], -32700, "{prefix}");
        }
    }

    struct BidiRuleEvaluator;

    impl Evaluator for BidiRuleEvaluator {
        fn evaluate(&mut self, _server: &str, _params: &Value) -> Result<Verdict, GateError> {
            Ok(Verdict {
                unclassified: false,
                outcome: DecisionOutcome::Deny,
                evidence_id: Uuid::nil(),
                rule_ids: vec!["rule\x1b[2K\r\n\u{202e}\u{200b}".into()],
                reason: "denied".into(),
                journaled: Ok(PathBuf::from("/j")),
                consumed_approval: None,
                hold_message: None,
            })
        }
    }

    #[test]
    fn warnings_escape_server_name_and_rule_ids() {
        let server = "srv\u{202e}\u{200b}\x1b[2K\r\n";
        for mode in [Mode::Observe, Mode::Enforce] {
            let mut eval = BidiRuleEvaluator;
            let out = handle_client_line(CALL, mode, server, &mut eval);
            let joined = out.warnings.join("\n");
            for forbidden in ["\x1b", "\r", "\u{202e}", "\u{200b}", "[2K\n"] {
                assert!(
                    !joined.contains(forbidden),
                    "raw {forbidden:?} in {mode:?} warnings:\n{joined:?}"
                );
            }
            assert!(joined.contains("\\u{202e}"), "{joined}");
            assert!(joined.contains("\\u{1b}"), "{joined}");
        }
    }
}
