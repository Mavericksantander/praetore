//! Stdio MCP probe for number-literal tests. TEST-ONLY.
//!
//! Records every JSON number token of each `tools/call` it receives, parsed
//! with Rust's correctly rounded `f64` parser (`FromStr`), not with
//! `serde_json`. One JSON line per call is appended to the path in the
//! first argument:
//!
//! `{"id":...,"numbers":[{"literal":"49.9999999999999965","parsed":"50.0"}]}`
//!
//! `parsed` is `nonfinite` when the token is not a finite binary64.

use serde_json::{Number, Value, json};
use std::{
    fs::OpenOptions,
    io::{BufRead, Write},
};

fn main() {
    let log_path = std::env::args().nth(1).expect("log path");
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .unwrap_or_else(|error| panic!("open {log_path}: {error}"));
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let message: Value = match serde_json::from_str(&line) {
            Ok(message) => message,
            Err(_) => {
                let _ = writeln!(
                    stdout,
                    r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":-32700,"message":"Parse error"}}}}"#
                );
                let _ = stdout.flush();
                continue;
            }
        };
        if message.get("method").and_then(Value::as_str) == Some("tools/call") {
            let numbers: Vec<Value> = number_tokens(&line)
                .into_iter()
                .map(|literal| {
                    json!({
                        "literal": literal,
                        "parsed": parsed_binary64(&literal),
                    })
                })
                .collect();
            writeln!(
                log,
                "{}",
                json!({
                    "id": message.get("id").cloned().unwrap_or(Value::Null),
                    "numbers": numbers,
                })
            )
            .unwrap();
            log.flush().unwrap();
        }
        let Some(id) = message.get("id").cloned() else {
            continue;
        };
        let result = match message.get("method").and_then(Value::as_str) {
            Some("initialize") => json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "number_probe", "version": "0.0.1"}
            }),
            Some("tools/list") => json!({"tools": [
                {"name": "pay", "inputSchema": {"type": "object"}}
            ]}),
            Some("tools/call") => json!({
                "content": [{"type": "text", "text": "ok"}],
                "isError": false
            }),
            _ => {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "Method not found"}})
                );
                let _ = stdout.flush();
                continue;
            }
        };
        let _ = writeln!(
            stdout,
            "{}",
            json!({"jsonrpc": "2.0", "id": id, "result": result})
        );
        let _ = stdout.flush();
    }
}

fn parsed_binary64(literal: &str) -> String {
    match literal.parse::<f64>() {
        Ok(value) if value.is_finite() => Number::from_f64(value)
            .map(|number| number.to_string())
            .unwrap_or_else(|| "nonfinite".to_owned()),
        _ => "nonfinite".to_owned(),
    }
}

/// Number tokens in `input`, in order. The grammar is JSON's; this does not
/// use `serde_json`, so the token text is the bytes the probe was given.
fn number_tokens(input: &str) -> Vec<String> {
    let bytes = input.as_bytes();
    let mut index = 0;
    let mut tokens = Vec::new();
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                index += 1;
                while index < bytes.len() {
                    match bytes[index] {
                        b'\\' => index = index.saturating_add(2).min(bytes.len()),
                        b'"' => {
                            index += 1;
                            break;
                        }
                        _ => index += 1,
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = index;
                if bytes[index] == b'-' {
                    index += 1;
                }
                if index < bytes.len() && bytes[index] == b'0' {
                    index += 1;
                } else {
                    while index < bytes.len() && bytes[index].is_ascii_digit() {
                        index += 1;
                    }
                }
                if index < bytes.len() && bytes[index] == b'.' {
                    index += 1;
                    while index < bytes.len() && bytes[index].is_ascii_digit() {
                        index += 1;
                    }
                }
                if index < bytes.len() && (bytes[index] == b'e' || bytes[index] == b'E') {
                    index += 1;
                    if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
                        index += 1;
                    }
                    while index < bytes.len() && bytes[index].is_ascii_digit() {
                        index += 1;
                    }
                }
                if index > start {
                    tokens.push(input[start..index].to_owned());
                }
            }
            _ => index += 1,
        }
    }
    tokens
}
