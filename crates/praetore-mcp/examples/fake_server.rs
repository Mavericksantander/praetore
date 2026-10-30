//! A tiny stdio MCP server for tests and demos. TEST-ONLY.
//!
//! Tools: `echo` (returns its arguments) and `delete_file` (pretends to
//! delete `arguments.path`). Every executed tools/call is also logged to
//! stderr as `fake_server: EXECUTED <tool>` so tests can see what ran.

use serde_json::{Value, json};
use std::io::{BufRead, Write};

fn main() {
    eprintln!("fake_server: started");
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            let _ = writeln!(
                stdout,
                r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":-32700,"message":"Parse error"}}}}"#
            );
            continue;
        };
        let Some(id) = message.get("id").cloned() else {
            continue; // notification
        };
        let result = match message.get("method").and_then(Value::as_str) {
            Some("initialize") => json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake_server", "version": "0.0.1"}
            }),
            Some("tools/list") => json!({"tools": [
                {"name": "echo", "description": "Echo arguments", "inputSchema": {"type": "object"}},
                {"name": "delete_file", "description": "Pretend to delete a file",
                 "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}}
            ]}),
            Some("tools/call") => {
                let name = message["params"]["name"].as_str().unwrap_or("?").to_owned();
                eprintln!("fake_server: EXECUTED {name}");
                json!({"content": [{"type": "text",
                    "text": format!("{name} ok: {}", message["params"]["arguments"])}],
                    "isError": false})
            }
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
