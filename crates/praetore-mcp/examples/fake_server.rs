//! A tiny stdio MCP server for tests and demos. TEST-ONLY.
//!
//! Tools: `echo` (returns its arguments), `delete_file` (pretends to
//! delete `arguments.path`) and `append` (really appends `arguments.text` to
//! `arguments.path`, for path-alias tests). An unlisted `write_text` call
//! does exactly what `append` does, for the evasion test of one tool used for
//! another's effect (tests/evasion.rs). Every executed tools/call is also logged to
//! stderr as `fake_server: EXECUTED <tool>` so tests can see what ran.
//!
//! A call with a numeric `arguments.amount` also logs the value this server
//! read, as `fake_server: RECORDED amount <id> int <i128>` or `... float
//! <f64>`. The literal is parsed with the standard library (`str::parse`),
//! not with `serde_json`, so the value does not depend on how the proxy's
//! JSON parser is built (tests/numeric_gate.rs).
//!
//! For `policy coverage` tests:
//! - `FAKE_SERVER_TOOLS=filesystem-2.3.0` makes `tools/list` return the 16
//!   tool names of `@modelcontextprotocol/server-filesystem@2.3.0`, in its
//!   order; `FAKE_SERVER_PAGE_SIZE=N` splits that list into pages linked by
//!   `nextCursor`.
//! - `FAKE_SERVER_EXIT_AT_START=1` exits without answering. On Unix it
//!   closes stdout first and writes `exiting without answering` to stderr a
//!   moment later, so a client sees the end of stdout before that line is
//!   written, as with a server that fails while still writing to stderr.

/// `tools/list` of `@modelcontextprotocol/server-filesystem@2.3.0`.
const FILESYSTEM_2_3_0: [&str; 16] = [
    "read_file",
    "read_text_file",
    "read_media_file",
    "read_multiple_files",
    "write_file",
    "append_file",
    "edit_file",
    "create_directory",
    "list_directory",
    "list_directory_with_sizes",
    "directory_tree",
    "move_file",
    "copy_file",
    "search_files",
    "get_file_info",
    "list_allowed_directories",
];

/// The text of `params.arguments.amount` in `line`, when it is a number.
fn amount_literal(line: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Message<'a> {
        #[serde(borrow)]
        params: Params<'a>,
    }
    #[derive(serde::Deserialize)]
    struct Params<'a> {
        #[serde(borrow)]
        arguments: Arguments<'a>,
    }
    #[derive(serde::Deserialize)]
    struct Arguments<'a> {
        #[serde(borrow)]
        amount: &'a serde_json::value::RawValue,
    }
    let message: Message = serde_json::from_str(line).ok()?;
    let literal = message.params.arguments.amount.get();
    literal
        .starts_with(|c: char| c == '-' || c.is_ascii_digit())
        .then(|| literal.to_owned())
}

/// `int <value>` or `float <value>`, as the standard library reads `literal`.
fn recorded(literal: &str) -> String {
    match literal.parse::<i128>() {
        Ok(integer) => format!("int {integer}"),
        Err(_) => format!("float {:?}", literal.parse::<f64>().unwrap_or(f64::NAN)),
    }
}

fn env_set(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn tools_list(params: &Value) -> Value {
    if env_set("FAKE_SERVER_TOOLS").as_deref() != Some("filesystem-2.3.0") {
        return json!({"tools": [
            {"name": "echo", "description": "Echo arguments", "inputSchema": {"type": "object"}},
            {"name": "delete_file", "description": "Pretend to delete a file",
             "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}}
        ]});
    }
    let size = env_set("FAKE_SERVER_PAGE_SIZE")
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|size| *size > 0)
        .unwrap_or(FILESYSTEM_2_3_0.len());
    let start = params["cursor"]
        .as_str()
        .and_then(|cursor| cursor.parse::<usize>().ok())
        .unwrap_or(0)
        .min(FILESYSTEM_2_3_0.len());
    let end = (start + size).min(FILESYSTEM_2_3_0.len());
    let tools: Vec<Value> = FILESYSTEM_2_3_0[start..end]
        .iter()
        .map(|name| json!({"name": name, "inputSchema": {"type": "object"}}))
        .collect();
    if end < FILESYSTEM_2_3_0.len() {
        json!({"tools": tools, "nextCursor": end.to_string()})
    } else {
        json!({"tools": tools})
    }
}

use serde_json::{Value, json};
use std::io::{BufRead, Write};

fn main() {
    eprintln!("fake_server: started");
    if env_set("FAKE_SERVER_EXIT_AT_START").is_some() {
        #[cfg(unix)]
        {
            // SAFETY: closes this process's own stdout, which nothing else
            // in this branch uses.
            unsafe { libc::close(1) };
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        eprintln!("fake_server: exiting without answering");
        return;
    }
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
            Some("tools/list") => tools_list(&message["params"]),
            Some("tools/call") => {
                let name = message["params"]["name"].as_str().unwrap_or("?").to_owned();
                eprintln!("fake_server: EXECUTED {name}");
                if let Some(literal) = amount_literal(&line) {
                    eprintln!("fake_server: RECORDED amount {id} {}", recorded(&literal));
                }
                if name == "append" || name == "write_text" {
                    let arguments = &message["params"]["arguments"];
                    let path = arguments["path"].as_str().unwrap_or_default();
                    let text = arguments["text"].as_str().unwrap_or_default();
                    let written = std::fs::OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(path)
                        .and_then(|mut file| file.write_all(text.as_bytes()));
                    eprintln!("fake_server: append {path:?} -> {written:?}");
                }
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
