//! `praetore-mcp policy coverage`: starts an MCP server, asks it for
//! `tools/list`, and closes it. Nothing is written; no `tools/call` is sent.

use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    time::{Duration, Instant},
};

/// How long the server has to answer `initialize` and every `tools/list`
/// page, in total.
pub const TIMEOUT: Duration = Duration::from_secs(60);
/// Most `tools/list` pages read before giving up on a server that keeps
/// returning `nextCursor`.
const MAX_PAGES: usize = 100;
/// Bytes of the server's stderr kept to explain a failure.
const STDERR_TAIL: usize = 4096;

struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    stderr: Arc<Mutex<Vec<u8>>>,
    deadline: Instant,
}

impl Server {
    fn send(&mut self, message: &Value) -> Result<(), String> {
        let stdin = self.stdin.as_mut().ok_or("server stdin is closed")?;
        writeln!(stdin, "{message}")
            .and_then(|()| stdin.flush())
            .map_err(|e| format!("cannot write to the server: {e}"))
    }

    /// Waits for the response to request `id`. Answers server requests with
    /// "method not found" and skips notifications.
    fn response(&mut self, id: u64) -> Result<Value, String> {
        loop {
            let left = self.deadline.saturating_duration_since(Instant::now());
            let line = match self.lines.recv_timeout(left) {
                Ok(line) => line,
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!(
                        "the server did not answer within {} seconds",
                        TIMEOUT.as_secs()
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err("the server closed its output before answering".into());
                }
            };
            let Ok(message) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let has_method = message.get("method").is_some();
            match message.get("id") {
                Some(other) if has_method => {
                    let reply = json!({"jsonrpc": "2.0", "id": other,
                        "error": {"code": -32601, "message": "Method not found"}});
                    self.send(&reply)?;
                }
                Some(Value::Number(n)) if n.as_u64() == Some(id) => {
                    if let Some(error) = message.get("error") {
                        return Err(format!("the server answered with an error: {error}"));
                    }
                    return message
                        .get("result")
                        .cloned()
                        .ok_or_else(|| "the server answered without a result".to_owned());
                }
                _ => {}
            }
        }
    }

    fn stderr_tail(&self) -> String {
        let bytes = self.stderr.lock().map(|b| b.clone()).unwrap_or_default();
        String::from_utf8_lossy(&bytes).trim_end().to_owned()
    }

    fn close(mut self) {
        drop(self.stdin.take());
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(command: &str, args: &[String]) -> Result<Server, String> {
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start {command:?}: {e}"))?;
    let stdout = child.stdout.take().ok_or("no server stdout")?;
    let mut stderr_pipe = child.stderr.take().ok_or("no server stderr")?;
    let (sender, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let tail = Arc::clone(&stderr);
    std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        while let Ok(n) = stderr_pipe.read(&mut buf) {
            if n == 0 {
                break;
            }
            if let Ok(mut kept) = tail.lock() {
                kept.extend_from_slice(&buf[..n]);
                let excess = kept.len().saturating_sub(STDERR_TAIL);
                kept.drain(..excess);
            }
        }
    });
    Ok(Server {
        stdin: child.stdin.take(),
        child,
        lines,
        stderr,
        deadline: Instant::now() + TIMEOUT,
    })
}

fn names(server: &mut Server) -> Result<Vec<String>, String> {
    server.send(
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "praetore-mcp-coverage", "version": env!("CARGO_PKG_VERSION")}}}),
    )?;
    server.response(1)?;
    server.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
    let mut tools = Vec::new();
    let mut cursor: Option<Value> = None;
    for page in 0..MAX_PAGES {
        let id = 2 + page as u64;
        let params = match &cursor {
            Some(cursor) => json!({ "cursor": cursor }),
            None => json!({}),
        };
        server
            .send(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": params}))?;
        let result = server.response(id)?;
        let list = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or("tools/list result has no tools array")?;
        for tool in list {
            let name = tool
                .get("name")
                .and_then(Value::as_str)
                .ok_or("a tool in tools/list has no name")?;
            tools.push(name.to_owned());
        }
        match result.get("nextCursor") {
            Some(next) if !next.is_null() => cursor = Some(next.clone()),
            _ => return Ok(tools),
        }
    }
    Err(format!(
        "tools/list still returned nextCursor after {MAX_PAGES} pages"
    ))
}

/// Starts `command`, lists its tools and closes it. On failure the error
/// includes the end of the server's stderr.
pub fn list_tools(command: &str, args: &[String]) -> Result<Vec<String>, String> {
    let mut server = start(command, args)?;
    let result = names(&mut server);
    let tail = server.stderr_tail();
    server.close();
    result.map_err(|error| {
        if tail.is_empty() {
            error
        } else {
            format!(
                "{error}\nserver stderr (end):\n{}",
                tail.lines()
                    .map(|line| praetore_core::display::escape_bounded(line, 500))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        }
    })
}
