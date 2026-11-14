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
    thread::JoinHandle,
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
/// How long a server has to exit after its stdin is closed before it is
/// killed.
const EXIT_GRACE: Duration = Duration::from_secs(2);
/// How long, once the server has exited, the reader threads have to reach
/// the end of its stdout and stderr. A process the server started can keep
/// those pipes open after the server exits; the threads are then left
/// running and what they copied so far is used.
const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// A thread copying one of the server's pipes. `done` receives a message
/// (or disconnects) when the thread is about to return.
struct Reader {
    handle: JoinHandle<()>,
    done: Receiver<()>,
}

impl Reader {
    fn spawn(body: impl FnOnce() + Send + 'static) -> Self {
        let (signal, done) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            body();
            let _ = signal.send(());
        });
        Self { handle, done }
    }

    /// Joins the thread once it has reached the end of its pipe, waiting at
    /// most until `until`. Returns whether it was joined.
    fn join_until(self, until: Instant) -> bool {
        let left = until.saturating_duration_since(Instant::now());
        match self.done.recv_timeout(left) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                let _ = self.handle.join();
                true
            }
            Err(RecvTimeoutError::Timeout) => false,
        }
    }
}

struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    stdout_reader: Reader,
    stderr_reader: Reader,
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

    /// Closes stdin, waits for the server to exit (killing it after
    /// [`EXIT_GRACE`]), joins both reader threads, and only then returns the
    /// end of the server's stderr, so nothing it wrote before exiting is
    /// missed.
    fn close(mut self) -> String {
        drop(self.stdin.take());
        let until = Instant::now() + EXIT_GRACE;
        let mut exited = false;
        while Instant::now() < until {
            if let Ok(Some(_)) = self.child.try_wait() {
                exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if !exited {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let drained = Instant::now() + DRAIN_GRACE;
        self.stdout_reader.join_until(drained);
        self.stderr_reader.join_until(drained);
        let bytes = self.stderr.lock().map(|b| b.clone()).unwrap_or_default();
        String::from_utf8_lossy(&bytes).trim_end().to_owned()
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
    let stdout_reader = Reader::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let tail = Arc::clone(&stderr);
    let stderr_reader = Reader::spawn(move || {
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
        stdout_reader,
        stderr_reader,
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
    let tail = server.close();
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
