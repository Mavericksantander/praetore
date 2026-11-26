//! `praetore-mcp wrap`: spawns the real MCP server and relays stdio.
//!
//! Two directions, each one thread, each preserving order:
//! * client→server (this process's stdin → child stdin), where `tools/call`
//!   is gated synchronously, so evaluation only delays later client lines;
//! * server→client (child stdout → this process's stdout), never parsed and
//!   never blocked by evaluation.
//!
//! Both directions write to our stdout (blocked replies and server output),
//! so whole lines are written under one mutex. The child's stderr is
//! inherited and passes straight through.

use crate::shown::Show;
use crate::{
    gate::{Evaluator, Gate, GateError, Mode, Verdict},
    proxy::{handle_client_line, oversized_line_response},
    report::{self, SessionLog, SessionMeta},
    store::Home,
    unparsed::UnparsedLine,
};
use serde_json::Value;
use std::{
    io::{self, BufRead, BufReader, Write},
    process::{Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};
use time::OffsetDateTime;

/// Maximum client line kept in memory for classification (32 MiB).
pub const MAX_CLIENT_LINE_BYTES: usize = 32 * 1024 * 1024;

pub struct WrapOptions {
    pub home: Home,
    pub name: String,
    pub mode: Mode,
    pub command: String,
    pub args: Vec<String>,
    /// Write the session report under `DIR/reports/` when the session ends.
    pub report: bool,
}

/// Evaluator that fails every call when the gate could not be loaded, so
/// enforce mode fails closed while non-tools traffic keeps working.
struct GateOrError(Result<Gate, String>);

impl Evaluator for GateOrError {
    fn evaluate(&mut self, server: &str, params: &Value) -> Result<Verdict, GateError> {
        match &mut self.0 {
            Ok(gate) => gate.evaluate(server, params),
            Err(error) => Err(GateError::Failed(format!(
                "praetore-mcp is not ready: {error}"
            ))),
        }
    }

    fn record_unparsed(&mut self, server: &str, line: &UnparsedLine) -> Result<Verdict, GateError> {
        match &mut self.0 {
            Ok(gate) => gate.record_unparsed(server, line),
            Err(error) => Err(GateError::Failed(format!(
                "praetore-mcp is not ready: {error}"
            ))),
        }
    }
}

/// Records which receipts this session journaled, for the session report.
/// It only reads the verdict; the verdict itself is returned unchanged.
struct Recording<E> {
    inner: E,
    log: SessionLog,
}

impl<E: Evaluator> Evaluator for Recording<E> {
    fn evaluate(&mut self, server: &str, params: &Value) -> Result<Verdict, GateError> {
        let verdict = self.inner.evaluate(server, params)?;
        if verdict.journaled.is_ok() {
            self.log.record(&verdict.evidence_id);
        }
        Ok(verdict)
    }

    fn record_unparsed(&mut self, server: &str, line: &UnparsedLine) -> Result<Verdict, GateError> {
        let verdict = self.inner.record_unparsed(server, line)?;
        if verdict.journaled.is_ok() {
            self.log.record(&verdict.evidence_id);
        }
        Ok(verdict)
    }
}

/// Why `wrap` stops waiting.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
enum End {
    /// The server closed its stdout.
    ServerClosed,
    /// SIGINT or SIGTERM arrived.
    Signal(i32),
}

/// With the session report on, SIGINT and SIGTERM end the session in
/// order so its report is written: the handler writes the signal number to
/// a pipe and a thread turns it into an [`End::Signal`]. After the report,
/// `wrap` ends by that same signal ([`die_by`]), as it did without a
/// handler. A second signal ends `wrap` at once, without the report.
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod signals {
    use super::End;
    use std::{
        fs::File,
        io::Read,
        os::fd::FromRawFd,
        sync::{
            atomic::{AtomicI32, AtomicU32, Ordering},
            mpsc::Sender,
        },
        thread,
    };

    static PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);
    static RECEIVED: AtomicU32 = AtomicU32::new(0);
    /// The first signal received, 0 for none. Set in the handler, so a
    /// signal is seen even when its byte is still in the pipe.
    static FIRST: AtomicI32 = AtomicI32::new(0);

    #[cfg(target_os = "linux")]
    fn errno_location() -> *mut libc::c_int {
        // SAFETY: returns this thread's errno; no arguments.
        unsafe { libc::__errno_location() }
    }

    #[cfg(target_os = "macos")]
    fn errno_location() -> *mut libc::c_int {
        // SAFETY: returns this thread's errno; no arguments.
        unsafe { libc::__error() }
    }

    extern "C" fn on_signal(signal: libc::c_int) {
        // The interrupted code may be about to read errno: keep it.
        let errno = errno_location();
        // SAFETY: errno_location points at this thread's errno.
        let saved = unsafe { *errno };
        if RECEIVED.fetch_add(1, Ordering::SeqCst) > 0 {
            // A second signal: stop now, without the report. `signal` and
            // `raise` are async-signal-safe; the raised signal is delivered
            // with the default action when this handler returns.
            // SAFETY: plain calls with no pointers.
            unsafe {
                libc::signal(signal, libc::SIG_DFL);
                libc::raise(signal);
            }
        } else {
            FIRST.store(signal, Ordering::SeqCst);
            let fd = PIPE_WRITE.load(Ordering::Relaxed);
            if fd >= 0 {
                let byte = signal as u8;
                // SAFETY: `write` is async-signal-safe; `byte` lives for the
                // call.
                unsafe {
                    libc::write(fd, (&raw const byte).cast(), 1);
                }
            }
        }
        // SAFETY: as above.
        unsafe { *errno = saved };
    }

    /// The first SIGINT or SIGTERM the handler received, if any.
    pub fn first() -> Option<i32> {
        match FIRST.load(Ordering::SeqCst) {
            0 => None,
            signal => Some(signal),
        }
    }

    /// Ends the process by `signal` with its default action, so the parent
    /// sees `wrap` terminated by that signal.
    pub fn die_by(signal: i32) {
        // SAFETY: plain calls with no pointers.
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
            libc::raise(signal);
        }
    }

    /// Whether `signal` is ignored in this process (inherited SIG_IGN, for
    /// example a background job). An ignored signal keeps being ignored.
    fn ignored(signal: libc::c_int) -> bool {
        // SAFETY: `old` is fully written by `sigaction` when it returns 0; a
        // null new action only reads the current one.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            libc::sigaction(signal, std::ptr::null(), &raw mut old) == 0
                && old.sa_sigaction == libc::SIG_IGN
        }
    }

    /// Installs the handlers. If the pipe cannot be created the default
    /// actions stay in place (the session ends without a report).
    pub fn install(events: Sender<End>) {
        let mut fds = [-1; 2];
        // SAFETY: `pipe` fills the two descriptors of the array it is given.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return;
        }
        PIPE_WRITE.store(fds[1], Ordering::Relaxed);
        // SAFETY: `fds[0]` is a descriptor this function just created and
        // nothing else owns.
        let mut reader = unsafe { File::from_raw_fd(fds[0]) };
        thread::spawn(move || {
            let mut byte = [0u8; 1];
            while reader.read_exact(&mut byte).is_ok() {
                if events.send(End::Signal(i32::from(byte[0]))).is_err() {
                    break;
                }
            }
        });
        for signal in [libc::SIGINT, libc::SIGTERM] {
            if ignored(signal) {
                continue;
            }
            // SAFETY: `action` is fully initialized before `sigaction` reads
            // it, and the handler only calls async-signal-safe functions.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
                action.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&raw mut action.sa_mask);
                libc::sigaction(signal, &raw const action, std::ptr::null_mut());
            }
        }
    }

    /// Sends `signal` to the server.
    pub fn forward(pid: u32, signal: i32) {
        if let Ok(pid) = libc::pid_t::try_from(pid) {
            // SAFETY: `kill` takes no pointers.
            unsafe {
                libc::kill(pid, signal);
            }
        }
    }
}

/// How often `wrap` checks whether the server exited while it waits for a
/// server that closed its stdout.
const EXIT_POLL: Duration = Duration::from_millis(50);

/// Whether the server exits within `limit`.
fn exits_within(child: &mut std::process::Child, limit: Duration) -> bool {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if !matches!(child.try_wait(), Ok(None)) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Passes `signal` on to the server (Linux and macOS).
fn forward_signal(child: &std::process::Child, signal: i32) {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    signals::forward(child.id(), signal);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = (child, signal);
}

/// Time the server gets to end by itself after a signal before the signal
/// is forwarded to it, and then before it is killed.
const SIGNAL_GRACE: [Duration; 2] = [Duration::from_millis(300), Duration::from_secs(2)];

/// Windows-style command lookup: a bare name (no separator, no extension)
/// is searched in `path` with each `pathext` extension, so `npx` finds
/// `npx.cmd`. `Command::new` alone only finds `.exe`. Used on Windows;
/// platform-independent so it can be tested anywhere.
pub fn resolve_command(
    command: &str,
    path: Option<&std::ffi::OsStr>,
    pathext: Option<&std::ffi::OsStr>,
) -> Option<std::path::PathBuf> {
    if command.contains(['/', '\\']) || std::path::Path::new(command).extension().is_some() {
        return None;
    }
    let pathext = pathext
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or(".COM;.EXE;.BAT;.CMD")
        .to_owned();
    for dir in std::env::split_paths(path?) {
        for ext in pathext.split(';').filter(|ext| !ext.is_empty()) {
            let candidate = dir.join(format!("{command}{}", ext.to_ascii_lowercase()));
            if candidate.is_file() {
                return Some(candidate);
            }
            let candidate = dir.join(format!("{command}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

pub enum LineRead {
    Eof,
    Line,
    /// The line exceeded the limit; `buf` holds the first `limit` bytes and
    /// the rest of the line is still unread.
    TooLong,
}

/// Reads one line (including `\n`) into `buf`, stopping at `limit` bytes.
pub fn read_line_limited<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    limit: usize,
) -> io::Result<LineRead> {
    buf.clear();
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            return Ok(if buf.is_empty() {
                LineRead::Eof
            } else {
                LineRead::Line
            });
        }
        let room = limit - buf.len();
        let (take, done) = match available.iter().position(|b| *b == b'\n') {
            Some(index) if index < room => (index + 1, true),
            _ => (available.len().min(room), false),
        };
        buf.extend_from_slice(&available[..take]);
        reader.consume(take);
        if done {
            return Ok(LineRead::Line);
        }
        if buf.len() >= limit {
            return Ok(LineRead::TooLong);
        }
    }
}

/// Copies (or discards, when `sink` is `None`) the rest of the current line.
fn drain_line<R: BufRead>(reader: &mut R, mut sink: Option<&mut dyn Write>) -> io::Result<()> {
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(());
        }
        let (take, done) = match available.iter().position(|b| *b == b'\n') {
            Some(index) => (index + 1, true),
            None => (available.len(), false),
        };
        if let Some(sink) = sink.as_mut() {
            sink.write_all(&available[..take])?;
        }
        reader.consume(take);
        if done {
            return Ok(());
        }
    }
}

fn write_locked(out: &Mutex<io::Stdout>, bytes: &[u8]) -> io::Result<()> {
    let stdout = out.lock().map_err(|_| io::Error::other("stdout lock"))?;
    let mut stdout = stdout.lock();
    stdout.write_all(bytes)?;
    stdout.flush()
}

/// Commands that usually run the server in another mount namespace or on
/// another host. Heuristic, for a startup warning only.
const OTHER_NAMESPACE_LAUNCHERS: &[&str] = &[
    "docker",
    "podman",
    "nerdctl",
    "ssh",
    "chroot",
    "lima",
    "limactl",
    "orb",
    "orbctl",
    "kubectl",
    "multipass",
    "wsl",
    "flatpak",
    "firejail",
    "bwrap",
    "systemd-nspawn",
    "lxc",
    "incus",
    "distrobox",
    "toolbox",
    "nsenter",
    "unshare",
];

/// The launcher in `command` (or behind `env`/`sudo`/`doas`) if it is one of
/// [`OTHER_NAMESPACE_LAUNCHERS`].
pub fn other_namespace_launcher(command: &str, args: &[String]) -> Option<String> {
    let base = |word: &str| {
        let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
        name.strip_suffix(".exe").unwrap_or(name).to_owned()
    };
    let mut words = std::iter::once(command).chain(args.iter().map(String::as_str));
    while let Some(word) = words.next() {
        let name = base(word);
        if OTHER_NAMESPACE_LAUNCHERS.contains(&name.as_str()) {
            return Some(name);
        }
        if !matches!(name.as_str(), "env" | "sudo" | "doas") {
            return None;
        }
        // Skip the wrapper's options and VAR=value assignments.
        for next in words.by_ref() {
            if !(next.starts_with('-') || next.contains('=')) {
                let name = base(next);
                return OTHER_NAMESPACE_LAUNCHERS
                    .contains(&name.as_str())
                    .then_some(name);
            }
        }
    }
    None
}

pub fn run(options: WrapOptions) -> i32 {
    let started_at = OffsetDateTime::now_utc();
    let gate = Gate::load(&options.home, options.mode);
    // Without a gate no receipt can be written, so there is nothing to
    // observe: both modes refuse every tools/call (fail closed) and gate the
    // rest of the traffic as enforce does. Other MCP traffic still flows, so
    // the client shows the refusal instead of a dead server.
    let mode = match &gate {
        Ok(_) => options.mode,
        Err(error) => {
            eprintln!(
                "praetore-mcp: ERROR {error}\npraetore-mcp: {} mode: every tools/call will be REFUSED until this is fixed",
                options.mode.as_str()
            );
            Mode::Enforce
        }
    };
    if gate.as_ref().is_ok_and(Gate::has_path_rules)
        && let Some(launcher) = other_namespace_launcher(&options.command, &options.args)
    {
        eprintln!(
            "praetore-mcp: WARNING the server is started through {launcher:?}, which usually runs it in another mount namespace or on another host. Path rules are checked against THIS machine's filesystem; the server may resolve the same path to a different file. This setup is not supported by the path check (defense in depth only)."
        );
    }
    let log = SessionLog::default();
    let mut evaluator = Recording {
        inner: GateOrError(gate),
        log: log.clone(),
    };

    #[cfg(windows)]
    let program = resolve_command(
        &options.command,
        std::env::var_os("PATH").as_deref(),
        std::env::var_os("PATHEXT").as_deref(),
    )
    .unwrap_or_else(|| std::path::PathBuf::from(&options.command));
    #[cfg(not(windows))]
    let program = std::path::PathBuf::from(&options.command);
    let mut child = match Command::new(&program)
        .args(&options.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            eprintln!(
                "praetore-mcp: cannot start MCP server {:?}: {error}",
                options.command
            );
            return 127;
        }
    };
    let (Some(mut child_stdin), Some(child_stdout)) = (child.stdin.take(), child.stdout.take())
    else {
        eprintln!("praetore-mcp: child stdio unavailable");
        let _ = child.kill();
        return 1;
    };

    let stdout = Arc::new(Mutex::new(io::stdout()));

    let (events, ended) = mpsc::channel();
    let server_to_client = {
        let stdout = Arc::clone(&stdout);
        let events = events.clone();
        thread::spawn(move || {
            let mut reader = BufReader::new(child_stdout);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                match reader.read_until(b'\n', &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if write_locked(&stdout, &buf).is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = events.send(End::ServerClosed);
        })
    };
    // Without the report, SIGINT and SIGTERM keep their default action:
    // `wrap` ends at once, as in 0.3.5.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if options.report {
        signals::install(events);
    } else {
        drop(events);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    drop(events);

    let name = options.name.clone();
    let client_stdout = Arc::clone(&stdout);
    thread::spawn(move || {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        let mut buf = Vec::new();
        loop {
            match read_line_limited(&mut reader, &mut buf, MAX_CLIENT_LINE_BYTES) {
                Ok(LineRead::Eof) | Err(_) => break,
                Ok(LineRead::TooLong) => {
                    // Too long to parse, so it can be neither evaluated nor
                    // checked for a safety* tool name (G7): refused in both
                    // modes, never forwarded unchecked. The client still gets
                    // a JSON-RPC error, or it would wait until its own timeout.
                    // Drain first: the rest of the line may still be filling
                    // the pipe, and a reply written before that read can stall
                    // both sides.
                    let reply = oversized_line_response(&buf);
                    eprintln!(
                        "praetore-mcp: REFUSED client message over {MAX_CLIENT_LINE_BYTES} bytes ({}); it cannot be checked",
                        mode.as_str()
                    );
                    if drain_line(&mut reader, None).is_err() {
                        break;
                    }
                    if write_locked(&client_stdout, &reply).is_err() {
                        break;
                    }
                }
                Ok(LineRead::Line) => {
                    let outcome = handle_client_line(&buf, mode, &name, &mut evaluator);
                    for warning in &outcome.warnings {
                        eprintln!("{warning}");
                    }
                    if let Some(reply) = &outcome.to_client
                        && write_locked(&client_stdout, reply).is_err()
                    {
                        break;
                    }
                    if let Some(bytes) = &outcome.to_server
                        && child_stdin
                            .write_all(bytes)
                            .and_then(|()| child_stdin.flush())
                            .is_err()
                    {
                        break;
                    }
                }
            }
        }
        // Dropping child_stdin closes the server's stdin (client went away).
    });

    let mut by_signal = None;
    match ended.recv() {
        Ok(End::Signal(signal)) => {
            by_signal = Some(signal);
            // The client is going away. Give the server a moment to end by
            // itself (a terminal's Ctrl-C reaches it too), then pass the
            // signal on, then stop waiting for it.
            if !matches!(ended.recv_timeout(SIGNAL_GRACE[0]), Ok(End::ServerClosed)) {
                forward_signal(&child, signal);
                if !matches!(ended.recv_timeout(SIGNAL_GRACE[1]), Ok(End::ServerClosed)) {
                    let _ = child.kill();
                }
            }
        }
        Ok(End::ServerClosed) | Err(_) => {
            let _ = server_to_client.join();
            // The server closed its stdout but may still be running. Wait
            // for it while listening for a signal, which then ends it the
            // same way as above (its stdout is already closed, so the end
            // is seen by its exit).
            loop {
                if !matches!(child.try_wait(), Ok(None)) {
                    break;
                }
                match ended.recv_timeout(EXIT_POLL) {
                    Ok(End::Signal(signal)) => {
                        by_signal = Some(signal);
                        if !exits_within(&mut child, SIGNAL_GRACE[0]) {
                            forward_signal(&child, signal);
                            if !exits_within(&mut child, SIGNAL_GRACE[1]) {
                                let _ = child.kill();
                            }
                        }
                        break;
                    }
                    Ok(End::ServerClosed) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                    // No handler (no report): nothing to listen for.
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        }
    }
    let status = child.wait();
    let _ = stdout.lock().map(|out| out.lock().flush());
    let code = match status {
        Ok(status) => status.code().unwrap_or(1),
        Err(_) => 1,
    };
    if options.report {
        write_report(&options, started_at, &log);
    }
    // A signal that came while waiting for the server or writing the
    // report still ends `wrap` by that signal.
    while let Ok(event) = ended.try_recv() {
        if let End::Signal(signal) = event {
            by_signal.get_or_insert(signal);
        }
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(signal) = signals::first() {
        by_signal.get_or_insert(signal);
    }
    // Ended by SIGINT or SIGTERM: after the report, end by that signal, so
    // the parent sees what it saw before the report existed.
    if let Some(signal) = by_signal {
        let _ = io::stderr().flush();
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        signals::die_by(signal);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let _ = signal;
    }
    code
}

/// Where to see and download the report. The dashboard writes nothing
/// under the home, so whether one is running (and on which port) cannot be
/// known without connecting to a local port: the hint names the command
/// that starts it with `--port 8787` written out, the page of the session
/// on that port, and says to open the same page on another port.
pub fn dashboard_hint(home: &crate::store::Home, session_id: &str) -> String {
    let port = crate::dashboard::DEFAULT_PORT;
    format!(
        "to see and download it, run {} dashboard --dir {} --port {port} and open http://127.0.0.1:{port}/#/sessions/{session_id} (a dashboard on another port: #/sessions/{session_id} there)",
        crate::commands::program(),
        crate::commands::dir(&home.root),
    )
}

/// Writes the session report. Whatever happens here goes to stderr and
/// nowhere else: the exit code and every decision already made stay as
/// they are.
fn write_report(options: &WrapOptions, started_at: OffsetDateTime, log: &SessionLog) {
    let id = report::new_session_id();
    let meta = SessionMeta {
        id: id.clone(),
        server: options.name.clone(),
        mode: options.mode.as_str().to_owned(),
        started_at,
        ended_at: OffsetDateTime::now_utc(),
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        report::close_session(&options.home, meta, log)
    }));
    match outcome {
        Ok(Ok(Some(generated))) => {
            eprintln!(
                "praetore-mcp: session report: {}{}",
                generated.pdf.shown(),
                if generated.verify_passed {
                    ""
                } else {
                    " (verify FAILED; see the report)"
                }
            );
            if let Some(summary) = &generated.verify_summary {
                eprintln!("praetore-mcp: {summary}");
            }
            eprintln!("praetore-mcp: {}", dashboard_hint(&options.home, &id));
        }
        Ok(Ok(None)) => {}
        Ok(Err(error)) => eprintln!("praetore-mcp: session report not written: {error}"),
        Err(_) => eprintln!("praetore-mcp: session report not written: internal error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_namespace_launchers_are_recognised() {
        let args = |list: &[&str]| list.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
        for (command, rest, expected) in [
            ("docker", &["run", "-i", "img"][..], Some("docker")),
            ("/usr/local/bin/podman", &["run"][..], Some("podman")),
            ("ssh", &["host", "server"][..], Some("ssh")),
            ("env", &["FOO=1", "-i", "docker", "run"][..], Some("docker")),
            (
                "sudo",
                &["-E", "chroot", "/jail", "srv"][..],
                Some("chroot"),
            ),
            ("C:\\bin\\docker.exe", &[][..], Some("docker")),
            (
                "npx",
                &["-y", "@modelcontextprotocol/server-filesystem"][..],
                None,
            ),
            ("env", &["node", "docker.js"][..], None),
            ("/usr/bin/python3", &["ssh_server.py"][..], None),
        ] {
            assert_eq!(
                other_namespace_launcher(command, &args(rest)).as_deref(),
                expected,
                "{command} {rest:?}"
            );
        }
    }

    #[test]
    fn resolves_bare_commands_through_pathext() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("npx.cmd"), "").unwrap();
        let path = std::env::join_paths([temp.path()]).unwrap();
        let found = resolve_command("npx", Some(&path), Some(".EXE;.CMD".as_ref())).unwrap();
        assert_eq!(found, temp.path().join("npx.cmd"));
        assert!(resolve_command("npx.cmd", Some(&path), None).is_none());
        assert!(resolve_command("dir/npx", Some(&path), None).is_none());
        assert!(resolve_command("missing", Some(&path), None).is_none());
    }

    #[test]
    fn limited_reader_splits_lines_and_flags_overflow() {
        let data = b"abc\nlonglonglong\nz";
        let mut reader = BufReader::with_capacity(4, &data[..]);
        let mut buf = Vec::new();
        assert!(matches!(
            read_line_limited(&mut reader, &mut buf, 8).unwrap(),
            LineRead::Line
        ));
        assert_eq!(buf, b"abc\n");
        assert!(matches!(
            read_line_limited(&mut reader, &mut buf, 8).unwrap(),
            LineRead::TooLong
        ));
        assert_eq!(buf, b"longlong");
        let mut rest = Vec::new();
        drain_line(&mut reader, Some(&mut rest)).unwrap();
        assert_eq!(rest, b"long\n");
        assert!(matches!(
            read_line_limited(&mut reader, &mut buf, 8).unwrap(),
            LineRead::Line
        ));
        assert_eq!(buf, b"z");
        assert!(matches!(
            read_line_limited(&mut reader, &mut buf, 8).unwrap(),
            LineRead::Eof
        ));
    }
}
