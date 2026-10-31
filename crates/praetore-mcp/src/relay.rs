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

use crate::{
    gate::{Evaluator, Gate, Mode, Verdict},
    proxy::handle_client_line,
    store::Home,
};
use serde_json::Value;
use std::{
    io::{self, BufRead, BufReader, Write},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
};

/// Maximum client line kept in memory for classification (32 MiB).
pub const MAX_CLIENT_LINE_BYTES: usize = 32 * 1024 * 1024;

pub struct WrapOptions {
    pub home: Home,
    pub name: String,
    pub mode: Mode,
    pub command: String,
    pub args: Vec<String>,
}

/// Evaluator that fails every call when the gate could not be loaded, so
/// enforce mode fails closed while non-tools traffic keeps working.
struct GateOrError(Result<Gate, String>);

impl Evaluator for GateOrError {
    fn evaluate(&mut self, server: &str, params: &Value) -> Result<Verdict, String> {
        match &mut self.0 {
            Ok(gate) => gate.evaluate(server, params),
            Err(error) => Err(format!("praetore-mcp is not ready: {error}")),
        }
    }
}

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
    let mut evaluator = GateOrError(gate);

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

    let server_to_client = {
        let stdout = Arc::clone(&stdout);
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
        })
    };

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
                    let result = match mode {
                        Mode::Observe => {
                            eprintln!(
                                "praetore-mcp: WARNING client message over {MAX_CLIENT_LINE_BYTES} bytes forwarded unchecked (observe mode)"
                            );
                            child_stdin
                                .write_all(&buf)
                                .and_then(|()| drain_line(&mut reader, Some(&mut child_stdin)))
                                .and_then(|()| child_stdin.flush())
                        }
                        Mode::Enforce => {
                            eprintln!(
                                "praetore-mcp: REFUSED client message over {MAX_CLIENT_LINE_BYTES} bytes (enforce mode)"
                            );
                            drain_line(&mut reader, None)
                        }
                    };
                    if result.is_err() {
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

    let _ = server_to_client.join();
    let status = child.wait();
    let _ = stdout.lock().map(|out| out.lock().flush());
    match status {
        Ok(status) => status.code().unwrap_or(1),
        Err(_) => 1,
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
