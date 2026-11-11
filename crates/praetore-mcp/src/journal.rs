//! Hash-linked receipts journal.
//!
//! Each line is `{"seq":N,"prev":"<64 hex>","evidence":{...}}`, the line
//! format of `praetore_core::journal_chain`, linked with the same function
//! ([`receipt_link`]): `seq` counts from 0 across all daily files, and
//! `prev` is the link of the previous entry (64 zeros for the first one).
//! A deleted, duplicated or reordered entry breaks `seq` or `prev`, and
//! `verify` reports it. Removing entries at the end of the journal is only
//! detected against a head kept somewhere else (`verify --expected-head`).
//!
//! Lines written before the chain existed (a bare evidence document) are
//! read as unchained entries. They may only come before the first chained
//! entry, and `verify` counts them apart.

use praetore_core::{
    Evidence,
    journal_chain::{ChainLink, receipt_link},
};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::{
    collections::HashSet,
    fs,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

/// Largest line read back from the end of the journal. A receipt stays
/// below the 64 KiB evidence limit; the chain fields add less than 200 bytes.
const MAX_TAIL_BYTES: u64 = 256 * 1024;
/// Lock file next to the daily files (not `*.jsonl`, so never read as one).
const LOCK_FILE: &str = ".journal.lock";
/// How long an append waits for another wrapper to finish one entry.
/// An fsync of a receipt is far shorter; a holder that does not release
/// the lock by then is treated as stuck and the wait is rejected.
const LOCK_WAIT: Duration = Duration::from_secs(5);
/// Pause between non-blocking attempts while `LOCK_WAIT` has not elapsed.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const LOCK_POLL: Duration = Duration::from_millis(20);

/// Position of a chained entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub seq: u64,
    pub prev: ChainLink,
}

impl Position {
    pub const FIRST: Self = Self {
        seq: 0,
        prev: ChainLink::GENESIS,
    };

    /// The position right after the entry at `self` holding `evidence`.
    pub fn after(&self, evidence: &Evidence) -> Result<Self, String> {
        let seq = self
            .seq
            .checked_add(1)
            .ok_or("journal sequence number overflow")?;
        let prev = receipt_link(self.seq, &self.prev, evidence).map_err(|e| e.to_string())?;
        Ok(Self { seq, prev })
    }
}

/// One journal line: a chained entry, or an unchained line written before
/// the chain existed.
#[derive(Debug)]
pub struct Entry {
    pub position: Option<Position>,
    pub evidence: Evidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainedLine<'a> {
    seq: u64,
    prev: &'a str,
    #[serde(borrow)]
    evidence: &'a RawValue,
}

/// Parses one journal line (without its newline).
pub fn parse_line(text: &str) -> Result<Entry, String> {
    // A chained line is an object with an `evidence` member; a bare evidence
    // document has none (its own schema rejects unknown fields).
    let probe: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    if probe.get("evidence").is_none() {
        let evidence = Evidence::from_json(text).map_err(|e| format!("{}: {e}", e.code()))?;
        return Ok(Entry {
            position: None,
            evidence,
        });
    }
    // Struct deserialization rejects duplicate and unknown members.
    let line: ChainedLine<'_> =
        serde_json::from_str(text).map_err(|e| format!("malformed chained line: {e}"))?;
    let prev = ChainLink::from_hex(line.prev).ok_or("prev is not 64 lowercase hex characters")?;
    let evidence =
        Evidence::from_json(line.evidence.get()).map_err(|e| format!("{}: {e}", e.code()))?;
    Ok(Entry {
        position: Some(Position {
            seq: line.seq,
            prev,
        }),
        evidence,
    })
}

/// The line written for `evidence_json` (canonical evidence) at `position`,
/// newline included.
pub fn chained_line(position: &Position, evidence_json: &str) -> String {
    format!(
        "{{\"seq\":{},\"prev\":\"{}\",\"evidence\":{evidence_json}}}\n",
        position.seq, position.prev
    )
}

/// Daily files (`*.jsonl`) in `dir`, in name (date) order.
pub fn journal_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
            .collect(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(format!("cannot read {}: {error}", dir.display())),
    };
    files.sort();
    Ok(files)
}

/// Last line of `path` without its newline, `None` for an empty file.
/// A last line without a newline (interrupted write) is an error: nothing
/// is appended after it until someone looks at the journal.
fn last_line(path: &Path) -> Result<Option<String>, String> {
    let fail = |e: io::Error| format!("cannot read {}: {e}", path.display());
    let mut file = fs::File::open(path).map_err(fail)?;
    let len = file.metadata().map_err(fail)?.len();
    if len == 0 {
        return Ok(None);
    }
    let start = len.saturating_sub(MAX_TAIL_BYTES);
    file.seek(SeekFrom::Start(start)).map_err(fail)?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail).map_err(fail)?;
    let Some(body) = tail.strip_suffix(b"\n") else {
        return Err(format!(
            "{} does not end with a newline (interrupted write?); run `praetore-mcp verify`",
            path.display()
        ));
    };
    let line = match body.iter().rposition(|&b| b == b'\n') {
        Some(index) => &body[index + 1..],
        None if start == 0 => body,
        None => return Err(format!("{}: last line is too long", path.display())),
    };
    String::from_utf8(line.to_vec())
        .map(Some)
        .map_err(|_| format!("{}: last line is not UTF-8", path.display()))
}

/// Where the next entry goes: the newest daily file that is not older than
/// `today` (so file order stays chain order if the clock goes back), and the
/// position after the last entry of the journal.
pub fn next_append(dir: &Path, today: PathBuf) -> Result<(PathBuf, Position), String> {
    let files = journal_files(dir)?;
    let path = match files.last() {
        Some(newest) if *newest > today => newest.clone(),
        _ => today,
    };
    for file in files.iter().rev() {
        let Some(text) = last_line(file)? else {
            continue;
        };
        let entry = parse_line(&text).map_err(|e| {
            format!(
                "last entry of {} is unreadable ({e}); run `praetore-mcp verify`",
                file.display()
            )
        })?;
        return Ok(match entry.position {
            Some(position) => (path, position.after(&entry.evidence)?),
            // Only unchained lines so far: the chain starts here.
            None => (path, Position::FIRST),
        });
    }
    Ok((path, Position::FIRST))
}

/// Exclusive lock over the journal while one entry is appended, so that
/// concurrent wrappers (one per server) never write two entries at the same
/// position. Released when dropped (and by the kernel if the process dies).
/// On Linux and macOS the wait is bounded by [`LOCK_WAIT`]: if the holder
/// does not release the lock in time, acquisition fails and the append is
/// rejected.
pub struct JournalLock {
    /// Holding the descriptor holds the lock.
    _file: fs::File,
}

impl JournalLock {
    pub fn acquire(dir: &Path) -> Result<Self, String> {
        Self::acquire_within(dir, LOCK_WAIT)
    }

    fn acquire_within(dir: &Path, wait: Duration) -> Result<Self, String> {
        let path = dir.join(LOCK_FILE);
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(nofollow_flag());
        }
        let file = options
            .open(&path)
            .map_err(|e| format!("cannot open lock {}: {e}", path.display()))?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        lock_exclusive(&file, wait)
            .map_err(|error| format!("cannot lock {}: {error}", path.display()))?;
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let _ = wait;
        Ok(Self { _file: file })
    }
}

/// `LOCK_EX` with a deadline. `flock` itself does not take a timeout, so this
/// retries `LOCK_NB` until `wait` elapses and then rejects the wait.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn lock_exclusive(file: &fs::File, wait: Duration) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::time::Instant;
    let fd = file.as_raw_fd();
    let deadline = Instant::now() + wait;
    loop {
        // SAFETY: `flock` on a descriptor this function owns; no memory is
        // passed to the kernel. `LOCK_NB` returns instead of waiting.
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted && error.kind() != io::ErrorKind::WouldBlock {
            return Err(error);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "timed out waiting {}ms for the journal lock",
                    wait.as_millis()
                ),
            ));
        }
        std::thread::sleep(LOCK_POLL.min(deadline - now));
    }
}

/// `O_NOFOLLOW` where `libc` is available: opening a symlink fails.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn nofollow_flag() -> i32 {
    libc::O_NOFOLLOW
}

/// Other Unix targets: the symlink checks before opening still apply.
#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
pub fn nofollow_flag() -> i32 {
    0
}

/// Checks the order of the entries of a whole journal, in file order.
#[derive(Default)]
pub struct ChainCheck {
    /// Position expected for the next chained entry; `None` before the
    /// first one and after an entry whose link could not be computed.
    expected: Option<Position>,
    started: bool,
    seen: HashSet<Uuid>,
    pub chained: u64,
    pub unchained: u64,
    head: Option<Position>,
}

impl ChainCheck {
    /// Records one parsed entry. Returns the problem, if any.
    pub fn push(&mut self, entry: &Entry) -> Option<String> {
        let mut problem = None;
        if !self.seen.insert(entry.evidence.evidence_id) {
            problem = Some(format!(
                "duplicate evidence_id {}",
                entry.evidence.evidence_id
            ));
        }
        let Some(position) = entry.position else {
            self.unchained += 1;
            if self.started {
                return problem.or(Some("unchained line after the chain started".into()));
            }
            return problem;
        };
        self.chained += 1;
        let order = if !self.started {
            (position != Position::FIRST).then(|| {
                format!(
                    "chain starts at seq {} instead of 0: earlier entries are missing",
                    position.seq
                )
            })
        } else {
            match self.expected {
                Some(expected) if expected != position => Some(format!(
                    "seq {} / prev do not follow the previous entry (expected seq {}): an entry was removed, duplicated or reordered",
                    position.seq, expected.seq
                )),
                _ => None,
            }
        };
        problem = problem.or(order);
        self.started = true;
        self.expected = position.after(&entry.evidence).ok();
        self.head = self.expected;
        problem
    }

    /// Records a chained-looking line that could not be parsed: the next
    /// entry cannot be checked against it.
    pub fn push_unreadable(&mut self) {
        self.started = true;
        self.expected = None;
        self.head = None;
    }

    /// Position after the last chained entry: the next `seq` (the last
    /// entry's `seq` + 1, which is not the number of entries present when
    /// some were removed; see `chained`) and the link to keep somewhere else
    /// and compare later. `None` if the last entry could not
    /// be linked or there is no chained entry.
    pub fn head(&self) -> Option<Position> {
        self.head
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn journal_lock_acquires_immediately_when_free() {
        let dir = tempfile::tempdir().unwrap();
        let started = Instant::now();
        let lock = JournalLock::acquire_within(dir.path(), Duration::from_secs(5)).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a free lock waited {:?}",
            started.elapsed()
        );
        drop(lock);
        JournalLock::acquire(dir.path()).unwrap();
    }

    /// Another process holds the lock. `flock` is per process on macOS, so a
    /// second acquire in this process would not wait there; a child process
    /// does, on both macOS and Linux.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn journal_lock_times_out_while_another_process_holds_it() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join(LOCK_FILE);
        let child = std::process::Command::new("python3")
            .arg("-c")
            .arg(
                "import fcntl, os, sys, time\n\
                 fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\n\
                 fcntl.flock(fd, fcntl.LOCK_EX)\n\
                 print('held', flush=True)\n\
                 time.sleep(30)\n",
            )
            .arg(&lock_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("python3 is required to hold the journal lock");
        struct KillOnDrop(Option<std::process::Child>);
        impl Drop for KillOnDrop {
            fn drop(&mut self) {
                if let Some(child) = self.0.as_mut() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        let mut holder = KillOnDrop(Some(child));

        let stdout = holder.0.as_mut().unwrap().stdout.take().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stdout);
            let _ = std::io::BufRead::read_line(&mut reader, &mut line);
            let _ = ready_tx.send(line);
        });
        let ready = ready_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_default();
        assert_eq!(
            ready.trim(),
            "held",
            "holder did not take the lock: {ready:?}"
        );

        let dir_path = dir.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = Instant::now();
            let result = JournalLock::acquire_within(&dir_path, Duration::from_millis(200));
            let _ = tx.send((result.map(|_| ()), started.elapsed()));
        });
        let (result, elapsed) = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the lock wait was not rejected");
        let message = result.expect_err("acquired a lock another process holds");
        assert!(message.contains("timed out"), "{message}");
        assert!(
            elapsed >= Duration::from_millis(200),
            "wait returned early: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "wait ran long: {elapsed:?}"
        );

        let child = holder.0.as_mut().unwrap();
        let _ = child.kill();
        let _ = child.wait();
        let dir_path = dir.path().to_path_buf();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if JournalLock::acquire_within(&dir_path, Duration::from_millis(50)).is_ok() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the lock was not released after the holder exited"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
