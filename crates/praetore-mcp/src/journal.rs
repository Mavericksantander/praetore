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
};
use uuid::Uuid;

/// Largest line read back from the end of the journal. A receipt stays
/// below the 64 KiB evidence limit; the chain fields add less than 200 bytes.
const MAX_TAIL_BYTES: u64 = 256 * 1024;
/// Lock file next to the daily files (not `*.jsonl`, so never read as one).
const LOCK_FILE: &str = ".journal.lock";

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
pub struct JournalLock {
    /// Holding the descriptor holds the lock.
    _file: fs::File,
}

impl JournalLock {
    pub fn acquire(dir: &Path) -> Result<Self, String> {
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
        {
            use std::os::fd::AsRawFd;
            // SAFETY: `flock` on a descriptor this function owns; no memory
            // is passed to the kernel.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                return Err(format!(
                    "cannot lock {}: {}",
                    path.display(),
                    io::Error::last_os_error()
                ));
            }
        }
        Ok(Self { _file: file })
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

    /// Number of chained entries and the link after the last one, to keep
    /// somewhere else and compare later. `None` if the last entry could not
    /// be linked or there is no chained entry.
    pub fn head(&self) -> Option<Position> {
        self.head
    }
}
