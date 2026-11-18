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

use crate::shown::Show;
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
fn chained_line(position: &Position, evidence_json: &str) -> String {
    format!(
        "{{\"seq\":{},\"prev\":\"{}\",\"evidence\":{evidence_json}}}\n",
        position.seq, position.prev
    )
}

/// Why a receipt did not reach the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    /// The line for this receipt does not read back as the receipt that was
    /// signed, so writing it would leave an entry that `verify` rejects and
    /// that stops every later append. Nothing was written. The call is
    /// refused in both modes: forwarding it would run a call whose receipt
    /// can never exist.
    Unverifiable(String),
    /// The journal could not be read, locked or written. Enforce refuses
    /// the call; observe forwards it and warns.
    Unavailable(String),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unverifiable(error) => write!(
                f,
                "the receipt does not verify when read back, so it was not written ({error})"
            ),
            Self::Unavailable(error) => f.write_str(error),
        }
    }
}

impl From<JournalError> for String {
    fn from(error: JournalError) -> Self {
        error.to_string()
    }
}

/// A journal line that was read back before it is written: the only thing
/// [`crate::gate::Journal`] appends.
///
/// The writer used to serialize a receipt and append it, and only the next
/// append read that line. A receipt that does not survive its own JSON
/// round trip (a float that prints as text which parses to another float)
/// was therefore written, and from then on every append failed on it.
#[derive(Debug)]
pub struct VerifiedLine {
    text: String,
    position: Position,
    next: Position,
}

impl VerifiedLine {
    /// Builds the line for `evidence` at `position` and checks what a later
    /// reader will check: the line parses as a chained entry at `position`,
    /// its evidence passes the integrity check, and the link of the next
    /// entry can be computed from it.
    pub fn new(position: &Position, evidence: &Evidence) -> Result<Self, String> {
        let evidence_json = evidence
            .to_json()
            .map_err(|e| format!("cannot serialize evidence: {e}"))?;
        let text = chained_line(position, &evidence_json);
        let entry = parse_line(text.strip_suffix('\n').unwrap_or(&text))?;
        if entry.position != Some(*position) {
            return Err("the line does not read back at its own position".into());
        }
        if !entry.evidence.verify_integrity() {
            return Err("EVIDENCE_FAIL: evidence integrity verification failed".into());
        }
        let next = position.after(&entry.evidence)?;
        Ok(Self {
            text,
            position: *position,
            next,
        })
    }

    /// The line, newline included.
    pub fn as_bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }

    /// Where this line goes.
    pub fn position(&self) -> &Position {
        &self.position
    }

    /// Where the entry after this one goes.
    pub fn next(&self) -> &Position {
        &self.next
    }
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
        Err(error) => return Err(format!("cannot read {}: {error}", dir.shown())),
    };
    files.sort();
    Ok(files)
}

/// Last line of `path` without its newline, `None` for an empty file.
/// A last line without a newline (interrupted write) is an error: nothing
/// is appended after it until someone looks at the journal.
fn last_line(path: &Path, verify: &str) -> Result<Option<String>, String> {
    let fail = |e: io::Error| format!("cannot read {}: {e}", path.shown());
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
            "{} does not end with a newline (interrupted write?); run `{verify}`",
            path.shown()
        ));
    };
    let line = match body.iter().rposition(|&b| b == b'\n') {
        Some(index) => &body[index + 1..],
        None if start == 0 => body,
        None => return Err(format!("{}: last line is too long", path.shown())),
    };
    String::from_utf8(line.to_vec())
        .map(Some)
        .map_err(|_| format!("{}: last line is not UTF-8", path.shown()))
}

/// Where the next entry goes: the newest daily file that is not older than
/// `today` (so file order stays chain order if the clock goes back), and the
/// position after the last entry of the journal. `verify` is the command
/// an error tells to run ([`crate::commands::command`]).
pub fn next_append(
    dir: &Path,
    today: PathBuf,
    verify: &str,
) -> Result<(PathBuf, Position), String> {
    let files = journal_files(dir)?;
    let path = match files.last() {
        Some(newest) if *newest > today => newest.clone(),
        _ => today,
    };
    for file in files.iter().rev() {
        let Some(text) = last_line(file, verify)? else {
            continue;
        };
        let entry = parse_line(&text).map_err(|e| {
            format!(
                "last entry of {} is unreadable ({e}); run `{verify}`",
                file.shown()
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
            .map_err(|e| format!("cannot open lock {}: {e}", path.shown()))?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: `flock` on a descriptor this function owns; no memory
            // is passed to the kernel.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                return Err(format!(
                    "cannot lock {}: {}",
                    path.shown(),
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

/// The `seq` and `prev` a line claims, when it is a chained line whose
/// evidence could not be read. The line fails on its own; its claimed
/// position only lets [`Chain::rebuild`] keep walking past it, so one
/// damaged entry does not put every earlier entry outside the chain.
pub fn claimed_position(text: &str) -> Option<Position> {
    let line: ChainedLine<'_> = serde_json::from_str(text).ok()?;
    Some(Position {
        seq: line.seq,
        prev: ChainLink::from_hex(line.prev)?,
    })
}

/// One journal line as [`Chain::rebuild`] sees it.
#[derive(Clone, Copy)]
pub enum ChainLine<'a> {
    Entry(&'a Entry),
    /// A line that could not be parsed, with its [`claimed_position`].
    Unreadable(Option<Position>),
}

/// The journal as one chain: the result of [`Chain::rebuild`].
///
/// The invariant: the lines of the journal are exactly the entries of the
/// chain that ends at the head, in chain order. The chain is rebuilt from
/// the head backwards along `prev` to the first entry (`seq` 0, `prev` 64
/// zeros). A line that this walk does not reach is outside the chain: it
/// is not covered by the head, so nothing says it was there when the head
/// was saved. A link the walk cannot follow is a missing entry.
///
/// A bare evidence line (the format before the chain existed) has no
/// `seq` or `prev`, so it is never part of a chain and always fails.
pub struct Chain {
    /// One per line, in file order: why the line breaks the invariant.
    pub problems: Vec<Option<String>>,
    /// Set when no line produces the expected head.
    pub missing: Option<String>,
    /// Chained lines present, whether or not they are in the chain.
    pub chained: u64,
    /// Bare evidence lines present. Each one is a problem.
    pub unchained: u64,
    /// Position after the last line of the journal, when that line is a
    /// chained entry: the next `seq`, and the link to keep somewhere else
    /// and pass later as the expected head.
    pub head: Option<Position>,
}

impl Chain {
    /// Rebuilds the chain that ends at `expected`, or, without one, at the
    /// last entry of the journal that can be linked. `lines` are the lines
    /// in file order.
    ///
    /// Without `expected`, entries removed at the end of the journal leave
    /// a shorter journal that still is exactly one chain: only a head kept
    /// somewhere else finds them.
    pub fn rebuild(lines: &[ChainLine<'_>], expected: Option<ChainLink>) -> Self {
        // The link each chained line produces: the `prev` of its successor.
        let produced: Vec<Option<(Position, ChainLink)>> = lines
            .iter()
            .map(|line| {
                let ChainLine::Entry(entry) = line else {
                    return None;
                };
                let position = entry.position?;
                let next = position.after(&entry.evidence).ok()?;
                Some((position, next.prev))
            })
            .collect();
        let entry_of = |index: usize| match lines[index] {
            ChainLine::Entry(entry) => Some(entry),
            ChainLine::Unreadable(_) => None,
        };
        let mut chain = Self {
            problems: vec![None; lines.len()],
            missing: None,
            chained: produced.iter().flatten().count() as u64,
            unchained: (0..lines.len())
                .filter(|&index| entry_of(index).is_some_and(|entry| entry.position.is_none()))
                .count() as u64,
            head: None,
        };
        // The last entry that can be linked is the journal's own head.
        chain.head = produced
            .iter()
            .rev()
            .flatten()
            .next()
            .map(|(position, link)| Position {
                seq: position.seq.saturating_add(1),
                prev: *link,
            });
        // The first line that produces each link.
        let mut by_link: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for (index, link) in produced.iter().enumerate() {
            if let Some((_, link)) = link {
                by_link.entry(link.to_hex()).or_insert(index);
            }
        }

        // Walk from the head back to the first entry.
        let own_head = chain.head.map(|head| head.prev);
        let head = match expected {
            // The expected head is not the link of any entry here: that is
            // one failure of the whole journal. The lines are then checked
            // against the journal's own head, so each line that is outside
            // that chain is still named.
            Some(link) if !by_link.contains_key(&link.to_hex()) => {
                chain.missing = Some(format!("no entry produces the head {link}"));
                own_head
            }
            Some(link) => Some(link),
            None => own_head,
        };
        let mut members: Vec<usize> = Vec::new();
        let mut in_chain = vec![false; lines.len()];
        let mut wanted = head.map(|link| (link, None::<u64>));
        while let Some((link, successor_seq)) = wanted.take() {
            let member = by_link
                .get(&link.to_hex())
                .and_then(|&index| Some((index, produced[index]?.0)))
                // No entry produces this link. A line that could not be
                // read and claims the seq before `successor_seq` holds the
                // place; it fails on its own.
                .or_else(|| {
                    let seq = successor_seq?.checked_sub(1)?;
                    lines
                        .iter()
                        .enumerate()
                        .find_map(|(index, line)| match line {
                            ChainLine::Unreadable(Some(position))
                                if position.seq == seq && !in_chain[index] =>
                            {
                                Some((index, *position))
                            }
                            _ => None,
                        })
                });
            let Some((index, position)) = member else {
                // The walk stops at the last member: nothing here produces
                // the link it names as its predecessor.
                if let (Some(&successor), Some(seq)) = (members.last(), successor_seq) {
                    chain.problems[successor] = Some(format!(
                        "the entry before seq {seq} (link {link}) is missing: an entry was removed"
                    ));
                }
                break;
            };
            if in_chain[index] {
                // Unreachable with a collision-free hash; ends the walk.
                chain.missing = Some(format!("the chain loops at link {link}"));
                break;
            }
            if successor_seq.is_some_and(|seq| position.seq.checked_add(1) != Some(seq)) {
                chain.problems[index] = Some(format!(
                    "seq {} does not come right before seq {}: an entry was removed, duplicated or reordered",
                    position.seq,
                    successor_seq.unwrap_or_default()
                ));
            }
            in_chain[index] = true;
            members.push(index);
            if position.seq == 0 {
                if position.prev != ChainLink::GENESIS {
                    chain.problems[index] = Some(format!(
                        "the first entry (seq 0) has prev {} instead of 64 zeros",
                        position.prev
                    ));
                }
                break;
            }
            wanted = Some((position.prev, Some(position.seq)));
        }

        // The file must hold the chain in chain order.
        members.reverse();
        let mut last_index = None;
        for &index in &members {
            if last_index.is_some_and(|last| index < last) {
                chain.problems[index].get_or_insert_with(|| {
                    "the entry is in the chain but out of place in the file: entries were reordered"
                        .into()
                });
            }
            last_index = Some(last_index.map_or(index, |last: usize| last.max(index)));
        }

        // Every other line is outside the chain.
        let mut ids: HashSet<Uuid> = members
            .iter()
            .filter_map(|&index| entry_of(index).map(|entry| entry.evidence.evidence_id))
            .collect();
        let anchor = match head {
            Some(link) => format!("the chain that ends at head {link}"),
            None => "any chain: the journal has no head".to_owned(),
        };
        for (index, _) in in_chain.iter().enumerate().filter(|(_, member)| !**member) {
            let Some(entry) = entry_of(index) else {
                // Its parse error is reported on its own.
                continue;
            };
            let duplicate = if ids.insert(entry.evidence.evidence_id) {
                ""
            } else {
                "duplicate evidence_id; "
            };
            chain.problems[index] = Some(match entry.position {
                None => {
                    format!("{duplicate}unchained line (no seq and prev): it is outside {anchor}")
                }
                Some(position) => format!(
                    "{duplicate}seq {} is outside {anchor}: an entry was added, duplicated or reordered, or the head is older than this entry",
                    position.seq
                ),
            });
        }
        chain
    }
}
