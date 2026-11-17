//! One append for the receipts journal and the approval journal.
//!
//! A line is one buffer, trailing newline included, stored with a single
//! `write`, then fsynced. If that write is short or returns an error, the
//! file is truncated back to the length from before the call and that
//! truncation is fsynced. The error means the line was not persisted.
//!
//! A full disk or `RLIMIT_FSIZE` can store a prefix and then stop. A writer
//! that retries the tail keeps that prefix: `verify` reads it (`str::lines`
//! keeps a tail with no newline) and reports `not JSON`.
//!
//! An fsync error after a complete write is returned as-is and does not
//! truncate. The line is whole, so dropping it would discard a record the
//! kernel has accepted. A crash in the window between the short write and
//! the truncate still leaves a cut line; `verify` and the next append keep
//! treating that as damage.

#[cfg(test)]
use crate::shown::Show;
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

/// Something the journal append can write one line to.
///
/// [`std::fs::File`] is the production writer. Tests pass a writer that
/// stores a prefix and then reports a short count or a full disk.
pub(crate) trait JournalWriter {
    fn len(&self) -> io::Result<u64>;
    fn write_bytes(&mut self, buf: &[u8]) -> io::Result<usize>;
    fn sync_data(&mut self) -> io::Result<()>;
    fn set_len(&mut self, len: u64) -> io::Result<()>;
}

impl JournalWriter for fs::File {
    fn len(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    fn write_bytes(&mut self, buf: &[u8]) -> io::Result<usize> {
        Write::write(self, buf)
    }

    fn sync_data(&mut self) -> io::Result<()> {
        fs::File::sync_data(self)
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        fs::File::set_len(self, len)
    }
}

/// Opens `path` for append (mode `0o600`, `O_NOFOLLOW` where it exists) and
/// writes one journal line.
pub(crate) fn append_journal_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let (mut file, created) = open_journal(path)?;
    commit_journal_line(&mut file, bytes)?;
    // Creating the file adds a directory entry. Fsync the directory too, or
    // a crash could lose the new file with its first line. A failure here
    // does not truncate: the line is already complete.
    if created && let Some(dir) = path.parent() {
        crate::fsutil::sync_dir(dir)?;
    }
    Ok(())
}

fn open_journal(path: &Path) -> io::Result<(fs::File, bool)> {
    let mut options = fs::OpenOptions::new();
    options.append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(crate::journal::nofollow_flag());
    }
    match options.open(path) {
        Ok(file) => Ok((file, false)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok((options.create_new(true).open(path)?, true))
        }
        Err(error) => Err(error),
    }
}

/// Writes `bytes` (one journal line, newline included) with a single
/// `write`, then fsyncs.
///
/// A short count or a write error is rolled back to `len` from before this
/// call, and that truncation is fsynced. The returned error means the line
/// was not persisted.
pub(crate) fn commit_journal_line(file: &mut impl JournalWriter, bytes: &[u8]) -> io::Result<()> {
    let previous_len = file.len()?;
    let written = write_once(file, bytes);
    if matches!(written, Ok(n) if n == bytes.len()) {
        return file.sync_data();
    }
    let write_error = match written {
        Ok(n) => io::Error::new(
            io::ErrorKind::StorageFull,
            format!("short write ({n} of {} bytes)", bytes.len()),
        ),
        Err(error) => error,
    };
    match restore_len(file, previous_len) {
        Ok(()) => Err(write_error),
        Err(rollback) => {
            let kind = write_error.kind();
            Err(io::Error::new(
                kind,
                format!(
                    "{write_error}; failed to restore the journal to {previous_len} bytes: {rollback}"
                ),
            ))
        }
    }
}

/// One `write` of the whole line. `Interrupted` before any byte is reported
/// is retried. A short count is returned to the caller, which rolls it back.
fn write_once(file: &mut impl JournalWriter, bytes: &[u8]) -> io::Result<usize> {
    loop {
        match file.write_bytes(bytes) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

fn restore_len(file: &mut impl JournalWriter, previous_len: u64) -> io::Result<()> {
    file.set_len(previous_len)?;
    file.sync_data()
}

/// How many bytes of a 401-byte line a full `RLIMIT_FSIZE` left on disk
/// before this rollback (verified on main, 16 Nov 2026).
#[cfg(test)]
pub(crate) const PROBE_ROOM: usize = 180;

#[cfg(test)]
pub(crate) const PROBE_LINE_LEN: usize = 401;

/// One 401-byte buffer ending in a newline. The first [`PROBE_ROOM`] bytes
/// are not a JSON line.
#[cfg(test)]
pub(crate) fn line_of_401() -> Vec<u8> {
    let mut line = Vec::with_capacity(PROBE_LINE_LEN);
    line.extend_from_slice(br#"{"seq":1,"prev":""#);
    line.resize(PROBE_LINE_LEN - 1, b'a');
    line.push(b'\n');
    debug_assert_eq!(line.len(), PROBE_LINE_LEN);
    line
}

/// Simulated full disk. `room` bytes are stored in the real file, then the
/// call returns a short count or an error. `durable` is the bytes observed
/// at the last fsync.
#[cfg(test)]
pub(crate) struct FaultyFile {
    path: std::path::PathBuf,
    file: fs::File,
    room: usize,
    mode: FaultMode,
    pub accepted: usize,
    pub durable: Option<Vec<u8>>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum FaultMode {
    /// `Ok(room)` once `room` is used up.
    Short,
    /// Store `room` bytes, then `StorageFull` (ENOSPC).
    StorageFull,
    /// Store `room` bytes, then `FileTooLarge` (EFBIG).
    FileTooLarge,
}

#[cfg(test)]
impl FaultyFile {
    pub(crate) fn open(path: &Path, room: usize, mode: FaultMode) -> io::Result<Self> {
        let (file, created) = open_journal(path)?;
        if created {
            return Err(io::Error::other(format!(
                "journal {} did not exist",
                path.shown()
            )));
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            room,
            mode,
            accepted: 0,
            durable: None,
        })
    }

    fn store(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut stored = 0;
        while stored < buf.len() {
            match self.file.write(&buf[stored..])? {
                0 => break,
                n => stored += n,
            }
        }
        Ok(stored)
    }
}

#[cfg(test)]
impl JournalWriter for FaultyFile {
    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn write_bytes(&mut self, buf: &[u8]) -> io::Result<usize> {
        let want = self.room.min(buf.len());
        let stored = self.store(&buf[..want])?;
        self.room -= stored;
        self.accepted += stored;
        if stored == buf.len() {
            return Ok(stored);
        }
        if self.room > 0 {
            return Ok(stored);
        }
        match self.mode {
            FaultMode::Short => Ok(stored),
            FaultMode::StorageFull => Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "No space left on device",
            )),
            FaultMode::FileTooLarge => Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "File too large",
            )),
        }
    }

    fn sync_data(&mut self) -> io::Result<()> {
        self.file.sync_data()?;
        self.durable = Some(fs::read(&self.path)?);
        Ok(())
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }
}

#[cfg(test)]
pub(crate) fn temp_home() -> (tempfile::TempDir, crate::store::Home) {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = fs::canonicalize(temp.path()).expect("canonicalize");
    let home = crate::store::Home::new(root.join("home"));
    crate::store::init(&home).expect("init");
    (temp, home)
}

/// The failed append did not change the file, the fsync saw that image, and
/// `verify` still accepts the journal.
#[cfg(test)]
pub(crate) fn assert_journal_intact(
    home: &crate::store::Home,
    path: &Path,
    original: &[u8],
    writer: &FaultyFile,
    error: &io::Error,
    kind: io::ErrorKind,
) {
    assert_eq!(
        writer.accepted, PROBE_ROOM,
        "the simulated writer stored nothing, so a missing truncate would not fail this test"
    );
    assert_eq!(error.kind(), kind, "{error}");
    let now = fs::metadata(path).expect("metadata").len();
    assert_eq!(
        now,
        original.len() as u64,
        "file grew from {} to {now} after {error}",
        original.len()
    );
    let bytes = fs::read(path).expect("read journal");
    assert_eq!(bytes, original, "journal bytes changed");
    assert_eq!(
        writer.durable.as_deref(),
        Some(original),
        "fsync after the rollback did not see the previous bytes"
    );
    assert!(bytes.ends_with(b"\n"), "journal no longer ends on a line");
    let report = crate::receipts::verify_journal(home, None).expect("verify");
    assert!(
        report.failures.is_empty(),
        "verify after the failed append: {:?}",
        report.failures
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The invariant `AppendErrorPreservesLength` of
    /// `docs/formal/JournalAppend.tla`, on the real [`commit_journal_line`]:
    /// for each fault mode and each prefix the write stores (0 to 401
    /// bytes), an error after a short or failed write leaves the file at
    /// its previous length and bytes, and that is what the last fsync saw.
    /// `Ok` comes back only for the whole line (`OkMeansWholeLine`). The
    /// spec is not model-checked in CI; this test is what runs.
    #[test]
    fn append_error_preserves_length() {
        let spec = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/formal/JournalAppend.tla"),
        )
        .expect("docs/formal/JournalAppend.tla");
        for name in ["AppendErrorPreservesLength ==", "OkMeansWholeLine =="] {
            assert!(spec.contains(name), "the spec no longer defines {name}");
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("journal.jsonl");
        let before = b"{\"seq\":0}\n".to_vec();
        let line = line_of_401();
        let mut checked = 0;
        for mode in [
            FaultMode::Short,
            FaultMode::StorageFull,
            FaultMode::FileTooLarge,
        ] {
            for room in 0..=line.len() {
                fs::write(&path, &before).expect("seed");
                let mut file = FaultyFile::open(&path, room, mode).expect("open");
                let result = commit_journal_line(&mut file, &line);
                let after = fs::read(&path).expect("read");
                match result {
                    Ok(()) => {
                        assert_eq!(room, line.len(), "{mode:?} room {room}: Ok for a cut line");
                        assert_eq!(after, [before.as_slice(), &line].concat());
                    }
                    Err(error) => {
                        assert!(
                            room < line.len(),
                            "{mode:?}: error for a whole line: {error}"
                        );
                        assert_eq!(after, before, "{mode:?} room {room}: {error}");
                        assert_eq!(
                            file.durable.as_deref(),
                            Some(before.as_slice()),
                            "{mode:?} room {room}: the fsync after the rollback"
                        );
                    }
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 3 * 402);
    }

    /// Outside the invariant's condition: when the rollback itself fails,
    /// the error says so, so the caller knows the length is not known.
    #[test]
    fn a_failed_rollback_is_named_in_the_error() {
        struct NoTruncate(Vec<u8>);
        impl JournalWriter for NoTruncate {
            fn len(&self) -> io::Result<u64> {
                Ok(self.0.len() as u64)
            }
            fn write_bytes(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.extend_from_slice(&buf[..buf.len() / 2]);
                Ok(buf.len() / 2)
            }
            fn sync_data(&mut self) -> io::Result<()> {
                Ok(())
            }
            fn set_len(&mut self, _: u64) -> io::Result<()> {
                Err(io::Error::other("set_len refused"))
            }
        }
        let mut file = NoTruncate(b"x\n".to_vec());
        let error = commit_journal_line(&mut file, b"0123456789\n").expect_err("short");
        let text = error.to_string();
        assert!(
            text.contains("failed to restore the journal to 2 bytes")
                && text.contains("set_len refused"),
            "{text}"
        );
    }

    /// A full write whose fsync fails stays on the writer. Truncating it
    /// would drop a line the write already accepted.
    #[test]
    fn sync_error_after_a_complete_write_does_not_truncate() {
        struct Mem {
            data: Vec<u8>,
        }

        impl JournalWriter for Mem {
            fn len(&self) -> io::Result<u64> {
                Ok(self.data.len() as u64)
            }

            fn write_bytes(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.data.extend_from_slice(buf);
                Ok(buf.len())
            }

            fn sync_data(&mut self) -> io::Result<()> {
                Err(io::Error::other("sync failed"))
            }

            fn set_len(&mut self, len: u64) -> io::Result<()> {
                let len = usize::try_from(len).expect("len fits");
                self.data.truncate(len);
                Ok(())
            }
        }

        let mut mem = Mem {
            data: b"ok\n".to_vec(),
        };
        let error = commit_journal_line(&mut mem, b"next\n").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other, "{error}");
        assert_eq!(mem.data, b"ok\nnext\n");
    }

    /// `RLIMIT_FSIZE` in a child process. The parent suite does not inherit
    /// the limit or the ignored `SIGXFSZ`. Both journals must stay intact.
    #[cfg(unix)]
    #[test]
    fn rlimit_fsize_leaves_both_journals_intact() {
        if std::env::var_os("PRAETORE_JOURNAL_RLIMIT_PROBE").is_some() {
            probe_both_journals();
            return;
        }
        let exe = std::env::current_exe().expect("current_exe");
        let output = std::process::Command::new(exe)
            .args([
                "--exact",
                "journal_io::tests::rlimit_fsize_leaves_both_journals_intact",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("PRAETORE_JOURNAL_RLIMIT_PROBE", "1")
            .output()
            .expect("spawn rlimit probe");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("--- rlimit probe child stdout ---");
        println!("{stdout}");
        if !stderr.trim().is_empty() {
            println!("--- rlimit probe child stderr ---");
            println!("{stderr}");
        }
        assert!(output.status.success(), "probe status {:?}", output.status);
        assert!(
            stdout.contains("running 1 test"),
            "probe did not run as its own process"
        );
        // Linux cuts an O_APPEND write at RLIMIT_FSIZE, so the rollback runs.
        // macOS (APFS, checked on 27.0) does not apply the limit to an
        // O_APPEND write: the line is stored whole (see `probe_one`).
        let outcome = if cfg!(target_os = "linux") {
            "intact"
        } else {
            ""
        };
        for label in ["RECEIPTS", "APPROVALS"] {
            assert!(
                stdout.contains(&format!("PROBE {label} {outcome}")),
                "{label}: {stdout}"
            );
        }
    }

    #[cfg(unix)]
    fn probe_both_journals() {
        let (_temp, home) = temp_home();
        let receipts = crate::gate::seed_one_receipt(&home);
        let approvals = crate::approvals::seed_one_decision(&home);
        let receipt_bytes = fs::read(&receipts).expect("read receipts");
        let approval_bytes = fs::read(&approvals).expect("read approvals");
        let seeded = crate::receipts::verify_journal(&home, None).expect("verify seed");
        assert!(seeded.failures.is_empty(), "seed {:?}", seeded.failures);
        assert!(seeded.ok >= 1, "{seeded:?}");
        assert!(seeded.approval_decisions >= 1, "{seeded:?}");
        ignore_sigxfsz();
        probe_one("RECEIPTS", &home, &receipts, &receipt_bytes);
        probe_one("APPROVALS", &home, &approvals, &approval_bytes);
    }

    #[cfg(unix)]
    fn probe_one(label: &str, home: &crate::store::Home, path: &Path, before: &[u8]) {
        let limit = (before.len() as u64).saturating_add(PROBE_ROOM as u64);
        set_fsize_limit(limit);
        let result = append_journal_file(path, &line_of_401());
        if !cfg!(target_os = "linux")
            && let Ok(()) = result
        {
            // Not cut, so nothing to roll back: the line must be there whole.
            let after = fs::read(path).expect("read journal");
            assert_eq!(
                after,
                [before, line_of_401().as_slice()].concat(),
                "{label}: an append past RLIMIT_FSIZE is either cut and rolled back or whole"
            );
            println!(
                "PROBE {label} whole before={} after={} limit={limit} line={PROBE_LINE_LEN} (this OS does not apply RLIMIT_FSIZE to an O_APPEND write)",
                before.len(),
                after.len()
            );
            fs::write(path, before).expect("restore journal");
            return;
        }
        let error = result.expect_err("append must fail");
        let after = fs::read(path).expect("read journal");
        let report = crate::receipts::verify_journal(home, None).expect("verify");
        let ends_nl = after.ends_with(b"\n");
        println!(
            "PROBE {label} intact before={} after={} limit={limit} line={PROBE_LINE_LEN} err={error} verify_failures={} ends_with_nl={ends_nl}",
            before.len(),
            after.len(),
            report.failures.len()
        );
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::StorageFull | io::ErrorKind::FileTooLarge
            ),
            "{label} unexpected error {error:?}"
        );
        assert_eq!(after, before, "{label} journal changed: {error}");
        assert!(ends_nl, "{label} journal lost its trailing newline");
        assert!(
            report.failures.is_empty(),
            "{label} verify {:?}",
            report.failures
        );
    }

    #[cfg(unix)]
    fn ignore_sigxfsz() {
        // SAFETY: `SIG_IGN` is a constant disposition. No handler runs.
        let previous = unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
        assert_ne!(previous, libc::SIG_ERR, "{}", io::Error::last_os_error());
    }

    #[cfg(unix)]
    fn set_fsize_limit(limit: u64) {
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `current` is a valid `rlimit` this function owns.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut current) };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        assert!(
            current.rlim_max >= limit,
            "hard RLIMIT_FSIZE {} is below {limit}",
            current.rlim_max
        );
        let next = libc::rlimit {
            rlim_cur: limit,
            rlim_max: current.rlim_max,
        };
        // SAFETY: `next` is a valid `rlimit`. The soft limit stays at or
        // below the hard limit.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &next) };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
    }
}
