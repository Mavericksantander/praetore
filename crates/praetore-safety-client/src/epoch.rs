//! The source epoch, persisted across restarts of the source.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

/// 2^53 - 1: the largest `source_epoch` (an exact JSON integer).
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// A file that holds the last `source_epoch` of a source, as decimal text.
///
/// [`EpochFile::start`] reads it (a missing file is epoch 0), adds one,
/// writes the new value to a temporary file, `fsync`s it, renames it over
/// the old one and `fsync`s the directory, and only then returns the new
/// epoch. If any step fails, or the file holds anything but an epoch, it
/// returns an error and the source must not report events: it never
/// starts again from epoch 1, which would make the ingester reject every
/// event as `stale_epoch` (or, worse, look like a replay of an earlier run).
///
/// Call it once per start of the source, before the first event, and use
/// the result as `source_epoch` of every event of that run, with
/// `source_seq` from 1. The file must be on persistent storage, owned by
/// the source and not shared with another source.
#[derive(Debug, Clone)]
pub struct EpochFile {
    path: PathBuf,
}

impl EpochFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The epoch currently stored (0 when there is no file yet).
    pub fn current(&self) -> io::Result<u64> {
        let mut text = String::new();
        match File::open(&self.path) {
            Ok(file) => {
                file.take(32).read_to_string(&mut text)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error),
        }
        let digits = text.strip_suffix('\n').unwrap_or(&text);
        let valid = !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
            && (digits == "0" || !digits.starts_with('0'));
        digits
            .parse::<u64>()
            .ok()
            .filter(|epoch| valid && *epoch <= MAX_SAFE_INTEGER)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} does not hold a source epoch", self.path.display()),
                )
            })
    }

    /// Persists and returns the epoch of this run: the stored one plus one.
    pub fn start(&self) -> io::Result<u64> {
        let epoch = self
            .current()?
            .checked_add(1)
            .filter(|epoch| *epoch <= MAX_SAFE_INTEGER)
            .ok_or_else(|| io::Error::other("the source epoch is exhausted"))?;
        let directory = match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let name = self
            .path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
        let mut temporary_name = name.to_os_string();
        temporary_name.push(".tmp");
        let temporary = directory.join(temporary_name);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)?;
        file.write_all(format!("{epoch}\n").as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &self.path)?;
        File::open(&directory)?.sync_all()?;
        // Read it back: what the next start sees is what this run uses.
        if self.current()? != epoch {
            return Err(io::Error::other("the source epoch did not persist"));
        }
        Ok(epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("praetore-epoch-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn every_start_persists_a_larger_epoch() {
        let dir = scratch("starts");
        let file = EpochFile::new(dir.join("epoch"));
        assert_eq!(file.current().unwrap(), 0);
        assert_eq!(file.start().unwrap(), 1);
        assert_eq!(file.start().unwrap(), 2);
        // Another handle (a restarted process) continues from the file.
        assert_eq!(EpochFile::new(dir.join("epoch")).start().unwrap(), 3);
        assert_eq!(fs::read_to_string(dir.join("epoch")).unwrap(), "3\n");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_unreadable_or_unwritable_epoch_fails_closed() {
        let dir = scratch("fails");
        for bad in ["", "x", "-1", "01", "1 2", "9007199254740992"] {
            fs::write(dir.join("epoch"), bad).unwrap();
            assert!(
                EpochFile::new(dir.join("epoch")).start().is_err(),
                "{bad:?}"
            );
        }
        fs::write(dir.join("epoch"), "9007199254740991\n").unwrap();
        assert!(EpochFile::new(dir.join("epoch")).start().is_err());
        // A directory that does not exist: nothing can be persisted.
        assert!(
            EpochFile::new(dir.join("missing").join("epoch"))
                .start()
                .is_err()
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
