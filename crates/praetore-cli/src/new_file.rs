//! Writing a new file that never replaces anything and never appears
//! partially written (G2).
//!
//! [`write_new_file`] writes and syncs the contents to a file that has no
//! name yet, or a temporary name, in the target directory, then links it to
//! the target name. `link` fails if the name exists (also as a dangling
//! symlink), so nothing is replaced. After the link, the entry at the
//! target name is checked (`lstat`, device and inode) against the file this
//! process wrote; if another entry was put there in between, it is removed
//! while it is still that entry and the write fails.
//!
//! * Linux: an anonymous `O_TMPFILE` file linked with `linkat` through
//!   `/proc/self/fd`, so there is no temporary name at all. When the
//!   directory's filesystem or the kernel does not support it, or `/proc`
//!   is missing, it falls back to the temporary name below.
//! * Other Unix systems: a temporary name `.<name>.<uuid>.tmp`, created
//!   with `O_CREAT | O_EXCL`, removed afterwards only while it is still the
//!   file this process created.
//!
//! A filesystem without hard links (FAT, exFAT, some SMB or FUSE mounts)
//! always fails, with a message that says so; there is deliberately no
//! fallback to a non-atomic write.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Writes `contents` to `path`, which must not exist (see the module docs).
pub fn write_new_file(path: &Path, contents: &[u8]) -> CliResult<()> {
    #[cfg(unix)]
    {
        let (directory, name) = split(path)?;
        #[cfg(target_os = "linux")]
        if let Some(result) = linux::write_anonymous(directory, path, contents) {
            result?;
            sync_directory(directory);
            return Ok(());
        }
        write_through_temporary(directory, &name, path, contents, |_| {})?;
        sync_directory(directory);
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, contents);
        Err("writing a new file without a partial result is supported only on Unix".into())
    }
}

#[cfg(unix)]
fn split(path: &Path) -> CliResult<(&Path, String)> {
    let name = path
        .file_name()
        .ok_or_else(|| format!("{} does not name a file", path.display()))?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Ok((directory, name.to_string_lossy().into_owned()))
}

/// Device and inode: what identifies the file this process wrote.
#[cfg(unix)]
type Identity = (u64, u64);

#[cfg(unix)]
fn identity_of(metadata: &fs::Metadata) -> Identity {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

/// The identity of the entry at `path`, not following a symlink.
#[cfg(unix)]
fn entry_at(path: &Path) -> Option<(Identity, bool)> {
    fs::symlink_metadata(path)
        .ok()
        .map(|metadata| (identity_of(&metadata), metadata.file_type().is_file()))
}

/// Removes `path` only while the entry there is still `identity`.
#[cfg(unix)]
fn remove_if_still(path: &Path, identity: Identity) {
    if entry_at(path).is_some_and(|(found, _)| found == identity) {
        let _ = fs::remove_file(path);
    }
}

/// After the link: the entry at `path` must be the regular file `ours`. If
/// it is not, it is removed while it is still the entry that was found, and
/// the write fails.
#[cfg(unix)]
fn check_linked(path: &Path, ours: Identity) -> CliResult<()> {
    match entry_at(path) {
        Some((found, true)) if found == ours => Ok(()),
        found => {
            if let Some((found, _)) = found {
                remove_if_still(path, found);
            }
            Err(format!(
                "cannot create {}: the file was replaced while it was being written; nothing was written",
                path.display()
            )
            .into())
        }
    }
}

/// The error for a failed link, with a hint when the filesystem has no
/// hard links.
#[cfg(unix)]
fn link_error(path: &Path, error: std::io::Error) -> Box<dyn std::error::Error> {
    let errno = error.raw_os_error();
    let no_links = [
        rustix::io::Errno::NOTSUP,
        rustix::io::Errno::OPNOTSUPP,
        rustix::io::Errno::PERM,
        rustix::io::Errno::MLINK,
    ]
    .iter()
    .any(|candidate| errno == Some(candidate.raw_os_error()));
    if no_links {
        format!(
            "cannot create {}: {error}; the filesystem of that directory does not support hard links, which this command needs to write the file in one step. Write it to a local filesystem (for example APFS or ext4) and copy it from there",
            path.display()
        )
        .into()
    } else {
        format!("cannot create {}: {error}", path.display()).into()
    }
}

/// The temporary-name path. `before_link` lets a test act between the sync
/// and the link (it receives the temporary path).
#[cfg(unix)]
fn write_through_temporary(
    directory: &Path,
    name: &str,
    path: &Path,
    contents: &[u8],
    before_link: impl FnOnce(&Path),
) -> CliResult<()> {
    let temporary: PathBuf = directory.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    // Nothing to clean up if this fails: the name was not created by us.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    let ours = identity_of(&file.metadata()?);
    let result = (|| -> CliResult<()> {
        file.write_all(contents)?;
        file.sync_all()?;
        before_link(&temporary);
        fs::hard_link(&temporary, path).map_err(|error| link_error(path, error))?;
        check_linked(path, ours)
    })();
    remove_if_still(&temporary, ours);
    drop(file);
    result
}

/// Best effort: the file is complete either way.
#[cfg(unix)]
fn sync_directory(directory: &Path) {
    if let Ok(directory) = fs::File::open(directory) {
        let _ = directory.sync_all();
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{CliResult, check_linked, identity_of, link_error};
    use rustix::fs::{AtFlags, CWD, Mode, OFlags};
    use std::{fs::File, io::Write, os::fd::AsRawFd, path::Path};

    /// `None` when `O_TMPFILE` or the `/proc` link is not available here:
    /// the caller falls back to a temporary name. Nothing has been created
    /// in that case (an unlinked `O_TMPFILE` file disappears on close).
    pub(super) fn write_anonymous(
        directory: &Path,
        path: &Path,
        contents: &[u8],
    ) -> Option<CliResult<()>> {
        let fd = rustix::fs::openat(
            CWD,
            directory,
            OFlags::TMPFILE | OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o644),
        )
        .ok()?;
        let mut file = File::from(fd);
        if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
            return Some(Err(
                format!("cannot create {}: {error}", path.display()).into()
            ));
        }
        let ours = match file.metadata() {
            Ok(metadata) => identity_of(&metadata),
            Err(error) => return Some(Err(error.into())),
        };
        let source = format!("/proc/self/fd/{}", file.as_raw_fd());
        match rustix::fs::linkat(CWD, source.as_str(), CWD, path, AtFlags::SYMLINK_FOLLOW) {
            Ok(()) => Some(check_linked(path, ours)),
            Err(errno) if errno == rustix::io::Errno::EXIST => {
                Some(Err(link_error(path, std::io::Error::from(errno))))
            }
            // No /proc, or a filesystem that cannot link this file: retry
            // with a temporary name, which reports its own error if it
            // cannot link either.
            Err(_) => None,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "praetore-new-file-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn names(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn never_replaces_and_leaves_no_temporary_file() {
        let dir = Dir::new();
        let path = dir.0.join("manifest.json");
        write_new_file(&path, b"first\n").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first\n");
        let error = write_new_file(&path, b"second\n").unwrap_err();
        assert!(error.to_string().contains("cannot create"), "{error}");
        assert_eq!(fs::read(&path).unwrap(), b"first\n");

        // A dangling symlink at the output name is not followed.
        let target = dir.0.join("elsewhere");
        let link = dir.0.join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_new_file(&link, b"x").is_err());
        assert!(!target.exists());

        // A failed write leaves nothing: here the directory does not exist.
        let missing = dir.0.join("missing").join("manifest.json");
        assert!(write_new_file(&missing, b"x").is_err());
        assert!(!missing.exists());

        assert_eq!(dir.names(), ["link.json", "manifest.json"]);
    }

    #[test]
    fn the_temporary_name_path_never_replaces_either() {
        let dir = Dir::new();
        let path = dir.0.join("manifest.json");
        write_through_temporary(&dir.0, "manifest.json", &path, b"first\n", |_| {}).unwrap();
        assert!(
            write_through_temporary(&dir.0, "manifest.json", &path, b"second\n", |_| {}).is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), b"first\n");
        assert_eq!(dir.names(), ["manifest.json"]);
    }

    /// Another file renamed over the temporary name between the sync and
    /// the link: the output is not left pointing at it, and the other file
    /// (no longer ours) is not removed.
    #[test]
    fn a_temporary_file_swapped_before_the_link_is_detected() {
        let dir = Dir::new();
        let path = dir.0.join("manifest.json");
        let intruder = dir.0.join("intruder");
        fs::write(&intruder, b"not the manifest").unwrap();
        let mut swapped = None;
        let error = write_through_temporary(&dir.0, "manifest.json", &path, b"ours\n", |tmp| {
            fs::rename(&intruder, tmp).unwrap();
            swapped = Some(tmp.to_path_buf());
        })
        .unwrap_err();
        assert!(error.to_string().contains("was replaced"), "{error}");
        assert!(!path.exists());
        let swapped = swapped.unwrap();
        assert_eq!(fs::read(&swapped).unwrap(), b"not the manifest");

        // The same with a symlink swapped in: the output is not a symlink.
        let path = dir.0.join("second.json");
        let target = dir.0.join("target");
        let error = write_through_temporary(&dir.0, "second.json", &path, b"ours\n", |tmp| {
            let link = dir.0.join("evil-link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            fs::rename(&link, tmp).unwrap();
        })
        .unwrap_err();
        assert!(error.to_string().contains("was replaced"), "{error}");
        assert!(fs::symlink_metadata(&path).is_err());
        assert!(!target.exists());
    }

    #[test]
    fn a_filesystem_without_hard_links_gets_a_clear_message() {
        let error = link_error(
            Path::new("m.json"),
            std::io::Error::from_raw_os_error(rustix::io::Errno::NOTSUP.raw_os_error()),
        );
        assert!(
            error.to_string().contains("does not support hard links"),
            "{error}"
        );
        let error = link_error(
            Path::new("m.json"),
            std::io::Error::from_raw_os_error(rustix::io::Errno::EXIST.raw_os_error()),
        );
        assert!(!error.to_string().contains("hard links"), "{error}");
    }
}
