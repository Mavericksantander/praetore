//! Local key files, opened once.
//!
//! [`KeyPath`] has no public constructor. [`KeyPath::open`] and
//! [`KeyPath::create`] `lstat` the `keys/` directory and the named file,
//! refuse a symlink at either name, require both to be owned by the
//! effective uid, and open the file with `O_NOFOLLOW`. The bytes are read
//! or written on that descriptor. Every key file this crate opens or
//! creates goes through this type.

use crate::shown::Show;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(crate) const ISSUER_FILE: &str = "issuer.local-dev.key";
pub(crate) const AGENT_FILE: &str = "agent.local-dev.key";
pub(crate) const ATTESTER_FILE: &str = "attester.local-dev.key";
pub(crate) const APPROVER_FILE: &str = "approver.local-dev.key";

const REQUIRED_FILES: [&str; 3] = [ISSUER_FILE, AGENT_FILE, ATTESTER_FILE];
/// A key file is a short JSON document. Anything larger is refused.
const MAX_KEY_FILE_BYTES: u64 = 8 * 1024;

/// An open key file. Constructed only by [`KeyPath::open`].
pub(crate) struct KeyPath {
    file: std::fs::File,
    path: PathBuf,
}

impl std::fmt::Debug for KeyPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPath")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl KeyPath {
    /// Reads the open file from its descriptor, at most
    /// [`MAX_KEY_FILE_BYTES`].
    pub(crate) fn read_to_string(&mut self) -> Result<Zeroizing<String>, String> {
        use std::io::Read;
        let mut bytes = Zeroizing::new(Vec::new());
        self.file
            .by_ref()
            .take(MAX_KEY_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read {}: {error}", self.path.shown()))?;
        if bytes.len() as u64 > MAX_KEY_FILE_BYTES {
            return Err(format!(
                "{} is larger than {MAX_KEY_FILE_BYTES} bytes",
                self.path.shown()
            ));
        }
        let text = String::from_utf8(bytes.as_slice().to_vec())
            .map_err(|_| format!("{} is not UTF-8", self.path.shown()))?;
        Ok(Zeroizing::new(text))
    }
}

/// Opens every installed key file. The approver key may be absent (a home
/// from before it existed). A symlink, a wrong owner or a non-regular file
/// is an error for every name, including the approver key.
pub(crate) fn check_installed(keys_dir: &Path) -> Result<(), String> {
    for name in REQUIRED_FILES {
        let mut key = KeyPath::open(keys_dir, name)?;
        let _contents = key.read_to_string()?;
    }
    if let Some(mut key) = KeyPath::open_if_present(keys_dir, APPROVER_FILE)? {
        let _contents = key.read_to_string()?;
    }
    Ok(())
}

/// [`check_installed`] when `keys/` exists. An absent directory is not a
/// symlink: homes kept for verification without their private keys (the
/// published fixtures) have no `keys/` and stay verifiable. A symlink at
/// `keys/` is still refused.
pub(crate) fn check_installed_if_present(keys_dir: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(keys_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot stat {}: {error}", keys_dir.shown())),
        Ok(meta) if meta.file_type().is_symlink() => Err(symlink_message(keys_dir)),
        Ok(_) => check_installed(keys_dir),
    }
}

fn single_component(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(format!(
            "key file name {name:?} is not a single path component"
        ));
    }
    Ok(())
}

fn symlink_message(path: &Path) -> String {
    format!("{} is a symlink; refusing to follow it", path.shown())
}

#[cfg(unix)]
mod unix {
    use super::{KeyPath, single_component, symlink_message};
    use crate::shown::Show;
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use std::{
        fs,
        io::Write,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
    };

    struct KeysDir {
        fd: rustix::fd::OwnedFd,
        path: PathBuf,
    }

    impl KeysDir {
        /// `lstat` of `keys/`, then `open` with `O_DIRECTORY | O_NOFOLLOW`.
        /// The descriptor is checked against the `lstat` result.
        fn open(path: &Path) -> Result<Self, String> {
            let looked = rustix::fs::lstat(path)
                .map_err(|error| format!("cannot stat {}: {}", path.shown(), io_error(error)))?;
            require_type(&looked, path, FileType::Directory)?;
            require_owner(&looked, path)?;
            let fd = rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| open_error(error, path))?;
            let opened = rustix::fs::fstat(&fd)
                .map_err(|error| format!("cannot stat {}: {}", path.shown(), io_error(error)))?;
            if !same_file(&opened, &looked) {
                return Err(format!("{} changed while it was opened", path.shown()));
            }
            require_type(&opened, path, FileType::Directory)?;
            require_owner(&opened, path)?;
            Ok(Self {
                fd,
                path: path.to_path_buf(),
            })
        }
    }

    impl KeyPath {
        pub(crate) fn open(keys_dir: &Path, file_name: &str) -> Result<Self, String> {
            let dir = KeysDir::open(keys_dir)?;
            let Some(key) = Self::open_at(&dir, file_name)? else {
                let path = dir.path.join(file_name);
                return Err(format!("cannot stat {}: not found", path.shown()));
            };
            Ok(key)
        }

        pub(crate) fn open_if_present(
            keys_dir: &Path,
            file_name: &str,
        ) -> Result<Option<Self>, String> {
            let dir = KeysDir::open(keys_dir)?;
            Self::open_at(&dir, file_name)
        }

        /// `lstat` of the file (via `statat` with `AT_SYMLINK_NOFOLLOW`) and
        /// `openat` with `O_NOFOLLOW`. `None` when the name is absent.
        fn open_at(dir: &KeysDir, file_name: &str) -> Result<Option<Self>, String> {
            single_component(file_name)?;
            let path = dir.path.join(file_name);
            let Some(looked) = stat_name(dir, file_name, &path)? else {
                return Ok(None);
            };
            require_type(&looked, &path, FileType::RegularFile)?;
            require_owner(&looked, &path)?;
            let fd = rustix::fs::openat(
                &dir.fd,
                file_name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| open_error(error, &path))?;
            let opened = rustix::fs::fstat(&fd)
                .map_err(|error| format!("cannot stat {}: {}", path.shown(), io_error(error)))?;
            if !same_file(&opened, &looked) {
                return Err(format!("{} changed while it was opened", path.shown()));
            }
            require_type(&opened, &path, FileType::RegularFile)?;
            require_owner(&opened, &path)?;
            require_private(&opened, &path)?;
            Ok(Some(Self {
                file: fs::File::from(fd),
                path,
            }))
        }

        /// Creates a new key file through the directory descriptor
        /// (`O_CREAT | O_EXCL | O_NOFOLLOW`). An existing name, including a
        /// symlink, is refused.
        pub(crate) fn create(
            keys_dir: &Path,
            file_name: &str,
            contents: &str,
        ) -> Result<(), String> {
            single_component(file_name)?;
            let dir = KeysDir::open(keys_dir)?;
            let path = dir.path.join(file_name);
            if let Some(stat) = stat_name(&dir, file_name, &path)? {
                if file_type(&stat) == FileType::Symlink {
                    return Err(symlink_message(&path));
                }
                return Err(format!("{} already exists", path.shown()));
            }
            let fd = rustix::fs::openat(
                &dir.fd,
                file_name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|error| {
                if error == rustix::io::Errno::EXIST || error == rustix::io::Errno::LOOP {
                    format!(
                        "{} is a symlink or already exists; refusing to replace it",
                        path.shown()
                    )
                } else {
                    format!("cannot create {}: {}", path.shown(), io_error(error))
                }
            })?;
            let mut file = fs::File::from(fd);
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("cannot set mode of {}: {error}", path.shown()))?;
            let meta = file
                .metadata()
                .map_err(|error| format!("cannot stat {}: {error}", path.shown()))?;
            if !meta.is_file() {
                return Err(format!("{} is not a regular file", path.shown()));
            }
            if meta.uid() != rustix::process::geteuid().as_raw() {
                return Err(format!("{} is not owned by this user", path.shown()));
            }
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(format!(
                    "{} is accessible by group/others (mode {:o})",
                    path.shown(),
                    meta.permissions().mode() & 0o777
                ));
            }
            file.write_all(contents.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|error| format!("cannot write {}: {error}", path.shown()))?;
            rustix::fs::fsync(&dir.fd).map_err(|error| {
                format!("cannot sync {}: {}", dir.path.shown(), io_error(error))
            })?;
            Ok(())
        }
    }

    fn stat_name(
        dir: &KeysDir,
        name: &str,
        path: &Path,
    ) -> Result<Option<rustix::fs::Stat>, String> {
        match rustix::fs::statat(&dir.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(stat)),
            Err(errno) if errno == rustix::io::Errno::NOENT => Ok(None),
            Err(errno) => Err(format!("cannot stat {}: {}", path.shown(), io_error(errno))),
        }
    }

    fn require_type(
        stat: &rustix::fs::Stat,
        path: &Path,
        expected: FileType,
    ) -> Result<(), String> {
        let kind = file_type(stat);
        if kind == FileType::Symlink {
            return Err(symlink_message(path));
        }
        if kind != expected {
            let what = if expected == FileType::Directory {
                "a directory"
            } else {
                "a regular file"
            };
            return Err(format!("{} is not {what}", path.shown()));
        }
        Ok(())
    }

    fn require_owner(stat: &rustix::fs::Stat, path: &Path) -> Result<(), String> {
        if stat.st_uid != rustix::process::geteuid().as_raw() {
            return Err(format!("{} is not owned by this user", path.shown()));
        }
        Ok(())
    }

    fn require_private(stat: &rustix::fs::Stat, path: &Path) -> Result<(), String> {
        // `st_mode` is `mode_t` (`u16` on macOS, `u32` on Linux). The mask
        // uses that width, so the check does not narrow the value.
        let mode = stat.st_mode;
        let group_or_other: rustix::fs::RawMode = 0o077;
        let shown: rustix::fs::RawMode = 0o777;
        if mode & group_or_other != 0 {
            return Err(format!(
                "{} is accessible by group/others (mode {:o}); run: chmod 600 {}",
                path.shown(),
                mode & shown,
                path.shown()
            ));
        }
        Ok(())
    }

    fn file_type(stat: &rustix::fs::Stat) -> FileType {
        FileType::from_raw_mode(stat.st_mode)
    }

    fn open_error(errno: rustix::io::Errno, path: &Path) -> String {
        if errno == rustix::io::Errno::LOOP {
            symlink_message(path)
        } else {
            format!("cannot open {}: {}", path.shown(), io_error(errno))
        }
    }

    fn io_error(errno: rustix::io::Errno) -> std::io::Error {
        std::io::Error::from(errno)
    }

    fn same_file(opened: &rustix::fs::Stat, looked: &rustix::fs::Stat) -> bool {
        opened.st_dev == looked.st_dev && opened.st_ino == looked.st_ino
    }
}

#[cfg(not(unix))]
mod portable {
    use super::{KeyPath, single_component, symlink_message};
    use crate::shown::Show;
    use std::{
        fs,
        io::Write,
        path::{Path, PathBuf},
    };

    struct KeysDir {
        path: PathBuf,
    }

    impl KeysDir {
        fn open(path: &Path) -> Result<Self, String> {
            let meta = fs::symlink_metadata(path)
                .map_err(|error| format!("cannot stat {}: {error}", path.shown()))?;
            if meta.file_type().is_symlink() {
                return Err(symlink_message(path));
            }
            if !meta.is_dir() {
                return Err(format!("{} is not a directory", path.shown()));
            }
            Ok(Self {
                path: path.to_path_buf(),
            })
        }
    }

    impl KeyPath {
        pub(crate) fn open(keys_dir: &Path, file_name: &str) -> Result<Self, String> {
            let dir = KeysDir::open(keys_dir)?;
            Self::open_at(&dir, file_name)?.ok_or_else(|| {
                format!(
                    "cannot stat {}: not found",
                    dir.path.join(file_name).shown()
                )
            })
        }

        pub(crate) fn open_if_present(
            keys_dir: &Path,
            file_name: &str,
        ) -> Result<Option<Self>, String> {
            let dir = KeysDir::open(keys_dir)?;
            Self::open_at(&dir, file_name)
        }

        fn open_at(dir: &KeysDir, file_name: &str) -> Result<Option<Self>, String> {
            single_component(file_name)?;
            let path = dir.path.join(file_name);
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(format!("cannot stat {}: {error}", path.shown())),
                Ok(meta) if meta.file_type().is_symlink() => return Err(symlink_message(&path)),
                Ok(meta) if !meta.is_file() => {
                    return Err(format!("{} is not a regular file", path.shown()));
                }
                Ok(_) => {}
            }
            let file = fs::File::open(&path)
                .map_err(|error| format!("cannot open {}: {error}", path.shown()))?;
            Ok(Some(Self { file, path }))
        }

        pub(crate) fn create(
            keys_dir: &Path,
            file_name: &str,
            contents: &str,
        ) -> Result<(), String> {
            single_component(file_name)?;
            let dir = KeysDir::open(keys_dir)?;
            let path = dir.path.join(file_name);
            if let Ok(meta) = fs::symlink_metadata(&path) {
                if meta.file_type().is_symlink() {
                    return Err(symlink_message(&path));
                }
                return Err(format!("{} already exists", path.shown()));
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|error| format!("cannot create {}: {error}", path.shown()))?;
            file.write_all(contents.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|error| format!("cannot write {}: {error}", path.shown()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_defines_keys_read_only_from_owned_non_symlink() {
        let spec = include_str!("../../../docs/formal/KeyPath.tla");
        let cfg = include_str!("../../../docs/formal/KeyPath.cfg");
        assert!(
            spec.contains("KeysReadOnlyFromOwnedNonSymlink =="),
            "the spec no longer defines KeysReadOnlyFromOwnedNonSymlink =="
        );
        assert!(
            cfg.contains("KeysReadOnlyFromOwnedNonSymlink"),
            "KeyPath.cfg no longer checks the invariant"
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_reads_the_file_descriptor_and_refuses_symlinks() {
        let (temp, home) = crate::journal_io::temp_home();
        let keys = home.keys_dir();
        let agent = std::fs::read_to_string(home.agent_key()).unwrap();
        let issuer = std::fs::read(home.issuer_key()).unwrap();
        let mut opened = KeyPath::open(&keys, AGENT_FILE).unwrap();
        assert_eq!(opened.read_to_string().unwrap().as_str(), agent);

        let real = keys.join("agent.real");
        std::fs::rename(home.agent_key(), &real).unwrap();
        std::os::unix::fs::symlink(&real, home.agent_key()).unwrap();
        let error = KeyPath::open(&keys, AGENT_FILE).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        assert!(!error.contains("secret_key_hex"), "{error}");
        assert_eq!(std::fs::read_to_string(&real).unwrap(), agent);
        let marker = keys.join("marker");
        std::fs::write(&marker, "MARKER-NOT-A-KEY").unwrap();
        std::fs::remove_file(home.agent_key()).unwrap();
        std::os::unix::fs::symlink(&marker, home.agent_key()).unwrap();
        let error = KeyPath::create(&keys, AGENT_FILE, "new key bytes").unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "MARKER-NOT-A-KEY"
        );

        let moved = temp.path().join("keys.real");
        std::fs::rename(&keys, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &keys).unwrap();
        let error = check_installed(&keys).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        assert_eq!(std::fs::read(moved.join(ISSUER_FILE)).unwrap(), issuer);
    }

    #[cfg(unix)]
    #[test]
    fn group_readable_key_is_refused() {
        let (_temp, home) = crate::journal_io::temp_home();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(home.agent_key(), std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = KeyPath::open(&home.keys_dir(), AGENT_FILE).unwrap_err();
        assert!(error.contains("group/others"), "{error}");
    }
}
