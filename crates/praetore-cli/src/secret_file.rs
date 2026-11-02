//! Reading a small secret file from one open descriptor (G2).
//!
//! [`read_private_file`] opens the path once, without following a symlink
//! as the last component and without blocking on a FIFO
//! (`O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`), checks that open file with
//! `fstat` (a regular file, owned by the effective uid, no group or other
//! permission bits, at most `max_bytes`), and reads through the same
//! descriptor with the size limit enforced again while reading. There is no
//! window between the check and the read in which the path can be swapped.
//!
//! Only the safety namespace key uses it for now. `read_secret` in
//! `main.rs` (the local demo keys) still checks by path; moving it here is
//! a follow-up.

use std::{fmt, io::Read, path::Path};

/// Why a secret file was refused. The message names the problem, never the
/// contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretFileError {
    /// The last component is a symbolic link.
    SymbolicLink,
    /// Not a regular file (a directory, a FIFO, a device, a socket).
    NotRegularFile,
    /// Owned by another user than the effective uid.
    WrongOwner,
    /// Readable, writable or executable by group or others.
    NotPrivate,
    /// Larger than the limit.
    TooLarge { max: u64 },
    /// Missing or unreadable.
    Unreadable(String),
    /// Owner-only files cannot be checked on this platform.
    #[cfg_attr(unix, allow(dead_code))]
    Unsupported,
}

impl fmt::Display for SecretFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SymbolicLink => f.write_str("is a symbolic link; name the file itself"),
            Self::NotRegularFile => f.write_str("is not a regular file"),
            Self::WrongOwner => f.write_str("is not owned by the current user"),
            Self::NotPrivate => {
                f.write_str("is accessible by group or others; set its mode to 0600 or 0400")
            }
            Self::TooLarge { max } => write!(f, "is larger than {max} bytes"),
            Self::Unreadable(reason) => write!(f, "cannot be read: {reason}"),
            Self::Unsupported => {
                f.write_str("cannot be checked for owner-only access on this platform")
            }
        }
    }
}

impl std::error::Error for SecretFileError {}

/// Reads a private file of at most `max_bytes` (see the module docs).
pub fn read_private_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, SecretFileError> {
    #[cfg(unix)]
    {
        read_private_file_owned_by(path, max_bytes, rustix::process::geteuid().as_raw())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, max_bytes);
        Err(SecretFileError::Unsupported)
    }
}

/// [`read_private_file`] with the expected owner given, so the owner check
/// can be tested without a second account.
#[cfg(unix)]
fn read_private_file_owned_by(
    path: &Path,
    max_bytes: u64,
    owner: u32,
) -> Result<Vec<u8>, SecretFileError> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| {
        if errno == rustix::io::Errno::LOOP {
            SecretFileError::SymbolicLink
        } else {
            SecretFileError::Unreadable(std::io::Error::from(errno).to_string())
        }
    })?;
    let file = std::fs::File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|error| SecretFileError::Unreadable(error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(SecretFileError::NotRegularFile);
    }
    if metadata.uid() != owner {
        return Err(SecretFileError::WrongOwner);
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SecretFileError::NotPrivate);
    }
    if metadata.len() > max_bytes {
        return Err(SecretFileError::TooLarge { max: max_bytes });
    }
    let mut contents = Vec::with_capacity(max_bytes as usize + 1);
    file.take(max_bytes + 1)
        .read_to_end(&mut contents)
        .map_err(|error| SecretFileError::Unreadable(error.to_string()))?;
    // The file may have grown between `fstat` and the read.
    if contents.len() as u64 > max_bytes {
        return Err(SecretFileError::TooLarge { max: max_bytes });
    }
    Ok(contents)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "praetore-secret-file-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn private(&self, name: &str, contents: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, contents).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            path
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn reads_an_owner_only_regular_file() {
        let dir = Dir::new();
        let path = dir.private("key", b"abc\n");
        assert_eq!(read_private_file(&path, 128).unwrap(), b"abc\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(read_private_file(&path, 128).unwrap(), b"abc\n");
    }

    #[test]
    fn refuses_a_symbolic_link_even_to_a_private_file() {
        let dir = Dir::new();
        let target = dir.private("key", b"abc");
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            read_private_file(&link, 128),
            Err(SecretFileError::SymbolicLink)
        );
    }

    #[test]
    fn refuses_a_fifo_without_blocking() {
        let dir = Dir::new();
        let fifo = dir.0.join("fifo");
        let status = std::process::Command::new("mkfifo")
            .arg("-m")
            .arg("600")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            read_private_file(&fifo, 128),
            Err(SecretFileError::NotRegularFile)
        );
        assert_eq!(
            read_private_file(&dir.0, 128),
            Err(SecretFileError::NotRegularFile)
        );
    }

    #[test]
    fn refuses_an_oversized_file() {
        let dir = Dir::new();
        let path = dir.private("key", &[b'a'; 129]);
        assert_eq!(
            read_private_file(&path, 128),
            Err(SecretFileError::TooLarge { max: 128 })
        );
        let exact = dir.private("exact", &[b'a'; 128]);
        assert_eq!(read_private_file(&exact, 128).unwrap().len(), 128);
    }

    #[test]
    fn refuses_group_or_other_permission_bits() {
        let dir = Dir::new();
        let path = dir.private("key", b"abc");
        for mode in [0o640, 0o604, 0o610, 0o601, 0o644, 0o660] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                read_private_file(&path, 128),
                Err(SecretFileError::NotPrivate),
                "{mode:o}"
            );
        }
    }

    #[test]
    fn refuses_a_file_owned_by_another_user() {
        let dir = Dir::new();
        let path = dir.private("key", b"abc");
        let me = rustix::process::geteuid().as_raw();
        assert!(read_private_file_owned_by(&path, 128, me).is_ok());
        assert_eq!(
            read_private_file_owned_by(&path, 128, me.wrapping_add(1)),
            Err(SecretFileError::WrongOwner)
        );
    }

    #[test]
    fn a_missing_file_is_unreadable() {
        let dir = Dir::new();
        assert!(matches!(
            read_private_file(&dir.0.join("missing"), 128),
            Err(SecretFileError::Unreadable(_))
        ));
    }
}
