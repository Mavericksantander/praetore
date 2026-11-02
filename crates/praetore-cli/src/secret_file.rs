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
//! Access control lists: on macOS an extended ACL (`chmod +a`) can grant
//! access that the mode bits do not show, so a file with any extended ACL
//! entry is refused (checked on the same descriptor, `acl_get_fd_np`; an
//! error while checking is a refusal). On Linux a POSIX ACL with named user
//! or group entries sets the group bits to its mask, so the mode check
//! already refuses it. Other platforms are not checked for ACLs.
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
    /// Has extended ACL entries (macOS), or they could not be checked.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    ExtendedAcl,
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
            Self::ExtendedAcl => f.write_str(
                "has extended ACL entries, or they cannot be checked; remove them (chmod -N)",
            ),
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
    // On Linux this also covers POSIX ACLs: with named entries, the group
    // bits hold the ACL mask, so any extra grant shows up here.
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SecretFileError::NotPrivate);
    }
    #[cfg(target_os = "macos")]
    if acl::has_extended_entries(&file)? {
        return Err(SecretFileError::ExtendedAcl);
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

/// macOS extended ACLs, which the mode bits do not show. Neither rustix nor
/// libc exposes the ACL API, so this declares the three functions it needs
/// from libSystem.
#[cfg(target_os = "macos")]
mod acl {
    use super::SecretFileError;
    use std::{
        fs::File,
        os::{
            fd::AsRawFd,
            raw::{c_int, c_void},
        },
    };

    /// `ACL_TYPE_EXTENDED` and `ACL_FIRST_ENTRY` from `<sys/acl.h>`.
    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: c_int = 0;

    unsafe extern "C" {
        fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_free(object: *mut c_void) -> c_int;
    }

    /// Whether the open `file` has at least one extended ACL entry. "No
    /// ACL" (`ENOENT`) is `false`; every other error is
    /// [`SecretFileError::ExtendedAcl`], so the caller refuses the file
    /// when its ACL cannot be checked.
    pub(super) fn has_extended_entries(file: &File) -> Result<bool, SecretFileError> {
        let no_entry = rustix::io::Errno::NOENT.raw_os_error();
        // SAFETY: `file` is open for the whole call, so its descriptor is
        // valid; the call only reads it and returns an owned ACL or NULL.
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            return match std::io::Error::last_os_error().raw_os_error() {
                Some(errno) if errno == no_entry => Ok(false),
                _ => Err(SecretFileError::ExtendedAcl),
            };
        }
        let mut entry = std::ptr::null_mut();
        // SAFETY: `acl` is the non-NULL ACL returned above and is freed only
        // below; `entry` is a valid out pointer for the call.
        let status = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        // SAFETY: `acl` came from `acl_get_fd_np`, is freed once, and is not
        // used afterwards (`entry` points into it and is not used either).
        unsafe { acl_free(acl) };
        match status {
            0 => Ok(true),
            // No first entry: an empty ACL.
            _ if errno == Some(rustix::io::Errno::INVAL.raw_os_error()) => Ok(false),
            _ => Err(SecretFileError::ExtendedAcl),
        }
    }
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

    /// An ACL can grant access the mode bits do not show (macOS).
    #[cfg(target_os = "macos")]
    #[test]
    fn refuses_a_file_with_an_extended_acl() {
        let dir = Dir::new();
        let path = dir.private("key", b"abc");
        assert!(read_private_file(&path, 128).is_ok());
        let chmod = |args: &[&str]| {
            assert!(
                std::process::Command::new("chmod")
                    .args(args)
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            )
        };
        chmod(&["+a", "everyone allow read"]);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            read_private_file(&path, 128),
            Err(SecretFileError::ExtendedAcl)
        );
        // A deny entry is refused too: any extended entry is.
        chmod(&["-N"]);
        chmod(&["+a", "everyone deny write"]);
        assert_eq!(
            read_private_file(&path, 128),
            Err(SecretFileError::ExtendedAcl)
        );
        chmod(&["-N"]);
        assert!(read_private_file(&path, 128).is_ok());
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
