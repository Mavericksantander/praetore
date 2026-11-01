//! File effects performed through directory descriptors beneath one sandbox
//! root, instead of resolving a path string and then using it.
//!
//! This crate is the shared primitive behind
//! `praetore_gateway::sandbox::SandboxDispatcher` and is meant to be reused
//! by a tool runner that performs `path`/`path_list` effects inside its
//! sandbox root (see PR #61, proposal B3). It holds no policy: ownership and
//! mode requirements on the root, allowlists and refusal codes belong to the
//! caller.
//!
//! # How a path is resolved
//!
//! A path is a relative `name(/name)*` string. It is checked structurally
//! first (not empty, not absolute, no empty, `.` or `..` component, no NUL,
//! components of at most [`MAX_COMPONENT_BYTES`] bytes, no component
//! starting with [`TEMP_PREFIX`] compared ASCII case-insensitively). Then:
//!
//! - **Parent directory.** On Linux, the intermediate components are opened
//!   in one `openat2(root_fd, "a/b", O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`
//!   call with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS
//!   | RESOLVE_NO_XDEV`, so the kernel refuses any symlink, any escape from
//!   the root and any mount crossing (including a bind mount of the same
//!   filesystem) during that single resolution. When the kernel has no
//!   `openat2` (`ENOSYS`, Linux < 5.6, or a seccomp profile that answers
//!   `ENOSYS`), and on every other Unix (macOS included), the portable walk
//!   is used: one `openat(dirfd, name, O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`
//!   per component, each relative to the descriptor of the previous one.
//!   The `ENOSYS` fallback is logged once (`tracing::warn!`) and visible
//!   through [`openat2_status`]; [`Resolver::Openat2`] refuses it instead.
//!   `EPERM` (seccomp or an LSM denying `openat2`) is a permanent refusal,
//!   [`ConfineError::Openat2Denied`], never a fallback. Every other
//!   `openat2` error fails closed. In both cases each opened directory is
//!   `fstat`ed and refused if it is on a different device than the root.
//! - **Final component.** It is only ever used relative to the parent
//!   descriptor: inspected with `fstatat(AT_SYMLINK_NOFOLLOW)`, created with
//!   `openat(O_CREAT | O_EXCL | O_NOFOLLOW)`, opened with `O_NOFOLLOW |
//!   O_NONBLOCK | O_NOCTTY` and checked again with `fstat` on the opened
//!   descriptor, replaced with `renameat` and removed with `unlinkat(…, 0)`.
//!
//! Once a directory descriptor is held, replacing that directory's *name*
//! with a symlink (or anything else) does not change what the descriptor
//! refers to, so the check and the use are the same object.
//!
//! # What this prevents, and what it does not
//!
//! Prevented, for effects made through this crate:
//!
//! - following a symlink at any component, including one swapped in between
//!   an earlier check and the effect (the race tested in `tests/race.rs`);
//! - `..` and absolute paths (refused structurally; with `openat2` also by
//!   `RESOLVE_BENEATH`);
//! - crossing into another mounted filesystem through a path component
//!   (device check; with `openat2` also bind mounts, via `RESOLVE_NO_XDEV`);
//! - writing through, or truncating, an existing inode that has more than
//!   one hard link: [`Root::write_file`] never opens the existing target, it
//!   renames a new file over the directory entry, and [`Dir::open_existing`]
//!   refuses `st_nlink != 1` on the opened descriptor;
//! - opening FIFOs, sockets and device nodes (refused before opening and
//!   again on the opened descriptor; `O_NONBLOCK` keeps a FIFO swapped in
//!   between those two steps from blocking the caller).
//!
//! Not prevented (documented residual risks):
//!
//! - **Rename out of the root.** A process that can rename directories
//!   inside the root *and* has write access to a directory outside it on the
//!   same filesystem can move a directory that this crate has already opened
//!   out of the root while one operation is in flight; the effect then lands
//!   in the moved directory. Descriptors cannot detect this without a
//!   further (racy) check.
//! - **Hard links created later.** A hard link to a file inside the root
//!   created *after* the `fstat` check, by a process with write access
//!   outside the root, makes later writes to that inode visible outside.
//!   Hard links that already exist are detected (`st_nlink > 1`).
//! - **Mounts and other processes.** Anything mounted over the root itself,
//!   or a root whose own path the caller resolved wrongly, is outside the
//!   scope of this crate: the caller decides which directory is the root.
//!   Other processes with access to the same files are not restricted.
//! - **Temporary file swapped before the rename.** The temporary file of
//!   [`Root::write_file`] is visible to `readdir`. A process with write
//!   access to the root can replace it with a symlink before `renameat`; the
//!   target then becomes that symlink (the rename moves the link, it never
//!   follows it) and the call returns `Written { confirmed: false }`. No
//!   file outside the root is written; that process could have created the
//!   same symlink directly.
//! - **Quotas, permissions and contents.** No limit on file count or size,
//!   no check of what is written.

#![forbid(unsafe_code)]
#![cfg(unix)]

use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use std::fs::{File, Permissions};
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use thiserror::Error;

/// Longest accepted path component, in bytes.
pub const MAX_COMPONENT_BYTES: usize = 255;
/// Prefix of the temporary files used by [`Root::write_file`]. Path-level
/// operations refuse any component that starts with it (see
/// [`is_temp_name`]), so an action can never target an in-flight write.
pub const TEMP_PREFIX: &str = ".praetore-tmp-";

/// [`TEMP_PREFIX`], compared ASCII case-insensitively: on a case-insensitive
/// filesystem (default APFS) `.PRAETORE-TMP-x` names the same entry.
pub fn is_temp_name(name: &[u8]) -> bool {
    name.len() >= TEMP_PREFIX.len()
        && name[..TEMP_PREFIX.len()].eq_ignore_ascii_case(TEMP_PREFIX.as_bytes())
}

/// What this process has learned about `openat2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Openat2Status {
    /// Not used or probed yet.
    Unknown,
    Available,
    /// `ENOSYS` (or not Linux): [`Resolver::Auto`] uses the portable walk,
    /// [`Resolver::Openat2`] refuses.
    Unavailable,
    /// `EPERM` (seccomp or an LSM): every resolver except
    /// [`Resolver::Walk`] refuses permanently.
    Denied,
}

impl Openat2Status {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Unknown => "openat2 not probed yet",
            Self::Available => "openat2 available",
            Self::Unavailable => "openat2 unavailable (ENOSYS or not Linux)",
            Self::Denied => "openat2 denied (EPERM, seccomp or LSM)",
        }
    }
}

/// Process-wide `openat2` status. `Unavailable` and `Denied` are sticky:
/// once seen, the syscall is not retried.
struct Openat2State(AtomicU8);

impl Openat2State {
    const fn new() -> Self {
        Self(AtomicU8::new(0))
    }

    fn get(&self) -> Openat2Status {
        match self.0.load(Ordering::Relaxed) {
            1 => Openat2Status::Available,
            2 => Openat2Status::Unavailable,
            3 => Openat2Status::Denied,
            _ => Openat2Status::Unknown,
        }
    }

    /// Records `status`; returns `true` only for the call that first moved
    /// the state to `Unavailable` or `Denied` (the one that logs).
    fn record(&self, status: Openat2Status) -> bool {
        let code = match status {
            Openat2Status::Unknown => return false,
            Openat2Status::Available => {
                let _ = self
                    .0
                    .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed);
                return false;
            }
            Openat2Status::Unavailable => 2,
            Openat2Status::Denied => 3,
        };
        let mut current = self.0.load(Ordering::Relaxed);
        loop {
            if current >= 2 {
                return false;
            }
            match self
                .0
                .compare_exchange(current, code, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }
}

static OPENAT2: Openat2State = Openat2State::new();

/// What this process has learned about `openat2` so far. Always
/// `Unavailable` off Linux.
pub fn openat2_status() -> Openat2Status {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        OPENAT2.get()
    } else {
        Openat2Status::Unavailable
    }
}

/// How intermediate components are resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Resolver {
    /// `openat2` when the kernel has it, otherwise the portable walk (only
    /// on `ENOSYS`, logged once; `EPERM` and every other error fail
    /// closed).
    #[default]
    Auto,
    /// Only `openat2`; fails with [`ConfineError::Openat2Unavailable`] when
    /// the kernel or platform does not provide it.
    Openat2,
    /// Only the portable `openat(O_NOFOLLOW | O_DIRECTORY)` walk.
    Walk,
}

#[derive(Debug, Error)]
pub enum ConfineError {
    /// The path string is not a confined relative path. The payload is a
    /// stable reason: `empty_path`, `absolute_path`, `nul_byte`,
    /// `empty_component`, `dot_component`, `component_too_long`,
    /// `reserved_name` (a component starting with [`TEMP_PREFIX`]).
    #[error("invalid confined path: {0}")]
    InvalidPath(&'static str),
    /// An intermediate component is a symlink (`ELOOP`) or not a directory
    /// (`ENOTDIR`).
    #[error("a path component is a symlink or not a directory")]
    SymlinkOrNotDirectory,
    #[error("a parent directory does not exist")]
    MissingParent,
    /// A component is on another mount (`EXDEV`, or a different `st_dev`),
    /// or `openat2` reported that resolution would leave the root.
    #[error("the path crosses a mount point or leaves the root")]
    CrossesBoundary,
    #[error("the final component is a symlink")]
    Symlink,
    #[error("the final component is not a regular file")]
    NotRegularFile,
    #[error("the final component has more than one hard link")]
    HardLinked,
    #[error("the final component already exists")]
    AlreadyExists,
    #[error("the final component does not exist")]
    NotFound,
    #[error("openat2 is not available")]
    Openat2Unavailable,
    /// `openat2` returned `EPERM` (seccomp or an LSM). Permanent: retrying
    /// does not help.
    #[error("openat2 is denied (EPERM)")]
    Openat2Denied,
    #[error("the root is not a directory")]
    RootNotDirectory,
    #[error("the root is not accessible: {0}")]
    RootUnavailable(io::Error),
    #[error("a parent directory is not accessible: {0}")]
    ParentUnavailable(io::Error),
    #[error("the final component is not accessible: {0}")]
    EntryUnavailable(io::Error),
}

impl ConfineError {
    /// Descriptor or I/O failures that may succeed on retry. Everything
    /// else is a property of the path or of the tree.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::RootUnavailable(_) | Self::ParentUnavailable(_) | Self::EntryUnavailable(_)
        )
    }
}

/// Read or write access for [`Dir::open_existing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

/// Result of [`Root::write_file`]. Returned only once the target entry was
/// replaced; any `Err` means the target directory entry was not changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Written {
    pub bytes: usize,
    /// The directory was `fsync`ed and the entry now names the new inode.
    pub confirmed: bool,
}

/// Result of [`Root::remove_file`]. Returned only once the entry was
/// unlinked; any `Err` means nothing was removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Removed {
    /// The directory was `fsync`ed and the entry is gone.
    pub confirmed: bool,
}

/// An open directory descriptor that every effect is relative to.
pub struct Root {
    fd: OwnedFd,
    stat: Stat,
    resolver: Resolver,
}

impl std::fmt::Debug for Root {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Root")
            .field("fd", &self.fd)
            .field("resolver", &self.resolver)
            .finish_non_exhaustive()
    }
}

impl Root {
    /// Opens `path` as the root with `O_DIRECTORY | O_NOFOLLOW`. The path
    /// itself is trusted configuration: only its last component is protected
    /// against being a symlink.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ConfineError> {
        let fd = rustix::fs::open(
            path.as_ref(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| ConfineError::RootUnavailable(errno.into()))?;
        Self::from_fd(fd)
    }

    /// Uses an already opened directory descriptor as the root.
    pub fn from_fd(fd: OwnedFd) -> Result<Self, ConfineError> {
        let stat =
            rustix::fs::fstat(&fd).map_err(|errno| ConfineError::RootUnavailable(errno.into()))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(ConfineError::RootNotDirectory);
        }
        Ok(Self {
            fd,
            stat,
            resolver: Resolver::Auto,
        })
    }

    /// A second handle on the same root directory with another resolver.
    pub fn clone_with(&self, resolver: Resolver) -> Result<Self, ConfineError> {
        let fd = rustix::io::fcntl_dupfd_cloexec(&self.fd, 0)
            .map_err(|errno| ConfineError::RootUnavailable(errno.into()))?;
        Ok(Self::from_fd(fd)?.with_resolver(resolver))
    }

    pub fn with_resolver(mut self, resolver: Resolver) -> Self {
        self.resolver = resolver;
        self
    }

    pub fn set_resolver(&mut self, resolver: Resolver) {
        self.resolver = resolver;
    }

    pub fn resolver(&self) -> Resolver {
        self.resolver
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Opens the directory holding the final component of `path` and
    /// returns it with that final component.
    pub fn open_parent<'p>(&self, path: &'p str) -> Result<(Dir, &'p str), ConfineError> {
        let (directories, name) = split_relative(path)?;
        let dir = if directories.is_empty() {
            let fd = rustix::io::fcntl_dupfd_cloexec(&self.fd, 0)
                .map_err(|errno| ConfineError::RootUnavailable(errno.into()))?;
            self.dir_from(fd)?
        } else {
            let prefix = &path[..path.len() - name.len() - 1];
            self.open_directories(prefix, &directories)?
        };
        Ok((dir, name))
    }

    fn open_directories(&self, prefix: &str, components: &[&str]) -> Result<Dir, ConfineError> {
        match self.resolver {
            Resolver::Walk => self.walk(components),
            Resolver::Auto | Resolver::Openat2 => self.resolve_openat2(prefix, components),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn resolve_openat2(&self, prefix: &str, components: &[&str]) -> Result<Dir, ConfineError> {
        use rustix::fs::ResolveFlags;
        match OPENAT2.get() {
            Openat2Status::Unavailable => return self.openat2_unavailable(components),
            Openat2Status::Denied => return Err(ConfineError::Openat2Denied),
            Openat2Status::Unknown | Openat2Status::Available => {}
        }
        let resolve = ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV;
        let result = rustix::fs::openat2(
            &self.fd,
            prefix,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            resolve,
        );
        self.after_openat2(&OPENAT2, result, components)
    }

    /// Not Linux: `Auto` is the portable walk by design (nothing to log).
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn resolve_openat2(&self, _prefix: &str, components: &[&str]) -> Result<Dir, ConfineError> {
        self.openat2_unavailable(components)
    }

    /// Classifies one `openat2` result. Platform-independent so the
    /// fallback and refusal rules are unit-tested everywhere.
    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    fn after_openat2(
        &self,
        state: &Openat2State,
        result: Result<OwnedFd, Errno>,
        components: &[&str],
    ) -> Result<Dir, ConfineError> {
        match result {
            Ok(fd) => {
                state.record(Openat2Status::Available);
                self.dir_from(fd)
            }
            Err(errno) if errno == Errno::NOSYS => {
                if state.record(Openat2Status::Unavailable) {
                    tracing::warn!(
                        "openat2 unavailable (ENOSYS): Resolver::Auto falls back to the portable \
                         O_NOFOLLOW walk for the rest of this process; bind mounts of the same \
                         filesystem are no longer detected"
                    );
                }
                self.openat2_unavailable(components)
            }
            Err(errno) if errno == Errno::PERM => {
                if state.record(Openat2Status::Denied) {
                    tracing::warn!(
                        "openat2 denied (EPERM, seccomp or LSM): confined file effects that \
                         resolve directories fail closed for the rest of this process"
                    );
                }
                Err(ConfineError::Openat2Denied)
            }
            Err(errno) => Err(directory_error(errno)),
        }
    }

    fn openat2_unavailable(&self, components: &[&str]) -> Result<Dir, ConfineError> {
        match self.resolver {
            Resolver::Auto | Resolver::Walk => self.walk(components),
            Resolver::Openat2 => Err(ConfineError::Openat2Unavailable),
        }
    }

    fn walk(&self, components: &[&str]) -> Result<Dir, ConfineError> {
        let mut current = rustix::io::fcntl_dupfd_cloexec(&self.fd, 0)
            .map_err(|errno| ConfineError::RootUnavailable(errno.into()))?;
        for component in components {
            let next = rustix::fs::openat(
                &current,
                *component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(directory_error)?;
            let stat = rustix::fs::fstat(&next)
                .map_err(|errno| ConfineError::ParentUnavailable(errno.into()))?;
            if stat.st_dev != self.stat.st_dev {
                return Err(ConfineError::CrossesBoundary);
            }
            current = next;
        }
        self.dir_from(current)
    }

    fn dir_from(&self, fd: OwnedFd) -> Result<Dir, ConfineError> {
        let stat = rustix::fs::fstat(&fd)
            .map_err(|errno| ConfineError::ParentUnavailable(errno.into()))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(ConfineError::SymlinkOrNotDirectory);
        }
        if stat.st_dev != self.stat.st_dev {
            return Err(ConfineError::CrossesBoundary);
        }
        Ok(Dir { fd, stat })
    }

    /// Atomically replaces (or creates) the regular file at `path` with
    /// `content` and Unix permission bits `mode`. The new content is written
    /// to a fresh `O_CREAT | O_EXCL | O_NOFOLLOW` temporary file in the same
    /// directory, `fsync`ed and `renameat`ed over the target, then the
    /// directory is `fsync`ed. An existing target must be a regular file
    /// with one link; it is never opened, so its inode is never written.
    pub fn write_file(
        &self,
        path: &str,
        content: &[u8],
        mode: u32,
    ) -> Result<Written, ConfineError> {
        let (dir, name) = self.open_parent(path)?;
        dir.check_entry(name, true)?;
        let (temp, mut file) = dir.create_temp()?;
        let prepared = (|| -> Result<Stat, ConfineError> {
            let unavailable = ConfineError::EntryUnavailable;
            // fchmod: the mode does not depend on the umask.
            file.set_permissions(Permissions::from_mode(mode))
                .map_err(unavailable)?;
            file.write_all(content).map_err(unavailable)?;
            file.sync_all().map_err(unavailable)?;
            let stat = rustix::fs::fstat(&file).map_err(|errno| unavailable(errno.into()))?;
            if u64::try_from(stat.st_size).ok() != Some(content.len() as u64) {
                return Err(unavailable(io::Error::other("short write")));
            }
            // Narrows, but does not need to close, the window: renameat
            // replaces the entry and never follows what is there.
            dir.check_entry(name, true)?;
            Ok(stat)
        })();
        let temp_stat = match prepared {
            Ok(stat) => stat,
            Err(error) => {
                dir.unlink_quietly(&temp);
                return Err(error);
            }
        };
        if let Err(errno) = rustix::fs::renameat(&dir.fd, temp.as_str(), &dir.fd, name) {
            dir.unlink_quietly(&temp);
            return Err(final_error(errno));
        }
        let synced = rustix::fs::fsync(&dir.fd).is_ok();
        let confirmed = synced
            && dir.stat_entry(name).ok().flatten().is_some_and(|stat| {
                stat.st_dev == temp_stat.st_dev
                    && stat.st_ino == temp_stat.st_ino
                    && stat.st_size == temp_stat.st_size
            });
        Ok(Written {
            bytes: content.len(),
            confirmed,
        })
    }

    /// Creates a new regular file at `path` (`O_CREAT | O_EXCL |
    /// O_NOFOLLOW`); fails if anything already has that name.
    pub fn create_new_file(&self, path: &str, mode: u32) -> Result<File, ConfineError> {
        let (dir, name) = self.open_parent(path)?;
        dir.create_new(name, mode)
    }

    /// Opens an existing regular, single-link file at `path`.
    pub fn open_file(&self, path: &str, access: Access) -> Result<File, ConfineError> {
        let (dir, name) = self.open_parent(path)?;
        dir.open_existing(name, access)
    }

    /// Removes the regular, single-link file at `path` with
    /// `unlinkat(parent_fd, name, 0)`, which never removes a directory and,
    /// if the entry was swapped for a symlink, removes the link itself.
    pub fn remove_file(&self, path: &str) -> Result<Removed, ConfineError> {
        let (dir, name) = self.open_parent(path)?;
        dir.check_entry(name, false)?;
        rustix::fs::unlinkat(&dir.fd, name, AtFlags::empty()).map_err(|errno| {
            if errno == Errno::NOENT {
                ConfineError::NotFound
            } else {
                final_error(errno)
            }
        })?;
        let synced = rustix::fs::fsync(&dir.fd).is_ok();
        Ok(Removed {
            confirmed: synced && matches!(dir.stat_entry(name), Ok(None)),
        })
    }
}

/// A directory beneath the root, held by descriptor. Every method takes a
/// single component name and acts relative to this descriptor.
pub struct Dir {
    fd: OwnedFd,
    stat: Stat,
}

impl std::fmt::Debug for Dir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dir")
            .field("fd", &self.fd)
            .finish_non_exhaustive()
    }
}

impl Dir {
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// `fstatat(AT_SYMLINK_NOFOLLOW)`; `Ok(None)` when absent.
    pub fn stat_entry(&self, name: &str) -> Result<Option<Stat>, ConfineError> {
        check_component(name)?;
        match rustix::fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(stat)),
            Err(errno) if errno == Errno::NOENT => Ok(None),
            Err(errno) => Err(ConfineError::EntryUnavailable(errno.into())),
        }
    }

    /// The entry must be a regular file with one link, or absent when
    /// `may_be_absent`. Never follows a symlink.
    pub fn check_entry(
        &self,
        name: &str,
        may_be_absent: bool,
    ) -> Result<Option<Stat>, ConfineError> {
        match self.stat_entry(name)? {
            Some(stat) => {
                check_regular_single_link(&stat)?;
                Ok(Some(stat))
            }
            None if may_be_absent => Ok(None),
            None => Err(ConfineError::NotFound),
        }
    }

    /// `openat(O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW)`, then `fchmod` to
    /// `mode`.
    pub fn create_new(&self, name: &str, mode: u32) -> Result<File, ConfineError> {
        check_component(name)?;
        let fd = rustix::fs::openat(
            &self.fd,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|errno| {
            if errno == Errno::EXIST {
                ConfineError::AlreadyExists
            } else {
                final_error(errno)
            }
        })?;
        let file = File::from(fd);
        file.set_permissions(Permissions::from_mode(mode))
            .map_err(ConfineError::EntryUnavailable)?;
        Ok(file)
    }

    /// Opens an existing regular file with one link. Non-regular entries are
    /// refused before opening (so devices and FIFOs are not opened), and the
    /// opened descriptor is checked again with `fstat` (authoritative).
    pub fn open_existing(&self, name: &str, access: Access) -> Result<File, ConfineError> {
        self.check_entry(name, false)?;
        let access_flags = match access {
            Access::Read => OFlags::RDONLY,
            Access::Write => OFlags::WRONLY,
        };
        let fd = rustix::fs::openat(
            &self.fd,
            name,
            access_flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(final_error)?;
        let stat =
            rustix::fs::fstat(&fd).map_err(|errno| ConfineError::EntryUnavailable(errno.into()))?;
        check_regular_single_link(&stat)?;
        if stat.st_dev != self.stat.st_dev {
            return Err(ConfineError::CrossesBoundary);
        }
        Ok(File::from(fd))
    }

    /// `renameat` within this directory. Replaces the `to` entry without
    /// opening or following what it names.
    pub fn rename(&self, from: &str, to: &str) -> Result<(), ConfineError> {
        check_component(from)?;
        check_component(to)?;
        rustix::fs::renameat(&self.fd, from, &self.fd, to).map_err(final_error)
    }

    /// `unlinkat(…, 0)`: never removes a directory; removes a symlink
    /// itself, never its target.
    pub fn unlink(&self, name: &str) -> Result<(), ConfineError> {
        check_component(name)?;
        rustix::fs::unlinkat(&self.fd, name, AtFlags::empty()).map_err(final_error)
    }

    pub fn sync(&self) -> io::Result<()> {
        rustix::fs::fsync(&self.fd).map_err(Into::into)
    }

    fn create_temp(&self) -> Result<(String, File), ConfineError> {
        let name = format!("{TEMP_PREFIX}{}", uuid::Uuid::new_v4().simple());
        let file = self.create_new(&name, 0o600)?;
        Ok((name, file))
    }

    fn unlink_quietly(&self, name: &str) {
        let _ = rustix::fs::unlinkat(&self.fd, name, AtFlags::empty());
    }
}

/// Regular file with exactly one link; symlinks, directories, FIFOs,
/// sockets and devices are refused.
pub fn check_regular_single_link(stat: &Stat) -> Result<(), ConfineError> {
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::RegularFile => {}
        FileType::Symlink => return Err(ConfineError::Symlink),
        _ => return Err(ConfineError::NotRegularFile),
    }
    // A second link may be a name outside the root for the same inode.
    if stat.st_nlink != 1 {
        return Err(ConfineError::HardLinked);
    }
    Ok(())
}

/// Splits `path` into its intermediate components and its final component,
/// refusing anything that is not `name(/name)*`.
fn split_relative(path: &str) -> Result<(Vec<&str>, &str), ConfineError> {
    if path.is_empty() {
        return Err(ConfineError::InvalidPath("empty_path"));
    }
    if path.starts_with('/') {
        return Err(ConfineError::InvalidPath("absolute_path"));
    }
    let mut components: Vec<&str> = path.split('/').collect();
    for component in &components {
        check_component(component)?;
        if is_temp_name(component.as_bytes()) {
            return Err(ConfineError::InvalidPath("reserved_name"));
        }
    }
    let name = components
        .pop()
        .ok_or(ConfineError::InvalidPath("empty_path"))?;
    Ok((components, name))
}

fn check_component(component: &str) -> Result<(), ConfineError> {
    match component {
        "" => Err(ConfineError::InvalidPath("empty_component")),
        "." | ".." => Err(ConfineError::InvalidPath("dot_component")),
        c if c.contains('/') => Err(ConfineError::InvalidPath("empty_component")),
        c if c.contains('\0') => Err(ConfineError::InvalidPath("nul_byte")),
        c if c.len() > MAX_COMPONENT_BYTES => Err(ConfineError::InvalidPath("component_too_long")),
        _ => Ok(()),
    }
}

fn directory_error(errno: Errno) -> ConfineError {
    if errno == Errno::LOOP || errno == Errno::NOTDIR {
        ConfineError::SymlinkOrNotDirectory
    } else if errno == Errno::NOENT {
        ConfineError::MissingParent
    } else if errno == Errno::XDEV {
        ConfineError::CrossesBoundary
    } else {
        ConfineError::ParentUnavailable(errno.into())
    }
}

fn final_error(errno: Errno) -> ConfineError {
    if errno == Errno::LOOP {
        ConfineError::Symlink
    } else if errno == Errno::NOENT {
        ConfineError::NotFound
    } else if errno == Errno::ISDIR || errno == Errno::NXIO || errno == Errno::NOTDIR {
        ConfineError::NotRegularFile
    } else {
        ConfineError::EntryUnavailable(errno.into())
    }
}

/// Probes `openat2` once with a harmless `openat2(root, ".",
/// RESOLVE_BENEATH)` and records the answer in [`openat2_status`] (logging
/// once if it is unavailable or denied). Always `Unavailable` off Linux.
pub fn probe_openat2(root: &Root) -> Openat2Status {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::fs::ResolveFlags;
        if matches!(
            OPENAT2.get(),
            Openat2Status::Unknown | Openat2Status::Available
        ) {
            let result = rustix::fs::openat2(
                &root.fd,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH,
            );
            let _ = root
                .clone_with(Resolver::Openat2)
                .and_then(|probe| probe.after_openat2(&OPENAT2, result, &[]));
        }
        OPENAT2.get()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = root;
        Openat2Status::Unavailable
    }
}

/// Whether the running kernel resolves paths with `openat2` (always `false`
/// off Linux). See [`probe_openat2`].
pub fn openat2_available(root: &Root) -> bool {
    probe_openat2(root) == Openat2Status::Available
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_path_rules() {
        for (path, reason) in [
            ("", "empty_path"),
            ("/etc/passwd", "absolute_path"),
            ("a//b", "empty_component"),
            ("a/", "empty_component"),
            ("..", "dot_component"),
            ("a/../b", "dot_component"),
            ("./a", "dot_component"),
            ("a\0b", "nul_byte"),
        ] {
            match split_relative(path) {
                Err(ConfineError::InvalidPath(got)) => assert_eq!(got, reason, "{path:?}"),
                other => panic!("{path:?} gave {other:?}"),
            }
        }
        let long = "x".repeat(MAX_COMPONENT_BYTES + 1);
        assert!(matches!(
            split_relative(&long),
            Err(ConfineError::InvalidPath("component_too_long"))
        ));
        let (dirs, name) = split_relative("a/b/c.txt").unwrap();
        assert_eq!((dirs, name), (vec!["a", "b"], "c.txt"));
    }

    struct TempRoot(std::path::PathBuf);

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_root() -> TempRoot {
        let path = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("praetore-sandbox-fs-unit-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(path.join("d")).unwrap();
        std::os::unix::fs::symlink(std::env::temp_dir(), path.join("link")).unwrap();
        TempRoot(path)
    }

    #[test]
    fn openat2_enosys_falls_back_only_in_auto_and_is_recorded_once() {
        let tree = temp_root();
        let state = Openat2State::new();
        let auto = Root::open(&tree.0).unwrap();
        assert_eq!(state.get(), Openat2Status::Unknown);
        // Auto: ENOSYS -> portable walk, which still refuses symlinks.
        let dir = auto.after_openat2(&state, Err(Errno::NOSYS), &["d"]);
        assert!(dir.is_ok(), "{dir:?}");
        assert!(matches!(
            auto.after_openat2(&state, Err(Errno::NOSYS), &["link"]),
            Err(ConfineError::SymlinkOrNotDirectory)
        ));
        assert_eq!(state.get(), Openat2Status::Unavailable);
        // Logged once: only the first transition reports `true`.
        assert!(!state.record(Openat2Status::Unavailable));
        assert!(!state.record(Openat2Status::Denied));
        assert_eq!(state.get(), Openat2Status::Unavailable);
        // Openat2 required: ENOSYS is a refusal, never a walk.
        let required = auto.clone_with(Resolver::Openat2).unwrap();
        assert!(matches!(
            required.after_openat2(&state, Err(Errno::NOSYS), &["d"]),
            Err(ConfineError::Openat2Unavailable)
        ));
    }

    #[test]
    fn openat2_eperm_is_a_permanent_refusal_in_every_openat2_resolver() {
        let tree = temp_root();
        for resolver in [Resolver::Auto, Resolver::Openat2] {
            let state = Openat2State::new();
            let root = Root::open(&tree.0).unwrap().with_resolver(resolver);
            let error = root
                .after_openat2(&state, Err(Errno::PERM), &["d"])
                .unwrap_err();
            assert!(matches!(error, ConfineError::Openat2Denied), "{error:?}");
            assert!(!error.is_transient());
            assert_eq!(state.get(), Openat2Status::Denied);
            assert!(!state.record(Openat2Status::Denied));
        }
        // Other errors keep their usual classification.
        let state = Openat2State::new();
        let root = Root::open(&tree.0).unwrap();
        assert!(matches!(
            root.after_openat2(&state, Err(Errno::LOOP), &["d"]),
            Err(ConfineError::SymlinkOrNotDirectory)
        ));
        assert!(matches!(
            root.after_openat2(&state, Err(Errno::XDEV), &["d"]),
            Err(ConfineError::CrossesBoundary)
        ));
        assert!(
            root.after_openat2(&state, Err(Errno::AGAIN), &["d"])
                .unwrap_err()
                .is_transient()
        );
        assert_eq!(state.get(), Openat2Status::Unknown);
    }

    #[test]
    fn temp_prefix_is_reserved_case_insensitively() {
        for path in [
            ".praetore-tmp-x",
            ".PRAETORE-TMP-x",
            "d/.Praetore-Tmp-y",
            ".praetore-tmp-dir/file",
        ] {
            assert!(
                matches!(
                    split_relative(path),
                    Err(ConfineError::InvalidPath("reserved_name"))
                ),
                "{path:?}"
            );
        }
        assert!(split_relative("d/praetore-tmp-x").is_ok());
        assert!(split_relative("d/.praetore-tmp").is_ok());
        assert!(is_temp_name(b".PRAETORE-tmp-"));
        assert!(!is_temp_name(b".praetore-tm"));
    }
}
