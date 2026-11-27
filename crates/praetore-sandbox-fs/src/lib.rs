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
//! # Directories between the root and the target
//!
//! A process that can rename a directory inside the root *and* write to a
//! directory outside it on the same filesystem can move a directory that
//! this crate has already opened out of the root while one operation is in
//! flight; the effect then lands in the moved directory (the temporary file
//! of [`Root::write_file`] is visible to `readdir`, which gives such a
//! process an exact signal). Two measures bound this:
//!
//! - **Directory check** ([`Root::with_directory_check`]). The caller
//!   supplies the ownership and mode rule it already applies to the root;
//!   this crate applies it to every directory between the root and the
//!   target's parent, both included. In the portable walk each component is
//!   `fstat`ed as it is opened; after `openat2` the parent is walked back up
//!   with `openat(fd, "..", O_DIRECTORY | O_NOFOLLOW)` exactly as many steps
//!   as the path has directories, checking each one, and the walk must end
//!   at the root's `(st_dev, st_ino)` ([`ConfineError::NotBeneathRoot`]
//!   otherwise). A directory that fails the rule is
//!   [`ConfineError::InsecureDirectory`]. With a rule such as "owned by this
//!   user and not group/other-writable", no other local user can rename
//!   anything on the way to the target.
//! - **Confirmation after the effect.** Once the `renameat` or `unlinkat`
//!   has happened, the path is resolved again from the root and the parent
//!   reached must be the directory the effect used (same `st_dev`/`st_ino`)
//!   and hold the expected entry. A write or delete whose directory was
//!   moved out of the root meanwhile is reported with
//!   [`Unconfirmed::ParentNotAtPath`], never as confirmed. The effect is not
//!   undone; the result says so.
//!
//! Not prevented (documented residual risks):
//!
//! - **Rename out of the root by a process the directory check admits.**
//!   The directory check is the caller's rule; a process it does not
//!   exclude (the same user, or root) can still move an opened directory
//!   out between the check and the effect. The result is then
//!   unconfirmed, as above.
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
//!   follows it) and the call returns a [`Written`] with
//!   [`Unconfirmed::EntryMismatch`]. No file outside the root is written;
//!   that process could have created the same symlink directly.
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
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use thiserror::Error;

/// The caller's rule for every directory between the root and the target's
/// parent (both included): `true` admits the directory. It receives the
/// directory's descriptor (for checks the `Stat` does not show, such as
/// extended ACL entries) and its `fstat`. See [`Root::with_directory_check`].
pub type DirectoryCheck = Arc<dyn Fn(BorrowedFd<'_>, &Stat) -> bool + Send + Sync>;

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
    /// A directory between the root and the target's parent fails the
    /// caller's [`DirectoryCheck`].
    #[error("a directory on the path fails the directory check")]
    InsecureDirectory,
    /// Walking up from the parent directory with `..` did not reach the
    /// root in as many steps as the path has directories: the parent is not
    /// (or no longer) beneath the root.
    #[error("the parent directory is not beneath the root")]
    NotBeneathRoot,
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

/// Why an effect that did happen is not confirmed. The effect is not undone;
/// the caller reports it as executed, never as confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unconfirmed {
    /// `fsync` of the parent directory failed.
    DirectorySyncFailed,
    /// Resolving the path again from the root did not reach the directory
    /// the effect used: it was moved, replaced or left the root meanwhile.
    ParentNotAtPath,
    /// The parent is the same directory but the entry is not what the
    /// effect left there (a write: another inode or size; a delete: an
    /// entry is present).
    EntryMismatch,
}

impl Unconfirmed {
    /// Stable code for results and receipts.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectorySyncFailed => "directory_sync_failed",
            Self::ParentNotAtPath => "parent_not_at_path",
            Self::EntryMismatch => "entry_mismatch",
        }
    }
}

/// Result of [`Root::write_file`]. Returned only once the target entry was
/// replaced; any `Err` means the target directory entry was not changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Written {
    pub bytes: usize,
    /// `None`: the directory was `fsync`ed and, resolved again from the
    /// root, the path names this directory and the entry names the new
    /// inode.
    pub unconfirmed: Option<Unconfirmed>,
}

impl Written {
    pub fn confirmed(&self) -> bool {
        self.unconfirmed.is_none()
    }
}

/// Result of [`Root::remove_file`], [`Root::unlink_in`] and
/// [`Dir::unlink_file`]. Returned only once the entry was unlinked. An `Err`
/// before the `unlinkat` call (a path or entry check) means nothing was
/// removed; an `Err` from the call itself does not prove that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Removed {
    /// `None`: the directory was `fsync`ed and the entry is gone (through
    /// [`Root`], also: resolved again from the root, the path names this
    /// directory).
    pub unconfirmed: Option<Unconfirmed>,
}

impl Removed {
    pub fn confirmed(&self) -> bool {
        self.unconfirmed.is_none()
    }
}

/// An open directory descriptor that every effect is relative to.
pub struct Root {
    fd: OwnedFd,
    stat: Stat,
    resolver: Resolver,
    directory_check: Option<DirectoryCheck>,
}

impl std::fmt::Debug for Root {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Root")
            .field("fd", &self.fd)
            .field("resolver", &self.resolver)
            .field("directory_check", &self.directory_check.is_some())
            .finish_non_exhaustive()
    }
}

fn same_inode(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
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
            directory_check: None,
        })
    }

    /// A second handle on the same root directory with another resolver
    /// (same directory check).
    pub fn clone_with(&self, resolver: Resolver) -> Result<Self, ConfineError> {
        let fd = rustix::io::fcntl_dupfd_cloexec(&self.fd, 0)
            .map_err(|errno| ConfineError::RootUnavailable(errno.into()))?;
        let mut root = Self::from_fd(fd)?.with_resolver(resolver);
        root.directory_check = self.directory_check.clone();
        Ok(root)
    }

    pub fn with_resolver(mut self, resolver: Resolver) -> Self {
        self.resolver = resolver;
        self
    }

    /// Applies `check` to every directory between the root and the target's
    /// parent, both included, on every path resolution (see the crate
    /// documentation). Without it, only the root's identity is checked.
    pub fn with_directory_check(mut self, check: DirectoryCheck) -> Self {
        self.directory_check = Some(check);
        self
    }

    pub fn set_directory_check(&mut self, check: Option<DirectoryCheck>) {
        self.directory_check = check;
    }

    pub fn has_directory_check(&self) -> bool {
        self.directory_check.is_some()
    }

    fn check_directory(&self, fd: BorrowedFd<'_>, stat: &Stat) -> Result<(), ConfineError> {
        match &self.directory_check {
            Some(check) if !check(fd, stat) => Err(ConfineError::InsecureDirectory),
            _ => Ok(()),
        }
    }

    /// After a single `openat2` resolution: `dir` must be exactly `depth`
    /// directories below the root. Each `..` step is checked with the
    /// directory check and must stay on the root's device; the walk must
    /// end at the root's inode.
    fn verify_lineage(&self, dir: &Dir, depth: usize) -> Result<(), ConfineError> {
        self.check_directory(dir.fd.as_fd(), &dir.stat)?;
        let mut current = rustix::io::fcntl_dupfd_cloexec(&dir.fd, 0)
            .map_err(|errno| ConfineError::ParentUnavailable(errno.into()))?;
        let mut stat = dir.stat;
        for _ in 0..depth {
            if same_inode(&stat, &self.stat) {
                // The root was reached too early: `dir` is not where the
                // path says.
                return Err(ConfineError::NotBeneathRoot);
            }
            let parent = rustix::fs::openat(
                &current,
                "..",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(directory_error)?;
            let parent_stat = rustix::fs::fstat(&parent)
                .map_err(|errno| ConfineError::ParentUnavailable(errno.into()))?;
            if parent_stat.st_dev != self.stat.st_dev {
                return Err(ConfineError::CrossesBoundary);
            }
            self.check_directory(parent.as_fd(), &parent_stat)?;
            current = parent;
            stat = parent_stat;
        }
        if same_inode(&stat, &self.stat) {
            Ok(())
        } else {
            Err(ConfineError::NotBeneathRoot)
        }
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
            let dir = self.dir_from(fd)?;
            self.check_directory(dir.fd.as_fd(), &dir.stat)?;
            dir
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
                let dir = self.dir_from(fd)?;
                self.verify_lineage(&dir, components.len())?;
                Ok(dir)
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
            self.check_directory(next.as_fd(), &stat)?;
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
        let unconfirmed = if rustix::fs::fsync(&dir.fd).is_err() {
            Some(Unconfirmed::DirectorySyncFailed)
        } else {
            self.verify_entry(path, &dir, Some(&temp_stat)).err()
        };
        Ok(Written {
            bytes: content.len(),
            unconfirmed,
        })
    }

    /// Resolves `path` again from the root (directory check included) and
    /// confirms that its parent is `parent` (same `st_dev`/`st_ino`) and
    /// that the entry is `expected`: the same inode and size when `Some`,
    /// absent when `None`. This is the confirmation step of
    /// [`Root::write_file`] and [`Root::unlink_in`].
    pub fn verify_entry(
        &self,
        path: &str,
        parent: &Dir,
        expected: Option<&Stat>,
    ) -> Result<(), Unconfirmed> {
        let (resolved, name) = self
            .open_parent(path)
            .map_err(|_| Unconfirmed::ParentNotAtPath)?;
        if !same_inode(&resolved.stat, &parent.stat) {
            return Err(Unconfirmed::ParentNotAtPath);
        }
        let entry = resolved
            .stat_entry(name)
            .map_err(|_| Unconfirmed::EntryMismatch)?;
        match (entry, expected) {
            (None, None) => Ok(()),
            (Some(entry), Some(expected))
                if same_inode(&entry, expected) && entry.st_size == expected.st_size =>
            {
                Ok(())
            }
            _ => Err(Unconfirmed::EntryMismatch),
        }
    }

    /// The `unlinkat(parent, name, 0)` of a checked delete, then the
    /// confirmation of [`Root::verify_entry`]. `parent` and `name` come from
    /// [`Root::open_parent`] on the same `path`, so a caller can keep its
    /// own checks between resolving and unlinking.
    pub fn unlink_in(&self, path: &str, parent: &Dir, name: &str) -> Result<Removed, ConfineError> {
        let removed = parent.unlink_file(name)?;
        if removed.unconfirmed.is_some() {
            return Ok(removed);
        }
        Ok(Removed {
            unconfirmed: self.verify_entry(path, parent, None).err(),
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
        self.unlink_in(path, &dir, name)
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

    /// `unlinkat(fd, name, 0)` without any check of the entry (callers run
    /// [`Dir::check_entry`] first), then `fsync` of this directory. Never
    /// removes a directory. An `Err` comes from the `unlinkat` call itself,
    /// so it does not prove that the entry is still there: `ENOENT`, for
    /// example, is reported as [`ConfineError::NotFound`] whatever removed
    /// the entry.
    pub fn unlink_file(&self, name: &str) -> Result<Removed, ConfineError> {
        check_component(name)?;
        rustix::fs::unlinkat(&self.fd, name, AtFlags::empty()).map_err(|errno| {
            if errno == Errno::NOENT {
                ConfineError::NotFound
            } else {
                final_error(errno)
            }
        })?;
        let unconfirmed = if rustix::fs::fsync(&self.fd).is_err() {
            Some(Unconfirmed::DirectorySyncFailed)
        } else if matches!(self.stat_entry(name), Ok(None)) {
            None
        } else {
            Some(Unconfirmed::EntryMismatch)
        };
        Ok(Removed { unconfirmed })
    }

    /// This directory's `fstat`, taken when it was opened.
    pub fn stat(&self) -> &Stat {
        &self.stat
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

    /// The `..` walk after `openat2`, exercised directly so it is tested on
    /// every platform: it reaches the root in exactly `depth` steps from a
    /// parent that is where the path says, and reports `NotBeneathRoot`
    /// once that parent has been moved out of the root.
    #[test]
    fn lineage_walk_reaches_the_root_and_detects_a_parent_moved_out() {
        let tree = temp_root();
        std::fs::create_dir_all(tree.0.join("d/e")).unwrap();
        let outside = tree.0.parent().unwrap().join(format!(
            "praetore-sandbox-fs-unit-outside-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&outside).unwrap();
        let root = Root::open(&tree.0).unwrap().with_resolver(Resolver::Walk);
        let (dir, name) = root.open_parent("d/e/f").unwrap();
        assert_eq!(name, "f");
        root.verify_lineage(&dir, 2).unwrap();
        // Wrong depth: the walk ends above or below the root.
        assert!(matches!(
            root.verify_lineage(&dir, 1),
            Err(ConfineError::NotBeneathRoot)
        ));
        assert!(matches!(
            root.verify_lineage(&dir, 3),
            Err(ConfineError::NotBeneathRoot)
        ));
        // Depth 0 is the root itself.
        let (top, _) = root.open_parent("f").unwrap();
        root.verify_lineage(&top, 0).unwrap();
        // Moved out: the descriptor is still open, the lineage is not.
        std::fs::rename(tree.0.join("d/e"), outside.join("e")).unwrap();
        assert!(matches!(
            root.verify_lineage(&dir, 2),
            Err(ConfineError::NotBeneathRoot)
        ));
        // And the confirmation step says so for a write that used it.
        assert_eq!(
            root.verify_entry("d/e/f", &dir, None),
            Err(Unconfirmed::ParentNotAtPath)
        );
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// The directory check runs on each `..` step of the lineage walk and on
    /// the parent itself; the directory that fails it is refused as
    /// `InsecureDirectory` even when the lineage is otherwise right.
    #[test]
    fn lineage_walk_applies_the_directory_check_to_every_step() {
        let tree = temp_root();
        std::fs::create_dir_all(tree.0.join("d/e")).unwrap();
        std::fs::set_permissions(tree.0.join("d"), Permissions::from_mode(0o777)).unwrap();
        let strict: DirectoryCheck = Arc::new(|_, stat: &Stat| {
            !Mode::from_raw_mode(stat.st_mode).intersects(Mode::WGRP | Mode::WOTH)
        });
        let root = Root::open(&tree.0)
            .unwrap()
            .with_resolver(Resolver::Walk)
            .with_directory_check(strict);
        // The walk itself refuses `d`.
        assert!(matches!(
            root.open_parent("d/e/f"),
            Err(ConfineError::InsecureDirectory)
        ));
        // Through a root without the check, then the lineage walk with it.
        let lax = Root::open(&tree.0).unwrap().with_resolver(Resolver::Walk);
        let (dir, _) = lax.open_parent("d/e/f").unwrap();
        assert!(matches!(
            root.verify_lineage(&dir, 2),
            Err(ConfineError::InsecureDirectory)
        ));
        std::fs::set_permissions(tree.0.join("d"), Permissions::from_mode(0o755)).unwrap();
        root.verify_lineage(&dir, 2).unwrap();
        assert!(root.open_parent("d/e/f").is_ok());
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
