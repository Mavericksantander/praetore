//! Filesystem sandbox adapter executed by the gateway itself.
//!
//! [`SandboxDispatcher`] implements [`ActionDispatcher`] for a closed
//! allowlist of two actions, confined to one canonical root directory:
//!
//! | `action_type`    | capability  | parameters                 |
//! |------------------|-------------|----------------------------|
//! | `fs:write_file`  | `fs:write`  | `{"path", "content"}`      |
//! | `fs:delete_file` | `fs:delete` | `{"path"}`                 |
//!
//! Both require the configured target (default `sandbox`). Optionally the
//! existing in-memory `demo:set_value` adapter is kept unchanged. Anything
//! else is refused in [`ActionDispatcher::preflight`], so the gateway records
//! it as `not_dispatched` instead of `outcome_unknown`. There is no `exec`.
//!
//! # Confinement
//!
//! Confinement does not rely on string checks alone:
//!
//! - The root must be an absolute, canonical, existing directory (not `/`),
//!   owned by the gateway's effective user and not writable by group or
//!   others. It is opened once as a directory file descriptor and its
//!   device/inode is checked against the path. Before every preflight and
//!   dispatch the path is checked again to still name that same directory;
//!   if the root was renamed or replaced, the action is refused (fail closed).
//! - Paths are validated lexically first: relative only, no `.`/`..`, no
//!   empty components, no NUL/control characters, no `\`, no Unicode
//!   bidirectional or zero-width format characters, bounded length and depth.
//! - Every component is then resolved with `openat(2)` relative to the
//!   previous directory descriptor using `O_NOFOLLOW | O_DIRECTORY`, so a
//!   symlink at any level fails instead of being followed, and the kernel
//!   never resolves `..`. A component on another device (a mount point) is
//!   refused. Intermediate directories are never created.
//! - The final component must be absent (write) or a regular file with a
//!   single link (write and delete); symlinks, hard links, directories,
//!   FIFOs, sockets and devices are refused.
//!
//! # Effects
//!
//! - `fs:write_file` is atomic: the content is written to a fresh
//!   `O_CREAT | O_EXCL | O_NOFOLLOW` temporary file (mode `0600`) in the
//!   target's directory, `fsync`ed, and `renameat`ed over the target, then
//!   the directory is `fsync`ed. `renameat` replaces the directory entry and
//!   never opens or follows what was there, so even a target swapped for a
//!   symlink, hard link or special file after the checks cannot redirect the
//!   write outside the root. Replaced files get mode `0600` and the gateway
//!   user as owner. Content is limited (16 KiB by default).
//! - `fs:delete_file` uses `unlinkat(…, 0)` on the parent descriptor, which
//!   never removes a directory and removes a symlink itself, never its target.
//!
//! Residual risks (documented, not solved here): a process that can rename
//! directories inside the root *and* write outside it can move an already
//! opened directory out of the root while a single operation is in flight;
//! there is no quota on the number of files; and idempotency/reconciliation
//! records are kept in memory and are lost on restart, like the local demo
//! adapter.

use crate::{
    ActionDispatcher, DispatchError, DispatchRefused, DispatchReport, ExecutionKey,
    ReconciliationReport, local_demo::LocalDemoDispatcher,
};
use praetore_core::{Action, Authority};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    ffi::CString,
    fs::File,
    io::{self, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::Mutex,
};
use thiserror::Error;

pub const WRITE_ACTION: &str = "fs:write_file";
pub const DELETE_ACTION: &str = "fs:delete_file";
pub const WRITE_CAPABILITY: &str = "fs:write";
pub const DELETE_CAPABILITY: &str = "fs:delete";
pub const DEFAULT_TARGET: &str = "sandbox";
/// Default maximum file content accepted by `fs:write_file` (16 KiB).
pub const DEFAULT_MAX_CONTENT_BYTES: usize = 16_384;
/// Upper bound for a configured limit. Requests are already capped at 64 KiB
/// by the HTTP layer and by PRÆTORE's canonical JSON value limit.
pub const MAX_CONTENT_BYTES_LIMIT: usize = 32_768;
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_COMPONENT_BYTES: usize = 255;
pub const MAX_PATH_DEPTH: usize = 16;
/// Prefix of the temporary files used for atomic writes. Paths whose final
/// component starts with it are refused, so an action can never target one.
pub const TEMP_PREFIX: &str = ".praetore-tmp-";
/// Mode of every file created or replaced by `fs:write_file`.
pub const FILE_MODE: u32 = 0o600;

#[derive(Debug, Error)]
pub enum SandboxConfigError {
    #[error("sandbox root must be an absolute path")]
    NotAbsolute,
    #[error("sandbox root must not be a symlink")]
    Symlink,
    #[error("sandbox root is not a directory")]
    NotDirectory,
    #[error("sandbox root must be canonical (no symlinks, `.` or `..`): {0}")]
    NotCanonical(PathBuf),
    #[error("sandbox root must not be the filesystem root")]
    FilesystemRoot,
    #[error("sandbox root must be owned by the gateway user")]
    NotOwned,
    #[error("sandbox root must not be writable by group or others")]
    InsecurePermissions,
    #[error("sandbox root changed while it was being opened")]
    Replaced,
    #[error("sandbox root is not accessible: {0}")]
    Io(#[from] io::Error),
    #[error("sandbox content limit must be between 1 byte and 32 KiB")]
    InvalidLimit,
}

/// What the adapter knows about one execution key, for idempotency and
/// read-only reconciliation.
#[derive(Default)]
struct Records {
    /// Effects performed: action digest and output.
    executions: HashMap<ExecutionKey, (String, Value)>,
    /// Dispatches that failed before any change to the target: digest.
    not_applied: HashMap<ExecutionKey, String>,
}

pub struct SandboxDispatcher {
    root: PathBuf,
    c_root: CString,
    root_fd: OwnedFd,
    root_dev: libc::dev_t,
    root_ino: libc::ino_t,
    target: String,
    max_content_bytes: usize,
    demo: Option<LocalDemoDispatcher>,
    records: Mutex<Records>,
}

enum FsOp<'a> {
    Write { path: &'a str, content: &'a str },
    Delete { path: &'a str },
}

/// A dispatch attempt that failed before anything changed at the target, so
/// reconciliation may truthfully report `NotApplied`. Every failure after
/// the effect point (`renameat`/`unlinkat`) is reported as success with
/// `Executed` instead, because the effect did happen.
struct BeforeEffect;

impl SandboxDispatcher {
    /// Opens `root` fail-closed: it must exist and be an absolute, canonical,
    /// non-symlink directory other than `/`, owned by the effective user and
    /// not writable by group or others. The directory is held open for the
    /// lifetime of the dispatcher; if the path later stops naming that same
    /// directory, every action is refused.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, SandboxConfigError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(SandboxConfigError::NotAbsolute);
        }
        let c_root = CString::new(root.as_os_str().as_bytes())
            .map_err(|_| SandboxConfigError::NotCanonical(root.to_path_buf()))?;
        let metadata = std::fs::symlink_metadata(root)?;
        if metadata.file_type().is_symlink() {
            return Err(SandboxConfigError::Symlink);
        }
        if !metadata.is_dir() {
            return Err(SandboxConfigError::NotDirectory);
        }
        let canonical = std::fs::canonicalize(root)?;
        if canonical != root {
            return Err(SandboxConfigError::NotCanonical(canonical));
        }
        if canonical.parent().is_none() {
            return Err(SandboxConfigError::FilesystemRoot);
        }
        let before = fstatat_nofollow(libc::AT_FDCWD, &c_root)?;
        // SAFETY: valid NUL-terminated path; the returned fd is owned below.
        let fd = unsafe {
            libc::open(
                c_root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: `fd` is a freshly opened descriptor owned by nobody else.
        let root_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // The descriptor, not the path, is authoritative: it must be the
        // directory that was inspected above (no swap during the checks).
        let stat = fstat(root_fd.as_raw_fd())?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(SandboxConfigError::NotDirectory);
        }
        let (root_dev, root_ino) = (stat.st_dev, stat.st_ino);
        if before.st_mode & libc::S_IFMT != libc::S_IFDIR
            || root_dev != before.st_dev
            || root_ino != before.st_ino
        {
            return Err(SandboxConfigError::Replaced);
        }
        // SAFETY: geteuid has no preconditions.
        if stat.st_uid != unsafe { libc::geteuid() } {
            return Err(SandboxConfigError::NotOwned);
        }
        if stat.st_mode & 0o022 != 0 {
            return Err(SandboxConfigError::InsecurePermissions);
        }
        Ok(Self {
            root: canonical,
            c_root,
            root_fd,
            root_dev,
            root_ino,
            target: DEFAULT_TARGET.into(),
            max_content_bytes: DEFAULT_MAX_CONTENT_BYTES,
            demo: None,
            records: Mutex::new(Records::default()),
        })
    }

    pub fn with_max_content_bytes(mut self, limit: usize) -> Result<Self, SandboxConfigError> {
        if limit == 0 || limit > MAX_CONTENT_BYTES_LIMIT {
            return Err(SandboxConfigError::InvalidLimit);
        }
        self.max_content_bytes = limit;
        Ok(self)
    }

    /// Keeps the existing in-memory `demo:set_value` adapter available.
    pub fn with_local_demo(mut self, demo: LocalDemoDispatcher) -> Self {
        self.demo = Some(demo);
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Validates the action shape. Pure: no filesystem access.
    fn parse<'a>(&self, action: &'a Action) -> Result<FsOp<'a>, DispatchRefused> {
        let (capability, keys): (&str, &[&str]) = match action.action_type.as_str() {
            WRITE_ACTION => (WRITE_CAPABILITY, &["content", "path"]),
            DELETE_ACTION => (DELETE_CAPABILITY, &["path"]),
            _ => return Err(DispatchRefused("action_not_in_sandbox_allowlist")),
        };
        if action.capability.as_deref() != Some(capability) {
            return Err(DispatchRefused("capability_mismatch"));
        }
        if action.target.as_deref() != Some(self.target.as_str()) {
            return Err(DispatchRefused("target_mismatch"));
        }
        let parameters = action
            .parameters
            .as_object()
            .ok_or(DispatchRefused("invalid_parameters"))?;
        let mut present: Vec<&str> = parameters.keys().map(String::as_str).collect();
        present.sort_unstable();
        if present != keys {
            return Err(DispatchRefused("invalid_parameters"));
        }
        let path = parameters
            .get("path")
            .and_then(Value::as_str)
            .ok_or(DispatchRefused("invalid_path"))?;
        validate_relative_path(path)?;
        if action.action_type == WRITE_ACTION {
            let content = parameters
                .get("content")
                .and_then(Value::as_str)
                .ok_or(DispatchRefused("invalid_content"))?;
            if content.len() > self.max_content_bytes {
                return Err(DispatchRefused("content_too_large"));
            }
            Ok(FsOp::Write { path, content })
        } else {
            Ok(FsOp::Delete { path })
        }
    }

    /// Fails closed when the configured path no longer names the directory
    /// opened at startup (renamed, removed or replaced, including by a
    /// symlink).
    fn check_root_unchanged(&self) -> Result<(), DispatchRefused> {
        match fstatat_nofollow(libc::AT_FDCWD, &self.c_root) {
            Ok(stat)
                if stat.st_mode & libc::S_IFMT == libc::S_IFDIR
                    && stat.st_dev == self.root_dev
                    && stat.st_ino == self.root_ino =>
            {
                Ok(())
            }
            _ => Err(DispatchRefused("sandbox_root_replaced")),
        }
    }

    /// Walks every intermediate component without following symlinks or
    /// crossing mount points and returns the parent directory fd plus the
    /// final component name.
    fn open_parent(&self, path: &str) -> Result<(OwnedFd, CString), DispatchRefused> {
        self.check_root_unchanged()?;
        let components: Vec<&str> = path.split('/').collect();
        let (name, directories) = components
            .split_last()
            .ok_or(DispatchRefused("invalid_path"))?;
        let mut current = dup(self.root_fd.as_raw_fd())?;
        for directory in directories {
            let c = c_component(directory)?;
            // SAFETY: `current` is a valid directory fd; `c` is NUL-terminated.
            let fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(match io::Error::last_os_error().raw_os_error() {
                    Some(libc::ELOOP) | Some(libc::ENOTDIR) => {
                        DispatchRefused("symlink_or_non_directory_in_path")
                    }
                    Some(libc::ENOENT) => DispatchRefused("parent_directory_missing"),
                    _ => DispatchRefused("parent_directory_unavailable"),
                });
            }
            // SAFETY: freshly opened, exclusively owned.
            current = unsafe { OwnedFd::from_raw_fd(fd) };
            let stat = fstat(current.as_raw_fd())
                .map_err(|_| DispatchRefused("parent_directory_unavailable"))?;
            if stat.st_dev != self.root_dev {
                return Err(DispatchRefused("mount_point_in_path"));
            }
        }
        Ok((current, c_component(name)?))
    }

    /// Side-effect-free inspection of the final component.
    fn check_final(&self, op: &FsOp<'_>) -> Result<(), DispatchRefused> {
        let path = match op {
            FsOp::Write { path, .. } | FsOp::Delete { path } => path,
        };
        let (parent, name) = self.open_parent(path)?;
        check_entry(parent.as_raw_fd(), &name, matches!(op, FsOp::Write { .. }))
    }

    fn admit(&self, action: &Action) -> Result<(), DispatchRefused> {
        if action.action_type == "demo:set_value" && self.demo.is_some() {
            return Ok(());
        }
        let op = self.parse(action)?;
        self.check_final(&op)
    }

    fn perform(&self, op: &FsOp<'_>) -> Result<DispatchReport, BeforeEffect> {
        match op {
            FsOp::Write { path, content } => {
                let (parent, name) = self.open_parent(path).map_err(|_| BeforeEffect)?;
                let dirfd = parent.as_raw_fd();
                check_entry(dirfd, &name, true).map_err(|_| BeforeEffect)?;
                let temp = CString::new(format!("{TEMP_PREFIX}{}", uuid::Uuid::new_v4().simple()))
                    .map_err(|_| BeforeEffect)?;
                // SAFETY: valid dirfd and NUL-terminated name. O_EXCL and
                // O_NOFOLLOW guarantee a brand-new regular file.
                let fd = unsafe {
                    libc::openat(
                        dirfd,
                        temp.as_ptr(),
                        libc::O_WRONLY
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        FILE_MODE as libc::c_uint,
                    )
                };
                if fd < 0 {
                    return Err(BeforeEffect);
                }
                // SAFETY: freshly opened, exclusively owned.
                let mut file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
                let prepared = (|| {
                    // SAFETY: valid fd. Makes the mode independent of umask.
                    if unsafe { libc::fchmod(file.as_raw_fd(), FILE_MODE as libc::mode_t) } != 0 {
                        return Err(());
                    }
                    file.write_all(content.as_bytes()).map_err(|_| ())?;
                    file.sync_all().map_err(|_| ())?;
                    let stat = fstat(file.as_raw_fd()).map_err(|_| ())?;
                    if stat.st_size as u64 != content.len() as u64 {
                        return Err(());
                    }
                    // Re-check right before the rename (narrows, does not
                    // need to close, the window: rename never follows).
                    check_entry(dirfd, &name, true).map_err(|_| ())?;
                    Ok(stat)
                })();
                let temp_stat = match prepared {
                    Ok(stat) => stat,
                    Err(()) => {
                        unlink_quietly(dirfd, &temp);
                        return Err(BeforeEffect);
                    }
                };
                // SAFETY: valid dirfds and NUL-terminated names.
                if unsafe { libc::renameat(dirfd, temp.as_ptr(), dirfd, name.as_ptr()) } != 0 {
                    unlink_quietly(dirfd, &temp);
                    return Err(BeforeEffect);
                }
                // SAFETY: valid directory fd.
                let synced = unsafe { libc::fsync(dirfd) } == 0;
                let output = json!({
                    "action": WRITE_ACTION,
                    "path": path,
                    "bytes": content.len(),
                    "sha256": hex::encode(Sha256::digest(content.as_bytes())),
                });
                let confirmed = synced
                    && fstatat_nofollow(dirfd, &name).is_ok_and(|stat| {
                        stat.st_dev == temp_stat.st_dev
                            && stat.st_ino == temp_stat.st_ino
                            && stat.st_size == temp_stat.st_size
                    });
                Ok(if confirmed {
                    DispatchReport::Confirmed(output)
                } else {
                    DispatchReport::Executed(output)
                })
            }
            FsOp::Delete { path } => {
                let (parent, name) = self.open_parent(path).map_err(|_| BeforeEffect)?;
                let dirfd = parent.as_raw_fd();
                check_entry(dirfd, &name, false).map_err(|_| BeforeEffect)?;
                // SAFETY: valid dirfd and NUL-terminated name. Flag 0 never
                // removes a directory and removes a symlink, not its target.
                if unsafe { libc::unlinkat(dirfd, name.as_ptr(), 0) } != 0 {
                    return Err(BeforeEffect);
                }
                // SAFETY: valid directory fd.
                let synced = unsafe { libc::fsync(dirfd) } == 0;
                let output = json!({"action": DELETE_ACTION, "path": path});
                match fstatat_nofollow(dirfd, &name) {
                    Err(error) if synced && error.raw_os_error() == Some(libc::ENOENT) => {
                        Ok(DispatchReport::Confirmed(output))
                    }
                    _ => Ok(DispatchReport::Executed(output)),
                }
            }
        }
    }
}

impl ActionDispatcher for SandboxDispatcher {
    fn dispatch(
        &self,
        key: ExecutionKey,
        authority: &Authority,
        action: &Action,
        action_digest: &str,
    ) -> Result<DispatchReport, DispatchError> {
        if action.action_type == "demo:set_value" {
            return match &self.demo {
                Some(demo) => demo.dispatch(key, authority, action, action_digest),
                None => Err(DispatchError),
            };
        }
        if crate::action_digest(action).map_or(true, |digest| digest != action_digest) {
            return Err(DispatchError);
        }
        // The lock serializes sandbox effects and makes key reuse idempotent.
        let mut records = self.records.lock().map_err(|_| DispatchError)?;
        if let Some((digest, output)) = records.executions.get(&key) {
            return if digest == action_digest {
                Ok(DispatchReport::Confirmed(output.clone()))
            } else {
                Err(DispatchError)
            };
        }
        if records.not_applied.contains_key(&key) {
            // A key is dispatched at most once by the gateway; never retry.
            return Err(DispatchError);
        }
        let result = match self.parse(action) {
            Ok(op) => self.perform(&op),
            Err(_) => Err(BeforeEffect),
        };
        match result {
            Ok(report) => {
                let output = match &report {
                    DispatchReport::Executed(output) | DispatchReport::Confirmed(output) => {
                        output.clone()
                    }
                };
                records
                    .executions
                    .insert(key, (action_digest.to_owned(), output));
                Ok(report)
            }
            Err(BeforeEffect) => {
                records.not_applied.insert(key, action_digest.to_owned());
                Err(DispatchError)
            }
        }
    }

    fn reconcile(
        &self,
        key: ExecutionKey,
        authority: &Authority,
        action: &Action,
        action_digest: &str,
    ) -> ReconciliationReport {
        if action.action_type == "demo:set_value" {
            return match &self.demo {
                Some(demo) => demo.reconcile(key, authority, action, action_digest),
                None => ReconciliationReport::Unknown,
            };
        }
        let Ok(records) = self.records.lock() else {
            return ReconciliationReport::Unknown;
        };
        match records.executions.get(&key) {
            Some((digest, output)) if digest == action_digest => {
                ReconciliationReport::Applied(output.clone())
            }
            Some(_) => ReconciliationReport::Unknown,
            None => match records.not_applied.get(&key) {
                Some(digest) if digest == action_digest => ReconciliationReport::NotApplied,
                _ => ReconciliationReport::Unknown,
            },
        }
    }

    fn preflight(&self, action: &Action) -> Result<(), DispatchRefused> {
        self.admit(action)
    }
}

/// Accepts only `name(/name)*` with each name a normal, non-empty component.
/// Rejects absolute paths, `.`/`..`, empty components (`a//b`, trailing `/`),
/// NUL and control characters (C0, DEL, C1), backslashes, Unicode
/// bidirectional and zero-width format characters (which could make the path
/// shown to an approver differ from the one written), names starting with
/// [`TEMP_PREFIX`], and excessive length or depth. This is lexical only:
/// visually confusable names (for example Cyrillic `а` for Latin `a`) are
/// distinct, ordinary file names and are not detected.
pub fn validate_relative_path(path: &str) -> Result<(), DispatchRefused> {
    if path.is_empty() {
        return Err(DispatchRefused("empty_path"));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(DispatchRefused("path_too_long"));
    }
    if path.starts_with('/') {
        return Err(DispatchRefused("absolute_path"));
    }
    if path
        .chars()
        .any(|c| c.is_control() || c == '\\' || is_format_char(c))
    {
        return Err(DispatchRefused("invalid_path_character"));
    }
    let mut depth = 0;
    for component in path.split('/') {
        depth += 1;
        match component {
            "" => return Err(DispatchRefused("empty_path_component")),
            "." | ".." => return Err(DispatchRefused("path_traversal")),
            c if c.len() > MAX_COMPONENT_BYTES => {
                return Err(DispatchRefused("path_component_too_long"));
            }
            c if c.starts_with(TEMP_PREFIX) => {
                return Err(DispatchRefused("reserved_file_name"));
            }
            _ => {}
        }
    }
    if depth > MAX_PATH_DEPTH {
        return Err(DispatchRefused("path_too_deep"));
    }
    Ok(())
}

/// Invisible or direction-changing format characters.
fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
    )
}

/// The final entry must be absent (only when `may_be_absent`) or a regular
/// file with exactly one link. Never follows a symlink.
fn check_entry(dirfd: RawFd, name: &CString, may_be_absent: bool) -> Result<(), DispatchRefused> {
    match fstatat_nofollow(dirfd, name) {
        Ok(stat) => check_regular_single_link(&stat),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            if may_be_absent {
                Ok(())
            } else {
                Err(DispatchRefused("file_not_found"))
            }
        }
        Err(_) => Err(DispatchRefused("file_unavailable")),
    }
}

fn unlink_quietly(dirfd: RawFd, name: &CString) {
    // SAFETY: valid dirfd and NUL-terminated name.
    unsafe { libc::unlinkat(dirfd, name.as_ptr(), 0) };
}

fn c_component(component: &str) -> Result<CString, DispatchRefused> {
    CString::new(component).map_err(|_| DispatchRefused("invalid_path_character"))
}

fn dup(fd: RawFd) -> Result<OwnedFd, DispatchRefused> {
    // SAFETY: `fd` is a valid open descriptor owned by the dispatcher.
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new < 0 {
        return Err(DispatchRefused("sandbox_root_unavailable"));
    }
    // SAFETY: freshly duplicated, exclusively owned.
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid fd and a properly sized out-pointer.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat succeeded and initialized the struct.
    Ok(unsafe { stat.assume_init() })
}

fn fstatat_nofollow(dirfd: RawFd, name: &CString) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid dirfd, NUL-terminated name, properly sized out-pointer.
    if unsafe {
        libc::fstatat(
            dirfd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat succeeded and initialized the struct.
    Ok(unsafe { stat.assume_init() })
}

fn check_regular_single_link(stat: &libc::stat) -> Result<(), DispatchRefused> {
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG => {}
        libc::S_IFLNK => return Err(DispatchRefused("symlink_not_allowed")),
        _ => return Err(DispatchRefused("not_a_regular_file")),
    }
    // A hard link could alias an inode outside the sandbox.
    if stat.st_nlink != 1 {
        return Err(DispatchRefused("hard_link_not_allowed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use praetore_core::AgentId;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::Arc;
    use uuid::Uuid;

    struct Dirs {
        base: PathBuf,
        root: PathBuf,
        outside: PathBuf,
    }

    impl Drop for Dirs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn dirs() -> Dirs {
        let base = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("praetore-sandbox-test-{}", Uuid::new_v4()));
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        // Independent of the process umask: the root must not be group- or
        // other-writable.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Dirs {
            base,
            root,
            outside,
        }
    }

    fn write(path: &str, content: &str) -> Action {
        Action::new(
            WRITE_ACTION,
            Some(DEFAULT_TARGET.into()),
            json!({"path": path, "content": content}),
        )
        .unwrap()
        .with_capability(WRITE_CAPABILITY)
    }

    fn delete(path: &str) -> Action {
        Action::new(
            DELETE_ACTION,
            Some(DEFAULT_TARGET.into()),
            json!({"path": path}),
        )
        .unwrap()
        .with_capability(DELETE_CAPABILITY)
    }

    fn key(n: u128) -> ExecutionKey {
        ExecutionKey {
            tenant_id: Uuid::from_u128(3),
            agent_id: Uuid::from_u128(1),
            request_id: Uuid::from_u128(n),
        }
    }

    fn authority() -> Authority {
        Authority::new(AgentId::new(), "sandbox-test", vec![])
    }

    fn run(
        d: &SandboxDispatcher,
        n: u128,
        action: &Action,
    ) -> Result<DispatchReport, DispatchError> {
        d.dispatch(
            key(n),
            &authority(),
            action,
            &crate::action_digest(action).unwrap(),
        )
    }

    fn outside_is_empty(dirs: &Dirs) -> bool {
        std::fs::read_dir(&dirs.outside).unwrap().next().is_none()
    }

    #[test]
    fn write_then_delete_inside_root_is_confirmed_and_idempotent() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        std::fs::create_dir(dirs.root.join("sub")).unwrap();
        let action = write("sub/hola.txt", "hola");
        assert!(d.preflight(&action).is_ok());
        let report = run(&d, 1, &action).unwrap();
        assert!(matches!(report, DispatchReport::Confirmed(ref o) if o["bytes"] == 4));
        assert_eq!(
            std::fs::read_to_string(dirs.root.join("sub/hola.txt")).unwrap(),
            "hola"
        );
        // Same key + digest: no second effect, same report.
        std::fs::write(dirs.root.join("sub/hola.txt"), "changed").unwrap();
        assert_eq!(run(&d, 1, &action).unwrap(), report);
        assert_eq!(
            std::fs::read_to_string(dirs.root.join("sub/hola.txt")).unwrap(),
            "changed"
        );
        let digest = crate::action_digest(&action).unwrap();
        assert_eq!(
            d.reconcile(key(1), &authority(), &action, &digest),
            ReconciliationReport::Applied(match report {
                DispatchReport::Confirmed(o) => o,
                _ => unreachable!(),
            })
        );
        let del = delete("sub/hola.txt");
        assert!(matches!(run(&d, 2, &del), Ok(DispatchReport::Confirmed(_))));
        assert!(!dirs.root.join("sub/hola.txt").exists());
        assert_eq!(d.preflight(&del), Err(DispatchRefused("file_not_found")));
    }

    #[test]
    fn dot_dot_traversal_is_refused() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        for path in ["../outside/x", "a/../../outside/x", "..", "./x", "sub/./x"] {
            let action = write(path, "x");
            assert!(d.preflight(&action).is_err(), "{path}");
            assert_eq!(run(&d, 10, &action), Err(DispatchError), "{path}");
        }
        assert!(outside_is_empty(&dirs));
    }

    #[test]
    fn absolute_path_is_refused_even_when_inside_root() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        for path in [
            dirs.outside.join("x").display().to_string(),
            dirs.root.join("x").display().to_string(),
            "/etc/passwd".into(),
        ] {
            assert_eq!(
                d.preflight(&write(&path, "x")),
                Err(DispatchRefused("absolute_path"))
            );
            assert_eq!(
                d.preflight(&delete(&path)),
                Err(DispatchRefused("absolute_path"))
            );
            assert_eq!(run(&d, 11, &write(&path, "x")), Err(DispatchError));
        }
        assert!(outside_is_empty(&dirs));
        assert!(!dirs.root.join("x").exists());
    }

    #[test]
    fn final_symlink_to_outside_is_not_followed() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        let target = dirs.outside.join("victim.txt");
        std::fs::write(&target, "original").unwrap();
        symlink(&target, dirs.root.join("link.txt")).unwrap();
        // Dangling symlink to a not-yet-existing outside file.
        symlink(dirs.outside.join("new.txt"), dirs.root.join("dangling.txt")).unwrap();

        assert_eq!(
            d.preflight(&write("link.txt", "pwned")),
            Err(DispatchRefused("symlink_not_allowed"))
        );
        assert_eq!(
            d.preflight(&write("dangling.txt", "pwned")),
            Err(DispatchRefused("symlink_not_allowed"))
        );
        assert_eq!(
            d.preflight(&delete("link.txt")),
            Err(DispatchRefused("symlink_not_allowed"))
        );
        // Even bypassing preflight, dispatch refuses (O_NOFOLLOW / lstat).
        assert_eq!(run(&d, 20, &write("link.txt", "pwned")), Err(DispatchError));
        assert_eq!(
            run(&d, 21, &write("dangling.txt", "pwned")),
            Err(DispatchError)
        );
        assert_eq!(run(&d, 22, &delete("link.txt")), Err(DispatchError));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "original");
        assert!(!dirs.outside.join("new.txt").exists());
        assert!(
            std::fs::symlink_metadata(dirs.root.join("link.txt"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn symlink_in_intermediate_directory_is_not_followed() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        std::fs::write(dirs.outside.join("victim.txt"), "original").unwrap();
        symlink(&dirs.outside, dirs.root.join("escape")).unwrap();
        std::fs::create_dir(dirs.root.join("real")).unwrap();
        symlink(&dirs.outside, dirs.root.join("real/deeper")).unwrap();
        for path in ["escape/x.txt", "escape/victim.txt", "real/deeper/x.txt"] {
            assert_eq!(
                d.preflight(&write(path, "pwned")),
                Err(DispatchRefused("symlink_or_non_directory_in_path")),
                "{path}"
            );
            assert_eq!(
                run(&d, 30, &write(path, "pwned")),
                Err(DispatchError),
                "{path}"
            );
        }
        assert_eq!(
            d.preflight(&delete("escape/victim.txt")),
            Err(DispatchRefused("symlink_or_non_directory_in_path"))
        );
        assert_eq!(
            run(&d, 31, &delete("escape/victim.txt")),
            Err(DispatchError)
        );
        assert_eq!(
            std::fs::read_to_string(dirs.outside.join("victim.txt")).unwrap(),
            "original"
        );
        assert_eq!(std::fs::read_dir(&dirs.outside).unwrap().count(), 1);
    }

    #[test]
    fn empty_names_are_refused() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        assert_eq!(
            d.preflight(&write("", "x")),
            Err(DispatchRefused("empty_path"))
        );
        assert_eq!(d.preflight(&delete("")), Err(DispatchRefused("empty_path")));
        for path in ["a//b", "dir/", "/"] {
            assert!(d.preflight(&write(path, "x")).is_err(), "{path}");
        }
        assert_eq!(
            d.preflight(&write("a\0b", "x")),
            Err(DispatchRefused("invalid_path_character"))
        );
        assert_eq!(run(&d, 40, &write("", "x")), Err(DispatchError));
        assert_eq!(std::fs::read_dir(&dirs.root).unwrap().count(), 0);
    }

    #[test]
    fn oversized_content_and_paths_are_refused() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root)
            .unwrap()
            .with_max_content_bytes(8)
            .unwrap();
        assert!(d.preflight(&write("ok.txt", "12345678")).is_ok());
        let big = write("big.txt", "123456789");
        assert_eq!(d.preflight(&big), Err(DispatchRefused("content_too_large")));
        assert_eq!(run(&d, 50, &big), Err(DispatchError));
        assert!(!dirs.root.join("big.txt").exists());
        let default = SandboxDispatcher::open(&dirs.root).unwrap();
        let huge = write("huge.txt", &"x".repeat(DEFAULT_MAX_CONTENT_BYTES + 1));
        assert_eq!(
            default.preflight(&huge),
            Err(DispatchRefused("content_too_large"))
        );
        assert_eq!(
            default.preflight(&write(&"a".repeat(256), "x")),
            Err(DispatchRefused("path_component_too_long"))
        );
        assert_eq!(
            default.preflight(&write(&"a/".repeat(600), "x")),
            Err(DispatchRefused("path_too_long"))
        );
        assert_eq!(
            default.preflight(&write(&format!("{}leaf", "a/".repeat(16)), "x")),
            Err(DispatchRefused("path_too_deep"))
        );
        assert!(
            SandboxDispatcher::open(&dirs.root)
                .unwrap()
                .with_max_content_bytes(0)
                .is_err()
        );
    }

    #[test]
    fn hard_links_fifos_and_directories_are_refused() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        let outside = dirs.outside.join("victim.txt");
        std::fs::write(&outside, "original").unwrap();
        if std::fs::hard_link(&outside, dirs.root.join("hard.txt")).is_ok() {
            assert_eq!(
                d.preflight(&write("hard.txt", "pwned")),
                Err(DispatchRefused("hard_link_not_allowed"))
            );
            assert_eq!(run(&d, 60, &write("hard.txt", "pwned")), Err(DispatchError));
            assert_eq!(std::fs::read_to_string(&outside).unwrap(), "original");
        }
        std::fs::create_dir(dirs.root.join("dir")).unwrap();
        assert_eq!(
            d.preflight(&write("dir", "x")),
            Err(DispatchRefused("not_a_regular_file"))
        );
        assert_eq!(
            d.preflight(&delete("dir")),
            Err(DispatchRefused("not_a_regular_file"))
        );
        let fifo = CString::new(dirs.root.join("fifo").as_os_str().as_bytes()).unwrap();
        // SAFETY: valid path.
        if unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) } == 0 {
            assert_eq!(
                d.preflight(&write("fifo", "x")),
                Err(DispatchRefused("not_a_regular_file"))
            );
            assert_eq!(run(&d, 61, &write("fifo", "x")), Err(DispatchError));
        }
        assert_eq!(
            d.preflight(&write("missing/x.txt", "x")),
            Err(DispatchRefused("parent_directory_missing"))
        );
    }

    #[test]
    fn actions_outside_the_allowlist_are_refused_explicitly() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        let exec = Action::new(
            "shell:exec",
            Some("sandbox".into()),
            json!({"argv": ["ls"]}),
        )
        .unwrap()
        .with_capability("shell:exec");
        assert_eq!(
            d.preflight(&exec),
            Err(DispatchRefused("action_not_in_sandbox_allowlist"))
        );
        assert_eq!(run(&d, 70, &exec), Err(DispatchError));
        let demo = Action::new(
            "demo:set_value",
            Some("demo-state".into()),
            json!({"key": "k", "value": "v"}),
        )
        .unwrap()
        .with_capability("demo:write");
        assert!(
            d.preflight(&demo).is_err(),
            "demo disabled unless configured"
        );
        let wrong_cap = write("x", "y").with_capability("fs:delete");
        assert_eq!(
            d.preflight(&wrong_cap),
            Err(DispatchRefused("capability_mismatch"))
        );
        let wrong_target = Action::new(
            WRITE_ACTION,
            Some("other".into()),
            json!({"path": "x", "content": "y"}),
        )
        .unwrap()
        .with_capability(WRITE_CAPABILITY);
        assert_eq!(
            d.preflight(&wrong_target),
            Err(DispatchRefused("target_mismatch"))
        );
        let extra = Action::new(
            WRITE_ACTION,
            Some("sandbox".into()),
            json!({"path": "x", "content": "y", "mode": 777}),
        )
        .unwrap()
        .with_capability(WRITE_CAPABILITY);
        assert_eq!(
            d.preflight(&extra),
            Err(DispatchRefused("invalid_parameters"))
        );
        let with_demo = SandboxDispatcher::open(&dirs.root)
            .unwrap()
            .with_local_demo(LocalDemoDispatcher::new());
        assert!(with_demo.preflight(&demo).is_ok());
        assert!(matches!(
            run(&with_demo, 71, &demo),
            Ok(DispatchReport::Confirmed(_))
        ));
        assert_eq!(std::fs::read_dir(&dirs.root).unwrap().count(), 0);
    }

    #[test]
    fn invalid_roots_fail_closed() {
        let dirs = dirs();
        assert!(matches!(
            SandboxDispatcher::open("relative/root"),
            Err(SandboxConfigError::NotAbsolute)
        ));
        assert!(matches!(
            SandboxDispatcher::open(dirs.base.join("missing")),
            Err(SandboxConfigError::Io(_))
        ));
        std::fs::write(dirs.base.join("file"), "x").unwrap();
        assert!(matches!(
            SandboxDispatcher::open(dirs.base.join("file")),
            Err(SandboxConfigError::NotDirectory)
        ));
        symlink(&dirs.root, dirs.base.join("rootlink")).unwrap();
        assert!(matches!(
            SandboxDispatcher::open(dirs.base.join("rootlink")),
            Err(SandboxConfigError::Symlink)
        ));
        assert!(matches!(
            SandboxDispatcher::open(dirs.root.join("../root")),
            Err(SandboxConfigError::NotCanonical(_))
        ));
    }

    fn no_temp_files(dir: &Path) -> bool {
        std::fs::read_dir(dir).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(TEMP_PREFIX)
        })
    }

    #[test]
    fn writes_are_atomic_owner_only_and_leave_no_temporary_files() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        let existing = dirs.root.join("existing.txt");
        std::fs::write(&existing, "old content that is longer").unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o644)).unwrap();
        let before = std::fs::metadata(&existing).unwrap();
        assert!(matches!(
            run(&d, 100, &write("existing.txt", "new")),
            Ok(DispatchReport::Confirmed(_))
        ));
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "new");
        let after = std::fs::metadata(&existing).unwrap();
        // Replaced by rename (a new inode), never truncated in place.
        assert_ne!(
            std::os::unix::fs::MetadataExt::ino(&before),
            std::os::unix::fs::MetadataExt::ino(&after)
        );
        assert_eq!(after.permissions().mode() & 0o7777, FILE_MODE);
        assert!(matches!(
            run(&d, 101, &write("created.txt", "")),
            Ok(DispatchReport::Confirmed(ref o)) if o["bytes"] == 0
        ));
        assert_eq!(
            std::fs::metadata(dirs.root.join("created.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            FILE_MODE
        );
        assert!(no_temp_files(&dirs.root));
        assert_eq!(
            d.preflight(&write(&format!("{TEMP_PREFIX}x"), "x")),
            Err(DispatchRefused("reserved_file_name"))
        );
    }

    #[test]
    fn root_renamed_or_replaced_after_open_fails_closed() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        std::fs::write(dirs.root.join("keep.txt"), "x").unwrap();
        let moved = dirs.base.join("moved");
        std::fs::rename(&dirs.root, &moved).unwrap();
        // Path missing.
        assert_eq!(
            d.preflight(&write("a.txt", "x")),
            Err(DispatchRefused("sandbox_root_replaced"))
        );
        // Path replaced by another directory.
        std::fs::create_dir(&dirs.root).unwrap();
        assert_eq!(
            d.preflight(&write("a.txt", "x")),
            Err(DispatchRefused("sandbox_root_replaced"))
        );
        assert_eq!(run(&d, 110, &write("a.txt", "x")), Err(DispatchError));
        assert_eq!(run(&d, 111, &delete("keep.txt")), Err(DispatchError));
        std::fs::remove_dir(&dirs.root).unwrap();
        // Path replaced by a symlink to the original directory.
        symlink(&moved, &dirs.root).unwrap();
        assert_eq!(
            d.preflight(&write("a.txt", "x")),
            Err(DispatchRefused("sandbox_root_replaced"))
        );
        assert_eq!(run(&d, 112, &write("a.txt", "x")), Err(DispatchError));
        assert!(!moved.join("a.txt").exists());
        assert!(moved.join("keep.txt").exists());
        // The failed dispatches are known not to have changed anything.
        let action = write("a.txt", "x");
        let digest = crate::action_digest(&action).unwrap();
        assert_eq!(
            d.reconcile(key(112), &authority(), &action, &digest),
            ReconciliationReport::NotApplied
        );
        // Never retried for the same key.
        std::fs::remove_file(&dirs.root).unwrap();
        std::fs::rename(&moved, &dirs.root).unwrap();
        assert_eq!(run(&d, 112, &action), Err(DispatchError));
        assert!(!dirs.root.join("a.txt").exists());
        // Back in place: works again for a new key.
        assert!(matches!(
            run(&d, 113, &action),
            Ok(DispatchReport::Confirmed(_))
        ));
    }

    #[test]
    fn insecure_or_filesystem_roots_are_refused() {
        let dirs = dirs();
        assert!(matches!(
            SandboxDispatcher::open("/"),
            Err(SandboxConfigError::FilesystemRoot)
        ));
        for mode in [0o770, 0o707, 0o777] {
            std::fs::set_permissions(&dirs.root, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(
                    SandboxDispatcher::open(&dirs.root),
                    Err(SandboxConfigError::InsecurePermissions)
                ),
                "{mode:o}"
            );
        }
        std::fs::set_permissions(&dirs.root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(SandboxDispatcher::open(&dirs.root).is_ok());
    }

    #[test]
    fn deletes_never_remove_directories_symlinks_targets_or_special_files() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        let victim = dirs.outside.join("victim.txt");
        std::fs::write(&victim, "original").unwrap();
        std::fs::create_dir(dirs.root.join("dir")).unwrap();
        std::fs::write(dirs.root.join("dir/inner.txt"), "x").unwrap();
        symlink(&victim, dirs.root.join("link")).unwrap();
        symlink(&dirs.outside, dirs.root.join("dirlink")).unwrap();
        for (n, path) in ["dir", "link", "dirlink", "dirlink/victim.txt", "missing"]
            .into_iter()
            .enumerate()
        {
            assert!(d.preflight(&delete(path)).is_err(), "{path}");
            assert_eq!(
                run(&d, 120 + n as u128, &delete(path)),
                Err(DispatchError),
                "{path}"
            );
        }
        assert!(dirs.root.join("dir/inner.txt").exists());
        assert!(std::fs::symlink_metadata(dirs.root.join("link")).is_ok());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "original");
    }

    #[test]
    fn sockets_and_files_used_as_directories_are_refused() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        std::fs::write(dirs.root.join("file.txt"), "x").unwrap();
        assert_eq!(
            d.preflight(&write("file.txt/x", "x")),
            Err(DispatchRefused("symlink_or_non_directory_in_path"))
        );
        if let Ok(_listener) = std::os::unix::net::UnixListener::bind(dirs.root.join("sock")) {
            assert_eq!(
                d.preflight(&write("sock", "x")),
                Err(DispatchRefused("not_a_regular_file"))
            );
            assert_eq!(
                d.preflight(&delete("sock")),
                Err(DispatchRefused("not_a_regular_file"))
            );
            assert_eq!(run(&d, 130, &write("sock", "x")), Err(DispatchError));
            assert!(std::fs::symlink_metadata(dirs.root.join("sock")).is_ok());
        }
    }

    #[test]
    fn unicode_is_lexical_format_characters_are_refused() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        for path in [
            "evil\u{202E}txt.exe",
            "a\u{200B}b",
            "x\u{2066}y",
            "bom\u{FEFF}",
            "c1\u{0085}",
            "del\u{7F}",
        ] {
            assert_eq!(
                d.preflight(&write(path, "x")),
                Err(DispatchRefused("invalid_path_character")),
                "{path:?}"
            );
        }
        // Lookalikes are ordinary names inside the root, never traversal:
        // U+2024 ONE DOT LEADER, U+FF0F FULLWIDTH SOLIDUS, Cyrillic а.
        for (n, path) in ["\u{2024}\u{2024}", "a\u{FF0F}b", "p\u{0430}sswd"]
            .into_iter()
            .enumerate()
        {
            assert!(
                matches!(
                    run(&d, 140 + n as u128, &write(path, "x")),
                    Ok(DispatchReport::Confirmed(_))
                ),
                "{path}"
            );
            assert!(dirs.root.join(path).is_file(), "{path}");
        }
        assert!(outside_is_empty(&dirs));
        assert_eq!(std::fs::read_dir(dirs.base.as_path()).unwrap().count(), 2);
    }

    #[test]
    fn concurrent_writes_are_serialized_and_never_torn() {
        let dirs = dirs();
        let d = Arc::new(SandboxDispatcher::open(&dirs.root).unwrap());
        let threads: Vec<_> = (0..16u128)
            .map(|n| {
                let d = Arc::clone(&d);
                std::thread::spawn(move || {
                    let content = n.to_string().repeat(1000);
                    run(&d, 200 + n, &write("shared.txt", &content)).unwrap();
                    run(&d, 300 + n, &write(&format!("own-{n}.txt"), &content)).unwrap();
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let shared = std::fs::read_to_string(dirs.root.join("shared.txt")).unwrap();
        assert!(
            (0..16u128).any(|n| shared == n.to_string().repeat(1000)),
            "torn write"
        );
        for n in 0..16u128 {
            assert_eq!(
                std::fs::read_to_string(dirs.root.join(format!("own-{n}.txt"))).unwrap(),
                n.to_string().repeat(1000)
            );
        }
        assert!(no_temp_files(&dirs.root));
    }
}
