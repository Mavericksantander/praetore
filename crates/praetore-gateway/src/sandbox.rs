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
//!   owned by the gateway's effective user, not writable by group or others
//!   and, on macOS, without extended ACL entries (on Linux, POSIX ACLs are
//!   bounded by the mask shown in the group bits). It is opened once as a
//!   directory file descriptor and its device/inode is checked against the
//!   path. Before every preflight and dispatch the path is checked again to
//!   still name that same directory and the owner/mode/ACL requirements are
//!   re-validated; otherwise the action is refused (fail closed). At open,
//!   leftover temporary files (see [`TEMP_PREFIX`], matched ASCII
//!   case-insensitively) are removed without following links.
//! - Refusal codes are terminal except `sandbox_root_unavailable`,
//!   `parent_directory_unavailable` and `file_unavailable` (descriptor or
//!   I/O errors while inspecting), which are transient.
//! - Paths are validated lexically first: relative only, no `.`/`..`, no
//!   empty components, no NUL/control characters, no `\`, no Unicode
//!   bidirectional or zero-width format characters, bounded length and depth.
//! - Every effect then goes through [`praetore_sandbox_fs`], relative to
//!   the root descriptor, never through a joined path string. On Linux the
//!   intermediate components are opened with one `openat2(RESOLVE_BENEATH |
//!   RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)` call;
//!   on kernels without `openat2` (`ENOSYS`) and on macOS, one `openat(2)`
//!   per component relative to the previous directory descriptor using
//!   `O_NOFOLLOW | O_DIRECTORY`. Either way a symlink at any level fails
//!   instead of being followed, the kernel never resolves `..`, and a
//!   component on another device (a mount point; with `openat2` also a bind
//!   mount) is refused. Intermediate directories are never created. Because
//!   each step is relative to an already opened descriptor, swapping a
//!   directory for a symlink between the check and the effect does not
//!   redirect the effect (see the race tests in `praetore-sandbox-fs` and
//!   below).
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
//! directories inside the root *and* write outside it on the same
//! filesystem can move an already opened directory out of the root while a
//! single operation is in flight; a hard link created by such a process
//! after the checks is not detected (it cannot redirect `fs:write_file`,
//! which replaces the entry by rename, nor make `fs:delete_file` remove
//! anything but the inside name); there is no quota on the number of files;
//! and idempotency/reconciliation records are kept in memory and are lost on
//! restart, like the local demo adapter.

use crate::{
    ActionDispatcher, DispatchError, DispatchRefused, DispatchReport, ExecutionKey,
    ReconciliationReport, local_demo::LocalDemoDispatcher,
};
use praetore_core::{Action, Authority};
// `is_temp_name`: TEMP_PREFIX compared ASCII case-insensitively, shared with
// praetore-sandbox-fs (which also refuses such paths on its own).
use praetore_sandbox_fs::{ConfineError, Openat2Status, Resolver, Root, is_temp_name};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    ffi::CString,
    io,
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
pub const TEMP_PREFIX: &str = praetore_sandbox_fs::TEMP_PREFIX;
/// Mode of every file created or replaced by `fs:write_file`.
pub const FILE_MODE: u32 = 0o600;
/// Environment variable that makes [`SandboxDispatcher::require_openat2`]
/// mandatory for the gateway (`1`/`true`). See [`require_openat2_from_env`].
pub const REQUIRE_OPENAT2_ENV: &str = "PRAETORE_SANDBOX_REQUIRE_OPENAT2";

/// Parses the value of [`REQUIRE_OPENAT2_ENV`]: unset, empty, `0` or
/// `false` means not required; `1` or `true` means required; anything else
/// is a configuration error (fail closed).
pub fn require_openat2_from_env(value: Option<&str>) -> Result<bool, SandboxConfigError> {
    match value.map(str::trim) {
        None | Some("" | "0" | "false") => Ok(false),
        Some("1" | "true") => Ok(true),
        Some(other) => Err(SandboxConfigError::InvalidRequireOpenat2(other.to_owned())),
    }
}

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
    #[error("sandbox root must not carry extended ACL entries")]
    ExtendedAcl,
    #[error("sandbox root changed while it was being opened")]
    Replaced,
    #[error("sandbox root is not accessible: {0}")]
    Io(#[from] io::Error),
    #[error("sandbox content limit must be between 1 byte and 32 KiB")]
    InvalidLimit,
    #[error("openat2 is required ({REQUIRE_OPENAT2_ENV}) but {0}")]
    Openat2Required(&'static str),
    #[error("{REQUIRE_OPENAT2_ENV} must be 1, true, 0, false or unset, not {0:?}")]
    InvalidRequireOpenat2(String),
}

/// What the adapter knows about one execution key, for idempotency and
/// read-only reconciliation.
#[derive(Default)]
struct Records {
    /// Effects performed: action digest and output.
    executions: HashMap<ExecutionKey, (String, Value)>,
    /// Dispatches that failed before any change to the target: digest and
    /// refusal reason.
    not_applied: HashMap<ExecutionKey, (String, &'static str)>,
}

pub struct SandboxDispatcher {
    root: PathBuf,
    c_root: CString,
    root_fd: Root,
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
/// `Executed` instead, because the effect did happen. Carries the refusal
/// reason (kept internally; dispatch errors stay opaque).
struct BeforeEffect(&'static str);

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
        match root_security(root_fd.as_raw_fd(), &stat) {
            Ok(()) => {}
            Err(RootProblem::NotOwned) => return Err(SandboxConfigError::NotOwned),
            Err(RootProblem::Writable) => return Err(SandboxConfigError::InsecurePermissions),
            Err(RootProblem::Acl) => return Err(SandboxConfigError::ExtendedAcl),
        }
        // Temporary files left by an interrupted write are never the target
        // of an action; remove them (best effort, never following links).
        sweep_temp_files(root_fd.as_raw_fd(), root_dev, 0);
        let root_fd = Root::from_fd(root_fd).map_err(|_| SandboxConfigError::NotDirectory)?;
        // Records (and logs once, if unavailable or denied) what this kernel
        // offers, so the startup log below states the resolution in use.
        praetore_sandbox_fs::probe_openat2(&root_fd);
        let dispatcher = Self {
            root: canonical,
            c_root,
            root_fd,
            root_dev,
            root_ino,
            target: DEFAULT_TARGET.into(),
            max_content_bytes: DEFAULT_MAX_CONTENT_BYTES,
            demo: None,
            records: Mutex::new(Records::default()),
        };
        tracing::info!(
            root = %dispatcher.root.display(),
            path_resolution = dispatcher.path_resolution(),
            "sandbox root opened"
        );
        Ok(dispatcher)
    }

    /// Refuses to run unless the kernel resolves paths with `openat2`
    /// (Linux >= 5.6, not denied by seccomp): no portable-walk fallback.
    /// Afterwards a later `ENOSYS` or `EPERM` refuses the action instead of
    /// degrading.
    pub fn require_openat2(mut self) -> Result<Self, SandboxConfigError> {
        let status = praetore_sandbox_fs::probe_openat2(&self.root_fd);
        if status != Openat2Status::Available {
            return Err(SandboxConfigError::Openat2Required(status.reason()));
        }
        self.root_fd.set_resolver(Resolver::Openat2);
        tracing::info!(
            root = %self.root.display(),
            path_resolution = self.path_resolution(),
            "sandbox root requires openat2"
        );
        Ok(self)
    }

    /// How intermediate path components are resolved right now, for logs
    /// and `doctor`.
    pub fn path_resolution(&self) -> &'static str {
        match (
            self.root_fd.resolver(),
            praetore_sandbox_fs::openat2_status(),
        ) {
            (Resolver::Openat2, _) => "openat2 (required)",
            (Resolver::Walk, _) => "portable O_NOFOLLOW walk",
            (Resolver::Auto, Openat2Status::Available) => "openat2",
            (Resolver::Auto, Openat2Status::Unavailable) => {
                "portable O_NOFOLLOW walk (openat2 unavailable: ENOSYS or not Linux)"
            }
            (Resolver::Auto, Openat2Status::Denied) => {
                "nested paths refused (openat2 denied: EPERM, seccomp or LSM)"
            }
            (Resolver::Auto, Openat2Status::Unknown) => "openat2 when available (not probed)",
        }
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
            _ => return Err(DispatchRefused::terminal("action_not_in_sandbox_allowlist")),
        };
        if action.capability.as_deref() != Some(capability) {
            return Err(DispatchRefused::terminal("capability_mismatch"));
        }
        if action.target.as_deref() != Some(self.target.as_str()) {
            return Err(DispatchRefused::terminal("target_mismatch"));
        }
        let parameters = action
            .parameters
            .as_object()
            .ok_or(DispatchRefused::terminal("invalid_parameters"))?;
        let mut present: Vec<&str> = parameters.keys().map(String::as_str).collect();
        present.sort_unstable();
        if present != keys {
            return Err(DispatchRefused::terminal("invalid_parameters"));
        }
        let path = parameters
            .get("path")
            .and_then(Value::as_str)
            .ok_or(DispatchRefused::terminal("invalid_path"))?;
        validate_relative_path(path)?;
        if action.action_type == WRITE_ACTION {
            let content = parameters
                .get("content")
                .and_then(Value::as_str)
                .ok_or(DispatchRefused::terminal("invalid_content"))?;
            if content.len() > self.max_content_bytes {
                return Err(DispatchRefused::terminal("content_too_large"));
            }
            Ok(FsOp::Write { path, content })
        } else {
            Ok(FsOp::Delete { path })
        }
    }

    /// Fails closed when the configured path no longer names the directory
    /// opened at startup (renamed, removed or replaced, including by a
    /// symlink), or when that directory stopped satisfying the ownership,
    /// mode and ACL requirements checked at open.
    fn check_root_unchanged(&self) -> Result<(), DispatchRefused> {
        let path_stat = match fstatat_nofollow(libc::AT_FDCWD, &self.c_root) {
            Ok(stat)
                if stat.st_mode & libc::S_IFMT == libc::S_IFDIR
                    && stat.st_dev == self.root_dev
                    && stat.st_ino == self.root_ino =>
            {
                stat
            }
            _ => return Err(DispatchRefused::terminal("sandbox_root_replaced")),
        };
        let root_fd = self.root_fd.as_fd().as_raw_fd();
        let fd_stat =
            fstat(root_fd).map_err(|_| DispatchRefused::transient("sandbox_root_unavailable"))?;
        for stat in [&path_stat, &fd_stat] {
            root_security(root_fd, stat)
                .map_err(|_| DispatchRefused::terminal("sandbox_root_insecure"))?;
        }
        Ok(())
    }

    /// Opens the parent directory of `path` relative to the root descriptor
    /// (no symlinks, no mount crossing; see [`praetore_sandbox_fs`]) and
    /// returns it with the final component name.
    fn open_parent<'p>(
        &self,
        path: &'p str,
    ) -> Result<(praetore_sandbox_fs::Dir, &'p str), DispatchRefused> {
        self.check_root_unchanged()?;
        self.root_fd.open_parent(path).map_err(refusal)
    }

    /// Side-effect-free inspection of the final component.
    fn check_final(&self, op: &FsOp<'_>) -> Result<(), DispatchRefused> {
        let path = match op {
            FsOp::Write { path, .. } | FsOp::Delete { path } => path,
        };
        let (parent, name) = self.open_parent(path)?;
        parent
            .check_entry(name, matches!(op, FsOp::Write { .. }))
            .map(drop)
            .map_err(refusal)
    }

    fn admit(&self, action: &Action) -> Result<(), DispatchRefused> {
        if action.action_type == "demo:set_value" && self.demo.is_some() {
            return Ok(());
        }
        let op = self.parse(action)?;
        self.check_final(&op)
    }

    /// Performs the effect through [`praetore_sandbox_fs::Root`]. Its
    /// contract matches [`BeforeEffect`]: an `Err` from `write_file` or
    /// `remove_file` means the target entry was not changed.
    fn perform(&self, op: &FsOp<'_>) -> Result<DispatchReport, BeforeEffect> {
        self.check_root_unchanged()
            .map_err(|refused| BeforeEffect(refused.reason()))?;
        match op {
            FsOp::Write { path, content } => {
                let written = self
                    .root_fd
                    .write_file(path, content.as_bytes(), FILE_MODE)
                    .map_err(|error| BeforeEffect(refusal(error).reason()))?;
                let output = json!({
                    "action": WRITE_ACTION,
                    "path": path,
                    "bytes": content.len(),
                    "sha256": hex::encode(Sha256::digest(content.as_bytes())),
                });
                Ok(if written.confirmed {
                    DispatchReport::Confirmed(output)
                } else {
                    DispatchReport::Executed(output)
                })
            }
            FsOp::Delete { path } => {
                let removed = self
                    .root_fd
                    .remove_file(path)
                    .map_err(|error| BeforeEffect(refusal(error).reason()))?;
                let output = json!({"action": DELETE_ACTION, "path": path});
                Ok(if removed.confirmed {
                    DispatchReport::Confirmed(output)
                } else {
                    DispatchReport::Executed(output)
                })
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
            Err(refused) => Err(BeforeEffect(refused.reason())),
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
            Err(BeforeEffect(reason)) => {
                records
                    .not_applied
                    .insert(key, (action_digest.to_owned(), reason));
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
                Some((digest, _)) if digest == action_digest => ReconciliationReport::NotApplied,
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
        return Err(DispatchRefused::terminal("empty_path"));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(DispatchRefused::terminal("path_too_long"));
    }
    if path.starts_with('/') {
        return Err(DispatchRefused::terminal("absolute_path"));
    }
    if path
        .chars()
        .any(|c| c.is_control() || c == '\\' || is_format_char(c))
    {
        return Err(DispatchRefused::terminal("invalid_path_character"));
    }
    let mut depth = 0;
    for component in path.split('/') {
        depth += 1;
        match component {
            "" => return Err(DispatchRefused::terminal("empty_path_component")),
            "." | ".." => return Err(DispatchRefused::terminal("path_traversal")),
            c if c.len() > MAX_COMPONENT_BYTES => {
                return Err(DispatchRefused::terminal("path_component_too_long"));
            }
            c if is_temp_name(c.as_bytes()) => {
                return Err(DispatchRefused::terminal("reserved_file_name"));
            }
            _ => {}
        }
    }
    if depth > MAX_PATH_DEPTH {
        return Err(DispatchRefused::terminal("path_too_deep"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootProblem {
    NotOwned,
    Writable,
    Acl,
}

/// Owned by the effective user, not group/other-writable, and (on macOS) no
/// extended ACL entries, which could grant write access the mode bits do not
/// show. On Linux, POSIX ACL entries are bounded by the ACL mask, which is
/// reported as the group mode bits, so the mode check covers them.
fn root_security(fd: RawFd, stat: &libc::stat) -> Result<(), RootProblem> {
    // SAFETY: geteuid has no preconditions.
    if stat.st_uid != unsafe { libc::geteuid() } {
        return Err(RootProblem::NotOwned);
    }
    if stat.st_mode & 0o022 != 0 {
        return Err(RootProblem::Writable);
    }
    if has_extended_acl(fd) {
        return Err(RootProblem::Acl);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn has_extended_acl(fd: RawFd) -> bool {
    // <sys/acl.h>: ACL_TYPE_EXTENDED, ACL_FIRST_ENTRY. Part of libSystem.
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_get_entry(
            acl: *mut libc::c_void,
            entry_id: libc::c_int,
            entry: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }
    // SAFETY: valid fd; the returned ACL (if any) is freed below.
    let acl = unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        // ENOENT: no ACL. Any other error: fail closed.
        return io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT);
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: `acl` is a valid ACL; `entry` is a valid out-pointer.
    let has_entry = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) } == 0;
    // SAFETY: `acl` was returned by acl_get_fd_np and is freed once.
    unsafe { acl_free(acl) };
    has_entry
}

#[cfg(not(target_os = "macos"))]
fn has_extended_acl(_fd: RawFd) -> bool {
    false
}

/// Best-effort removal of leftover temporary files below `dirfd`, never
/// following symlinks or crossing devices, bounded by [`MAX_PATH_DEPTH`].
fn sweep_temp_files(dirfd: RawFd, root_dev: libc::dev_t, depth: usize) {
    let Ok(dir) = dup(dirfd) else {
        return;
    };
    // SAFETY: `dir` is an owned directory fd; fdopendir takes ownership.
    let stream = unsafe { libc::fdopendir(dir.as_raw_fd()) };
    if stream.is_null() {
        return;
    }
    std::mem::forget(dir);
    let mut names = Vec::new();
    loop {
        // SAFETY: `stream` is a valid DIR*.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: d_name is NUL-terminated within the dirent.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(name.to_owned());
        }
    }
    // SAFETY: closes the stream and its descriptor exactly once.
    unsafe { libc::closedir(stream) };
    for name in names {
        let Ok(stat) = fstatat_nofollow(dirfd, &name) else {
            continue;
        };
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFREG if is_temp_name(name.to_bytes()) => unlink_quietly(dirfd, &name),
            libc::S_IFDIR if depth < MAX_PATH_DEPTH && stat.st_dev == root_dev => {
                // SAFETY: valid dirfd and NUL-terminated name.
                let fd = unsafe {
                    libc::openat(
                        dirfd,
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd >= 0 {
                    // SAFETY: freshly opened, exclusively owned.
                    let child = unsafe { OwnedFd::from_raw_fd(fd) };
                    if fstat(child.as_raw_fd()).is_ok_and(|stat| stat.st_dev == root_dev) {
                        sweep_temp_files(child.as_raw_fd(), root_dev, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }
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

fn unlink_quietly(dirfd: RawFd, name: &CString) {
    // SAFETY: valid dirfd and NUL-terminated name.
    unsafe { libc::unlinkat(dirfd, name.as_ptr(), 0) };
}

fn dup(fd: RawFd) -> Result<OwnedFd, DispatchRefused> {
    // SAFETY: `fd` is a valid open descriptor owned by the dispatcher.
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new < 0 {
        return Err(DispatchRefused::transient("sandbox_root_unavailable"));
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

/// Refusal code for a [`ConfineError`], unchanged from the codes this
/// adapter reported before it used `praetore-sandbox-fs`.
fn refusal(error: ConfineError) -> DispatchRefused {
    match error {
        ConfineError::InvalidPath(_) => DispatchRefused::terminal("invalid_path"),
        ConfineError::SymlinkOrNotDirectory => {
            DispatchRefused::terminal("symlink_or_non_directory_in_path")
        }
        ConfineError::MissingParent => DispatchRefused::terminal("parent_directory_missing"),
        ConfineError::CrossesBoundary => DispatchRefused::terminal("mount_point_in_path"),
        ConfineError::Symlink => DispatchRefused::terminal("symlink_not_allowed"),
        ConfineError::NotRegularFile => DispatchRefused::terminal("not_a_regular_file"),
        ConfineError::HardLinked => DispatchRefused::terminal("hard_link_not_allowed"),
        ConfineError::NotFound => DispatchRefused::terminal("file_not_found"),
        ConfineError::AlreadyExists => DispatchRefused::terminal("file_exists"),
        // Permanent: openat2 was required and is missing, or seccomp/LSM
        // denies it. Retrying cannot succeed.
        ConfineError::Openat2Unavailable => DispatchRefused::terminal("openat2_unavailable"),
        ConfineError::Openat2Denied => DispatchRefused::terminal("openat2_denied"),
        ConfineError::RootNotDirectory | ConfineError::RootUnavailable(_) => {
            DispatchRefused::transient("sandbox_root_unavailable")
        }
        ConfineError::ParentUnavailable(_) => {
            DispatchRefused::transient("parent_directory_unavailable")
        }
        ConfineError::EntryUnavailable(_) => DispatchRefused::transient("file_unavailable"),
    }
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
        assert_eq!(
            d.preflight(&del),
            Err(DispatchRefused::terminal("file_not_found"))
        );
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
                Err(DispatchRefused::terminal("absolute_path"))
            );
            assert_eq!(
                d.preflight(&delete(&path)),
                Err(DispatchRefused::terminal("absolute_path"))
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
            Err(DispatchRefused::terminal("symlink_not_allowed"))
        );
        assert_eq!(
            d.preflight(&write("dangling.txt", "pwned")),
            Err(DispatchRefused::terminal("symlink_not_allowed"))
        );
        assert_eq!(
            d.preflight(&delete("link.txt")),
            Err(DispatchRefused::terminal("symlink_not_allowed"))
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
                Err(DispatchRefused::terminal(
                    "symlink_or_non_directory_in_path"
                )),
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
            Err(DispatchRefused::terminal(
                "symlink_or_non_directory_in_path"
            ))
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
            Err(DispatchRefused::terminal("empty_path"))
        );
        assert_eq!(
            d.preflight(&delete("")),
            Err(DispatchRefused::terminal("empty_path"))
        );
        for path in ["a//b", "dir/", "/"] {
            assert!(d.preflight(&write(path, "x")).is_err(), "{path}");
        }
        assert_eq!(
            d.preflight(&write("a\0b", "x")),
            Err(DispatchRefused::terminal("invalid_path_character"))
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
        assert_eq!(
            d.preflight(&big),
            Err(DispatchRefused::terminal("content_too_large"))
        );
        assert_eq!(run(&d, 50, &big), Err(DispatchError));
        assert!(!dirs.root.join("big.txt").exists());
        let default = SandboxDispatcher::open(&dirs.root).unwrap();
        let huge = write("huge.txt", &"x".repeat(DEFAULT_MAX_CONTENT_BYTES + 1));
        assert_eq!(
            default.preflight(&huge),
            Err(DispatchRefused::terminal("content_too_large"))
        );
        assert_eq!(
            default.preflight(&write(&"a".repeat(256), "x")),
            Err(DispatchRefused::terminal("path_component_too_long"))
        );
        assert_eq!(
            default.preflight(&write(&"a/".repeat(600), "x")),
            Err(DispatchRefused::terminal("path_too_long"))
        );
        assert_eq!(
            default.preflight(&write(&format!("{}leaf", "a/".repeat(16)), "x")),
            Err(DispatchRefused::terminal("path_too_deep"))
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
                Err(DispatchRefused::terminal("hard_link_not_allowed"))
            );
            assert_eq!(run(&d, 60, &write("hard.txt", "pwned")), Err(DispatchError));
            assert_eq!(std::fs::read_to_string(&outside).unwrap(), "original");
        }
        std::fs::create_dir(dirs.root.join("dir")).unwrap();
        assert_eq!(
            d.preflight(&write("dir", "x")),
            Err(DispatchRefused::terminal("not_a_regular_file"))
        );
        assert_eq!(
            d.preflight(&delete("dir")),
            Err(DispatchRefused::terminal("not_a_regular_file"))
        );
        let fifo = CString::new(dirs.root.join("fifo").as_os_str().as_bytes()).unwrap();
        // SAFETY: valid path.
        if unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) } == 0 {
            assert_eq!(
                d.preflight(&write("fifo", "x")),
                Err(DispatchRefused::terminal("not_a_regular_file"))
            );
            assert_eq!(run(&d, 61, &write("fifo", "x")), Err(DispatchError));
        }
        assert_eq!(
            d.preflight(&write("missing/x.txt", "x")),
            Err(DispatchRefused::terminal("parent_directory_missing"))
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
            Err(DispatchRefused::terminal("action_not_in_sandbox_allowlist"))
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
            Err(DispatchRefused::terminal("capability_mismatch"))
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
            Err(DispatchRefused::terminal("target_mismatch"))
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
            Err(DispatchRefused::terminal("invalid_parameters"))
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
            Err(DispatchRefused::terminal("reserved_file_name"))
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
            Err(DispatchRefused::terminal("sandbox_root_replaced"))
        );
        // Path replaced by another directory.
        std::fs::create_dir(&dirs.root).unwrap();
        assert_eq!(
            d.preflight(&write("a.txt", "x")),
            Err(DispatchRefused::terminal("sandbox_root_replaced"))
        );
        assert_eq!(run(&d, 110, &write("a.txt", "x")), Err(DispatchError));
        assert_eq!(run(&d, 111, &delete("keep.txt")), Err(DispatchError));
        std::fs::remove_dir(&dirs.root).unwrap();
        // Path replaced by a symlink to the original directory.
        symlink(&moved, &dirs.root).unwrap();
        assert_eq!(
            d.preflight(&write("a.txt", "x")),
            Err(DispatchRefused::terminal("sandbox_root_replaced"))
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
            Err(DispatchRefused::terminal(
                "symlink_or_non_directory_in_path"
            ))
        );
        if let Ok(_listener) = std::os::unix::net::UnixListener::bind(dirs.root.join("sock")) {
            assert_eq!(
                d.preflight(&write("sock", "x")),
                Err(DispatchRefused::terminal("not_a_regular_file"))
            );
            assert_eq!(
                d.preflight(&delete("sock")),
                Err(DispatchRefused::terminal("not_a_regular_file"))
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
                Err(DispatchRefused::terminal("invalid_path_character")),
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

    /// Review finding 5: mode and owner are re-validated on every
    /// operation, not only at open.
    #[test]
    fn root_mode_changed_after_open_fails_closed() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        assert!(d.preflight(&write("a.txt", "x")).is_ok());
        std::fs::set_permissions(&dirs.root, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            d.preflight(&write("a.txt", "x")),
            Err(DispatchRefused::terminal("sandbox_root_insecure"))
        );
        assert_eq!(run(&d, 400, &write("a.txt", "x")), Err(DispatchError));
        assert!(!dirs.root.join("a.txt").exists());
        std::fs::set_permissions(&dirs.root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            run(&d, 401, &write("a.txt", "x")),
            Ok(DispatchReport::Confirmed(_))
        ));
    }

    /// Review finding 5 (macOS): an extended ACL can grant write access the
    /// mode bits do not show; it is refused at open and on every operation.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_extended_acl_on_root_is_refused() {
        let dirs = dirs();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        let chmod = |args: &[&str]| {
            assert!(
                std::process::Command::new("/bin/chmod")
                    .args(args)
                    .arg(&dirs.root)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        chmod(&[
            "+a",
            "everyone allow add_file,add_subdirectory,delete_child",
        ]);
        assert!(matches!(
            SandboxDispatcher::open(&dirs.root),
            Err(SandboxConfigError::ExtendedAcl)
        ));
        assert_eq!(
            d.preflight(&write("a.txt", "x")),
            Err(DispatchRefused::terminal("sandbox_root_insecure"))
        );
        assert_eq!(run(&d, 410, &write("a.txt", "x")), Err(DispatchError));
        assert!(!dirs.root.join("a.txt").exists());
        chmod(&["-N"]);
        assert!(SandboxDispatcher::open(&dirs.root).is_ok());
        assert!(d.preflight(&write("a.txt", "x")).is_ok());
    }

    /// Review finding 6: the reserved prefix is matched case-insensitively
    /// (case-insensitive APFS), and leftovers are swept at open without
    /// following symlinks.
    #[test]
    fn temp_prefix_is_case_insensitive_and_leftovers_are_swept_at_open() {
        let dirs = dirs();
        for name in [".PRAETORE-TMP-x", ".Praetore-Tmp-y", "sub/.praetore-tmp-z"] {
            assert_eq!(
                validate_relative_path(name),
                Err(DispatchRefused::terminal("reserved_file_name")),
                "{name}"
            );
        }
        std::fs::create_dir(dirs.root.join("sub")).unwrap();
        std::fs::write(dirs.root.join(".praetore-tmp-abc"), "partial").unwrap();
        std::fs::write(dirs.root.join("sub/.PRAETORE-TMP-def"), "partial").unwrap();
        std::fs::write(dirs.root.join("keep.txt"), "keep").unwrap();
        std::fs::create_dir(dirs.root.join(".praetore-tmp-dir")).unwrap();
        std::fs::write(dirs.outside.join(".praetore-tmp-victim"), "outside").unwrap();
        symlink(&dirs.outside, dirs.root.join("link")).unwrap();
        symlink(
            dirs.outside.join(".praetore-tmp-victim"),
            dirs.root.join(".praetore-tmp-link"),
        )
        .unwrap();
        SandboxDispatcher::open(&dirs.root).unwrap();
        assert!(!dirs.root.join(".praetore-tmp-abc").exists());
        assert!(!dirs.root.join("sub/.PRAETORE-TMP-def").exists());
        assert!(dirs.root.join("keep.txt").exists());
        // Only regular files are removed; links and directories stay, and
        // nothing outside the root is touched.
        assert!(dirs.root.join(".praetore-tmp-dir").is_dir());
        assert!(
            std::fs::symlink_metadata(dirs.root.join(".praetore-tmp-link"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_to_string(dirs.outside.join(".praetore-tmp-victim")).unwrap(),
            "outside"
        );
    }

    impl SandboxDispatcher {
        /// Reason recorded for a dispatch that failed before its effect.
        fn not_applied_reason(&self, key: ExecutionKey) -> Option<&'static str> {
            let records = self.records.lock().unwrap();
            records.not_applied.get(&key).map(|(_, reason)| *reason)
        }
    }

    #[test]
    fn refusal_reasons_are_kept_for_dispatches_that_did_not_apply() {
        let dirs = dirs();
        symlink(&dirs.outside, dirs.root.join("link")).unwrap();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        assert!(run(&d, 1, &write("link/x", "x")).is_err());
        assert_eq!(
            d.not_applied_reason(key(1)),
            Some("symlink_or_non_directory_in_path")
        );
        assert!(run(&d, 2, &delete("missing.txt")).is_err());
        assert_eq!(d.not_applied_reason(key(2)), Some("file_not_found"));
        assert!(run(&d, 3, &write("../x", "x")).is_err());
        assert_eq!(d.not_applied_reason(key(3)), Some("path_traversal"));
    }

    #[test]
    fn openat2_refusals_are_permanent() {
        for (error, reason) in [
            (ConfineError::Openat2Denied, "openat2_denied"),
            (ConfineError::Openat2Unavailable, "openat2_unavailable"),
        ] {
            let refused = refusal(error);
            assert_eq!(refused.reason(), reason);
            assert!(!refused.is_transient(), "{reason} must not be retried");
        }
    }

    #[test]
    fn require_openat2_env_is_parsed_fail_closed() {
        for value in [None, Some(""), Some("0"), Some("false"), Some(" 0 ")] {
            assert!(!require_openat2_from_env(value).unwrap(), "{value:?}");
        }
        for value in [Some("1"), Some("true")] {
            assert!(require_openat2_from_env(value).unwrap(), "{value:?}");
        }
        for value in ["yes", "2", "TRUE", "on"] {
            assert!(
                matches!(
                    require_openat2_from_env(Some(value)),
                    Err(SandboxConfigError::InvalidRequireOpenat2(_))
                ),
                "{value:?}"
            );
        }
    }

    /// Linux with openat2 (CI): requiring it works and nested writes go
    /// through it. Elsewhere (macOS, old kernels): requiring it fails
    /// closed at startup and the fallback is reported.
    #[test]
    fn require_openat2_is_enforced_and_reported() {
        let dirs = dirs();
        std::fs::create_dir(dirs.root.join("sub")).unwrap();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        let status = praetore_sandbox_fs::openat2_status();
        eprintln!(
            "openat2 status: {status:?}; path resolution: {}",
            d.path_resolution()
        );
        if status == Openat2Status::Available {
            assert_eq!(d.path_resolution(), "openat2");
            let d = d.require_openat2().unwrap();
            assert_eq!(d.path_resolution(), "openat2 (required)");
            assert!(run(&d, 1, &write("sub/x.txt", "x")).is_ok());
            symlink(&dirs.outside, dirs.root.join("link")).unwrap();
            assert!(run(&d, 2, &write("link/x.txt", "x")).is_err());
            assert_eq!(
                d.not_applied_reason(key(2)),
                Some("symlink_or_non_directory_in_path")
            );
        } else {
            assert!(d.path_resolution().starts_with("portable") || status == Openat2Status::Denied);
            match d.require_openat2() {
                Err(SandboxConfigError::Openat2Required(reason)) => {
                    assert_eq!(reason, status.reason());
                }
                other => panic!("expected Openat2Required, got {:?}", other.err()),
            }
        }
        if cfg!(target_os = "macos") {
            assert_eq!(status, Openat2Status::Unavailable);
        }
        assert!(outside_is_empty(&dirs));
    }

    /// Name -> (inode, content) of every entry in `dir`, not following links.
    fn snapshot(dir: &Path) -> std::collections::BTreeMap<String, (u64, Vec<u8>)> {
        use std::os::unix::fs::MetadataExt;
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let metadata = std::fs::symlink_metadata(&path).unwrap();
                let content = if metadata.is_file() {
                    std::fs::read(&path).unwrap_or_default()
                } else {
                    Vec::new()
                };
                (
                    path.file_name().unwrap().to_string_lossy().into_owned(),
                    (metadata.ino(), content),
                )
            })
            .collect()
    }

    /// T-013B race through the dispatcher: while one thread keeps swapping
    /// the intermediate directory `d` for a symlink to a directory outside
    /// the root (atomic exchange with `d.link`), the dispatcher writes and
    /// deletes `d/...`. After every dispatch the outside directory must be
    /// unchanged. Bounded by `PRAETORE_RACE_MILLIS` (default 1500 ms).
    #[test]
    fn race_intermediate_directory_swapped_for_outside_symlink_never_escapes() {
        use rustix::fs::{CWD, RenameFlags, renameat_with};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};
        let dirs = dirs();
        std::fs::create_dir(dirs.root.join("d")).unwrap();
        std::fs::write(dirs.outside.join("victim"), "original").unwrap();
        let d = SandboxDispatcher::open(&dirs.root).unwrap();
        // Created after open: `open` only accepts a clean root.
        symlink(&dirs.outside, dirs.root.join("d.link")).unwrap();
        let baseline = snapshot(&dirs.outside);
        let budget = Duration::from_millis(
            std::env::var("PRAETORE_RACE_MILLIS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(1500),
        );
        let stop = AtomicBool::new(false);
        let (dir_path, link_path) = (dirs.root.join("d"), dirs.root.join("d.link"));
        let (swaps, ok, refused, iterations, escape) = std::thread::scope(|scope| {
            let mut refused = std::collections::BTreeMap::<&'static str, u64>::new();
            // Stops the swapper even if this thread panics, so the scope
            // cannot wait forever.
            struct StopOnDrop<'a>(&'a AtomicBool);
            impl Drop for StopOnDrop<'_> {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Relaxed);
                }
            }
            let swapper = scope.spawn(|| {
                let mut swaps = 0u64;
                let mut d_is_link = false;
                while !stop.load(Ordering::Relaxed) {
                    renameat_with(CWD, &dir_path, CWD, &link_path, RenameFlags::EXCHANGE)
                        .expect("atomic exchange");
                    d_is_link = !d_is_link;
                    swaps += u64::from(d_is_link);
                }
                if d_is_link {
                    renameat_with(CWD, &dir_path, CWD, &link_path, RenameFlags::EXCHANGE).unwrap();
                }
                swaps
            });
            let guard = StopOnDrop(&stop);
            let started = Instant::now();
            let (mut ok, mut iterations, mut n) = (0u64, 0u64, 10_000u128);
            let mut escape = None;
            'race: while started.elapsed() < budget && iterations < 20_000 {
                let fresh = format!("d/new-{}", iterations % 8);
                let content = format!("inside-{iterations}");
                for action in [
                    write("d/victim", &content),
                    write(&fresh, &content),
                    delete(&fresh),
                    delete("d/victim"),
                ] {
                    n += 1;
                    match run(&d, n, &action) {
                        Ok(_) => ok += 1,
                        Err(_) => {
                            let reason = d.not_applied_reason(key(n)).unwrap_or("unrecorded");
                            *refused.entry(reason).or_default() += 1;
                        }
                    }
                    let now = snapshot(&dirs.outside);
                    if now != baseline {
                        escape = Some(format!(
                            "iteration {iterations}: {} {} changed the outside directory: {:?} -> {:?}",
                            action.action_type,
                            action.parameters["path"],
                            baseline.keys().collect::<Vec<_>>(),
                            now.iter()
                                .map(|(name, (_, content))| {
                                    format!("{name}={}", String::from_utf8_lossy(content))
                                })
                                .collect::<Vec<_>>()
                        ));
                        break 'race;
                    }
                }
                iterations += 1;
            }
            drop(guard);
            (swapper.join().unwrap(), ok, refused, iterations, escape)
        });
        eprintln!(
            "dispatcher race: iterations={iterations} swaps_to_symlink={swaps} ok={ok} refused={refused:?} escape={escape:?} path_resolution={:?}",
            d.path_resolution()
        );
        assert!(escape.is_none(), "{}", escape.unwrap_or_default());
        // Every refusal is the symlink/escape kind (or the delete that
        // followed a refused write); nothing transient or unexpected.
        let expected = [
            "symlink_or_non_directory_in_path",
            "mount_point_in_path",
            "file_not_found",
        ];
        assert!(
            refused.keys().all(|reason| expected.contains(reason)),
            "unexpected refusal reasons: {refused:?}"
        );
        assert!(swaps > 0 && ok > 0, "race not exercised");
        assert!(
            refused
                .get("symlink_or_non_directory_in_path")
                .is_some_and(|count| *count > 0),
            "no dispatch was refused for the swapped-in symlink: {refused:?}"
        );
        assert!(
            std::fs::symlink_metadata(dirs.root.join("d"))
                .unwrap()
                .is_dir()
        );
    }
}
