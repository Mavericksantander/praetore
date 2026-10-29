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
//! Confinement does not rely on string checks alone: the root is opened once
//! as a directory file descriptor, and every path component is resolved with
//! `openat(2)` relative to its parent using `O_NOFOLLOW | O_DIRECTORY`, so a
//! symlink anywhere on the path (intermediate or final) fails with
//! `ELOOP`/`ENOTDIR` instead of being followed. Files are opened with
//! `O_NOFOLLOW | O_NONBLOCK`, checked to be regular single-link files, and
//! only then truncated. Deletion uses `fstatat(AT_SYMLINK_NOFOLLOW)` and
//! `unlinkat` on the parent descriptor. Intermediate directories are never
//! created.
//!
//! Idempotency and reconciliation records are kept in memory and are lost on
//! restart, like the local demo adapter.

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
    #[error("sandbox root is not accessible: {0}")]
    Io(#[from] io::Error),
    #[error("sandbox content limit must be between 1 byte and 32 KiB")]
    InvalidLimit,
}

#[derive(Default)]
struct Records {
    executions: HashMap<ExecutionKey, (String, Value)>,
}

pub struct SandboxDispatcher {
    root: PathBuf,
    root_fd: OwnedFd,
    target: String,
    max_content_bytes: usize,
    demo: Option<LocalDemoDispatcher>,
    records: Mutex<Records>,
}

enum FsOp<'a> {
    Write { path: &'a str, content: &'a str },
    Delete { path: &'a str },
}

impl SandboxDispatcher {
    /// Opens `root` fail-closed: it must exist, be an absolute, canonical,
    /// non-symlink directory. The directory is held open for the lifetime of
    /// the dispatcher, so renaming or replacing the path later has no effect.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, SandboxConfigError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(SandboxConfigError::NotAbsolute);
        }
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
        let c_root = CString::new(canonical.as_os_str().as_bytes())
            .map_err(|_| SandboxConfigError::NotCanonical(canonical.clone()))?;
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
        Ok(Self {
            root: canonical,
            root_fd,
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

    /// Walks every intermediate component without following symlinks and
    /// returns the parent directory fd plus the final component name.
    fn open_parent(&self, path: &str) -> Result<(OwnedFd, CString), DispatchRefused> {
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
        }
        Ok((current, c_component(name)?))
    }

    /// Side-effect-free inspection of the final component.
    fn check_final(&self, op: &FsOp<'_>) -> Result<(), DispatchRefused> {
        let path = match op {
            FsOp::Write { path, .. } | FsOp::Delete { path } => path,
        };
        let (parent, name) = self.open_parent(path)?;
        match fstatat_nofollow(parent.as_raw_fd(), &name) {
            Ok(stat) => check_regular_single_link(&stat),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => match op {
                FsOp::Write { .. } => Ok(()),
                FsOp::Delete { .. } => Err(DispatchRefused("file_not_found")),
            },
            Err(_) => Err(DispatchRefused("file_unavailable")),
        }
    }

    fn admit(&self, action: &Action) -> Result<(), DispatchRefused> {
        if action.action_type == "demo:set_value" && self.demo.is_some() {
            return Ok(());
        }
        let op = self.parse(action)?;
        self.check_final(&op)
    }

    fn perform(&self, op: &FsOp<'_>) -> Result<DispatchReport, DispatchError> {
        match op {
            FsOp::Write { path, content } => {
                let (parent, name) = self.open_parent(path).map_err(|_| DispatchError)?;
                // SAFETY: valid dirfd and NUL-terminated name. O_NOFOLLOW makes
                // a final symlink fail; O_NONBLOCK keeps a FIFO from blocking.
                let fd = unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_WRONLY
                            | libc::O_CREAT
                            | libc::O_NOFOLLOW
                            | libc::O_NONBLOCK
                            | libc::O_CLOEXEC,
                        0o600 as libc::c_uint,
                    )
                };
                if fd < 0 {
                    return Err(DispatchError);
                }
                // SAFETY: freshly opened, exclusively owned.
                let mut file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
                let stat = fstat(file.as_raw_fd()).map_err(|_| DispatchError)?;
                check_regular_single_link(&stat).map_err(|_| DispatchError)?;
                file.set_len(0).map_err(|_| DispatchError)?;
                file.write_all(content.as_bytes())
                    .map_err(|_| DispatchError)?;
                file.sync_all().map_err(|_| DispatchError)?;
                let written = fstat(file.as_raw_fd()).map_err(|_| DispatchError)?;
                let output = json!({
                    "action": WRITE_ACTION,
                    "path": path,
                    "bytes": content.len(),
                    "sha256": hex::encode(Sha256::digest(content.as_bytes())),
                });
                if written.st_size as u64 == content.len() as u64 {
                    Ok(DispatchReport::Confirmed(output))
                } else {
                    Ok(DispatchReport::Executed(output))
                }
            }
            FsOp::Delete { path } => {
                let (parent, name) = self.open_parent(path).map_err(|_| DispatchError)?;
                let stat =
                    fstatat_nofollow(parent.as_raw_fd(), &name).map_err(|_| DispatchError)?;
                check_regular_single_link(&stat).map_err(|_| DispatchError)?;
                // SAFETY: valid dirfd and NUL-terminated name; flag 0 = file.
                if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                    return Err(DispatchError);
                }
                // SAFETY: valid directory fd.
                unsafe { libc::fsync(parent.as_raw_fd()) };
                let output = json!({"action": DELETE_ACTION, "path": path});
                match fstatat_nofollow(parent.as_raw_fd(), &name) {
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
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
        let op = self.parse(action).map_err(|_| DispatchError)?;
        let report = self.perform(&op)?;
        let output = match &report {
            DispatchReport::Executed(output) | DispatchReport::Confirmed(output) => output.clone(),
        };
        records
            .executions
            .insert(key, (action_digest.to_owned(), output));
        Ok(report)
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
            _ => ReconciliationReport::Unknown,
        }
    }

    fn preflight(&self, action: &Action) -> Result<(), DispatchRefused> {
        self.admit(action)
    }
}

/// Accepts only `name(/name)*` with each name a normal, non-empty component.
/// Rejects absolute paths, `.`/`..`, empty components (`a//b`, trailing `/`),
/// NUL and control characters, backslashes, and excessive length or depth.
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
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b'\\')
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
            _ => {}
        }
    }
    if depth > MAX_PATH_DEPTH {
        return Err(DispatchRefused("path_too_deep"));
    }
    Ok(())
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
    use std::os::unix::fs::symlink;
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
}
