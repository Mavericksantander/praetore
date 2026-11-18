//! Where a secret key may be read from.
//!
//! The key files used to be read with calls that follow symlinks. A scratch
//! home whose `keys` was a symlink to another home's `keys/` (or whose key
//! files were symlinks or hard links to that home's files) therefore signed
//! receipts with the other home's keys under its own policy, without the
//! process that set it up ever opening a key file. [`KeyPath`] is the only
//! way to a secret: it refuses that layout before anything is read.

use crate::{shown::Show, store::Home};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// A key file under `DIR/keys` that passed the checks of [`KeyPath::new`].
#[derive(Debug)]
pub struct KeyPath {
    path: PathBuf,
}

impl KeyPath {
    /// Checks, without following any link (`lstat`):
    /// * no directory above `keys/` is a symlink made by a user (a symlink
    ///   owned by root, such as `/tmp` or `/var` on macOS, is the system's);
    /// * `keys/` is a real directory owned by the effective user;
    /// * the key is a regular file owned by the effective user, with one
    ///   name (no hard link elsewhere) and no access for group or others.
    pub fn new(home: &Home, file_name: &str) -> Result<Self, String> {
        check_keys_dir(home)?;
        let path = home.keys_dir().join(file_name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.shown()))?;
        check_key_file(&metadata, &path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Opens the key with `O_NOFOLLOW` and repeats the file checks on the
    /// open descriptor, so what is read is what was checked.
    fn open(&self) -> Result<fs::File, String> {
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(crate::journal::nofollow_flag());
        }
        let file = options
            .open(&self.path)
            .map_err(|e| format!("cannot open {}: {e}", self.path.shown()))?;
        let metadata = file
            .metadata()
            .map_err(|e| format!("cannot read {}: {e}", self.path.shown()))?;
        check_key_file(&metadata, &self.path)?;
        Ok(file)
    }

    /// The file's text. The buffer is wiped when dropped.
    pub fn read(&self) -> Result<Zeroizing<String>, String> {
        let mut text = Zeroizing::new(String::new());
        self.open()?
            .read_to_string(&mut text)
            .map_err(|e| format!("cannot read {}: {e}", self.path.shown()))?;
        Ok(text)
    }
}

/// How to fix a refused layout; appended to every refusal.
const FIX: &str = "Keys are read only from a real DIR/keys directory with real files owned by the user running this program, so that one home cannot sign with another home's keys. Use a home whose keys were created in place by its own init";

/// The checks of [`KeyPath::new`] on the directories. Also what `init`,
/// `verify` and `policy check` run on a home before using it.
pub fn check_keys_dir(home: &Home) -> Result<(), String> {
    let keys = home.keys_dir();
    for ancestor in keys.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() && !system_owned(&metadata) => {
                return Err(format!(
                    "{} is a symlink, and {} is below it. {FIX}",
                    ancestor.shown(),
                    keys.shown()
                ));
            }
            // A missing directory is created (or reported) by the caller.
            _ => {}
        }
    }
    let metadata = match fs::symlink_metadata(&keys) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("cannot read {}: {error}", keys.shown())),
    };
    if metadata.file_type().is_symlink() {
        return Err(format!("{} is a symlink. {FIX}", keys.shown()));
    }
    if !metadata.is_dir() {
        return Err(format!("{} is not a directory. {FIX}", keys.shown()));
    }
    check_owner(&metadata, &keys)
}

/// [`check_keys_dir`], and [`KeyPath::new`] for every key file of `home`
/// that exists. A home copied without its `keys/` passes.
pub fn check_home_keys(home: &Home) -> Result<(), String> {
    check_keys_dir(home)?;
    for path in home.key_files() {
        if fs::symlink_metadata(&path).is_ok() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("key file name is not UTF-8")?;
            KeyPath::new(home, name)?;
        }
    }
    Ok(())
}

fn check_key_file(metadata: &fs::Metadata, path: &Path) -> Result<(), String> {
    if metadata.file_type().is_symlink() {
        return Err(format!("{} is a symlink. {FIX}", path.shown()));
    }
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file. {FIX}", path.shown()));
    }
    check_owner(metadata, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 {
            return Err(format!(
                "{} has {} hard links: the same key file has another name. {FIX}",
                path.shown(),
                metadata.nlink()
            ));
        }
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} is accessible by group/others (mode {:o}); run: chmod 600 {}",
                path.shown(),
                mode & 0o777,
                path.shown()
            ));
        }
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn check_owner(metadata: &fs::Metadata, path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid {
        return Err(format!(
            "{} is owned by uid {}, not by the user running praetore-mcp (uid {euid}). {FIX}",
            path.shown(),
            metadata.uid()
        ));
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn check_owner(_metadata: &fs::Metadata, _path: &Path) -> Result<(), String> {
    Ok(())
}

/// Whether a symlink above `keys/` belongs to the system: owned by root,
/// so no unprivileged user made it or can repoint it.
#[cfg(unix)]
fn system_owned(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.uid() == 0
}

#[cfg(not(unix))]
fn system_owned(_metadata: &fs::Metadata) -> bool {
    false
}
