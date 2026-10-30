//! Careful file replacement for client configs and the policy.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

/// Creates a new file (O_CREAT|O_EXCL, so an existing file or symlink at
/// `path` is never followed or reused) with Unix `mode`.
pub fn create_new(path: &Path, mode: u32) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    options.open(path)
}

/// The file to rewrite: `path` itself, or the final target if `path` is a
/// symlink (dotfile managers), so the link is preserved.
pub fn resolve_target(path: &Path) -> Result<PathBuf, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    let real = if metadata.file_type().is_symlink() {
        fs::canonicalize(path)
            .map_err(|e| format!("cannot resolve symlink {}: {e}", path.display()))?
    } else {
        path.to_path_buf()
    };
    if !fs::metadata(&real)
        .map_err(|e| format!("cannot stat {}: {e}", real.display()))?
        .is_file()
    {
        return Err(format!("{} is not a regular file", real.display()));
    }
    Ok(real)
}

fn timestamp() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

/// Writes a 0600 backup of `contents` next to `real`, never overwriting.
fn write_backup(real: &Path, contents: &str) -> Result<PathBuf, String> {
    let stamp = timestamp();
    for counter in 0..1000 {
        let suffix = if counter == 0 {
            format!(".praetore-backup-{stamp}")
        } else {
            format!(".praetore-backup-{stamp}-{counter}")
        };
        let candidate = sibling(real, &suffix);
        match create_new(&candidate, 0o600) {
            Ok(mut file) => {
                file.write_all(contents.as_bytes())
                    .and_then(|()| file.sync_all())
                    .map_err(|e| format!("cannot write backup {}: {e}", candidate.display()))?;
                return Ok(candidate);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "cannot create backup {}: {error}",
                    candidate.display()
                ));
            }
        }
    }
    Err(format!("too many backups next to {}", real.display()))
}

/// Replaces the file at `path` (or its symlink target) with `updated`:
/// checks it still holds `original`, writes a 0600 backup, writes a
/// randomly named temp file in the same directory with the original
/// permissions, then renames it over the target. Returns
/// `(target, backup)`.
pub fn write_with_backup(
    path: &Path,
    original: &str,
    updated: &str,
) -> Result<(PathBuf, PathBuf), String> {
    let real = resolve_target(path)?;
    let current =
        fs::read_to_string(&real).map_err(|e| format!("cannot read {}: {e}", real.display()))?;
    if current != original {
        return Err(format!(
            "{} changed while praetore-mcp was working; nothing was written",
            real.display()
        ));
    }
    let permissions = fs::metadata(&real)
        .map_err(|e| format!("cannot stat {}: {e}", real.display()))?
        .permissions();
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        permissions.mode() & 0o777
    };
    #[cfg(not(unix))]
    let mode = 0o600;

    let backup = write_backup(&real, original)?;
    let tmp = sibling(
        &real,
        &format!(".praetore-tmp-{}", uuid::Uuid::new_v4().simple()),
    );
    let result = (|| -> io::Result<()> {
        let mut file = create_new(&tmp, mode)?;
        file.write_all(updated.as_bytes())?;
        file.sync_all()?;
        fs::set_permissions(&tmp, permissions)?;
        fs::rename(&tmp, &real)
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&tmp);
        return Err(format!("cannot update {}: {error}", real.display()));
    }
    Ok((real, backup))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_keeps_mode_and_private_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        fs::write(&path, "old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        }
        let (real, backup) = write_with_backup(&path, "old", "new").unwrap();
        assert_eq!(real, path);
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(fs::read_to_string(&backup).unwrap(), "old");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o640);
            assert_eq!(mode(&backup), 0o600);
        }
        // A concurrent change is detected and nothing is written.
        assert!(write_with_backup(&path, "old", "newer").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_config_updates_target_and_keeps_link() {
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("dotfiles");
        fs::create_dir(&real_dir).unwrap();
        let real = real_dir.join("mcp.json");
        fs::write(&real, "old").unwrap();
        let link = dir.path().join("mcp.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let (target, backup) = write_with_backup(&link, "old", "new").unwrap();
        assert_eq!(target, fs::canonicalize(&real).unwrap());
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&real).unwrap(), "new");
        assert_eq!(backup.parent(), target.parent());
    }

    #[cfg(unix)]
    #[test]
    fn create_new_refuses_existing_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, "keep").unwrap();
        let link = dir.path().join("tmp");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(create_new(&link, 0o600).is_err());
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
    }
}
