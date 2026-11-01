#![allow(dead_code)]

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// `base/root` (the sandbox root, mode 0700) next to `base/outside`, which
/// holds `victim` = "original". Removed on drop.
pub struct Tree {
    pub base: PathBuf,
    pub root: PathBuf,
    pub outside: PathBuf,
}

impl Tree {
    pub fn new(tag: &str) -> Self {
        let base = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "praetore-sandbox-fs-{tag}-{}",
                uuid::Uuid::new_v4()
            ));
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(outside.join("victim"), "original").unwrap();
        Self {
            base,
            root,
            outside,
        }
    }

    pub fn snapshot_outside(&self) -> Snapshot {
        Snapshot::of(&self.outside)
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// Name -> (inode, link count, content) for every entry of a directory,
/// without following symlinks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot(pub BTreeMap<String, (u64, u64, Vec<u8>)>);

impl Snapshot {
    pub fn of(dir: &Path) -> Self {
        let mut entries = BTreeMap::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            let content = if metadata.is_file() {
                std::fs::read(&path).unwrap_or_default()
            } else {
                Vec::new()
            };
            entries.insert(
                entry.file_name().to_string_lossy().into_owned(),
                (metadata.ino(), metadata.nlink(), content),
            );
        }
        Self(entries)
    }

    /// Human-readable list of what differs from `before`.
    pub fn diff(&self, before: &Snapshot) -> Vec<String> {
        let mut changes = Vec::new();
        for (name, value) in &self.0 {
            match before.0.get(name) {
                None => changes.push(format!("created {name}")),
                Some(old) if old.0 != value.0 || old.2 != value.2 => {
                    changes.push(format!(
                        "modified {name}: {:?} -> {:?}",
                        String::from_utf8_lossy(&old.2),
                        String::from_utf8_lossy(&value.2)
                    ));
                }
                Some(_) => {}
            }
        }
        for name in before.0.keys() {
            if !self.0.contains_key(name) {
                changes.push(format!("deleted {name}"));
            }
        }
        changes
    }
}
