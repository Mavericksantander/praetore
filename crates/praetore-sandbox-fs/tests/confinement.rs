//! Deterministic confinement cases. Each case runs with every resolver the
//! platform has (`Auto`, `Walk`, and on Linux with openat2 also `Openat2`)
//! and checks both the refusal and that nothing outside the root changed.

mod common;

use common::Tree;
use praetore_sandbox_fs::{Access, ConfineError, Resolver, Root};
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, symlink};
use std::path::Path;

fn roots(path: &Path) -> Vec<Root> {
    let mut resolvers = vec![Resolver::Auto, Resolver::Walk];
    if praetore_sandbox_fs::openat2_available(&Root::open(path).unwrap()) {
        resolvers.push(Resolver::Openat2);
    }
    resolvers
        .into_iter()
        .map(|resolver| Root::open(path).unwrap().with_resolver(resolver))
        .collect()
}

macro_rules! assert_err {
    ($result:expr, $pattern:pat, $root:expr) => {
        match $result {
            Err($pattern) => {}
            other => panic!(
                "{:?}: expected {}, got {other:?}",
                $root.resolver(),
                stringify!($pattern)
            ),
        }
    };
}

#[test]
fn writes_and_deletes_inside_the_root_work() {
    let tree = Tree::new("ok");
    std::fs::create_dir_all(tree.root.join("a/b")).unwrap();
    let before = tree.snapshot_outside();
    for root in roots(&tree.root) {
        let written = root.write_file("a/b/f.txt", b"hola", 0o600).unwrap();
        assert_eq!(written.bytes, 4);
        assert_eq!(std::fs::read(tree.root.join("a/b/f.txt")).unwrap(), b"hola");
        root.write_file("a/b/f.txt", b"adios", 0o600).unwrap();
        assert_eq!(
            std::fs::read(tree.root.join("a/b/f.txt")).unwrap(),
            b"adios"
        );
        let mut file = root.open_file("a/b/f.txt", Access::Write).unwrap();
        file.write_all(b"ADIOS").unwrap();
        root.remove_file("a/b/f.txt").unwrap();
        assert!(!tree.root.join("a/b/f.txt").exists());
        root.create_new_file("top.txt", 0o640).unwrap();
        assert_err!(
            root.create_new_file("top.txt", 0o640),
            ConfineError::AlreadyExists,
            root
        );
        root.remove_file("top.txt").unwrap();
    }
    assert!(tree.snapshot_outside().diff(&before).is_empty());
}

#[test]
fn final_component_symlink_is_never_followed() {
    let tree = Tree::new("final-symlink");
    symlink(tree.outside.join("victim"), tree.root.join("link")).unwrap();
    // Dangling: O_CREAT without O_EXCL would create outside/created.
    symlink(tree.outside.join("created"), tree.root.join("dangling")).unwrap();
    let before = tree.snapshot_outside();
    for root in roots(&tree.root) {
        assert_err!(
            root.write_file("link", b"x", 0o600),
            ConfineError::Symlink,
            root
        );
        assert_err!(
            root.open_file("link", Access::Write),
            ConfineError::Symlink,
            root
        );
        assert_err!(
            root.open_file("link", Access::Read),
            ConfineError::Symlink,
            root
        );
        assert_err!(root.remove_file("link"), ConfineError::Symlink, root);
        assert_err!(
            root.create_new_file("link", 0o600),
            ConfineError::AlreadyExists,
            root
        );
        assert_err!(
            root.write_file("dangling", b"x", 0o600),
            ConfineError::Symlink,
            root
        );
        assert_err!(
            root.create_new_file("dangling", 0o600),
            ConfineError::AlreadyExists,
            root
        );
        // The low-level rename/unlink act on the entry, never the target.
        let (dir, _) = root.open_parent("link").unwrap();
        let mut temp = dir.create_new("tmp", 0o600).unwrap();
        temp.write_all(b"replacement").unwrap();
        dir.rename("tmp", "link").unwrap();
        assert!(
            std::fs::symlink_metadata(tree.root.join("link"))
                .unwrap()
                .is_file()
        );
        dir.unlink("link").unwrap();
        symlink(tree.outside.join("victim"), tree.root.join("link")).unwrap();
    }
    assert!(tree.snapshot_outside().diff(&before).is_empty());
    assert!(!tree.outside.join("created").exists());
}

#[test]
fn intermediate_symlink_is_never_followed() {
    let tree = Tree::new("intermediate-symlink");
    std::fs::create_dir(tree.outside.join("sub")).unwrap();
    std::fs::write(tree.outside.join("sub/victim"), "original").unwrap();
    symlink(&tree.outside, tree.root.join("d")).unwrap();
    std::fs::create_dir(tree.root.join("a")).unwrap();
    symlink(tree.outside.join("sub"), tree.root.join("a/b")).unwrap();
    // Even a symlink that stays inside the root is refused: no symlinks.
    std::fs::create_dir(tree.root.join("real")).unwrap();
    symlink(tree.root.join("real"), tree.root.join("alias")).unwrap();
    // A regular file used as a directory.
    std::fs::write(tree.root.join("file"), "x").unwrap();
    let before = tree.snapshot_outside();
    let before_sub = common::Snapshot::of(&tree.outside.join("sub"));
    for root in roots(&tree.root) {
        for path in ["d/victim", "d/new", "a/b/victim", "a/b/new", "alias/x"] {
            assert_err!(
                root.write_file(path, b"x", 0o600),
                ConfineError::SymlinkOrNotDirectory,
                root
            );
            assert_err!(
                root.remove_file(path),
                ConfineError::SymlinkOrNotDirectory,
                root
            );
            assert_err!(
                root.create_new_file(path, 0o600),
                ConfineError::SymlinkOrNotDirectory,
                root
            );
            assert_err!(
                root.open_file(path, Access::Write),
                ConfineError::SymlinkOrNotDirectory,
                root
            );
        }
        assert_err!(
            root.write_file("file/x", b"x", 0o600),
            ConfineError::SymlinkOrNotDirectory,
            root
        );
        assert_err!(
            root.write_file("missing/x", b"x", 0o600),
            ConfineError::MissingParent,
            root
        );
    }
    assert!(tree.snapshot_outside().diff(&before).is_empty());
    assert!(
        common::Snapshot::of(&tree.outside.join("sub"))
            .diff(&before_sub)
            .is_empty()
    );
    assert!(!tree.root.join("real/x").exists());
}

#[test]
fn dot_dot_and_absolute_paths_are_refused() {
    let tree = Tree::new("dotdot");
    std::fs::create_dir(tree.root.join("d")).unwrap();
    let before = tree.snapshot_outside();
    let absolute = tree.outside.join("victim");
    let absolute = absolute.to_str().unwrap();
    for root in roots(&tree.root) {
        for (path, reason) in [
            ("../outside/victim", "dot_component"),
            ("d/../../outside/victim", "dot_component"),
            ("..", "dot_component"),
            ("d/.", "dot_component"),
            (absolute, "absolute_path"),
            ("/etc/passwd", "absolute_path"),
            ("", "empty_path"),
            ("d//x", "empty_component"),
            ("d/x/", "empty_component"),
        ] {
            match root.write_file(path, b"x", 0o600) {
                Err(ConfineError::InvalidPath(got)) => assert_eq!(got, reason, "{path:?}"),
                other => panic!("{path:?}: {other:?}"),
            }
            assert!(matches!(
                root.remove_file(path),
                Err(ConfineError::InvalidPath(_))
            ));
        }
    }
    assert!(tree.snapshot_outside().diff(&before).is_empty());
}

/// A hard link to an outside file can be *detected* (`st_nlink > 1`) and is
/// refused; O_NOFOLLOW alone would not stop it. Replacing by rename never
/// writes the shared inode even if the link appears after the check. A link
/// created after an in-place open is NOT detected (documented residual).
#[test]
fn hard_links_are_detected_and_never_written_through() {
    let tree = Tree::new("hardlink");
    let victim = tree.outside.join("victim");
    std::fs::hard_link(&victim, tree.root.join("hl")).unwrap();
    let before = tree.snapshot_outside();
    for root in roots(&tree.root) {
        assert_err!(
            root.write_file("hl", b"x", 0o600),
            ConfineError::HardLinked,
            root
        );
        assert_err!(
            root.open_file("hl", Access::Write),
            ConfineError::HardLinked,
            root
        );
        assert_err!(root.remove_file("hl"), ConfineError::HardLinked, root);
        // Link appearing between the check and the rename: the rename
        // replaces the inside entry; the outside inode keeps its content.
        let (dir, name) = root.open_parent("late").unwrap();
        assert!(dir.check_entry(name, true).unwrap().is_none());
        let mut temp = dir.create_new("tmp", 0o600).unwrap();
        temp.write_all(b"new").unwrap();
        std::fs::hard_link(&victim, tree.root.join("late")).unwrap();
        dir.rename("tmp", name).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"original");
        assert_eq!(std::fs::read(tree.root.join("late")).unwrap(), b"new");
        std::fs::remove_file(tree.root.join("late")).unwrap();
    }
    assert!(tree.snapshot_outside().diff(&before).is_empty());
    assert_eq!(std::fs::read(&victim).unwrap(), b"original");
}

#[test]
fn hard_link_created_after_in_place_open_is_not_detected() {
    let tree = Tree::new("hardlink-late");
    std::fs::write(tree.root.join("f"), "inside").unwrap();
    let root = Root::open(&tree.root).unwrap();
    let mut file = root.open_file("f", Access::Write).unwrap();
    // Another process with write access outside links the inode out.
    std::fs::hard_link(tree.root.join("f"), tree.outside.join("alias")).unwrap();
    file.write_all(b"LEAKED").unwrap();
    drop(file);
    // Residual risk, asserted so it stays documented: the write is visible
    // outside through the late link.
    assert_eq!(
        std::fs::read(tree.outside.join("alias")).unwrap(),
        b"LEAKED"
    );
}

#[test]
fn fifos_are_refused_without_blocking() {
    let tree = Tree::new("fifo");
    let fifo = tree.root.join("fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        std::fs::symlink_metadata(&fifo)
            .unwrap()
            .file_type()
            .is_fifo()
    );
    for root in roots(&tree.root) {
        assert_err!(
            root.write_file("fifo", b"x", 0o600),
            ConfineError::NotRegularFile,
            root
        );
        assert_err!(
            root.open_file("fifo", Access::Write),
            ConfineError::NotRegularFile,
            root
        );
        assert_err!(
            root.open_file("fifo", Access::Read),
            ConfineError::NotRegularFile,
            root
        );
        assert_err!(root.remove_file("fifo"), ConfineError::NotRegularFile, root);
        // The descriptor-level check alone (no pre-check): O_NONBLOCK opens
        // or fails immediately and fstat refuses it.
        let (dir, name) = root.open_parent("fifo").unwrap();
        assert_err!(
            dir.open_existing(name, Access::Read),
            ConfineError::NotRegularFile,
            root
        );
    }
    assert!(
        std::fs::symlink_metadata(&fifo)
            .unwrap()
            .file_type()
            .is_fifo()
    );
}

/// Device nodes cannot be created without privileges, so `/dev` itself is
/// used as the root: `null` is a character device there. Nothing is ever
/// created in `/dev` because the target is refused before any temporary
/// file is made.
#[test]
fn devices_are_refused() {
    let dev = Path::new("/dev");
    assert!(
        std::fs::symlink_metadata("/dev/null")
            .unwrap()
            .file_type()
            .is_char_device()
    );
    for root in roots(dev) {
        assert_err!(
            root.write_file("null", b"x", 0o600),
            ConfineError::NotRegularFile,
            root
        );
        assert_err!(
            root.open_file("null", Access::Write),
            ConfineError::NotRegularFile,
            root
        );
        assert_err!(
            root.open_file("null", Access::Read),
            ConfineError::NotRegularFile,
            root
        );
        assert_err!(root.remove_file("null"), ConfineError::NotRegularFile, root);
    }
    assert!(
        std::fs::symlink_metadata("/dev/null")
            .unwrap()
            .file_type()
            .is_char_device()
    );
}

/// With CAP_MKNOD (for example root in a container) a device node is also
/// created inside a temporary root; otherwise the case is reported skipped.
#[cfg(target_os = "linux")]
#[test]
fn device_node_inside_root_is_refused_when_it_can_be_created() {
    use rustix::fs::{CWD, FileType, Mode, makedev, mknodat};
    let tree = Tree::new("device");
    let node = tree.root.join("null");
    if let Err(errno) = mknodat(
        CWD,
        &node,
        FileType::CharacterDevice,
        Mode::RUSR | Mode::WUSR,
        makedev(1, 3),
    ) {
        eprintln!("device node test SKIPPED: mknod failed ({errno}); covered via /dev");
        return;
    }
    for root in roots(&tree.root) {
        assert_err!(
            root.write_file("null", b"x", 0o600),
            ConfineError::NotRegularFile,
            root
        );
        assert_err!(
            root.open_file("null", Access::Write),
            ConfineError::NotRegularFile,
            root
        );
        assert_err!(root.remove_file("null"), ConfineError::NotRegularFile, root);
    }
}

#[test]
fn directories_are_not_files() {
    let tree = Tree::new("dirs");
    std::fs::create_dir(tree.root.join("dir")).unwrap();
    for root in roots(&tree.root) {
        assert_err!(
            root.write_file("dir", b"x", 0o600),
            ConfineError::NotRegularFile,
            root
        );
        assert_err!(root.remove_file("dir"), ConfineError::NotRegularFile, root);
        assert_err!(
            root.open_file("dir", Access::Read),
            ConfineError::NotRegularFile,
            root
        );
    }
    assert!(tree.root.join("dir").is_dir());
}

#[test]
fn openat2_is_reported_correctly_for_the_platform() {
    let tree = Tree::new("probe");
    let root = Root::open(&tree.root).unwrap();
    let available = praetore_sandbox_fs::openat2_available(&root);
    eprintln!("openat2 available: {available}");
    if cfg!(not(target_os = "linux")) {
        assert!(!available);
        assert_err!(
            root.with_resolver(Resolver::Openat2).open_parent("a/b"),
            ConfineError::Openat2Unavailable,
            Root::open(&tree.root).unwrap()
        );
    }
}
