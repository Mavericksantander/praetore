//! TOCTOU races. Intermediate component: one thread keeps swapping the
//! directory `root/d` for a symlink to a directory outside the root, and
//! back, while another thread writes and deletes `d/...` paths. Final
//! component: one thread keeps swapping the regular file `root/t` with a
//! symlink to an outside file, a hard link to it, or a non-empty directory,
//! while another writes and deletes `t`. After every single operation the
//! outside directory must be exactly as it was: nothing created, modified
//! or deleted (and the swapped directory must keep its content).
//!
//! The same test can be pointed at a deliberately path-based implementation
//! (check every component with `symlink_metadata`, then `std::fs::write` /
//! `std::fs::remove_file` on the joined path) to show that it detects the
//! race:
//!
//! ```text
//! PRAETORE_SANDBOX_FS_RACE_IMPL=path-based cargo test -p praetore-sandbox-fs --test race
//! ```
//!
//! Bounds: `PRAETORE_RACE_MILLIS` (default 1500 ms per test) and at most
//! 20 000 iterations. `PRAETORE_REQUIRE_OPENAT2=1` makes the Linux `openat2`
//! variant fail instead of skipping when the kernel lacks `openat2`.

mod common;

use common::{Snapshot, Tree};
use praetore_sandbox_fs::{ConfineError, Resolver, Root};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_ITERATIONS: u64 = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ok,
    RefusedSymlink,
    /// Refused because the final entry was a hard link or not a regular
    /// file (the swapped-in hard link or directory).
    RefusedSpecial,
    Missing,
    Other,
}

trait Effects: Send + Sync {
    fn label(&self) -> String;
    fn write(&self, path: &str, content: &[u8]) -> Outcome;
    fn remove(&self, path: &str) -> Outcome;
}

struct FdEffects(Root);

fn classify(result: Result<(), ConfineError>) -> Outcome {
    match result {
        Ok(()) => Outcome::Ok,
        Err(ConfineError::SymlinkOrNotDirectory | ConfineError::Symlink) => Outcome::RefusedSymlink,
        Err(ConfineError::MissingParent | ConfineError::NotFound) => Outcome::Missing,
        Err(ConfineError::HardLinked | ConfineError::NotRegularFile) => Outcome::RefusedSpecial,
        Err(_) => Outcome::Other,
    }
}

impl Effects for FdEffects {
    fn label(&self) -> String {
        format!("fd/{:?}", self.0.resolver())
    }

    fn write(&self, path: &str, content: &[u8]) -> Outcome {
        classify(self.0.write_file(path, content, 0o600).map(drop))
    }

    fn remove(&self, path: &str) -> Outcome {
        classify(self.0.remove_file(path).map(drop))
    }
}

/// DELIBERATELY VULNERABLE, test-only reference: checks the path, then uses
/// the path. Never use this outside this test.
struct PathBasedReference {
    root: PathBuf,
}

impl PathBasedReference {
    fn check(&self, path: &str) -> Outcome {
        let components: Vec<&str> = path.split('/').collect();
        let mut current = self.root.clone();
        for (index, component) in components.iter().enumerate() {
            if component.is_empty() || *component == "." || *component == ".." {
                return Outcome::Other;
            }
            current.push(component);
            let last = index + 1 == components.len();
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Outcome::RefusedSymlink;
                }
                Ok(metadata) if !last && !metadata.is_dir() => return Outcome::Other,
                Ok(metadata) if last && metadata.is_dir() => return Outcome::RefusedSpecial,
                Ok(_) => {}
                Err(_) if last => {}
                Err(_) => return Outcome::Missing,
            }
        }
        Outcome::Ok
    }
}

impl Effects for PathBasedReference {
    fn label(&self) -> String {
        "path-based reference (check, then std::fs on the joined path)".into()
    }

    fn write(&self, path: &str, content: &[u8]) -> Outcome {
        match self.check(path) {
            Outcome::Ok => match std::fs::write(self.root.join(path), content) {
                Ok(()) => Outcome::Ok,
                Err(_) => Outcome::Other,
            },
            refused => refused,
        }
    }

    fn remove(&self, path: &str) -> Outcome {
        match self.check(path) {
            Outcome::Ok => match std::fs::remove_file(self.root.join(path)) {
                Ok(()) => Outcome::Ok,
                Err(_) => Outcome::Missing,
            },
            refused => refused,
        }
    }
}

fn implementation(tree: &Tree, resolver: Resolver) -> Box<dyn Effects> {
    match std::env::var("PRAETORE_SANDBOX_FS_RACE_IMPL").as_deref() {
        Ok("path-based") => Box::new(PathBasedReference {
            root: tree.root.clone(),
        }),
        Ok("fd") | Err(_) => Box::new(FdEffects(
            Root::open(&tree.root).unwrap().with_resolver(resolver),
        )),
        Ok(other) => panic!("unknown PRAETORE_SANDBOX_FS_RACE_IMPL={other}"),
    }
}

fn duration() -> Duration {
    let millis = std::env::var("PRAETORE_RACE_MILLIS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1500);
    Duration::from_millis(millis)
}

/// Swaps `root/d` (a real directory) with a symlink to `outside`, and back,
/// until `stop`. Uses an atomic exchange (`renameat2(RENAME_EXCHANGE)` on
/// Linux, `renameatx_np(RENAME_SWAP)` on macOS) with `root/d.link`, so `d`
/// always exists; falls back to rename/symlink/unlink/rename where the
/// filesystem has no exchange. Returns how many times `d` became the
/// symlink.
fn swapper(root: PathBuf, outside: PathBuf, stop: Arc<AtomicBool>) -> u64 {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    let d = root.join("d");
    let link = root.join("d.link");
    let parked = root.join("d.real");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    let mut swaps = 0;
    let mut d_is_link = false;
    let mut exchange = true;
    while !stop.load(Ordering::Relaxed) {
        if exchange {
            match renameat_with(CWD, &d, CWD, &link, RenameFlags::EXCHANGE) {
                Ok(()) => {
                    d_is_link = !d_is_link;
                    swaps += u64::from(d_is_link);
                }
                Err(_) => exchange = false,
            }
            continue;
        }
        if std::fs::rename(&d, &parked).is_err() {
            continue;
        }
        if std::os::unix::fs::symlink(&outside, &d).is_ok() {
            swaps += 1;
            std::thread::yield_now();
            let _ = std::fs::remove_file(&d);
        }
        let _ = std::fs::rename(&parked, &d);
    }
    if d_is_link {
        renameat_with(CWD, &d, CWD, &link, RenameFlags::EXCHANGE).unwrap();
    }
    let _ = std::fs::remove_file(&link);
    restore(&root);
    let mode = if exchange {
        "atomic exchange"
    } else {
        "rename/symlink fallback"
    };
    eprintln!("swapper: {mode}");
    swaps
}

fn restore(root: &Path) {
    let d = root.join("d");
    if std::fs::symlink_metadata(&d).is_ok_and(|m| m.file_type().is_symlink()) {
        std::fs::remove_file(&d).unwrap();
    }
    if root.join("d.real").exists() {
        std::fs::rename(root.join("d.real"), &d).unwrap();
    }
    assert!(std::fs::symlink_metadata(&d).unwrap().is_dir());
}

#[derive(Debug, Default)]
struct Tally {
    iterations: u64,
    ok: u64,
    refused_symlink: u64,
    refused_special: u64,
    missing: u64,
    other: u64,
    escapes: Vec<String>,
}

impl Tally {
    fn add(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Ok => self.ok += 1,
            Outcome::RefusedSymlink => self.refused_symlink += 1,
            Outcome::RefusedSpecial => self.refused_special += 1,
            Outcome::Missing => self.missing += 1,
            Outcome::Other => self.other += 1,
        }
    }
}

fn run_race(tag: &str, resolver: Resolver) {
    let tree = Tree::new(tag);
    std::fs::create_dir(tree.root.join("d")).unwrap();
    let effects = implementation(&tree, resolver);
    let mut baseline = tree.snapshot_outside();
    let stop = Arc::new(AtomicBool::new(false));
    let swaps = AtomicU64::new(0);
    let budget = duration();
    let tally = std::thread::scope(|scope| {
        let swapper = {
            let (root, outside, stop) = (tree.root.clone(), tree.outside.clone(), stop.clone());
            scope.spawn(move || swapper(root, outside, stop))
        };
        // Stops the swapper even if this thread panics, so the scope cannot
        // wait forever.
        struct StopOnDrop(Arc<AtomicBool>);
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let guard = StopOnDrop(stop.clone());
        let started = Instant::now();
        let mut tally = Tally::default();
        while tally.iterations < MAX_ITERATIONS && started.elapsed() < budget {
            let i = tally.iterations;
            let fresh = format!("d/new-{}", i % 8);
            let content = format!("inside-{i}");
            let ops: [(&str, &str, bool); 4] = [
                ("write", "d/victim", true),
                ("write", &fresh, true),
                ("delete", &fresh, false),
                ("delete", "d/victim", false),
            ];
            for (op, path, is_write) in ops {
                let outcome = if is_write {
                    effects.write(path, content.as_bytes())
                } else {
                    effects.remove(path)
                };
                tally.add(outcome);
                let changes = Snapshot::of(&tree.outside).diff(&baseline);
                if !changes.is_empty() {
                    tally.escapes.push(format!(
                        "iteration {i}: {op} {path:?} -> {outcome:?}; outside: {}",
                        changes.join(", ")
                    ));
                    // Put the outside directory back so later escapes are
                    // detected individually.
                    for entry in std::fs::read_dir(&tree.outside).unwrap() {
                        let _ = std::fs::remove_file(entry.unwrap().path());
                    }
                    std::fs::write(tree.outside.join("victim"), "original").unwrap();
                    baseline = tree.snapshot_outside();
                    break;
                }
            }
            tally.iterations += 1;
            if tally.escapes.len() >= 20 {
                break;
            }
        }
        drop(guard);
        swaps.store(swapper.join().unwrap(), Ordering::Relaxed);
        tally
    });
    let swaps = swaps.load(Ordering::Relaxed);
    eprintln!(
        "race[{}]: iterations={} swaps_to_symlink={swaps} ok={} refused_symlink={} missing={} other={} escapes={}",
        effects.label(),
        tally.iterations,
        tally.ok,
        tally.refused_symlink,
        tally.missing,
        tally.other,
        tally.escapes.len()
    );
    for escape in tally.escapes.iter().take(5) {
        eprintln!("  ESCAPE {escape}");
    }
    assert!(
        tally.escapes.is_empty(),
        "{}: {} operation(s) changed the directory outside the root; first: {}",
        effects.label(),
        tally.escapes.len(),
        tally.escapes[0]
    );
    // The race was actually exercised: effects succeeded while `d` was a
    // directory and were refused while it was a symlink.
    assert!(swaps > 0, "the swapper never installed the symlink");
    assert!(tally.ok > 0, "no operation ever succeeded");
    assert!(
        tally.refused_symlink > 0,
        "no operation ever observed the symlink; the race was not exercised"
    );
}

#[test]
fn race_intermediate_symlink_swap_never_touches_outside_auto() {
    run_race("race-auto", Resolver::Auto);
}

#[test]
fn race_intermediate_symlink_swap_never_touches_outside_portable_walk() {
    run_race("race-walk", Resolver::Walk);
}

#[cfg(target_os = "linux")]
#[test]
fn race_intermediate_symlink_swap_never_touches_outside_linux_openat2() {
    let probe = Tree::new("probe");
    let available = praetore_sandbox_fs::openat2_available(&Root::open(&probe.root).unwrap());
    drop(probe);
    if !available {
        assert!(
            std::env::var_os("PRAETORE_REQUIRE_OPENAT2").is_none(),
            "PRAETORE_REQUIRE_OPENAT2 is set but this kernel has no openat2"
        );
        eprintln!("race[openat2]: SKIPPED, kernel without openat2 (ENOSYS)");
        return;
    }
    eprintln!("race[openat2]: kernel supports openat2");
    run_race("race-openat2", Resolver::Openat2);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Alternate {
    /// Symlink to `outside/victim`.
    Symlink,
    /// Hard link to `outside/victim` (same filesystem).
    HardLink,
    /// Non-empty directory `{inner: "inner"}`.
    Directory,
}

fn make_alternate(kind: Alternate, path: &Path, outside: &Path) {
    match kind {
        Alternate::Symlink => std::os::unix::fs::symlink(outside.join("victim"), path).unwrap(),
        Alternate::HardLink => std::fs::hard_link(outside.join("victim"), path).unwrap(),
        Alternate::Directory => {
            std::fs::create_dir(path).unwrap();
            std::fs::write(path.join("inner"), "inner").unwrap();
        }
    }
}

fn is_alternate(kind: Alternate, path: &Path, victim_ino: u64) -> bool {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => match kind {
            Alternate::Symlink => metadata.file_type().is_symlink(),
            Alternate::HardLink => metadata.is_file() && metadata.ino() == victim_ino,
            Alternate::Directory => metadata.is_dir(),
        },
        Err(_) => false,
    }
}

/// Swaps `root/t` with `root/t.alt` atomically until `stop`. When an effect
/// consumed the alternate (a write renamed over it, a delete unlinked it),
/// recreates it; when a slot is empty, puts a fresh regular file there.
/// Returns (swaps, alternates recreated).
fn final_swapper(
    root: PathBuf,
    outside: PathBuf,
    kind: Alternate,
    stop: Arc<AtomicBool>,
) -> (u64, u64) {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    use std::os::unix::fs::MetadataExt;
    let target = root.join("t");
    let alternate = root.join("t.alt");
    let victim_ino = std::fs::metadata(outside.join("victim")).unwrap().ino();
    let (mut swaps, mut recreated) = (0, 0);
    while !stop.load(Ordering::Relaxed) {
        if renameat_with(CWD, &target, CWD, &alternate, RenameFlags::EXCHANGE).is_ok() {
            swaps += 1;
        }
        if !is_alternate(kind, &target, victim_ino) && !is_alternate(kind, &alternate, victim_ino) {
            // Never a directory here: a directory cannot be consumed.
            let _ = std::fs::remove_file(&alternate);
            make_alternate(kind, &alternate, &outside);
            recreated += 1;
        }
        for slot in [&target, &alternate] {
            if std::fs::symlink_metadata(slot).is_err() {
                let _ = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(slot);
            }
        }
    }
    (swaps, recreated)
}

fn run_final_race(tag: &str, kind: Alternate) {
    let tree = Tree::new(tag);
    std::fs::write(tree.root.join("t"), "inside").unwrap();
    make_alternate(kind, &tree.root.join("t.alt"), &tree.outside);
    let effects = implementation(&tree, Resolver::Auto);
    let mut baseline = tree.snapshot_outside();
    let stop = Arc::new(AtomicBool::new(false));
    let budget = duration();
    let (tally, (swaps, recreated)) = std::thread::scope(|scope| {
        let swapper = {
            let (root, outside, stop) = (tree.root.clone(), tree.outside.clone(), stop.clone());
            scope.spawn(move || final_swapper(root, outside, kind, stop))
        };
        struct StopOnDrop(Arc<AtomicBool>);
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let guard = StopOnDrop(stop.clone());
        let started = Instant::now();
        let mut tally = Tally::default();
        while tally.iterations < MAX_ITERATIONS && started.elapsed() < budget {
            let i = tally.iterations;
            let content = format!("inside-{i}");
            for (op, is_write) in [("write", true), ("delete", false), ("write", true)] {
                let outcome = if is_write {
                    effects.write("t", content.as_bytes())
                } else {
                    effects.remove("t")
                };
                tally.add(outcome);
                let changes = Snapshot::of(&tree.outside).diff(&baseline);
                if !changes.is_empty() {
                    tally.escapes.push(format!(
                        "iteration {i}: {op} \"t\" -> {outcome:?}; outside: {}",
                        changes.join(", ")
                    ));
                    for entry in std::fs::read_dir(&tree.outside).unwrap() {
                        let _ = std::fs::remove_file(entry.unwrap().path());
                    }
                    std::fs::write(tree.outside.join("victim"), "original").unwrap();
                    baseline = tree.snapshot_outside();
                    break;
                }
            }
            tally.iterations += 1;
            if tally.escapes.len() >= 20 {
                break;
            }
        }
        drop(guard);
        (tally, swapper.join().unwrap())
    });
    eprintln!(
        "race-final[{} / {kind:?}]: iterations={} swaps={swaps} alternates_recreated={recreated} ok={} refused_symlink={} refused_special={} missing={} other={} escapes={}",
        effects.label(),
        tally.iterations,
        tally.ok,
        tally.refused_symlink,
        tally.refused_special,
        tally.missing,
        tally.other,
        tally.escapes.len()
    );
    for escape in tally.escapes.iter().take(5) {
        eprintln!("  ESCAPE {escape}");
    }
    assert!(
        tally.escapes.is_empty(),
        "{}: {} operation(s) changed the directory outside the root; first: {}",
        effects.label(),
        tally.escapes.len(),
        tally.escapes[0]
    );
    if kind == Alternate::Directory {
        let directories: Vec<_> = ["t", "t.alt"]
            .iter()
            .map(|name| tree.root.join(name))
            .filter(|path| std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()))
            .collect();
        assert_eq!(directories.len(), 1, "the swapped directory disappeared");
        assert_eq!(
            std::fs::read_to_string(directories[0].join("inner")).unwrap(),
            "inner",
            "the swapped directory lost its content"
        );
    }
    assert!(swaps > 0, "the swapper never swapped");
    assert!(tally.ok > 0, "no operation ever succeeded");
    assert!(
        tally.refused_symlink + tally.refused_special > 0,
        "no operation ever observed the alternate at `t`; the race was not exercised"
    );
}

#[test]
fn race_final_component_swapped_for_outside_symlink_never_touches_outside() {
    run_final_race("final-symlink", Alternate::Symlink);
}

#[test]
fn race_final_component_swapped_for_outside_hard_link_never_touches_outside() {
    run_final_race("final-hardlink", Alternate::HardLink);
}

#[test]
fn race_final_component_swapped_for_directory_leaves_it_intact() {
    run_final_race("final-directory", Alternate::Directory);
}
