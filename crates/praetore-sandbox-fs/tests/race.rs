//! TOCTOU race: one thread keeps swapping the intermediate directory
//! `root/d` for a symlink to a directory outside the root, and back, while
//! another thread writes and deletes `d/...` paths. After every single
//! operation the outside directory must be exactly as it was: nothing
//! created, modified or deleted.
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
    missing: u64,
    other: u64,
    escapes: Vec<String>,
}

impl Tally {
    fn add(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Ok => self.ok += 1,
            Outcome::RefusedSymlink => self.refused_symlink += 1,
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
