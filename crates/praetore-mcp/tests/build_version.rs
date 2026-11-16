//! The build version of the session reports (`build_version.rs`, run by
//! `build.rs`): where the commit may come from and what counts as a
//! release. Each case runs the same function `build.rs` runs, with real git
//! repositories in temporary directories.

#[path = "../build_version.rs"]
#[allow(dead_code)]
mod build_version;

use build_version::{Inputs, build_version};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const VERSION: &str = "1.2.3";

fn inputs(manifest_dir: &Path) -> Inputs {
    Inputs {
        manifest_dir: manifest_dir.to_path_buf(),
        version: VERSION.into(),
        release: None,
        commit: None,
        path: None,
    }
}

/// `git <args>` in `dir`, with no global or system configuration.
fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// A git repository in `dir` with one commit; `own` makes it look like
/// this one (`crates/praetore-mcp/build.rs` at its top level). Returns the
/// crate directory inside it and the short commit.
fn repository(dir: &Path, own: bool) -> (PathBuf, String) {
    let crate_dir = dir.join("crates/praetore-mcp");
    fs::create_dir_all(&crate_dir).unwrap();
    if own {
        fs::write(crate_dir.join("build.rs"), "fn main() {}\n").unwrap();
    } else {
        fs::write(crate_dir.join("lib.rs"), "\n").unwrap();
    }
    git(dir, &["init", "-q"]);
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", "one"]);
    let commit = git(dir, &["rev-parse", "--short=7", "HEAD"]);
    (crate_dir, commit)
}

#[test]
fn this_repository_gives_dev_and_its_commit() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut this = inputs(manifest);
    this.version = env!("CARGO_PKG_VERSION").into();
    let commit = git(manifest, &["rev-parse", "--short=7", "HEAD"]);
    let tags = git(manifest, &["tag", "--points-at", "HEAD"]);
    let expected = if tags
        .lines()
        .any(|t| t == format!("v{}", env!("CARGO_PKG_VERSION")))
    {
        env!("CARGO_PKG_VERSION").to_owned()
    } else {
        format!("{}-dev+{commit}", env!("CARGO_PKG_VERSION"))
    };
    assert_eq!(build_version(&this), expected);
    // The binary under test was built with the same rule.
    assert_eq!(praetore_mcp::report::BUILD_VERSION, expected);
}

#[test]
fn without_a_git_directory_the_commit_comes_only_from_the_variable() {
    let temp = tempfile::tempdir().unwrap();
    let crate_dir = temp.path().join("crates/praetore-mcp");
    fs::create_dir_all(&crate_dir).unwrap();
    fs::write(crate_dir.join("build.rs"), "fn main() {}\n").unwrap();
    let mut plain = inputs(&crate_dir);
    // A temporary directory is not inside a repository; if it were, the
    // case would be the next test's.
    assert!(plain.git(&["rev-parse", "--show-toplevel"]).is_none());
    assert_eq!(build_version(&plain), "1.2.3-dev");
    plain.commit = Some("ABCDEF1234".into());
    assert_eq!(build_version(&plain), "1.2.3-dev+abcdef1234");
    for bad in ["abc", "zzzzzzz", "abcdef1; rm -rf /", "", &"a".repeat(41)] {
        plain.commit = Some(bad.to_owned());
        assert_eq!(build_version(&plain), "1.2.3-dev", "{bad:?}");
    }
}

#[test]
fn inside_another_repository_its_commit_and_tags_are_not_used() {
    let temp = tempfile::tempdir().unwrap();
    let (crate_dir, foreign) = repository(temp.path(), false);
    // Its exact release tag is not ours either.
    git(temp.path(), &["tag", "v1.2.3"]);
    let mut other = inputs(&crate_dir);
    assert!(other.own_toplevel().is_none());
    let version = build_version(&other);
    assert_eq!(version, "1.2.3-dev");
    assert!(!version.contains(&foreign));
    other.commit = Some("1234567".into());
    assert_eq!(build_version(&other), "1.2.3-dev+1234567");
    assert!(build_version_watched_is_empty(&other));
}

fn build_version_watched_is_empty(inputs: &Inputs) -> bool {
    build_version::watched(inputs).is_empty()
}

#[test]
fn without_git_on_path_the_commit_comes_only_from_the_variable() {
    let empty = tempfile::tempdir().unwrap();
    let mut no_git = inputs(Path::new(env!("CARGO_MANIFEST_DIR")));
    no_git.path = Some(OsString::from(empty.path()));
    assert!(
        no_git.git(&["--version"]).is_none(),
        "git found on an empty PATH"
    );
    assert_eq!(build_version(&no_git), "1.2.3-dev");
    no_git.commit = Some("fedcba9".into());
    assert_eq!(build_version(&no_git), "1.2.3-dev+fedcba9");
}

#[test]
fn a_release_is_only_the_exact_version_tag_or_the_variable() {
    let temp = tempfile::tempdir().unwrap();
    let (crate_dir, commit) = repository(temp.path(), true);
    let mut ours = inputs(&crate_dir);
    assert_eq!(build_version(&ours), format!("1.2.3-dev+{commit}"));
    // Other v* tags are not this release.
    for tag in ["v1.2.4", "v1.2.3-rc1", "v1.2", "1.2.3", "v1.2.30"] {
        git(temp.path(), &["tag", tag]);
    }
    assert_eq!(build_version(&ours), format!("1.2.3-dev+{commit}"));
    git(temp.path(), &["tag", "-a", "v1.2.3", "-m", "release"]);
    assert_eq!(build_version(&ours), "1.2.3");
    // The tag on an older commit does not make a later one a release.
    fs::write(crate_dir.join("more.rs"), "\n").unwrap();
    git(temp.path(), &["add", "-A"]);
    git(temp.path(), &["commit", "-q", "-m", "two"]);
    let later = git(temp.path(), &["rev-parse", "--short=7", "HEAD"]);
    assert_eq!(build_version(&ours), format!("1.2.3-dev+{later}"));
    // The variable alone makes a release, wherever the build runs.
    ours.release = Some("1".into());
    assert_eq!(build_version(&ours), "1.2.3");
    ours.release = Some("yes".into());
    assert_eq!(build_version(&ours), format!("1.2.3-dev+{later}"));
    let mut nowhere = inputs(temp.path().join("missing").as_path());
    nowhere.release = Some("1".into());
    assert_eq!(build_version(&nowhere), "1.2.3");
}
