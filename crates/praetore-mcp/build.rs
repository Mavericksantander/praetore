//! Sets `PRAETORE_MCP_BUILD_VERSION`, the version written in the header of
//! the session reports (JSON and PDF):
//!
//! * a release build: the crate version, `0.3.5`. A build is a release when
//!   it runs for a `v*` tag in CI (`GITHUB_REF=refs/tags/v...`), when the
//!   checked out commit carries the tag `v<version>`, or when
//!   `PRAETORE_MCP_RELEASE=1` is set;
//! * any other build: `0.3.5-dev+<short commit>`, or `0.3.5-dev` when the
//!   commit cannot be read (no git, or not a git checkout).

use std::{path::Path, process::Command};

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (!text.is_empty()).then_some(text)
}

/// Rebuilds when the checked out commit or the tags change. Only paths that
/// exist are named: a missing one would make every build run this again.
fn watch_git() {
    let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]) else {
        return;
    };
    let common = git(&["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .unwrap_or_else(|| git_dir.clone());
    let mut paths = vec![
        format!("{git_dir}/HEAD"),
        format!("{common}/packed-refs"),
        format!("{common}/refs/tags"),
    ];
    if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"]) {
        paths.push(format!("{common}/{reference}"));
    }
    for path in paths {
        if Path::new(&path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=GITHUB_REF");
    println!("cargo:rerun-if-env-changed=PRAETORE_MCP_RELEASE");
    watch_git();
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let tag = format!("v{version}");
    let release = std::env::var("PRAETORE_MCP_RELEASE").as_deref() == Ok("1")
        || std::env::var("GITHUB_REF").is_ok_and(|r| r.starts_with("refs/tags/v"))
        || git(&["tag", "--points-at", "HEAD"]).is_some_and(|tags| tags.lines().any(|t| t == tag));
    let build = if release {
        version
    } else {
        match git(&["rev-parse", "--short=7", "HEAD"]) {
            Some(commit) => format!("{version}-dev+{commit}"),
            None => format!("{version}-dev"),
        }
    };
    println!("cargo:rustc-env=PRAETORE_MCP_BUILD_VERSION={build}");
}
