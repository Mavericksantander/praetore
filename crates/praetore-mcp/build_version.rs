//! The version written in the header of the session reports, worked out
//! at build time. Used by `build.rs` and by `tests/build_version.rs`.
//!
//! * Release build: the crate version, `0.3.6`. Only when the checked out
//!   commit of this repository carries the exact tag `v<crate version>`, or
//!   when `PRAETORE_MCP_RELEASE=1` is set.
//! * Any other build: `0.3.6-dev+<short commit>` or `0.3.6-dev`. The commit
//!   comes from git only when the repository git finds is this one (its top
//!   level holds `crates/praetore-mcp/build.rs`). Otherwise (no `.git`, a
//!   build inside some other repository, no `git` on `PATH`) it is
//!   `PRAETORE_MCP_BUILD_COMMIT` when that is 7 to 40 hex characters, or
//!   none.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
};

/// What the version depends on, read from the build environment.
pub struct Inputs {
    /// `CARGO_MANIFEST_DIR`.
    pub manifest_dir: PathBuf,
    /// `CARGO_PKG_VERSION`.
    pub version: String,
    /// `PRAETORE_MCP_RELEASE`.
    pub release: Option<String>,
    /// `PRAETORE_MCP_BUILD_COMMIT`.
    pub commit: Option<String>,
    /// The `PATH` git is looked up in; `None` keeps the current one.
    pub path: Option<OsString>,
}

impl Inputs {
    pub fn from_env() -> Self {
        Self {
            manifest_dir: PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default()),
            version: std::env::var("CARGO_PKG_VERSION").unwrap_or_default(),
            release: std::env::var("PRAETORE_MCP_RELEASE").ok(),
            commit: std::env::var("PRAETORE_MCP_BUILD_COMMIT").ok(),
            path: None,
        }
    }

    /// `git <args>` in the manifest directory, trimmed, or `None` (no git,
    /// a failure, empty output). Git's own location variables are cleared,
    /// so only the directory decides which repository is read.
    pub fn git(&self, args: &[&str]) -> Option<String> {
        let mut command = Command::new("git");
        command.args(args).current_dir(&self.manifest_dir);
        for name in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_INDEX_FILE",
        ] {
            command.env_remove(name);
        }
        if let Some(path) = &self.path {
            command.env("PATH", path);
        }
        let out = command.output().ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8(out.stdout).ok()?.trim().to_owned();
        (!text.is_empty()).then_some(text)
    }

    /// The top level of the repository git finds, if it is this one.
    pub fn own_toplevel(&self) -> Option<PathBuf> {
        let top = PathBuf::from(self.git(&["rev-parse", "--show-toplevel"])?);
        top.join("crates/praetore-mcp/build.rs")
            .is_file()
            .then_some(top)
    }
}

fn is_commit(text: &str) -> bool {
    (7..=40).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The version string for `inputs`.
pub fn build_version(inputs: &Inputs) -> String {
    let version = &inputs.version;
    if inputs.release.as_deref() == Some("1") {
        return version.clone();
    }
    let own = inputs.own_toplevel().is_some();
    if own {
        let tag = format!("v{version}");
        let tagged = inputs
            .git(&["tag", "--points-at", "HEAD"])
            .is_some_and(|tags| tags.lines().any(|line| line.trim() == tag));
        if tagged {
            return version.clone();
        }
        if let Some(commit) = inputs.git(&["rev-parse", "--short=7", "HEAD"]) {
            return format!("{version}-dev+{commit}");
        }
    }
    match inputs.commit.as_deref().map(str::trim) {
        Some(commit) if is_commit(commit) => {
            format!("{version}-dev+{}", commit.to_ascii_lowercase())
        }
        _ => format!("{version}-dev"),
    }
}

/// Files whose change means the version may change: this repository's
/// `HEAD`, the ref it points at, `packed-refs` and the tags. Only existing
/// paths: a missing one would make every build run `build.rs` again.
pub fn watched(inputs: &Inputs) -> Vec<PathBuf> {
    if inputs.own_toplevel().is_none() {
        return Vec::new();
    }
    let Some(git_dir) = inputs.git(&["rev-parse", "--absolute-git-dir"]) else {
        return Vec::new();
    };
    let common = inputs
        .git(&["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .unwrap_or_else(|| git_dir.clone());
    let mut paths = vec![
        Path::new(&git_dir).join("HEAD"),
        Path::new(&common).join("packed-refs"),
        Path::new(&common).join("refs/tags"),
    ];
    if let Some(reference) = inputs.git(&["symbolic-ref", "-q", "HEAD"]) {
        paths.push(Path::new(&common).join(reference));
    }
    paths.retain(|path| path.exists());
    paths
}
