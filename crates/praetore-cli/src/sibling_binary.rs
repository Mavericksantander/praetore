//! Test support: workspace binaries next to the test executable. Shared by
//! the CLI's unit tests and its integration tests
//! (`#[path = "../src/sibling_binary.rs"]`), so every test finds
//! `praetore-verify` the same way.

use std::{
    env,
    path::{Path, PathBuf},
};

/// A workspace binary in the Cargo artifact directory (`target/debug`
/// or `target/release`). Built with
/// `cargo build -p praetore-cli -p praetore-verify --locked`.
///
/// Cargo 1.99 places the test executable in `…/deps/`. Cargo 1.100
/// places it in `…/build/<package>/<hash>/out/` (the intermediate
/// layout is not a stable interface; rust-lang/cargo#17354). In both
/// cases the named binary is uplifted to the artifact directory, so
/// this walks ancestors of the test executable until it finds it.
pub fn sibling_binary(name: &str) -> PathBuf {
    let exe = env::current_exe().unwrap();
    locate_sibling_binary(&exe, name).unwrap_or_else(|| {
        let filename = format!("{name}{}", std::env::consts::EXE_SUFFIX);
        panic!(
            "{filename} is missing (looked from {}): run `cargo build -p praetore-cli -p praetore-verify --locked` first",
            exe.display()
        )
    })
}

pub fn locate_sibling_binary(current_exe: &Path, name: &str) -> Option<PathBuf> {
    let filename = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    let mut dir = current_exe.parent()?;
    // Two hops from `…/deps/<test>`, five from
    // `…/build/<package>/<hash>/out/<test>`. The bound stays inside
    // the target directory.
    for _ in 0..8 {
        let path = dir.join(&filename);
        if path.is_file() {
            return Some(path);
        }
        dir = dir.parent()?;
    }
    None
}
