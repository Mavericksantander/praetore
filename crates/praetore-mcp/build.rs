//! Sets `PRAETORE_MCP_BUILD_VERSION`, the version written in the header of
//! the session reports (JSON and PDF). The rules are in `build_version.rs`.

mod build_version;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_version.rs");
    println!("cargo:rerun-if-env-changed=PRAETORE_MCP_RELEASE");
    println!("cargo:rerun-if-env-changed=PRAETORE_MCP_BUILD_COMMIT");
    let inputs = build_version::Inputs::from_env();
    for path in build_version::watched(&inputs) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!(
        "cargo:rustc-env=PRAETORE_MCP_BUILD_VERSION={}",
        build_version::build_version(&inputs)
    );
}
