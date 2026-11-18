//! A command praetore-mcp prints for someone to run starts with the binary
//! that printed it and names its home with `--dir`
//! (`praetore_mcp::commands::command` or `program()`). A bare
//! "`praetore-mcp ...`" in a message may run another binary, or none, and
//! act on another home. This test reads every string literal under `src/`
//! and refuses one that contains "`praetore-mcp ", except the help text
//! listed in [`EXCEPTIONS`].

mod lex;

use std::{
    fs,
    path::{Path, PathBuf},
};

const NEEDLE: &str = "`praetore-mcp ";

/// Literals allowed to name a bare command: (file under the crate, how the
/// literal starts, why).
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    (
        "src/cli.rs",
        "praetore-mcp: put PRÆTORE",
        "top-level help text",
    ),
    (
        "src/cli.rs",
        "Usage: praetore-mcp ",
        "help text of a subcommand",
    ),
    (
        "src/store.rs",
        "PRAETORE LOCAL/DEV KEY",
        "written into each key file: says what made the key, not a command to run",
    ),
];

const WHY: &str = "build printed commands with praetore_mcp::commands::command(args, &home.root) \
(or program() and the home's --dir), so they name the binary that printed them and the home \
they act on. A bare `praetore-mcp ...` may run another version, or nothing when the binary \
is not on PATH, and acts on the default home. Help text is listed in EXCEPTIONS.";

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// `file:line` of each literal of `text` (from `file`) that names a bare
/// command and is not an exception.
fn bare_commands(file: &str, text: &str) -> Vec<String> {
    lex::lex(text)
        .literals
        .into_iter()
        .filter(|literal| literal.text.contains(NEEDLE))
        .filter(|literal| {
            !EXCEPTIONS
                .iter()
                .any(|(path, start, _)| *path == file && literal.text.starts_with(start))
        })
        .map(|literal| format!("{file}:{}", literal.line))
        .collect()
}

#[test]
fn no_message_in_src_names_a_bare_praetore_mcp_command() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();
    assert!(files.iter().any(|f| f.ends_with("src/cli.rs")));
    let mut found = Vec::new();
    for path in &files {
        let file = path
            .strip_prefix(root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/");
        found.extend(bare_commands(&file, &fs::read_to_string(path).unwrap()));
    }
    assert!(
        found.is_empty(),
        "bare `praetore-mcp ...` in {}. {WHY}",
        found.join(", ")
    );
}

/// Comments and doc comments may name commands; literals may not, apart
/// from the listed help text.
#[test]
fn the_check_reads_literals_only() {
    let message = format!("Err(format!(\"run {NEEDLE}verify\"))");
    assert_eq!(bare_commands("src/x.rs", &message), ["src/x.rs:1"]);
    let raw = format!("let s = r#\"see {NEEDLE}init\"#;");
    assert_eq!(bare_commands("src/x.rs", &raw), ["src/x.rs:1"]);
    let comment = format!("//! {NEEDLE}wrap\n/// {NEEDLE}init\n/* {NEEDLE}x */ fn f() {{}}");
    assert!(bare_commands("src/x.rs", &comment).is_empty());
    let help = format!("const H: &str = \"Usage: praetore-mcp init\\n{NEEDLE}x\";");
    assert!(bare_commands("src/cli.rs", &help).is_empty());
    assert_eq!(bare_commands("src/other.rs", &help), ["src/other.rs:1"]);
}
