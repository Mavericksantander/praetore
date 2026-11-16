//! `clippy.toml` disallows `Expiry::at`, so whether an approval expired is
//! only asked through `Expiry::is_expired_at`. A display use is marked with
//! `#[expect(clippy::disallowed_methods, reason = "...")]`, which fails when
//! nothing needs it. An allow of that lint (on an item, a module, the crate,
//! or in a `[lints]` table) would turn the check off without a trace, so
//! this test refuses one anywhere in the crate.

use std::{
    fs,
    path::{Path, PathBuf},
};

/// Lint names that silence `clippy::disallowed_methods`: the lint and the
/// groups it belongs to.
const SILENCING: [&str; 3] = ["clippy::disallowed_methods", "clippy::style", "clippy::all"];

const WHY: &str = "clippy.toml disallows Expiry::at so that expiry is only compared with \
Expiry::is_expired_at; allowing clippy::disallowed_methods (or clippy::style or clippy::all, \
which contain it) turns that check off for everything it covers. Mark the one display use \
with #[expect(clippy::disallowed_methods, reason = \"display only\")] instead: an expect fails \
when nothing needs it, an allow never does.";

/// Lines of Rust source where a lint attribute allows one of [`SILENCING`]:
/// `#[allow(...)]`, `#![allow(...)]`, `cfg_attr(..., allow(...))`, also
/// split over several lines. Line comments are skipped.
fn rust_allows(text: &str) -> Vec<usize> {
    // The code without line comments and whitespace, with the line of each
    // character.
    let mut code = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.split_once("//").map_or(line, |(code, _)| code);
        code.extend(
            line.chars()
                .filter(|c| !c.is_whitespace())
                .map(|c| (c, index + 1)),
        );
    }
    let chars: String = code.iter().map(|(c, _)| *c).collect();
    let needle = concat!("al", "low(");
    let mut found = Vec::new();
    for (start, _) in chars.match_indices(needle) {
        let before = chars[..start].chars().last();
        if !matches!(before, Some('[' | ',' | '(')) {
            continue;
        }
        let rest = &chars[start + needle.len()..];
        let inside = rest.split(')').next().unwrap_or_default();
        if inside.split(',').any(|lint| SILENCING.contains(&lint)) {
            found.push(code[chars[..start].chars().count()].1);
        }
    }
    found
}

/// Lines of a Cargo.toml `[lints]` (or `[workspace.lints]`) table that set
/// one of [`SILENCING`] to "allow", in any of the table forms Cargo accepts.
fn toml_allows(text: &str) -> Vec<usize> {
    let names: Vec<&str> = SILENCING
        .iter()
        .map(|lint| lint.trim_start_matches("clippy::"))
        .collect();
    let mut in_lints = false;
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.split_once('#').map_or(line, |(code, _)| code).trim();
        if line.starts_with('[') {
            let header = line.trim_matches(|c| c == '[' || c == ']').trim();
            in_lints = header.starts_with("lints") || header.starts_with("workspace.lints");
            continue;
        }
        if !(in_lints || line.starts_with("lints") || line.starts_with("workspace.lints")) {
            continue;
        }
        let words: Vec<&str> = line
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|word| !word.is_empty())
            .collect();
        if words.contains(&"allow") && names.iter().any(|name| words.contains(name)) {
            found.push(index + 1);
        }
    }
    found
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_allow_of_disallowed_methods_in_the_crate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(root, &mut files);
    files.sort();
    assert!(files.iter().any(|f| f.ends_with("src/lib.rs")));
    assert!(files.iter().any(|f| f.ends_with("tests/lint_guard.rs")));
    let mut problems = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).unwrap();
        for line in rust_allows(&text) {
            problems.push(format!(
                "{}:{line}",
                file.strip_prefix(root).unwrap().display()
            ));
        }
    }
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    for line in toml_allows(&manifest) {
        problems.push(format!("Cargo.toml:{line}"));
    }
    // A crate that takes its lints from the workspace takes this too.
    if manifest.contains("[lints]") && manifest.contains("workspace = true") {
        let workspace = root.join("../../Cargo.toml");
        for line in toml_allows(&fs::read_to_string(&workspace).unwrap()) {
            problems.push(format!("workspace Cargo.toml:{line}"));
        }
    }
    assert!(
        problems.is_empty(),
        "allow of clippy::disallowed_methods at {}. {WHY}",
        problems.join(", ")
    );
    let clippy = fs::read_to_string(root.join("clippy.toml")).unwrap();
    assert!(
        clippy.contains("\"praetore_mcp::approvals::Expiry::at\""),
        "clippy.toml no longer disallows Expiry::at. {WHY}"
    );
}

/// The four ways to silence the lint are found; `expect`, `warn`, `deny`,
/// comments and other lints are not.
#[test]
fn the_guard_finds_each_way_to_allow_the_lint() {
    let allow = concat!("al", "low");
    let flagged = [
        format!("#[{allow}(clippy::disallowed_methods)]\nfn f() {{}}"),
        format!("mod m {{\n    #![{allow}(clippy::disallowed_methods)]\n}}"),
        format!("//! crate\n#![{allow}(clippy::disallowed_methods)]\n"),
        format!("#[{allow}(dead_code, clippy::disallowed_methods)]"),
        format!("#[{allow}(\n    clippy::disallowed_methods,\n)]"),
        format!("#[cfg_attr(test, {allow}(clippy::disallowed_methods))]"),
        format!("#![{allow}(clippy::style)]"),
        format!("#![{allow}(clippy::all)]"),
        format!("#[ {allow} ( clippy :: disallowed_methods ) ]"),
    ];
    for text in &flagged {
        assert!(!rust_allows(text).is_empty(), "not found in {text:?}");
    }
    assert_eq!(
        rust_allows(&format!(
            "fn a() {{}}\n\n#[{allow}(\n    clippy::disallowed_methods\n)]\nfn b() {{}}"
        )),
        [3]
    );
    let clean = [
        "#[expect(clippy::disallowed_methods, reason = \"display only\")]".to_owned(),
        "#[warn(clippy::disallowed_methods)]".to_owned(),
        "#[deny(clippy::disallowed_methods)]".to_owned(),
        format!("// #[{allow}(clippy::disallowed_methods)]"),
        format!("#[{allow}(clippy::too_many_lines)]"),
        format!("#[{allow}(dead_code)]"),
        format!("x.{allow}(clippy::style)"),
        format!("let s = \"dis{allow}(x)\";"),
    ];
    for text in &clean {
        assert!(rust_allows(text).is_empty(), "found in {text:?}");
    }

    let toml_flagged = [
        format!("[lints.clippy]\ndisallowed_methods = \"{allow}\"\n"),
        format!("[lints.clippy]\ndisallowed_methods = {{ level = \"{allow}\", priority = 1 }}\n"),
        format!("[lints]\nclippy = {{ disallowed_methods = \"{allow}\" }}\n"),
        format!("[lints]\nclippy.style = \"{allow}\"\n"),
        format!("[workspace.lints.clippy]\nall = \"{allow}\"\n"),
        format!("lints.clippy.disallowed_methods = \"{allow}\"\n"),
    ];
    for text in &toml_flagged {
        assert!(!toml_allows(text).is_empty(), "not found in {text:?}");
    }
    let toml_clean = [
        "[lints.clippy]\ndisallowed_methods = \"deny\"\n".to_owned(),
        format!("[lints.rust]\nunused = \"{allow}\"\n"),
        format!("[lints.clippy]\ntoo_many_lines = \"{allow}\"\n"),
        format!("[dependencies]\nall = \"1\"\nstyle = \"{allow}\"\n"),
        format!("[lints.clippy]\n# disallowed_methods = \"{allow}\"\n"),
    ];
    for text in &toml_clean {
        assert!(toml_allows(text).is_empty(), "found in {text:?}");
    }
}
