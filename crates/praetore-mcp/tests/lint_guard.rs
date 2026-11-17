//! `clippy.toml` disallows `Expiry::at`, so whether an approval expired is
//! only asked through `Expiry::is_expired_at`. A display use is marked with
//! `#[expect(clippy::disallowed_methods, reason = "...")]`, which fails when
//! nothing needs it. Anything that allows that lint turns the check off
//! without a trace, so this test refuses, in the crate:
//!
//! - an allow of it, of a group that holds it (`clippy::style`,
//!   `clippy::all`, `warnings`) or of its old name, on an item, a module or
//!   the crate, also through `cfg_attr` or a macro;
//! - the lint named anywhere in code but an `expect` attribute (a macro
//!   could turn it into an allow);
//! - a `#[path]` or `include!` that brings in Rust code from outside the
//!   crate, where this test does not look;
//! - an allow in a `[lints]` table of the crate's Cargo.toml, or of the
//!   workspace when the crate inherits it (`[lints] workspace = true` or
//!   `lints.workspace = true`);
//! - `rustflags` that allow it or cap lints, in a `.cargo/config.toml`
//!   Cargo reads for this crate, or in `RUSTFLAGS`,
//!   `CARGO_ENCODED_RUSTFLAGS` or `CARGO_BUILD_RUSTFLAGS`.
//!
//! What it cannot see (flags passed to one clippy run) the canary step in
//! `.github/workflows/assurance.yml` (`scripts/clippy-canary.sh`) catches.

mod lex;

use std::{
    fs,
    path::{Component, Path, PathBuf},
};

/// Lint names that silence `clippy::disallowed_methods`: the lint, its old
/// name, and the groups it belongs to.
const SILENCING: [&str; 5] = [
    "clippy::disallowed_methods",
    "clippy::disallowed_method",
    "clippy::style",
    "clippy::all",
    "warnings",
];

const WHY: &str = "clippy.toml disallows Expiry::at so that expiry is only compared with \
Expiry::is_expired_at; allowing clippy::disallowed_methods (its old name, or clippy::style, \
clippy::all or warnings, which contain it) turns that check off for everything it covers, \
and so do rustflags that allow it or cap lints. Mark the one display use with \
#[expect(clippy::disallowed_methods, reason = \"display only\")] instead: an expect fails \
when nothing needs it, an allow never does.";

/// `code` (from [`lex::lex`]) without whitespace, with the line of each
/// character.
fn compact(code: &str) -> (String, Vec<usize>) {
    let mut chars = String::new();
    let mut lines = Vec::new();
    for (index, line) in code.lines().enumerate() {
        for c in line.chars().filter(|c| !c.is_whitespace()) {
            chars.push(c);
            lines.push(index + 1);
        }
    }
    (chars, lines)
}

/// Problems in Rust source `text`: an allow of [`SILENCING`] or with a
/// macro metavariable, and the lint named outside an `expect` attribute.
/// Comments and string literals are never read as code.
fn rust_allows(text: &str) -> Vec<(usize, &'static str)> {
    let (chars, lines) = compact(&lex::lex(text).code);
    let line_at = |byte: usize| lines[chars[..byte].chars().count()];
    let mut found = Vec::new();
    // Byte ranges of the allow lists already reported.
    let mut reported = Vec::new();
    let needle = concat!("al", "low(");
    for (start, _) in chars.match_indices(needle) {
        if !matches!(chars[..start].chars().last(), Some('[' | ',' | '(')) {
            continue;
        }
        let inside = chars[start + needle.len()..]
            .split(')')
            .next()
            .unwrap_or_default();
        reported.push(start..start + needle.len() + inside.len());
        if inside.split(',').any(|lint| SILENCING.contains(&lint)) {
            found.push((
                line_at(start),
                "allows clippy::disallowed_methods or a group with it",
            ));
        } else if inside.contains('$') {
            found.push((
                line_at(start),
                "an allow built by a macro cannot be checked",
            ));
        }
    }
    for (at, _) in chars.match_indices("clippy::disallowed_method") {
        if reported.iter().any(|range| range.contains(&at)) {
            continue;
        }
        let opened = chars[..at]
            .rfind("#[")
            .into_iter()
            .chain(chars[..at].rfind("#!["));
        let in_expect = opened.max().is_some_and(|open| {
            let attribute = &chars[open..at];
            !attribute.contains(']') && attribute.contains("expect(") && !attribute.contains(needle)
        });
        if !in_expect {
            found.push((line_at(at), "the lint is named outside an expect attribute"));
        }
    }
    found
}

/// The string literal that starts after `from` in `code` (only `=`, `(` and
/// whitespace between), read from `source`.
fn literal_after(code: &[char], source: &[char], from: usize) -> Option<String> {
    let open = from
        + code[from..]
            .iter()
            .position(|c| !matches!(c, '=' | '(') && !c.is_whitespace())?;
    if code[open] != '"' {
        return None;
    }
    let close = open + 1 + code[open + 1..].iter().position(|&c| c == '"')?;
    Some(source[open + 1..close].iter().collect())
}

/// `path` with `.` and `..` resolved without touching the filesystem.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// Lines of `text` (the file `file` of the crate at `root`) where
/// `#[path = ..]` or `include!(..)` brings in code from outside the crate,
/// or from a path that is not a plain string.
fn outside_code(file: &Path, root: &Path, text: &str) -> Vec<(usize, &'static str)> {
    let lexed = lex::lex(text);
    let code: Vec<char> = lexed.code.chars().collect();
    let source: Vec<char> = text.chars().collect();
    let line_of = |at: usize| code[..at].iter().filter(|&&c| c == '\n').count() + 1;
    let base = file.parent().unwrap_or(root);
    let mut found = Vec::new();
    let flat: String = code.iter().collect();
    for (keyword, after) in [("path", "="), ("include!", "(")] {
        for (byte, _) in flat.match_indices(keyword) {
            let at = flat[..byte].chars().count();
            let end = at + keyword.chars().count();
            let mut before: Vec<char> = code[..at]
                .iter()
                .rev()
                .filter(|c| !c.is_whitespace())
                .take(2)
                .copied()
                .collect();
            before.reverse();
            let rest: String = code[end..]
                .iter()
                .filter(|c| !c.is_whitespace())
                .take(1)
                .collect();
            let attribute = keyword == "path" && before == ['#', '['] && rest == after;
            let ident_before = at > 0 && (code[at - 1].is_alphanumeric() || code[at - 1] == '_');
            let call = keyword == "include!" && !ident_before && rest == after;
            if !attribute && !call {
                continue;
            }
            match literal_after(&code, &source, end) {
                Some(target) if normalize(&base.join(&target)).starts_with(normalize(root)) => {}
                Some(_) => found.push((line_of(at), "brings in code from outside the crate")),
                None => found.push((
                    line_of(at),
                    "brings in code from a path that is not a plain string",
                )),
            }
        }
    }
    found
}

/// Whether a lint level item (`"allow"` or `{ level = "allow", .. }`) is
/// allow.
fn is_allow(item: &toml_edit::Item) -> bool {
    let level = item
        .as_str()
        .or_else(|| item.get("level").and_then(toml_edit::Item::as_str));
    level == Some("allow")
}

/// What in a `[lints]` (or `[workspace.lints]`) table allows one of
/// [`SILENCING`], by name.
fn lints_allow(lints: &toml_edit::Item) -> Vec<String> {
    let mut found = Vec::new();
    for lint in SILENCING {
        let (tool, name) = lint.split_once("::").unwrap_or(("rust", lint));
        if lints
            .get(tool)
            .and_then(|table| table.get(name))
            .is_some_and(is_allow)
        {
            found.push(format!("{tool}.{name} = allow"));
        }
    }
    found
}

/// Problems in a Cargo.toml: lints it allows, and whether it inherits the
/// workspace lints.
fn manifest_lints(text: &str) -> (Vec<String>, bool) {
    let document: toml_edit::Document<String> = text.parse().expect("Cargo.toml parses");
    let mut found = Vec::new();
    let mut inherits = false;
    if let Some(lints) = document.get("lints") {
        found.extend(lints_allow(lints));
        inherits = lints.get("workspace").and_then(toml_edit::Item::as_bool) == Some(true);
    }
    if let Some(lints) = document.get("workspace").and_then(|w| w.get("lints")) {
        found.extend(
            lints_allow(lints)
                .into_iter()
                .map(|f| format!("workspace.{f}")),
        );
    }
    (found, inherits)
}

/// Whether rustflags `flags` allow one of [`SILENCING`] or cap lints.
fn flags_silence(flags: &[String]) -> bool {
    let mut words = flags.iter().map(String::as_str).peekable();
    while let Some(flag) = words.next() {
        if flag.starts_with("--cap-lints") {
            return true;
        }
        let lint = match flag {
            "-A" | "--allow" => words.next().unwrap_or_default(),
            _ => flag
                .strip_prefix("--allow=")
                .or_else(|| flag.strip_prefix("-A"))
                .unwrap_or_default(),
        };
        if SILENCING.contains(&lint.replace('-', "_").as_str()) {
            return true;
        }
    }
    false
}

/// The rustflags of a Cargo config file (`build.rustflags`,
/// `target.<triple or cfg>.rustflags`), string or array.
fn config_rustflags(text: &str) -> Vec<String> {
    let document: toml_edit::Document<String> = text.parse().expect("cargo config parses");
    let words = |item: &toml_edit::Item| -> Vec<String> {
        if let Some(text) = item.as_str() {
            text.split_whitespace().map(str::to_owned).collect()
        } else {
            item.as_array()
                .map(|array| {
                    array
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        }
    };
    let mut flags = Vec::new();
    if let Some(item) = document.get("build").and_then(|b| b.get("rustflags")) {
        flags.extend(words(item));
    }
    if let Some(targets) = document
        .get("target")
        .and_then(toml_edit::Item::as_table_like)
    {
        for (_, target) in targets.iter() {
            if let Some(item) = target.get("rustflags") {
                flags.extend(words(item));
            }
        }
    }
    flags
}

/// Rustflags from the environment of this test run.
fn env_rustflags() -> Vec<(String, Vec<String>)> {
    let mut found = Vec::new();
    for name in ["RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS"] {
        if let Ok(value) = std::env::var(name) {
            found.push((
                name.to_owned(),
                value.split_whitespace().map(str::to_owned).collect(),
            ));
        }
    }
    if let Ok(value) = std::env::var("CARGO_ENCODED_RUSTFLAGS") {
        found.push((
            "CARGO_ENCODED_RUSTFLAGS".to_owned(),
            value
                .split('\x1f')
                .filter(|f| !f.is_empty())
                .map(str::to_owned)
                .collect(),
        ));
    }
    found
}

/// The Cargo config files Cargo reads for a build in `dir`: `.cargo/config`
/// and `.cargo/config.toml` in `dir` and each parent, and in `CARGO_HOME`.
fn cargo_configs(dir: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = dir.ancestors().map(|d| d.join(".cargo")).collect();
    if let Some(home) = std::env::var_os("CARGO_HOME") {
        dirs.push(PathBuf::from(home));
    }
    dirs.iter()
        .flat_map(|d| [d.join("config"), d.join("config.toml")])
        .filter(|path| path.is_file())
        .collect()
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
        let shown = file.strip_prefix(root).unwrap().display();
        for (line, what) in rust_allows(&text)
            .into_iter()
            .chain(outside_code(file, root, &text))
        {
            problems.push(format!("{shown}:{line} {what}"));
        }
    }
    let (found, inherits) = manifest_lints(&fs::read_to_string(root.join("Cargo.toml")).unwrap());
    problems.extend(found.into_iter().map(|f| format!("Cargo.toml: {f}")));
    if inherits {
        let workspace = fs::read_to_string(root.join("../../Cargo.toml")).unwrap();
        problems.extend(
            manifest_lints(&workspace)
                .0
                .into_iter()
                .map(|f| format!("workspace Cargo.toml: {f}")),
        );
    }
    for config in cargo_configs(root) {
        if flags_silence(&config_rustflags(&fs::read_to_string(&config).unwrap())) {
            problems.push(format!("{}: rustflags", config.display()));
        }
    }
    for (name, flags) in env_rustflags() {
        if flags_silence(&flags) {
            problems.push(format!("{name}: {}", flags.join(" ")));
        }
    }
    assert!(
        problems.is_empty(),
        "lint check turned off at {}. {WHY}",
        problems.join("; ")
    );
    let clippy = fs::read_to_string(root.join("clippy.toml")).unwrap();
    assert!(
        clippy.contains("\"praetore_mcp::approvals::Expiry::at\""),
        "clippy.toml no longer disallows Expiry::at. {WHY}"
    );
}

/// Each way to silence the lint is found; `expect`, `warn`, `deny`,
/// comments, strings and other lints are not.
#[test]
fn the_guard_finds_each_way_to_allow_the_lint() {
    let allow = concat!("al", "low");
    let lint = concat!("clippy::disallowed", "_methods");
    let flagged = [
        format!("#[{allow}({lint})]\nfn f() {{}}"),
        format!("mod m {{\n    #![{allow}({lint})]\n}}"),
        format!("//! crate\n#![{allow}({lint})]\n"),
        format!("#[{allow}(dead_code, {lint})]"),
        format!("#[{allow}(\n    {lint},\n)]"),
        format!("#[cfg_attr(test, {allow}({lint}))]"),
        format!("#![{allow}(clippy::style)]"),
        format!("#![{allow}(clippy::all)]"),
        format!("#[ {allow} ( clippy :: disallowed_methods ) ]"),
        // n14: groups and names the first guard missed.
        format!("#![{allow}(warnings)]"),
        format!("#[{allow}(warnings)]\nfn f() {{}}"),
        format!("#[{allow}(clippy::disallowed_method)]"),
        format!("#[{allow}(/* why */ {lint})]"),
        format!("const S: &str = \"//\"; #[{allow}({lint})] fn f() {{}}"),
        format!("macro_rules! m {{ ($l:path) => {{ #[{allow}($l)] fn f() {{}} }} }}\nm!(x);"),
        format!("m!({lint});"),
    ];
    for text in &flagged {
        assert!(!rust_allows(text).is_empty(), "not found in {text:?}");
    }
    assert_eq!(
        rust_allows(&format!(
            "fn a() {{}}\n\n#[{allow}(\n    {lint}\n)]\nfn b() {{}}"
        ))
        .iter()
        .map(|(line, _)| *line)
        .collect::<Vec<_>>(),
        [3]
    );
    let clean = [
        format!("#[expect({lint}, reason = \"display only\")]"),
        format!("#[cfg_attr(test, expect({lint}))]"),
        format!("// #[{allow}({lint})]"),
        format!("/* #[{allow}({lint})] */"),
        format!("#[{allow}(clippy::too_many_lines)]"),
        format!("#[{allow}(dead_code)]"),
        format!("x.{allow}(clippy::style)"),
        format!("let s = \"#[{allow}({lint})]\";"),
        format!("let s = r#\"m!({lint})\"#;"),
    ];
    for text in &clean {
        assert!(
            rust_allows(text).is_empty(),
            "found in {text:?}: {:?}",
            rust_allows(text)
        );
    }

    let root = Path::new("/c");
    let file = Path::new("/c/src/lib.rs");
    for text in [
        "#[path = \"../../other/x.rs\"]\nmod x;",
        "#[path=\"/elsewhere/x.rs\"] mod x;",
        "include!(\"../../other/x.rs\");",
        "include!(concat!(env!(\"OUT_DIR\"), \"/x.rs\"));",
    ] {
        assert_eq!(
            outside_code(file, root, text).len(),
            1,
            "not found in {text:?}"
        );
    }
    for text in [
        "#[path = \"../build_version.rs\"] mod v;",
        "#[path = \"sub/x.rs\"] mod x;",
        "include!(\"gen.rs\");",
        "const J: &str = include_str!(\"../../x.json\");",
        "// include!(\"../../x.rs\");",
        "let s = \"#[path = \\\"../../x.rs\\\"]\";",
        "let path = 1;",
    ] {
        assert!(
            outside_code(file, root, text).is_empty(),
            "found in {text:?}"
        );
    }

    let toml_flagged = [
        format!("[lints.clippy]\ndisallowed_methods = \"{allow}\"\n"),
        format!("[lints.clippy]\ndisallowed_methods = {{ level = \"{allow}\", priority = 1 }}\n"),
        format!("[lints]\nclippy = {{ disallowed_methods = \"{allow}\" }}\n"),
        format!("[lints]\nclippy.style = \"{allow}\"\n"),
        format!("[workspace.lints.clippy]\nall = \"{allow}\"\n"),
        format!("lints.clippy.disallowed_methods = \"{allow}\"\n"),
        format!("[lints.rust]\nwarnings = \"{allow}\"\n"),
        format!("[lints.clippy]\ndisallowed_method = \"{allow}\"\n"),
    ];
    for text in &toml_flagged {
        assert!(!manifest_lints(text).0.is_empty(), "not found in {text:?}");
    }
    let toml_clean = [
        "[lints.clippy]\ndisallowed_methods = \"deny\"\n".to_owned(),
        format!("[lints.rust]\nunused = \"{allow}\"\n"),
        format!("[lints.clippy]\ntoo_many_lines = \"{allow}\"\n"),
        format!("[dependencies]\nall = \"1\"\nstyle = \"{allow}\"\n"),
        format!("[lints.clippy]\n# disallowed_methods = \"{allow}\"\n"),
    ];
    for text in &toml_clean {
        assert!(manifest_lints(text).0.is_empty(), "found in {text:?}");
    }
    // Both spellings of inheriting the workspace lints.
    assert!(manifest_lints("[lints]\nworkspace = true\n").1);
    assert!(manifest_lints("lints.workspace = true\n[package]\nname = \"x\"\n").1);
    assert!(!manifest_lints("[lints.rust]\nunused = \"warn\"\n").1);

    let words = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
    for flags in [
        format!("-A {lint}"),
        format!("-A{lint}"),
        "-Awarnings".to_owned(),
        "--cap-lints allow".to_owned(),
        format!("--allow={lint}"),
        "-A clippy::disallowed-methods".to_owned(),
    ] {
        assert!(flags_silence(&words(&flags)), "not found in {flags:?}");
    }
    for flags in ["-C target-cpu=native", "-A dead_code", "-D warnings"] {
        assert!(!flags_silence(&words(flags)), "found in {flags:?}");
    }
    let config = format!("[build]\nrustflags = [\"-A\", \"{lint}\"]\n");
    assert!(flags_silence(&config_rustflags(&config)));
    let config = "[target.'cfg(all())']\nrustflags = \"-Awarnings\"\n";
    assert!(flags_silence(&config_rustflags(config)));
    assert!(!flags_silence(&config_rustflags("[build]\njobs = 4\n")));
}

/// Journal lines are appended only by `journal_io`. Clippy's
/// `disallowed-methods` cannot say "no `write_all` on a journal file": it
/// matches a method path for the whole crate, and `write_all` is the right
/// call for pending files, reports and the dashboard. This test is the
/// check that fits. `journal_io` writes a line once; a retry of the tail is
/// what leaves a cut JSON line when the disk fills.
#[test]
fn journal_append_does_not_call_write_all_outside_the_helper() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = root.join("src");
    let helper_path = src.join("journal_io.rs");
    let helper = fs::read_to_string(&helper_path).unwrap();
    assert!(
        !helper.contains("write_all("),
        "journal_io must write each line once"
    );
    assert!(helper.contains("fn commit_journal_line"));
    assert!(helper.contains("fn append_journal_file"));

    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut append_open = Vec::new();
    for path in &files {
        let text = fs::read_to_string(path).unwrap();
        if text.contains(".append(true)") {
            append_open.push(path.strip_prefix(&src).unwrap().display().to_string());
        }
    }
    append_open.sort();
    assert_eq!(
        append_open,
        vec!["journal_io.rs".to_string()],
        "a journal opened for append outside journal_io"
    );

    let gate = fs::read_to_string(src.join("gate.rs")).unwrap();
    let approvals = fs::read_to_string(src.join("approvals.rs")).unwrap();
    assert!(
        gate.contains("journal_io::append_journal_file"),
        "receipts journal does not use the shared append"
    );
    assert!(
        approvals.contains("journal_io::append_journal_file"),
        "approval journal does not use the shared append"
    );
    assert!(
        !gate.contains("write_all("),
        "receipts journal calls write_all"
    );

    let write_all_lines: Vec<usize> = approvals
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("write_all("))
        .map(|(index, _)| index + 1)
        .collect();
    let private_at = approvals
        .lines()
        .position(|line| line.starts_with("fn write_private("))
        .expect("write_private")
        + 1;
    let private_end = approvals
        .lines()
        .enumerate()
        .skip(private_at)
        .find(|(_, line)| line.starts_with("fn "))
        .map(|(index, _)| index + 1)
        .unwrap_or(usize::MAX);
    assert!(
        write_all_lines
            .iter()
            .all(|line| *line > private_at && *line < private_end),
        "write_all in approvals.rs outside write_private (pending files, not the journal) at {write_all_lines:?}; write_private is {private_at}..{private_end}"
    );
    assert!(
        !write_all_lines.is_empty(),
        "write_private no longer writes its pending file; the allow-range in this test is stale"
    );
}
