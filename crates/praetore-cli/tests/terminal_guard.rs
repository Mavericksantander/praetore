//! G7: the terminal output of `praetore`, `praetore-safety-ingest` and
//! `praetore-verify` escapes text from outside (paths, gateway bodies,
//! errors, warnings) with `praetore_core::display`, the one escaping rule
//! of the workspace. Source checks like the ones of praetore-mcp
//! (`crates/praetore-mcp/tests/control_chars.rs`), over the source of both
//! crates, with the same lexer.

#[path = "../../praetore-mcp/tests/lex/mod.rs"]
mod lex;

use std::{collections::BTreeSet, fs, path::Path};

/// One allowed use: the file, the exact line of code (trimmed) and why.
struct Exception {
    file: &'static str,
    line: &'static str,
    why: &'static str,
}

const fn allow(file: &'static str, line: &'static str, why: &'static str) -> Exception {
    Exception { file, line, why }
}

/// The crates whose `src/**/*.rs` the checks read.
const CRATES: &[&str] = &["praetore-cli", "praetore-verify"];

/// Every `src/**/*.rs` file of `CRATES`: its path from `crates/` and its
/// text.
fn src_files() -> Vec<(String, String)> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    for name in CRATES {
        let mut stack = vec![crates.join(name).join("src")];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    let file = path
                        .strip_prefix(crates)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    files.push((file, fs::read_to_string(&path).unwrap()));
                }
            }
        }
    }
    files.sort();
    files
}

/// Lines `find` reports and no exception covers, and exceptions that no
/// longer match a line (so the list cannot outlive the code).
fn check_guard(
    exceptions: &[Exception],
    find: impl Fn(&str) -> Vec<(usize, String)>,
) -> (Vec<String>, Vec<String>) {
    let mut found = Vec::new();
    let mut used = vec![false; exceptions.len()];
    for (file, source) in src_files() {
        for (number, line) in find(&source) {
            match exceptions
                .iter()
                .position(|e| e.file == file && e.line == line)
            {
                Some(index) => used[index] = true,
                None => found.push(format!("{file}:{number}: {line}")),
            }
        }
    }
    let stale = exceptions
        .iter()
        .zip(used)
        .filter(|(_, used)| !used)
        .map(|(e, _)| format!("{}: {} ({})", e.file, e.line, e.why))
        .collect();
    (found, stale)
}

/// Macros that write to the terminal: print macros, `write!` to a handle
/// and the `tracing` events (their subscriber writes to stderr).
const TERMINAL_MACROS: &[&str] = &[
    "print", "println", "eprint", "eprintln", "write", "writeln", "trace", "debug", "info", "warn",
    "error",
];

/// For each call of one of `names` in the lexed `code`: its first and last
/// line (1-based) and its arguments as lexed code.
fn macro_calls<'c>(code: &'c str, names: &[&str]) -> Vec<(usize, usize, &'c str)> {
    let bytes = code.as_bytes();
    let mut calls = Vec::new();
    for name in names {
        let open = format!("{name}!");
        let mut from = 0;
        while let Some(at) = code[from..].find(&open).map(|i| from + i) {
            from = at + open.len();
            let ident_before = at > 0
                && (bytes[at - 1].is_ascii_alphanumeric()
                    || bytes[at - 1] == b'_'
                    || bytes[at - 1] == b':');
            let mut start = from;
            while bytes.get(start).is_some_and(u8::is_ascii_whitespace) {
                start += 1;
            }
            let close = match bytes.get(start) {
                Some(b'(') => b')',
                Some(b'[') => b']',
                Some(b'{') => b'}',
                _ => continue,
            };
            if ident_before && !code[..at].ends_with("tracing::") {
                continue;
            }
            let opening = bytes[start];
            let mut depth = 0;
            let mut end = start;
            for (offset, &b) in bytes[start..].iter().enumerate() {
                if b == opening {
                    depth += 1;
                } else if b == close {
                    depth -= 1;
                    if depth == 0 {
                        end = start + offset;
                        break;
                    }
                }
            }
            let first = code[..start].matches('\n').count() + 1;
            let last = code[..end].matches('\n').count() + 1;
            calls.push((first, last, &code[start..end]));
        }
    }
    calls
}

/// Lines (1-based, as written) inside a terminal macro whose lexed code
/// contains `needle`.
fn needle_in_terminal_macros(source: &str, needle: &str) -> Vec<(usize, String)> {
    let code = lex::lex(source).code;
    let lines: Vec<&str> = source.lines().collect();
    let mut hits = BTreeSet::new();
    for (first, _, args) in macro_calls(&code, TERMINAL_MACROS) {
        let mut search = 0;
        while let Some(i) = args[search..].find(needle).map(|i| search + i) {
            hits.insert(first + args[..i].matches('\n').count());
            search = i + needle.len();
        }
    }
    hits.into_iter()
        .map(|n| (n, lines[n - 1].trim().to_owned()))
        .collect()
}

/// Lines that may format `Path::display` or `to_string_lossy()` in a
/// terminal macro.
const DISPLAY_EXCEPTIONS: &[Exception] = &[];

/// A path is shown with `.shown()` (`praetore_core::display::Show`), never
/// `Path::display` or `to_string_lossy()`, which write control characters
/// as they are.
#[test]
fn terminal_macros_show_paths_escaped() {
    let (found, stale) = check_guard(DISPLAY_EXCEPTIONS, |source| {
        let mut hits = needle_in_terminal_macros(source, ".display()");
        hits.extend(needle_in_terminal_macros(source, ".to_string_lossy()"));
        hits
    });
    assert!(
        found.is_empty(),
        "show these paths with `.shown()` (use praetore_core::display::Show), or add an exception with its exact line and reason:\n{}",
        found.join("\n")
    );
    assert!(
        stale.is_empty(),
        "exceptions that match no line any more:\n{}",
        stale.join("\n")
    );
}

/// Inline captures that hold text from outside: errors (their messages
/// name paths and ids), gateway bodies, warnings and problems.
const OUTSIDE_TEXT: &[&str] = &[
    "error", "body", "text", "problem", "message", "warning", "line",
];

/// Lines (1-based, as written) of a print macro that captures one of
/// `OUTSIDE_TEXT` raw, as `{name}` or `{name:?}`, in its format string.
fn raw_outside_text(source: &str) -> Vec<(usize, String)> {
    let code = lex::lex(source).code;
    let lines: Vec<&str> = source.lines().collect();
    let mut hits = BTreeSet::new();
    for (first, last, _) in macro_calls(&code, &["print", "println", "eprint", "eprintln"]) {
        for number in first..=last {
            let line = lines[number - 1];
            if OUTSIDE_TEXT.iter().any(|name| {
                line.contains(&format!("{{{name}}}")) || line.contains(&format!("{{{name}:?}}"))
            }) {
                hits.insert(number);
            }
        }
    }
    hits.into_iter()
        .map(|n| (n, lines[n - 1].trim().to_owned()))
        .collect()
}

/// Print macros that may capture outside text raw.
const RAW_TEXT_EXCEPTIONS: &[Exception] = &[allow(
    "praetore-cli/src/policy_classify.rs",
    "eprintln!(\"{line}\");",
    "report() escapes the policy id and each problem when it builds these lines",
)];

/// Text from outside reaches the terminal through
/// `praetore_core::display::escape_for_display` (or `escape_invisible` for
/// JSON text), not as a raw `{error}`, `{body}` or `{text}` capture.
#[test]
fn print_macros_escape_outside_text() {
    let (found, stale) = check_guard(RAW_TEXT_EXCEPTIONS, raw_outside_text);
    assert!(
        found.is_empty(),
        "escape these with praetore_core::display::escape_for_display, or add an exception with its exact line and reason:\n{}",
        found.join("\n")
    );
    assert!(
        stale.is_empty(),
        "exceptions that match no line any more:\n{}",
        stale.join("\n")
    );
}

/// The checks read code, not comments or strings, follow a macro over
/// several lines and see `tracing::` events.
#[test]
fn the_guards_find_each_macro_and_span_lines() {
    let source = "fn f(p: &Path, error: E, body: String) {\n    let a = p.display();\n    eprintln!(\"open {}\", p.display());\n    println!(\n        \"{}\",\n        p.to_string_lossy()\n    );\n    tracing::info!(root = %p.display(), \"x\");\n    // println!(\"{}\", p.display());\n    let s = \"println!({}) p.display()\";\n    myprintln!(p.display());\n    eprintln!(\"Error: {error}\");\n    let m = format!(\"{body}\");\n    println!(\n        \"{body:?}\"\n    );\n}\n";
    let mut display: Vec<usize> = needle_in_terminal_macros(source, ".display()")
        .into_iter()
        .chain(needle_in_terminal_macros(source, ".to_string_lossy()"))
        .map(|(n, _)| n)
        .collect();
    display.sort();
    assert_eq!(display, [3, 6, 8]);
    let raw: Vec<usize> = raw_outside_text(source)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(raw, [12, 15]);
}
