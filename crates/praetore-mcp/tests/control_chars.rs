//! m5: paths and names that hold control characters (a terminal escape,
//! `\r`, `\n`) are shown escaped in each output: the terminal, the PDF
//! report (here) and the dashboard (`tests-js/dashboard.test.mjs`). Data
//! keeps the exact value.

mod lex;

use serde_json::json;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

/// A file name that clears the terminal line, returns to its start and
/// begins a new one.
const EVIL: &str = "x\x1b[2K\r\nfake";
/// `EVIL` as praetore-mcp shows it.
const SHOWN: &str = "x\\u{1b}[2K\\u{d}\\u{a}fake";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_praetore-mcp")
}

fn run(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// stdout and stderr together, checked to hold no escape, no `\r`, and no
/// line that the name split.
fn terminal_text(out: &Output) -> String {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !text.contains('\x1b') && !text.contains('\r'),
        "raw control character in the terminal output:\n{text:?}"
    );
    assert!(
        !text.contains("[2K\nfake"),
        "the name split a line:\n{text:?}"
    );
    text
}

#[cfg(unix)]
#[test]
fn the_terminal_shows_a_home_with_control_characters_escaped() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join(EVIL);
    let home_arg = home.to_str().unwrap();

    // `init` lists the home's files and prints the next commands.
    let out = run(&["init", "--dir", home_arg], "");
    assert!(out.status.success(), "{out:?}");
    let text = terminal_text(&out);
    assert!(text.contains(SHOWN), "{text}");
    // The printed commands still give the exact home when pasted in bash.
    assert!(
        text.contains("--dir $'") && text.contains("x\\x1b[2K\\x0d\\x0afake"),
        "{text}"
    );

    // An error message names the path.
    let missing = temp.path().join(format!("missing-{EVIL}"));
    let out = run(&["policy", "check", "--dir", missing.to_str().unwrap()], "");
    assert!(!out.status.success(), "{out:?}");
    let text = terminal_text(&out);
    assert!(text.contains(&format!("missing-{SHOWN}")), "{text}");

    // `verify` names the trust files of the home.
    let out = run(&["verify", "--dir", home_arg], "");
    let text = terminal_text(&out);
    assert!(text.contains(SHOWN), "{text}");
}

fn fake_server() -> PathBuf {
    Path::new(bin())
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("fake_server{}", std::env::consts::EXE_SUFFIX))
}

fn has(bytes: &[u8], needle: &str) -> bool {
    bytes
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

#[test]
fn the_pdf_report_shows_a_tool_name_with_control_characters_escaped() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let home_arg = home.to_str().unwrap();
    assert!(run(&["init", "--dir", home_arg], "").status.success());
    let call = json!({
        "jsonrpc": "2.0", "id": 20, "method": "tools/call",
        "params": {"name": format!("t{EVIL}"), "arguments": {}}
    });
    let input = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        call,
    ]
    .iter()
    .map(|line| format!("{line}\n"))
    .collect::<String>();
    let server = fake_server();
    let out = run(
        &[
            "wrap",
            "--dir",
            home_arg,
            "--name",
            "fake",
            "--mode",
            "enforce",
            "--",
            server.to_str().unwrap(),
        ],
        &input,
    );
    assert!(out.status.success(), "{out:?}");
    let pdf = fs::read_dir(home.join("reports"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "pdf"))
        .expect("a PDF report");
    let pdf = fs::read(pdf).unwrap();
    // The display escape, with each backslash doubled by the PDF string.
    assert!(
        has(&pdf, "tx\\\\u{1b}[2K\\\\u{d}\\\\u{a}fake"),
        "the escaped tool name is not in the PDF"
    );
    assert!(!has(&pdf, "\x1b[2K"), "raw escape in the PDF");
    assert!(
        !has(&pdf, "?[2K??fake"),
        "the name was blanked, not escaped"
    );
}

/// One allowed use: the file, the exact line of code (trimmed) and why.
struct Exception {
    file: &'static str,
    line: &'static str,
    why: &'static str,
}

const fn allow(file: &'static str, line: &'static str, why: &'static str) -> Exception {
    Exception { file, line, why }
}

/// Lines that may keep `Path::display`: the exact path is data here.
const DISPLAY_EXCEPTIONS: &[Exception] = &[
    allow(
        "src/commands.rs",
        "return crate::policy::shell_word(&root.display().to_string());",
        "Windows --dir word of a command to copy; not POSIX-quoted",
    ),
    allow(
        "src/commands.rs",
        "quote(&absolute.display().to_string())",
        "quote() writes control characters as $'\\xHH'",
    ),
    allow(
        "src/commands.rs",
        "text.ends_with(&format!(\"{}'\", root.canonicalize().unwrap().display())),",
        "unit test comparing with the exact path",
    ),
    allow(
        "src/policy.rs",
        "let data = format!(\"/System/Volumes/Data{}\", root.display());",
        "unit test building a path, not a message",
    ),
    allow(
        "src/dashboard.rs",
        "\"home\": home.root.display().to_string(),",
        "JSON data for the page, escaped there by shown()",
    ),
    allow(
        "src/dashboard.rs",
        "\"attester_pin\": home.attester_pin().display().to_string(),",
        "JSON data for the page, escaped there by shown()",
    ),
    allow(
        "src/dashboard.rs",
        "\"issuer_pins\": home.issuer_pins().display().to_string(),",
        "JSON data for the page, escaped there by shown()",
    ),
    allow(
        "src/dashboard.rs",
        "let location = json!({\"file\": line.file.display().to_string(), \"line\": line.line_number});",
        "JSON data for the page, escaped there by shown()",
    ),
    allow(
        "src/dashboard.rs",
        "\"path\": home.policy().display().to_string(),",
        "JSON data for the page, escaped there by shown()",
    ),
];

/// Every `src/**/*.rs` file: its path from the crate root and its text.
fn src_files() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    let mut stack = vec![root.join("src")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let file = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push((file, fs::read_to_string(&path).unwrap()));
            }
        }
    }
    files.sort();
    files
}

/// Lines of `source` (1-based, with their code as written) where `hit`
/// finds a forbidden use in the lexed code, so text inside comments and
/// string literals never counts and code after a `//` inside a string
/// still does.
fn offending_lines(source: &str, hit: impl Fn(&str) -> bool) -> Vec<(usize, String)> {
    let lexed = lex::lex(source);
    lexed
        .code
        .lines()
        .zip(source.lines())
        .enumerate()
        .filter(|(_, (code, _))| hit(code))
        .map(|(index, (_, line))| (index + 1, line.trim().to_owned()))
        .collect()
}

/// Lines `find` reports in src and no exception covers, and exceptions
/// that no longer match a line (so the list cannot outlive the code).
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

/// m5: every terminal message formats a path through `Shown`
/// (`.shown()`), never `Path::display`, which writes control characters
/// as they are. The exceptions keep the exact path as data.
#[test]
fn src_formats_paths_with_shown_not_display() {
    let (found, stale) = check_guard(DISPLAY_EXCEPTIONS, |source| {
        offending_lines(source, |code| code.contains(".display()"))
    });
    assert!(
        found.is_empty(),
        "format these paths with `.shown()` (use crate::shown::Show), or add an exception with its exact line and reason:\n{}",
        found.join("\n")
    );
    assert!(
        stale.is_empty(),
        "exceptions that match no line any more:\n{}",
        stale.join("\n")
    );
}

/// The guard reads code, not text: `.display()` after a `//` inside a
/// string is code; in a comment or a string it is not.
#[test]
fn the_guard_sees_code_after_a_double_slash_in_a_string() {
    let source = "fn f(p: &Path) {\n    eprintln!(\"open http://x/ {}\", p.display());\n    // p.display() in a comment\n    let s = \"p.display()\";\n}\n";
    let hits = offending_lines(source, |code| code.contains(".display()"));
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].0, 2);
}

/// The code points `praetore_core::display::is_invisible` escapes, as
/// inclusive `[first, last]` ranges.
fn invisible_ranges() -> Vec<[u32; 2]> {
    let mut ranges: Vec<[u32; 2]> = Vec::new();
    for c in (0..=0x10FFFFu32).filter_map(char::from_u32) {
        if !praetore_core::display::is_invisible(c) {
            continue;
        }
        let cp = c as u32;
        match ranges.last_mut() {
            Some(last) if last[1] + 1 == cp => last[1] = cp,
            _ => ranges.push([cp, cp]),
        }
    }
    ranges
}

/// m1: the dashboard escapes with the rule of praetore_core, not a copy
/// kept by hand. This test holds tests-js/fixtures/invisible-ranges.json
/// equal to `is_invisible` over every code point; the JS test "shown()
/// escapes exactly the code points of praetore_core" holds `shown()` in
/// app.js equal to that file. Rewrite it with PRAETORE_WRITE_FIXTURES=1.
#[test]
fn the_dashboard_fixture_holds_the_invisible_ranges_of_praetore_core() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests-js/fixtures/invisible-ranges.json");
    let expected = format!(
        "{}\n",
        json!({
            "source": "praetore_core::display::is_invisible",
            "ranges": invisible_ranges(),
        })
    );
    if std::env::var_os("PRAETORE_WRITE_FIXTURES").is_some() {
        fs::write(&path, &expected).unwrap();
    }
    let written = fs::read_to_string(&path).unwrap_or_default();
    assert!(
        written == expected,
        "{} differs from praetore_core::display::is_invisible; run this test with PRAETORE_WRITE_FIXTURES=1 and update shown() in src/dashboard/app.js",
        path.display()
    );
}

/// Macros that build text for a person or a message.
const FORMAT_MACROS: &[&str] = &[
    "format", "print", "println", "eprint", "eprintln", "write", "writeln",
];

/// Lines (1-based, as written) where `needle` is inside the arguments of
/// one of `FORMAT_MACROS`, in the lexed code of `source`.
fn inside_format_macros(source: &str, needle: &str) -> Vec<(usize, String)> {
    let code = lex::lex(source).code;
    let bytes = code.as_bytes();
    let mut lines = std::collections::BTreeSet::new();
    for name in FORMAT_MACROS {
        let open = format!("{name}!");
        let mut from = 0;
        while let Some(at) = code[from..].find(&open).map(|i| from + i) {
            from = at + open.len();
            let ident_before =
                at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_');
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
            if ident_before {
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
            let span = &code[start..end];
            let mut search = 0;
            while let Some(i) = span[search..].find(needle).map(|i| search + i) {
                lines.insert(code[..start + i].matches('\n').count() + 1);
                search = i + needle.len();
            }
        }
    }
    let source_lines: Vec<&str> = source.lines().collect();
    lines
        .into_iter()
        .map(|n| (n, source_lines[n - 1].trim().to_owned()))
        .collect()
}

/// Lines that may format `to_string_lossy()` in a message: none today.
const LOSSY_EXCEPTIONS: &[Exception] = &[];

/// m4: `to_string_lossy()` writes control characters as they are, like
/// `Path::display`. Inside a formatting macro it must be `.shown()`.
#[test]
fn src_formats_no_to_string_lossy_in_a_message() {
    let (found, stale) = check_guard(LOSSY_EXCEPTIONS, |source| {
        inside_format_macros(source, ".to_string_lossy()")
    });
    assert!(
        found.is_empty(),
        "format these with `.shown()`, or add an exception with its exact line and reason:\n{}",
        found.join("\n")
    );
    assert!(
        stale.is_empty(),
        "exceptions that match no line any more:\n{}",
        stale.join("\n")
    );
}

#[test]
fn the_lossy_guard_finds_each_macro_and_spans_lines() {
    let source = "fn f(p: &Path, out: &mut String) {\n    let a = p.to_string_lossy();\n    eprintln!(\"open http://x/ {}\", p.to_string_lossy());\n    let _ = format!(\n        \"{}\",\n        p.to_string_lossy()\n    );\n    let _ = write!(out, \"{}\", p.to_string_lossy());\n    // println!(\"{}\", p.to_string_lossy());\n    let s = \"format!({}) p.to_string_lossy()\";\n    myformat!(p.to_string_lossy());\n}\n";
    let lines: Vec<usize> = inside_format_macros(source, ".to_string_lossy()")
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(lines, [3, 6, 8]);
}
