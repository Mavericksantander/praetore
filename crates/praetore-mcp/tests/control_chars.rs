//! m5: paths and names that hold control characters (a terminal escape,
//! `\r`, `\n`) are shown escaped in each output: the terminal, the PDF
//! report (here) and the dashboard (`tests-js/dashboard.test.mjs`). Data
//! keeps the exact value.

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

/// Every terminal message formats a path through `Shown` (`.shown()`),
/// never `Path::display`, which writes control characters as they are.
/// The exceptions keep the exact path as data.
#[test]
fn src_formats_paths_with_shown_not_display() {
    const EXCEPTIONS: &[(&str, &str, &str)] = &[
        (
            "src/commands.rs",
            "shell_word(&root.display().to_string())",
            "Windows --dir word for a command to copy, not POSIX-quoted",
        ),
        (
            "src/commands.rs",
            "quote(&absolute.display().to_string())",
            "quote() writes control characters as $'\\xHH'",
        ),
        (
            "src/commands.rs",
            "root.canonicalize().unwrap().display()",
            "unit test",
        ),
        ("src/policy.rs", "root.display());", "unit test"),
        (
            "src/dashboard.rs",
            ".display().to_string()",
            "JSON data for the page, escaped there by shown()",
        ),
    ];
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    let mut stack = vec![root.join("src")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let file = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            for (index, line) in fs::read_to_string(&path).unwrap().lines().enumerate() {
                let code = line.split("//").next().unwrap_or_default();
                if !code.contains(".display()") {
                    continue;
                }
                let allowed = EXCEPTIONS
                    .iter()
                    .any(|(f, snippet, _)| *f == file && code.contains(snippet));
                if !allowed {
                    found.push(format!("{file}:{}: {}", index + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "format these paths with `.shown()` (use crate::shown::Show), or add an exception with its reason:\n{}",
        found.join("\n")
    );
}
