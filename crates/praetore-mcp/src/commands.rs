//! Commands that praetore-mcp prints for a person to copy into a terminal
//! (`approve` and `reject` for a held call, `init`, `policy` suggestions,
//! and the same commands in the dashboard).
//!
//! On Linux and macOS a printed command starts with the absolute path of the
//! running binary (`std::env::current_exe`, canonicalized), so it works when
//! the binary is not on `PATH`, and its `--dir` is the absolute home. Each
//! word is printed bare when a POSIX shell will not interpret it, and in
//! single quotes (each `'` written as `'\''`) only when it is empty or
//! holds whitespace or a shell-special character. A lost leading or trailing
//! quote on a typical path then still pastes as the same command. When the
//! binary's path cannot be read (or is not UTF-8) the command starts with
//! `praetore-mcp`, which needs the binary on `PATH`.
//! Control and invisible characters are the exception and use `$'...'` (bash, zsh and ksh, not POSIX `sh`).
//!
//! On other platforms (Windows) nothing changes: commands start with
//! `praetore-mcp` and `--dir` is written as before, because POSIX quoting
//! does not apply to cmd.exe or PowerShell.

use std::path::{Path, PathBuf};

/// The word a command starts with when the binary's path is unknown.
pub const FALLBACK_PROGRAM: &str = "praetore-mcp";

/// Characters a POSIX shell does not interpret in an unquoted word.
fn is_bare_safe(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '=')
}

/// Whether `value` must be quoted to remain one POSIX shell word.
///
/// An empty value, whitespace, or a shell-special character (quotes,
/// dollar, backtick, backslash, bang, glob, parentheses, braces,
/// semicolon, ampersand, pipe, redirects, hash, tilde, and anything
/// else outside [`is_bare_safe`]) needs quotes.
pub(crate) fn needs_quoting(value: &str) -> bool {
    value.is_empty() || !value.chars().all(is_bare_safe)
}

/// `value` as one POSIX shell word, in single quotes when quoting is
/// needed, with each `'` as `'\''`. Control characters are not rewritten
/// here; see [`quote`].
pub(crate) fn quote_if_needed(value: &str) -> String {
    if needs_quoting(value) {
        format!("'{}'", value.replace('\'', "'\\''"))
    } else {
        value.to_owned()
    }
}

/// `value` as one shell word.
///
/// A value that holds only characters a shell does not interpret (letters,
/// digits, `_`, `-`, `.`, `/`, `:`, `=`) is printed bare, so a typo that
/// drops a quote around a typical path still pastes as the same command.
/// An empty value, or one with whitespace or a shell-special character, is
/// written in single quotes, with each `'` as `'\''`.
///
/// A value with a control, zero-width or bidi character (m5: a home named
/// with `\x1b[2K` or `\r` would rewrite the line the command is printed
/// in) is written as `$'...'` instead, with every byte outside printable
/// ASCII as `\xHH`. The printed command then holds no such character and
/// still gives the exact path when pasted into bash or zsh.
pub fn quote(value: &str) -> String {
    if value.chars().any(praetore_core::display::is_invisible) {
        return dollar_quote(value);
    }
    quote_if_needed(value)
}

/// `$'value'` with `\`, `'` and every byte outside printable ASCII
/// escaped.
fn dollar_quote(value: &str) -> String {
    let mut out = String::from("$'");
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            ' '..='~' => out.push(c),
            _ => {
                let mut bytes = [0; 4];
                for byte in c.encode_utf8(&mut bytes).bytes() {
                    out.push_str(&format!("\\x{byte:02x}"));
                }
            }
        }
    }
    out.push('\'');
    out
}

/// The first word of a printed command, for the running binary.
pub fn program() -> String {
    program_from(std::env::current_exe())
}

/// [`program`] for a given `current_exe` result: the canonical path as one
/// shell word ([`quote`]), or [`FALLBACK_PROGRAM`] when there is none.
pub fn program_from(exe: std::io::Result<PathBuf>) -> String {
    if !cfg!(unix) {
        return FALLBACK_PROGRAM.to_owned();
    }
    exe.and_then(|path| path.canonicalize())
        .ok()
        .and_then(|path| path.to_str().map(quote))
        .unwrap_or_else(|| FALLBACK_PROGRAM.to_owned())
}

/// The `--dir` value of a printed command: the absolute home, as one
/// shell word.
pub fn dir(root: &Path) -> String {
    if !cfg!(unix) {
        return crate::policy::shell_word(&root.display().to_string());
    }
    let absolute = root
        .canonicalize()
        .or_else(|_| std::path::absolute(root))
        .unwrap_or_else(|_| root.to_path_buf());
    quote(&absolute.display().to_string())
}

/// `<program> <args> --dir <home>`. `args` is already shell words.
pub fn command(args: &str, root: &Path) -> String {
    format!("{} {args} --dir {}", program(), dir(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// What `sh` makes of `word`: the one argument it passes to printf.
    fn through_sh(word: &str) -> String {
        let out = Command::new("sh")
            .arg("-c")
            .arg(format!("printf %s {word}"))
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8(out.stdout).unwrap()
    }

    /// What `sh` makes of a printed command: each word as one argument.
    fn argv_through_sh(line: &str) -> Vec<String> {
        let out = Command::new("sh")
            .arg("-c")
            .arg(format!("printf '%s\\n' {line}"))
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn quote_leaves_a_plain_path_bare() {
        for value in [
            "/Users/josesantander/.local/bin/praetore-mcp",
            "/Users/josesantander/.praetore/mcp",
            "/opt/homebrew/bin/npx",
            "/tmp/a-b_c.d",
            "praetore-mcp",
        ] {
            assert_eq!(quote(value), value);
            assert!(!needs_quoting(value), "{value}");
        }
    }

    #[test]
    fn quote_quotes_spaces_apostrophes_and_the_empty_arg() {
        assert_eq!(
            quote("/home/user/My Apps/praetore-mcp"),
            "'/home/user/My Apps/praetore-mcp'"
        );
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn quote_quotes_shell_special_characters() {
        for value in [
            "my fs",
            "$(id)",
            "/tmp/$HOME",
            "a`x`",
            "a\"b",
            "a\\b",
            "a!b",
            "a*b",
            "a?b",
            "a[b]",
            "a(b)",
            "a{b}",
            "a;b",
            "a&b",
            "a|b",
            "a<b",
            "a>b",
            "a#b",
            "~",
        ] {
            assert!(needs_quoting(value), "{value}");
            assert_eq!(quote(value), format!("'{}'", value.replace('\'', "'\\''")));
        }
    }

    #[test]
    fn quote_survives_spaces_and_single_quotes_in_sh() {
        for value in [
            "/home/user/My Apps/praetore-mcp",
            "/tmp/it's here/praetore-mcp",
            "/tmp/'''/a b/'",
            "/tmp/$HOME `x` \"y\" \\z *",
            "",
        ] {
            let word = quote(value);
            assert!(word.starts_with('\'') && word.ends_with('\''), "{word}");
            if cfg!(unix) {
                assert_eq!(through_sh(&word), value, "{word}");
            }
        }
        if cfg!(unix) {
            assert_eq!(
                through_sh(&quote("/Users/me/.local/bin/praetore-mcp")),
                "/Users/me/.local/bin/praetore-mcp"
            );
        }
    }

    /// m5: a path with a terminal escape, `\r`, `\n`, a C1 control or a
    /// zero-width space is printed with none of them and still pastes as the
    /// exact path in bash.
    #[test]
    fn quote_writes_control_characters_as_escapes_that_bash_reads_back() {
        for value in ["/tmp/a\x1b[2K\r\nb", "/tmp/it's\t\u{9b}x\u{200b}y\\z é"] {
            let word = quote(value);
            assert!(
                !word.chars().any(praetore_core::display::is_invisible),
                "{word:?}"
            );
            assert!(word.starts_with("$'") && word.ends_with('\''), "{word}");
            if cfg!(unix) {
                let out = Command::new("bash")
                    .arg("-c")
                    .arg(format!("printf %s {word}"))
                    .output()
                    .unwrap();
                assert!(out.status.success(), "{out:?}");
                assert_eq!(String::from_utf8(out.stdout).unwrap(), value, "{word}");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn program_is_the_canonical_path_of_the_running_binary() {
        let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
        let program = program();
        assert_eq!(program, quote(exe.to_str().unwrap()));
        assert_eq!(through_sh(&program), exe.to_str().unwrap());
    }

    #[test]
    fn program_falls_back_without_current_exe() {
        let missing = Err(std::io::Error::other("no current_exe"));
        assert_eq!(program_from(missing), FALLBACK_PROGRAM);
        // A path that does not exist cannot be canonicalized either.
        let gone = Ok(PathBuf::from("/nonexistent/praetore-mcp-gone"));
        assert_eq!(program_from(gone), FALLBACK_PROGRAM);
    }

    #[cfg(unix)]
    #[test]
    fn program_and_dir_with_spaces_and_quotes_round_trip_through_sh() {
        let temp = std::env::temp_dir().join(format!("praetore it's a dir {}", std::process::id()));
        std::fs::create_dir_all(&temp).unwrap();
        let exe = temp.join("praetore-mcp");
        std::fs::write(&exe, b"").unwrap();
        let program = program_from(Ok(exe.clone()));
        let canonical = exe.canonicalize().unwrap();
        assert_eq!(through_sh(&program), canonical.to_str().unwrap());
        let home = dir(&temp);
        assert_eq!(
            through_sh(&home),
            temp.canonicalize().unwrap().to_str().unwrap()
        );
        std::fs::remove_dir_all(&temp).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn dir_is_absolute_for_a_relative_home() {
        let word = dir(Path::new("some/relative home"));
        assert!(word.starts_with("'/"), "{word}");
        assert!(word.ends_with("some/relative home'"), "{word}");
    }

    #[cfg(unix)]
    #[test]
    fn command_starts_with_the_program_and_ends_with_the_dir() {
        let root = std::env::temp_dir();
        let text = command("approve abc", &root);
        assert_eq!(
            text,
            format!("{} approve abc --dir {}", program(), dir(&root))
        );
        let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
        let home = root.canonicalize().unwrap();
        assert_eq!(
            argv_through_sh(&text),
            vec![
                exe.to_str().unwrap(),
                "approve",
                "abc",
                "--dir",
                home.to_str().unwrap(),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn printed_suggestions_round_trip_through_sh_as_argv() {
        let temp = std::env::temp_dir().join(format!("praetore-cmd-{}", std::process::id()));
        std::fs::create_dir_all(&temp).unwrap();
        let spaced = temp.join("My Apps");
        std::fs::create_dir_all(&spaced).unwrap();
        let quoted = temp.join("it's here");
        std::fs::create_dir_all(&quoted).unwrap();

        for root in [&temp, &spaced, &quoted] {
            let approve = command("approve 7ced10ab", root);
            let home = root.canonicalize().unwrap();
            let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
            assert_eq!(
                argv_through_sh(&approve),
                vec![
                    exe.to_str().unwrap(),
                    "approve",
                    "7ced10ab",
                    "--dir",
                    home.to_str().unwrap(),
                ],
                "{approve}"
            );
            let allow = format!(
                "{} policy allow --id allow-filesystem-read_text_file --server filesystem --tool read_text_file --dir {}",
                program(),
                dir(root)
            );
            assert_eq!(
                argv_through_sh(&allow),
                vec![
                    exe.to_str().unwrap(),
                    "policy",
                    "allow",
                    "--id",
                    "allow-filesystem-read_text_file",
                    "--server",
                    "filesystem",
                    "--tool",
                    "read_text_file",
                    "--dir",
                    home.to_str().unwrap(),
                ],
                "{allow}"
            );
        }
        std::fs::remove_dir_all(&temp).unwrap();
    }

    /// `shell` recovers one argument from the printed word.
    ///
    /// `{shell} -c 'printf %s "$1"' _ <word>` compares exact bytes. The
    /// outer shell is `shell`, so `$'...'` is parsed only when that shell
    /// understands it. A `\n` in dash's printf format is the letter n, so
    /// the delimiter is not `%s\n`.
    #[cfg(unix)]
    fn shell_word(shell: &str, word: &str, dir: &Path) -> Result<Vec<u8>, String> {
        let script = format!("{shell} -c 'printf %s \"$1\"' _ {word}");
        let out = Command::new(shell)
            .arg("-c")
            .arg(&script)
            .current_dir(dir)
            .env("HOME", "/tmp/audit-quote-home")
            .env("IFS", " \t\n")
            .output()
            .map_err(|error| format!("{shell}: {error}"))?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(format!(
                "{shell} exit {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ))
        }
    }

    /// Portable words round-trip through POSIX `sh`. Control and invisible
    /// characters round-trip through bash, and through zsh when it is
    /// installed. A missing zsh is reported and skipped; it is not a pass.
    #[cfg(unix)]
    #[test]
    fn quote_posix_sh_round_trips_shell_edge_cases() {
        let dir = std::env::temp_dir().join(format!("praetore-quote-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["zed", "q", "a", "ab"] {
            std::fs::write(dir.join(name), b"").unwrap();
        }

        let portable: &[(&str, &str)] = &[
            ("space", "a b"),
            ("spaces", "  x  "),
            ("single quote", "it's"),
            ("only single quote", "'"),
            ("double quote", "a\"b"),
            ("only double quote", "\""),
            ("dollar", "$HOME"),
            ("dollar paren", "$(echo AUDIT_EXPANDED)"),
            ("backtick", "`echo AUDIT_EXPANDED`"),
            ("backslash", "a\\b"),
            ("only backslash", "\\"),
            ("empty", ""),
            ("leading dash", "-n"),
            ("only dash", "-"),
            ("double dash", "--dir"),
            ("equals", "="),
            ("assignment", "FOO=bar"),
            ("glob star", "*"),
            ("glob question", "?"),
            ("glob class", "a[b]"),
            ("hash", "#"),
            ("hash word", "#hash"),
            ("tilde", "~"),
            ("tilde path", "~/x"),
            ("bang", "a!b"),
            ("semicolon", "a;b"),
            ("ampersand", "a&b"),
            ("pipe", "a|b"),
            ("redirect in", "a<b"),
            ("redirect out", "a>b"),
            ("paren", "a(b)"),
            ("brace", "a{b}"),
            ("unicode n", "cañón"),
            ("emoji", "ok😀"),
            ("rtl letters", "مرحبا"),
        ];
        let invisible: &[(&str, &str)] = &[
            ("newline", "a\nb"),
            ("only newline", "\n"),
            ("tab", "a\tb"),
            ("nbsp", "a\u{00a0}b"),
            ("zero width", "a\u{200b}b"),
            ("rtl mark", "a\u{200f}b"),
            ("rtl override", "a\u{202e}b"),
        ];

        let mut failures = Vec::new();
        let mut sh_ok = 0usize;
        for (label, value) in portable {
            let quoted = quote(value);
            let bare = shell_word("sh", value, &dir);
            let bare_preserved = bare.as_deref() == Ok(value.as_bytes());
            if !bare_preserved && quoted == *value {
                failures.push(format!(
                    "{label}: left unquoted but sh does not preserve it ({bare:?})"
                ));
                continue;
            }
            match shell_word("sh", &quoted, &dir) {
                Ok(got) if got == value.as_bytes() => sh_ok += 1,
                other => failures.push(format!(
                    "{label}: quote={quoted:?} sh={other:?} want={value:?}"
                )),
            }
        }
        let mut bash_meta_ok = 0usize;
        for (label, value) in portable {
            if !matches!(
                *label,
                "bang"
                    | "semicolon"
                    | "ampersand"
                    | "pipe"
                    | "redirect in"
                    | "redirect out"
                    | "paren"
                    | "brace"
            ) {
                continue;
            }
            let quoted = quote(value);
            match shell_word("bash", &quoted, &dir) {
                Ok(got) if got == value.as_bytes() => bash_meta_ok += 1,
                other => failures.push(format!(
                    "{label}: quote={quoted:?} bash={other:?} want={value:?}"
                )),
            }
        }
        eprintln!("quote-edge: bash passed {bash_meta_ok}/8 metacharacter cases");

        // Absent zsh is skipped on purpose. A zsh that exists and does not
        // answer the probe is a failure, not a skip and not a pass.
        let zsh_ready = match Command::new("zsh").arg("-c").arg("printf zsh").output() {
            Ok(out) if out.status.success() && out.stdout == b"zsh" => true,
            Ok(out) => {
                failures.push(format!(
                    "zsh: installed but probe failed: exit {:?} stdout {} stderr {}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                ));
                false
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                failures.push(format!("zsh: {error}"));
                false
            }
        };
        let zsh_absent = !zsh_ready && !failures.iter().any(|line| line.starts_with("zsh:"));
        let invisible_labels: Vec<&str> = invisible.iter().map(|(label, _)| *label).collect();
        let mut bash_ok = 0usize;
        let mut zsh_ok = 0usize;
        for (label, value) in invisible {
            let quoted = quote(value);
            if !quoted.starts_with("$'") {
                failures.push(format!(
                    "{label}: control/invisible word is not $'...': {quoted:?}"
                ));
                continue;
            }
            match shell_word("bash", &quoted, &dir) {
                Ok(got) if got == value.as_bytes() => bash_ok += 1,
                other => failures.push(format!(
                    "{label}: quote={quoted:?} bash={other:?} want={value:?}"
                )),
            }
            if zsh_ready {
                match shell_word("zsh", &quoted, &dir) {
                    Ok(got) if got == value.as_bytes() => zsh_ok += 1,
                    other => failures.push(format!(
                        "{label}: quote={quoted:?} zsh={other:?} want={value:?}"
                    )),
                }
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
        eprintln!(
            "quote-edge: sh passed {sh_ok}/{} portable cases",
            portable.len()
        );
        eprintln!(
            "quote-edge: bash passed {bash_ok}/{} invisible cases",
            invisible.len()
        );
        if zsh_absent {
            eprintln!(
                "quote-edge: zsh not installed; skipped {} invisible cases: {}",
                invisible.len(),
                invisible_labels.join(", ")
            );
        } else {
            eprintln!(
                "quote-edge: zsh passed {zsh_ok}/{} invisible cases",
                invisible.len()
            );
        }
        assert!(
            failures.is_empty(),
            "{} edge case(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
