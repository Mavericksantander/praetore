//! Commands that praetore-mcp prints for a person to copy into a terminal
//! (`approve` and `reject` for a held call, `init`, `policy` suggestions,
//! and the same commands in the dashboard).
//!
//! On Linux and macOS a printed command starts with the absolute path of the
//! running binary (`std::env::current_exe`, canonicalized), so it works when
//! the binary is not on `PATH`, and its `--dir` is the absolute home. Both
//! are quoted for a POSIX shell: inside single quotes, each `'` written as
//! `'\''`. When the binary's path cannot be read (or is not UTF-8) the
//! command starts with `praetore-mcp`, which needs the binary on `PATH`.
//!
//! On other platforms (Windows) nothing changes: commands start with
//! `praetore-mcp` and `--dir` is written as before, because POSIX quoting
//! does not apply to cmd.exe or PowerShell.

use std::path::{Path, PathBuf};

/// The word a command starts with when the binary's path is unknown.
pub const FALLBACK_PROGRAM: &str = "praetore-mcp";

/// `value` as one POSIX shell word: `'value'`, with each `'` as `'\''`.
pub fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// The first word of a printed command, for the running binary.
pub fn program() -> String {
    program_from(std::env::current_exe())
}

/// [`program`] for a given `current_exe` result: the quoted canonical path,
/// or [`FALLBACK_PROGRAM`] when there is none.
pub fn program_from(exe: std::io::Result<PathBuf>) -> String {
    if !cfg!(unix) {
        return FALLBACK_PROGRAM.to_owned();
    }
    exe.and_then(|path| path.canonicalize())
        .ok()
        .and_then(|path| path.to_str().map(quote))
        .unwrap_or_else(|| FALLBACK_PROGRAM.to_owned())
}

/// The `--dir` value of a printed command: the absolute home, quoted.
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
    }

    #[cfg(unix)]
    #[test]
    fn program_is_the_quoted_canonical_path_of_the_running_binary() {
        let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
        let program = program();
        assert_eq!(program, quote(exe.to_str().unwrap()));
        assert!(program.starts_with("'/"), "{program}");
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
        assert!(
            text.starts_with(&format!("{} approve abc --dir '", program())),
            "{text}"
        );
        assert!(
            text.ends_with(&format!("{}'", root.canonicalize().unwrap().display())),
            "{text}"
        );
    }
}
