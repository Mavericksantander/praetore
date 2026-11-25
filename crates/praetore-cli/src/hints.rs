//! Command lines `praetore` prints for a person to copy into a terminal
//! (`doctor` after `init`, `approve`/`reject` when a request is held, and
//! `dispatch` after an approval).

use praetore_core::display::Show;
use std::path::Path;

/// The `doctor` line printed at the end of `init`.
pub fn doctor(directory: &Path) -> String {
    format!("Then run: praetore doctor {}", directory.shown())
}

/// The `approve` and `reject` lines printed when a request is held.
///
/// These strings are only the hint. Nothing here signs or sends a
/// decision.
pub fn approve_reject(directory: &Path, request_id: &str, approver: &str) -> String {
    format!(
        "  praetore approve {} {request_id} --approver {approver}\n  praetore reject {} {request_id} --approver {approver}",
        directory.shown(),
        directory.shown(),
    )
}

/// The `dispatch` line printed after an approval is recorded and the
/// action has not run.
pub fn dispatch(directory: &Path, request_id: &str, agent_id: &str) -> String {
    format!(
        "  praetore dispatch {} {request_id} --agent {agent_id}",
        directory.shown()
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::Command;

    /// A directory name that would rewrite the line it is printed in.
    const INVISIBLE: &str = "/tmp/demo\x1b[2K\r\nfake\u{202e}";
    /// `INVISIBLE` as one `$'...'` word (`commands::quote`).
    const INVISIBLE_WORD: &str = "$'/tmp/demo\\x1b[2K\\x0d\\x0afake\\xe2\\x80\\xae'";
    /// A directory name a POSIX shell would split or expand if left bare.
    const META: &str = "/tmp/My Apps/it's $HOME";
    /// `META` as one single-quoted word (`commands::quote`).
    const META_WORD: &str = "'/tmp/My Apps/it'\\''s $HOME'";

    const REQUEST: &str = "11111111-1111-1111-1111-111111111111";
    const AGENT: &str = "22222222-2222-2222-2222-222222222222";
    const APPROVER: &str = "local-approver";

    /// Recover the exact argument from a printed shell word, without
    /// invoking `praetore`. `{shell} -c 'printf %s "$1"' _ <word>`
    /// compares exact bytes. A `\n` in dash's printf format is the
    /// letter n, so the delimiter is not `%s\n`.
    fn through_shell(shell: &str, word: &str) -> Result<Vec<u8>, String> {
        let script = format!("{shell} -c 'printf %s \"$1\"' _ {word}");
        let out = Command::new(shell)
            .arg("-c")
            .arg(&script)
            .env("HOME", "/tmp/praetore-hint-quote-home")
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

    fn zsh_ready(failures: &mut Vec<String>) -> bool {
        match Command::new("zsh").arg("-c").arg("printf zsh").output() {
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
        }
    }

    /// The printed word holds no raw invisible character and pastes as
    /// `want` in bash, and in zsh when it is installed. A missing zsh is
    /// reported and skipped; it is not a pass.
    fn assert_copyable(word: &str, want: &str) {
        assert!(
            !word.chars().any(praetore_core::display::is_invisible),
            "raw invisible character in {word:?}"
        );
        let got = through_shell("bash", word).expect("bash");
        assert_eq!(got, want.as_bytes(), "bash: quote={word:?}");

        let mut failures = Vec::new();
        if zsh_ready(&mut failures) {
            let got = through_shell("zsh", word).expect("zsh");
            assert_eq!(got, want.as_bytes(), "zsh: quote={word:?}");
            eprintln!("quote-edge: zsh passed 1/1 for {word}");
        } else if failures.is_empty() {
            eprintln!("quote-edge: zsh not installed; skipped the round-trip of {word}");
        } else {
            panic!("{}", failures.join("\n"));
        }
    }

    fn assert_no_raw(text: &str) {
        for raw in ['\x1b', '\r', '\n', '\u{202e}', '\''] {
            if text.contains(raw) && raw != '\n' && raw != '\'' {
                assert!(!text.contains(raw), "raw {raw:?} in {text:?}");
            }
        }
        assert!(
            !text.contains('\x1b') && !text.contains('\r') && !text.contains('\u{202e}'),
            "raw control or bidi character in {text:?}"
        );
    }

    #[test]
    fn doctor_hint_is_a_copyable_shell_word() {
        let invisible = doctor(Path::new(INVISIBLE));
        assert_no_raw(&invisible);
        assert_eq!(
            invisible,
            format!("Then run: praetore doctor {INVISIBLE_WORD}")
        );
        assert_copyable(INVISIBLE_WORD, INVISIBLE);

        let meta = doctor(Path::new(META));
        assert_eq!(meta, format!("Then run: praetore doctor {META_WORD}"));
        assert_copyable(META_WORD, META);
    }

    #[test]
    fn approve_reject_hint_is_a_copyable_shell_word() {
        // Only the printed hint is checked. Nothing here runs approve or reject.
        let invisible = approve_reject(Path::new(INVISIBLE), REQUEST, APPROVER);
        assert_no_raw(&invisible);
        assert_eq!(
            invisible,
            format!(
                "  praetore approve {INVISIBLE_WORD} {REQUEST} --approver {APPROVER}\n  praetore reject {INVISIBLE_WORD} {REQUEST} --approver {APPROVER}"
            )
        );
        assert_copyable(INVISIBLE_WORD, INVISIBLE);

        let meta = approve_reject(Path::new(META), REQUEST, APPROVER);
        assert_eq!(
            meta,
            format!(
                "  praetore approve {META_WORD} {REQUEST} --approver {APPROVER}\n  praetore reject {META_WORD} {REQUEST} --approver {APPROVER}"
            )
        );
        assert_copyable(META_WORD, META);
    }

    #[test]
    fn dispatch_hint_is_a_copyable_shell_word() {
        let invisible = dispatch(Path::new(INVISIBLE), REQUEST, AGENT);
        assert_no_raw(&invisible);
        assert_eq!(
            invisible,
            format!("  praetore dispatch {INVISIBLE_WORD} {REQUEST} --agent {AGENT}")
        );
        assert_copyable(INVISIBLE_WORD, INVISIBLE);

        let meta = dispatch(Path::new(META), REQUEST, AGENT);
        assert_eq!(
            meta,
            format!("  praetore dispatch {META_WORD} {REQUEST} --agent {AGENT}")
        );
        assert_copyable(META_WORD, META);
    }
}
