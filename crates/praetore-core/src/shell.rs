//! A path or a name as one POSIX shell word, for a command a person
//! copies into a terminal.
//!
//! This is the one quoting rule of the workspace: `praetore-mcp`
//! (`commands::quote`) and the copy-paste hints of `praetore` both use
//! [`quote`]. Control, zero-width and bidi characters use `$'...'` (bash,
//! zsh and ksh, not POSIX `sh`). Metacharacters use single quotes.

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
pub fn needs_quoting(value: &str) -> bool {
    value.is_empty() || !value.chars().all(is_bare_safe)
}

/// `value` as one POSIX shell word, in single quotes when quoting is
/// needed, with each `'` as `'\''`. Control characters are not rewritten
/// here; see [`quote`].
pub fn quote_if_needed(value: &str) -> String {
    if needs_quoting(value) {
        format!("'{}'", value.replace('\'', r"'\''"))
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
/// A value with a control, zero-width or bidi character (a home named
/// with `\x1b[2K` or `\r` would rewrite the line the command is printed
/// in) is written as `$'...'` instead, with every byte outside printable
/// ASCII as `\xHH`. The printed command then holds no such character and
/// still gives the exact path when pasted into bash or zsh.
pub fn quote(value: &str) -> String {
    if value.chars().any(crate::display::is_invisible) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_leaves_a_plain_path_bare() {
        assert_eq!(quote("/tmp/a-b_c.d"), "/tmp/a-b_c.d");
    }

    #[test]
    fn quote_quotes_spaces_and_apostrophes() {
        assert_eq!(quote("/tmp/My Apps/x"), "'/tmp/My Apps/x'");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn quote_writes_control_characters_as_dollar_quotes() {
        assert_eq!(quote("/tmp/a\x1b[2K\r\nb"), "$'/tmp/a\\x1b[2K\\x0d\\x0ab'");
        assert!(!quote("a\0b").as_bytes().contains(&0));
        assert!(quote("a\0b").contains("\\x00"));
    }
}
