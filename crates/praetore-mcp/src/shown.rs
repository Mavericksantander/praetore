//! Paths and names as a person reads them (m5).
//!
//! A path or a name can hold any character but `/` and NUL: an escape
//! sequence (`\x1b[2K` clears the terminal line), `\r` or `\n` would let a
//! file name rewrite or fake the line it is printed in. Every place that
//! shows a path or a name to a person (terminal messages, the PDF report)
//! goes through [`Shown`], which writes control characters (C0, DEL, C1),
//! zero-width and bidi characters as `\u{..}` and a backslash as `\\`, with
//! the same rules as the rest of the journal display: `Shown` is
//! [`praetore_core::display::Shown`], shared with `praetore` and
//! `praetore-verify`. The dashboard applies
//! the same rules in the browser (`shown` in `dashboard/app.js`).
//!
//! Data keeps the exact value: JSON output, the report JSON and the
//! commands a person copies (those are quoted by [`crate::commands`]).

pub use praetore_core::display::{Show, Shown};

/// `text` escaped like [`Shown`], at most `max_chars` characters of it,
/// with `…` when it was cut.
pub fn bounded(text: &str, max_chars: usize) -> String {
    praetore_core::display::escape_bounded(text, max_chars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn control_characters_in_a_path_are_escaped() {
        let path = Path::new("/tmp/a\x1b[2K\r\nb\0c\u{9b}d\u{7f}");
        let shown = path.shown().to_string();
        assert_eq!(shown, "/tmp/a\\u{1b}[2K\\u{d}\\u{a}b\\u{0}c\\u{9b}d\\u{7f}");
        assert!(!shown.chars().any(char::is_control), "{shown:?}");
        assert_eq!("plain name".shown().to_string(), "plain name");
        assert_eq!(bounded("ab\x1bc", 2), "ab…");
    }
}
