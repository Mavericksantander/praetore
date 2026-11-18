//! Paths and names as a person reads them (m5).
//!
//! A path or a name can hold any character but `/` and NUL: an escape
//! sequence (`\x1b[2K` clears the terminal line), `\r` or `\n` would let a
//! file name rewrite or fake the line it is printed in. Every place that
//! shows a path or a name to a person (terminal messages, the PDF report)
//! goes through [`Shown`], which writes control characters (C0, DEL, C1),
//! zero-width and bidi characters as `\u{..}` and a backslash as `\\`, with
//! the same rules as the rest of the journal display
//! ([`praetore_core::display::escape_for_display`]). The dashboard applies
//! the same rules in the browser (`shown` in `dashboard/app.js`).
//!
//! Data keeps the exact value: JSON output, the report JSON and the
//! commands a person copies (those are quoted by [`crate::commands`]).

use std::{borrow::Cow, fmt, path::Path};

/// A path or a name, escaped when it is formatted.
#[derive(Debug, Clone)]
pub struct Shown<'a>(Cow<'a, str>);

impl fmt::Display for Shown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&praetore_core::display::escape_for_display(&self.0))
    }
}

/// `.shown()`: the [`Shown`] form of a path or a name.
pub trait Show {
    fn shown(&self) -> Shown<'_>;
}

impl Show for Path {
    fn shown(&self) -> Shown<'_> {
        Shown(self.to_string_lossy())
    }
}

impl Show for str {
    fn shown(&self) -> Shown<'_> {
        Shown(Cow::Borrowed(self))
    }
}

/// `text` escaped like [`Shown`], at most `max_chars` characters of it,
/// with `…` when it was cut.
pub fn bounded(text: &str, max_chars: usize) -> String {
    praetore_core::display::escape_bounded(text, max_chars)
}

#[cfg(test)]
mod tests {
    use super::*;

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
