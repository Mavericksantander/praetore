//! Escaping for human-facing text (G7).
//!
//! Action types and tool names come from agents and servers. A signed
//! receipt keeps them exactly, and JSON output stays exact; text meant for a
//! person (a log line, a table, `--format text`) escapes the characters that
//! render invisibly or reorder text, so `local:set_value\u{200b}` does not
//! read as `local:set_value`.

/// Whether `c` renders invisibly, moves the cursor or reorders text: control
/// characters, format characters (zero-width characters, bidi controls,
/// the byte order mark, soft hyphen, tag characters) and every Unicode
/// space other than U+0020.
pub fn is_invisible(c: char) -> bool {
    c.is_control()
        || (c.is_whitespace() && c != ' ')
        || matches!(
            c as u32,
            0x00AD
                | 0x034F
                | 0x061C
                | 0x0600..=0x0605
                | 0x06DD
                | 0x070F
                | 0x115F
                | 0x1160
                | 0x17B4
                | 0x17B5
                | 0x180B..=0x180F
                | 0x200B..=0x200F
                | 0x202A..=0x202E
                | 0x2060..=0x206F
                | 0x3164
                | 0xFE00..=0xFE0F
                | 0xFEFF
                | 0xFFA0
                | 0xFFF9..=0xFFFB
                | 0x110BD
                | 0x110CD
                | 0x1BCA0..=0x1BCA3
                | 0x1D173..=0x1D17A
                | 0xE0000..=0xE0FFF
        )
}

/// `value` with every [`is_invisible`] character written as `\u{XXXX}` and
/// every backslash as `\\`, so the result is unambiguous: a literal
/// `\u{200b}` in the input becomes `\\u{200b}`.
///
/// ```
/// use praetore_core::display::escape_for_display;
///
/// assert_eq!(escape_for_display("local:set_value\u{200b}"), "local:set_value\\u{200b}");
/// assert_eq!(escape_for_display("a\u{202e}b"), "a\\u{202e}b");
/// assert_eq!(escape_for_display("x\\u{200b}"), "x\\\\u{200b}");
/// assert_eq!(escape_for_display("fs:write_file"), "fs:write_file");
/// ```
pub fn escape_for_display(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if is_invisible(c) => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// [`escape_for_display`] for text that is already JSON-encoded (its
/// backslashes are already escaped): only invisible characters are written
/// as `\u{XXXX}`. JSON never writes a brace after `\u`, so the result stays
/// unambiguous.
pub fn escape_invisible(json_text: &str) -> String {
    let mut out = String::with_capacity(json_text.len());
    for c in json_text.chars() {
        if is_invisible(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// [`escape_for_display`] of at most the first `max_chars` characters of
/// `value`, with `…` appended when it was cut.
pub fn escape_bounded(value: &str, max_chars: usize) -> String {
    let mut out = escape_for_display(&value.chars().take(max_chars).collect::<String>());
    if value.chars().count() > max_chars {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invisible_and_bidi_characters_are_escaped() {
        for (input, expected) in [
            ("local:set_value\u{200b}", "local:set_value\\u{200b}"),
            ("safety:\u{202e}tlah", "safety:\\u{202e}tlah"),
            ("a\u{2066}b\u{2069}", "a\\u{2066}b\\u{2069}"),
            ("\u{feff}x", "\\u{feff}x"),
            ("tab\tnew\nline", "tab\\u{9}new\\u{a}line"),
            ("nbsp\u{a0}", "nbsp\\u{a0}"),
            ("tag\u{e0041}", "tag\\u{e0041}"),
            ("caf\u{e9}", "caf\u{e9}"),
        ] {
            assert_eq!(escape_for_display(input), expected, "{input:?}");
        }
        assert_eq!(escape_bounded("abcdef", 3), "abc…");
        assert_eq!(
            escape_invisible("\"x\\\\u{200b}\u{200b}\""),
            "\"x\\\\u{200b}\\u{200b}\""
        );
    }
}
