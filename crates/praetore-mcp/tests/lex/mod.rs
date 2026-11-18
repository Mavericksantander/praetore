//! A small Rust lexer for the source checks in `tests/`: it tells code from
//! comments and string literals, so a check never matches text inside a
//! comment or a string by accident and never misses code next to one.

/// One string literal: the line it starts on and its contents as written
/// (escapes are not resolved).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Literal {
    pub line: usize,
    pub text: String,
}

/// `source` split into code and string literals. `code` has the same
/// lines as `source`; comments and the contents of string and char
/// literals are blanked (newlines kept), the quotes stay.
#[derive(Debug, Default)]
pub struct Lexed {
    pub code: String,
    pub literals: Vec<Literal>,
}

pub fn lex(source: &str) -> Lexed {
    let chars: Vec<char> = source.chars().collect();
    let mut out = Lexed::default();
    let mut line = 1;
    let mut i = 0;
    // Blanks `c` in `code`, keeping newlines.
    let blank = |c: char| if c == '\n' { '\n' } else { ' ' };
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                out.code.push(' ');
                i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.code.push_str("  ");
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.code.push_str("  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if chars[i] == '\n' {
                        line += 1;
                    }
                    out.code.push(blank(chars[i]));
                    i += 1;
                }
            }
            continue;
        }
        // Raw strings: r"..", r#".."#, br"..", cr"..".
        let raw_start = match (c, next) {
            ('r', Some('"' | '#')) => Some(i + 1),
            ('b' | 'c', Some('r')) if matches!(chars.get(i + 2), Some('"' | '#')) => Some(i + 2),
            _ => None,
        };
        let ident_before = i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_');
        if let Some(mut j) = raw_start.filter(|_| !ident_before) {
            let mut hashes = 0;
            while chars.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if chars.get(j) == Some(&'"') {
                for &p in &chars[i..=j] {
                    out.code.push(p);
                }
                let start_line = line;
                let mut text = String::new();
                let mut k = j + 1;
                while let Some(&ch) = chars.get(k) {
                    if ch == '"' && (0..hashes).all(|h| chars.get(k + 1 + h) == Some(&'#')) {
                        out.code.push('"');
                        out.code.extend(std::iter::repeat_n('#', hashes));
                        k += 1 + hashes;
                        break;
                    }
                    if ch == '\n' {
                        line += 1;
                    }
                    text.push(ch);
                    out.code.push(blank(ch));
                    k += 1;
                }
                out.literals.push(Literal {
                    line: start_line,
                    text,
                });
                i = k;
                continue;
            }
        }
        if c == '"' {
            out.code.push('"');
            let start_line = line;
            let mut text = String::new();
            let mut k = i + 1;
            while let Some(&ch) = chars.get(k) {
                if ch == '\\' {
                    text.push(ch);
                    out.code.push(' ');
                    if let Some(&escaped) = chars.get(k + 1) {
                        if escaped == '\n' {
                            line += 1;
                        }
                        text.push(escaped);
                        out.code.push(blank(escaped));
                    }
                    k += 2;
                    continue;
                }
                if ch == '"' {
                    out.code.push('"');
                    k += 1;
                    break;
                }
                if ch == '\n' {
                    line += 1;
                }
                text.push(ch);
                out.code.push(blank(ch));
                k += 1;
            }
            out.literals.push(Literal {
                line: start_line,
                text,
            });
            i = k;
            continue;
        }
        // A char literal ('x', '\n', '\u{..}'), not a lifetime ('a).
        if c == '\'' {
            let end = match next {
                Some('\\') => chars[i + 2..]
                    .iter()
                    .position(|&ch| ch == '\'')
                    .map(|p| i + 2 + p),
                Some(_) if chars.get(i + 2) == Some(&'\'') => Some(i + 2),
                _ => None,
            };
            if let Some(end) = end {
                out.code.push('\'');
                for _ in i + 1..end {
                    out.code.push(' ');
                }
                out.code.push('\'');
                i = end + 1;
                continue;
            }
        }
        if c == '\n' {
            line += 1;
        }
        out.code.push(c);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::lex;

    #[test]
    fn comments_and_strings_are_blanked_and_lines_kept() {
        let source = "let a = \"x // y\"; // gone\n/* a\n b */ let b = r#\"q\"#;\nlet c = '\"';";
        let lexed = lex(source);
        assert_eq!(lexed.code.lines().count(), source.lines().count());
        assert!(!lexed.code.contains("gone") && !lexed.code.contains("x // y"));
        assert!(lexed.code.contains("let b = r#\" \"#;"), "{}", lexed.code);
        assert!(lexed.code.contains("let c = ' ';"), "{}", lexed.code);
        let texts: Vec<_> = lexed
            .literals
            .iter()
            .map(|l| (l.line, l.text.as_str()))
            .collect();
        assert_eq!(texts, [(1, "x // y"), (3, "q")]);
        assert_eq!(
            lex("fn f<'a>(x: &'a str) {}").code,
            "fn f<'a>(x: &'a str) {}"
        );
    }
}
