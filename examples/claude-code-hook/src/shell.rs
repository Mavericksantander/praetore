//! Conservative scan of a `Bash` tool command for `git push`.
//!
//! The scan splits the command into simple-command segments on shell
//! operators and looks for a `git` word whose subcommand is `push`. It never
//! executes or expands anything. Whatever it cannot reason about lexically
//! (command substitution, process substitution, heredocs, `eval`, a shell's
//! `-c`, a variable in command position or next to `push`, an inline git
//! alias) makes the command unanalyzable, which the policy denies. False
//! positives such as `echo git push` are accepted.

#[derive(Debug, PartialEq, Eq)]
pub enum Scan {
    Analyzed { git_push: bool },
    Unanalyzable(&'static str),
}

#[derive(Debug, Default)]
struct Word {
    text: String,
    /// Contains an unquoted or double-quoted `$` expansion.
    dynamic: bool,
}

const SHELLS: [&str; 6] = ["sh", "bash", "zsh", "dash", "ksh", "fish"];
/// git global options that take a separate value.
const GIT_OPTIONS_WITH_VALUE: [&str; 6] = [
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
];

pub fn scan(command: &str) -> Scan {
    let segments = match split(command) {
        Ok(segments) => segments,
        Err(reason) => return Scan::Unanalyzable(reason),
    };
    let mut git_push = false;
    for words in &segments {
        match scan_segment(words) {
            Ok(push) => git_push |= push,
            Err(reason) => return Scan::Unanalyzable(reason),
        }
    }
    Scan::Analyzed { git_push }
}

fn scan_segment(words: &[Word]) -> Result<bool, &'static str> {
    let command_word = words.iter().find(|w| !is_assignment(&w.text));
    let Some(command_word) = command_word else {
        return Ok(false);
    };
    if command_word.dynamic {
        return Err("variable in command position");
    }
    if words.iter().any(|w| w.dynamic) && words.iter().any(|w| w.text == "push") {
        return Err("variable expansion next to push");
    }
    for (index, word) in words.iter().enumerate() {
        let name = basename(&word.text);
        if name == "eval" {
            return Err("eval");
        }
        if SHELLS.contains(&name) && words[index + 1..].iter().any(|w| w.text.starts_with("-c")) {
            return Err("shell -c");
        }
    }
    let mut git_push = false;
    for (index, word) in words.iter().enumerate() {
        if basename(&word.text) != "git" {
            continue;
        }
        let mut rest = words[index + 1..].iter();
        while let Some(next) = rest.next() {
            if GIT_OPTIONS_WITH_VALUE.contains(&next.text.as_str()) {
                let value = rest.next().ok_or("git option without value")?;
                if next.text == "-c" && value.text.contains("alias.") {
                    return Err("inline git alias");
                }
            } else if next.text.starts_with("-c") && next.text.contains("alias.") {
                return Err("inline git alias");
            } else if next.text.starts_with('-') {
                continue;
            } else {
                if next.dynamic {
                    return Err("variable as git subcommand");
                }
                git_push |= next.text == "push";
                break;
            }
        }
    }
    Ok(git_push)
}

/// Splits a command into segments of words. Quotes and backslashes are
/// removed; operators (`;`, `&`, `|`, newline, parentheses, redirections) end
/// a segment.
fn split(command: &str) -> Result<Vec<Vec<Word>>, &'static str> {
    let mut segments = vec![Vec::new()];
    let mut word: Option<Word> = None;
    let mut chars = command.chars().peekable();

    fn finish(word: &mut Option<Word>, segments: &mut [Vec<Word>]) {
        if let Some(word) = word.take() {
            segments
                .last_mut()
                .expect("at least one segment")
                .push(word);
        }
    }

    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                let current = word.get_or_insert_with(Word::default);
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => current.text.push(c),
                        None => return Err("unterminated single quote"),
                    }
                }
            }
            '"' => {
                let current = word.get_or_insert_with(Word::default);
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(c) => current.text.push(c),
                            None => return Err("unterminated double quote"),
                        },
                        Some('`') => return Err("command substitution"),
                        Some('$') => {
                            if chars.peek() == Some(&'(') {
                                return Err("command substitution");
                            }
                            current.dynamic = true;
                            current.text.push('$');
                        }
                        Some(c) => current.text.push(c),
                        None => return Err("unterminated double quote"),
                    }
                }
            }
            '\\' => match chars.next() {
                Some('\n') => {}
                Some(c) => word.get_or_insert_with(Word::default).text.push(c),
                None => return Err("trailing backslash"),
            },
            '`' => return Err("command substitution"),
            '$' => {
                if chars.peek() == Some(&'(') {
                    return Err("command substitution");
                }
                let current = word.get_or_insert_with(Word::default);
                current.dynamic = true;
                current.text.push('$');
            }
            '#' if word.is_none() => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
                finish(&mut word, &mut segments);
                segments.push(Vec::new());
            }
            '<' | '>' => {
                if chars.peek() == Some(&'(') {
                    return Err("process substitution");
                }
                if c == '<' && chars.peek() == Some(&'<') {
                    return Err("heredoc");
                }
                finish(&mut word, &mut segments);
                segments.push(Vec::new());
            }
            ';' | '&' | '|' | '\n' | '(' | ')' => {
                finish(&mut word, &mut segments);
                segments.push(Vec::new());
            }
            c if c.is_whitespace() => finish(&mut word, &mut segments),
            c => word.get_or_insert_with(Word::default).text.push(c),
        }
    }
    finish(&mut word, &mut segments);
    segments.retain(|segment| !segment.is_empty());
    Ok(segments)
}

fn is_assignment(word: &str) -> bool {
    match word.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push(command: &str) -> bool {
        match scan(command) {
            Scan::Analyzed { git_push } => git_push,
            Scan::Unanalyzable(reason) => panic!("{command:?} unanalyzable: {reason}"),
        }
    }

    #[test]
    fn finds_git_push_behind_operators_wrappers_and_options() {
        for command in [
            "git push",
            "cd x && git push",
            "cd x; git push origin main",
            "true || git push",
            "ls | git push",
            "(git push)",
            "cargo test\ngit push",
            "FOO=1 git push",
            "sudo git push",
            "env GIT_TRACE=1 git push",
            "/usr/bin/git push",
            "git -C ../repo push",
            "git -c core.x=1 --no-pager push",
            "git --git-dir .git push",
            "'git' push",
            "g\\it pu\\sh",
            "\"git\" \"push\"",
            "git push > out.log 2>&1",
            "xargs -I {} git push",
            "echo git push",
        ] {
            assert!(push(command), "{command:?} should be detected");
        }
    }

    #[test]
    fn leaves_other_commands_alone() {
        for command in [
            "cargo test",
            "git status && git log --oneline",
            "git commit -m 'git push later'",
            "echo \"git push\"",
            "git pushx",
            "ls # git push",
            "git -C push status",
            "echo $HOME",
        ] {
            assert!(!push(command), "{command:?} should not be detected");
        }
    }

    #[test]
    fn unanalyzable_commands_are_reported() {
        for command in [
            "$(echo git) push",
            "`echo git` push",
            "echo \"$(git push)\"",
            "$GIT push",
            "git $SUB",
            "sudo $G push",
            "bash -c 'git push'",
            "sh -c \"git push\"",
            "eval git push",
            "cat <<EOF | sh\ngit push\nEOF",
            "diff <(git log) x",
            "git -c alias.p=push p",
            "echo 'unterminated",
            "trailing\\",
        ] {
            assert!(
                matches!(scan(command), Scan::Unanalyzable(_)),
                "{command:?} should be unanalyzable"
            );
        }
    }
}
