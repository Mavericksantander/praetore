//! Conservative lexical scan of a `Bash` tool command.
//!
//! The scan splits the command into simple-command segments on shell
//! operators and looks for a `git` word whose subcommand is `push` and for a
//! common network tool. It also collects the words that may name a path
//! (arguments, option values after `=`, redirection targets), which the hook
//! resolves against the project root. It never executes or expands anything.
//! Whatever it cannot reason about lexically (command substitution, process
//! substitution, heredocs, `eval`, a shell's `-c`, a variable in command
//! position or next to `push`, an inline git alias) makes the command
//! unanalyzable, which the policy treats as requiring approval. False
//! positives such as `echo git push` or `echo curl` are accepted.
//!
//! This is defense in depth, not a security boundary: a script, a Makefile,
//! an alias or function defined elsewhere, a glob, or an encoded payload
//! decoded by an allowed program does what the command text does not say.

#[derive(Debug, PartialEq, Eq)]
pub enum Scan {
    Analyzed(Analysis),
    Unanalyzable(&'static str),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Analysis {
    pub git_push: bool,
    /// A word names a common network tool (see [`NETWORK_TOOLS`]).
    pub network: bool,
    /// Words that may name a path, in order. The hook resolves them.
    pub paths: Vec<PathWord>,
}

/// A word that may name a path.
#[derive(Debug, PartialEq, Eq)]
pub struct PathWord {
    pub text: String,
    /// Contains a `$` expansion: its value is unknown.
    pub dynamic: bool,
    /// The word in command position (a program run by path). The hook does
    /// not count a program outside the project, such as `/usr/bin/git`, as
    /// leaving the root.
    pub program: bool,
}

#[derive(Debug, Default)]
struct Word {
    text: String,
    /// Contains an unquoted or double-quoted `$` expansion.
    dynamic: bool,
    /// The first word after a `<` or `>` redirection operator.
    redirect: bool,
}

const SHELLS: [&str; 6] = ["sh", "bash", "zsh", "dash", "ksh", "fish"];
/// Common programs that open network connections. Matched by basename on
/// any word, so `sudo curl` and `xargs wget` count too.
pub const NETWORK_TOOLS: [&str; 9] = [
    "curl", "wget", "nc", "ssh", "scp", "rsync", "ftp", "telnet", "socat",
];
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
    let mut analysis = Analysis::default();
    for words in &segments {
        match scan_segment(words) {
            Ok(push) => analysis.git_push |= push,
            Err(reason) => return Scan::Unanalyzable(reason),
        }
        collect(words, &mut analysis);
    }
    Scan::Analyzed(analysis)
}

/// Records network tools and the words of one segment that may name a path.
fn collect(words: &[Word], analysis: &mut Analysis) {
    let program = words
        .iter()
        .position(|w| !is_assignment(&w.text) && !w.redirect);
    for (index, word) in words.iter().enumerate() {
        analysis.network |= NETWORK_TOOLS.contains(&basename(&word.text));
        let mut push = |text: &str| {
            if !text.is_empty() {
                analysis.paths.push(PathWord {
                    text: text.to_string(),
                    dynamic: word.dynamic,
                    program: Some(index) == program,
                });
            }
        };
        // `--output=PATH`, `of=PATH`, `VAR=PATH`: the value may be a path.
        let value = word.text.split_once('=').map(|(_, value)| value);
        if word.text.starts_with('-') {
            if let Some(value) = value {
                push(value);
            }
            continue;
        }
        push(&word.text);
        if let Some(value) = value {
            push(value);
        }
    }
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
    // Set by `<` or `>`; marks the next word as a redirection target.
    let mut redirect = false;

    fn begin<'a>(word: &'a mut Option<Word>, redirect: &mut bool) -> &'a mut Word {
        word.get_or_insert_with(|| Word {
            redirect: std::mem::take(redirect),
            ..Word::default()
        })
    }

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
                let current = begin(&mut word, &mut redirect);
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => current.text.push(c),
                        None => return Err("unterminated single quote"),
                    }
                }
            }
            '"' => {
                let current = begin(&mut word, &mut redirect);
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
                Some(c) => begin(&mut word, &mut redirect).text.push(c),
                None => return Err("trailing backslash"),
            },
            '`' => return Err("command substitution"),
            '$' => {
                if chars.peek() == Some(&'(') {
                    return Err("command substitution");
                }
                let current = begin(&mut word, &mut redirect);
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
                redirect = false;
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
                redirect = true;
            }
            ';' | '&' | '|' | '\n' | '(' | ')' => {
                finish(&mut word, &mut segments);
                segments.push(Vec::new());
                redirect = false;
            }
            c if c.is_whitespace() => finish(&mut word, &mut segments),
            c => begin(&mut word, &mut redirect).text.push(c),
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
            Scan::Analyzed(analysis) => analysis.git_push,
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

    fn analysis(command: &str) -> Analysis {
        match scan(command) {
            Scan::Analyzed(analysis) => analysis,
            Scan::Unanalyzable(reason) => panic!("{command:?} unanalyzable: {reason}"),
        }
    }

    #[test]
    fn finds_network_tools_by_basename_on_any_word() {
        for command in [
            "curl https://x.test",
            "cd x && wget -q https://x.test",
            "sudo /usr/bin/nc host 80",
            "ls | xargs scp host:x",
            "ssh host",
            "rsync -a . host:x",
            "echo curl",
        ] {
            assert!(analysis(command).network, "{command:?}");
        }
        for command in ["cargo test curl_parsing", "git status", "ls curlx"] {
            assert!(!analysis(command).network, "{command:?}");
        }
    }

    #[test]
    fn collects_arguments_option_values_and_redirection_targets() {
        let paths = |command: &str| -> Vec<(String, bool)> {
            analysis(command)
                .paths
                .into_iter()
                .map(|p| (p.text, p.program))
                .collect()
        };
        assert_eq!(
            paths("echo x >> .git/config"),
            [
                ("echo".to_string(), true),
                ("x".to_string(), false),
                (".git/config".to_string(), false)
            ]
        );
        assert_eq!(
            paths("cmd --out=/a/b of=c -q"),
            [
                ("cmd".to_string(), true),
                ("/a/b".to_string(), false),
                ("of=c".to_string(), false),
                ("c".to_string(), false)
            ]
        );
        // The redirection target is not taken for the program.
        assert_eq!(paths("> '.claude/x'"), [(".claude/x".to_string(), false)]);
        assert!(analysis("cat $HOME/x").paths.iter().any(|p| p.dynamic));
    }
}
