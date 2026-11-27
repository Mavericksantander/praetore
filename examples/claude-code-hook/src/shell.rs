//! Conservative lexical scan of a `Bash` tool command.
//!
//! The scan splits the command into simple-command segments on shell
//! operators and looks for a `git` word whose subcommand is `push` and for a
//! common network tool. It also collects the words that may name a path
//! (arguments, option values after `=`, redirection targets), which the hook
//! resolves against the project root. It never executes or expands anything.
//! Whatever it cannot reason about lexically (command substitution, process
//! substitution, heredocs, `eval`, a shell's `-c`, `xargs`, `env -S`, a
//! variable in command position or next to `push`, a git alias or git
//! configuration given inline or through the environment) makes the command
//! unanalyzable, which the policy denies. An unquoted word the shell expands
//! before running (a `$` expansion, a brace expansion `{a,b}`, a glob) has
//! an unknown value: it is unanalyzable in command position or as a git
//! subcommand, and counts as a path outside the root anywhere else (see
//! [`PathWord::dynamic`]). False positives such as `echo git push` or
//! `echo curl` are accepted.
//!
//! This is defense in depth, not a security boundary: a script, a Makefile,
//! an alias or function defined elsewhere, or an encoded payload decoded by
//! an allowed program does what the command text does not say.

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
    /// The shell expands it before running (a `$` expansion, or an unquoted
    /// brace expansion or glob): its value is unknown.
    pub dynamic: bool,
    /// The word in command position (a program run by path). The hook does
    /// not count a program outside the project, such as `/usr/bin/git`, as
    /// leaving the root.
    pub program: bool,
}

#[derive(Debug, Default)]
struct Word {
    text: String,
    /// Contains an unquoted or double-quoted `$` expansion, or an unquoted
    /// brace expansion or glob (see [`expands`]).
    dynamic: bool,
    /// The first word after a `<` or `>` redirection operator.
    redirect: bool,
    /// The characters written outside quotes and without a backslash: the
    /// ones the shell may expand.
    unquoted: String,
}

const SHELLS: [&str; 6] = ["sh", "bash", "zsh", "dash", "ksh", "fish"];
/// Environment variables that change what `git` runs for a subcommand: its
/// configuration (`GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_COUNT`/`_KEY_n`/
/// `_VALUE_n`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, ... all under the
/// `GIT_CONFIG` prefix), the repository whose configuration it reads, where
/// it finds its subcommand binaries, and the home and XDG directories whose
/// configuration files it loads. An alias set through any of them turns an
/// innocent subcommand into `push`. An assignment to one of them in a
/// segment that runs git is unanalyzable.
const GIT_ENVIRONMENT: [&str; 7] = [
    "GIT_CONFIG",
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_EXEC_PATH",
    "HOME",
    "XDG_CONFIG_HOME",
    "PATH",
];
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

/// Whether a shell argument makes the shell run a command string: `-c`
/// alone or in a group of short options (`-lc`, `-ec`, `-xvc`), or fish's
/// `--command`.
fn runs_a_string(argument: &str) -> bool {
    match argument.strip_prefix('-') {
        Some(long) if long.starts_with('-') => long == "-command" || long.starts_with("-command="),
        Some(short) => short.contains('c'),
        None => false,
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
        if SHELLS.contains(&name) && words[index + 1..].iter().any(|w| runs_a_string(&w.text)) {
            return Err("shell -c");
        }
        // `xargs` builds a command from its input; `env -S` splits one
        // argument into a command line. Neither is visible here.
        if name == "xargs" {
            return Err("xargs");
        }
        if name == "env" && words[index + 1..].iter().any(|w| splits_a_string(&w.text)) {
            return Err("env -S");
        }
    }
    // A segment that runs git with its configuration, repository, binaries
    // or home taken from an assignment (`GIT_CONFIG_PARAMETERS=... git p`,
    // `env HOME=/x git p`) may be running an alias.
    let runs_git = words.iter().any(|w| git_subcommand_of(&w.text).is_some());
    if runs_git
        && words.iter().any(|w| {
            is_assignment(&w.text)
                && w.text.split_once('=').is_some_and(|(name, _)| {
                    GIT_ENVIRONMENT
                        .iter()
                        .any(|v| name == *v || (*v == "GIT_CONFIG" && name.starts_with(v)))
                })
        })
    {
        return Err("git configuration from the environment");
    }
    let mut git_push = false;
    for (index, word) in words.iter().enumerate() {
        let Some(subcommand) = git_subcommand_of(&word.text) else {
            continue;
        };
        // `git-push` (the subcommand binary, run by name or by path).
        if let Some(subcommand) = subcommand {
            git_push |= subcommand == "push";
            continue;
        }
        let mut rest = words[index + 1..].iter();
        while let Some(next) = rest.next() {
            // An alias in any global option or its value: `-c alias.p=push`,
            // `--config-env=alias.p=VAR`, `--config-env alias.p=VAR`.
            if next.text.contains("alias.") {
                return Err("inline git alias");
            }
            if GIT_OPTIONS_WITH_VALUE.contains(&next.text.as_str()) {
                let value = rest.next().ok_or("git option without value")?;
                if value.text.contains("alias.") {
                    return Err("inline git alias");
                }
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

/// `Some(None)` for a word that runs `git`, `Some(Some(sub))` for a word that
/// runs the subcommand binary `git-<sub>` directly, `None` otherwise.
fn git_subcommand_of(word: &str) -> Option<Option<&str>> {
    let name = basename(word);
    if name == "git" {
        return Some(None);
    }
    name.strip_prefix("git-")
        .filter(|sub| !sub.is_empty())
        .map(Some)
}

/// Whether an `env` argument splits a string into a command line: `-S` alone
/// or in a group of short options, or `--split-string`.
fn splits_a_string(argument: &str) -> bool {
    match argument.strip_prefix('-') {
        Some(long) if long.starts_with('-') => {
            long == "-split-string" || long.starts_with("-split-string=")
        }
        Some(short) => short.contains('S'),
        None => false,
    }
}

/// Whether the shell expands the unquoted part of a word before running it:
/// a brace expansion (`{a,b}`, `{1..3}`) or a glob (`*`, `?`, `[...]`). A
/// lone `{}` (xargs, find) and a lone `[` (test) do not expand.
fn expands(unquoted: &str) -> bool {
    if unquoted.contains(['*', '?']) {
        return true;
    }
    let bracket = unquoted
        .split_once('[')
        .is_some_and(|(_, rest)| rest.contains(']'));
    let brace = unquoted
        .split_once('{')
        .and_then(|(_, rest)| rest.rsplit_once('}'))
        .is_some_and(|(inside, _)| inside.contains(',') || inside.contains(".."));
    bracket || brace
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
        if let Some(mut word) = word.take() {
            // What the shell would expand has an unknown value, like `$VAR`.
            word.dynamic |= expands(&word.unquoted);
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
            c => {
                let current = begin(&mut word, &mut redirect);
                current.text.push(c);
                current.unquoted.push(c);
            }
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
            "echo git push",
            // The subcommand binary, by name or by path.
            "git-push origin main",
            "/usr/libexec/git-core/git-push origin main",
            // A lone `[` (test) or `{}` (find) is not an expansion.
            "[ -f x ] && git push",
            "find . -name x -exec echo {} \\; ; git push",
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
            // git environment without git in the segment, and globs away
            // from git, are analyzable.
            "HOME=/tmp cargo test",
            "ls *.rs; git status",
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
            // `-c` grouped with other short options, and fish's long form.
            "bash -lc 'git push'",
            "sh -ec 'git push'",
            "bash -l -c 'git push'",
            "zsh -xvc 'git push'",
            "/bin/bash -cl 'git push'",
            "fish --command 'git push'",
            "fish --command='git push'",
            "eval git push",
            "cat <<EOF | sh\ngit push\nEOF",
            "diff <(git log) x",
            "git -c alias.p=push p",
            // An alias through the environment or --config-env.
            "GIT_CONFIG_PARAMETERS=\"'alias.p=push'\" git p",
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.p GIT_CONFIG_VALUE_0=push git p",
            "GIT_CONFIG_GLOBAL=/tmp/cfg git p",
            "HOME=/tmp git p",
            "XDG_CONFIG_HOME=/tmp git p",
            "GIT_DIR=/tmp/repo git p",
            "GIT_EXEC_PATH=/tmp git p",
            "PATH=/tmp:/usr/bin git p",
            "env HOME=/tmp git p",
            "X=push git --config-env=alias.p=X p",
            "X=push git --config-env alias.p=X p",
            // A command built by another program.
            "echo push | xargs git",
            "xargs -I {} git push",
            "env -S 'git push'",
            "env -iS 'git push'",
            "env --split-string='git push'",
            // Brace expansion and globs the shell resolves before running.
            "{git,push,origin,main}",
            "git pu{s,}sh",
            "git pu{s..s}h",
            "git pus?",
            "git pus[h]",
            "*it push",
            "echo 'unterminated",
            "trailing\\",
        ] {
            assert!(
                matches!(scan(command), Scan::Unanalyzable(_)),
                "{command:?} should be unanalyzable"
            );
        }
    }

    /// An unquoted brace expansion or glob has an unknown value, like `$VAR`:
    /// the hook then counts the word as leaving the root. Quoted or escaped,
    /// it is literal.
    #[test]
    fn brace_expansions_and_globs_are_dynamic_words() {
        let dynamic = |command: &str| -> Vec<(String, bool)> {
            analysis(command)
                .paths
                .into_iter()
                .map(|p| (p.text, p.dynamic))
                .collect()
        };
        assert_eq!(
            dynamic("rm -rf .cl{a,}ude"),
            [("rm".to_string(), false), (".cl{a,}ude".to_string(), true)]
        );
        assert_eq!(
            dynamic("cat .claud?/x *.rs src/[ab].rs"),
            [
                ("cat".to_string(), false),
                (".claud?/x".to_string(), true),
                ("*.rs".to_string(), true),
                ("src/[ab].rs".to_string(), true),
            ]
        );
        assert_eq!(
            dynamic("echo {1..3} '{a,b}' \"*\" \\*"),
            [
                ("echo".to_string(), false),
                ("{1..3}".to_string(), true),
                ("{a,b}".to_string(), false),
                ("*".to_string(), false),
                ("*".to_string(), false),
            ]
        );
        assert_eq!(
            dynamic("xargs_like -I {} [ ]"),
            [
                ("xargs_like".to_string(), false),
                ("{}".to_string(), false),
                ("[".to_string(), false),
                ("]".to_string(), false),
            ]
        );
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
            "ls | scp host:x",
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
