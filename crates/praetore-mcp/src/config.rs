//! Optional `DIR/config.toml`: whether session reports are written, and the
//! approval window. Neither changes the outcome a rule gives a call (ALLOW,
//! DENY or REQUIRE_APPROVAL), but `approval_ttl_seconds` decides how long a
//! held call can still be approved, and so whether a later matching call
//! runs. tests/evasion.rs
//! `config_toml_changes_no_rule_outcome_only_the_approval_window` pins both.
//!
//! The file is a flat list of `key = value` lines (a TOML subset; `#` starts
//! a comment). The keys are `report` and `approval_ttl_seconds`:
//!
//! ```toml
//! report = false   # do not write session reports under DIR/reports/
//! approval_ttl_seconds = 1800   # pending approvals last 30 minutes
//! ```
//!
//! A missing file means the defaults. For `report`, a line that cannot be
//! read is a warning and is skipped, so a typo there never stops `wrap`.
//! `approval_ttl_seconds` is read strictly by [`approval_ttl_seconds`]: an
//! unreadable file, a malformed or repeated key is an error, and `wrap`
//! refuses to start on it.

use crate::shown::Show;
use crate::store::Home;
use std::{fs, io, path::PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Write the session report when `wrap` ends.
    pub report: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self { report: true }
    }
}

pub fn path(home: &Home) -> PathBuf {
    home.root.join("config.toml")
}

/// The key of the approval TTL in `config.toml`.
pub const APPROVAL_TTL_KEY: &str = "approval_ttl_seconds";

/// A key as written, without the quotes TOML allows around it
/// (`"key"` or `'key'`).
fn unquoted(key: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = key
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner;
        }
    }
    key
}

/// The raw `approval_ttl_seconds` value of `config.toml`, or `None` when the
/// file or the key is absent. Unlike [`load`], this fails on a file that
/// cannot be read or starts with a byte order mark, on a line naming the key
/// without `= value` (`key: value` included), and on the
/// key given twice: an approval window must never fall back to a default
/// the user did not choose. The range is checked by the caller.
pub fn approval_ttl_seconds(home: &Home) -> Result<Option<String>, String> {
    let path = path(home);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot read {}: {error}", path.shown())),
    };
    // A byte order mark is not part of the first key. Read as text it would
    // hide that key, and the default would apply without a word.
    if text.starts_with('\u{feff}') {
        return Err(format!(
            "{} starts with a byte order mark (U+FEFF); save it as UTF-8 without one",
            path.shown()
        ));
    }
    let mut found: Option<(usize, String)> = None;
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        let at = index + 1;
        // A line whose first word (up to white space, `=` or `:`) is the key
        // is about the TTL: anything but `key = value` is an error.
        let first = line
            .split(|c: char| c.is_whitespace() || c == '=' || c == ':')
            .next()
            .unwrap_or_default();
        if unquoted(first) != APPROVAL_TTL_KEY {
            continue;
        }
        let value = line
            .split_once('=')
            .filter(|(key, _)| unquoted(key.trim()) == APPROVAL_TTL_KEY)
            .map(|(_, value)| value.trim());
        let Some(value) = value else {
            return Err(format!(
                "{} line {at}: expected `{APPROVAL_TTL_KEY} = <seconds>`",
                path.shown()
            ));
        };
        if let Some((first, _)) = found {
            return Err(format!(
                "{} line {at}: {APPROVAL_TTL_KEY} is already set on line {first}",
                path.shown()
            ));
        }
        found = Some((at, value.to_owned()));
    }
    Ok(found.map(|(_, value)| value))
}

/// The config of `home` and the warnings found while reading it.
pub fn load(home: &Home) -> (Config, Vec<String>) {
    let path = path(home);
    match fs::read_to_string(&path) {
        Ok(text) => {
            let (config, problems) = parse(&text);
            let warnings = problems
                .into_iter()
                .map(|problem| format!("{}: {problem}", path.shown()))
                .collect();
            (config, warnings)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (Config::default(), Vec::new()),
        Err(error) => (
            Config::default(),
            vec![format!(
                "cannot read {}: {error}; using the defaults",
                path.shown()
            )],
        ),
    }
}

pub fn parse(text: &str) -> (Config, Vec<String>) {
    let mut config = Config::default();
    let mut problems = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let at = index + 1;
        let Some((key, value)) = line.split_once('=') else {
            problems.push(format!("line {at}: expected `key = value`; ignored"));
            continue;
        };
        match (unquoted(key.trim()), value.trim()) {
            ("report", "true") => config.report = true,
            ("report", "false") => config.report = false,
            ("report", other) => problems.push(format!(
                "line {at}: report must be true or false, got {other:?}; ignored"
            )),
            // Checked strictly by `approval_ttl_seconds`.
            (APPROVAL_TTL_KEY, _) => {}
            (other, _) => problems.push(format!("line {at}: unknown key {other:?}; ignored")),
        }
    }
    (config, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_defaults_to_on_and_can_be_turned_off() {
        assert!(parse("").0.report);
        assert!(parse("# nothing\n").0.report);
        let (config, problems) = parse("report = false # quiet\n");
        assert!(!config.report);
        assert!(problems.is_empty());
        assert!(parse("report=true").0.report);
    }

    #[test]
    fn unreadable_lines_are_warnings_and_keep_the_default() {
        let (config, problems) = parse("report = no\nother = 1\nnonsense\n");
        assert!(config.report);
        assert_eq!(problems.len(), 3);
        assert!(problems[0].contains("line 1"));
        assert!(problems[1].contains("unknown key"));
    }

    #[test]
    fn approval_ttl_is_read_strictly() {
        let temp = tempfile::tempdir().unwrap();
        let home = Home::new(temp.path().to_path_buf());
        assert_eq!(approval_ttl_seconds(&home), Ok(None));
        let write = |text: &str| fs::write(path(&home), text).unwrap();
        write("report = false\n");
        assert_eq!(approval_ttl_seconds(&home), Ok(None));
        write("report = false\napproval_ttl_seconds = 1800 # half an hour\n");
        assert_eq!(approval_ttl_seconds(&home), Ok(Some("1800".into())));
        assert!(parse("approval_ttl_seconds = 1800").1.is_empty());
        for (text, says) in [
            ("approval_ttl_seconds 1800\n", "line 1: expected"),
            ("approval_ttl_seconds\t1800\n", "line 1: expected"),
            ("approval_ttl_seconds\n", "line 1: expected"),
            ("approval_ttl_seconds: 90000\n", "line 1: expected"),
            ("approval_ttl_seconds:90000\n", "line 1: expected"),
            ("\u{feff}approval_ttl_seconds = 1800\n", "byte order mark"),
            ("\u{feff}report = false\n", "byte order mark"),
            (
                "approval_ttl_seconds = 1\napproval_ttl_seconds = 2\n",
                "already set on line 1",
            ),
        ] {
            write(text);
            let error = approval_ttl_seconds(&home).unwrap_err();
            assert!(error.contains(says), "{text:?}: {error}");
        }
        // m3: a quoted key (TOML allows it) is the key, never a warning.
        for text in [
            "\"approval_ttl_seconds\" = 1800\n",
            "'approval_ttl_seconds' = 1800\n",
        ] {
            write(text);
            assert_eq!(
                approval_ttl_seconds(&home),
                Ok(Some("1800".into())),
                "{text:?}"
            );
            assert!(parse(text).1.is_empty(), "{text:?}: {:?}", parse(text).1);
        }
        write("\"approval_ttl_seconds\"\t1800\n");
        assert!(approval_ttl_seconds(&home).is_err());
        // A key that only starts like it is another key.
        write("approval_ttl_seconds_x = 1\n");
        assert_eq!(approval_ttl_seconds(&home), Ok(None));
    }
}
