//! Optional `DIR/config.toml`: settings that never affect a policy decision.
//!
//! The file is a flat list of `key = value` lines (a TOML subset; `#` starts
//! a comment). The only key is `report`:
//!
//! ```toml
//! report = false   # do not write session reports under DIR/reports/
//! ```
//!
//! A missing file means the defaults. A line that cannot be read is reported
//! as a warning and skipped, so a typo here never stops `wrap`.

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

/// The config of `home` and the warnings found while reading it.
pub fn load(home: &Home) -> (Config, Vec<String>) {
    let path = path(home);
    match fs::read_to_string(&path) {
        Ok(text) => {
            let (config, problems) = parse(&text);
            let warnings = problems
                .into_iter()
                .map(|problem| format!("{}: {problem}", path.display()))
                .collect();
            (config, warnings)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (Config::default(), Vec::new()),
        Err(error) => (
            Config::default(),
            vec![format!(
                "cannot read {}: {error}; using the defaults",
                path.display()
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
        match (key.trim(), value.trim()) {
            ("report", "true") => config.report = true,
            ("report", "false") => config.report = false,
            ("report", other) => problems.push(format!(
                "line {at}: report must be true or false, got {other:?}; ignored"
            )),
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
}
