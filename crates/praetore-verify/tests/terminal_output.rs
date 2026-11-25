//! G7: a path given on the command line is shown escaped in every message,
//! so a file name cannot rewrite or fake the line it is printed in.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// A file name that clears the terminal line, returns to its start, begins
/// a new one and reverses the text after it.
const EVIL: &str = "pin\x1b[2K\r\nfake\u{202e}";
/// `EVIL` as the verifier shows it.
const SHOWN: &str = "pin\\u{1b}[2K\\u{d}\\u{a}fake\\u{202e}";

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "praetore-verify-terminal-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/outcomes")
        .join(name)
}

/// The verifier's stderr for `args`, run in `dir`.
fn stderr(dir: &Path, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    String::from_utf8(output.stderr).unwrap()
}

fn assert_shown(stderr: &str) {
    assert!(stderr.contains(SHOWN), "{stderr:?}");
    for raw in ['\x1b', '\r', '\u{202e}'] {
        assert!(!stderr.contains(raw), "raw {raw:?} in {stderr:?}");
    }
}

#[test]
fn a_repeated_attester_pin_is_named_escaped() {
    let dir = Dir::new();
    fs::copy(fixture("attester-pin-1.hex"), dir.0.join(EVIL)).unwrap();
    fs::write(dir.0.join("journal.jsonl"), "").unwrap();
    let stderr = stderr(
        &dir.0,
        &[
            "journal",
            "--journal",
            "journal.jsonl",
            "--attester-pin",
            EVIL,
            "--attester-pin",
            EVIL,
        ],
    );
    assert!(stderr.contains("repeats a key"), "{stderr:?}");
    assert_shown(&stderr);
}

#[test]
fn a_repeated_execution_pin_is_named_escaped() {
    let dir = Dir::new();
    fs::copy(
        fixture("attester-pin-1.hex"),
        dir.0.join("attester-pin-1.hex"),
    )
    .unwrap();
    fs::copy(fixture("execution-pin-1.json"), dir.0.join(EVIL)).unwrap();
    fs::write(dir.0.join("journal.jsonl"), "").unwrap();
    let stderr = stderr(
        &dir.0,
        &[
            "outcomes",
            "--outcomes",
            "journal.jsonl",
            "--journal",
            "journal.jsonl",
            "--attester-pin",
            "attester-pin-1.hex",
            "--execution-pin",
            EVIL,
            "--execution-pin",
            EVIL,
        ],
    );
    assert!(stderr.contains("repeats a key or key id"), "{stderr:?}");
    assert_shown(&stderr);
}
