//! G7: a directory given to `praetore init` is shown escaped, so its name
//! cannot rewrite or fake the line it is printed in.

use std::{fs, process::Command};

/// A directory name that clears the terminal line, returns to its start,
/// begins a new one and reverses the text after it.
const EVIL: &str = "demo\x1b[2K\r\nfake\u{202e}";
/// `EVIL` as the CLI shows it.
const SHOWN: &str = "demo\\u{1b}[2K\\u{d}\\u{a}fake\\u{202e}";

#[test]
fn init_shows_the_directory_escaped() {
    let parent = std::env::temp_dir().join(format!(
        "praetore-cli-terminal-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&parent).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_praetore"))
        .arg("init")
        .arg(parent.join(EVIL))
        .output()
        .unwrap();
    fs::remove_dir_all(&parent).unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    // The "Initialized ... at" line is for reading (shown). The doctor
    // line is a command to copy: the path is one shell word.
    let quoted = praetore_core::shell::quote(&parent.join(EVIL).to_string_lossy());
    let initialized = stdout.contains(&format!("{SHOWN}\nHuman approver id:"));
    let doctor = stdout.contains(&format!("Then run: praetore doctor {quoted}"));
    assert!(initialized && doctor, "{stdout:?}");
    for raw in ['\x1b', '\r', '\u{202e}'] {
        assert!(!stdout.contains(raw), "raw {raw:?} in {stdout:?}");
    }
}
