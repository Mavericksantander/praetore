//! `install` / `uninstall` against fixture configs through the real binary.

use std::{
    fs,
    path::Path,
    process::{Command, Output, Stdio},
};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_praetore-mcp"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn parse(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap()
}

fn backups(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".praetore-backup-"))
        .collect()
}

fn round_trip(fixture: &str, client: &str, file_name: &str, expected_wrapped: usize) {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let home_str = home.to_str().unwrap();
    assert!(run(&["init", "--dir", home_str]).status.success());
    let config = temp.path().join(file_name);
    let original = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(fixture)).unwrap();
    fs::write(&config, &original).unwrap();
    let config_str = config.to_str().unwrap();
    let base = ["--client", client, "--config", config_str];

    // --dry-run changes nothing.
    let mut args = vec!["install"];
    args.extend(base);
    args.extend(["--dir", home_str, "--dry-run"]);
    let out = run(&args);
    assert!(out.status.success(), "{out:?}");
    let summary = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        summary.matches("    + ").count(),
        expected_wrapped,
        "{summary}"
    );
    assert!(summary.contains("dry run"));
    assert_eq!(fs::read_to_string(&config).unwrap(), original);

    // Without --yes and without a terminal, nothing is modified.
    let mut args = vec!["install"];
    args.extend(base);
    args.extend(["--dir", home_str]);
    let out = run(&args);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(fs::read_to_string(&config).unwrap(), original);
    assert!(backups(temp.path()).is_empty());

    // --yes applies, with a byte-identical backup next to the file.
    args.push("--yes");
    let out = run(&args);
    assert!(out.status.success(), "{out:?}");
    let installed = fs::read_to_string(&config).unwrap();
    assert_ne!(installed, original);
    let wrapped = parse(&installed);
    let exe = fs::canonicalize(env!("CARGO_BIN_EXE_praetore-mcp")).unwrap();
    let servers = wrapped
        .as_object()
        .unwrap()
        .values()
        .find_map(|v| v.as_object().filter(|o| o.values().all(|s| s.is_object())))
        .unwrap();
    let wrapped_count = servers
        .values()
        .filter(|s| s["command"] == exe.to_str().unwrap())
        .count();
    assert_eq!(wrapped_count, expected_wrapped);
    let backup_names = backups(temp.path());
    assert_eq!(backup_names.len(), 1);
    assert_eq!(
        fs::read_to_string(temp.path().join(&backup_names[0])).unwrap(),
        original
    );

    // Installing again is a no-op.
    let out = run(&args);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("nothing to change"));
    assert_eq!(fs::read_to_string(&config).unwrap(), installed);

    // Uninstall restores the original entries exactly.
    let mut args = vec!["uninstall"];
    args.extend(base);
    args.push("--yes");
    let out = run(&args);
    assert!(out.status.success(), "{out:?}");
    let restored = fs::read_to_string(&config).unwrap();
    assert_eq!(parse(&restored), parse(&original));
}

#[test]
fn claude_desktop_install_uninstall_round_trip() {
    round_trip(
        "tests/fixtures/claude_desktop_config.json",
        "claude-desktop",
        "claude_desktop_config.json",
        2,
    );
}

#[test]
fn cursor_install_uninstall_round_trip() {
    round_trip("tests/fixtures/cursor_mcp.json", "cursor", "mcp.json", 2);
}

#[test]
fn vscode_install_uninstall_round_trip() {
    round_trip("tests/fixtures/vscode_mcp.json", "vscode", "mcp.json", 1);
}

#[test]
fn refuses_jsonc_without_modifying() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    assert!(
        run(&["init", "--dir", home.to_str().unwrap()])
            .status
            .success()
    );
    let config = temp.path().join("mcp.json");
    let text = "{\n  // comment\n  \"servers\": {}\n}\n";
    fs::write(&config, text).unwrap();
    let out = run(&[
        "install",
        "--client",
        "vscode",
        "--config",
        config.to_str().unwrap(),
        "--dir",
        home.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not strict JSON"));
    assert_eq!(fs::read_to_string(&config).unwrap(), text);
}
