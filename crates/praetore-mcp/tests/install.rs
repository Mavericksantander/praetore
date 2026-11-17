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

// ---- Claude Code (`--client claude-code`) ----

const CC_USER: &str = include_str!("fixtures/claude_code_claude.json");
const CC_PROJECT: &str = include_str!("fixtures/claude_code_mcp.json");

/// Runs the binary with HOME and the working directory set, and without
/// `CLAUDE_CONFIG_DIR`.
fn run_in(args: &[&str], home: &Path, cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_praetore-mcp"))
        .args(args)
        .env("HOME", home)
        .env_remove("CLAUDE_CONFIG_DIR")
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A temp dir with an initialized praetore home; returns (temp, home dir).
fn cc_setup() -> (tempfile::TempDir, String) {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("praetore");
    let home_str = home.to_str().unwrap().to_owned();
    assert!(run(&["init", "--dir", &home_str]).status.success());
    (temp, home_str)
}

/// The text before and after the top-level `"mcpServers"` value, found by
/// the key line the fixtures use.
fn outside_user_servers(text: &str) -> (String, String) {
    let start = text
        .find("\n  \"mcpServers\": ")
        .expect("top-level mcpServers");
    let value = start + "\n  \"mcpServers\": ".len();
    let end = value + text[value..].find("\n  }").unwrap() + "\n  }".len();
    (text[..value].to_owned(), text[end..].to_owned())
}

fn cc_round_trip(fixture: &str, file_name: &str, wrapped: &[&str], remote: &[&str]) -> String {
    let (temp, home) = cc_setup();
    let config = temp.path().join(file_name);
    fs::write(&config, fixture).unwrap();
    let config_str = config.to_str().unwrap();
    let base = ["--client", "claude-code", "--config", config_str];

    // --dry-run lists everything and writes nothing.
    let mut args = vec!["install"];
    args.extend(base);
    args.extend(["--dir", home.as_str(), "--dry-run"]);
    let out = run(&args);
    assert!(out.status.success(), "{out:?}");
    let summary = text(&out.stdout);
    assert!(summary.contains("dry run: file not modified"), "{summary}");
    for name in wrapped {
        assert!(
            summary.contains(&format!("  ~ {name}\n")),
            "{name}: {summary}"
        );
    }
    for name in remote {
        assert!(
            summary.contains(&format!("  ! {name}: not wrapped (remote server)\n")),
            "{name}: {summary}"
        );
    }
    assert_eq!(fs::read_to_string(&config).unwrap(), fixture);
    assert!(backups(temp.path()).is_empty());

    // --yes applies, with a byte-identical backup.
    args.pop();
    args.push("--yes");
    let out = run(&args);
    assert!(out.status.success(), "{out:?}");
    let installed = fs::read_to_string(&config).unwrap();
    let doc = parse(&installed);
    let exe = fs::canonicalize(env!("CARGO_BIN_EXE_praetore-mcp")).unwrap();
    for name in wrapped {
        assert_eq!(
            doc["mcpServers"][name]["command"],
            exe.to_str().unwrap(),
            "{name}"
        );
    }
    for name in remote {
        assert_eq!(
            doc["mcpServers"][name],
            parse(fixture)["mcpServers"][name],
            "{name} left as is"
        );
    }
    let names = backups(temp.path());
    assert_eq!(names.len(), 1);
    assert_eq!(
        fs::read_to_string(temp.path().join(&names[0])).unwrap(),
        fixture
    );

    // Installing again changes nothing.
    let out = run(&args);
    assert!(out.status.success());
    assert!(text(&out.stdout).contains("nothing to change"));
    assert_eq!(fs::read_to_string(&config).unwrap(), installed);

    // Uninstall gives back the original file, byte for byte.
    let out = run(&[
        "uninstall",
        "--client",
        "claude-code",
        "--config",
        config_str,
        "--yes",
    ]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(fs::read_to_string(&config).unwrap(), fixture);
    installed
}

#[test]
fn claude_code_user_scope_install_uninstall_is_byte_identical() {
    let installed = cc_round_trip(
        CC_USER,
        ".claude.json",
        &["filesystem", "no-type"],
        &["sentry", "legacy", "events"],
    );
    // Only the user-scope mcpServers value changed.
    assert_eq!(
        outside_user_servers(&installed),
        outside_user_servers(CC_USER)
    );
}

#[test]
fn claude_code_project_scope_install_uninstall_is_byte_identical() {
    cc_round_trip(CC_PROJECT, ".mcp.json", &["repo-tools"], &["shared-api"]);
}

#[test]
fn claude_code_keeps_var_references_literal_in_args_and_env() {
    let (temp, home) = cc_setup();
    for (fixture, name) in [(CC_USER, ".claude.json"), (CC_PROJECT, ".mcp.json")] {
        let config = temp.path().join(name);
        fs::write(&config, fixture).unwrap();
        let out = run(&[
            "install",
            "--client",
            "claude-code",
            "--config",
            config.to_str().unwrap(),
            "--dir",
            &home,
            "--yes",
        ]);
        assert!(out.status.success(), "{out:?}");
    }
    let user = parse(&fs::read_to_string(temp.path().join(".claude.json")).unwrap());
    let fs_entry = &user["mcpServers"]["filesystem"];
    assert_eq!(fs_entry["type"], "stdio");
    assert_eq!(
        fs_entry["args"].as_array().unwrap().last().unwrap(),
        "${HOME}/projects"
    );
    assert_eq!(fs_entry["env"]["LOG_LEVEL"], "${LOG_LEVEL:-info}");
    let project = parse(&fs::read_to_string(temp.path().join(".mcp.json")).unwrap());
    let tools = &project["mcpServers"]["repo-tools"];
    assert_eq!(
        tools["args"].as_array().unwrap().last().unwrap(),
        "${CLAUDE_PROJECT_DIR:-.}/tools/mcp.js"
    );
    assert_eq!(tools["env"]["TOKEN"], "${REPO_TOKEN}");
    // The remote entry keeps its references too.
    assert_eq!(
        project["mcpServers"]["shared-api"]["headers"]["Authorization"],
        "Bearer ${API_KEY}"
    );
}

#[test]
fn claude_code_local_scope_servers_are_listed_and_end_with_a_warning() {
    let (temp, home) = cc_setup();
    let config = temp.path().join(".claude.json");
    fs::write(&config, CC_USER).unwrap();
    for extra in [&["--dry-run"][..], &["--yes"]] {
        let mut args = vec![
            "install",
            "--client",
            "claude-code",
            "--config",
            config.to_str().unwrap(),
            "--dir",
            &home,
        ];
        args.extend(extra);
        let out = run(&args);
        assert!(out.status.success(), "{out:?}");
        let stdout = text(&out.stdout);
        assert!(
            stdout
                .contains("  ! local-db: not wrapped (local scope, project /Users/me/work/api)\n"),
            "{stdout}"
        );
        let stderr = text(&out.stderr);
        assert!(
            stderr.trim_end().ends_with(
                "praetore-mcp: WARNING: 1 Claude Code local-scope server(s) listed above are NOT wrapped and are NOT governed by praetore-mcp. This version does not wrap local scope. To govern one, remove it (`claude mcp remove NAME --scope local`), add it again with `--scope user` or `--scope project`, and run install again."
            ),
            "{stderr}"
        );
    }
    // The local-scope entry itself is left as is.
    let installed = parse(&fs::read_to_string(&config).unwrap());
    assert_eq!(
        installed["projects"]["/Users/me/work/api"]["mcpServers"],
        parse(CC_USER)["projects"]["/Users/me/work/api"]["mcpServers"]
    );
}

#[test]
fn claude_code_a_local_entry_that_overrides_a_wrapped_user_entry_is_named() {
    let (temp, home) = cc_setup();
    let config = temp.path().join(".claude.json");
    let original = "{\n  \"projects\": {\n    \"/Users/me/site\": {\n      \"mcpServers\": {\n        \"filesystem\": {\n          \"command\": \"npx\",\n          \"args\": [\n            \"-y\",\n            \"@modelcontextprotocol/server-filesystem\",\n            \"/Users/me/site\"\n          ]\n        }\n      }\n    }\n  },\n  \"mcpServers\": {\n    \"filesystem\": {\n      \"type\": \"stdio\",\n      \"command\": \"npx\",\n      \"args\": [\n        \"-y\",\n        \"@modelcontextprotocol/server-filesystem\",\n        \"/tmp\"\n      ]\n    }\n  }\n}";
    fs::write(&config, original).unwrap();
    let out = run(&[
        "install",
        "--client",
        "claude-code",
        "--config",
        config.to_str().unwrap(),
        "--dir",
        &home,
        "--yes",
    ]);
    assert!(out.status.success(), "{out:?}");
    let stdout = text(&out.stdout);
    assert!(stdout.contains("  ~ filesystem\n"), "{stdout}");
    assert!(
        stdout.contains(
            "a local-scope entry named filesystem overrides the wrapped user-scope filesystem; that server is NOT governed"
        ),
        "{stdout}"
    );
    assert!(text(&out.stderr).contains("WARNING: 1 Claude Code local-scope server(s)"));
}

#[test]
fn claude_code_default_paths_alias_and_missing_servers_key() {
    let (temp, home) = cc_setup();
    let user_home = temp.path().join("user");
    let project = temp.path().join("project");
    fs::create_dir_all(&user_home).unwrap();
    fs::create_dir_all(&project).unwrap();
    // No mcpServers at all: install adds the key and nothing else.
    let original = "{\n  \"numStartups\": 3,\n  \"lastCost\": 0.0000123,\n  \"projects\": {}\n}";
    let claude_json = user_home.join(".claude.json");
    fs::write(&claude_json, original).unwrap();
    fs::write(project.join(".mcp.json"), CC_PROJECT).unwrap();
    let out = run_in(
        &["install", "--client", "cc", "--dir", &home, "--yes"],
        &user_home,
        &project,
    );
    assert!(out.status.success(), "{out:?}");
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("  + mcpServers (key created, empty)\n"),
        "{stdout}"
    );
    assert!(stdout.contains("  ~ repo-tools\n"), "{stdout}");
    let after = fs::read_to_string(&claude_json).unwrap();
    assert_eq!(
        after,
        "{\n  \"numStartups\": 3,\n  \"lastCost\": 0.0000123,\n  \"projects\": {},\n  \"mcpServers\": {}\n}"
    );
    // Byte for byte outside mcpServers: drop the added member and compare.
    assert_eq!(after.replace(",\n  \"mcpServers\": {}", ""), original);
    let project_doc = parse(&fs::read_to_string(project.join(".mcp.json")).unwrap());
    assert!(project_doc["mcpServers"]["repo-tools"]["args"][0] == "wrap");
}

#[test]
fn claude_code_creates_a_missing_claude_json_only_when_asked_by_name() {
    let (temp, home) = cc_setup();
    let user_home = temp.path().join("user");
    fs::create_dir_all(&user_home).unwrap();
    let claude_json = user_home.join(".claude.json");
    // Without --client, a missing ~/.claude.json is not created.
    let out = run_in(
        &["install", "--dir", &home, "--yes"],
        &user_home,
        &user_home,
    );
    assert!(out.status.success(), "{out:?}");
    assert!(!claude_json.exists());
    // --dry-run does not create it either.
    let out = run_in(
        &[
            "install",
            "--client",
            "claude-code",
            "--dir",
            &home,
            "--dry-run",
        ],
        &user_home,
        &user_home,
    );
    assert!(out.status.success(), "{out:?}");
    assert!(!claude_json.exists());
    let out = run_in(
        &[
            "install",
            "--client",
            "claude-code",
            "--dir",
            &home,
            "--yes",
        ],
        &user_home,
        &user_home,
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        fs::read_to_string(&claude_json).unwrap(),
        "{\n  \"mcpServers\": {}\n}\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&claude_json).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn claude_code_warns_that_claude_config_dir_is_ignored() {
    let (temp, home) = cc_setup();
    let config = temp.path().join(".claude.json");
    fs::write(&config, CC_PROJECT).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_praetore-mcp"))
        .args([
            "install",
            "--client",
            "claude-code",
            "--config",
            config.to_str().unwrap(),
            "--dir",
            &home,
            "--dry-run",
        ])
        .env("CLAUDE_CONFIG_DIR", temp.path().join("elsewhere"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(
        text(&out.stderr).contains("warning: CLAUDE_CONFIG_DIR is set and is ignored"),
        "{out:?}"
    );
    // Other clients do not mention it.
    let vscode = temp.path().join("mcp.json");
    fs::write(&vscode, "{\"servers\":{}}").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_praetore-mcp"))
        .args([
            "install",
            "--client",
            "vscode",
            "--config",
            vscode.to_str().unwrap(),
            "--dir",
            &home,
            "--dry-run",
        ])
        .env("CLAUDE_CONFIG_DIR", temp.path().join("elsewhere"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!text(&out.stderr).contains("CLAUDE_CONFIG_DIR"), "{out:?}");
}

#[test]
fn client_names_keep_claude_for_desktop_and_list_claude_code() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("c.json");
    fs::write(&config, "{\"mcpServers\":{}}").unwrap();
    for (name, shown) in [
        ("claude", "[claude-desktop]"),
        ("claude-code", "[claude-code]"),
        ("cc", "[claude-code]"),
    ] {
        let out = run(&[
            "uninstall",
            "--client",
            name,
            "--config",
            config.to_str().unwrap(),
            "--dry-run",
        ]);
        assert!(out.status.success(), "{name}: {out:?}");
        assert!(text(&out.stdout).starts_with(shown), "{name}: {out:?}");
    }
    let out = run(&["install", "--client", "claude-cli", "--dry-run"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(
        text(&out.stderr).contains(
            "unknown client \"claude-cli\" (claude-desktop, cursor, vscode, claude-code)"
        ),
        "{out:?}"
    );
}

/// Claude Code rewrites `~/.claude.json` while it runs. The file changes
/// after install read it and before the confirmation is answered: nothing
/// is written, no backup is left, and the message says to quit Claude Code.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn claude_code_a_file_changed_before_the_write_is_not_overwritten() {
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    let (temp, home) = cc_setup();
    let config = temp.path().join(".claude.json");
    fs::write(&config, CC_USER).unwrap();
    let (mut master_raw, mut slave_raw) = (-1, -1);
    let rc = unsafe {
        libc::openpty(
            &mut master_raw,
            &mut slave_raw,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    let master = unsafe { OwnedFd::from_raw_fd(master_raw) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave_raw) };
    let mut child = Command::new(env!("CARGO_BIN_EXE_praetore-mcp"))
        .args([
            "install",
            "--client",
            "claude-code",
            "--config",
            config.to_str().unwrap(),
            "--dir",
            &home,
        ])
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave))
        .spawn()
        .unwrap();
    let mut master = fs::File::from(master);
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    assert_eq!(
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
    let mut buf = Vec::new();
    let started = Instant::now();
    let mut answered = false;
    let rewritten = CC_USER.replace("\"numStartups\": 412", "\"numStartups\": 413");
    let status = loop {
        let mut chunk = [0u8; 4096];
        match master.read(&mut chunk) {
            Ok(0) => {}
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) if e.raw_os_error() == Some(libc::EIO) => {}
            Err(e) => panic!("read pty: {e}"),
        }
        if !answered && text(&buf).contains("Apply these changes") {
            // What a running Claude Code does between the read and the write.
            fs::write(&config, &rewritten).unwrap();
            master.write_all(b"y\n").unwrap();
            answered = true;
        }
        if let Some(status) = child.try_wait().unwrap() {
            // Drain what is left.
            std::thread::sleep(Duration::from_millis(50));
            while let Ok(n) = master.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "timed out: {}",
            text(&buf)
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = text(&buf);
    assert!(answered, "{output}");
    assert_eq!(status.code(), Some(1), "{output}");
    assert!(
        output.contains("changed while praetore-mcp was working; nothing was written. Claude Code rewrites this file while it runs: quit Claude Code and run the command again."),
        "{output}"
    );
    assert_eq!(fs::read_to_string(&config).unwrap(), rewritten);
    assert!(backups(temp.path()).is_empty());
}
