//! Default-deny `init`, the allow-all warnings, and `policy coverage`.

use praetore_core::{Policy, PolicyEffect, PolicyRule};
use praetore_mcp::store::{ACTION_TYPE, CAPABILITY, LEGACY_ALLOW_ALL_RULE};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const FILESYSTEM_TOOLS: [&str; 16] = [
    "read_file",
    "read_text_file",
    "read_media_file",
    "read_multiple_files",
    "write_file",
    "append_file",
    "edit_file",
    "create_directory",
    "list_directory",
    "list_directory_with_sizes",
    "directory_tree",
    "move_file",
    "copy_file",
    "search_files",
    "get_file_info",
    "list_allowed_directories",
];

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_praetore-mcp")
}

fn fake_server() -> PathBuf {
    let path = Path::new(bin())
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("fake_server{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.exists(),
        "{} missing: run via `cargo test` so examples are built",
        path.display()
    );
    path
}

fn run_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(bin());
    command
        .args(args)
        .stdin(Stdio::null())
        .env_remove("FAKE_SERVER_TOOLS")
        .env_remove("FAKE_SERVER_PAGE_SIZE")
        .env_remove("FAKE_SERVER_EXIT_AT_START");
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn run(args: &[&str]) -> Output {
    run_env(args, &[])
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn init() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let out = run(&["init", "--dir", home.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    (temp, home)
}

fn policy_of(home: &Path) -> Policy {
    Policy::from_json(&fs::read_to_string(home.join("policy.json")).unwrap()).unwrap()
}

/// Rewrites the policy as `init` wrote it up to 0.3.4: one allow-all rule.
fn write_legacy_policy(home: &Path) {
    let policy = Policy::new_v2(
        "praetore-mcp-default",
        1,
        vec![
            PolicyRule::new(LEGACY_ALLOW_ALL_RULE, ACTION_TYPE, PolicyEffect::Allow)
                .with_capability(CAPABILITY),
        ],
    )
    .with_mission_actions([ACTION_TYPE]);
    fs::write(
        home.join("policy.json"),
        serde_json::to_string_pretty(&policy).unwrap() + "\n",
    )
    .unwrap();
}

fn policy_cmd(home: &Path, args: &[&str]) {
    let mut all = vec!["policy"];
    all.extend_from_slice(args);
    all.extend(["--dir", home.to_str().unwrap()]);
    let out = run(&all);
    assert!(out.status.success(), "{all:?}: {out:?}");
}

/// The allow-all policy plus DENY rules per tool, as in a real setup that
/// left `copy_file` and `append_file` of server-filesystem 2.3.0 allowed.
fn legacy_with_tool_denies(home: &Path) {
    write_legacy_policy(home);
    for tool in ["write_file", "edit_file", "move_file", "create_directory"] {
        let id = format!("deny-{tool}");
        policy_cmd(
            home,
            &[
                "deny",
                "--id",
                &id,
                "--server",
                "filesystem",
                "--tool",
                tool,
            ],
        );
    }
}

fn coverage(home: &Path, server: Option<&str>, env: &[(&str, &str)]) -> Output {
    let fake = fake_server();
    let mut args = vec!["policy", "coverage", "--dir", home.to_str().unwrap()];
    if let Some(server) = server {
        args.extend(["--server", server]);
    }
    args.extend(["--", fake.to_str().unwrap()]);
    run_env(&args, env)
}

const FS_TOOLS_ENV: &[(&str, &str)] = &[("FAKE_SERVER_TOOLS", "filesystem-2.3.0")];

/// Every file under `root` with its bytes.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.insert(path.clone(), fs::read(&path).unwrap());
            }
        }
    }
    files
}

/// The coverage row of `tool`: its line split on runs of spaces.
fn row<'a>(text: &'a str, tool: &str) -> Vec<&'a str> {
    let line = text
        .lines()
        .find(|line| line.split_whitespace().next() == Some(tool))
        .unwrap_or_else(|| panic!("no row for {tool}:\n{text}"));
    line.split("  ")
        .map(str::trim)
        .filter(|cell| !cell.is_empty())
        .collect()
}

#[test]
fn init_writes_a_default_deny_policy_without_allow_all() {
    let (_temp, home) = init();
    let policy = policy_of(&home);
    assert!(policy.rules.is_empty(), "{:?}", policy.rules);
    assert!(
        !policy.rules.iter().any(praetore_mcp::policy::is_allow_all),
        "init wrote an allow-all rule"
    );
    let check = run(&["policy", "check", "--dir", home.to_str().unwrap()]);
    let report = stdout(&check);
    assert!(check.status.success(), "{report}");
    assert!(report.contains("no ALLOW rule"), "{report}");
    assert!(report.contains("policy allow"), "{report}");
}

#[test]
fn init_prints_how_to_allow_a_tool() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let out = run(&["init", "--dir", home.to_str().unwrap()]);
    let text = stdout(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("no rules: default deny"), "{text}");
    assert!(
        text.contains("praetore-mcp policy allow --id ID --server NAME --tool NAME"),
        "{text}"
    );
    assert!(!text.contains("warning"), "{text}");
}

#[test]
fn init_on_a_home_with_allow_all_warns_and_keeps_the_rule() {
    let (_temp, home) = init();
    legacy_with_tool_denies(&home);
    let before = fs::read(home.join("policy.json")).unwrap();
    let dir = home.to_str().unwrap();
    let out = run(&["init", "--dir", dir]);
    let text = stdout(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("already initialized"), "{text}");
    assert!(
        text.contains("warning") && text.contains(LEGACY_ALLOW_ALL_RULE),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "praetore-mcp policy remove --id {LEGACY_ALLOW_ALL_RULE} --dir {dir}"
        )),
        "{text}"
    );
    assert_eq!(
        fs::read(home.join("policy.json")).unwrap(),
        before,
        "init changed the policy"
    );
}

#[test]
fn coverage_lists_every_tool_with_its_decision() {
    let (_temp, home) = init();
    policy_cmd(
        &home,
        &[
            "allow",
            "--id",
            "allow-read",
            "--server",
            "filesystem",
            "--tool",
            "read_text_file",
        ],
    );
    policy_cmd(
        &home,
        &[
            "deny",
            "--id",
            "deny-write",
            "--server",
            "filesystem",
            "--tool",
            "write_file",
        ],
    );
    policy_cmd(
        &home,
        &[
            "require-approval",
            "--id",
            "approve-edit",
            "--server",
            "filesystem",
            "--tool",
            "edit_file",
            "--arg-path-prefix",
            "path=/srv/data",
        ],
    );
    let before = snapshot(&home);
    let out = coverage(&home, Some("filesystem"), FS_TOOLS_ENV);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{text}{out:?}");
    assert!(text.contains("server \"filesystem\": 16 tool(s)"), "{text}");
    for tool in FILESYSTEM_TOOLS {
        let cells = row(&text, tool);
        assert!(cells.len() >= 4, "{tool}: {cells:?}");
    }
    assert_eq!(
        row(&text, "read_text_file"),
        ["read_text_file", "ALLOW", "allow-read", "no"]
    );
    assert_eq!(
        row(&text, "write_file"),
        ["write_file", "DENY", "deny-write", "no"]
    );
    for tool in ["copy_file", "append_file", "read_file"] {
        assert_eq!(row(&text, tool), [tool, "DENY", "default deny", "no"]);
    }
    let edit = row(&text, "edit_file");
    assert_eq!(edit[..3], ["edit_file", "DENY", "default deny"], "{edit:?}");
    assert!(
        edit[3].starts_with("yes: approve-edit (REQUIRE_APPROVAL) when arguments.path PathPrefix"),
        "{edit:?}"
    );
    assert!(
        text.contains("no tool is allowed only by an allow-all rule"),
        "{text}"
    );
    assert_eq!(snapshot(&home), before, "coverage wrote under DIR");
}

#[test]
fn coverage_reads_every_page_of_tools_list() {
    let (_temp, home) = init();
    let out = coverage(
        &home,
        Some("filesystem"),
        &[
            ("FAKE_SERVER_TOOLS", "filesystem-2.3.0"),
            ("FAKE_SERVER_PAGE_SIZE", "5"),
        ],
    );
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{text}{out:?}");
    assert!(text.contains("16 tool(s)"), "{text}");
    for tool in FILESYSTEM_TOOLS {
        row(&text, tool);
    }
}

#[test]
fn coverage_exits_1_when_a_tool_is_allowed_only_by_allow_all() {
    let (_temp, home) = init();
    legacy_with_tool_denies(&home);
    let before = snapshot(&home);
    let out = coverage(&home, Some("filesystem"), FS_TOOLS_ENV);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(1), "{text}{out:?}");
    assert_eq!(
        row(&text, "write_file"),
        ["write_file", "DENY", "deny-write_file", "no"]
    );
    assert_eq!(
        row(&text, "copy_file"),
        ["copy_file", "ALLOW", LEGACY_ALLOW_ALL_RULE, "no"]
    );
    let section = text
        .split("allowed only by an allow-all rule (12):")
        .nth(1)
        .unwrap_or_else(|| panic!("no allow-all section:\n{text}"));
    for tool in ["copy_file", "append_file"] {
        assert!(
            section
                .lines()
                .any(|l| l.split_whitespace().next() == Some(tool)),
            "{tool} not listed:\n{section}"
        );
    }
    for tool in ["write_file", "edit_file", "move_file", "create_directory"] {
        assert!(
            !section
                .lines()
                .any(|l| l.split_whitespace().next() == Some(tool)),
            "{tool} listed:\n{section}"
        );
    }
    assert!(
        section.contains(&format!(
            "praetore-mcp policy remove --id {LEGACY_ALLOW_ALL_RULE}"
        )),
        "{section}"
    );
    assert_eq!(snapshot(&home), before, "coverage wrote under DIR");

    // A tool-specific ALLOW rule takes that tool off the list.
    policy_cmd(
        &home,
        &[
            "allow",
            "--id",
            "allow-copy",
            "--server",
            "filesystem",
            "--tool",
            "copy_file",
        ],
    );
    let text = stdout(&coverage(&home, Some("filesystem"), FS_TOOLS_ENV));
    assert!(
        text.contains("allowed only by an allow-all rule (11):"),
        "{text}"
    );
}

#[test]
fn coverage_uses_the_command_file_name_as_server_by_default() {
    let (_temp, home) = init();
    write_legacy_policy(&home);
    let out = coverage(&home, None, &[]);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(1), "{text}{out:?}");
    assert!(text.contains("server \"fake_server\": 2 tool(s)"), "{text}");
}

#[test]
fn coverage_exits_2_on_usage_errors_and_dead_servers() {
    let (_temp, home) = init();
    let dir = home.to_str().unwrap();
    let before = snapshot(&home);
    let silent = coverage(
        &home,
        Some("filesystem"),
        &[("FAKE_SERVER_EXIT_AT_START", "1")],
    );
    assert_eq!(silent.status.code(), Some(2), "{silent:?}");
    let stderr = String::from_utf8_lossy(&silent.stderr);
    assert!(
        stderr.contains("closed its output") && stderr.contains("exiting without answering"),
        "{stderr}"
    );
    let missing = run(&[
        "policy",
        "coverage",
        "--dir",
        dir,
        "--",
        "/nonexistent/praetore-mcp-test-server",
    ]);
    assert_eq!(missing.status.code(), Some(2), "{missing:?}");
    let no_command = run(&["policy", "coverage", "--dir", dir]);
    assert_eq!(no_command.status.code(), Some(2), "{no_command:?}");
    let bad_flag = run(&["policy", "coverage", "--dir", dir, "--tool", "x", "--", "x"]);
    assert_eq!(bad_flag.status.code(), Some(2), "{bad_flag:?}");
    assert_eq!(snapshot(&home), before, "coverage wrote under DIR");
}

#[test]
fn policy_check_warns_about_allow_all_with_tool_denies() {
    let (_temp, home) = init();
    let dir = home.to_str().unwrap();
    write_legacy_policy(&home);
    let alone = stdout(&run(&["policy", "check", "--dir", dir]));
    assert!(!alone.contains("allow-all rule"), "{alone}");
    assert!(alone.contains("0 warning(s)"), "{alone}");

    legacy_with_tool_denies(&home);
    let check = run(&["policy", "check", "--dir", dir]);
    let report = stdout(&check);
    assert!(check.status.success(), "{report}");
    let warning = report
        .lines()
        .find(|line| line.starts_with("warning: allow-all rule"))
        .unwrap_or_else(|| panic!("no allow-all warning:\n{report}"));
    assert!(warning.contains(LEGACY_ALLOW_ALL_RULE), "{warning}");
    assert!(
        warning.contains("every tool those rules do not name is ALLOWED"),
        "{warning}"
    );
    assert!(warning.contains("policy coverage"), "{warning}");
    assert!(
        warning.contains("write_file") && warning.contains("create_directory"),
        "{warning}"
    );
}

/// Runs one `echo` tools/call through `wrap` in `mode`; returns its stderr.
fn wrap_echo(home: &Path, mode: &str) -> String {
    use std::io::Write;
    let fake = fake_server();
    let mut child = Command::new(bin())
        .args([
            "wrap",
            "--dir",
            home.to_str().unwrap(),
            "--name",
            "fake",
            "--mode",
            mode,
            "--",
            fake.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let input = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hola"}}}"#,
    ]
    .join("\n")
        + "\n";
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(r#""id":2"#) && text.contains("delete_file"),
        "tools/list did not pass: {text}"
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn default_deny_blocks_in_enforce_and_observe_still_forwards() {
    let (_temp, home) = init();
    let observe = wrap_echo(&home, "observe");
    assert!(observe.contains("EXECUTED echo"), "{observe}");
    let enforce = wrap_echo(&home, "enforce");
    assert!(!enforce.contains("EXECUTED echo"), "{enforce}");
    let receipts = run(&["receipts", "--dir", home.to_str().unwrap()]);
    let table = stdout(&receipts);
    assert_eq!(table.matches("DENY").count(), 2, "{table}");

    policy_cmd(
        &home,
        &[
            "allow",
            "--id",
            "allow-echo",
            "--server",
            "fake",
            "--tool",
            "echo",
        ],
    );
    let allowed = wrap_echo(&home, "enforce");
    assert!(allowed.contains("EXECUTED echo"), "{allowed}");
}

#[test]
fn coverage_suggested_lines_run_as_printed() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("it's a home");
    let out = run(&["init", "--dir", home.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    policy_cmd(
        &home,
        &[
            "allow",
            "--id",
            "allow-read",
            "--server",
            "filesystem",
            "--tool",
            "read_text_file",
        ],
    );
    policy_cmd(
        &home,
        &[
            "require-approval",
            "--id",
            "approve-edit",
            "--server",
            "filesystem",
            "--tool",
            "edit_file",
            "--arg-path-prefix",
            "path=/srv/data",
        ],
    );
    let before = snapshot(&home);
    let out = coverage(&home, Some("filesystem"), FS_TOOLS_ENV);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "{text}{out:?}");
    assert_eq!(snapshot(&home), before, "coverage wrote under DIR");
    let section = text
        .split("denied because no rule names them (14).")
        .nth(1)
        .unwrap_or_else(|| panic!("no suggestion section:\n{text}"));
    let lines: Vec<&str> = section
        .lines()
        .filter(|l| l.starts_with("  praetore-mcp policy allow "))
        .collect();
    assert_eq!(lines.len(), 14, "{section}");
    for tool in ["read_text_file", "edit_file"] {
        assert!(!section.contains(&format!("--tool {tool} ")), "{section}");
    }
    let copy = lines
        .iter()
        .find(|l| l.contains("--tool copy_file "))
        .unwrap_or_else(|| panic!("no copy_file line:\n{section}"));

    // The line, as printed, through a POSIX shell.
    let line = copy.trim().replacen("praetore-mcp", "\"$PRAETORE_MCP\"", 1);
    let ran = Command::new("sh")
        .arg("-c")
        .arg(&line)
        .env("PRAETORE_MCP", bin())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(ran.status.success(), "{line}\n{ran:?}");
    let text = stdout(&coverage(&home, Some("filesystem"), FS_TOOLS_ENV));
    assert_eq!(
        row(&text, "copy_file"),
        ["copy_file", "ALLOW", "allow-filesystem-copy_file", "no"]
    );
    assert!(
        text.contains("denied because no rule names them (13)."),
        "{text}"
    );
}
