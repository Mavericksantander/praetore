//! `praetore-mcp policy ...` command-line behavior.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_praetore-mcp"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn init() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    assert!(
        run(&["init", "--dir", home.to_str().unwrap()])
            .status
            .success()
    );
    (temp, home)
}

fn backups(home: &Path) -> usize {
    fs::read_dir(home)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .contains(".praetore-backup-")
        })
        .count()
}

fn with_dir<'a>(args: &[&'a str], dir: &'a str) -> Vec<&'a str> {
    let mut all = args.to_vec();
    all.extend(["--dir", dir]);
    all
}

#[test]
fn invalid_input_never_writes() {
    let (_temp, home) = init();
    let dir = home.to_str().unwrap();
    let policy = home.join("policy.json");
    let before = fs::read(&policy).unwrap();
    let bad: &[&[&str]] = &[
        // duplicate id
        &[
            "policy",
            "deny",
            "--id",
            "allow-all-mcp-tool-calls",
            "--tool",
            "x",
        ],
        // argument condition without a tool/server selector
        &["policy", "deny", "--id", "a", "--arg-exact", "path=/etc"],
        // no selector at all
        &["policy", "deny", "--id", "b"],
        // relative path prefix (rejected by core validation)
        &[
            "policy",
            "deny",
            "--id",
            "c",
            "--tool",
            "t",
            "--arg-path-prefix",
            "path=etc/x",
        ],
        // malformed KEY=VALUE
        &[
            "policy",
            "deny",
            "--id",
            "d",
            "--tool",
            "t",
            "--arg-exact",
            "novalue",
        ],
        // missing --id, unknown flag, unknown effect
        &["policy", "deny", "--tool", "t"],
        &["policy", "deny", "--id", "e", "--tool", "t", "--value", "x"],
        &["policy", "block", "--id", "f", "--tool", "t"],
        // blank id and blank server
        &["policy", "deny", "--id", " ", "--tool", "t"],
        &["policy", "deny", "--id", "g", "--server", " "],
        // remove a rule that does not exist
        &["policy", "remove", "--id", "nope"],
    ];
    for args in bad {
        let out = run(&with_dir(args, dir));
        assert!(!out.status.success(), "{args:?} should fail: {out:?}");
        assert_eq!(
            fs::read(&policy).unwrap(),
            before,
            "{args:?} modified the policy"
        );
    }
    assert_eq!(backups(&home), 0);
}

#[test]
fn add_list_remove_with_backups() {
    let (_temp, home) = init();
    let dir = home.to_str().unwrap();
    let out = run(&with_dir(
        &[
            "policy",
            "deny",
            "--id",
            "deny-rm",
            "--tool",
            "run_shell",
            "--arg-prefix",
            "cmd=rm ",
            "--arg-exact",
            "force=true",
        ],
        dir,
    ));
    assert!(out.status.success(), "{out:?}");
    assert_eq!(backups(&home), 1);
    let policy: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home.join("policy.json")).unwrap()).unwrap();
    let rule = &policy["rules"][1];
    assert_eq!(rule["required_capability"], "mcp:tools/call");
    assert_eq!(rule["parameter_conditions"][2]["expected"], true);
    assert_eq!(policy["version"], 2);

    let list = run(&with_dir(&["policy", "list"], dir));
    let text = String::from_utf8_lossy(&list.stdout);
    assert!(list.status.success());
    assert!(
        text.contains("deny-rm")
            && text.contains("run_shell")
            && text.contains("arguments.cmd Prefix \"rm \""),
        "{text}"
    );
    assert!(text.contains("restart your MCP client"));

    let out = run(&with_dir(&["policy", "remove", "--id", "deny-rm"], dir));
    assert!(out.status.success(), "{out:?}");
    assert_eq!(backups(&home), 2);
    let list = run(&with_dir(&["policy", "list"], dir));
    assert!(!String::from_utf8_lossy(&list.stdout).contains("deny-rm"));
}

#[test]
fn any_tool_allows_explicitly_unscoped_rules() {
    let (_temp, home) = init();
    let out = run(&with_dir(
        &[
            "policy",
            "deny",
            "--id",
            "no-ssh",
            "--arg-path-prefix",
            "path=/home/u/.ssh",
            "--any-tool",
        ],
        home.to_str().unwrap(),
    ));
    assert!(out.status.success(), "{out:?}");
    let check = run(&with_dir(&["policy", "check"], home.to_str().unwrap()));
    // Valid, but the lint explains the unknown-matches-restrictive effect.
    assert!(check.status.success());
    assert!(String::from_utf8_lossy(&check.stdout).contains("warning: rule \"no-ssh\""));
}

#[test]
fn check_reports_hand_written_mistakes() {
    let (_temp, home) = init();
    let dir = home.to_str().unwrap();
    let policy = home.join("policy.json");
    let ok = run(&with_dir(&["policy", "check"], dir));
    let text = String::from_utf8_lossy(&ok.stdout);
    assert!(ok.status.success(), "{text}");
    assert!(text.contains("digest ") && text.contains("HighAssurance engine starts"));

    // `value` instead of `expected`, missing fields: invalid, exit 1.
    fs::write(
        &policy,
        r#"{"id":"p","version":1,"canonical_version":1,"semantics_version":2,"rules":[
          {"id":"d","action_type":"mcp.tools/call","effect":"Deny",
           "parameter_conditions":[{"key":"tool","operator":"Exact","value":"x"}]}]}"#,
    )
    .unwrap();
    let bad = run(&with_dir(&["policy", "check"], dir));
    assert_eq!(bad.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bad.stdout).starts_with("INVALID"));
    // Mutating commands refuse to build on an invalid policy.
    let out = run(&with_dir(
        &["policy", "deny", "--id", "z", "--tool", "t"],
        dir,
    ));
    assert!(!out.status.success());

    // Valid JSON, but approval without capability: warned.
    fs::write(
        &policy,
        r#"{"id":"p","version":1,"canonical_version":1,"semantics_version":2,"rules":[
          {"id":"allow","action_type":"mcp.tools/call","effect":"Allow","required_capability":"mcp:tools/call",
           "target":null,"parameter_conditions":[],"context_conditions":[]},
          {"id":"ra","action_type":"mcp.tools/call","effect":"RequireApproval","required_capability":null,
           "target":null,"parameter_conditions":[],"context_conditions":[]}]}"#,
    )
    .unwrap();
    let warned = run(&with_dir(&["policy", "check"], dir));
    let text = String::from_utf8_lossy(&warned.stdout);
    assert!(warned.status.success(), "{text}");
    assert!(text.contains("without required_capability"), "{text}");
}
