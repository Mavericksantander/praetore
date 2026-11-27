//! `--help`, `--version` and documented exit codes of the CLI itself.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_praetore-mcp"))
        .args(args)
        .env("PRAETORE_MCP_HOME", "/nonexistent/praetore-mcp-cli-test")
        .output()
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn every_subcommand_has_help_on_stdout_with_exit_zero() {
    for command in [
        "init",
        "wrap",
        "install",
        "uninstall",
        "doctor",
        "receipts",
        "verify",
        "dashboard",
        "approvals",
        "approve",
        "reject",
        "policy",
    ] {
        for flag in ["--help", "-h"] {
            let out = run(&[command, flag]);
            assert_eq!(out.status.code(), Some(0), "{command} {flag}: {out:?}");
            assert!(
                stdout(&out).starts_with(&format!("Usage: praetore-mcp {command}"))
                    || (command == "policy" && stdout(&out).contains("praetore-mcp policy list")),
                "{command} {flag}: {}",
                stdout(&out)
            );
            assert!(out.stderr.is_empty(), "{command} {flag}: {out:?}");
        }
    }
}

#[test]
fn help_is_found_among_other_options_and_policy_subcommands() {
    for args in [
        &["wrap", "--mode", "enforce", "--help"][..],
        &["policy", "deny", "--help"],
        &["policy", "check", "-h"],
        &["receipts", "--tail", "3", "--help"],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {out:?}");
        assert!(stdout(&out).contains("Usage"), "{args:?}");
    }
}

#[test]
fn help_after_double_dash_belongs_to_the_wrapped_server() {
    // `--help` after `--` is the server's argument, so `wrap` tries to start
    // the (missing) server instead of printing its own help.
    let out = run(&["wrap", "--", "/nonexistent/praetore-mcp-server", "--help"]);
    assert_eq!(out.status.code(), Some(127), "{out:?}");
    assert!(!stdout(&out).contains("Usage"), "{out:?}");
}

#[test]
fn top_level_help_documents_exit_codes() {
    for flag in ["--help", "-h", "help"] {
        let out = run(&[flag]);
        assert_eq!(out.status.code(), Some(0), "{flag}: {out:?}");
        let text = stdout(&out);
        assert!(text.contains("Exit codes:"), "{text}");
        assert!(text.contains("<command> --help"), "{text}");
    }
}

/// The build version, the one the session reports name: the crate version
/// for a release build, `<version>-dev+<commit>` or `<version>-dev`
/// otherwise (rules in `build_version.rs`).
#[test]
fn version_prints_the_build_version() {
    let build = praetore_mcp::report::BUILD_VERSION;
    let rest = build.strip_prefix(env!("CARGO_PKG_VERSION")).unwrap();
    assert!(
        rest.is_empty()
            || rest == "-dev"
            || rest.strip_prefix("-dev+").is_some_and(|c| {
                (7..=40).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_hexdigit())
            }),
        "{build}"
    );
    for flag in ["--version", "-V", "version"] {
        let out = run(&[flag]);
        assert_eq!(out.status.code(), Some(0), "{flag}: {out:?}");
        assert_eq!(stdout(&out), format!("praetore-mcp {build}\n"));
    }
}

#[test]
fn usage_errors_exit_two() {
    for args in [
        &[][..],
        &["no-such-command"],
        &["init", "--bogus"],
        &["wrap"],
        &["policy", "no-such-subcommand"],
        &["receipts", "--tail", "many"],
        &["doctor", "--client", "cursor"],
        &["doctor", "--mode", "loud"],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
        assert!(!out.stderr.is_empty(), "{args:?}: {out:?}");
    }
}

/// Observe mode is not "never blocks": it still refuses unclassified calls,
/// unparseable lines that may name a safety* tool, lines over 32 MiB,
/// batches with a refused call, and, when the home cannot be loaded, every
/// call and every unparseable line. The help says so, in words a test can
/// pin.
#[test]
fn init_help_says_what_observe_mode_still_refuses() {
    let words = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let init = words(&stdout(&run(&["init", "--help"])));
    assert!(
        init.contains(
            "Observe mode records a DENY and forwards the call, but it still refuses a \
             tools/call the policy does not classify, a client line it cannot parse that \
             may name a safety* tool, a client line over 32 MiB, and a whole batch when a \
             tools/call in it is refused. When the home cannot be loaded (before init, for \
             example), every tools/call and every client line that cannot be parsed is \
             refused."
        ),
        "{init}"
    );
    let top = words(&stdout(&run(&["--help"])));
    assert!(
        top.contains(
            "it still refuses unclassified calls, unparseable lines that may name a \
             safety* tool, lines over 32 MiB and batches with a refused call, and, when the \
             home cannot be loaded, every tools/call."
        ),
        "{top}"
    );
    for text in [&init, &top] {
        assert!(!text.contains("never blocks"), "{text}");
    }
}

/// The text `init` prints about observe mode, not only its help.
#[test]
fn init_output_says_what_observe_mode_still_refuses() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("home");
    let out = run(&["init", "--dir", dir.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = stdout(&out)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        text.contains(
            "In enforce mode every tools/call is denied unless a rule allows it. Observe \
             mode records a DENY and forwards the call, but it still refuses calls the \
             policy does not classify and client lines it cannot check (see `init --help`)."
        ),
        "{text}"
    );
    assert!(!text.contains("never blocks"), "{text}");
}
