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
        "receipts",
        "verify",
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

#[test]
fn version_prints_crate_version() {
    for flag in ["--version", "-V", "version"] {
        let out = run(&[flag]);
        assert_eq!(out.status.code(), Some(0), "{flag}: {out:?}");
        assert_eq!(
            stdout(&out).trim(),
            format!("praetore-mcp {}", env!("CARGO_PKG_VERSION"))
        );
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
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
        assert!(!out.stderr.is_empty(), "{args:?}: {out:?}");
    }
}
