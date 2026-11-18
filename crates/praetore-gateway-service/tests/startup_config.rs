//! `praetore-gateway-demo` refuses to start, before it opens any database
//! connection, without an explicitly named adapter or without two distinct
//! attester keys read from owner-only files. No PostgreSQL needed: every
//! case fails before the first connection.

#![cfg(unix)]

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("praetore-startup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn key(&self, name: &str, key: [u8; 32], mode: u32) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, format!("{}\n", hex::encode(key))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs the service with exactly `vars` in its environment and returns
/// its exit code and output. The database URL names a closed loopback port:
/// reaching it would be a different error.
fn run(vars: &[(&str, &Path)], extra: &[(&str, &str)]) -> (Option<i32>, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_praetore-gateway-demo"));
    command.env_clear();
    for (name, value) in vars {
        command.env(name, value);
    }
    for (name, value) in extra {
        command.env(name, value);
    }
    let output = command.output().unwrap();
    (
        output.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

const DATABASE: (&str, &str) = (
    "PRAETORE_GATEWAY_DATABASE_URL",
    "postgres://gateway@127.0.0.1:1/praetore",
);

fn assert_refused(result: (Option<i32>, String), expected: &str) {
    let (code, log) = result;
    assert_eq!(code, Some(1), "{log}");
    assert!(log.contains(expected), "expected {expected:?}: {log}");
    assert!(!log.contains("listening"), "{log}");
    assert!(!log.contains("panicked"), "{log}");
}

#[test]
fn without_an_adapter_the_service_does_not_start() {
    let dir = Dir::new();
    let evidence = dir.key("evidence.key", [7; 32], 0o600);
    let execution = dir.key("execution.key", [8; 32], 0o600);
    let keys = [
        (
            "PRAETORE_GATEWAY_EVIDENCE_ATTESTER_KEY_FILE",
            evidence.as_path(),
        ),
        (
            "PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_FILE",
            execution.as_path(),
        ),
    ];
    assert_refused(
        run(&keys, &[DATABASE]),
        "PRAETORE_GATEWAY_ADAPTER is required",
    );
    assert_refused(
        run(&keys, &[DATABASE, ("PRAETORE_GATEWAY_ADAPTER", "")]),
        "PRAETORE_GATEWAY_ADAPTER must be sandbox, http, or local-demo",
    );
}

#[test]
fn attester_keys_come_from_distinct_owner_only_files() {
    let dir = Dir::new();
    let evidence = dir.key("evidence.key", [7; 32], 0o600);
    let execution = dir.key("execution.key", [8; 32], 0o600);
    let same = dir.key("same.key", [7; 32], 0o600);
    let readable = dir.key("readable.key", [9; 32], 0o644);
    let adapter = ("PRAETORE_GATEWAY_ADAPTER", "local-demo");
    let evidence_var = "PRAETORE_GATEWAY_EVIDENCE_ATTESTER_KEY_FILE";
    let execution_var = "PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_FILE";

    assert_refused(
        run(
            &[(evidence_var, &evidence), (execution_var, &same)],
            &[DATABASE, adapter],
        ),
        "hold the same key",
    );
    assert_refused(
        run(
            &[(evidence_var, &evidence), (execution_var, &readable)],
            &[DATABASE, adapter],
        ),
        "accessible by group or others",
    );
    assert_refused(
        run(&[(evidence_var, &evidence)], &[DATABASE, adapter]),
        "PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_FILE is required",
    );
    // A key left in the variable of earlier releases is refused, not ignored.
    assert_refused(
        run(
            &[(evidence_var, &evidence), (execution_var, &execution)],
            &[
                DATABASE,
                adapter,
                (
                    "PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_HEX",
                    &hex::encode([8u8; 32]),
                ),
            ],
        ),
        "PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_HEX is set",
    );
}
