//! `praetore-observe` on a port already in use exits with the bind error
//! (status 1) instead of aborting while it drops its PostgreSQL client on
//! the runtime thread. Needs `PRAETORE_TEST_DATABASE_URL` (a role that can
//! CREATE DATABASE and CREATE ROLE).

use std::{net::TcpListener, process::Command};

/// A scratch database migrated as the admin role, with a LOGIN member of
/// `praetore_runtime`; the database and the role are dropped on drop.
struct Scratch {
    admin_url: String,
    name: String,
    role: String,
    url: String,
    runtime_url: String,
}

impl Scratch {
    fn create() -> Self {
        let admin_url = std::env::var("PRAETORE_TEST_DATABASE_URL").unwrap();
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let (name, role) = (
            format!("praetore_port_{suffix}"),
            format!("praetore_port_{suffix}"),
        );
        let mut admin = postgres::Client::connect(&admin_url, postgres::NoTls).unwrap();
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .unwrap();
        admin
            .batch_execute(&format!(
                "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'praetore-port-test'"
            ))
            .unwrap();
        let (base, _) = admin_url.split_once('?').unwrap_or((&admin_url, ""));
        let (prefix, _) = base.rsplit_once('/').unwrap();
        let url = format!("{prefix}/{name}");
        let host = prefix.rsplit_once('@').map_or(prefix, |(_, host)| host);
        let host = host.split_once("://").map_or(host, |(_, host)| host);
        let runtime_url = format!("postgres://{role}:praetore-port-test@{host}/{name}");
        let scratch = Self {
            admin_url,
            name,
            role,
            url,
            runtime_url,
        };
        let mut client = postgres::Client::connect(&scratch.url, postgres::NoTls).unwrap();
        praetore_replay_postgres::apply_migrations(&mut client).unwrap();
        client
            .batch_execute(&format!("GRANT praetore_runtime TO {}", scratch.role))
            .unwrap();
        scratch
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Ok(mut admin) = postgres::Client::connect(&self.admin_url, postgres::NoTls) {
            let _ = admin.batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            ));
            let _ = admin.batch_execute(&format!("DROP ROLE IF EXISTS {}", self.role));
        }
    }
}

/// The process exits with status 1 and the bind error, without a panic.
fn assert_reports_port_in_use(output: &std::process::Output) {
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(log.contains("Address already in use"), "{log}");
    assert!(!log.contains("panicked"), "{log}");
    eprintln!(
        "refused as expected: {}",
        log.lines().last().unwrap_or_default()
    );
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_observe_reports_a_port_in_use() {
    let scratch = Scratch::create();
    let dir = std::env::temp_dir().join(format!("praetore-observe-port-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let tokens = dir.join("tokens.json");
    std::fs::write(
        &tokens,
        serde_json::json!({
            "schema_version": 1,
            "tenants": [{
                "tenant_id": uuid::Uuid::new_v4(),
                "bearer_token_sha256": "ab".repeat(32),
            }],
        })
        .to_string(),
    )
    .unwrap();
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_praetore-observe"))
        .env("PRAETORE_OBSERVE_TENANT_TOKENS_FILE", &tokens)
        .env("PRAETORE_OBSERVE_DATABASE_URL", &scratch.runtime_url)
        .env(
            "PRAETORE_OBSERVE_BIND",
            taken.local_addr().unwrap().to_string(),
        )
        .env_remove("PRAETORE_SCHEMA_OWNER")
        .output()
        .unwrap();
    assert_reports_port_in_use(&output);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("PRAETORE_SCHEMA_OWNER is not set"),
        "the unset schema owner is warned about"
    );
    drop(taken);
    std::fs::remove_dir_all(&dir).unwrap();
}
