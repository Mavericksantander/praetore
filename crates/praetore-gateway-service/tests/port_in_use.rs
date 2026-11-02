//! `praetore-gateway-demo` on a port already in use exits with the bind
//! error (status 1) instead of aborting while it drops its PostgreSQL
//! clients on the runtime thread. Needs `PRAETORE_TEST_DATABASE_URL` (a
//! role that can CREATE DATABASE and CREATE ROLE).

use praetore_core::{AgentKeyPair, Policy, PolicyEffect, PolicyRule, TrustedAuthorityIssuer};
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
fn postgres_gateway_service_reports_a_port_in_use() {
    let scratch = Scratch::create();
    let dir = std::env::temp_dir().join(format!("praetore-gateway-port-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let policy = Policy::new_v2(
        "port-in-use",
        1,
        vec![PolicyRule::new(
            "allow-demo",
            "demo:set_value",
            PolicyEffect::Allow,
        )],
    )
    .with_mission_actions(["demo:set_value"]);
    let policy_file = dir.join("policy.json");
    std::fs::write(&policy_file, serde_json::to_vec(&policy).unwrap()).unwrap();
    let now = time::OffsetDateTime::now_utc();
    let rfc3339 = |at: time::OffsetDateTime| {
        at.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let pin = TrustedAuthorityIssuer::new(
        "port-in-use-issuer",
        AgentKeyPair::from_secret_bytes(&[5; 32]).public_key(),
    )
    .unwrap()
    .with_validity(praetore_core::authority::Validity {
        not_before: Some(rfc3339(now - time::Duration::minutes(5))),
        not_after: Some(rfc3339(now + time::Duration::days(1))),
    })
    .unwrap();
    let pin_file = dir.join("issuer-pin.json");
    std::fs::write(&pin_file, pin.export_pin_json().unwrap()).unwrap();
    let approver = AgentKeyPair::from_secret_bytes(&[6; 32]).public_key();
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_praetore-gateway-demo"))
        .env("PRAETORE_GATEWAY_DATABASE_URL", &scratch.runtime_url)
        .env("PRAETORE_GATEWAY_MIGRATION_DATABASE_URL", &scratch.url)
        .env(
            "PRAETORE_GATEWAY_EVIDENCE_ATTESTER_KEY_HEX",
            hex::encode([7u8; 32]),
        )
        .env(
            "PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_HEX",
            hex::encode([8u8; 32]),
        )
        .env("PRAETORE_GATEWAY_POLICY_FILE", &policy_file)
        .env("PRAETORE_GATEWAY_ISSUER_PIN_FILE", &pin_file)
        .env("PRAETORE_GATEWAY_APPROVER_KEY_ID", "port-in-use-approver")
        .env(
            "PRAETORE_GATEWAY_APPROVER_PUBLIC_KEY_HEX",
            hex::encode(approver.as_bytes()),
        )
        .env(
            "PRAETORE_GATEWAY_PORT",
            taken.local_addr().unwrap().port().to_string(),
        )
        .env_remove("PRAETORE_GATEWAY_ADAPTER")
        .env_remove("PRAETORE_GATEWAY_LISTEN_ADDR")
        .env_remove("PRAETORE_GATEWAY_API_CREDENTIALS_FILE")
        .env_remove("PRAETORE_GATEWAY_APPROVER_BINDINGS_FILE")
        .env_remove("PRAETORE_GATEWAY_FRESHNESS_FILE")
        .output()
        .unwrap();
    assert_reports_port_in_use(&output);
    drop(taken);
    std::fs::remove_dir_all(&dir).unwrap();
}
