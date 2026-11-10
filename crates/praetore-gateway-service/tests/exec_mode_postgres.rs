//! T19 and T19b for `praetore-gateway-demo` (local-demo adapter, no
//! sandbox) against real PostgreSQL: cooperative execution is refused by
//! default, and only `PRAETORE_GATEWAY_DEV_COOPERATIVE_EXEC=1` accepts it,
//! with a startup warning that the mode gives no guarantee. Needs
//! `PRAETORE_TEST_DATABASE_URL` (a role that can CREATE DATABASE and CREATE
//! ROLE).

use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, AuthorizationRequest, Policy, PolicyEffect,
    PolicyRule, TrustedAuthorityIssuer, authority::Validity,
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

const ISSUER: &str = "exec-mode-issuer";
const ISSUER_SECRET: [u8; 32] = [5; 32];

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
            format!("praetore_exec_{suffix}"),
            format!("praetore_exec_{suffix}"),
        );
        let mut admin = postgres::Client::connect(&admin_url, postgres::NoTls).unwrap();
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .unwrap();
        admin
            .batch_execute(&format!(
                "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'praetore-exec-test'"
            ))
            .unwrap();
        let (base, _) = admin_url.split_once('?').unwrap_or((&admin_url, ""));
        let (prefix, _) = base.rsplit_once('/').unwrap();
        let url = format!("{prefix}/{name}");
        let host = prefix.rsplit_once('@').map_or(prefix, |(_, host)| host);
        let host = host.split_once("://").map_or(host, |(_, host)| host);
        let runtime_url = format!("postgres://{role}:praetore-exec-test@{host}/{name}");
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

    /// Rows of the execution journal, all tenants (read as the admin role).
    fn journal_rows(&self) -> i64 {
        let mut client = postgres::Client::connect(&self.url, postgres::NoTls).unwrap();
        client
            .query_one("SELECT count(*) FROM praetore.execution_journal", &[])
            .unwrap()
            .get(0)
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

fn policy() -> Policy {
    Policy::new_v2(
        "exec-mode",
        1,
        vec![
            PolicyRule::new("allow-demo-set", "demo:set_value", PolicyEffect::Allow)
                .with_capability("demo:write")
                .with_target("demo-state"),
        ],
    )
    .with_mission_actions(["demo:set_value"])
}

fn rfc3339(at: time::OffsetDateTime) -> String {
    at.format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

/// A request for `demo:set_value` signed for the local-demo audience.
fn signed_request(tenant: uuid::Uuid) -> String {
    let issuer = AgentKeyPair::from_secret_bytes(&ISSUER_SECRET);
    let agent_key = AgentKeyPair::generate();
    let agent = agent_key.identity(AgentId::new());
    let now = time::OffsetDateTime::now_utc();
    let mut authority = Authority::new(agent.id.clone(), ISSUER, vec!["demo:write".into()])
        .with_constraint("tenant_id", tenant.to_string())
        .with_validity(Validity {
            not_before: Some(rfc3339(now - time::Duration::minutes(1))),
            not_after: Some(rfc3339(now + time::Duration::hours(1))),
        });
    authority.sign_for_agent(&issuer, &agent).unwrap();
    let action = Action::new(
        "demo:set_value",
        Some("demo-state".into()),
        serde_json::json!({"key": "k", "value": "v"}),
    )
    .unwrap()
    .with_capability("demo:write");
    let policy = policy();
    let action = policy.classify(action).unwrap().into_mission().unwrap();
    let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
    request
        .sign_intent_v2(
            &agent_key,
            "praetore-local-demo",
            now,
            now + time::Duration::seconds(60),
            policy.digest().unwrap(),
        )
        .unwrap();
    serde_json::to_string(&request).unwrap()
}

/// `praetore-gateway-demo` with the local-demo adapter on a free loopback
/// port; killed on drop. Its log goes to a file read by [`Self::log`].
struct Service {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Service {
    fn start(scratch: &Scratch, dev_flag: Option<&str>) -> Self {
        let dir = std::env::temp_dir().join(format!("praetore-exec-mode-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let policy_file = dir.join("policy.json");
        std::fs::write(&policy_file, serde_json::to_vec(&policy()).unwrap()).unwrap();
        let now = time::OffsetDateTime::now_utc();
        let pin = TrustedAuthorityIssuer::new(
            ISSUER,
            AgentKeyPair::from_secret_bytes(&ISSUER_SECRET).public_key(),
        )
        .unwrap()
        .with_validity(Validity {
            not_before: Some(rfc3339(now - time::Duration::minutes(5))),
            not_after: Some(rfc3339(now + time::Duration::days(1))),
        })
        .unwrap();
        let pin_file = dir.join("issuer-pin.json");
        std::fs::write(&pin_file, pin.export_pin_json().unwrap()).unwrap();
        let approver = AgentKeyPair::from_secret_bytes(&[6; 32]).public_key();
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let log = std::fs::File::create(dir.join("service.log")).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_praetore-gateway-demo"));
        command
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
            .env("PRAETORE_GATEWAY_APPROVER_KEY_ID", "exec-mode-approver")
            .env(
                "PRAETORE_GATEWAY_APPROVER_PUBLIC_KEY_HEX",
                hex::encode(approver.as_bytes()),
            )
            .env("PRAETORE_GATEWAY_PORT", port.to_string())
            .env("RUST_LOG", "info")
            .env_remove("PRAETORE_GATEWAY_ADAPTER")
            .env_remove("PRAETORE_GATEWAY_LISTEN_ADDR")
            .env_remove("PRAETORE_GATEWAY_API_CREDENTIALS_FILE")
            .env_remove("PRAETORE_GATEWAY_APPROVER_BINDINGS_FILE")
            .env_remove("PRAETORE_GATEWAY_FRESHNESS_FILE")
            .env_remove("PRAETORE_GATEWAY_DEV_COOPERATIVE_EXEC")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log));
        if let Some(flag) = dev_flag {
            command.env("PRAETORE_GATEWAY_DEV_COOPERATIVE_EXEC", flag);
        }
        let mut service = Self {
            child: command.spawn().unwrap(),
            port,
            dir,
        };
        let up = (0..200).any(|_| {
            if let Some(status) = service.child.try_wait().unwrap() {
                panic!("service exited with {status}: {}", service.log());
            }
            let ok = service.send("GET", "/healthz", &[], "").0 == 204;
            if !ok {
                std::thread::sleep(Duration::from_millis(50));
            }
            ok
        });
        assert!(up, "service did not start: {}", service.log());
        service
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("service.log")).unwrap_or_default()
    }

    /// One HTTP/1.1 request with exactly the given exec-mode headers.
    fn send(&self, method: &str, path: &str, modes: &[&str], body: &str) -> (u16, String) {
        let Ok(mut stream) = TcpStream::connect(("127.0.0.1", self.port)) else {
            return (0, String::new());
        };
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
        for mode in modes {
            request.push_str(&format!("praetore-exec-mode: {mode}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(body);
        let mut response = String::new();
        if stream.write_all(request.as_bytes()).is_err()
            || stream.read_to_string(&mut response).is_err()
        {
            return (0, String::new());
        }
        let status = response
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_owned())
            .unwrap_or_default();
        (status, body)
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn remove(path: &Path) {
    let _ = std::fs::remove_dir_all(path);
}

/// T19 (gateway service): by default, with the local-demo adapter and no
/// sandbox, `POST /v1/execute` without the declaration, with `cooperative`,
/// with `gateway,cooperative` or with a repeated header gets 409
/// `exec_mode_gateway_required` and nothing is journaled; with exactly
/// `gateway` the gateway evaluates and executes it.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_gateway_service_t019_refuses_cooperative_exec_by_default() {
    let scratch = Scratch::create();
    let service = Service::start(&scratch, None);
    let tenant = uuid::Uuid::new_v4();
    for modes in [
        &[][..],
        &["cooperative"][..],
        &["gateway,cooperative"][..],
        &["gateway", "cooperative"][..],
    ] {
        let (status, body) = service.send("POST", "/v1/execute", modes, &signed_request(tenant));
        assert_eq!(status, 409, "{modes:?}: {body}");
        assert!(body.contains("exec_mode_gateway_required"), "{body}");
    }
    assert_eq!(scratch.journal_rows(), 0, "nothing evaluated or journaled");
    let (status, body) = service.send("POST", "/v1/execute", &["gateway"], &signed_request(tenant));
    assert_eq!(status, 200, "{body}");
    let receipt: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(receipt["authorization"], "allowed", "{body}");
    assert_eq!(scratch.journal_rows(), 1);
    let log = service.log();
    assert!(!log.contains("development cooperative mode"), "{log}");
    let dir = service.dir.clone();
    drop(service);
    remove(&dir);
}

/// T19b (gateway service): only `PRAETORE_GATEWAY_DEV_COOPERATIVE_EXEC=1`
/// accepts a request without the declaration, and the service logs at
/// startup that this mode gives no guarantee. Any other value of the flag
/// stops the service before it listens. Not coverage of the default.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_gateway_service_t019b_development_flag_alone_enables_cooperative_exec() {
    let scratch = Scratch::create();
    let service = Service::start(&scratch, Some("1"));
    let log = service.log();
    assert!(log.contains("development cooperative mode"), "{log}");
    assert!(log.contains("gives no guarantee"), "{log}");
    let tenant = uuid::Uuid::new_v4();
    for modes in [&[][..], &["cooperative"][..]] {
        let (status, body) = service.send("POST", "/v1/execute", modes, &signed_request(tenant));
        assert_eq!(status, 200, "{modes:?}: {body}");
    }
    assert_eq!(scratch.journal_rows(), 2);
    drop(service);

    let output = Command::new(env!("CARGO_BIN_EXE_praetore-gateway-demo"))
        .env("PRAETORE_GATEWAY_DATABASE_URL", &scratch.runtime_url)
        .env(
            "PRAETORE_GATEWAY_EVIDENCE_ATTESTER_KEY_HEX",
            hex::encode([7u8; 32]),
        )
        .env(
            "PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_HEX",
            hex::encode([8u8; 32]),
        )
        .env_remove("PRAETORE_GATEWAY_ADAPTER")
        .env("PRAETORE_GATEWAY_DEV_COOPERATIVE_EXEC", "true")
        .output()
        .unwrap();
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(
        log.contains("PRAETORE_GATEWAY_DEV_COOPERATIVE_EXEC must be 0 or 1"),
        "{log}"
    );
}
