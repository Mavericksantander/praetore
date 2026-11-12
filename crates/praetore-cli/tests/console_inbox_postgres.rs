//! End to end for the console approvals inbox (D2), against real binaries
//! and a real PostgreSQL journal.
//!
//! `praetore init` + a policy that holds `demo:set_value` for approval,
//! `praetore run` as the gateway, two `praetore demo` requests held. Then
//! the console, in this process, reads the inbox from the journal, signs an
//! approval with `approver.key` and dispatches it through the gateway's HTTP
//! API, and rejects the other request. The journal must show one execution
//! and one signed rejection, and the inbox must be empty.
//!
//! Needs `PRAETORE_TEST_DATABASE_URL` (a role that can CREATE ROLE). The
//! gateway helpers mirror `journal_export_postgres.rs`.

#![cfg(unix)]

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use praetore_console::{
    ACTION_HEADER, ApproverSigner, ConsoleState, HttpApprovalGateway, Inbox, InboxStore,
    LocalSession, PendingKind, PostgresHistory, read_token_file,
};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use tower::ServiceExt;
use uuid::Uuid;

const PRAETORE: &str = env!("CARGO_BIN_EXE_praetore");
const RUNTIME_LOGIN: &str = "praetore_console_inbox_runtime";
const RUNTIME_PASSWORD: &str = "praetore-console-inbox-test";
const CONSOLE: &str = "http://127.0.0.1:8090";

static PROVISION: Mutex<()> = Mutex::new(());

fn provision(admin_url: &str) -> String {
    let _serial = PROVISION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut admin = postgres::Client::connect(admin_url, postgres::NoTls).unwrap();
    praetore_replay_postgres::apply_migrations(&mut admin).unwrap();
    admin
        .batch_execute(&format!(
            "DO $$ BEGIN CREATE ROLE {RUNTIME_LOGIN} LOGIN; \
             EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$; \
             ALTER ROLE {RUNTIME_LOGIN} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE \
                 NOCREATEDB PASSWORD '{RUNTIME_PASSWORD}'; \
             GRANT praetore_runtime TO {RUNTIME_LOGIN}"
        ))
        .unwrap();
    let (scheme, rest) = admin_url.split_once("://").expect("URL form");
    let host = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    format!("{scheme}://{RUNTIME_LOGIN}:{RUNTIME_PASSWORD}@{host}")
}

fn praetore(args: &[&str]) -> Output {
    Command::new(PRAETORE)
        .args(args)
        .env_remove("PRAETORE_GATEWAY_DATABASE_URL")
        .output()
        .unwrap()
}

fn ok(output: Output, what: &str) -> Output {
    assert!(
        output.status.success(),
        "{what} failed ({}):\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(dir: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(dir.join("config.json")).unwrap()).unwrap()
}

fn set_port(dir: &Path, port: u16) {
    let mut value = config(dir);
    value["port"] = port.into();
    fs::write(dir.join("config.json"), value.to_string()).unwrap();
}

struct Gateway {
    child: Child,
    log: PathBuf,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Gateway {
    fn start(dir: &Path, admin_url: &str, runtime_url: &str) -> Self {
        for attempt in 1..=5 {
            let log = dir.with_extension("log");
            let child = Command::new(PRAETORE)
                .arg("run")
                .arg(dir)
                .env("PRAETORE_GATEWAY_DATABASE_URL", runtime_url)
                .env("PRAETORE_GATEWAY_MIGRATION_DATABASE_URL", admin_url)
                .stdout(fs::File::create(&log).unwrap())
                .stderr(Stdio::from(
                    fs::OpenOptions::new().append(true).open(&log).unwrap(),
                ))
                .spawn()
                .unwrap();
            let mut gateway = Self { child, log };
            let port = config(dir)["port"].as_u64().unwrap() as u16;
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                if let Some(status) = gateway.child.try_wait().unwrap() {
                    let log = gateway.log();
                    if log.contains("Address already in use") && attempt < 5 {
                        set_port(dir, free_port());
                        break;
                    }
                    panic!("gateway exited with {status}: {log}");
                }
                if serves(dir, port) {
                    return gateway;
                }
                assert!(
                    Instant::now() < deadline,
                    "gateway not ready: {}",
                    gateway.log()
                );
                thread::sleep(Duration::from_millis(100));
            }
        }
        unreachable!("the last attempt returns or panics")
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }
}

fn serves(dir: &Path, port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let token = fs::read_to_string(dir.join("agent-api.token")).unwrap();
    let tenant = config(dir)["tenant_id"].as_str().unwrap().to_owned();
    let request = format!(
        "GET /v1/approvals/{tenant}/{}/{}/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         Authorization: Bearer {}\r\npraetore-exec-mode: gateway\r\n\
         Connection: close\r\n\r\n",
        Uuid::new_v4(),
        Uuid::new_v4(),
        token.trim()
    );
    let mut response = String::new();
    if stream.write_all(request.as_bytes()).is_err()
        || stream.read_to_string(&mut response).is_err()
    {
        return false;
    }
    let status = response.split(' ').nth(1).unwrap_or_default();
    response.starts_with("HTTP/1.1 ") && !["", "401", "403"].contains(&status)
}

/// `praetore demo <dir> set <key> v`, held for approval; its `request_id`.
fn held_demo(dir: &Path, key: &str) -> Uuid {
    let output = ok(
        praetore(&["demo", dir.to_str().unwrap(), "set", key, "v"]),
        "praetore demo",
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["authorization"], "requires_approval", "{receipt}");
    Uuid::parse_str(receipt["evidence"]["request_id"].as_str().unwrap()).unwrap()
}

fn action(uri: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::COOKIE, cookie())
        .header(header::ORIGIN, CONSOLE)
        .header(ACTION_HEADER, "1")
        .body(Body::empty())
        .unwrap()
}

fn cookie() -> String {
    LocalSession::from_secret([0x21; 32])
        .cookie_header()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

async fn call(
    app: &axum::Router,
    request: Request<Body>,
) -> (StatusCode, serde_json::Value, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    (status, serde_json::from_str(&text).unwrap(), text)
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_console_inbox_approves_dispatches_and_rejects_through_the_gateway() {
    let admin_url = std::env::var("PRAETORE_TEST_DATABASE_URL")
        .expect("PRAETORE_TEST_DATABASE_URL is required");
    let runtime_url = provision(&admin_url);
    let root = std::env::temp_dir().join(format!("praetore-console-inbox-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let dir = root.join("demo");
    ok(
        praetore(&[
            "init",
            dir.to_str().unwrap(),
            "--port",
            &free_port().to_string(),
        ]),
        "praetore init",
    );
    let tenant = Uuid::parse_str(config(&dir)["tenant_id"].as_str().unwrap()).unwrap();
    // Hold every demo write for a person.
    let mut policy: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("policy.json")).unwrap()).unwrap();
    policy["rules"][0]["effect"] = "RequireApproval".into();
    fs::write(dir.join("policy.json"), policy.to_string()).unwrap();

    let gateway = Gateway::start(&dir, &admin_url, &runtime_url);
    let port = config(&dir)["port"].as_u64().unwrap() as u16;
    let approve_id = held_demo(&dir, "aprobar");
    let reject_id = held_demo(&dir, "rechazar");

    let client = postgres::Client::connect(&runtime_url, postgres::NoTls).unwrap();
    let history = Arc::new(PostgresHistory::from_client(client, tenant).unwrap());
    let pending = history.pending().unwrap();
    assert_eq!(pending.items.len(), 2);
    assert_eq!(pending.unreadable, 0);
    assert!(
        pending
            .items
            .iter()
            .all(|item| item.kind == PendingKind::AwaitingApproval
                && item.wanted == "demo:set_value")
    );

    let signer = ApproverSigner::from_file("local-approver", &dir.join("approver.key")).unwrap();
    let token = read_token_file(&dir.join("approver-api.token")).unwrap();
    let inbox = Inbox::new(
        history.clone(),
        Arc::new(HttpApprovalGateway::new(
            format!("127.0.0.1:{port}").parse().unwrap(),
            token,
        )),
        signer,
        "127.0.0.1:8090".parse().unwrap(),
    );
    let state = Arc::new(
        ConsoleState::new(
            history.clone(),
            LocalSession::from_secret([0x21; 32]),
            HashMap::new(),
        )
        .with_inbox(inbox),
    );
    let app = ConsoleState::router_from(Arc::clone(&state));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let list = Request::builder()
            .uri("/api/bandeja")
            .header(header::COOKIE, cookie())
            .body(Body::empty())
            .unwrap();
        let (status, list, text) = call(&app, list).await;
        assert_eq!(status, StatusCode::OK, "{text}");
        assert!(!text.contains(&approve_id.to_string()));
        assert!(!text.contains(&tenant.to_string()));
        let items = list["solicitudes"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        // Oldest first: the first `praetore demo` is the first item.
        let first = items[0]["referencia"].as_str().unwrap().to_owned();
        let second = items[1]["referencia"].as_str().unwrap().to_owned();

        let (_, approved, text) =
            call(&app, action(&format!("/api/bandeja/{first}/aprobar"))).await;
        assert_eq!(
            approved["situacion"], "aprobado, pendiente de ejecución",
            "{text}"
        );
        assert_eq!(approved["puede_ejecutar"], true);
        let (_, executed, text) =
            call(&app, action(&format!("/api/bandeja/{first}/ejecutar"))).await;
        assert_eq!(executed["situacion"], "aprobado", "{text}");
        assert_eq!(executed["puede_ejecutar"], false);
        let (_, again, _) = call(&app, action(&format!("/api/bandeja/{first}/aprobar"))).await;
        assert_eq!(again["situacion"], "sin cambios");

        let (_, rejected, text) =
            call(&app, action(&format!("/api/bandeja/{second}/rechazar"))).await;
        assert_eq!(rejected["situacion"], "rechazado", "{text}");
        let (_, after, _) = call(&app, action(&format!("/api/bandeja/{second}/ejecutar"))).await;
        assert_eq!(after["puede_ejecutar"], false);

        let list = Request::builder()
            .uri("/api/bandeja")
            .header(header::COOKIE, cookie())
            .body(Body::empty())
            .unwrap();
        let (_, list, _) = call(&app, list).await;
        assert_eq!(list["solicitudes"].as_array().unwrap().len(), 0);
    });
    drop(runtime);
    drop(app);

    let mut admin = postgres::Client::connect(&admin_url, postgres::NoTls).unwrap();
    let mut row = |request: Uuid| {
        let row = admin
            .query_one(
                "SELECT execution_status, not_dispatched_reason \
                   FROM praetore.execution_journal WHERE tenant_id = $1 AND request_id = $2",
                &[&tenant, &request],
            )
            .unwrap();
        (row.get::<_, String>(0), row.get::<_, Option<String>>(1))
    };
    let (approved_status, _) = row(approve_id);
    assert!(
        ["executed", "confirmed"].contains(&approved_status.as_str()),
        "{approved_status}"
    );
    assert_eq!(
        row(reject_id),
        (
            "not_dispatched".to_owned(),
            Some("approval_rejected".to_owned())
        )
    );
    drop(gateway);
    drop(state);
    let _ = fs::remove_dir_all(&root);
}
