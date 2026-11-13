//! End to end for the console approvals inbox (D2), against real binaries
//! and a real PostgreSQL journal.
//!
//! `praetore init` + a policy that holds `demo:set_value` for approval,
//! `praetore run` as the gateway, two `praetore demo` requests held. Then
//! the console, in this process, reads the inbox from the journal, signs an
//! approval with `approver.key` and dispatches it through the gateway's HTTP
//! API, and rejects the other request. A third request is approved, then
//! read again by a console started afresh, which offers only its dispatch.
//! A fourth is left until its 30 s window closes: it is counted as expired,
//! not offered, and approving its old reference gets "expirado". The journal
//! must show two executions, one signed rejection and one signed expiry.
//!
//! D3: the compliance package of a tenant with real decisions, unpacked
//! with the system's `tar` and checked with `praetore-verify` built from
//! this workspace.
//!
//! Needs `PRAETORE_TEST_DATABASE_URL` (a role that can CREATE ROLE). The
//! gateway helpers mirror `journal_export_postgres.rs`.

#![cfg(unix)]

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use praetore_console::{
    ACTION_HEADER, ApproverSigner, CompliancePack, ConsoleState, EvidenceTrust,
    HttpApprovalGateway, Inbox, InboxStore, LocalSession, PackSettings, PendingKind,
    PostgresHistory, read_token_file,
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
        .header(header::HOST, "127.0.0.1:8090")
        .method("POST")
        .uri(uri)
        .header(header::AUTHORIZATION, auth())
        .header(header::ORIGIN, CONSOLE)
        .header(ACTION_HEADER, "1")
        .body(Body::empty())
        .unwrap()
}

fn inbox_request() -> Request<Body> {
    Request::builder()
        .header(header::HOST, "127.0.0.1:8090")
        .uri("/api/bandeja")
        .header(header::AUTHORIZATION, auth())
        .body(Body::empty())
        .unwrap()
}

fn auth() -> String {
    format!("Bearer {}", hex::encode([0x21; 32]))
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

    // The policy the gateway loads and the attester's public key: what the
    // console checks the journal evidence against before offering a
    // decision.
    // The attester pin `praetore init` wrote, as an operator would hand it out.
    let pin = root.join("attester-public-key.hex");
    fs::copy(dir.join("attester-public-key.hex"), &pin).unwrap();
    let trust =
        EvidenceTrust::load(&dir.join("policy.json"), std::slice::from_ref(&pin), None).unwrap();

    let gateway = Gateway::start(&dir, &admin_url, &runtime_url);
    let port = config(&dir)["port"].as_u64().unwrap() as u16;
    let approve_id = held_demo(&dir, "aprobar");
    let reject_id = held_demo(&dir, "rechazar");

    let client = postgres::Client::connect(&runtime_url, postgres::NoTls).unwrap();
    let history = Arc::new(
        PostgresHistory::from_client(client, tenant)
            .unwrap()
            .with_attester_pins(trust.pins()),
    );
    // Another attester, or another local policy: nothing is offered and
    // both holds are counted as unreadable.
    let foreign = root.join("foreign-attester.hex");
    fs::write(
        &foreign,
        hex::encode(
            praetore_core::EvidenceAttesterKey::from_secret_bytes(&[0x5a; 32])
                .public_key()
                .unwrap()
                .as_bytes(),
        ),
    )
    .unwrap();
    let foreign_trust = EvidenceTrust::load(
        &dir.join("policy.json"),
        std::slice::from_ref(&foreign),
        None,
    )
    .unwrap();
    let mut other_policy = policy.clone();
    other_policy["rules"][0]["effect"] = "Allow".into();
    let other_policy_file = root.join("other-policy.json");
    fs::write(&other_policy_file, other_policy.to_string()).unwrap();
    let rotated_trust =
        EvidenceTrust::load(&other_policy_file, std::slice::from_ref(&pin), None).unwrap();
    for refused in [&foreign_trust, &rotated_trust] {
        let pending = history.pending(refused).unwrap();
        assert!(pending.items.is_empty());
        assert_eq!(pending.unreadable, 2);
    }
    let pending = history.pending(&trust).unwrap();
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
        trust.clone(),
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
    let (reload_id, expire_id) = runtime.block_on(async {
        let list = Request::builder()
            .header(header::HOST, "127.0.0.1:8090")
            .uri("/api/bandeja")
            .header(header::AUTHORIZATION, auth())
            .body(Body::empty())
            .unwrap();
        let (status, list, text) = call(&app, list).await;
        assert_eq!(status, StatusCode::OK, "{text}");
        assert!(!text.contains(&approve_id.to_string()));
        assert!(!text.contains(&tenant.to_string()));
        let items = list["solicitudes"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        // The parameters the signature covers are shown.
        assert_eq!(items[0]["parametros_visibles"], true);
        assert!(!items[0]["parametros"].as_array().unwrap().is_empty());
        assert_eq!(items[0]["puede_aprobar"], true);
        // Newest first: the first `praetore demo` is the second item.
        let first = items[1]["referencia"].as_str().unwrap().to_owned();
        let second = items[0]["referencia"].as_str().unwrap().to_owned();

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
            .header(header::HOST, "127.0.0.1:8090")
            .uri("/api/bandeja")
            .header(header::AUTHORIZATION, auth())
            .body(Body::empty())
            .unwrap();
        let (_, list, _) = call(&app, list).await;
        assert_eq!(list["solicitudes"].as_array().unwrap().len(), 0);

        // Approved but not executed, then read again by a console started
        // afresh (new references): only the dispatch is offered.
        let reload_id = held_demo(&dir, "recargar");
        let (_, list, _) = call(&app, inbox_request()).await;
        let reload = list["solicitudes"][0]["referencia"]
            .as_str()
            .unwrap()
            .to_owned();
        let (_, approved, text) =
            call(&app, action(&format!("/api/bandeja/{reload}/aprobar"))).await;
        assert_eq!(
            approved["situacion"], "aprobado, pendiente de ejecución",
            "{text}"
        );
        let fresh = Arc::new(
            ConsoleState::new(
                history.clone(),
                LocalSession::from_secret([0x21; 32]),
                HashMap::new(),
            )
            .with_inbox(Inbox::new(
                history.clone(),
                Arc::new(HttpApprovalGateway::new(
                    format!("127.0.0.1:{port}").parse().unwrap(),
                    read_token_file(&dir.join("approver-api.token")).unwrap(),
                )),
                ApproverSigner::from_file("local-approver", &dir.join("approver.key")).unwrap(),
                trust.clone(),
            )),
        );
        let fresh_app = ConsoleState::router_from(Arc::clone(&fresh));
        let (_, list, text) = call(&fresh_app, inbox_request()).await;
        let items = list["solicitudes"].as_array().unwrap();
        assert_eq!(items.len(), 1, "{text}");
        assert_eq!(items[0]["situacion"], "aprobado, pendiente de ejecución");
        assert_eq!(items[0]["puede_aprobar"], false);
        assert_eq!(items[0]["puede_rechazar"], false);
        assert_eq!(items[0]["puede_ejecutar"], true);
        let again = items[0]["referencia"].as_str().unwrap().to_owned();
        assert_ne!(again, reload);
        // The old console's reference means nothing to the new one.
        let (stale, _, _) = call(
            &fresh_app,
            action(&format!("/api/bandeja/{reload}/ejecutar")),
        )
        .await;
        assert_eq!(stale, StatusCode::NOT_FOUND);
        let (_, refused, _) =
            call(&fresh_app, action(&format!("/api/bandeja/{again}/aprobar"))).await;
        assert_eq!(refused["situacion"], "sin cambios");
        let (_, executed, text) = call(
            &fresh_app,
            action(&format!("/api/bandeja/{again}/ejecutar")),
        )
        .await;
        assert_eq!(executed["situacion"], "aprobado", "{text}");

        // Expiry: the window (30 s in the demo) closes with no decision.
        let expire_id = held_demo(&dir, "vencer");
        let (_, list, _) = call(&fresh_app, inbox_request()).await;
        let late = list["solicitudes"][0]["referencia"]
            .as_str()
            .unwrap()
            .to_owned();
        thread::sleep(Duration::from_secs(32));
        let (_, list, text) = call(&fresh_app, inbox_request()).await;
        assert_eq!(list["solicitudes"].as_array().unwrap().len(), 0, "{text}");
        assert_eq!(list["vencidas"], 1, "{text}");
        let (_, expired, text) =
            call(&fresh_app, action(&format!("/api/bandeja/{late}/aprobar"))).await;
        assert_eq!(expired["situacion"], "expirado", "{text}");
        assert_eq!(expired["puede_ejecutar"], false);
        // The gateway recorded the expiry: it is no longer pending at all.
        let (_, list, _) = call(&fresh_app, inbox_request()).await;
        assert_eq!(list["vencidas"], 0);
        assert_eq!(list["solicitudes"].as_array().unwrap().len(), 0);
        drop(fresh_app);
        drop(fresh);
        (reload_id, expire_id)
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
    let (reloaded, _) = row(reload_id);
    assert!(
        ["executed", "confirmed"].contains(&reloaded.as_str()),
        "{reloaded}"
    );
    assert_eq!(
        row(expire_id),
        (
            "not_dispatched".to_owned(),
            Some("approval_expired".to_owned())
        )
    );
    drop(gateway);
    drop(state);
    let _ = fs::remove_dir_all(&root);
}

/// The `praetore-verify` this workspace builds, found the same way as the
/// CLI's own tests find it.
#[path = "../src/sibling_binary.rs"]
mod sibling_binary;

fn run(command: &mut Command, what: &str) -> Output {
    ok(command.output().unwrap(), what)
}

/// `sha256sum -c` where it exists (Linux), `shasum -a 256 -c` otherwise.
fn check_sums(dir: &Path) -> Output {
    let mut sha256sum = Command::new("sha256sum");
    sha256sum.args(["-c", "SHA256SUMS"]).current_dir(dir);
    match sha256sum.output() {
        Ok(output) => output,
        Err(_) => Command::new("shasum")
            .args(["-a", "256", "-c", "SHA256SUMS"])
            .current_dir(dir)
            .output()
            .unwrap(),
    }
}

fn pack_request() -> Request<Body> {
    Request::builder()
        .header(header::HOST, "127.0.0.1:8090")
        .uri("/api/paquete")
        .header(header::AUTHORIZATION, auth())
        .header(ACTION_HEADER, "1")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
}

/// D3 and D3.1 end to end: real decisions through the gateway (one approved
/// and executed, one rejected, one approved and not executed, one left
/// pending), then the console's compliance package. Its journal must be byte
/// for byte what `praetore journal-export --tenant` writes for the same
/// database, and the unpacked package must verify with the workspace's
/// `praetore-verify` (journal, policy digest, `--policy`, `--expected-head`,
/// and `outcomes` over approvals.jsonl, each outcome matching its request of
/// the journal) and with `sha256sum -c`. No key file of `praetore init` may
/// appear in it.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_console_compliance_pack_verifies_with_praetore_verify() {
    let admin_url = std::env::var("PRAETORE_TEST_DATABASE_URL")
        .expect("PRAETORE_TEST_DATABASE_URL is required");
    let runtime_url = provision(&admin_url);
    let root = std::env::temp_dir().join(format!("praetore-console-pack-{}", Uuid::new_v4()));
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
    let mut policy: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("policy.json")).unwrap()).unwrap();
    policy["rules"][0]["effect"] = "RequireApproval".into();
    fs::write(dir.join("policy.json"), policy.to_string()).unwrap();
    // The attester pin `praetore init` wrote, as an operator would hand it out.
    let pin = root.join("attester-public-key.hex");
    fs::copy(dir.join("attester-public-key.hex"), &pin).unwrap();
    // D3.1: the execution and approver pins `praetore init` wrote, as an
    // operator would hand them out. The execution pin names the key id
    // `praetore run` signs with.
    let execution_pin = root.join("execution-pin.json");
    fs::copy(dir.join("execution-pin.json"), &execution_pin).unwrap();
    let approver_pin = root.join("approver-pin.json");
    fs::copy(dir.join("approver-pin.json"), &approver_pin).unwrap();

    let gateway = Gateway::start(&dir, &admin_url, &runtime_url);
    let port = config(&dir)["port"].as_u64().unwrap() as u16;
    let approved_id = held_demo(&dir, "aprobar");
    let rejected_id = held_demo(&dir, "rechazar");
    let not_run_id = held_demo(&dir, "aprobar-sin-ejecutar");

    let trust =
        EvidenceTrust::load(&dir.join("policy.json"), std::slice::from_ref(&pin), None).unwrap();
    let client = postgres::Client::connect(&runtime_url, postgres::NoTls).unwrap();
    let history = Arc::new(
        PostgresHistory::from_client(client, tenant)
            .unwrap()
            .with_attester_pins(trust.pins()),
    );
    let state = Arc::new(
        ConsoleState::new(
            history.clone(),
            LocalSession::from_secret([0x21; 32]),
            HashMap::new(),
        )
        .with_inbox(Inbox::new(
            history.clone(),
            Arc::new(HttpApprovalGateway::new(
                format!("127.0.0.1:{port}").parse().unwrap(),
                read_token_file(&dir.join("approver-api.token")).unwrap(),
            )),
            ApproverSigner::from_file("local-approver", &dir.join("approver.key")).unwrap(),
            trust.clone(),
        ))
        .with_compliance_pack(CompliancePack::new(
            PackSettings::new(dir.join("policy.json"), vec![pin.clone()])
                .unwrap()
                .with_outcome_pins(vec![execution_pin.clone()], vec![approver_pin.clone()])
                .unwrap(),
            history.clone(),
        )),
    );
    let app = ConsoleState::router_from(Arc::clone(&state));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    // The same database through a console with no execution or approver
    // pin configured gets the D3 package.
    let d3_state = Arc::new(
        ConsoleState::new(
            history.clone(),
            LocalSession::from_secret([0x21; 32]),
            HashMap::new(),
        )
        .with_compliance_pack(CompliancePack::new(
            PackSettings::new(dir.join("policy.json"), vec![pin.clone()]).unwrap(),
            history.clone(),
        )),
    );
    let d3_app = ConsoleState::router_from(Arc::clone(&d3_state));
    let (pack, missing_policy, pending_id, d3_pack) = runtime.block_on(async {
        let (_, list, text) = call(&app, inbox_request()).await;
        let items = list["solicitudes"].as_array().unwrap();
        assert_eq!(items.len(), 3, "{text}");
        let first = items[2]["referencia"].as_str().unwrap().to_owned();
        let second = items[1]["referencia"].as_str().unwrap().to_owned();
        let third = items[0]["referencia"].as_str().unwrap().to_owned();
        let (_, approved, text) =
            call(&app, action(&format!("/api/bandeja/{first}/aprobar"))).await;
        assert_eq!(
            approved["situacion"], "aprobado, pendiente de ejecución",
            "{text}"
        );
        let (_, executed, text) =
            call(&app, action(&format!("/api/bandeja/{first}/ejecutar"))).await;
        assert_eq!(executed["situacion"], "aprobado", "{text}");
        let (_, rejected, text) =
            call(&app, action(&format!("/api/bandeja/{second}/rechazar"))).await;
        assert_eq!(rejected["situacion"], "rechazado", "{text}");
        // Approved, never executed.
        let (_, approved, text) =
            call(&app, action(&format!("/api/bandeja/{third}/aprobar"))).await;
        assert_eq!(
            approved["situacion"], "aprobado, pendiente de ejecución",
            "{text}"
        );
        // One more left pending: its receipt is in the journal too.
        let pending_id = held_demo(&dir, "pendiente");

        let response = app.clone().oneshot(pack_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/gzip");
        let pack = to_bytes(response.into_body(), 64 << 20)
            .await
            .unwrap()
            .to_vec();

        // A piece missing: no package, a plain message.
        fs::rename(dir.join("policy.json"), root.join("policy.json.aside")).unwrap();
        let response = app.clone().oneshot(pack_request()).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        fs::rename(root.join("policy.json.aside"), dir.join("policy.json")).unwrap();
        let message: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        let response = d3_app.clone().oneshot(pack_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let d3_pack = to_bytes(response.into_body(), 64 << 20)
            .await
            .unwrap()
            .to_vec();
        (pack, (status, message), pending_id, d3_pack)
    });
    drop(runtime);
    drop(app);
    drop(d3_app);
    assert_eq!(missing_policy.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        missing_policy.1["mensaje"],
        "No se pudo leer la política configurada en la consola. No se generó ningún paquete."
    );

    // Unpacked with the system's tar.
    let archive = root.join("praetore-compliance.tar.gz");
    fs::write(&archive, &pack).unwrap();
    let unpacked = root.join("unpacked");
    fs::create_dir_all(&unpacked).unwrap();
    run(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&unpacked),
        "tar -xzf",
    );
    let pack_dir = unpacked.join("praetore-compliance");
    let mut names: Vec<String> = fs::read_dir(&pack_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "LEEME.txt",
            "SHA256SUMS",
            "approvals.jsonl",
            "approver-pin-1.json",
            "attester-pin-1.hex",
            "execution-pin-1.json",
            "export.json",
            "journal.jsonl",
            "policy-digest.txt",
            "policy.json",
        ]
    );
    let sums = check_sums(&pack_dir);
    assert!(
        sums.status.success(),
        "SHA256SUMS: {}{}",
        String::from_utf8_lossy(&sums.stdout),
        String::from_utf8_lossy(&sums.stderr)
    );

    // The same chain `praetore journal-export --tenant` writes.
    let cli_export = root.join("cli-export.jsonl");
    run(
        Command::new(PRAETORE)
            .args(["journal-export", "--tenant", &tenant.to_string()])
            .arg("--attester-pin")
            .arg(&pin)
            .arg("--output")
            .arg(&cli_export)
            .env("PRAETORE_GATEWAY_DATABASE_URL", &runtime_url),
        "praetore journal-export --tenant",
    );
    let journal = fs::read(pack_dir.join("journal.jsonl")).unwrap();
    assert_eq!(journal, fs::read(&cli_export).unwrap());

    let export: serde_json::Value =
        serde_json::from_slice(&fs::read(pack_dir.join("export.json")).unwrap()).unwrap();
    assert_eq!(export["tenant_id"], tenant.to_string());
    let head = export["journal"]["head"].as_str().unwrap().to_owned();

    // `praetore-verify` built from this workspace, inside the package.
    let verify = sibling_binary::sibling_binary("praetore-verify");
    let verified = run(
        Command::new(&verify)
            .args([
                "journal",
                "--journal",
                "journal.jsonl",
                "--attester-pin",
                "attester-pin-1.hex",
                "--format",
                "json",
            ])
            .current_dir(&pack_dir),
        "praetore-verify journal",
    );
    let verified: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verified["ok"], true, "{verified}");
    assert_eq!(
        verified["details"]["tenant_id"],
        tenant.to_string(),
        "{verified}"
    );
    assert_eq!(
        verified["details"]["entries"], export["journal"]["entries"],
        "{verified}"
    );
    // Approved and executed, rejected, pending: at least three receipts.
    assert!(
        export["journal"]["entries"].as_u64().unwrap() >= 3,
        "{export}"
    );
    // Without storage records there is no reference line: every line is a
    // decision receipt, and LEEME.txt says how many.
    assert_eq!(export["journal"]["database_head"], serde_json::Value::Null);
    let receipts = export["journal"]["decision_receipts"].as_u64().unwrap();
    assert_eq!(receipts, export["journal"]["entries"].as_u64().unwrap());
    let readme = fs::read_to_string(pack_dir.join("LEEME.txt")).unwrap();
    assert!(readme.contains(&format!("Tiene {receipts} recibos de decisión.")));
    let anchored = run(
        Command::new(&verify)
            .args([
                "journal",
                "--journal",
                "journal.jsonl",
                "--attester-pin",
                "attester-pin-1.hex",
                "--expected-head",
                &head,
                "--policy",
                "policy.json",
                "--format",
                "json",
            ])
            .current_dir(&pack_dir),
        "praetore-verify journal --expected-head --policy",
    );
    let anchored: serde_json::Value = serde_json::from_slice(&anchored.stdout).unwrap();
    assert_eq!(anchored["ok"], true, "{anchored}");
    let digest = run(
        Command::new(&verify)
            .args([
                "policy-digest",
                "--policy",
                "policy.json",
                "--format",
                "json",
            ])
            .current_dir(&pack_dir),
        "praetore-verify policy-digest",
    );
    let digest: serde_json::Value = serde_json::from_slice(&digest.stdout).unwrap();
    assert_eq!(
        format!("{}\n", digest["details"]["digest"].as_str().unwrap()),
        fs::read_to_string(pack_dir.join("policy-digest.txt")).unwrap()
    );
    // An altered journal no longer verifies.
    let mut altered = String::from_utf8(journal.clone()).unwrap();
    let at = altered.find("demo:set_value").unwrap();
    altered.replace_range(at..at + 4, "dema");
    fs::write(pack_dir.join("altered.jsonl"), altered).unwrap();
    let refused = Command::new(&verify)
        .args([
            "journal",
            "--journal",
            "altered.jsonl",
            "--attester-pin",
            "attester-pin-1.hex",
        ])
        .current_dir(&pack_dir)
        .output()
        .unwrap();
    assert!(!refused.status.success());

    // D3.1: every approval, rejection and execution receipt verifies, and
    // each held request of the journal ends as it did.
    let outcomes_args = [
        "outcomes",
        "--outcomes",
        "approvals.jsonl",
        "--journal",
        "journal.jsonl",
        "--attester-pin",
        "attester-pin-1.hex",
        "--execution-pin",
        "execution-pin-1.json",
        "--approver-pin",
        "approver-pin-1.json",
        "--format",
        "json",
    ];
    let readme_folded = readme.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        readme_folded.contains(&outcomes_args[..11].join(" ")),
        "LEEME.txt gives the outcomes command"
    );
    let outcomes = run(
        Command::new(&verify)
            .args(outcomes_args)
            .current_dir(&pack_dir),
        "praetore-verify outcomes",
    );
    let outcomes: serde_json::Value = serde_json::from_slice(&outcomes.stdout).unwrap();
    assert_eq!(outcomes["ok"], true, "{outcomes}");
    let details = &outcomes["details"];
    assert_eq!(details["tenant_id"], tenant.to_string(), "{outcomes}");
    let ends: HashMap<String, String> = details["held"]
        .as_array()
        .unwrap()
        .iter()
        .map(|held| {
            (
                held["request_id"].as_str().unwrap().to_owned(),
                held["outcome"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    for (request, end) in [
        (approved_id, "approved_executed"),
        (rejected_id, "rejected"),
        (not_run_id, "approved_pending_dispatch"),
        (pending_id, "pending"),
    ] {
        assert_eq!(
            ends.get(&request.to_string()).map(String::as_str),
            Some(end),
            "{request}: {outcomes}"
        );
    }
    // Each held row is a request of journal.jsonl (by evidence_id), and
    // every held request of the journal has its row.
    let journal_text = String::from_utf8(journal.clone()).unwrap();
    for held in details["held"].as_array().unwrap() {
        let evidence_id = held["evidence_id"].as_str().unwrap();
        assert!(
            journal_text.contains(&format!("\"evidence_id\":\"{evidence_id}\"")),
            "{evidence_id} not in journal.jsonl"
        );
    }
    assert_eq!(details["held"].as_array().unwrap().len(), 4, "{outcomes}");
    assert_eq!(details["counts"]["approvals"], 2, "{outcomes}");
    assert_eq!(details["counts"]["rejections"], 1, "{outcomes}");
    assert_eq!(details["counts"]["expirations"], 0, "{outcomes}");
    assert_eq!(
        details["counts"]["execution_receipts_by_state"]["awaiting_approval"], 4,
        "{outcomes}"
    );
    assert_eq!(
        details["counts"]["execution_receipts_by_state"]["not_dispatched"], 1,
        "{outcomes}"
    );
    assert_eq!(details["unused_execution_pins"], serde_json::json!([]));
    assert_eq!(details["unused_approver_pins"], serde_json::json!([]));
    // export.json counts what the verifier counts.
    for field in [
        "approvals",
        "rejections",
        "expirations",
        "execution_receipts",
    ] {
        assert_eq!(
            export["outcomes"][field], details["counts"][field],
            "{field}"
        );
    }
    assert_eq!(
        export["outcomes"]["execution_receipts_by_state"],
        details["counts"]["execution_receipts_by_state"]
    );
    assert_eq!(
        export["outcomes"]["held_by_outcome"],
        details["held_by_outcome"]
    );
    let lines = fs::read_to_string(pack_dir.join("approvals.jsonl"))
        .unwrap()
        .lines()
        .count() as u64;
    assert_eq!(export["outcomes"]["records"], lines);
    // A decision flipped after signing, or a missing approver pin: refused.
    let approvals = fs::read_to_string(pack_dir.join("approvals.jsonl")).unwrap();
    let flipped = approvals.replacen("\"outcome\":\"reject\"", "\"outcome\":\"approve\"", 1);
    assert_ne!(flipped, approvals);
    fs::write(pack_dir.join("flipped.jsonl"), flipped).unwrap();
    let mut flipped_args = outcomes_args;
    flipped_args[2] = "flipped.jsonl";
    let refused = Command::new(&verify)
        .args(flipped_args)
        .current_dir(&pack_dir)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    let refused: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(refused["code"], "OUTCOME_SIGNATURE_INVALID", "{refused}");
    let refused = Command::new(&verify)
        .args(&outcomes_args[..9])
        .args(["--format", "json"])
        .current_dir(&pack_dir)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    let refused: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(refused["code"], "OUTCOME_KEY_UNKNOWN", "{refused}");

    // The console without execution or approver pins: the D3 package,
    // the same journal, no approvals.jsonl, and it still verifies.
    let d3_archive = root.join("d3.tar.gz");
    fs::write(&d3_archive, &d3_pack).unwrap();
    let d3_unpacked = root.join("d3");
    fs::create_dir_all(&d3_unpacked).unwrap();
    run(
        Command::new("tar")
            .arg("-xzf")
            .arg(&d3_archive)
            .arg("-C")
            .arg(&d3_unpacked),
        "tar -xzf (D3)",
    );
    let d3_dir = d3_unpacked.join("praetore-compliance");
    let mut d3_names: Vec<String> = fs::read_dir(&d3_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    d3_names.sort();
    assert_eq!(
        d3_names,
        [
            "LEEME.txt",
            "SHA256SUMS",
            "attester-pin-1.hex",
            "export.json",
            "journal.jsonl",
            "policy-digest.txt",
            "policy.json",
        ]
    );
    assert!(check_sums(&d3_dir).status.success());
    assert_eq!(fs::read(d3_dir.join("journal.jsonl")).unwrap(), journal);
    let d3_export: serde_json::Value =
        serde_json::from_slice(&fs::read(d3_dir.join("export.json")).unwrap()).unwrap();
    assert_eq!(d3_export["outcomes"]["included"], false, "{d3_export}");
    let d3_readme = fs::read_to_string(d3_dir.join("LEEME.txt")).unwrap();
    assert!(!d3_readme.contains("approvals.jsonl"));
    assert!(d3_readme.contains("No muestra si una solicitud retenida fue aprobada"));
    let d3_verified = run(
        Command::new(&verify)
            .args([
                "journal",
                "--journal",
                "journal.jsonl",
                "--attester-pin",
                "attester-pin-1.hex",
                "--expected-head",
                &head,
                "--format",
                "json",
            ])
            .current_dir(&d3_dir),
        "praetore-verify journal (D3 package)",
    );
    let d3_verified: serde_json::Value = serde_json::from_slice(&d3_verified.stdout).unwrap();
    assert_eq!(d3_verified["ok"], true, "{d3_verified}");
    assert_eq!(export["outcomes"]["included"], true);
    assert_eq!(export["outcomes"]["omitted_execution_pins"], 0);
    assert_eq!(export["outcomes"]["omitted_approver_pins"], 0);
    // The execution pin in the package is the one `praetore init` wrote.
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &fs::read(pack_dir.join("execution-pin-1.json")).unwrap()
        )
        .unwrap(),
        serde_json::from_slice::<serde_json::Value>(&fs::read(&execution_pin).unwrap()).unwrap()
    );

    // No secret of `praetore init` is in the package.
    let mut everything = Vec::new();
    for name in &names {
        everything.extend(fs::read(pack_dir.join(name)).unwrap());
    }
    let everything = String::from_utf8(everything).unwrap();
    for secret_file in [
        "approver.key",
        "evidence-attester.key",
        "execution-attester.key",
        "approver-api.token",
        "agent-api.token",
    ] {
        let path = dir.join(secret_file);
        let Ok(value) = fs::read_to_string(&path) else {
            continue;
        };
        let value = value.trim();
        assert!(value.len() >= 32, "{secret_file}");
        assert!(
            !everything.contains(value),
            "{secret_file} is in the package"
        );
    }

    drop(gateway);
    drop(state);
    drop(d3_state);
    let _ = fs::remove_dir_all(&root);
}
