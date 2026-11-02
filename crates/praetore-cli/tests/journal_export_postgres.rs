//! End to end: two local gateways (`praetore run`, two tenants) write real
//! signed receipts to one PostgreSQL journal, `praetore journal-export
//! --tenant` exports one tenant, and `praetore-verify journal` checks it.
//! Every step runs the real binaries as subprocesses. The gateways and the
//! export connect as a login member of `praetore_runtime` (migration 0011);
//! only migrations use the admin URL.
//!
//! Needs `PRAETORE_TEST_DATABASE_URL` (a role that can CREATE ROLE and
//! CREATE DATABASE) and the verifier built in the same profile: `cargo build
//! -p praetore-verify --locked`.
//!
//! Each gateway gets its own port (chosen with every probe listener held, so
//! two ports never coincide) and is ready only when it accepts this
//! directory's agent token: an unauthenticated `/healthz` would also be
//! answered by another gateway that happens to listen on that port. A
//! gateway that loses its port before binding it is restarted on a new one.

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

const PRAETORE: &str = env!("CARGO_BIN_EXE_praetore");
const RUNTIME_LOGIN: &str = "praetore_export_cli_runtime";
const RUNTIME_PASSWORD: &str = "praetore-export-cli-test";

fn verifier() -> PathBuf {
    let path = Path::new(PRAETORE)
        .with_file_name(format!("praetore-verify{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.is_file(),
        "{} is missing: run `cargo build -p praetore-verify --locked` first",
        path.display()
    );
    path
}

/// The tests of this file share one cluster-wide login role; concurrent
/// `ALTER ROLE`s of it would fail with "tuple concurrently updated".
static PROVISION: Mutex<()> = Mutex::new(());

/// Applies migrations as the admin role and returns the URL of a LOGIN member
/// of `praetore_runtime` on the same server and database.
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

fn praetore(args: &[&str], database_url: Option<&str>) -> Output {
    let mut command = Command::new(PRAETORE);
    command
        .args(args)
        .env_remove("PRAETORE_GATEWAY_DATABASE_URL");
    if let Some(url) = database_url {
        command.env("PRAETORE_GATEWAY_DATABASE_URL", url);
    }
    command.output().unwrap()
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

/// `N` distinct free loopback ports. Every probe listener stays bound until
/// all ports are chosen, so the kernel cannot hand out the same port twice
/// (two independent bind-and-close probes can). A port may still be taken
/// by another process before the gateway binds it; `Gateway::start` then
/// restarts the gateway on a new port.
fn free_ports<const N: usize>() -> [u16; N] {
    let listeners: Vec<TcpListener> = (0..N)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    std::array::from_fn(|index| listeners[index].local_addr().unwrap().port())
}

fn config(dir: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(dir.join("config.json")).unwrap()).unwrap()
}

fn set_port(dir: &Path, port: u16) {
    let mut value = config(dir);
    value["port"] = port.into();
    fs::write(dir.join("config.json"), value.to_string()).unwrap();
}

/// `praetore run <dir>`; killed on drop.
struct Gateway {
    child: Child,
    log: PathBuf,
}

/// How many times a gateway that could not bind its port is restarted.
const BIND_ATTEMPTS: usize = 5;

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Gateway {
    fn start(dir: &Path, admin_url: &str, runtime_url: &str) -> Self {
        for attempt in 1..=BIND_ATTEMPTS {
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
                    if log.contains("Address already in use") && attempt < BIND_ATTEMPTS {
                        eprintln!("port {port} was taken before the gateway bound it; retrying");
                        let [port] = free_ports();
                        set_port(dir, port);
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

/// Whether the gateway of `dir` is the one listening on `port`: an
/// authenticated, read-only status query with `dir`'s agent token and
/// tenant. Another gateway (another directory's tokens) answers 401 or 403;
/// nothing listening is not ready.
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

fn init(dir: &Path, port: u16) -> Uuid {
    ok(
        praetore(
            &["init", dir.to_str().unwrap(), "--port", &port.to_string()],
            None,
        ),
        "praetore init",
    );
    Uuid::parse_str(config(dir)["tenant_id"].as_str().unwrap()).unwrap()
}

/// `praetore demo <dir> set <key> <value>` through the running gateway;
/// returns the receipt's `request_id`.
fn demo(dir: &Path, key: &str) -> String {
    let output = ok(
        praetore(&["demo", dir.to_str().unwrap(), "set", key, "v"], None),
        "praetore demo",
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["authorization"], "allowed", "{receipt}");
    assert!(receipt["evidence"]["attester_signature"].is_string());
    receipt["evidence"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn export(tenant: Uuid, pin: &Path, output: &Path, database_url: Option<&str>) -> Output {
    export_with_pins(Some(tenant), &[pin], output, database_url)
}

/// `journal-export --tenant` (or `--database` without a tenant) with one
/// `--attester-pin` per pin.
fn export_with_pins(
    tenant: Option<Uuid>,
    pins: &[&Path],
    output: &Path,
    database_url: Option<&str>,
) -> Output {
    let tenant = tenant.map(|tenant| tenant.to_string());
    let mut args = vec!["journal-export"];
    match &tenant {
        Some(tenant) => args.extend(["--tenant", tenant.as_str()]),
        None => args.push("--database"),
    }
    for pin in pins {
        args.extend(["--attester-pin", pin.to_str().unwrap()]);
    }
    args.extend(["--output", output.to_str().unwrap()]);
    praetore(&args, database_url)
}

fn verify(journal: &Path, pin: &Path, expected_head: Option<&str>) -> Output {
    let mut extra = Vec::new();
    if let Some(head) = expected_head {
        extra.extend(["--expected-head", head]);
    }
    verify_with_pins(journal, &[pin], &extra)
}

fn verify_with_pins(journal: &Path, pins: &[&Path], extra: &[&str]) -> Output {
    let mut command = Command::new(verifier());
    command.args(["journal", "--journal"]).arg(journal);
    for pin in pins {
        command.arg("--attester-pin").arg(pin);
    }
    command.args(extra).args(["--format", "json"]);
    command.output().unwrap()
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

/// `request_id` of every entry of a chain file, in order.
fn chain_request_ids(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| {
            let entry: serde_json::Value = serde_json::from_str(line).unwrap();
            entry["evidence"]["request_id"].as_str().unwrap().to_owned()
        })
        .collect()
}

fn assert_rejected(output: &Output, what: &str) {
    assert!(!output.status.success(), "{what} was accepted");
    let code = json(output)["code"].as_str().unwrap_or_default().to_owned();
    assert!(
        ["JOURNAL_CHAIN_FAIL", "EVIDENCE_FAIL", "AUTH_FAIL"].contains(&code.as_str()),
        "{what}: unexpected code {code:?}"
    );
    assert!(!output.stderr.is_empty(), "{what}: no message on stderr");
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL and a built praetore-verify"]
fn postgres_cli_journal_export_tenant_end_to_end() {
    let admin_url = std::env::var("PRAETORE_TEST_DATABASE_URL").unwrap();
    let runtime_url = provision(&admin_url);
    let work = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("praetore-journal-e2e-{}", Uuid::new_v4()));
    fs::create_dir(&work).unwrap();
    let (dir_a, dir_b) = (work.join("a"), work.join("b"));
    let [port_a, port_b] = free_ports();
    let tenant_a = init(&dir_a, port_a);
    let tenant_b = init(&dir_b, port_b);
    assert_ne!(tenant_a, tenant_b);
    // One attester key for both tenants, so a leaked row of B would still
    // verify and only the tenant isolation can keep it out of A's export.
    fs::copy(
        dir_a.join("evidence-attester.key"),
        dir_b.join("evidence-attester.key"),
    )
    .unwrap();
    let secret: [u8; 32] = hex::decode(
        fs::read_to_string(dir_a.join("evidence-attester.key"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let pin = work.join("attester-public-key.hex");
    fs::write(
        &pin,
        hex::encode(
            praetore_core::EvidenceAttesterKey::from_secret_bytes(&secret)
                .public_key()
                .unwrap()
                .as_bytes(),
        ),
    )
    .unwrap();

    // Interleaved writes: A, B, A, B, A.
    let (mut ids_a, mut ids_b) = (Vec::new(), Vec::new());
    {
        let gateway_a = Gateway::start(&dir_a, &admin_url, &runtime_url);
        let gateway_b = Gateway::start(&dir_b, &admin_url, &runtime_url);
        for round in 0..3 {
            ids_a.push(demo(&dir_a, &format!("a{round}")));
            if round < 2 {
                ids_b.push(demo(&dir_b, &format!("b{round}")));
            }
        }
        // The gateways ran as the least-privilege role without complaint.
        for gateway in [&gateway_a, &gateway_b] {
            assert!(
                !gateway.log().contains("not least-privilege"),
                "{}",
                gateway.log()
            );
        }
    }

    // Export A as the runtime role.
    let out_a = work.join("a.jsonl");
    let exported = ok(
        export(tenant_a, &pin, &out_a, Some(&runtime_url)),
        "journal-export A",
    );
    assert!(
        exported.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let summary = json(&exported);
    assert_eq!(summary["entries"], 3);
    let head_a = summary["head"].as_str().unwrap().to_owned();
    // Only A's receipts, all of them, in the order they were written.
    assert_eq!(chain_request_ids(&out_a), ids_a);

    // The real verifier accepts it, with the head the export reported.
    let verified = ok(
        verify(&out_a, &pin, Some(&head_a)),
        "praetore-verify journal",
    );
    let verified = json(&verified);
    assert_eq!(verified["ok"], true);
    assert_eq!(verified["details"]["entries"], 3, "{verified}");
    assert_eq!(verified["details"]["head"], head_a.as_str());

    // B exports its own two receipts, which verify against the same pin.
    let out_b = work.join("b.jsonl");
    let summary_b = json(&ok(
        export(tenant_b, &pin, &out_b, Some(&runtime_url)),
        "journal-export B",
    ));
    assert_eq!(summary_b["entries"], 2);
    assert_eq!(chain_request_ids(&out_b), ids_b);
    ok(verify(&out_b, &pin, summary_b["head"].as_str()), "verify B");

    // The admin (owner or superuser) export is the same file, and warns that
    // row-level security may not apply to it.
    let out_admin = work.join("a-admin.jsonl");
    let admin_export = ok(
        export(tenant_a, &pin, &out_admin, Some(&admin_url)),
        "journal-export A as admin",
    );
    assert_eq!(fs::read(&out_admin).unwrap(), fs::read(&out_a).unwrap());
    assert!(String::from_utf8_lossy(&admin_export.stderr).contains("warning:"));

    // Tampering with one line is rejected: one changed byte of a receipt...
    let text = fs::read_to_string(&out_a).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let altered = lines[1].replacen(&ids_a[1], &ids_a[1].replacen('-', "_", 1), 1);
    assert_ne!(altered, lines[1]);
    let tampered = work.join("tampered.jsonl");
    fs::write(
        &tampered,
        format!("{}\n{altered}\n{}\n", lines[0], lines[2]),
    )
    .unwrap();
    assert_rejected(&verify(&tampered, &pin, None), "altered receipt");
    let swapped = lines[1].replacen(&ids_a[1], &ids_a[2], 1);
    fs::write(
        &tampered,
        format!("{}\n{swapped}\n{}\n", lines[0], lines[2]),
    )
    .unwrap();
    assert_rejected(&verify(&tampered, &pin, None), "replaced request_id");
    // ...and so is a deleted line.
    fs::write(&tampered, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
    assert_rejected(&verify(&tampered, &pin, None), "deleted entry");
    // A head from another export is not accepted either.
    let mismatch = verify(&out_a, &pin, summary_b["head"].as_str());
    assert!(!mismatch.status.success());
    assert_eq!(json(&mismatch)["code"], "JOURNAL_HEAD_MISMATCH");

    // An existing --output is never overwritten.
    let again = export(tenant_a, &pin, &out_a, Some(&runtime_url));
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("cannot create"));
    assert_eq!(fs::read_to_string(&out_a).unwrap(), text);

    // A tenant with no rows, or no database URL, exports nothing.
    let none = work.join("none.jsonl");
    assert!(
        !export(Uuid::new_v4(), &pin, &none, Some(&runtime_url))
            .status
            .success()
    );
    assert!(!export(tenant_a, &pin, &none, None).status.success());
    assert!(!none.exists());

    fs::remove_dir_all(&work).unwrap();
}

/// A throwaway database on the test server, dropped (with its sessions) on
/// drop.
struct ScratchDatabase {
    admin_url: String,
    name: String,
    url: String,
}

impl ScratchDatabase {
    fn create(admin_url: &str) -> Self {
        let name = format!("praetore_rotation_{}", Uuid::new_v4().simple());
        postgres::Client::connect(admin_url, postgres::NoTls)
            .unwrap()
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .unwrap();
        let (prefix, _) = admin_url
            .split_once('?')
            .map_or(admin_url, |(base, _)| base)
            .rsplit_once('/')
            .unwrap();
        let query = admin_url
            .split_once('?')
            .map(|(_, query)| format!("?{query}"))
            .unwrap_or_default();
        Self {
            admin_url: admin_url.to_owned(),
            url: format!("{prefix}/{name}{query}"),
            name,
        }
    }
}

impl Drop for ScratchDatabase {
    fn drop(&mut self) {
        if let Ok(mut admin) = postgres::Client::connect(&self.admin_url, postgres::NoTls) {
            let _ = admin.batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            ));
        }
    }
}

fn write_pin(path: &Path, key: &praetore_core::EvidenceAttesterKey) {
    fs::write(path, hex::encode(key.public_key().unwrap().as_bytes())).unwrap();
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// B5-5: a legacy baseline adopted with attester key A, then the attester
/// key rotated to B (a new `praetore init` key) and new receipts written.
/// The adoption record keeps A's signature (it is never re-signed). With
/// the pins {A, B}, `journal-export --database` and `--tenant` succeed and
/// `praetore-verify journal` verifies both chains. With only {B}, every
/// step that has to verify the adoption record fails and names A's key;
/// the tenant file alone verifies with {B}, because it holds only receipts
/// signed by B (its database reference is unsigned and proves nothing
/// without the database chain).
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL and a built praetore-verify"]
fn postgres_cli_journal_export_after_attester_key_rotation() {
    let base_url = std::env::var("PRAETORE_TEST_DATABASE_URL").unwrap();
    let scratch = ScratchDatabase::create(&base_url);
    let admin_url = scratch.url.clone();
    let work = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("praetore-journal-rotation-{}", Uuid::new_v4()));
    fs::create_dir(&work).unwrap();

    // Adoption with key A: a database migrated by the pre-runner code.
    let key_a = praetore_core::EvidenceAttesterKey::from_secret_bytes(&[61; 32]);
    {
        let mut admin = postgres::Client::connect(&admin_url, postgres::NoTls).unwrap();
        for (_, sql) in &praetore_replay_postgres::MIGRATIONS[..9] {
            admin.batch_execute(sql).unwrap();
        }
        praetore_replay_postgres::apply_migrations_with(
            &mut admin,
            &praetore_replay_postgres::MigrationOptions {
                adopt_legacy_baseline: true,
                record_signer: Some(std::sync::Arc::new(
                    praetore_core::EvidenceAttesterKey::from_secret_bytes(&[61; 32]),
                )),
                ..Default::default()
            },
        )
        .unwrap();
    }
    let runtime_url = provision(&admin_url);
    let stored_record = || -> String {
        postgres::Client::connect(&admin_url, postgres::NoTls)
            .unwrap()
            .query_one(
                "SELECT string_agg(record_json, '|' ORDER BY created_at) \
                 FROM praetore.storage_records",
                &[],
            )
            .unwrap()
            .get(0)
    };
    let record_before = stored_record();
    assert!(record_before.contains(&key_a.key_id()), "{record_before}");

    // Rotation: the gateway now signs with key B, generated by `init`.
    let dir = work.join("rotated");
    let [port] = free_ports();
    let tenant = init(&dir, port);
    let secret_b: [u8; 32] = hex::decode(
        fs::read_to_string(dir.join("evidence-attester.key"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let key_b = praetore_core::EvidenceAttesterKey::from_secret_bytes(&secret_b);
    assert_ne!(key_a.key_id(), key_b.key_id());
    let (pin_a, pin_b) = (work.join("pin-a.hex"), work.join("pin-b.hex"));
    write_pin(&pin_a, &key_a);
    write_pin(&pin_b, &key_b);
    let ids = {
        let _gateway = Gateway::start(&dir, &admin_url, &runtime_url);
        vec![demo(&dir, "r0"), demo(&dir, "r1")]
    };
    let both = [pin_a.as_path(), pin_b.as_path()];

    // {A, B}: both exports succeed.
    let database = work.join("database.jsonl");
    let summary = json(&ok(
        export_with_pins(None, &both, &database, Some(&runtime_url)),
        "journal-export --database with {A, B}",
    ));
    assert_eq!(summary["kind"], "database");
    assert_eq!(summary["entries"], 1);
    let database_head = summary["head"].as_str().unwrap().to_owned();
    let tenant_chain = work.join("tenant.jsonl");
    let exported = ok(
        export_with_pins(Some(tenant), &both, &tenant_chain, Some(&runtime_url)),
        "journal-export --tenant with {A, B}",
    );
    let summary = json(&exported);
    assert_eq!(summary["kind"], "tenant");
    assert_eq!(
        summary["entries"], 3,
        "the database reference and 2 receipts"
    );
    assert_eq!(summary["database_head"]["head"], database_head.as_str());
    let tenant_head = summary["head"].as_str().unwrap().to_owned();
    let lines: Vec<serde_json::Value> = fs::read_to_string(&tenant_chain)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(lines[0]["database_head"].is_object());
    let exported_ids: Vec<&str> = lines[1..]
        .iter()
        .map(|line| line["evidence"]["request_id"].as_str().unwrap())
        .collect();
    assert_eq!(exported_ids, ids);
    for line in &lines[1..] {
        assert_eq!(line["evidence"]["attester_key_id"], key_b.key_id().as_str());
    }
    // The record in the file and in the table is the one A signed.
    let record_line: serde_json::Value =
        serde_json::from_str(fs::read_to_string(&database).unwrap().trim()).unwrap();
    assert_eq!(record_line["record"]["key_id"], key_a.key_id().as_str());
    assert_eq!(stored_record(), record_before, "never re-signed");

    // praetore-verify with {A, B}: the database chain, and the tenant chain
    // checked against it and against its anchored head.
    let verified = json(&ok(
        verify_with_pins(&database, &both, &["--expected-head", &database_head]),
        "praetore-verify database chain with {A, B}",
    ));
    assert_eq!(verified["details"]["kind"], "database");
    let verified = json(&ok(
        verify_with_pins(
            &tenant_chain,
            &both,
            &[
                "--database-journal",
                database.to_str().unwrap(),
                "--expected-head",
                &tenant_head,
            ],
        ),
        "praetore-verify tenant chain with {A, B}",
    ));
    assert_eq!(verified["details"]["kind"], "tenant");
    assert_eq!(verified["details"]["database_head_verified"], true);
    assert_eq!(verified["details"]["expected_head_verified"], true);

    // Only {B}: every step that verifies the record A signed fails, names
    // A's key and writes nothing.
    let unpinned = format!(
        "signed by attester key {}, not by a pinned key",
        key_a.key_id()
    );
    for (source, output) in [(Some(tenant), "b-tenant.jsonl"), (None, "b-database.jsonl")] {
        let output = work.join(output);
        let refused = export_with_pins(source, &[&pin_b], &output, Some(&runtime_url));
        assert!(!refused.status.success(), "{source:?} exported with only B");
        let message = stderr(&refused);
        assert!(message.contains(&unpinned), "{message}");
        assert!(message.contains("--attester-pin"), "{message}");
        assert!(!output.exists());
        eprintln!("refused as expected: {}", message.trim());
    }
    for (journal, extra) in [
        (&database, Vec::new()),
        (
            &tenant_chain,
            vec!["--database-journal", database.to_str().unwrap()],
        ),
    ] {
        let refused = verify_with_pins(journal, &[&pin_b], &extra);
        assert!(!refused.status.success());
        assert_eq!(json(&refused)["code"], "EVIDENCE_FAIL");
        assert!(stderr(&refused).contains(&unpinned), "{}", stderr(&refused));
    }
    // The tenant file alone holds only B's receipts.
    ok(
        verify_with_pins(&tenant_chain, &[&pin_b], &["--expected-head", &tenant_head]),
        "praetore-verify tenant chain alone with {B}",
    );
    // And {A} alone does not verify B's receipts.
    let refused = verify_with_pins(&tenant_chain, &[&pin_a], &[]);
    assert!(!refused.status.success());
    assert_eq!(json(&refused)["code"], "AUTH_FAIL");

    fs::remove_dir_all(&work).unwrap();
}

/// `praetore run` on a port already in use exits with the bind error
/// (status 1), instead of aborting while it drops its database clients on
/// the runtime thread; `Gateway::start` relies on that message to retry.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_cli_run_reports_a_port_in_use() {
    let admin_url = std::env::var("PRAETORE_TEST_DATABASE_URL").unwrap();
    let runtime_url = provision(&admin_url);
    let work = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("praetore-port-in-use-{}", Uuid::new_v4()));
    fs::create_dir(&work).unwrap();
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let dir = work.join("gateway");
    init(&dir, taken.local_addr().unwrap().port());
    let output = Command::new(PRAETORE)
        .arg("run")
        .arg(&dir)
        .env("PRAETORE_GATEWAY_DATABASE_URL", &runtime_url)
        .env("PRAETORE_GATEWAY_MIGRATION_DATABASE_URL", &admin_url)
        .env_remove("PRAETORE_SCHEMA_OWNER")
        .output()
        .unwrap();
    let log = format!(
        "{}{}",
        stderr(&output),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(log.contains("Address already in use"), "{log}");
    assert!(!log.contains("panicked"), "{log}");
    assert!(log.contains("PRAETORE_SCHEMA_OWNER is not set"), "{log}");
    drop(taken);
    fs::remove_dir_all(&work).unwrap();
}
