//! End to end: two local gateways (`praetore run`, two tenants) write real
//! signed receipts to one PostgreSQL journal, `praetore journal-export
//! --tenant` exports one tenant, and `praetore-verify journal` checks it.
//! Every step runs the real binaries as subprocesses. The gateways and the
//! export connect as a login member of `praetore_runtime` (migration 0011);
//! only migrations use the admin URL.
//!
//! Needs `PRAETORE_TEST_DATABASE_URL` (a role that can CREATE ROLE) and the
//! verifier built in the same profile: `cargo build -p praetore-verify
//! --locked`.

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
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

/// Applies migrations as the admin role and returns the URL of a LOGIN member
/// of `praetore_runtime` on the same server and database.
fn provision(admin_url: &str) -> String {
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

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `praetore run <dir>`; killed on drop.
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
    fn start(dir: &Path, port: u16, admin_url: &str, runtime_url: &str) -> Self {
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
        let deadline = Instant::now() + Duration::from_secs(60);
        while !healthy(port) {
            if let Some(status) = gateway.child.try_wait().unwrap() {
                panic!("gateway exited with {status}: {}", gateway.log());
            }
            assert!(
                Instant::now() < deadline,
                "gateway not healthy: {}",
                gateway.log()
            );
            thread::sleep(Duration::from_millis(100));
        }
        gateway
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }
}

fn healthy(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let request = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let mut response = String::new();
    stream.write_all(request.as_bytes()).is_ok()
        && stream.read_to_string(&mut response).is_ok()
        && response.starts_with("HTTP/1.1 204")
}

fn init(dir: &Path, port: u16) -> Uuid {
    ok(
        praetore(
            &["init", dir.to_str().unwrap(), "--port", &port.to_string()],
            None,
        ),
        "praetore init",
    );
    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("config.json")).unwrap()).unwrap();
    Uuid::parse_str(config["tenant_id"].as_str().unwrap()).unwrap()
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
    praetore(
        &[
            "journal-export",
            "--tenant",
            &tenant.to_string(),
            "--attester-pin",
            pin.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ],
        database_url,
    )
}

fn verify(journal: &Path, pin: &Path, expected_head: Option<&str>) -> Output {
    let mut command = Command::new(verifier());
    command
        .args(["journal", "--journal"])
        .arg(journal)
        .arg("--attester-pin")
        .arg(pin)
        .args(["--format", "json"]);
    if let Some(head) = expected_head {
        command.args(["--expected-head", head]);
    }
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
    let (port_a, port_b) = (free_port(), free_port());
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
        let gateway_a = Gateway::start(&dir_a, port_a, &admin_url, &runtime_url);
        let gateway_b = Gateway::start(&dir_b, port_b, &admin_url, &runtime_url);
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
