//! G1 end to end: the real `praetore-safety-ingest` binary receives signed
//! post-hoc safety events from `praetore-safety-client`, stores signed
//! records in PostgreSQL as its own login role (a member of
//! `praetore_safety_ingest`), `praetore journal-export --safety` exports a
//! source's chain and `praetore-verify safety-journal` verifies it.
//!
//! Needs `PRAETORE_TEST_DATABASE_URL` (a role that can CREATE ROLE and
//! CREATE DATABASE) and the verifier built in the same profile: `cargo build
//! -p praetore-verify --locked`. Each test uses its own scratch database and
//! login role.

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use praetore_core::{
    ActionClass, EvidenceAttesterKey, Policy, SafetyEvent, SafetyEventDraft, SafetyNamespaceKey,
    SafetyNamespaceManifest, SafetySourceKey, safety_ingest::SafetyIngestKey,
};
use praetore_safety_client::{SafetyClient, SendError};
use serde_json::Value;
use uuid::Uuid;

const INGEST: &str = env!("CARGO_BIN_EXE_praetore-safety-ingest");
const PRAETORE: &str = env!("CARGO_BIN_EXE_praetore");
const PASSWORD: &str = "praetore-safety-ingest-test";
const TENANT: Uuid = Uuid::from_u128(0x6_1);
const SEND_BOUND: Duration = Duration::from_millis(50);

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

fn admin_url() -> String {
    std::env::var("PRAETORE_TEST_DATABASE_URL")
        .expect("PRAETORE_TEST_DATABASE_URL is required for PostgreSQL integration tests")
}

fn with_database(url: &str, database: &str) -> String {
    let (base, query) = url.split_once('?').map_or((url, ""), |(b, q)| (b, q));
    let (prefix, _) = base.rsplit_once('/').unwrap();
    if query.is_empty() {
        format!("{prefix}/{database}")
    } else {
        format!("{prefix}/{database}?{query}")
    }
}

fn with_user(url: &str, user: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap();
    let host = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    format!("{scheme}://{user}:{PASSWORD}@{host}")
}

/// A migrated scratch database and a LOGIN member of `praetore_safety_ingest`.
struct Scratch {
    database: String,
    role: String,
    admin: String,
    ingest: String,
}

impl Scratch {
    fn create() -> Self {
        let id = Uuid::new_v4().simple().to_string();
        let database = format!("g1_{id}");
        let role = format!("g1_ingest_{}", &id[..12]);
        let mut server = postgres::Client::connect(&admin_url(), postgres::NoTls).unwrap();
        server
            .batch_execute(&format!("CREATE DATABASE {database}"))
            .unwrap();
        server
            .batch_execute(&format!(
                "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB \
                     PASSWORD '{PASSWORD}'"
            ))
            .unwrap();
        let admin = with_database(&admin_url(), &database);
        let mut client = postgres::Client::connect(&admin, postgres::NoTls).unwrap();
        praetore_replay_postgres::apply_migrations(&mut client).unwrap();
        client
            .batch_execute(&format!("GRANT praetore_safety_ingest TO {role}"))
            .unwrap();
        // The schema owner registers the role for the tenant and key
        // (migration 0017).
        client
            .execute(
                "INSERT INTO praetore.safety_ingest_tenants (role_oid, tenant_id, ingest_key_id) \
                 VALUES ($1::pg_catalog.text::pg_catalog.regrole, $2, $3)",
                &[&role, &TENANT, &ingest_key().key_id()],
            )
            .unwrap();
        let ingest = with_database(&with_user(&admin_url(), &role), &database);
        Self {
            database,
            role,
            admin,
            ingest,
        }
    }

    fn admin(&self) -> postgres::Client {
        postgres::Client::connect(&self.admin, postgres::NoTls).unwrap()
    }

    /// Records of `chain`, read as the superuser (no RLS).
    fn count(&self, chain: &str) -> i64 {
        self.admin()
            .query_one(
                "SELECT count(*) FROM praetore.safety_records WHERE chain = $1",
                &[&chain],
            )
            .unwrap()
            .get(0)
    }

    fn wait_for(&self, chain: &str, records: i64) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.count(chain) < records {
            assert!(
                Instant::now() < deadline,
                "chain {chain} has {} records, expected {records}",
                self.count(chain)
            );
            thread::sleep(Duration::from_millis(50));
        }
        thread::sleep(Duration::from_millis(100));
        assert_eq!(self.count(chain), records, "chain {chain}");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Ok(mut server) = postgres::Client::connect(&admin_url(), postgres::NoTls) {
            let _ = server.batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.database
            ));
            let _ = server.batch_execute(&format!("DROP ROLE IF EXISTS {}", self.role));
        }
    }
}

fn source_key() -> SafetySourceKey {
    SafetySourceKey::from_secret_bytes(&[0x74; 32])
}

fn ingest_key() -> SafetyIngestKey {
    SafetyIngestKey::from_secret_bytes(&[0x71; 32])
}

fn namespace_key() -> SafetyNamespaceKey {
    SafetyNamespaceKey::from_secret_bytes(&[0x72; 32])
}

fn hex_key(key: &praetore_core::VerifiedPublicKey) -> String {
    hex::encode(key.as_bytes())
}

/// Keys, pins, the manifest and the socket in a short directory (`sun_path`
/// holds about 104 bytes).
struct Files {
    dir: PathBuf,
}

impl Files {
    fn new() -> Self {
        let dir = PathBuf::from("/tmp")
            .join(format!("g1-{}", &Uuid::new_v4().simple().to_string()[..10]));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let files = Self { dir };
        files.private("ingest.key", &(hex::encode([0x71u8; 32]) + "\n"));
        let policy = Policy::new_v2("ops", 1, vec![])
            .with_action_class("safety:halt", ActionClass::Safety)
            .with_action_class("safety:stop_all", ActionClass::Safety);
        let manifest = SafetyNamespaceManifest::from_policy(
            &policy,
            time::OffsetDateTime::from_unix_timestamp(1_793_491_200).unwrap(),
            &namespace_key(),
        )
        .unwrap();
        files.write("manifest.json", &manifest.to_file().unwrap());
        files.write(
            "namespace.pin",
            &hex_key(&namespace_key().public_key().unwrap()),
        );
        files.write(
            "attester.pin",
            &hex_key(
                &EvidenceAttesterKey::from_secret_bytes(&[0x73; 32])
                    .public_key()
                    .unwrap(),
            ),
        );
        files.write("ingest.pin", &hex_key(&ingest_key().public_key().unwrap()));
        files.write(
            "sources.jsonl",
            &format!(
                "{{\"source_id\":\"executor-1\",\"public_key\":\"{}\"}}\n",
                hex_key(&source_key().public_key().unwrap())
            ),
        );
        files
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn write(&self, name: &str, contents: &str) {
        fs::write(self.path(name), contents).unwrap();
    }

    fn private(&self, name: &str, contents: &str) {
        self.write(name, contents);
        fs::set_permissions(self.path(name), fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn socket(&self) -> PathBuf {
        self.path("ingest.sock")
    }

    fn command(&self, scratch: &Scratch, subcommand: &str) -> Command {
        let mut command = Command::new(INGEST);
        command
            .arg(subcommand)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("PRAETORE_SAFETY_SOCKET", self.socket())
            .env("PRAETORE_SAFETY_TENANT_ID", TENANT.to_string())
            .env("PRAETORE_SAFETY_INGEST_KEY_FILE", self.path("ingest.key"))
            .env("PRAETORE_SAFETY_MANIFEST_FILE", self.path("manifest.json"))
            .env(
                "PRAETORE_SAFETY_NAMESPACE_PIN_FILE",
                self.path("namespace.pin"),
            )
            .env(
                "PRAETORE_SAFETY_ATTESTER_PIN_FILE",
                self.path("attester.pin"),
            )
            .env(
                "PRAETORE_SAFETY_SOURCE_PINS_FILE",
                self.path("sources.jsonl"),
            )
            .env("PRAETORE_SAFETY_DATABASE_URL", &scratch.ingest);
        command
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// A running ingester; killed on drop.
struct Ingester {
    child: Child,
    log: PathBuf,
}

impl Ingester {
    fn start(files: &Files, scratch: &Scratch, extra: &[(&str, &str)]) -> Self {
        let log = files.path(&format!("ingest-{}.log", Uuid::new_v4().simple()));
        let mut command = files.command(scratch, "run");
        for (name, value) in extra {
            command.env(name, value);
        }
        let child = command
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        let mut ingester = Self { child, log };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ingester.log().contains("listening on") {
            if let Some(status) = ingester.child.try_wait().unwrap() {
                panic!("ingester exited with {status}: {}", ingester.log());
            }
            assert!(
                Instant::now() < deadline,
                "ingester not ready: {}",
                ingester.log()
            );
            thread::sleep(Duration::from_millis(50));
        }
        ingester
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// SIGTERM and wait for a clean exit.
    fn stop(mut self) -> String {
        rustix_kill(self.child.id());
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "ingester exited with {status}: {}",
                    self.log()
                );
                return self.log();
            }
            assert!(
                Instant::now() < deadline,
                "ingester did not stop: {}",
                self.log()
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
}

fn rustix_kill(pid: u32) {
    let status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

impl Drop for Ingester {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn event(seq: u64, action: &str) -> SafetyEvent {
    source_key()
        .sign_event(SafetyEventDraft {
            source_id: "executor-1".into(),
            source_epoch: 1,
            source_seq: seq,
            action: action.into(),
            occurred_at: time::OffsetDateTime::now_utc(),
            params: BTreeMap::new(),
        })
        .unwrap()
}

fn send(client: &SafetyClient, bytes: &[u8]) -> Result<(), SendError> {
    let start = Instant::now();
    let result = client.send_bytes(bytes);
    let elapsed = start.elapsed();
    assert!(elapsed < SEND_BOUND, "a send took {elapsed:?}");
    result
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

fn export(files: &Files, scratch: &Scratch, chain: &str, output: &Path) -> Value {
    export_with(files, scratch, chain, output, &[])
}

fn export_with(
    files: &Files,
    scratch: &Scratch,
    chain: &str,
    output: &Path,
    extra: &[&str],
) -> Value {
    let result = ok(
        Command::new(PRAETORE)
            .args([
                "journal-export",
                "--safety",
                "--tenant",
                &TENANT.to_string(),
                "--source",
                chain,
                "--ingest-pin",
                files.path("ingest.pin").to_str().unwrap(),
                "--output",
                output.to_str().unwrap(),
            ])
            .args(extra)
            .env("PRAETORE_SAFETY_DATABASE_URL", &scratch.ingest)
            .env_remove("PRAETORE_SAFETY_DATABASE_URL_FILE")
            .output()
            .unwrap(),
        "journal-export --safety",
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

fn verify(files: &Files, journal: &Path, expected_head: Option<&str>) -> (bool, Value) {
    verify_with(files, journal, expected_head, &[])
}

fn verify_with(
    files: &Files,
    journal: &Path,
    expected_head: Option<&str>,
    extra: &[&str],
) -> (bool, Value) {
    let mut command = Command::new(verifier());
    command.args([
        "safety-journal",
        "--journal",
        journal.to_str().unwrap(),
        "--ingest-pin",
        files.path("ingest.pin").to_str().unwrap(),
        "--source-pins",
        files.path("sources.jsonl").to_str().unwrap(),
        "--format",
        "json",
    ]);
    if let Some(head) = expected_head {
        command.args(["--expected-head", head]);
    }
    command.args(extra);
    let output = command.output().unwrap();
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_safety_ingest_end_to_end() {
    let scratch = Scratch::create();
    let files = Files::new();
    ok(
        files.command(&scratch, "doctor").output().unwrap(),
        "praetore-safety-ingest doctor",
    );
    // `public-key` prints the value to pin.
    let printed = ok(
        Command::new(INGEST)
            .args(["public-key", files.path("ingest.key").to_str().unwrap()])
            .output()
            .unwrap(),
        "praetore-safety-ingest public-key",
    );
    assert_eq!(
        String::from_utf8_lossy(&printed.stdout).trim(),
        fs::read_to_string(files.path("ingest.pin")).unwrap()
    );
    let ingester = Ingester::start(&files, &scratch, &[]);
    let mode = fs::symlink_metadata(files.socket())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "socket mode");

    let client = SafetyClient::new(files.socket()).unwrap();
    let wire = |event: SafetyEvent| event.to_wire().unwrap();
    let mut forged: Value = serde_json::from_slice(&wire(event(9, "safety:halt"))).unwrap();
    forged["signature"] = Value::from("00".repeat(64));
    let stranger = SafetySourceKey::from_secret_bytes(&[0x75; 32])
        .sign_event(SafetyEventDraft {
            source_id: "executor-9".into(),
            source_epoch: 1,
            source_seq: 1,
            action: "safety:halt".into(),
            occurred_at: time::OffsetDateTime::now_utc(),
            params: BTreeMap::new(),
        })
        .unwrap();
    // The same event twice is an exact duplicate, counted and not stored
    // again (another occurred_at would make it a conflict).
    let six = wire(event(6, "safety:halt"));
    let inputs: Vec<Vec<u8>> = vec![
        wire(event(1, "safety:halt")),
        wire(event(2, "safety:freeze")),
        wire(event(3, "safety:_x")),
        six.clone(),
        six,
        wire(event(1, "safety:stop_all")),
        b"\x00\xffnot json".to_vec(),
        serde_json::to_vec(&forged).unwrap(),
        wire(stranger),
    ];
    for input in &inputs {
        send(&client, input).unwrap();
        // One at a time keeps the order the chain must show.
        thread::sleep(Duration::from_millis(30));
    }
    // executor-1: accepted, undeclared, invalid_name, loss (4-5), accepted,
    // conflict. _unattributed: three rejected and the count of the
    // duplicate (written once the ingester is idle).
    scratch.wait_for("executor-1", 6);
    scratch.wait_for("_unattributed", 4);

    let out = files.path("executor-1.jsonl");
    let summary = export(&files, &scratch, "executor-1", &out);
    assert_eq!(summary["entries"], 6, "{summary}");
    let head = summary["head"].as_str().unwrap().to_owned();
    let (verified, report) = verify(&files, &out, Some(&head));
    assert!(verified, "{report}");
    // The same chain in two ranges: the second is anchored on the first
    // one's head and ends at the full head.
    let first = files.path("executor-1-range-0.jsonl");
    let first_summary = export_with(
        &files,
        &scratch,
        "executor-1",
        &first,
        &["--from-seq", "0", "--limit", "3"],
    );
    let next = first_summary["next_from_seq"].as_u64().unwrap();
    assert!((3..=4).contains(&next), "{first_summary}");
    let second = files.path("executor-1-range-1.jsonl");
    let second_summary = export_with(
        &files,
        &scratch,
        "executor-1",
        &second,
        &["--from-seq", &next.to_string()],
    );
    assert_eq!(
        second_summary["next_from_seq"],
        Value::Null,
        "{second_summary}"
    );
    assert_eq!(second_summary["head"], head.as_str());
    let first_head = first_summary["head"].as_str().unwrap();
    let (range_verified, range_report) = verify_with(&files, &second, Some(&head), &[]);
    assert!(
        !range_verified,
        "a range is not a whole chain: {range_report}"
    );
    let mut command_args = vec!["--range", "--expected-anchor", first_head];
    let (range_verified, range_report) = verify_with(&files, &second, Some(&head), &command_args);
    assert!(range_verified, "{range_report}");
    assert_eq!(
        range_report["details"]["range_start"], next,
        "{range_report}"
    );
    command_args[2] = &head;
    let (range_verified, _) = verify_with(&files, &second, Some(&head), &command_args);
    assert!(
        !range_verified,
        "a range anchored on the wrong record verified"
    );
    let counts = &report["details"]["counts"];
    for (status, count) in [
        ("accepted", 2),
        ("undeclared", 1),
        ("invalid_name", 1),
        ("loss", 1),
        ("lost_events", 2),
        ("duplicate", 0),
        ("conflict", 1),
    ] {
        assert_eq!(counts[status], count, "{status}: {report}");
    }
    assert_eq!(report["details"]["source_signatures_verified"], true);
    // The export never overwrites.
    assert!(
        !Command::new(PRAETORE)
            .args([
                "journal-export",
                "--safety",
                "--tenant",
                &TENANT.to_string(),
                "--source",
                "executor-1",
                "--ingest-pin",
                files.path("ingest.pin").to_str().unwrap(),
                "--output",
                out.to_str().unwrap(),
            ])
            .env("PRAETORE_SAFETY_DATABASE_URL", &scratch.ingest)
            .output()
            .unwrap()
            .status
            .success()
    );

    let rejected = files.path("unattributed.jsonl");
    let summary = export(&files, &scratch, "_unattributed", &rejected);
    assert_eq!(summary["counts"]["rejected"], 3, "{summary}");
    let records: Vec<Value> = fs::read_to_string(&rejected)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let reasons: Vec<&str> = records
        .iter()
        .filter(|r| r["status"] == "rejected")
        .map(|r| r["reason"].as_str().unwrap())
        .collect();
    assert_eq!(
        reasons,
        ["malformed", "signature_invalid", "unknown_source"]
    );
    let duplicate = records
        .iter()
        .find(|r| r["status"] == "loss" && r["reason"] == "duplicate")
        .expect("a signed count of the duplicate");
    assert_eq!(duplicate["dropped"], 1);
    assert_eq!(duplicate["detail"], "executor-1=1");
    assert_eq!(
        summary["counts"]["dropped_by_reason"]["duplicate"], 1,
        "{summary}"
    );
    assert_eq!(records[0]["raw"]["escaped"], "\\x00\\xffnot json");

    // Tampering with the export: an edited, a removed and a reordered
    // record each fail.
    let text = fs::read_to_string(&out).unwrap();
    let lines: Vec<String> = text.lines().map(|line| format!("{line}\n")).collect();
    let mut edited = lines.clone();
    edited[1] = edited[1].replacen("\"recorded_at\":\"20", "\"recorded_at\":\"19", 1);
    let mut removed = lines.clone();
    removed.remove(2);
    let mut reordered = lines.clone();
    reordered.swap(4, 5);
    for (name, tampered) in [
        ("edited", edited),
        ("removed", removed),
        ("reordered", reordered),
    ] {
        let path = files.path(&format!("{name}.jsonl"));
        fs::write(&path, tampered.concat()).unwrap();
        let (verified, report) = verify(&files, &path, None);
        assert!(!verified, "{name} verified: {report}");
        eprintln!("{name}: refused with {}", report["code"]);
    }
    // The table refuses changes, even from its owner.
    let mut admin = scratch.admin();
    for statement in [
        "UPDATE praetore.safety_records SET status = 'accepted'",
        "DELETE FROM praetore.safety_records",
        "TRUNCATE praetore.safety_records",
    ] {
        let error = admin.batch_execute(statement).unwrap_err();
        assert!(
            error
                .as_db_error()
                .unwrap()
                .message()
                .contains("append-only"),
            "{statement}: {error}"
        );
    }

    // Graceful shutdown removes the socket; a restart continues the chain.
    let log = ingester.stop();
    assert!(log.contains("stopped"), "{log}");
    assert!(!files.socket().exists());
    assert_eq!(
        client.send(&event(7, "safety:halt")),
        Err(SendError::NoListener)
    );
    let ingester = Ingester::start(&files, &scratch, &[]);
    send(&client, &wire(event(8, "safety:halt"))).unwrap();
    // seq 7 was dropped by the client while no ingester ran: a loss record.
    scratch.wait_for("executor-1", 8);
    let out = files.path("executor-1-after.jsonl");
    let summary = export(&files, &scratch, "executor-1", &out);
    assert_eq!(summary["counts"]["lost_events"], 3, "{summary}");
    let (verified, report) = verify(&files, &out, Some(summary["head"].as_str().unwrap()));
    assert!(verified, "{report}");
    // The earlier export is a prefix: it verifies only against its own head.
    let (verified, _) = verify(
        &files,
        &files.path("executor-1.jsonl"),
        Some(summary["head"].as_str().unwrap()),
    );
    assert!(!verified);
    ingester.stop();
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_safety_ingest_refuses_to_start_on_a_bad_manifest_or_a_shared_key() {
    let scratch = Scratch::create();
    let files = Files::new();
    let refused = |files: &Files, expected: &str| {
        let output = files.command(&scratch, "run").output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(!output.status.success(), "started: {stderr}");
        assert!(
            stderr.contains(expected),
            "expected {expected:?} in {stderr}"
        );
        assert!(
            !fs::symlink_metadata(files.socket()).is_ok_and(|m| {
                use std::os::unix::fs::FileTypeExt;
                m.file_type().is_socket()
            }),
            "a refused start left a socket"
        );
        // The executor is unaffected: its send returns at once.
        let client = SafetyClient::new(files.socket()).unwrap();
        assert_eq!(
            send(&client, &event(1, "safety:halt").to_wire().unwrap()),
            Err(SendError::NoListener)
        );
    };
    let manifest = fs::read_to_string(files.path("manifest.json")).unwrap();
    // A manifest that is not in its canonical file form.
    files.write("manifest.json", manifest.trim_end());
    refused(&files, "manifest");
    // A manifest that does not verify under the namespace pin.
    files.write("manifest.json", &manifest);
    let namespace_pin = fs::read_to_string(files.path("namespace.pin")).unwrap();
    files.write(
        "namespace.pin",
        &hex_key(
            &SafetyNamespaceKey::from_secret_bytes(&[0x79; 32])
                .public_key()
                .unwrap(),
        ),
    );
    refused(&files, "manifest");
    files.write("namespace.pin", &namespace_pin);
    // A missing manifest.
    fs::remove_file(files.path("manifest.json")).unwrap();
    refused(&files, "manifest");
    files.write("manifest.json", &manifest);
    // The attester key is the ingestion key.
    let attester = fs::read_to_string(files.path("attester.pin")).unwrap();
    files.write(
        "attester.pin",
        &hex_key(&ingest_key().public_key().unwrap()),
    );
    refused(&files, "must be different keys");
    files.write("attester.pin", &attester);
    // A key file readable by others.
    fs::set_permissions(files.path("ingest.key"), fs::Permissions::from_mode(0o644)).unwrap();
    refused(&files, "group or others");
    fs::set_permissions(files.path("ingest.key"), fs::Permissions::from_mode(0o600)).unwrap();
    // A role that is also the gateway runtime role.
    scratch
        .admin()
        .batch_execute(&format!("GRANT praetore_runtime TO {}", scratch.role))
        .unwrap();
    refused(&files, "praetore_runtime");
    scratch
        .admin()
        .batch_execute(&format!("REVOKE praetore_runtime FROM {}", scratch.role))
        .unwrap();
    // A regular file at the socket path is never replaced.
    files.write("ingest.sock", "keep");
    refused(&files, "is not a socket");
    assert_eq!(
        fs::read_to_string(files.path("ingest.sock")).unwrap(),
        "keep"
    );
    fs::remove_file(files.path("ingest.sock")).unwrap();
    // Everything restored: it starts, and a second ingester for the same
    // tenant (another socket) is refused by the tenant lock.
    let first = Ingester::start(&files, &scratch, &[]);
    let output = files
        .command(&scratch, "run")
        .env("PRAETORE_SAFETY_SOCKET", files.path("second.sock"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The refusal names the holding session.
    assert!(
        stderr.contains("holds the lock") && stderr.contains("(pid ") && stderr.contains(", role "),
        "{stderr}"
    );
    // So does doctor.
    let doctor = files
        .command(&scratch, "doctor")
        .env("PRAETORE_SAFETY_SOCKET", files.path("second.sock"))
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&doctor.stdout);
    assert!(!doctor.status.success());
    assert!(
        report.contains("holds the lock") && report.contains("(pid "),
        "{report}"
    );
    first.stop();
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_safety_ingest_records_overflow_and_storage_loss_without_blocking_the_client() {
    let scratch = Scratch::create();
    let files = Files::new();
    let ingester = Ingester::start(&files, &scratch, &[("PRAETORE_SAFETY_QUEUE_CAPACITY", "1")]);
    let client = SafetyClient::new(files.socket()).unwrap();
    send(&client, &event(1, "safety:halt").to_wire().unwrap()).unwrap();
    scratch.wait_for("executor-1", 1);

    // The database blocks the ingester's insert; its queue (capacity 1)
    // fills and it drops what it cannot queue. The client never waits.
    let mut locker = scratch.admin();
    let mut lock = locker.transaction().unwrap();
    lock.batch_execute("LOCK TABLE praetore.safety_records IN ACCESS EXCLUSIVE MODE")
        .unwrap();
    let mut longest = Duration::ZERO;
    for seq in 2..=101 {
        let start = Instant::now();
        let _ = client.send(&event(seq, "safety:halt"));
        longest = longest.max(start.elapsed());
        thread::sleep(Duration::from_millis(2));
    }
    println!("100 sends against a blocked ingester: longest {longest:?}");
    assert!(longest < SEND_BOUND, "a send took {longest:?}");
    thread::sleep(Duration::from_millis(300));
    lock.rollback().unwrap();
    // After the lock: what was queued is stored, the overflow is recorded.
    let deadline = Instant::now() + Duration::from_secs(30);
    while scratch.count("_unattributed") < 1 {
        assert!(Instant::now() < deadline, "no overflow record");
        thread::sleep(Duration::from_millis(50));
    }

    // The ingester's connection is killed: the next message cannot be
    // stored and is recorded as a storage loss once it reconnects.
    scratch
        .admin()
        .query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1",
            &[&scratch.role],
        )
        .unwrap();
    thread::sleep(Duration::from_millis(200));
    send(&client, &event(102, "safety:halt").to_wire().unwrap()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while scratch.count("_unattributed") < 2 {
        assert!(
            Instant::now() < deadline,
            "no storage loss record: {}",
            ingester.log()
        );
        thread::sleep(Duration::from_millis(50));
    }
    // One more event shows every gap of the source chain.
    send(&client, &event(103, "safety:halt").to_wire().unwrap()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let last: Option<i64> = scratch
            .admin()
            .query_one(
                "SELECT max(source_seq) FROM praetore.safety_records WHERE chain = 'executor-1'",
                &[],
            )
            .unwrap()
            .get(0);
        if last == Some(103) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "seq 103 not stored: {}",
            ingester.log()
        );
        thread::sleep(Duration::from_millis(50));
    }
    let log = ingester.stop();

    let source = files.path("source.jsonl");
    let summary = export(&files, &scratch, "executor-1", &source);
    let (verified, report) = verify(&files, &source, None);
    assert!(verified, "{report}");
    let counts = &report["details"]["counts"];
    let accepted = counts["accepted"].as_u64().unwrap();
    let lost = counts["lost_events"].as_u64().unwrap();
    assert_eq!(accepted + lost, 103, "{summary}");
    assert!(lost >= 1, "{summary}");

    let unattributed = files.path("unattributed.jsonl");
    export(&files, &scratch, "_unattributed", &unattributed);
    let (verified, report) = verify(&files, &unattributed, None);
    assert!(verified, "{report}");
    let reasons: Vec<String> = fs::read_to_string(&unattributed)
        .unwrap()
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line).unwrap()["reason"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert!(
        reasons.contains(&"queue_overflow".to_owned()),
        "{reasons:?}\n{log}"
    );
    assert!(
        reasons.contains(&"storage_error".to_owned()),
        "{reasons:?}\n{log}"
    );
    println!("loss records: {reasons:?}; counts {counts}");
}

/// Every `dropped` count on the unattributed chain, by reason, read as the
/// superuser.
fn dropped_by_reason(scratch: &Scratch) -> BTreeMap<String, i64> {
    let mut counts = BTreeMap::new();
    for row in scratch
        .admin()
        .query(
            "SELECT record_json FROM praetore.safety_records \
             WHERE chain = '_unattributed' AND status = 'loss'",
            &[],
        )
        .unwrap()
    {
        let record: Value = serde_json::from_str(&row.get::<_, String>(0)).unwrap();
        *counts
            .entry(record["reason"].as_str().unwrap().to_owned())
            .or_default() += record["dropped"].as_i64().unwrap();
    }
    counts
}

#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_safety_ingest_flood_is_bounded_and_counted() {
    let scratch = Scratch::create();
    let files = Files::new();
    let ingester = Ingester::start(
        &files,
        &scratch,
        &[
            ("PRAETORE_SAFETY_SOURCE_RATE", "1"),
            ("PRAETORE_SAFETY_SOURCE_BURST", "10"),
            ("PRAETORE_SAFETY_REJECTED_RATE", "1"),
            ("PRAETORE_SAFETY_REJECTED_BURST", "5"),
        ],
    );
    let client = SafetyClient::new(files.socket()).unwrap();
    // A flood: garbage, events of one source and replays of its first
    // event. Every send returns at once (send() asserts the bound), and a
    // full socket buffer or queue only drops: the executor never waits.
    let garbage = 2000;
    let events = 500;
    let replays = 500;
    let mut sent = 0i64;
    for _ in 0..garbage {
        sent += i64::from(send(&client, b"garbage").is_ok());
    }
    for seq in 1..=events {
        sent += i64::from(send(&client, &event(seq, "safety:halt").to_wire().unwrap()).is_ok());
    }
    let replay = event(1, "safety:halt").to_wire().unwrap();
    for _ in 0..replays {
        sent += i64::from(send(&client, &replay).is_ok());
    }
    let client_dropped = (garbage + events + replays) as i64 - sent;
    assert_eq!(client_dropped as u64, client.dropped());
    // Wait until every message the ingester received is accounted for:
    // stored as a record, or in a signed count. Every record but a loss
    // stands for one message: a replay of an event the queue dropped
    // arrives after the chain moved on and is recorded as `late`.
    let deadline = Instant::now() + Duration::from_secs(30);
    let accounted = |scratch: &Scratch| {
        let records: i64 = scratch
            .admin()
            .query_one(
                "SELECT count(*) FROM praetore.safety_records WHERE status <> 'loss'",
                &[],
            )
            .unwrap()
            .get(0);
        records + dropped_by_reason(scratch).values().sum::<i64>()
    };
    while accounted(&scratch) < sent {
        assert!(
            Instant::now() < deadline,
            "{} of {sent} messages accounted for: {:?}\n{}",
            accounted(&scratch),
            dropped_by_reason(&scratch),
            ingester.log()
        );
        thread::sleep(Duration::from_millis(100));
    }
    let log = ingester.stop();
    assert_eq!(accounted(&scratch), sent, "{log}");
    // Bounded: a few seconds of the rate limits, plus about one count
    // record per reason per second.
    let total: i64 = scratch
        .admin()
        .query_one("SELECT count(*) FROM praetore.safety_records", &[])
        .unwrap()
        .get(0);
    assert!(total < 100, "{total} records for {sent} messages");
    // Individual records stay within the rate limits (bursts of 5 and 10,
    // one per second after that); the rest is in signed counts, including
    // what the full queue dropped.
    let dropped = dropped_by_reason(&scratch);
    let rows = |status: &str| -> i64 {
        scratch
            .admin()
            .query_one(
                "SELECT count(*) FROM praetore.safety_records WHERE status = $1",
                &[&status],
            )
            .unwrap()
            .get(0)
    };
    assert!(
        rows("rejected") <= 5 + 30,
        "{} rejected records",
        rows("rejected")
    );
    assert!(
        rows("accepted") <= 10 + 30,
        "{} accepted records",
        rows("accepted")
    );
    for reason in ["rejected_suppressed", "rate_limited"] {
        assert!(dropped.get(reason).copied().unwrap_or(0) > 0, "{dropped:?}");
    }
    // Both chains verify.
    for chain in ["executor-1", "_unattributed"] {
        let out = files.path(&format!("flood-{chain}.jsonl"));
        export(&files, &scratch, chain, &out);
        let (verified, report) = verify(&files, &out, None);
        assert!(verified, "{chain}: {report}");
    }
}

/// `PRAETORE_SAFETY_ALLOWED_UIDS` (Linux): datagrams from another user id
/// are counted as `peer_refused` and not read; on other platforms the
/// setting makes startup fail.
#[test]
#[ignore = "requires PRAETORE_TEST_DATABASE_URL"]
fn postgres_safety_ingest_checks_the_sender_uid() {
    let scratch = Scratch::create();
    let files = Files::new();
    let own = rustix::process::geteuid().as_raw();
    let other = if own == 0 { 1 } else { 0 };
    if !cfg!(target_os = "linux") {
        let output = files
            .command(&scratch, "run")
            .env("PRAETORE_SAFETY_ALLOWED_UIDS", own.to_string())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("needs Linux"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    // Allowed: this process's uid.
    let ingester = Ingester::start(
        &files,
        &scratch,
        &[("PRAETORE_SAFETY_ALLOWED_UIDS", &format!("{other},{own}"))],
    );
    let client = SafetyClient::new(files.socket()).unwrap();
    send(&client, &event(1, "safety:halt").to_wire().unwrap()).unwrap();
    scratch.wait_for("executor-1", 1);
    ingester.stop();
    // Not allowed: only another uid.
    let ingester = Ingester::start(
        &files,
        &scratch,
        &[("PRAETORE_SAFETY_ALLOWED_UIDS", &other.to_string())],
    );
    let client = SafetyClient::new(files.socket()).unwrap();
    for seq in 2..=4 {
        send(&client, &event(seq, "safety:halt").to_wire().unwrap()).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while dropped_by_reason(&scratch)
        .get("peer_refused")
        .copied()
        .unwrap_or(0)
        < 3
    {
        assert!(Instant::now() < deadline, "{}", ingester.log());
        thread::sleep(Duration::from_millis(100));
    }
    ingester.stop();
    assert_eq!(scratch.count("executor-1"), 1);
    assert_eq!(dropped_by_reason(&scratch)["peer_refused"], 3);
}
