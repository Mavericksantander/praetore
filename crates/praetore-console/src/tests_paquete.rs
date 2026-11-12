//! D3 tests: the compliance package's files, names and sums, that it carries
//! no private key, that a missing piece yields no package, and that the
//! download needs the local session.

use crate::{aprobador::ApproverSigner, paquete::*, *};
use axum::body::to_bytes;
use ed25519_dalek::SigningKey;
use praetore_core::{VerifiedPublicKey, journal_chain::verify_chain, policy::RecordedPolicy};
use praetore_replay_postgres::journal_export::{
    TenantExport, chain_receipts, export_with_database_head, parse_attester_pin,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};
use tower::ServiceExt;

const TENANT: Uuid = Uuid::from_u128(0x0d3);
const APPROVER_SECRET: [u8; 32] = [0x44; 32];
const SESSION_SECRET: [u8; 32] = [0x11; 32];

/// Published evidence set 04: signed receipts, their policy and the
/// attester's public key.
fn set_04() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/claude-code-hook/evidence/04-sesion-real-bloqueada-web-fetch")
}

fn receipts_of_set_04() -> Vec<String> {
    let dir = set_04().join("evidence");
    let mut names: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
        .iter()
        .map(|name| fs::read_to_string(dir.join(name)).unwrap())
        .collect()
}

fn attester_pin() -> VerifiedPublicKey {
    parse_attester_pin(&fs::read_to_string(set_04().join("attester-public-key.hex")).unwrap())
        .unwrap()
}

/// Stand-in for the PostgreSQL export: chains set 04 with the code the CLI
/// uses, against whatever pins the console passes.
struct SetExport {
    calls: AtomicUsize,
    fail: bool,
}

impl JournalExportStore for SetExport {
    fn tenant_id(&self) -> Uuid {
        TENANT
    }

    fn export_tenant(&self, attesters: &[VerifiedPublicKey]) -> Result<TenantExport, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err("database unavailable".into());
        }
        let (text, head, unused_attesters) = chain_receipts(&receipts_of_set_04(), None, attesters)
            .map_err(|error| error.to_string())?;
        Ok(TenantExport {
            text,
            head,
            database_head: None,
            unused_attesters,
        })
    }
}

struct NoHistory;

impl HistoryStore for NoHistory {
    fn list(&self, _query: &ListRequest) -> Result<HistoryPage, HistoryError> {
        Ok(HistoryPage {
            total: 0,
            receipts: Vec::new(),
            agents: Vec::new(),
        })
    }
}

struct NoInbox;

impl InboxStore for NoInbox {
    fn pending(&self) -> Result<InboxPage, HistoryError> {
        Ok(InboxPage {
            items: Vec::new(),
            unreadable: 0,
            truncated: false,
            agents: Vec::new(),
        })
    }
}

struct NoGateway;

impl ApprovalGateway for NoGateway {
    fn challenge(&self, _key: &praetore_gateway::ExecutionKey) -> GatewayReply {
        panic!("the package never talks to the gateway")
    }
    fn decide(&self, _key: &praetore_gateway::ExecutionKey, _decision: &str) -> GatewayReply {
        panic!("the package never talks to the gateway")
    }
    fn dispatch(&self, _key: &praetore_gateway::ExecutionKey) -> GatewayReply {
        panic!("the package never talks to the gateway")
    }
}

/// A scratch folder for this test's configured files.
fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("praetore-console-d3-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

struct Setup {
    dir: PathBuf,
    policy: PathBuf,
    pin: PathBuf,
}

impl Setup {
    fn new(name: &str) -> Self {
        let dir = scratch(name);
        let policy = dir.join("policy.json");
        fs::copy(set_04().join("policy.json"), &policy).unwrap();
        let pin = dir.join("attester.hex");
        fs::copy(set_04().join("attester-public-key.hex"), &pin).unwrap();
        Self { dir, policy, pin }
    }

    fn settings(&self) -> PackSettings {
        PackSettings::new(self.policy.clone(), vec![self.pin.clone()]).unwrap()
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn app(settings: Option<PackSettings>, store: Arc<SetExport>, with_inbox: bool) -> Router {
    let mut state = ConsoleState::new(
        Arc::new(NoHistory),
        LocalSession::from_secret(SESSION_SECRET),
        HashMap::new(),
    );
    if with_inbox {
        state = state.with_inbox(Inbox::new(
            Arc::new(NoInbox),
            Arc::new(NoGateway),
            ApproverSigner::new("approver-1", APPROVER_SECRET).unwrap(),
        ));
    }
    if let Some(settings) = settings {
        state = state.with_compliance_pack(CompliancePack::new(settings, store));
    }
    state.router()
}

fn store() -> Arc<SetExport> {
    Arc::new(SetExport {
        calls: AtomicUsize::new(0),
        fail: false,
    })
}

fn download() -> Request<Body> {
    Request::builder()
        .uri("/api/paquete")
        .header(header::HOST, "127.0.0.1:8090")
        .header(
            header::COOKIE,
            LocalSession::from_secret(SESSION_SECRET).cookie_header(),
        )
        .header(ACTION_HEADER, "1")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
}

async fn body(response: Response) -> Vec<u8> {
    to_bytes(response.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap()
        .to_vec()
}

/// Archive entries in order: (path, bytes), the folder with empty bytes.
fn unpack(gz: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(gz));
    archive
        .entries()
        .unwrap()
        .map(|entry| {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let header = entry.header();
            assert_eq!(
                header.mode().unwrap() & 0o022,
                0,
                "{path}: not writable by others"
            );
            assert_eq!(header.uid().unwrap(), 0);
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            (path, bytes)
        })
        .collect()
}

fn file<'a>(files: &'a [(String, Vec<u8>)], name: &str) -> &'a [u8] {
    let path = format!("{PACK_DIR}/{name}");
    &files
        .iter()
        .find(|(entry, _)| *entry == path)
        .unwrap_or_else(|| panic!("{path} missing"))
        .1
}

fn text<'a>(files: &'a [(String, Vec<u8>)], name: &str) -> &'a str {
    std::str::from_utf8(file(files, name)).unwrap()
}

const EXPECTED_NAMES: [&str; 8] = [
    "praetore-compliance/",
    "praetore-compliance/LEEME.txt",
    "praetore-compliance/journal.jsonl",
    "praetore-compliance/policy.json",
    "praetore-compliance/policy-digest.txt",
    "praetore-compliance/attester-pin-1.hex",
    "praetore-compliance/export.json",
    "praetore-compliance/SHA256SUMS",
];

#[tokio::test]
async fn the_package_has_fixed_names_and_the_cli_export_policy_and_pins() {
    let setup = Setup::new("contents");
    let response = app(Some(setup.settings()), store(), false)
        .oneshot(download())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/gzip");
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"praetore-compliance.tar.gz\""
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let files = unpack(&body(response).await);
    let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, EXPECTED_NAMES);

    // The journal is the published `journal-export` output for set 04, and
    // it verifies against the pin in the package.
    let journal = text(&files, "journal.jsonl");
    assert_eq!(
        journal,
        fs::read_to_string(set_04().join("journal-chain.jsonl")).unwrap()
    );
    let pin = parse_attester_pin(text(&files, "attester-pin-1.hex")).unwrap();
    assert_eq!(pin, attester_pin());
    assert_eq!(
        text(&files, "attester-pin-1.hex"),
        fs::read_to_string(set_04().join("attester-public-key.hex"))
            .unwrap()
            .trim()
            .to_owned()
            + "\n"
    );
    let head = verify_chain(journal, &pin, None, None).unwrap();

    // The policy byte for byte, and its digest as `RecordedPolicy` (the
    // engine's and `praetore-verify policy-digest`'s) computes it.
    let policy_text = fs::read_to_string(set_04().join("policy.json")).unwrap();
    assert_eq!(text(&files, "policy.json"), policy_text);
    let digest = RecordedPolicy::from_json(&policy_text)
        .unwrap()
        .digest()
        .to_owned();
    assert_eq!(text(&files, "policy-digest.txt"), format!("{digest}\n"));

    let export: serde_json::Value = serde_json::from_str(text(&files, "export.json")).unwrap();
    assert_eq!(export["tenant_id"], TENANT.to_string());
    assert_eq!(export["journal"]["entries"], head.entries.get());
    assert_eq!(export["journal"]["head"], head.head.to_hex());
    assert_eq!(export["journal"]["database_head"], serde_json::Value::Null);
    assert_eq!(export["policy"]["digest"], digest);
    assert_eq!(
        export["attester_pins"],
        serde_json::json!(["attester-pin-1.hex"])
    );
    assert!(
        time::OffsetDateTime::parse(
            export["generated_at"].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339
        )
        .is_ok()
    );

    let readme = text(&files, "LEEME.txt");
    for needed in [
        "praetore-verify journal --journal journal.jsonl --attester-pin attester-pin-1.hex",
        "praetore-verify policy-digest --policy policy.json",
        "cargo build --release --locked -p praetore-verify",
        "No prueba que el agente no tuvo un camino fuera del gateway",
        "No prueba nada de lo ocurrido antes del primer registro ni después de la\n  exportación",
        "El praetore-verify de v0.3.3 rechaza los recibos schema v5",
        "No muestra si una solicitud retenida fue aprobada, rechazada, venció o\n  se ejecutó",
        "sha256sum -c SHA256SUMS",
        &digest,
        &head.head.to_hex(),
        &TENANT.to_string(),
    ] {
        assert!(readme.contains(needed), "LEEME.txt lacks {needed:?}");
    }
}

#[tokio::test]
async fn sha256sums_covers_every_other_file_and_matches() {
    let setup = Setup::new("sums");
    let response = app(Some(setup.settings()), store(), false)
        .oneshot(download())
        .await
        .unwrap();
    let files = unpack(&body(response).await);
    let sums = text(&files, "SHA256SUMS");
    let mut listed = Vec::new();
    for line in sums.lines() {
        let (sum, name) = line.split_once("  ").unwrap();
        assert_eq!(sum.len(), 64);
        assert_eq!(
            sum,
            hex::encode(Sha256::digest(file(&files, name))),
            "{name}"
        );
        listed.push(format!("{PACK_DIR}/{name}"));
    }
    let others: Vec<String> = files
        .iter()
        .map(|(name, _)| name.clone())
        .filter(|name| !name.ends_with('/') && !name.ends_with("/SHA256SUMS"))
        .collect();
    assert_eq!(listed, others);
    assert!(sums.ends_with('\n'));
}

/// Every 64-hex token and every 32-byte window of the package, checked
/// against the keys in play: none is the secret of the approver or of a
/// key the package pins, and the approver's public key is not there
/// either.
#[tokio::test]
async fn the_package_carries_no_private_key() {
    let setup = Setup::new("no-secret");
    let response = app(Some(setup.settings()), store(), true)
        .oneshot(download())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let gz = body(response).await;
    let files = unpack(&gz);
    let approver = SigningKey::from_bytes(&APPROVER_SECRET);
    let approver_public = approver.verifying_key().to_bytes();
    let pinned = attester_pin().as_bytes();
    let mut all = Vec::new();
    for (_, bytes) in &files {
        all.extend_from_slice(bytes);
        all.push(b'\n');
    }
    let haystack = String::from_utf8_lossy(&all);
    for forbidden in [hex::encode(APPROVER_SECRET), hex::encode(approver_public)] {
        assert!(!haystack.contains(&forbidden));
        assert!(!haystack.contains(&forbidden.to_uppercase()));
    }
    for window in all.windows(32) {
        assert_ne!(window, APPROVER_SECRET.as_slice());
        assert_ne!(window, approver_public.as_slice());
    }
    let mut tokens = 0usize;
    for token in haystack
        .split(|c: char| !c.is_ascii_hexdigit())
        .filter(|token| token.len() >= 64)
    {
        for start in 0..=token.len() - 64 {
            let candidate = &token[start..start + 64];
            let Ok(bytes) = <[u8; 32]>::try_from(hex::decode(candidate).unwrap()) else {
                continue;
            };
            tokens += 1;
            let derived = SigningKey::from_bytes(&bytes).verifying_key().to_bytes();
            assert_ne!(derived, pinned, "the attester's secret is in the package");
            assert_ne!(
                derived, approver_public,
                "the approver's secret is in the package"
            );
        }
    }
    assert!(tokens > 0, "the scan saw the package's hex values");
    // Only the eight known entries: nothing else slipped in.
    assert_eq!(files.len(), EXPECTED_NAMES.len());
}

#[test]
fn a_pin_that_is_the_approver_key_is_refused() {
    let setup = Setup::new("approver-pin");
    // A secret whose bytes also decode as an Ed25519 public key: the pin
    // parser alone would accept it, so only the approver check stops it.
    let secret = (1u8..=255)
        .map(|byte| [byte; 32])
        .find(|bytes| VerifiedPublicKey::from_bytes(bytes).is_ok())
        .unwrap();
    let signer = ApproverSigner::new("approver-1", secret).unwrap();
    let public = SigningKey::from_bytes(&secret).verifying_key().to_bytes();
    for value in [hex::encode(secret), hex::encode(public)] {
        assert!(parse_attester_pin(&value).is_ok());
        fs::write(&setup.pin, format!("{value}\n")).unwrap();
        let store = store();
        let pack = CompliancePack::new(setup.settings(), store.clone());
        assert_eq!(
            generate(&pack, Some(&signer), time::OffsetDateTime::now_utc()).err(),
            Some(PackError::PinIsApproverKey)
        );
        assert_eq!(store.calls.load(Ordering::SeqCst), 0, "no export was read");
    }
}

#[tokio::test]
async fn a_missing_piece_gives_a_plain_error_and_no_package() {
    async fn refused(settings: PackSettings, store: Arc<SetExport>, expected: PackError) {
        let response = app(Some(settings), store, false)
            .oneshot(download())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("application/json")
        );
        assert!(
            response
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .is_none()
        );
        let message: serde_json::Value = serde_json::from_slice(&body(response).await).unwrap();
        let message = message["mensaje"].as_str().unwrap();
        assert_eq!(message, expected.message());
        assert!(message.contains("No se generó ningún paquete"));
        assert!(!message.chars().any(|c| c.is_ascii_digit()), "{message}");
    }

    let setup = Setup::new("missing");
    // The policy cannot be read: gone, not a policy, a directory.
    let gone = PackSettings::new(setup.dir.join("nope.json"), vec![setup.pin.clone()]).unwrap();
    let store_gone = store();
    refused(gone, store_gone.clone(), PackError::Policy).await;
    assert_eq!(store_gone.calls.load(Ordering::SeqCst), 0);
    let broken = setup.dir.join("broken.json");
    fs::write(&broken, "{\"id\":").unwrap();
    refused(
        PackSettings::new(broken, vec![setup.pin.clone()]).unwrap(),
        store(),
        PackError::Policy,
    )
    .await;
    refused(
        PackSettings::new(setup.dir.clone(), vec![setup.pin.clone()]).unwrap(),
        store(),
        PackError::Policy,
    )
    .await;
    // A pin cannot be read, is not a public key, or repeats.
    refused(
        PackSettings::new(setup.policy.clone(), vec![setup.dir.join("nope.hex")]).unwrap(),
        store(),
        PackError::Pins,
    )
    .await;
    let upper = setup.dir.join("upper.hex");
    fs::write(
        &upper,
        fs::read_to_string(&setup.pin).unwrap().to_uppercase(),
    )
    .unwrap();
    refused(
        PackSettings::new(setup.policy.clone(), vec![upper]).unwrap(),
        store(),
        PackError::Pins,
    )
    .await;
    refused(
        PackSettings::new(
            setup.policy.clone(),
            vec![setup.pin.clone(), setup.pin.clone()],
        )
        .unwrap(),
        store(),
        PackError::Pins,
    )
    .await;
    // The export fails: the database, or a pin that signed none of it.
    refused(
        setup.settings(),
        Arc::new(SetExport {
            calls: AtomicUsize::new(0),
            fail: true,
        }),
        PackError::Journal,
    )
    .await;
    let other = setup.dir.join("other.hex");
    fs::write(
        &other,
        hex::encode(
            SigningKey::from_bytes(&[0x09; 32])
                .verifying_key()
                .to_bytes(),
        ),
    )
    .unwrap();
    refused(
        PackSettings::new(setup.policy.clone(), vec![other]).unwrap(),
        store(),
        PackError::Journal,
    )
    .await;
}

#[tokio::test]
async fn the_download_needs_the_session_and_the_page() {
    let setup = Setup::new("session");
    let store = store();
    let router = app(Some(setup.settings()), store.clone(), false);

    // No cookie, or a cookie from another run.
    for cookie in [
        None,
        Some(LocalSession::from_secret([0x22; 32]).cookie_header()),
    ] {
        let mut request = Request::builder()
            .uri("/api/paquete")
            .header(header::HOST, "127.0.0.1:8090")
            .header(ACTION_HEADER, "1");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    // Another name for the console (DNS rebinding).
    let mut request = download();
    request
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static("evil.example:8090"));
    assert_eq!(
        router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::MISDIRECTED_REQUEST
    );
    // Not from the console's page: no action header, or another site.
    let mut request = download();
    request.headers_mut().remove(ACTION_HEADER);
    assert_eq!(
        router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut request = download();
    request
        .headers_mut()
        .insert("sec-fetch-site", HeaderValue::from_static("same-site"));
    assert_eq!(
        router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        store.calls.load(Ordering::SeqCst),
        0,
        "nothing was exported"
    );
    // Read only: no other method.
    for method in ["POST", "PUT", "DELETE"] {
        let mut request = download();
        *request.method_mut() = method.parse().unwrap();
        assert_eq!(
            router.clone().oneshot(request).await.unwrap().status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method}"
        );
    }
    // With the session and from the page, it downloads.
    assert_eq!(
        router.oneshot(download()).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn without_configuration_the_console_says_so() {
    let response = app(None, store(), false).oneshot(download()).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let message: serde_json::Value = serde_json::from_slice(&body(response).await).unwrap();
    assert_eq!(
        message["mensaje"],
        "El paquete de compliance no está configurado en esta consola."
    );
}

#[test]
fn settings_need_one_to_sixteen_pins() {
    assert!(PackSettings::new("p".into(), Vec::new()).is_err());
    assert!(PackSettings::new("p".into(), vec!["a".into(); MAX_ATTESTER_PINS]).is_ok());
    assert!(PackSettings::new("p".into(), vec!["a".into(); MAX_ATTESTER_PINS + 1]).is_err());
}

#[test]
fn the_page_offers_the_download_in_words_without_ids() {
    let page = include_str!("../ui/index.html");
    assert!(page.contains(">Descargar paquete de compliance</button>"));
    assert!(page.contains("No trae claves privadas"));
    let script = include_str!("../ui/app.js");
    assert!(script.contains("\"/api/paquete\""));
    assert!(script.contains("\"x-praetore-consola\": \"1\""));
}

#[test]
fn file_names_number_the_pins() {
    assert_eq!(pin_file_name(0), "attester-pin-1.hex");
    assert_eq!(pin_file_name(1), "attester-pin-2.hex");
}

/// The review's case: a second "pin" that is really a secret whose bytes
/// decode as a public key, next to the right pin that covers every
/// receipt. The export alone accepts it; the console refuses it, with or
/// without the inbox, and writes nothing.
#[test]
fn a_pin_that_verified_nothing_is_refused_so_no_secret_slips_in() {
    let setup = Setup::new("unused-pin");
    let secret = (1u8..=255)
        .map(|byte| [byte; 32])
        .find(|bytes| VerifiedPublicKey::from_bytes(bytes).is_ok())
        .unwrap();
    let second = setup.dir.join("evidence-attester.key");
    fs::write(&second, hex::encode(secret) + "\n").unwrap();
    let store = store();
    let export = store
        .export_tenant(&[
            attester_pin(),
            parse_attester_pin(&hex::encode(secret)).unwrap(),
        ])
        .unwrap();
    assert_eq!(
        export.unused_attesters,
        vec![1],
        "the export alone accepts it"
    );
    let pack = CompliancePack::new(
        PackSettings::new(
            setup.policy.clone(),
            vec![setup.pin.clone(), second.clone()],
        )
        .unwrap(),
        store.clone(),
    );
    assert_eq!(
        generate(&pack, None, time::OffsetDateTime::now_utc()).err(),
        Some(PackError::PinUnused)
    );
    // The approver's own key as a pin, with no inbox configured: the
    // approver check cannot run, the unused check still refuses it.
    let approver_public = SigningKey::from_bytes(&secret).verifying_key().to_bytes();
    fs::write(&second, hex::encode(approver_public) + "\n").unwrap();
    assert_eq!(
        generate(&pack, None, time::OffsetDateTime::now_utc()).err(),
        Some(PackError::PinUnused)
    );
}

#[test]
fn a_database_head_reference_is_reported_and_said_to_be_unchecked_here() {
    use praetore_core::journal_chain::{ChainLink, DatabaseHead};
    let pin = attester_pin();
    let (text, head) =
        export_with_database_head(&receipts_of_set_04(), None, std::slice::from_ref(&pin)).unwrap();
    let policy_json = fs::read_to_string(set_04().join("policy.json")).unwrap();
    let reference = DatabaseHead {
        entries: std::num::NonZeroU64::new(2).unwrap(),
        head: ChainLink::from_hex(&"ab".repeat(32)).unwrap(),
    };
    let contents = PackContents {
        tenant_id: TENANT,
        generated_at: time::OffsetDateTime::now_utc(),
        export: TenantExport {
            text,
            head,
            database_head: Some(reference),
            unused_attesters: Vec::new(),
        },
        policy: RecordedPolicy::from_json(&policy_json).unwrap(),
        policy_json,
        pins: vec![pin],
    };
    let files = pack_files(&contents).unwrap();
    let get = |name: &str| {
        let path = format!("{PACK_DIR}/{name}");
        String::from_utf8(
            files
                .iter()
                .find(|file| file.name == path)
                .unwrap()
                .bytes
                .clone(),
        )
        .unwrap()
    };
    let export: serde_json::Value = serde_json::from_str(&get("export.json")).unwrap();
    assert_eq!(export["journal"]["database_head"]["entries"], 2);
    assert_eq!(export["journal"]["database_head"]["head"], "ab".repeat(32));
    assert!(get("LEEME.txt").contains("esa referencia no se puede comprobar con él"));
}
