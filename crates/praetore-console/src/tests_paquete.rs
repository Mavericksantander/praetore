//! D3 tests: the compliance package's files, names and sums, that it carries
//! no private key, that a missing piece yields no package, and that the
//! download needs the local session.

use crate::{aprobador::ApproverSigner, paquete::*, *};
use axum::body::to_bytes;
use ed25519_dalek::SigningKey;
use praetore_core::{VerifiedPublicKey, journal_chain::verify_chain, policy::RecordedPolicy};
use praetore_receipt::outcomes::Outcome;
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
    /// The receipts chained (set 04's, or D3.1's held ones).
    receipts: Vec<String>,
    /// D3.1: the approval and execution records the export returns.
    outcomes: Vec<Outcome>,
}

impl JournalExportStore for SetExport {
    fn tenant_id(&self) -> Uuid {
        TENANT
    }

    fn export_tenant(
        &self,
        attesters: &[VerifiedPublicKey],
    ) -> Result<(TenantExport, Vec<Outcome>), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err("database unavailable".into());
        }
        let (text, head, unused_attesters) =
            chain_receipts(&self.receipts, None, attesters).map_err(|error| error.to_string())?;
        Ok((
            TenantExport {
                text,
                head,
                database_head: None,
                unused_attesters,
            },
            self.outcomes.clone(),
        ))
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
        receipts: receipts_of_set_04(),
        outcomes: Vec::new(),
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

const EXPECTED_NAMES: [&str; 9] = [
    "praetore-compliance/",
    "praetore-compliance/LEEME.txt",
    "praetore-compliance/journal.jsonl",
    "praetore-compliance/approvals.jsonl",
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

    // Compared with line breaks folded into single spaces.
    let readme = text(&files, "LEEME.txt")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(!readme.contains("recibos de ejecución, que este paquete no trae"));
    assert!(!readme.contains("no van en este paquete"));
    assert_eq!(text(&files, "approvals.jsonl"), "");
    assert_eq!(export["outcomes"]["records"], 0);
    assert_eq!(export["outcomes"]["held_requests"], 0);
    assert_eq!(export["execution_pins"], serde_json::json!([]));
    assert_eq!(export["approver_pins"], serde_json::json!([]));
    for needed in [
        "praetore-verify journal --journal journal.jsonl --attester-pin attester-pin-1.hex",
        "praetore-verify policy-digest --policy policy.json",
        "cargo build --release --locked -p praetore-verify",
        "No prueba que el agente no tuvo un camino fuera del gateway",
        "No prueba nada de lo ocurrido antes del primer registro ni después de la exportación",
        "Use praetore-verify construido desde main. El praetore-verify de v0.3.3 también acepta este journal.jsonl, pero no muestra tenant_id ni avisa head_not_anchored, que el paso 3 usa, y no tiene el comando outcomes del paso 5. Además, v0.3.3 rechaza con RECEIPT_INVALID los recibos de ejecución schema v5 (awaiting_approval) y las razones approved_claim_expired y approval_rejected, que approvals.jsonl puede traer.",
        "Tiene 8 recibos de decisión. Cada línea encadena",
        "desde main, en un commit que incluya este paquete de compliance con approvals.jsonl (P-002 D3.1), o desde un release posterior a v0.3.3",
        "esos recibos van en approvals.jsonl",
        "Este tenant no tiene ninguno: el archivo está vacío.",
        "praetore-verify outcomes --outcomes approvals.jsonl --journal journal.jsonl --attester-pin attester-pin-1.hex",
        "Esta exportación no tiene solicitudes retenidas.",
        "No prueba que approvals.jsonl esté completo.",
        "puede seguir pendiente o haber vencido sin que el gateway lo haya registrado todavía",
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
            receipts: receipts_of_set_04(),
            outcomes: Vec::new(),
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
    let (export, _) = store
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
        Some(PackError::PinUnused {
            index: 1,
            more: false
        })
    );
    // The approver's own key as a pin, with no inbox configured: the
    // approver check cannot run, the unused check still refuses it.
    let approver_public = SigningKey::from_bytes(&secret).verifying_key().to_bytes();
    fs::write(&second, hex::encode(approver_public) + "\n").unwrap();
    assert_eq!(
        generate(&pack, None, time::OffsetDateTime::now_utc()).err(),
        Some(PackError::PinUnused {
            index: 1,
            more: false
        })
    );
}

#[test]
fn a_database_head_reference_is_reported_and_said_to_be_unchecked_here() {
    use praetore_core::journal_chain::{ChainLink, DatabaseHead};
    let pin = attester_pin();
    let policy_json = fs::read_to_string(set_04().join("policy.json")).unwrap();
    let reference = DatabaseHead {
        entries: std::num::NonZeroU64::new(2).unwrap(),
        head: ChainLink::from_hex(&"ab".repeat(32)).unwrap(),
    };
    // Line 0 is the reference, then set 04's eight receipts.
    let (text, head) = export_with_database_head(
        &receipts_of_set_04(),
        Some(reference),
        std::slice::from_ref(&pin),
    )
    .unwrap();
    assert_eq!(head.entries.get(), 9);
    assert!(text.lines().next().unwrap().contains("\"database_head\""));
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
        outcomes: PackOutcomes::default(),
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
    assert_eq!(export["journal"]["entries"], 9);
    assert_eq!(export["journal"]["decision_receipts"], 8);
    let readme = get("LEEME.txt")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(readme.contains("esa referencia no se puede comprobar con él"));
    assert!(
        readme.contains("Tiene 8 recibos de decisión. La primera línea no es un recibo"),
        "{readme}"
    );
    assert!(readme.contains("de toda la base: 2."), "{readme}");
    assert!(readme.contains("--expected-database-head"));
    assert!(!readme.contains("9 recibos"));
}

#[tokio::test]
async fn the_second_pin_unused_is_named_in_words() {
    let setup = Setup::new("second-unused");
    let second = setup.dir.join("second.hex");
    fs::write(
        &second,
        hex::encode(
            SigningKey::from_bytes(&[0x09; 32])
                .verifying_key()
                .to_bytes(),
        ) + "\n",
    )
    .unwrap();
    let settings = PackSettings::new(
        setup.policy.clone(),
        vec![setup.pin.clone(), second.clone()],
    )
    .unwrap();
    let response = app(Some(settings), store(), false)
        .oneshot(download())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .is_none()
    );
    let message: serde_json::Value = serde_json::from_slice(&body(response).await).unwrap();
    let message = message["mensaje"].as_str().unwrap();
    assert!(
        message.starts_with("La segunda clave configurada como clave pública del atestador"),
        "{message}"
    );
    assert!(message.contains("PRAETORE_CONSOLE_ATTESTER_PIN_FILES"));
    assert!(message.contains("No se generó ningún paquete"));
    assert!(!message.contains("Puede haber más"));
    assert!(!message.chars().any(|c| c.is_ascii_digit()), "{message}");

    // First and third unused: the first is named, and the page says there
    // may be more.
    let third = setup.dir.join("third.hex");
    fs::write(
        &third,
        hex::encode(
            SigningKey::from_bytes(&[0x0a; 32])
                .verifying_key()
                .to_bytes(),
        ),
    )
    .unwrap();
    let pack = CompliancePack::new(
        PackSettings::new(setup.policy.clone(), vec![second, setup.pin.clone(), third]).unwrap(),
        store(),
    );
    let error = generate(&pack, None, time::OffsetDateTime::now_utc()).unwrap_err();
    assert_eq!(
        error,
        PackError::PinUnused {
            index: 0,
            more: true
        }
    );
    let message = error.message();
    assert!(message.starts_with("La primera clave"), "{message}");
    assert!(message.contains("Puede haber más claves"));
    assert!(!message.chars().any(|c| c.is_ascii_digit()));
}

#[test]
fn every_pin_position_has_a_word() {
    for index in 0..MAX_ATTESTER_PINS {
        let message = PackError::PinUnused { index, more: false }.message();
        assert!(!message.chars().any(|c| c.is_ascii_digit()), "{message}");
        assert!(!message.contains("última"), "{index}");
    }
    assert!(
        !PackError::Journal
            .message()
            .chars()
            .any(|c| c.is_ascii_digit())
    );
    assert!(
        PackError::Journal
            .message()
            .contains("el registro es demasiado grande para una exportación")
    );
}

#[tokio::test]
async fn one_package_at_a_time() {
    let setup = Setup::new("busy");
    let store = store();
    let state = Arc::new(
        ConsoleState::new(
            Arc::new(NoHistory),
            LocalSession::from_secret(SESSION_SECRET),
            HashMap::new(),
        )
        .with_compliance_pack(CompliancePack::new(setup.settings(), store.clone())),
    );
    let router = ConsoleState::router_from(Arc::clone(&state));
    let held = Arc::clone(&state.pack_gate).try_acquire_owned().unwrap();
    let response = router.clone().oneshot(download()).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let message: serde_json::Value = serde_json::from_slice(&body(response).await).unwrap();
    assert_eq!(
        message["mensaje"],
        "Ya se está armando un paquete. Espera a que termine."
    );
    assert_eq!(store.calls.load(Ordering::SeqCst), 0);
    drop(held);
    let response = router.oneshot(download()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_page_learns_whether_the_package_is_configured() {
    let setup = Setup::new("status");
    for (settings, configured) in [(Some(setup.settings()), true), (None, false)] {
        let request = Request::builder()
            .uri("/api/paquete/estado")
            .header(header::HOST, "127.0.0.1:8090")
            .header(
                header::COOKIE,
                LocalSession::from_secret(SESSION_SECRET).cookie_header(),
            )
            .body(Body::empty())
            .unwrap();
        let store = store();
        let response = app(settings, store.clone(), false)
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let status: serde_json::Value = serde_json::from_slice(&body(response).await).unwrap();
        assert_eq!(status["configurado"], configured);
        assert_eq!(store.calls.load(Ordering::SeqCst), 0, "nothing exported");
    }
    // Without the session, refused like the rest of the API.
    let request = Request::builder()
        .uri("/api/paquete/estado")
        .header(header::HOST, "127.0.0.1:8090")
        .body(Body::empty())
        .unwrap();
    let response = app(None, store(), false).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// D3.1: approvals.jsonl, its execution and approver pins, all or nothing.

use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, AuthorizationIntentV2, Decision, Evidence,
    EvidenceAttesterKey,
};
use praetore_gateway::{
    ApprovalChallenge, AttestedOutcome, AuthorizationStatus, ExecutionAttestation, GatewayReceipt,
    HumanApprovalDecision, HumanApprovalOutcome, NotDispatchedReason,
};
use praetore_receipt::outcomes::{KeyPin, OutcomeKeys, verify_outcomes, write_outcomes};

const EXECUTION_SECRET: [u8; 32] = [0x55; 32];
const EXECUTION_KEY_ID: &str = "test-execution-v1";
const HELD_ATTESTER_SECRET: [u8; 32] = [0x52; 32];
const HELD_TENANT: Uuid = Uuid::from_u128(1);

struct TestExecutionSigner(SigningKey);

impl praetore_gateway::ExecutionAttestationSigner for TestExecutionSigner {
    fn key_id(&self) -> &str {
        EXECUTION_KEY_ID
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, praetore_gateway::ExecutionAttestationError> {
        use ed25519_dalek::Signer;
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}

fn key_pin(secret: [u8; 32], key_id: &str) -> KeyPin {
    KeyPin {
        key_id: key_id.into(),
        public_key: VerifiedPublicKey::from_bytes(
            &SigningKey::from_bytes(&secret).verifying_key().to_bytes(),
        )
        .unwrap(),
    }
}

fn execution_pin() -> KeyPin {
    key_pin(EXECUTION_SECRET, EXECUTION_KEY_ID)
}

/// The console's own approver ("approver-1"): its public key is a valid
/// approver pin.
fn approver_pin() -> KeyPin {
    key_pin(APPROVER_SECRET, "approver-1")
}

/// A request the policy held for approval, with the HighAssurance shape a
/// gateway hold carries (as in the D2 tests), signed by the held attester.
fn held_evidence(target: &str) -> Evidence {
    let expires_at = (time::OffsetDateTime::now_utc() + time::Duration::hours(1))
        .replace_nanosecond(0)
        .unwrap();
    let agent = AgentKeyPair::from_secret_bytes(&[0x51; 32]).identity(AgentId::new());
    let authority = Authority::new(
        agent.id.clone(),
        "consola-test",
        vec!["archivo:borrar".into()],
    )
    .with_constraint("tenant_id", HELD_TENANT.to_string());
    let authority_digest = authority.content_digest().unwrap();
    let action = Action::new("archivo:borrar", Some(target.into()), serde_json::json!({}))
        .unwrap()
        .with_capability("archivo:borrar");
    let mut evidence = Evidence::new_with_context(
        Uuid::new_v4(),
        agent,
        authority,
        action,
        Decision::require_approval("motivo", praetore_core::DecidedBy::rule("regla")),
        None,
        std::collections::BTreeMap::new(),
    )
    .unwrap();
    let rfc3339 = |at: time::OffsetDateTime| {
        at.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    evidence.intent_v2 = Some(AuthorizationIntentV2 {
        audience: "consola-test".into(),
        issued_at: rfc3339(expires_at - time::Duration::minutes(10)),
        expires_at: rfc3339(expires_at),
        policy_digest: "cd".repeat(32),
    });
    evidence.freshness_valid_until = Some(rfc3339(expires_at));
    evidence.decided_at = Some(rfc3339(expires_at - time::Duration::minutes(10)));
    evidence.evaluation_mode = Some("high_assurance".into());
    evidence.authority_digest = Some(authority_digest);
    evidence.semantics_version = Some(2);
    evidence.agent_signature = Some("ef".repeat(64));
    evidence.bind_policy_digest("cd".repeat(32)).unwrap();
    evidence
        .sign(&EvidenceAttesterKey::from_secret_bytes(
            &HELD_ATTESTER_SECRET,
        ))
        .unwrap();
    evidence
}

fn attested(evidence: &Evidence, outcome: AttestedOutcome) -> Outcome {
    let attestation = ExecutionAttestation::create(
        evidence,
        AuthorizationStatus::RequiresApproval,
        &outcome,
        time::OffsetDateTime::now_utc(),
        &TestExecutionSigner(SigningKey::from_bytes(&EXECUTION_SECRET)),
    )
    .unwrap();
    Outcome::ExecutionReceipt(Box::new(GatewayReceipt {
        evidence: evidence.clone(),
        authorization: attestation.authorization,
        execution: attestation.execution,
        output: outcome.output().cloned(),
        execution_attestation: attestation,
    }))
}

fn decided(evidence: &Evidence, outcome: HumanApprovalOutcome) -> Outcome {
    use ed25519_dalek::Signer;
    let challenge = ApprovalChallenge::from_evidence(
        evidence,
        &praetore_gateway::action_digest(&evidence.action).unwrap(),
    )
    .unwrap();
    let mut decision = HumanApprovalDecision {
        schema_version: 1,
        approval_id: Uuid::new_v4(),
        approver_key_id: "approver-1".into(),
        challenge,
        outcome,
        signature: String::new(),
    };
    decision.signature = hex::encode(
        SigningKey::from_bytes(&APPROVER_SECRET)
            .sign(&decision.signing_message().unwrap())
            .to_bytes(),
    );
    Outcome::HumanDecision(decision)
}

/// Three held requests, as the gateway records them: approved and executed,
/// rejected, and still pending.
fn held_set() -> (Vec<String>, Vec<Outcome>) {
    let executed = held_evidence("/tmp/aprobada");
    let rejected = held_evidence("/tmp/rechazada");
    let pending = held_evidence("/tmp/pendiente");
    let outcomes = vec![
        attested(&executed, AttestedOutcome::AwaitingApproval),
        decided(&executed, HumanApprovalOutcome::Approve),
        attested(
            &executed,
            AttestedOutcome::Executed(serde_json::json!({"borrado": true})),
        ),
        attested(&rejected, AttestedOutcome::AwaitingApproval),
        decided(&rejected, HumanApprovalOutcome::Reject),
        attested(
            &rejected,
            AttestedOutcome::NotDispatched(Some(NotDispatchedReason::ApprovalRejected)),
        ),
        attested(&pending, AttestedOutcome::AwaitingApproval),
    ];
    let receipts = [executed, rejected, pending]
        .iter()
        .map(|evidence| evidence.to_json().unwrap())
        .collect();
    (receipts, outcomes)
}

fn held_store_of(receipts: Vec<String>, outcomes: Vec<Outcome>) -> Arc<SetExport> {
    Arc::new(SetExport {
        calls: AtomicUsize::new(0),
        fail: false,
        receipts,
        outcomes,
    })
}

impl Setup {
    /// Like [`Setup::new`], with the held attester's pin.
    fn held(name: &str) -> Self {
        let setup = Self::new(name);
        let public = EvidenceAttesterKey::from_secret_bytes(&HELD_ATTESTER_SECRET)
            .public_key()
            .unwrap();
        fs::write(&setup.pin, hex::encode(public.as_bytes()) + "\n").unwrap();
        setup
    }

    /// A pin file in the scratch folder.
    fn key_pin(&self, name: &str, pin: &KeyPin) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, pin.to_json()).unwrap();
        path
    }

    fn with_pins(&self, execution: Vec<PathBuf>, approvers: Vec<PathBuf>) -> PackSettings {
        self.settings()
            .with_outcome_pins(execution, approvers)
            .unwrap()
    }

    /// The execution pin and the console approver's pin.
    fn both_pins(&self) -> PackSettings {
        let execution = self.key_pin("execution.json", &execution_pin());
        let approver = self.key_pin("approver.json", &approver_pin());
        self.with_pins(vec![execution], vec![approver])
    }
}

fn generate_with(
    settings: PackSettings,
    store: Arc<SetExport>,
    approver: Option<&ApproverSigner>,
) -> Result<Vec<u8>, PackError> {
    generate(
        &CompliancePack::new(settings, store),
        approver,
        time::OffsetDateTime::now_utc(),
    )
}

#[tokio::test]
async fn approvals_jsonl_carries_each_outcome_its_pins_and_its_counts() {
    let setup = Setup::held("d31-contents");
    let (receipts, outcomes) = held_set();
    let response = app(
        Some(setup.both_pins()),
        held_store_of(receipts, outcomes.clone()),
        true,
    )
    .oneshot(download())
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let files = unpack(&body(response).await);
    let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        [
            "praetore-compliance/",
            "praetore-compliance/LEEME.txt",
            "praetore-compliance/journal.jsonl",
            "praetore-compliance/approvals.jsonl",
            "praetore-compliance/policy.json",
            "praetore-compliance/policy-digest.txt",
            "praetore-compliance/attester-pin-1.hex",
            "praetore-compliance/execution-pin-1.json",
            "praetore-compliance/approver-pin-1.json",
            "praetore-compliance/export.json",
            "praetore-compliance/SHA256SUMS",
        ]
    );
    // The records, one per line, in the verifier's own format.
    let approvals = text(&files, "approvals.jsonl");
    assert_eq!(approvals, write_outcomes(&outcomes).unwrap());
    assert_eq!(approvals.lines().count(), 7);
    // Pins: public keys re-encoded with their key id; nothing else.
    let execution = KeyPin::from_json(text(&files, "execution-pin-1.json")).unwrap();
    let approver = KeyPin::from_json(text(&files, "approver-pin-1.json")).unwrap();
    assert_eq!(execution, execution_pin());
    assert_eq!(approver, approver_pin());

    // The package verifies with the code `praetore-verify outcomes` runs,
    // from its own files only, and each outcome is its request's.
    let attesters = [parse_attester_pin(text(&files, "attester-pin-1.hex")).unwrap()];
    let (_, journal) = praetore_core::journal_chain::verify_journal_receipts(
        text(&files, "journal.jsonl"),
        &attesters,
        None,
    )
    .unwrap();
    let report = verify_outcomes(
        approvals,
        &journal,
        &OutcomeKeys {
            evidence_attesters: &attesters,
            execution: &[execution],
            approvers: &[approver],
        },
    )
    .unwrap();
    let ends: Vec<(&str, Uuid)> = report
        .held
        .iter()
        .map(|held| (held.outcome.as_str(), held.request_id))
        .collect();
    assert_eq!(
        ends,
        vec![
            ("approved_executed", journal[0].request_id),
            ("rejected", journal[1].request_id),
            ("pending", journal[2].request_id),
        ]
    );

    let export: serde_json::Value = serde_json::from_str(text(&files, "export.json")).unwrap();
    assert_eq!(
        export["outcomes"],
        serde_json::json!({
            "file": "approvals.jsonl",
            "records": 7,
            "approvals": 1,
            "rejections": 1,
            "expirations": 0,
            "execution_receipts": 5,
            "execution_receipts_by_state": {
                "awaiting_approval": 3,
                "executed": 1,
                "not_dispatched": 1,
            },
            "held_requests": 3,
            "held_by_outcome": {
                "approved_executed": 1,
                "pending": 1,
                "rejected": 1,
            },
        })
    );
    assert_eq!(
        export["execution_pins"],
        serde_json::json!(["execution-pin-1.json"])
    );
    assert_eq!(
        export["approver_pins"],
        serde_json::json!(["approver-pin-1.json"])
    );
    // SHA256SUMS covers the new files.
    let sums = text(&files, "SHA256SUMS");
    for name in [
        "approvals.jsonl",
        "execution-pin-1.json",
        "approver-pin-1.json",
    ] {
        assert!(
            sums.contains(&format!(
                "{}  {name}\n",
                hex::encode(Sha256::digest(file(&files, name)))
            )),
            "{name}"
        );
    }
    let readme = text(&files, "LEEME.txt")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for needed in [
        "Tiene 7 registros: 1 aprobaciones, 1 rechazos, 0 vencimientos y 5 recibos de ejecución.",
        "praetore-verify outcomes --outcomes approvals.jsonl --journal journal.jsonl --attester-pin attester-pin-1.hex --execution-pin execution-pin-1.json --approver-pin approver-pin-1.json",
        "Esta exportación tiene 3 solicitudes retenidas: 1 approved_executed, 1 pending, 1 rejected.",
        "Los recibos de ejecución traen la salida del adaptador",
        "busque su request_id (o su evidence_id) en held",
        "No prueba que approvals.jsonl esté completo.",
    ] {
        assert!(readme.contains(needed), "LEEME.txt lacks {needed:?}");
    }
}

#[test]
fn a_record_signed_by_a_key_that_is_not_configured_yields_no_package() {
    let setup = Setup::held("d31-missing-key");
    let (receipts, outcomes) = held_set();
    // No execution or approver pin at all.
    assert_eq!(
        generate_with(
            setup.settings(),
            held_store_of(receipts.clone(), outcomes.clone()),
            None
        )
        .err(),
        Some(PackError::OutcomeKeyMissing)
    );
    // The right key under another key id is not the key the records name.
    let other_id = setup.key_pin("execution.json", &key_pin(EXECUTION_SECRET, "other-id"));
    let approver = setup.key_pin("approver.json", &approver_pin());
    assert_eq!(
        generate_with(
            setup.with_pins(vec![other_id], vec![approver.clone()]),
            held_store_of(receipts.clone(), outcomes.clone()),
            None
        )
        .err(),
        Some(PackError::OutcomeKeyMissing)
    );
    // Without the approver pin the decisions cannot be checked.
    let execution = setup.key_pin("execution.json", &execution_pin());
    assert_eq!(
        generate_with(
            setup.with_pins(vec![execution], Vec::new()),
            held_store_of(receipts.clone(), outcomes),
            None
        )
        .err(),
        Some(PackError::OutcomeKeyMissing)
    );
}

#[test]
fn a_record_that_does_not_verify_or_does_not_fit_yields_no_package() {
    let setup = Setup::held("d31-bad-record");
    let settings = setup.both_pins();
    let (receipts, outcomes) = held_set();
    let mut cases: Vec<Vec<Outcome>> = Vec::new();
    // The adapter output changed after signing.
    let mut changed = outcomes.clone();
    let Outcome::ExecutionReceipt(receipt) = &mut changed[2] else {
        unreachable!()
    };
    receipt.output = Some(serde_json::json!({"borrado": false}));
    cases.push(changed);
    // A decision flipped after signing.
    let mut flipped = outcomes.clone();
    let Outcome::HumanDecision(decision) = &mut flipped[4] else {
        unreachable!()
    };
    decision.outcome = HumanApprovalOutcome::Approve;
    cases.push(flipped);
    // The execution without its approval.
    let mut unapproved = outcomes.clone();
    unapproved.remove(1);
    cases.push(unapproved);
    // A record for a request that is not in the journal.
    let mut foreign = outcomes.clone();
    foreign.push(attested(
        &held_evidence("/tmp/otra"),
        AttestedOutcome::AwaitingApproval,
    ));
    cases.push(foreign);
    for case in cases {
        assert_eq!(
            generate_with(
                settings.clone(),
                held_store_of(receipts.clone(), case),
                None
            )
            .err(),
            Some(PackError::Outcomes)
        );
    }
    // Another key under the execution key id.
    let wrong = setup.key_pin("wrong.json", &key_pin([0x66; 32], EXECUTION_KEY_ID));
    let approver = setup.key_pin("approver.json", &approver_pin());
    assert_eq!(
        generate_with(
            setup.with_pins(vec![wrong], vec![approver]),
            held_store_of(receipts, outcomes),
            None
        )
        .err(),
        Some(PackError::Outcomes)
    );
}

#[test]
fn an_execution_or_approver_pin_that_verified_nothing_is_refused_and_named() {
    let setup = Setup::held("d31-unused");
    let execution = setup.key_pin("execution.json", &execution_pin());
    let approver = setup.key_pin("approver.json", &approver_pin());
    let spare = setup.key_pin("spare.json", &key_pin([0x66; 32], "spare"));
    let (receipts, outcomes) = held_set();
    // No records at all: an execution pin has nothing to verify.
    assert_eq!(
        generate_with(
            setup.with_pins(vec![execution.clone()], Vec::new()),
            held_store_of(receipts.clone(), Vec::new()),
            None
        )
        .err(),
        Some(PackError::KeyPinUnused {
            role: PinRole::Execution,
            index: 0,
            more: false
        })
    );
    // The second execution pin signed nothing.
    assert_eq!(
        generate_with(
            setup.with_pins(
                vec![execution.clone(), spare.clone()],
                vec![approver.clone()]
            ),
            held_store_of(receipts.clone(), outcomes.clone()),
            None
        )
        .err(),
        Some(PackError::KeyPinUnused {
            role: PinRole::Execution,
            index: 1,
            more: false
        })
    );
    // The first and third approver pins signed nothing.
    let third = setup.key_pin("third.json", &key_pin([0x67; 32], "third"));
    let error = generate_with(
        setup.with_pins(vec![execution], vec![spare, approver, third]),
        held_store_of(receipts.clone(), outcomes),
        None,
    )
    .unwrap_err();
    assert_eq!(
        error,
        PackError::KeyPinUnused {
            role: PinRole::Approver,
            index: 0,
            more: true
        }
    );
    let message = error.message();
    assert!(
        message.starts_with(
            "La primera clave configurada como clave pública de aprobador (en el orden de PRAETORE_CONSOLE_APPROVER_PIN_FILES) no verifica ningún recibo"
        ),
        "{message}"
    );
    assert!(message.contains("Puede haber más claves en la misma situación."));
}

#[test]
fn no_private_key_passes_as_an_execution_or_approver_pin() {
    let setup = Setup::held("d31-private");
    // This console's approver: a secret whose bytes also decode as a public
    // key, so only the approver check can stop it as a pin.
    let console_secret = (1u8..=255)
        .map(|byte| [byte; 32])
        .find(|bytes| VerifiedPublicKey::from_bytes(bytes).is_ok())
        .unwrap();
    let signer = ApproverSigner::new("approver-1", console_secret).unwrap();
    let approver_public = SigningKey::from_bytes(&console_secret)
        .verifying_key()
        .to_bytes();
    let raw_pin = |bytes: [u8; 32], key_id: &str| KeyPin {
        key_id: key_id.into(),
        public_key: VerifiedPublicKey::from_bytes(&bytes).unwrap(),
    };
    let (receipts, outcomes) = held_set();
    let execution = setup.key_pin("execution.json", &execution_pin());
    let approver = setup.key_pin("approver.json", &approver_pin());
    // The approver's secret as an approver pin.
    let secret = setup.key_pin("secret.json", &raw_pin(console_secret, "approver-2"));
    assert_eq!(
        generate_with(
            setup.with_pins(
                vec![execution.clone()],
                vec![approver.clone(), secret.clone()]
            ),
            held_store_of(receipts.clone(), outcomes.clone()),
            Some(&signer)
        )
        .err(),
        Some(PackError::KeyPinIsApproverKey {
            role: PinRole::Approver
        })
    );
    // Its public key or its secret as an execution pin.
    for bytes in [approver_public, console_secret] {
        let wrong = setup.key_pin("wrong.json", &raw_pin(bytes, "x"));
        assert_eq!(
            generate_with(
                setup.with_pins(vec![execution.clone(), wrong], vec![approver.clone()]),
                held_store_of(receipts.clone(), outcomes.clone()),
                Some(&signer)
            )
            .err(),
            Some(PackError::KeyPinIsApproverKey {
                role: PinRole::Execution
            })
        );
    }
    // Without the inbox configured, the secret verifies nothing and is
    // refused as such.
    assert!(matches!(
        generate_with(
            setup.with_pins(vec![execution.clone()], vec![approver.clone(), secret]),
            held_store_of(receipts.clone(), outcomes.clone()),
            None
        ),
        Err(PackError::KeyPinUnused {
            role: PinRole::Approver,
            index: 1,
            ..
        })
    ));
    // A bare hex key instead of a JSON pin, or a repeated key id.
    let bare = setup.dir.join("bare.hex");
    fs::write(&bare, hex::encode(approver_public)).unwrap();
    let again = setup.key_pin("again.json", &key_pin([0x66; 32], EXECUTION_KEY_ID));
    for pins in [vec![bare], vec![execution.clone(), again]] {
        assert_eq!(
            generate_with(
                setup.with_pins(pins, vec![approver.clone()]),
                held_store_of(receipts.clone(), outcomes.clone()),
                None
            )
            .err(),
            Some(PackError::KeyPins {
                role: PinRole::Execution
            })
        );
    }
    // With the right pins, the package is produced and holds no secret.
    let files = unpack(
        &generate_with(
            setup.with_pins(vec![execution], vec![approver]),
            held_store_of(receipts.clone(), outcomes),
            Some(&signer),
        )
        .unwrap(),
    );
    for (name, bytes) in &files {
        let text = String::from_utf8_lossy(bytes);
        for secret in [
            APPROVER_SECRET,
            EXECUTION_SECRET,
            HELD_ATTESTER_SECRET,
            console_secret,
        ] {
            assert!(!text.contains(&hex::encode(secret)), "{name}");
            assert!(!bytes.windows(32).any(|window| window == secret), "{name}");
        }
    }
}

#[tokio::test]
async fn a_d31_failure_shows_a_plain_message_and_no_package() {
    let setup = Setup::held("d31-page");
    let (receipts, outcomes) = held_set();
    let response = app(
        Some(setup.settings()),
        held_store_of(receipts, outcomes),
        false,
    )
    .oneshot(download())
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let reply: serde_json::Value = serde_json::from_slice(&body(response).await).unwrap();
    let message = reply.to_string();
    assert!(message.contains("está firmado con una clave que no está configurada"));
    assert!(!message.contains(&HELD_TENANT.to_string()));
}

#[test]
fn the_d31_messages_carry_no_ids_digits_or_hex() {
    for error in [
        PackError::KeyPins {
            role: PinRole::Execution,
        },
        PackError::KeyPins {
            role: PinRole::Approver,
        },
        PackError::KeyPinIsApproverKey {
            role: PinRole::Execution,
        },
        PackError::KeyPinIsApproverKey {
            role: PinRole::Approver,
        },
        PackError::KeyPinUnused {
            role: PinRole::Execution,
            index: 15,
            more: true,
        },
        PackError::OutcomeKeyMissing,
        PackError::Outcomes,
        PackError::OutcomesTooLarge,
    ] {
        let message = error.message();
        assert!(!message.chars().any(|c| c.is_ascii_digit()), "{message}");
        assert!(
            message.ends_with("No se generó ningún paquete."),
            "{message}"
        );
    }
    let settings = PackSettings::new("p".into(), vec!["a".into()]).unwrap();
    assert!(
        settings
            .clone()
            .with_outcome_pins(vec!["e".into(); 16], vec!["a".into(); 16])
            .is_ok()
    );
    assert!(
        settings
            .clone()
            .with_outcome_pins(vec!["e".into(); 17], Vec::new())
            .is_err()
    );
    assert!(
        settings
            .with_outcome_pins(Vec::new(), vec!["a".into(); 17])
            .is_err()
    );
}
