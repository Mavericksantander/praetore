//! D2 tests: the inbox, the signed decision and the single dispatch, against
//! a stand-in gateway that keeps the gateway's rules (one decision, one
//! dispatch, signature checked against the challenge).

use crate::{
    aprobador::{self, ApprovalGateway, ApproverSigner, GatewayReply},
    bandeja::{PendingColumns, PendingFacts, PendingKind, PendingRef, pending_from_columns},
    *,
};
use axum::body::to_bytes;
use ed25519_dalek::{Signature, SigningKey, Verifier};
use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, AuthorizationIntentV2, Decision, Evidence,
    EvidenceAttesterKey,
};
use praetore_gateway::{
    ApprovalChallenge, ApprovalChallengeView, ExecutionKey, HumanApprovalDecision, action_digest,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use tower::ServiceExt;
use uuid::Uuid;

const TENANT: Uuid = Uuid::from_u128(1);
const ORIGIN: &str = "http://127.0.0.1:8090";
const APPROVER_SECRET: [u8; 32] = [0x44; 32];

fn pending_evidence(
    action_type: &str,
    target: &str,
    expires_at: OffsetDateTime,
) -> (Evidence, String) {
    pending_evidence_with(
        action_type,
        target,
        expires_at,
        json!({"nota": "texto-libre"}),
    )
}

fn pending_evidence_with(
    action_type: &str,
    target: &str,
    expires_at: OffsetDateTime,
    parameters: Value,
) -> (Evidence, String) {
    let expires_at = expires_at.replace_nanosecond(0).unwrap();
    let agent_key = AgentKeyPair::from_secret_bytes(&[0x51; 32]);
    let agent = agent_key.identity(AgentId::new());
    let authority = Authority::new(
        agent.id.clone(),
        "consola-test",
        vec!["archivo:borrar".into()],
    )
    .with_constraint("tenant_id", TENANT.to_string());
    let authority_digest = authority.content_digest().unwrap();
    let action = Action::new(action_type, Some(target.into()), parameters)
        .unwrap()
        .with_capability("archivo:borrar");
    let mut evidence = Evidence::new_with_context(
        Uuid::new_v4(),
        agent,
        authority,
        action,
        Decision::require_approval("motivo-interno", praetore_core::DecidedBy::rule("regla")),
        None,
        BTreeMap::new(),
    )
    .unwrap();
    let stamp = expires_at.format(&Rfc3339).unwrap();
    evidence.intent_v2 = Some(AuthorizationIntentV2 {
        audience: "consola-test".into(),
        issued_at: (expires_at - Duration::minutes(10))
            .format(&Rfc3339)
            .unwrap(),
        expires_at: stamp.clone(),
        policy_digest: "cd".repeat(32),
    });
    evidence.freshness_valid_until = Some(stamp);
    // The rest of the HighAssurance shape a gateway hold carries.
    evidence.decided_at = Some(
        (expires_at - Duration::minutes(10))
            .format(&Rfc3339)
            .unwrap(),
    );
    evidence.evaluation_mode = Some("high_assurance".into());
    evidence.authority_digest = Some(authority_digest);
    evidence.semantics_version = Some(2);
    evidence.agent_signature = Some("ef".repeat(64));
    // Recomputes the integrity hash over the fields set above.
    evidence.bind_policy_digest("cd".repeat(32)).unwrap();
    evidence
        .sign(&EvidenceAttesterKey::from_secret_bytes(&[0x52; 32]))
        .unwrap();
    let json = evidence.to_json().unwrap();
    (evidence, json)
}

fn facts_for(evidence: &Evidence, json: String, kind: PendingKind) -> PendingFacts {
    pending_from_columns(
        TENANT,
        PendingColumns {
            created_at: OffsetDateTime::now_utc() - Duration::minutes(1),
            agent_id: *evidence.agent.id.as_uuid(),
            request_id: evidence.request_id,
            kind,
            evidence_json: json,
        },
    )
    .unwrap()
}

struct MemoryInbox {
    items: Vec<PendingFacts>,
    unreadable: u32,
}

impl InboxStore for MemoryInbox {
    fn pending(&self) -> Result<InboxPage, HistoryError> {
        let mut agents: Vec<Uuid> = self.items.iter().map(|f| f.key.agent_id).collect();
        agents.sort();
        agents.dedup();
        Ok(InboxPage {
            items: self.items.clone(),
            unreadable: self.unreadable,
            truncated: false,
            agents,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Pending,
    Approved,
    Rejected,
    Dispatched,
}

/// Stand-in for the gateway's approval endpoints, keeping its rules.
struct FakeGateway {
    view: ApprovalChallengeView,
    approver: ed25519_dalek::VerifyingKey,
    state: Mutex<FakeState>,
}

struct FakeState {
    held: Held,
    transient_dispatch_failures: u32,
    calls: Vec<&'static str>,
    decisions: Vec<HumanApprovalDecision>,
}

impl FakeGateway {
    fn new(evidence: &Evidence) -> Self {
        Self::with_action(evidence, evidence.action.clone())
    }

    /// The gateway shows `action`; the challenge commits to the evidence.
    fn with_action(evidence: &Evidence, shown: Action) -> Self {
        let digest = action_digest(&evidence.action).unwrap();
        let challenge = ApprovalChallenge::from_evidence(evidence, &digest).unwrap();
        Self {
            view: ApprovalChallengeView {
                challenge,
                action: shown,
            },
            approver: SigningKey::from_bytes(&APPROVER_SECRET).verifying_key(),
            state: Mutex::new(FakeState {
                held: Held::Pending,
                transient_dispatch_failures: 0,
                calls: Vec::new(),
                decisions: Vec::new(),
            }),
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.state.lock().unwrap().calls.clone()
    }

    fn held(&self) -> Held {
        self.state.lock().unwrap().held
    }
}

fn answered(status: u16, body: Value) -> GatewayReply {
    GatewayReply::Answered {
        status,
        body: body.to_string(),
    }
}

impl ApprovalGateway for FakeGateway {
    fn challenge(&self, key: &ExecutionKey) -> GatewayReply {
        let mut state = self.state.lock().unwrap();
        state.calls.push("challenge");
        assert_eq!(key.request_id, self.view.challenge.request_id);
        if state.held != Held::Pending {
            return answered(409, json!({"code": "approval_not_pending"}));
        }
        answered(200, serde_json::to_value(&self.view).unwrap())
    }

    fn decide(&self, _key: &ExecutionKey, decision_json: &str) -> GatewayReply {
        let mut state = self.state.lock().unwrap();
        state.calls.push("decide");
        let decision = HumanApprovalDecision::from_json(decision_json).unwrap();
        let signature: [u8; 64] = hex::decode(&decision.signature)
            .unwrap()
            .try_into()
            .unwrap();
        if decision.challenge != self.view.challenge
            || self
                .approver
                .verify(
                    &decision.signing_message().unwrap(),
                    &Signature::from_bytes(&signature),
                )
                .is_err()
        {
            return answered(403, json!({"code": "invalid_approval_signature"}));
        }
        if state.held != Held::Pending {
            return answered(409, json!({"code": "approval_not_pending"}));
        }
        state.decisions.push(decision.clone());
        match decision.outcome {
            praetore_gateway::HumanApprovalOutcome::Approve => {
                state.held = Held::Approved;
                answered(200, json!({"status": "approved_pending_dispatch"}))
            }
            praetore_gateway::HumanApprovalOutcome::Reject => {
                state.held = Held::Rejected;
                answered(200, json!({"status": "rejected"}))
            }
        }
    }

    fn dispatch(&self, _key: &ExecutionKey) -> GatewayReply {
        let mut state = self.state.lock().unwrap();
        state.calls.push("dispatch");
        if state.held != Held::Approved {
            return answered(409, json!({"code": "execution_state_conflict"}));
        }
        if state.transient_dispatch_failures > 0 {
            state.transient_dispatch_failures -= 1;
            return answered(503, json!({"code": "dispatch_temporarily_refused"}));
        }
        state.held = Held::Dispatched;
        answered(
            200,
            json!({"execution": "confirmed", "authorization": "requires_approval"}),
        )
    }
}

fn console(items: Vec<PendingFacts>, unreadable: u32, gateway: Arc<FakeGateway>) -> Router {
    let signer = ApproverSigner::new("consola-aprobador", APPROVER_SECRET).unwrap();
    let inbox = Inbox::new(Arc::new(MemoryInbox { items, unreadable }), gateway, signer);
    ConsoleState::new(
        Arc::new(NoHistory),
        LocalSession::from_secret([0x11; 32]),
        HashMap::from([(Uuid::from_u128(99), "nadie".to_owned())]),
    )
    .with_inbox(inbox)
    .router()
}

fn cookie() -> String {
    format!("{}={}", sesion::COOKIE_NAME, hex::encode([0x11; 32]))
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .header(header::HOST, "127.0.0.1:8090")
        .uri(uri)
        .header(header::COOKIE, cookie())
        .body(Body::empty())
        .unwrap()
}

fn post(uri: &str) -> Request<Body> {
    Request::builder()
        .header(header::HOST, "127.0.0.1:8090")
        .method("POST")
        .uri(uri)
        .header(header::COOKIE, cookie())
        .header(header::ORIGIN, ORIGIN)
        .header(ACTION_HEADER, "1")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
}

async fn json_of(response: Response) -> (StatusCode, Value, String) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    (status, serde_json::from_str(&text).unwrap(), text)
}

async fn first_reference(app: &Router) -> String {
    let (_, list, _) = json_of(app.clone().oneshot(get("/api/bandeja")).await.unwrap()).await;
    list["solicitudes"][0]["referencia"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn looks_technical(text: &str) -> bool {
    // UUIDs, 32+ hex runs, RFC 3339 instants.
    let hex_run = text
        .split(|c: char| !c.is_ascii_hexdigit())
        .any(|run| run.len() >= 32);
    let uuid = text
        .split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
        .any(|word| Uuid::parse_str(word).is_ok());
    let rfc3339 = text.contains("T") && text.contains("Z\"") && text.contains(":");
    hex_run || uuid || rfc3339
}

#[tokio::test]
async fn the_inbox_says_who_what_on_what_and_until_when_in_plain_words() {
    let in_ten = OffsetDateTime::now_utc() + Duration::minutes(10);
    let (waiting, waiting_json) = pending_evidence("borrar_archivo", "informe-trimestral", in_ten);
    let (approved, approved_json) = pending_evidence("enviar_correo", "clientes", in_ten);
    let (late, late_json) = pending_evidence(
        "leer_archivo",
        "viejo",
        OffsetDateTime::now_utc() - Duration::minutes(1),
    );
    let items = vec![
        facts_for(&waiting, waiting_json, PendingKind::AwaitingApproval),
        facts_for(
            &approved,
            approved_json,
            PendingKind::ApprovedPendingExecution,
        ),
        facts_for(&late, late_json, PendingKind::AwaitingApproval),
    ];
    let gateway = Arc::new(FakeGateway::new(&waiting));
    let app = console(items, 1, gateway.clone());
    let (status, list, text) =
        json_of(app.clone().oneshot(get("/api/bandeja")).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let first = &list["solicitudes"][0];
    assert_eq!(first["situacion"], "pendiente de aprobación");
    assert_eq!(first["queria"], "borrar_archivo");
    assert_eq!(first["sobre"], "informe-trimestral");
    assert!(first["agente"].as_str().unwrap().starts_with("Agente"));
    assert!(first["vale_hasta"].as_str().unwrap().ends_with(" UTC"));
    assert!(first["vale_hasta"].as_str().unwrap().contains(" de "));
    assert!(first["queda"].as_str().unwrap().starts_with("queda"));
    assert_eq!(first["puede_aprobar"], true);
    assert_eq!(first["puede_rechazar"], true);
    assert_eq!(first["parametros_visibles"], true);
    assert_eq!(
        first["parametros"],
        json!([{"clave": "nota", "valor": "\"texto-libre\""}])
    );
    assert!(first.get("nota").is_none());
    assert_eq!(first["puede_ejecutar"], false);
    let second = &list["solicitudes"][1];
    assert_eq!(second["situacion"], "aprobado, pendiente de ejecución");
    assert_eq!(second["puede_aprobar"], false);
    assert_eq!(second["puede_rechazar"], false);
    assert_eq!(second["puede_ejecutar"], true);
    assert_eq!(list["solicitudes"].as_array().unwrap().len(), 2);
    assert_eq!(list["vencidas"], 1);
    assert_eq!(list["ilegibles"], 1);
    assert!(!text.contains("motivo-interno"));
    assert!(!text.contains("awaiting_approval"));
    assert!(!text.contains("approved_pending_dispatch"));
    assert!(!looks_technical(&text), "{text}");
    // Reading the inbox never talks to the gateway.
    assert!(gateway.calls().is_empty());
}

#[tokio::test]
async fn approve_then_execute_signs_once_on_the_server_and_dispatches_once() {
    let (evidence, json) = pending_evidence(
        "borrar_archivo",
        "informe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    );
    let gateway = Arc::new(FakeGateway::new(&evidence));
    let app = console(
        vec![facts_for(&evidence, json, PendingKind::AwaitingApproval)],
        0,
        gateway.clone(),
    );
    let reference = first_reference(&app).await;

    let (status, approved, text) = json_of(
        app.clone()
            .oneshot(post(&format!("/api/bandeja/{reference}/aprobar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(approved["situacion"], "aprobado, pendiente de ejecución");
    assert_eq!(approved["puede_ejecutar"], true);
    assert!(!looks_technical(&text));
    assert!(!text.contains("signature"));
    assert_eq!(gateway.held(), Held::Approved);
    {
        let state = gateway.state.lock().unwrap();
        let decision = &state.decisions[0];
        assert_eq!(decision.approver_key_id, "consola-aprobador");
        assert_eq!(decision.challenge, gateway.view.challenge);
    }

    // Approving again never reaches a second decision.
    let (_, again, _) = json_of(
        app.clone()
            .oneshot(post(&format!("/api/bandeja/{reference}/aprobar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(again["situacion"], "sin cambios");
    assert!(
        again["mensaje"]
            .as_str()
            .unwrap()
            .contains("ya tiene una decisión")
    );
    assert_eq!(gateway.state.lock().unwrap().decisions.len(), 1);

    let (_, executed, _) = json_of(
        app.clone()
            .oneshot(post(&format!("/api/bandeja/{reference}/ejecutar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(executed["situacion"], "aprobado");
    assert_eq!(executed["puede_ejecutar"], false);
    assert_eq!(gateway.held(), Held::Dispatched);

    let (_, twice, _) = json_of(
        app.clone()
            .oneshot(post(&format!("/api/bandeja/{reference}/ejecutar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(twice["puede_ejecutar"], false);
    assert_eq!(
        gateway.calls(),
        vec!["challenge", "decide", "challenge", "dispatch", "dispatch"]
    );
}

#[tokio::test]
async fn a_failed_dispatch_stays_approved_and_only_the_dispatch_is_retried() {
    let (evidence, json) = pending_evidence(
        "borrar_archivo",
        "informe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    );
    let gateway = Arc::new(FakeGateway::new(&evidence));
    gateway.state.lock().unwrap().transient_dispatch_failures = 1;
    let app = console(
        vec![facts_for(&evidence, json, PendingKind::AwaitingApproval)],
        0,
        gateway.clone(),
    );
    let reference = first_reference(&app).await;
    let _ = app
        .clone()
        .oneshot(post(&format!("/api/bandeja/{reference}/aprobar")))
        .await
        .unwrap();
    let (_, failed, _) = json_of(
        app.clone()
            .oneshot(post(&format!("/api/bandeja/{reference}/ejecutar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(failed["situacion"], "aprobado, pendiente de ejecución");
    assert_eq!(failed["puede_ejecutar"], true);
    assert_eq!(gateway.held(), Held::Approved);
    let (_, retried, _) = json_of(
        app.clone()
            .oneshot(post(&format!("/api/bandeja/{reference}/ejecutar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(retried["situacion"], "aprobado");
    assert_eq!(gateway.held(), Held::Dispatched);
    assert_eq!(
        gateway.calls(),
        vec!["challenge", "decide", "dispatch", "dispatch"]
    );
    assert_eq!(gateway.state.lock().unwrap().decisions.len(), 1);
}

#[tokio::test]
async fn a_rejection_is_final_and_never_executes() {
    let (evidence, json) = pending_evidence(
        "borrar_archivo",
        "informe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    );
    let gateway = Arc::new(FakeGateway::new(&evidence));
    let app = console(
        vec![facts_for(&evidence, json, PendingKind::AwaitingApproval)],
        0,
        gateway.clone(),
    );
    let reference = first_reference(&app).await;
    let (_, rejected, _) = json_of(
        app.clone()
            .oneshot(post(&format!("/api/bandeja/{reference}/rechazar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(rejected["situacion"], "rechazado");
    assert_eq!(rejected["puede_ejecutar"], false);
    let (_, approve_after, _) = json_of(
        app.clone()
            .oneshot(post(&format!("/api/bandeja/{reference}/aprobar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(approve_after["situacion"], "sin cambios");
    let _ = app
        .clone()
        .oneshot(post(&format!("/api/bandeja/{reference}/ejecutar")))
        .await
        .unwrap();
    assert_eq!(gateway.held(), Held::Rejected);
    assert_eq!(gateway.state.lock().unwrap().decisions.len(), 1);
}

#[tokio::test]
async fn nothing_is_signed_when_the_gateway_shows_another_action() {
    let (evidence, json) = pending_evidence(
        "borrar_archivo",
        "informe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    );
    let other = Action::new("borrar_archivo", Some("todo".into()), json!({}))
        .unwrap()
        .with_capability("archivo:borrar");
    let gateway = Arc::new(FakeGateway::with_action(&evidence, other));
    let app = console(
        vec![facts_for(&evidence, json, PendingKind::AwaitingApproval)],
        0,
        gateway.clone(),
    );
    let reference = first_reference(&app).await;
    let (_, refused, _) = json_of(
        app.clone()
            .oneshot(post(&format!("/api/bandeja/{reference}/aprobar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(refused["situacion"], "sin cambios");
    assert!(
        refused["mensaje"]
            .as_str()
            .unwrap()
            .contains("No se firmó nada")
    );
    assert_eq!(gateway.calls(), vec!["challenge"]);
    assert_eq!(gateway.held(), Held::Pending);
}

#[test]
fn nothing_is_signed_when_the_challenge_commits_to_another_action_than_the_one_shown() {
    let expires = OffsetDateTime::now_utc() + Duration::minutes(10);
    let (shown, shown_json) = pending_evidence("borrar_archivo", "informe", expires);
    let facts = facts_for(&shown, shown_json, PendingKind::AwaitingApproval);
    // Same key in the journal, but the gateway's challenge is for a
    // different, self-consistent action.
    let (mut other, _) = pending_evidence("borrar_archivo", "todo", expires);
    other.request_id = shown.request_id;
    other.agent = shown.agent.clone();
    let gateway = FakeGateway::new(&other);
    let signer = ApproverSigner::new("consola-aprobador", APPROVER_SECRET).unwrap();
    let pending = PendingRef::from(&facts);
    let outcome = aprobador::decide(
        &gateway,
        &signer,
        &pending,
        praetore_gateway::HumanApprovalOutcome::Approve,
    );
    assert_eq!(outcome.situacion, "sin cambios");
    assert_eq!(gateway.calls(), vec!["challenge"]);
}

#[tokio::test]
async fn actions_need_the_console_page_and_a_known_reference() {
    let (evidence, json) = pending_evidence(
        "borrar_archivo",
        "informe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    );
    let gateway = Arc::new(FakeGateway::new(&evidence));
    let app = console(
        vec![facts_for(&evidence, json, PendingKind::AwaitingApproval)],
        0,
        gateway.clone(),
    );
    let reference = first_reference(&app).await;
    let uri = format!("/api/bandeja/{reference}/aprobar");
    let mut cases = Vec::new();
    for (origin, marker, site) in [
        (None, Some("1"), None),
        (Some("http://127.0.0.1:3000"), Some("1"), None),
        (Some("http://localhost:8090.evil.example"), Some("1"), None),
        (Some(ORIGIN), None, None),
        (Some(ORIGIN), Some("0"), None),
        (Some(ORIGIN), Some("1"), Some("same-site")),
        (Some(ORIGIN), Some("1"), Some("cross-site")),
    ] {
        let mut request = Request::builder()
            .header(header::HOST, "127.0.0.1:8090")
            .method("POST")
            .uri(&uri)
            .header(header::COOKIE, cookie());
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        if let Some(marker) = marker {
            request = request.header(ACTION_HEADER, marker);
        }
        if let Some(site) = site {
            request = request.header("sec-fetch-site", site);
        }
        cases.push(request.body(Body::empty()).unwrap());
    }
    for request in cases {
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let no_cookie = Request::builder()
        .header(header::HOST, "127.0.0.1:8090")
        .method("POST")
        .uri(&uri)
        .header(header::ORIGIN, ORIGIN)
        .header(ACTION_HEADER, "1")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(no_cookie).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    // `localhost` on the console's port is the same page.
    let localhost = Request::builder()
        .header(header::HOST, "127.0.0.1:8090")
        .method("POST")
        .uri("/api/bandeja/abcdefghjkmnpqrstuvw/aprobar")
        .header(header::COOKIE, cookie())
        .header(header::ORIGIN, "http://localhost:8090")
        .header(ACTION_HEADER, "1")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(localhost).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    for unknown in [
        "/api/bandeja/abcdefghjkmnpqrstuvw/aprobar".to_owned(),
        format!("/api/bandeja/{}/aprobar", evidence.request_id),
        "/api/bandeja/..%2F..%2Fx/aprobar".to_owned(),
    ] {
        let response = app.clone().oneshot(post(&unknown)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{unknown}");
    }
    let wrong_method = app
        .clone()
        .oneshot(get(&format!("/api/bandeja/{reference}/aprobar")))
        .await
        .unwrap();
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(gateway.calls().is_empty());
}

#[tokio::test]
async fn without_an_approver_the_inbox_is_off_and_nothing_mutates() {
    let app = ConsoleState::new(
        Arc::new(NoHistory),
        LocalSession::from_secret([0x11; 32]),
        HashMap::new(),
    )
    .router();
    let (status, body, _) = json_of(app.clone().oneshot(get("/api/bandeja")).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body["mensaje"]
            .as_str()
            .unwrap()
            .contains("no está configurada")
    );
    let response = app
        .oneshot(post("/api/bandeja/abcdefghjkmnpqrstuvw/aprobar"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn outcomes_never_offer_a_second_decision() {
    struct Scripted(Mutex<Vec<GatewayReply>>);
    impl ApprovalGateway for Scripted {
        fn challenge(&self, _: &ExecutionKey) -> GatewayReply {
            self.0.lock().unwrap().remove(0)
        }
        fn decide(&self, _: &ExecutionKey, _: &str) -> GatewayReply {
            self.0.lock().unwrap().remove(0)
        }
        fn dispatch(&self, _: &ExecutionKey) -> GatewayReply {
            self.0.lock().unwrap().remove(0)
        }
    }
    let (evidence, json) = pending_evidence(
        "borrar_archivo",
        "informe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    );
    let pending = PendingRef::from(&facts_for(&evidence, json, PendingKind::AwaitingApproval));
    let signer = ApproverSigner::new("consola-aprobador", APPROVER_SECRET).unwrap();
    for reply in [
        GatewayReply::NotSent,
        GatewayReply::Unconfirmed,
        answered(404, json!({})),
        answered(409, json!({"code": "approval_not_pending"})),
        answered(410, json!({"code": "approval_expired"})),
        answered(403, json!({"code": "caller_not_authorized"})),
        answered(503, json!({})),
        answered(200, json!({"no": "es un challenge"})),
    ] {
        let gateway = Scripted(Mutex::new(vec![reply]));
        let outcome = aprobador::decide(
            &gateway,
            &signer,
            &pending,
            praetore_gateway::HumanApprovalOutcome::Approve,
        );
        assert!(!outcome.puede_ejecutar, "{outcome:?}");
        assert!(gateway.0.lock().unwrap().is_empty());
    }
    const STILL: &str = "aprobado, pendiente de ejecución";
    for (reply, retry, situacion) in [
        (GatewayReply::NotSent, true, STILL),
        (
            answered(503, json!({"code": "dispatch_temporarily_refused"})),
            true,
            STILL,
        ),
        (
            answered(503, json!({"code": "authorization_unavailable"})),
            true,
            STILL,
        ),
        // These may come after the effect: never "sin ejecutar". Retrying
        // is safe, the gateway claims the dispatch once.
        (GatewayReply::Unconfirmed, true, "sin confirmar"),
        (
            answered(503, json!({"code": "execution_state_unavailable"})),
            true,
            "sin confirmar",
        ),
        (
            answered(503, json!({"code": "gateway_unavailable"})),
            true,
            "sin confirmar",
        ),
        (
            answered(500, json!({"code": "gateway_configuration_error"})),
            true,
            "sin confirmar",
        ),
        (
            answered(403, json!({"code": "action_not_dispatchable"})),
            false,
            "no se ejecutó",
        ),
        (
            answered(502, json!({"code": "action_effect_failed"})),
            false,
            "aprobado",
        ),
        (
            answered(409, json!({"code": "execution_state_conflict"})),
            false,
            "sin cambios",
        ),
        (
            answered(410, json!({"code": "approval_expired"})),
            false,
            "expirado",
        ),
        (
            answered(200, json!({"execution": "failed"})),
            false,
            "aprobado",
        ),
    ] {
        let gateway = Scripted(Mutex::new(vec![reply]));
        let outcome = aprobador::dispatch(&gateway, &pending);
        assert_eq!(outcome.puede_ejecutar, retry, "{outcome:?}");
        assert_eq!(outcome.situacion, situacion, "{outcome:?}");
        if situacion == "sin confirmar" {
            assert!(!outcome.mensaje.contains("sin ejecutar"), "{outcome:?}");
        }
    }
}

#[test]
fn a_receipt_from_another_tenant_or_without_a_window_is_not_offered() {
    let (evidence, json) = pending_evidence(
        "borrar_archivo",
        "informe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    );
    let columns = |tenant: Uuid, agent: Uuid, json: String| {
        pending_from_columns(
            tenant,
            PendingColumns {
                created_at: OffsetDateTime::now_utc(),
                agent_id: agent,
                request_id: evidence.request_id,
                kind: PendingKind::AwaitingApproval,
                evidence_json: json,
            },
        )
    };
    let agent = *evidence.agent.id.as_uuid();
    assert!(columns(TENANT, agent, json.clone()).is_ok());
    assert!(columns(Uuid::from_u128(2), agent, json.clone()).is_err());
    assert!(columns(TENANT, Uuid::from_u128(5), json.clone()).is_err());
    let tampered = json.replace("informe", "informe-otro");
    assert!(columns(TENANT, agent, tampered).is_err());
    let mut no_window = evidence.clone();
    no_window.intent_v2 = None;
    no_window.decided_at = None;
    no_window.evaluation_mode = None;
    no_window.freshness_valid_until = None;
    no_window.authority_digest = None;
    no_window.semantics_version = None;
    no_window.bind_policy_digest("cd".repeat(32)).unwrap();
    no_window
        .sign(&EvidenceAttesterKey::from_secret_bytes(&[0x52; 32]))
        .unwrap();
    assert!(columns(TENANT, agent, no_window.to_json().unwrap()).is_err());
}

#[tokio::test]
async fn another_host_name_reads_nothing() {
    let (evidence, json) = pending_evidence(
        "borrar_archivo",
        "informe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    );
    let gateway = Arc::new(FakeGateway::new(&evidence));
    let app = console(
        vec![facts_for(&evidence, json, PendingKind::AwaitingApproval)],
        0,
        gateway.clone(),
    );
    for host in [
        None,
        Some("evil.example:8090"),
        Some("127.0.0.1:9999"),
        Some("localhost:8091"),
    ] {
        for uri in ["/", "/api/bandeja", "/api/historial"] {
            let mut request = Request::builder().uri(uri).header(header::COOKIE, cookie());
            if let Some(host) = host {
                request = request.header(header::HOST, host);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::MISDIRECTED_REQUEST,
                "{host:?} {uri}"
            );
            assert!(response.headers().get(header::SET_COOKIE).is_none());
        }
    }
    let localhost = Request::builder()
        .uri("/api/bandeja")
        .header(header::HOST, "localhost:8090")
        .header(header::COOKIE, cookie())
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(localhost).await.unwrap().status(),
        StatusCode::OK
    );
    assert!(gateway.calls().is_empty());
}

#[tokio::test]
async fn agent_text_is_shown_inert_and_a_cut_list_says_so() {
    let (evidence, json) = pending_evidence(
        "borrar_archivo",
        "informe\u{202e}fdp.exe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    );
    let facts = facts_for(&evidence, json, PendingKind::AwaitingApproval);
    struct Cut(PendingFacts);
    impl InboxStore for Cut {
        fn pending(&self) -> Result<InboxPage, HistoryError> {
            Ok(InboxPage {
                items: vec![self.0.clone()],
                unreadable: 0,
                truncated: true,
                agents: vec![self.0.key.agent_id],
            })
        }
    }
    let app = ConsoleState::new(
        Arc::new(NoHistory),
        LocalSession::from_secret([0x11; 32]),
        HashMap::new(),
    )
    .with_inbox(Inbox::new(
        Arc::new(Cut(facts)),
        Arc::new(FakeGateway::new(&evidence)),
        ApproverSigner::new("consola-aprobador", APPROVER_SECRET).unwrap(),
    ))
    .router();
    let (_, list, text) = json_of(app.oneshot(get("/api/bandeja")).await.unwrap()).await;
    assert_eq!(list["hay_mas"], true);
    assert_eq!(list["solicitudes"][0]["sobre"], "informe\\u{202e}fdp.exe");
    assert!(!text.contains('\u{202e}'));
}

#[test]
fn nothing_is_signed_when_any_part_of_the_challenge_differs() {
    let (evidence, json) = pending_evidence(
        "borrar_archivo",
        "informe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    );
    let pending = PendingRef::from(&facts_for(&evidence, json, PendingKind::AwaitingApproval));
    let signer = ApproverSigner::new("consola-aprobador", APPROVER_SECRET).unwrap();
    let edits: [fn(&mut ApprovalChallenge); 4] = [
        |challenge| challenge.expires_at = "2099-01-01T00:00:00Z".into(),
        |challenge| challenge.policy_digest = "00".repeat(32),
        |challenge| challenge.evidence_hash = "11".repeat(32),
        |challenge| challenge.evidence_id = Uuid::from_u128(77),
    ];
    for edit in edits {
        let mut gateway = FakeGateway::new(&evidence);
        edit(&mut gateway.view.challenge);
        let outcome = aprobador::decide(
            &gateway,
            &signer,
            &pending,
            praetore_gateway::HumanApprovalOutcome::Approve,
        );
        assert_eq!(outcome.situacion, "sin cambios");
        assert_eq!(gateway.calls(), vec!["challenge"]);
    }
}

#[tokio::test]
async fn two_requests_that_differ_only_in_the_amount_look_different() {
    let expires = OffsetDateTime::now_utc() + Duration::minutes(10);
    let (small, small_json) = pending_evidence_with(
        "transferir",
        "cuenta-1",
        expires,
        json!({"monto": 10, "moneda": "CLP"}),
    );
    let (large, large_json) = pending_evidence_with(
        "transferir",
        "cuenta-1",
        expires,
        json!({"monto": 100000, "moneda": "CLP"}),
    );
    let gateway = Arc::new(FakeGateway::new(&small));
    let app = console(
        vec![
            facts_for(&small, small_json, PendingKind::AwaitingApproval),
            facts_for(&large, large_json, PendingKind::AwaitingApproval),
        ],
        0,
        gateway,
    );
    let (_, list, _) = json_of(app.oneshot(get("/api/bandeja")).await.unwrap()).await;
    let first = &list["solicitudes"][0];
    let second = &list["solicitudes"][1];
    assert_eq!(first["queria"], second["queria"]);
    assert_eq!(first["sobre"], second["sobre"]);
    assert_ne!(first["parametros"], second["parametros"]);
    assert_eq!(
        first["parametros"],
        json!([{"clave": "moneda", "valor": "\"CLP\""}, {"clave": "monto", "valor": "10"}])
    );
    assert_eq!(
        second["parametros"],
        json!([{"clave": "moneda", "valor": "\"CLP\""}, {"clave": "monto", "valor": "100000"}])
    );
}

#[tokio::test]
async fn parameters_that_do_not_fit_can_only_be_rejected_here() {
    let many: serde_json::Map<String, Value> = (0..21)
        .map(|index| (format!("k{index:02}"), json!(index)))
        .collect();
    for parameters in [
        Value::Object(many),
        json!({"a.b": 1}),
        json!({"monto": 1, "Monto": 2}),
        json!({"v": "cafe\u{301}"}),
    ] {
        only_rejecting(parameters).await;
    }
}

async fn only_rejecting(parameters: Value) {
    let (evidence, json) = pending_evidence_with(
        "borrar_archivo",
        "informe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
        parameters.clone(),
    );
    let gateway = Arc::new(FakeGateway::new(&evidence));
    let app = console(
        vec![facts_for(&evidence, json, PendingKind::AwaitingApproval)],
        0,
        gateway.clone(),
    );
    let (_, list, _) = json_of(app.clone().oneshot(get("/api/bandeja")).await.unwrap()).await;
    let item = &list["solicitudes"][0];
    assert_eq!(item["parametros_visibles"], false, "{parameters}");
    assert_eq!(item["parametros"], json!([]));
    assert_eq!(item["puede_aprobar"], false);
    assert_eq!(item["puede_rechazar"], true);
    assert!(item["nota"].as_str().unwrap().contains("praetore approve"));
    let reference = item["referencia"].as_str().unwrap().to_owned();
    // Refused server side even if the page asked anyway.
    let (_, refused, _) = json_of(
        app.clone()
            .oneshot(post(&format!("/api/bandeja/{reference}/aprobar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(refused["situacion"], "sin cambios");
    assert!(gateway.calls().is_empty());
    let (_, rejected, _) = json_of(
        app.oneshot(post(&format!("/api/bandeja/{reference}/rechazar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(rejected["situacion"], "rechazado");
    assert_eq!(gateway.held(), Held::Rejected);
}

#[tokio::test]
async fn texts_numbers_and_lists_are_told_apart_in_the_inbox() {
    let expires = OffsetDateTime::now_utc() + Duration::minutes(10);
    let (text, text_json) = pending_evidence_with(
        "transferir",
        "cuenta-1",
        expires,
        json!({"monto": "10", "etiquetas": "a, b"}),
    );
    let (typed, typed_json) = pending_evidence_with(
        "transferir",
        "cuenta-1",
        expires,
        json!({"monto": 10, "etiquetas": ["a", "b"]}),
    );
    let gateway = Arc::new(FakeGateway::new(&text));
    let app = console(
        vec![
            facts_for(&text, text_json, PendingKind::AwaitingApproval),
            facts_for(&typed, typed_json, PendingKind::AwaitingApproval),
        ],
        0,
        gateway,
    );
    let response = app.oneshot(get("/api/bandeja")).await.unwrap();
    assert_eq!(
        response.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
    let (_, list, _) = json_of(response).await;
    assert_eq!(
        list["solicitudes"][0]["parametros"],
        json!([
            {"clave": "etiquetas", "valor": "\"a, b\""},
            {"clave": "monto", "valor": "\"10\""},
        ])
    );
    assert_eq!(
        list["solicitudes"][1]["parametros"],
        json!([
            {"clave": "etiquetas", "lista": ["\"a\"", "\"b\""]},
            {"clave": "monto", "valor": "10"},
        ])
    );
}
