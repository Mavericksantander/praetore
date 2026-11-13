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
    EvidenceAttesterKey, policy::RecordedPolicy,
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
const ATTESTER_SECRET: [u8; 32] = [0x52; 32];

/// The local policy the test console loads: the evidence below records its
/// digest.
fn local_policy() -> RecordedPolicy {
    RecordedPolicy::from_json(include_str!(
        "../../../docs/golden/canonical-policy-v1.json"
    ))
    .unwrap()
}

/// Another valid policy, with another digest.
fn other_policy() -> RecordedPolicy {
    RecordedPolicy::from_json(include_str!(
        "../../../examples/claude-code-hook/evidence/04-sesion-real-bloqueada-web-fetch/policy.json"
    ))
    .unwrap()
}

fn policy_digest() -> String {
    local_policy().digest().to_owned()
}

/// The attester pin and the local policy of the test console.
fn trust() -> EvidenceTrust {
    EvidenceTrust::new(
        vec![
            EvidenceAttesterKey::from_secret_bytes(&ATTESTER_SECRET)
                .public_key()
                .unwrap(),
        ],
        local_policy(),
    )
    .unwrap()
}

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
        policy_digest: policy_digest(),
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
    evidence.bind_policy_digest(policy_digest()).unwrap();
    evidence
        .sign(&EvidenceAttesterKey::from_secret_bytes(&ATTESTER_SECRET))
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
        &trust(),
    )
    .unwrap()
}

struct MemoryInbox {
    items: Vec<PendingFacts>,
    unreadable: u32,
}

impl InboxStore for MemoryInbox {
    fn pending(&self, _trust: &EvidenceTrust) -> Result<InboxPage, HistoryError> {
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
    let inbox = Inbox::new(
        Arc::new(MemoryInbox { items, unreadable }),
        gateway,
        signer,
        trust(),
    );
    ConsoleState::new(
        Arc::new(NoHistory),
        LocalSession::from_secret([0x11; 32]),
        HashMap::from([(Uuid::from_u128(99), "nadie".to_owned())]),
    )
    .with_inbox(inbox)
    .router()
}

fn auth() -> String {
    format!("Bearer {}", hex::encode([0x11; 32]))
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .header(header::HOST, "127.0.0.1:8090")
        .uri(uri)
        .header(header::AUTHORIZATION, auth())
        .body(Body::empty())
        .unwrap()
}

fn post(uri: &str) -> Request<Body> {
    Request::builder()
        .header(header::HOST, "127.0.0.1:8090")
        .method("POST")
        .uri(uri)
        .header(header::AUTHORIZATION, auth())
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
    // UUIDs and 32+ hex runs: journal keys and digests never reach the page.
    let hex_run = text
        .split(|c: char| !c.is_ascii_hexdigit())
        .any(|run| run.len() >= 32);
    let uuid = text
        .split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
        .any(|word| Uuid::parse_str(word).is_ok());
    hex_run || uuid || !instants_only_in_utc_fields(text)
}

/// RFC 3339 instants go to the page only in the `*_utc` fields, which the
/// page words in local time and UTC.
fn instants_only_in_utc_fields(text: &str) -> bool {
    fn walk(key: &str, value: &Value) -> bool {
        match value {
            Value::String(text) => {
                let instant = OffsetDateTime::parse(text, &Rfc3339).is_ok();
                !instant || (key.ends_with("_utc") && text.ends_with('Z'))
            }
            Value::Array(items) => items.iter().all(|item| walk(key, item)),
            Value::Object(fields) => fields.iter().all(|(key, value)| walk(key, value)),
            _ => true,
        }
    }
    serde_json::from_str::<Value>(text).is_ok_and(|value| walk("", &value))
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
    // Codes and instants: the page words them in the operator's language.
    assert_eq!(first["situacion"], "awaiting_approval");
    assert_eq!(first["queria"], json!({"texto": "\"borrar_archivo\""}));
    assert_eq!(first["sobre"], json!({"texto": "\"informe-trimestral\""}));
    // Its number among the agents of this read; the page says "Agente N".
    assert!(first["agente"].get("nombre").is_none());
    assert!(
        first["agente"]["numero"]
            .as_u64()
            .is_some_and(|number| (1..=3).contains(&number)),
        "{}",
        first["agente"]
    );
    let deadline = first["vale_hasta_utc"].as_str().unwrap();
    assert_eq!(
        OffsetDateTime::parse(deadline, &Rfc3339).unwrap(),
        in_ten.replace_nanosecond(0).unwrap()
    );
    assert!(deadline.ends_with('Z'), "{deadline}");
    assert!(first["pedida_utc"].as_str().unwrap().ends_with('Z'));
    // The time left is counted by the page from its own clock.
    assert!(first.get("queda").is_none());
    assert!(first.get("vale_hasta").is_none());
    assert_eq!(first["puede_aprobar"], true);
    assert_eq!(first["puede_rechazar"], true);
    assert_eq!(first["parametros_visibles"], true);
    assert_eq!(
        first["parametros"],
        json!([{"clave": "\"nota\"", "valor": "\"texto-libre\""}])
    );
    assert!(first.get("nota").is_none());
    assert_eq!(first["puede_ejecutar"], false);
    let second = &list["solicitudes"][1];
    assert_eq!(second["situacion"], "approved_pending_execution");
    assert_eq!(second["puede_aprobar"], false);
    assert_eq!(second["puede_rechazar"], false);
    assert_eq!(second["puede_ejecutar"], true);
    assert_eq!(list["solicitudes"].as_array().unwrap().len(), 2);
    assert_eq!(list["vencidas"], 1);
    assert_eq!(list["ilegibles"], 1);
    assert_eq!(list["aviso"], "inbox_how_it_works");
    assert_eq!(list["limite"], 200);
    assert_eq!(list["hay_mas"], false);
    assert!(!text.contains("motivo-interno"));
    // The gateway's own state names are not the page's codes.
    assert!(!text.contains("approved_pending_dispatch"));
    assert!(!text.contains("requires_approval"));
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
    assert_eq!(approved["situacion"], "approved_pending_execution");
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
    assert_eq!(again["situacion"], "unchanged");
    assert_eq!(again["mensaje"]["codigo"], "already_decided_nothing_signed");
    assert!(
        crate::tests_i18n::es_json_message(&again["mensaje"]).contains("ya tiene una decisión")
    );
    assert_eq!(gateway.state.lock().unwrap().decisions.len(), 1);

    let (_, executed, _) = json_of(
        app.clone()
            .oneshot(post(&format!("/api/bandeja/{reference}/ejecutar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(executed["situacion"], "approved");
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
    assert_eq!(failed["situacion"], "approved_pending_execution");
    assert_eq!(failed["puede_ejecutar"], true);
    assert_eq!(gateway.held(), Held::Approved);
    let (_, retried, _) = json_of(
        app.clone()
            .oneshot(post(&format!("/api/bandeja/{reference}/ejecutar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(retried["situacion"], "approved");
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
    assert_eq!(rejected["situacion"], "rejected");
    assert_eq!(rejected["puede_ejecutar"], false);
    let (_, approve_after, _) = json_of(
        app.clone()
            .oneshot(post(&format!("/api/bandeja/{reference}/aprobar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(approve_after["situacion"], "unchanged");
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
    assert_eq!(refused["situacion"], "unchanged");
    assert!(crate::tests_i18n::es_json_message(&refused["mensaje"]).contains("No se firmó nada"));
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
        &trust(),
        &pending,
        praetore_gateway::HumanApprovalOutcome::Approve,
    );
    assert_eq!(outcome.situacion, codigos::OutcomeState::Unchanged);
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
            .header(header::AUTHORIZATION, auth());
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
        .header(header::AUTHORIZATION, auth())
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
    assert_eq!(body["mensaje"]["codigo"], "inbox_off");
    assert!(crate::tests_i18n::es_json_message(&body["mensaje"]).contains("no está configurada"));
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
            &trust(),
            &pending,
            praetore_gateway::HumanApprovalOutcome::Approve,
        );
        assert!(!outcome.puede_ejecutar, "{outcome:?}");
        assert!(gateway.0.lock().unwrap().is_empty());
    }
    use codigos::OutcomeState;
    const STILL: OutcomeState = OutcomeState::ApprovedPendingExecution;
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
        (GatewayReply::Unconfirmed, true, OutcomeState::Unconfirmed),
        (
            answered(503, json!({"code": "execution_state_unavailable"})),
            true,
            OutcomeState::Unconfirmed,
        ),
        (
            answered(503, json!({"code": "gateway_unavailable"})),
            true,
            OutcomeState::Unconfirmed,
        ),
        (
            answered(500, json!({"code": "gateway_configuration_error"})),
            true,
            OutcomeState::Unconfirmed,
        ),
        (
            answered(403, json!({"code": "action_not_dispatchable"})),
            false,
            OutcomeState::NotExecuted,
        ),
        (
            answered(502, json!({"code": "action_effect_failed"})),
            false,
            OutcomeState::Approved,
        ),
        (
            answered(409, json!({"code": "execution_state_conflict"})),
            false,
            OutcomeState::Unchanged,
        ),
        (
            answered(410, json!({"code": "approval_expired"})),
            false,
            OutcomeState::Expired,
        ),
        (
            answered(200, json!({"execution": "failed"})),
            false,
            OutcomeState::Approved,
        ),
    ] {
        let gateway = Scripted(Mutex::new(vec![reply]));
        let outcome = aprobador::dispatch(&gateway, &pending);
        assert_eq!(outcome.puede_ejecutar, retry, "{outcome:?}");
        assert_eq!(outcome.situacion, situacion, "{outcome:?}");
        if situacion == OutcomeState::Unconfirmed {
            let said = crate::tests_i18n::es_message(&outcome.mensaje);
            assert!(!said.contains("sin ejecutar"), "{outcome:?}");
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
            &trust(),
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
    no_window.bind_policy_digest(policy_digest()).unwrap();
    no_window
        .sign(&EvidenceAttesterKey::from_secret_bytes(&ATTESTER_SECRET))
        .unwrap();
    assert!(columns(TENANT, agent, no_window.to_json().unwrap()).is_err());
}

fn pending_columns(evidence: &Evidence, json: String) -> PendingColumns {
    PendingColumns {
        created_at: OffsetDateTime::now_utc(),
        agent_id: *evidence.agent.id.as_uuid(),
        request_id: evidence.request_id,
        kind: PendingKind::AwaitingApproval,
        evidence_json: json,
    }
}

#[test]
fn a_request_signed_by_an_attester_outside_the_pins_is_not_offered_or_signed() {
    let (mut evidence, json) = pending_evidence(
        "borrar_archivo",
        "informe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    );
    // Signed by the pinned attester under the local policy: offered.
    assert!(pending_from_columns(TENANT, pending_columns(&evidence, json), &trust()).is_ok());
    // Same receipt, integrity intact, signed by another attester.
    let foreign_attester = EvidenceAttesterKey::from_secret_bytes(&[0x53; 32]);
    evidence.sign(&foreign_attester).unwrap();
    assert!(evidence.verify_integrity());
    let foreign = evidence.to_json().unwrap();
    assert!(
        pending_from_columns(
            TENANT,
            pending_columns(&evidence, foreign.clone()),
            &trust()
        )
        .is_err()
    );
    // Listed by a console that trusted that attester, then decided by one
    // that does not: nothing is asked of the gateway, nothing is signed.
    let elsewhere =
        EvidenceTrust::new(vec![foreign_attester.public_key().unwrap()], local_policy()).unwrap();
    let pending = PendingRef::from(
        &pending_from_columns(TENANT, pending_columns(&evidence, foreign), &elsewhere).unwrap(),
    );
    let signer = ApproverSigner::new("consola-aprobador", APPROVER_SECRET).unwrap();
    for decision in [
        praetore_gateway::HumanApprovalOutcome::Approve,
        praetore_gateway::HumanApprovalOutcome::Reject,
    ] {
        let gateway = FakeGateway::new(&evidence);
        let outcome = aprobador::decide(&gateway, &signer, &trust(), &pending, decision);
        assert_eq!(outcome.situacion, codigos::OutcomeState::Unchanged);
        assert_eq!(
            outcome.mensaje.codigo,
            codigos::MessageCode::EvidenceUnverified
        );
        assert!(crate::tests_i18n::es_message(&outcome.mensaje).contains("no verifica"));
        assert!(gateway.calls().is_empty());
    }
}

#[test]
fn a_request_decided_under_another_policy_is_not_offered_or_signed() {
    let (evidence, json) = pending_evidence(
        "borrar_archivo",
        "informe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    );
    // Signed by the pinned attester, but the console loaded another policy.
    let pin = EvidenceAttesterKey::from_secret_bytes(&ATTESTER_SECRET)
        .public_key()
        .unwrap();
    let rotated = EvidenceTrust::new(vec![pin], other_policy()).unwrap();
    assert_ne!(other_policy().digest(), policy_digest());
    assert!(
        pending_from_columns(TENANT, pending_columns(&evidence, json.clone()), &rotated).is_err()
    );
    let pending = PendingRef::from(
        &pending_from_columns(TENANT, pending_columns(&evidence, json), &trust()).unwrap(),
    );
    let signer = ApproverSigner::new("consola-aprobador", APPROVER_SECRET).unwrap();
    for decision in [
        praetore_gateway::HumanApprovalOutcome::Approve,
        praetore_gateway::HumanApprovalOutcome::Reject,
    ] {
        let gateway = FakeGateway::new(&evidence);
        let outcome = aprobador::decide(&gateway, &signer, &rotated, &pending, decision);
        assert_eq!(outcome.situacion, codigos::OutcomeState::Unchanged);
        assert!(gateway.calls().is_empty());
    }
}

#[test]
fn a_request_signed_by_a_pin_under_the_local_policy_is_offered_and_signed() {
    let (evidence, json) = pending_evidence(
        "borrar_archivo",
        "informe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    );
    // A second, unrelated pin does not get in the way.
    let trust = EvidenceTrust::new(
        vec![
            EvidenceAttesterKey::from_secret_bytes(&[0x53; 32])
                .public_key()
                .unwrap(),
            EvidenceAttesterKey::from_secret_bytes(&ATTESTER_SECRET)
                .public_key()
                .unwrap(),
        ],
        local_policy(),
    )
    .unwrap();
    let facts = pending_from_columns(TENANT, pending_columns(&evidence, json), &trust).unwrap();
    let gateway = FakeGateway::new(&evidence);
    let signer = ApproverSigner::new("consola-aprobador", APPROVER_SECRET).unwrap();
    let outcome = aprobador::decide(
        &gateway,
        &signer,
        &trust,
        &PendingRef::from(&facts),
        praetore_gateway::HumanApprovalOutcome::Approve,
    );
    assert_eq!(
        outcome.situacion,
        codigos::OutcomeState::ApprovedPendingExecution
    );
    assert_eq!(gateway.calls(), vec!["challenge", "decide"]);
}

#[test]
fn the_trust_refuses_no_pins_repeated_pins_and_too_many() {
    let pin = EvidenceAttesterKey::from_secret_bytes(&ATTESTER_SECRET)
        .public_key()
        .unwrap();
    assert_eq!(
        EvidenceTrust::new(Vec::new(), local_policy()).unwrap_err(),
        TrustError::NoPins
    );
    assert_eq!(
        EvidenceTrust::new(vec![pin.clone(), pin], local_policy()).unwrap_err(),
        TrustError::Pin(2)
    );
    let many = (0..=MAX_ATTESTER_PINS as u8)
        .map(|seed| {
            EvidenceAttesterKey::from_secret_bytes(&[seed + 1; 32])
                .public_key()
                .unwrap()
        })
        .collect();
    assert_eq!(
        EvidenceTrust::new(many, local_policy()).unwrap_err(),
        TrustError::TooManyPins
    );
}

#[test]
fn an_inbox_without_the_policy_or_the_pins_does_not_start() {
    use std::ffi::OsStr;
    let policy = Some(OsStr::new("/etc/praetore/policy.json"));
    let pins = Some(OsStr::new("/etc/praetore/attester.hex"));
    assert!(require_for_inbox(true, policy, pins).is_ok());
    // Without the inbox, D1 alone or the package alone stay as they were.
    assert!(require_for_inbox(false, None, None).is_ok());
    assert!(require_for_inbox(false, policy, pins).is_ok());
    for (policy, pins, missing) in [
        (None, None, vec![POLICY_VARIABLE, PINS_VARIABLE]),
        (policy, None, vec![PINS_VARIABLE]),
        (None, pins, vec![POLICY_VARIABLE]),
        (Some(OsStr::new("")), pins, vec![POLICY_VARIABLE]),
    ] {
        let error = require_for_inbox(true, policy, pins).unwrap_err();
        assert_eq!(error, TrustError::MissingForInbox(missing.clone()));
        let message = error.to_string();
        for name in [POLICY_VARIABLE, PINS_VARIABLE] {
            assert_eq!(message.contains(name), missing.contains(&name), "{message}");
        }
    }
}

#[test]
fn the_trust_files_are_read_as_regular_files_only() {
    let dir = std::env::temp_dir().join(format!("praetore-console-trust-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        include_str!("../../../docs/golden/canonical-policy-v1.json"),
    )
    .unwrap();
    let pin = dir.join("attester.hex");
    let public = EvidenceAttesterKey::from_secret_bytes(&ATTESTER_SECRET)
        .public_key()
        .unwrap();
    std::fs::write(&pin, format!("{}\n", hex::encode(public.as_bytes()))).unwrap();
    let loaded = EvidenceTrust::load(&policy, std::slice::from_ref(&pin), None).unwrap();
    assert_eq!(loaded.pins(), std::slice::from_ref(&public));
    // The approver's own key is never an attester pin.
    let signer = ApproverSigner::new("consola-aprobador", APPROVER_SECRET).unwrap();
    let approver_pin = dir.join("approver.hex");
    std::fs::write(
        &approver_pin,
        hex::encode(
            SigningKey::from_bytes(&APPROVER_SECRET)
                .verifying_key()
                .to_bytes(),
        ),
    )
    .unwrap();
    assert_eq!(
        EvidenceTrust::load(&policy, &[pin.clone(), approver_pin], Some(&signer)).unwrap_err(),
        TrustError::PinIsApproverKey(2)
    );
    // Missing, a directory, not a policy.
    assert_eq!(
        EvidenceTrust::load(&dir.join("nope.json"), std::slice::from_ref(&pin), None).unwrap_err(),
        TrustError::Policy
    );
    assert_eq!(
        EvidenceTrust::load(&dir, std::slice::from_ref(&pin), None).unwrap_err(),
        TrustError::Policy
    );
    assert_eq!(
        EvidenceTrust::load(&pin, std::slice::from_ref(&pin), None).unwrap_err(),
        TrustError::Policy
    );
    #[cfg(unix)]
    {
        // A symlink is not followed; a FIFO is not waited on.
        let link = dir.join("link.hex");
        std::os::unix::fs::symlink(&pin, &link).unwrap();
        assert_eq!(
            EvidenceTrust::load(&policy, &[link], None).unwrap_err(),
            TrustError::Pin(1)
        );
        let fifo = dir.join("fifo.hex");
        let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `path` is a valid NUL-terminated string for the call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert_eq!(
            EvidenceTrust::load(&policy, &[fifo], None).unwrap_err(),
            TrustError::Pin(1)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
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
            let mut request = Request::builder()
                .uri(uri)
                .header(header::AUTHORIZATION, auth());
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
        .header(header::AUTHORIZATION, auth())
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
        fn pending(&self, _trust: &EvidenceTrust) -> Result<InboxPage, HistoryError> {
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
        trust(),
    ))
    .router();
    let (_, list, text) = json_of(app.oneshot(get("/api/bandeja")).await.unwrap()).await;
    assert_eq!(list["hay_mas"], true);
    assert_eq!(
        list["solicitudes"][0]["sobre"],
        json!({"texto": "\"informe\\u{202e}fdp.exe\""})
    );
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
            &trust(),
            &pending,
            praetore_gateway::HumanApprovalOutcome::Approve,
        );
        assert_eq!(outcome.situacion, codigos::OutcomeState::Unchanged);
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
        json!([{"clave": "\"moneda\"", "valor": "\"CLP\""}, {"clave": "\"monto\"", "valor": "10"}])
    );
    assert_eq!(
        second["parametros"],
        json!([{"clave": "\"moneda\"", "valor": "\"CLP\""}, {"clave": "\"monto\"", "valor": "100000"}])
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
    assert_eq!(item["nota"], json!({"codigo": "parameters_not_shown"}));
    assert!(crate::tests_i18n::es_json_message(&item["nota"]).contains("praetore approve"));
    let reference = item["referencia"].as_str().unwrap().to_owned();
    // Refused server side even if the page asked anyway.
    let (_, refused, _) = json_of(
        app.clone()
            .oneshot(post(&format!("/api/bandeja/{reference}/aprobar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(refused["situacion"], "unchanged");
    assert!(gateway.calls().is_empty());
    let (_, rejected, _) = json_of(
        app.oneshot(post(&format!("/api/bandeja/{reference}/rechazar")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(rejected["situacion"], "rejected");
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
            {"clave": "\"etiquetas\"", "valor": "\"a, b\""},
            {"clave": "\"monto\"", "valor": "\"10\""},
        ])
    );
    assert_eq!(
        list["solicitudes"][1]["parametros"],
        json!([
            {"clave": "\"etiquetas\"", "lista": ["\"a\"", "\"b\""]},
            {"clave": "\"monto\"", "valor": "10"},
        ])
    );
}

#[tokio::test]
async fn an_action_or_target_that_spells_a_placeholder_is_quoted() {
    let expires = OffsetDateTime::now_utc() + Duration::minutes(10);
    let (spelled, spelled_json) =
        pending_evidence("no se muestra", "sin objetivo indicado", expires);
    let gateway = Arc::new(FakeGateway::new(&spelled));
    let app = console(
        vec![facts_for(
            &spelled,
            spelled_json,
            PendingKind::AwaitingApproval,
        )],
        0,
        gateway,
    );
    let (_, list, _) = json_of(app.oneshot(get("/api/bandeja")).await.unwrap()).await;
    let item = &list["solicitudes"][0];
    // Agent text that spells the console's placeholders is text, quoted;
    // a placeholder is a code, never text.
    assert_eq!(item["queria"], json!({"texto": "\"no se muestra\""}));
    assert_eq!(item["sobre"], json!({"texto": "\"sin objetivo indicado\""}));
    assert_ne!(item["queria"], json!({"codigo": "not_shown"}));
    assert_ne!(item["sobre"], json!({"codigo": "no_target"}));
}

/// The page's language never reaches what the console signs: the same
/// request, approved (and rejected) with the browser asking for Spanish,
/// English or Portuguese, gets the same signed message and the same
/// signature, byte for byte. Only `approval_id` is random per decision, so
/// it is fixed here.
#[tokio::test]
async fn the_signed_decision_is_the_same_whatever_the_page_language() {
    fn fixed_id() -> Uuid {
        Uuid::from_u128(0x5eed)
    }
    let (evidence, json) = pending_evidence(
        "borrar_archivo",
        "informe",
        OffsetDateTime::now_utc() + Duration::minutes(10),
    );
    let facts = facts_for(&evidence, json, PendingKind::AwaitingApproval);
    for (route, outcome) in [
        ("aprobar", praetore_gateway::HumanApprovalOutcome::Approve),
        ("rechazar", praetore_gateway::HumanApprovalOutcome::Reject),
    ] {
        let mut signed = Vec::new();
        for language in [None, Some("es"), Some("en"), Some("pt-BR,pt;q=0.9")] {
            let gateway = Arc::new(FakeGateway::new(&evidence));
            let signer = ApproverSigner::new("consola-aprobador", APPROVER_SECRET)
                .unwrap()
                .with_approval_ids(fixed_id);
            let app = ConsoleState::new(
                Arc::new(NoHistory),
                LocalSession::from_secret([0x11; 32]),
                HashMap::new(),
            )
            .with_inbox(Inbox::new(
                Arc::new(MemoryInbox {
                    items: vec![facts.clone()],
                    unreadable: 0,
                }),
                gateway.clone(),
                signer,
                trust(),
            ))
            .router();
            let reference = first_reference(&app).await;
            let mut request = post(&format!("/api/bandeja/{reference}/{route}"));
            if let Some(language) = language {
                request.headers_mut().insert(
                    header::ACCEPT_LANGUAGE,
                    header::HeaderValue::from_static(language),
                );
            }
            let response = app.oneshot(request).await.unwrap();
            assert!(response.headers().get(header::SET_COOKIE).is_none());
            let (status, answer, _) = json_of(response).await;
            assert_eq!(status, StatusCode::OK, "{language:?} {answer}");
            let state = gateway.state.lock().unwrap();
            assert_eq!(state.decisions.len(), 1);
            let decision = &state.decisions[0];
            assert_eq!(decision.outcome, outcome);
            assert_eq!(decision.approval_id, fixed_id());
            signed.push((
                decision.signing_message().unwrap(),
                decision.signature.clone(),
                serde_json::to_string(decision).unwrap(),
            ));
        }
        for other in &signed[1..] {
            assert_eq!(&signed[0], other, "{route}");
        }
    }
}

/// Without `with_approval_ids`, each decision the console signs gets a fresh
/// random (version 4) `approval_id`: two decisions never share one.
#[test]
fn each_signed_decision_gets_its_own_random_approval_id() {
    let signer = ApproverSigner::new("consola-aprobador", APPROVER_SECRET).unwrap();
    let expires = OffsetDateTime::now_utc() + Duration::minutes(10);
    let ids: Vec<Uuid> = ["informe-1", "informe-2"]
        .into_iter()
        .map(|target| {
            let (evidence, _) = pending_evidence("borrar_archivo", target, expires);
            let view = FakeGateway::new(&evidence).view;
            signer
                .sign(view, praetore_gateway::HumanApprovalOutcome::Reject)
                .unwrap()
                .approval_id
        })
        .collect();
    assert_ne!(ids[0], ids[1]);
    for id in &ids {
        assert!(!id.is_nil());
        assert_eq!(id.get_version_num(), 4, "{id}");
        assert_eq!(id.get_variant(), uuid::Variant::RFC4122, "{id}");
    }
}
