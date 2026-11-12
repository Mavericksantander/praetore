//! Local operator console for a PRÆTORE journal.
//!
//! A separate surface from `praetore-observe`: loopback, a session file the
//! page never shows, and receipts retold in plain language (D1). With an
//! approver configured it also shows the approvals inbox (D2): the console
//! signs the operator's decision on this computer, as `praetore approve`
//! does, and the gateway verifies, records and dispatches it. It does not
//! export a compliance package.

mod aprobador;
mod bandeja;
mod historia;
mod lectura;
mod sesion;
#[cfg(test)]
mod tests_bandeja;

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bandeja::{PendingFacts, References, readable_deadline, time_left};
use historia::{
    ListRequest, NOTICE, RawQuery, ReceiptFacts, agent_label, page_window, prepare_detail_query,
    prepare_query, readable_time, situation, story, visible_target, visible_wanted,
};
use serde::Serialize;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use uuid::Uuid;

pub use aprobador::{
    ActOutcome, ApprovalGateway, ApproverConfigError, ApproverSigner, GatewayReply,
    HttpApprovalGateway, parse_gateway_address, read_token_file,
};
pub use bandeja::{PendingKind, PendingRef};
pub use historia::{NamesError, parse_agent_names};
pub use lectura::PostgresHistory;
pub use sesion::LocalSession;

const INDEX_HTML: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const APP_CSS: &str = include_str!("../ui/styles.css");

pub struct ConsoleState {
    store: Arc<dyn HistoryStore>,
    session: LocalSession,
    names: HashMap<Uuid, String>,
    inbox: Option<Inbox>,
}

/// D2. Present only when the console has an approver key, its gateway token
/// and the gateway address.
pub struct Inbox {
    store: Arc<dyn InboxStore>,
    gateway: Arc<dyn ApprovalGateway>,
    signer: Arc<ApproverSigner>,
    references: References,
    /// `http://host:port` values a mutating request may come from.
    origins: Vec<String>,
}

impl Inbox {
    /// `bind` is the console's own address: mutations are accepted only
    /// from a page served by it.
    pub fn new(
        store: Arc<dyn InboxStore>,
        gateway: Arc<dyn ApprovalGateway>,
        signer: ApproverSigner,
        bind: SocketAddr,
    ) -> Self {
        let mut origins = vec![format!("http://{bind}")];
        if bind.ip().is_loopback() && bind.is_ipv4() {
            origins.push(format!("http://localhost:{}", bind.port()));
        }
        Self {
            store,
            gateway,
            signer: Arc::new(signer),
            references: References::default(),
            origins,
        }
    }
}

pub trait InboxStore: Send + Sync + 'static {
    fn pending(&self) -> Result<InboxPage, HistoryError>;
}

pub struct InboxPage {
    pub items: Vec<PendingFacts>,
    /// Pending rows whose receipt does not check out. Never offered.
    pub unreadable: u32,
    pub agents: Vec<Uuid>,
}

impl std::fmt::Debug for ConsoleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConsoleState")
    }
}

pub trait HistoryStore: Send + Sync + 'static {
    fn list(&self, query: &ListRequest) -> Result<HistoryPage, HistoryError>;
}

pub struct HistoryPage {
    pub total: i64,
    pub receipts: Vec<ReceiptFacts>,
    pub agents: Vec<Uuid>,
}

#[derive(Debug)]
pub enum HistoryError {
    Unavailable,
    Invalid,
}

#[derive(Debug)]
pub enum ConfigError {
    NonLoopback,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonLoopback => f.write_str("la consola solo puede escuchar en este computador"),
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn validate_bind_address(address: SocketAddr) -> Result<SocketAddr, ConfigError> {
    if address.ip().is_loopback() {
        Ok(address)
    } else {
        Err(ConfigError::NonLoopback)
    }
}

impl ConsoleState {
    pub fn new(
        store: Arc<dyn HistoryStore>,
        session: LocalSession,
        names: HashMap<Uuid, String>,
    ) -> Self {
        Self {
            store,
            session,
            names,
            inbox: None,
        }
    }

    pub fn with_inbox(mut self, inbox: Inbox) -> Self {
        self.inbox = Some(inbox);
        self
    }

    pub fn router(self) -> Router {
        Self::router_from(Arc::new(self))
    }

    /// `state` is kept by the caller so the database client is dropped off the runtime.
    pub fn router_from(state: Arc<Self>) -> Router {
        let api = Router::new()
            .route("/historial", get(list_receipts))
            .route("/historial/{numero}", get(receipt_detail))
            .route("/bandeja", get(list_inbox))
            .route("/bandeja/{referencia}/aprobar", post(approve))
            .route("/bandeja/{referencia}/rechazar", post(reject))
            .route("/bandeja/{referencia}/ejecutar", post(execute))
            .route_layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                require_session,
            ));
        Router::new()
            .route("/", get(index))
            .route("/app.js", get(app_js))
            .route("/styles.css", get(app_css))
            .nest("/api", api)
            .with_state(state)
    }
}

async fn require_session(
    State(state): State<Arc<ConsoleState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let cookie = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok());
    if !state.session.accepts(cookie) {
        return api_message(
            StatusCode::UNAUTHORIZED,
            "Hay que abrir esta página en este computador.",
        );
    }
    next.run(request).await
}

/// Header the console page sends on every action. A page from another
/// origin cannot add it without a preflight the console never answers.
pub const ACTION_HEADER: &str = "x-praetore-consola";

/// A mutation must come from the console's own page: exact `Origin`, the
/// action header, and, when the browser sends it, `Sec-Fetch-Site:
/// same-origin`. The cookie alone is not enough: another local port is the
/// same site for `SameSite=Strict`.
fn same_page(inbox: &Inbox, headers: &HeaderMap) -> bool {
    let single = |name: &str| {
        let mut values = headers.get_all(name).iter();
        match (values.next(), values.next()) {
            (Some(value), None) => value.to_str().ok(),
            _ => None,
        }
    };
    let origin_ok = single(header::ORIGIN.as_str())
        .is_some_and(|origin| inbox.origins.iter().any(|allowed| allowed == origin));
    let marker_ok = single(ACTION_HEADER) == Some("1");
    let fetch_site_ok = match headers.get("sec-fetch-site") {
        None => true,
        Some(value) => value.as_bytes() == b"same-origin",
    };
    origin_ok && marker_ok && fetch_site_ok
}

async fn list_receipts(
    State(state): State<Arc<ConsoleState>>,
    query: Result<Query<RawQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(_) => return bad_query(),
    };
    let query = match prepare_query(query) {
        Ok(query) => query,
        Err(()) => return bad_query(),
    };
    let page = match read_page(Arc::clone(&state), query.clone()).await {
        Ok(page) => page,
        Err(error) => return storage_error(error),
    };
    let window = page_window(page.total, query.offset);
    let recibos = page
        .receipts
        .iter()
        .enumerate()
        .map(|(index, facts)| {
            receipt_view(
                facts,
                u64::from(query.offset) + index as u64 + 1,
                &state.names,
                &page.agents,
            )
        })
        .collect();
    api_json(
        StatusCode::OK,
        ListView {
            aviso: NOTICE,
            total: page.total,
            pagina: window.page,
            paginas: window.pages,
            recibos,
        },
    )
}

async fn receipt_detail(
    State(state): State<Arc<ConsoleState>>,
    Path(numero): Path<u64>,
    query: Result<Query<RawQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(_) => return bad_query(),
    };
    let query = match prepare_detail_query(query, numero) {
        Ok(query) => query,
        Err(()) => return bad_query(),
    };
    let page = match read_page(Arc::clone(&state), query).await {
        Ok(page) => page,
        Err(error) => return storage_error(error),
    };
    let Some(facts) = page.receipts.first() else {
        return api_message(StatusCode::NOT_FOUND, "Ese recibo no está.");
    };
    api_json(
        StatusCode::OK,
        DetailView {
            aviso: NOTICE,
            cuando: readable_time(facts.created_at),
            actualizado: readable_time(facts.updated_at),
            agente: agent_label(facts.agent_id, &state.names, &page.agents),
            queria: visible_wanted(facts),
            sobre: visible_target(facts),
            situacion: situation(facts).phrase(),
            relato: story(facts),
        },
    )
}

const INBOX_OFF: &str = "La bandeja de aprobaciones no está configurada en esta consola.";
const INBOX_NOTICE: &str = "Aprobar deja la solicitud aprobada y pendiente de ejecución; ejecutar la lleva a cabo una sola vez. Rechazar es final. La firma y el registro los hace el sistema, no esta página.";

async fn list_inbox(State(state): State<Arc<ConsoleState>>) -> Response {
    let Some(inbox) = &state.inbox else {
        return api_message(StatusCode::SERVICE_UNAVAILABLE, INBOX_OFF);
    };
    let store = Arc::clone(&inbox.store);
    let page = match tokio::task::spawn_blocking(move || store.pending()).await {
        Ok(Ok(page)) => page,
        Ok(Err(error)) => return storage_error(error),
        Err(_) => return storage_error(HistoryError::Unavailable),
    };
    let now = time::OffsetDateTime::now_utc();
    let mut solicitudes = Vec::with_capacity(page.items.len());
    let mut vencidas = 0u32;
    for facts in &page.items {
        // A window that closed is not offered: the gateway would refuse it,
        // and it records the expiry when it next sees the request.
        if facts.expires_at <= now {
            vencidas += 1;
            continue;
        }
        let Some(referencia) = inbox.references.reference_for(facts) else {
            return storage_error(HistoryError::Unavailable);
        };
        solicitudes.push(InboxItemView {
            referencia,
            situacion: facts.kind.phrase(),
            pedida: readable_time(facts.created_at),
            agente: agent_label(facts.key.agent_id, &state.names, &page.agents),
            queria: if facts.wanted.is_empty() {
                "no se muestra".to_owned()
            } else {
                facts.wanted.clone()
            },
            sobre: facts
                .target
                .clone()
                .unwrap_or_else(|| "sin objetivo indicado".to_owned()),
            vale_hasta: readable_deadline(facts.expires_at),
            queda: time_left(facts.expires_at, now),
            puede_decidir: facts.kind == PendingKind::AwaitingApproval,
            puede_ejecutar: facts.kind == PendingKind::ApprovedPendingExecution,
        });
    }
    api_json(
        StatusCode::OK,
        InboxView {
            aviso: INBOX_NOTICE,
            solicitudes,
            vencidas,
            ilegibles: page.unreadable,
        },
    )
}

async fn approve(
    state: State<Arc<ConsoleState>>,
    headers: HeaderMap,
    referencia: Path<String>,
) -> Response {
    let what = Act::Decide(praetore_gateway::HumanApprovalOutcome::Approve);
    act(state, headers, referencia, what).await
}

async fn reject(
    state: State<Arc<ConsoleState>>,
    headers: HeaderMap,
    referencia: Path<String>,
) -> Response {
    let what = Act::Decide(praetore_gateway::HumanApprovalOutcome::Reject);
    act(state, headers, referencia, what).await
}

async fn execute(
    state: State<Arc<ConsoleState>>,
    headers: HeaderMap,
    referencia: Path<String>,
) -> Response {
    act(state, headers, referencia, Act::Dispatch).await
}

#[derive(Clone, Copy)]
enum Act {
    Decide(praetore_gateway::HumanApprovalOutcome),
    Dispatch,
}

async fn act(
    State(state): State<Arc<ConsoleState>>,
    headers: HeaderMap,
    Path(referencia): Path<String>,
    what: Act,
) -> Response {
    let Some(inbox) = &state.inbox else {
        return api_message(StatusCode::SERVICE_UNAVAILABLE, INBOX_OFF);
    };
    if !same_page(inbox, &headers) {
        return api_message(
            StatusCode::FORBIDDEN,
            "Esta acción solo se acepta desde la página de la consola.",
        );
    }
    let Some(pending) = inbox.references.resolve(&referencia) else {
        return api_message(
            StatusCode::NOT_FOUND,
            "Esa solicitud ya no está en la bandeja. Vuelve a cargarla.",
        );
    };
    let gateway = Arc::clone(&inbox.gateway);
    let signer = Arc::clone(&inbox.signer);
    let result = tokio::task::spawn_blocking(move || match what {
        Act::Decide(outcome) => aprobador::decide(gateway.as_ref(), &signer, &pending, outcome),
        Act::Dispatch => aprobador::dispatch(gateway.as_ref(), &pending),
    })
    .await;
    match result {
        Ok(outcome) => api_json(StatusCode::OK, outcome),
        Err(_) => {
            tracing::error!(failure = "gateway_worker", "console action failed");
            api_message(
                StatusCode::SERVICE_UNAVAILABLE,
                "No se pudo confirmar qué pasó. Revisa el historial antes de seguir.",
            )
        }
    }
}

async fn read_page(
    state: Arc<ConsoleState>,
    query: ListRequest,
) -> Result<HistoryPage, HistoryError> {
    let store = Arc::clone(&state.store);
    match tokio::task::spawn_blocking(move || store.list(&query)).await {
        Ok(result) => result,
        Err(_) => {
            tracing::error!(failure = "database_worker", "console journal read failed");
            Err(HistoryError::Unavailable)
        }
    }
}

fn receipt_view(
    facts: &ReceiptFacts,
    abrir: u64,
    names: &HashMap<Uuid, String>,
    agents: &[Uuid],
) -> ReceiptView {
    ReceiptView {
        abrir,
        cuando: readable_time(facts.created_at),
        agente: agent_label(facts.agent_id, names, agents),
        queria: visible_wanted(facts),
        sobre: visible_target(facts),
        situacion: situation(facts).phrase(),
    }
}

fn bad_query() -> Response {
    api_message(StatusCode::BAD_REQUEST, "Esa consulta no se entiende.")
}

fn storage_error(error: HistoryError) -> Response {
    tracing::error!(
        failure = match error {
            HistoryError::Unavailable => "storage_unavailable",
            HistoryError::Invalid => "invalid_stored_record",
        },
        "console journal read failed"
    );
    api_message(
        StatusCode::SERVICE_UNAVAILABLE,
        "No se pudo leer el registro.",
    )
}

async fn index(State(state): State<Arc<ConsoleState>>) -> Response {
    let mut response = static_response(StatusCode::OK, "text/html; charset=utf-8", INDEX_HTML);
    if let Ok(cookie) = HeaderValue::from_str(&state.session.cookie_header()) {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    response
}

async fn app_js() -> Response {
    static_response(StatusCode::OK, "text/javascript; charset=utf-8", APP_JS)
}

async fn app_css() -> Response {
    static_response(StatusCode::OK, "text/css; charset=utf-8", APP_CSS)
}

fn static_response(status: StatusCode, content_type: &'static str, body: &'static str) -> Response {
    let mut response = (status, [(header::CONTENT_TYPE, content_type)], body).into_response();
    set_security_headers(response.headers_mut());
    response
}

fn api_json<T: Serialize>(status: StatusCode, body: T) -> Response {
    let mut response = (status, Json(body)).into_response();
    set_security_headers(response.headers_mut());
    response
}

fn api_message(status: StatusCode, mensaje: &'static str) -> Response {
    api_json(status, Message { mensaje })
}

#[derive(Serialize)]
struct Message {
    mensaje: &'static str,
}

#[derive(Serialize)]
struct ListView {
    aviso: &'static str,
    total: i64,
    pagina: u32,
    paginas: u32,
    recibos: Vec<ReceiptView>,
}

#[derive(Serialize)]
struct ReceiptView {
    abrir: u64,
    cuando: String,
    agente: String,
    queria: String,
    sobre: String,
    situacion: &'static str,
}

#[derive(Serialize)]
struct DetailView {
    aviso: &'static str,
    cuando: String,
    actualizado: String,
    agente: String,
    queria: String,
    sobre: String,
    situacion: &'static str,
    relato: &'static str,
}

#[derive(Serialize)]
struct InboxView {
    aviso: &'static str,
    solicitudes: Vec<InboxItemView>,
    /// Pending in the journal, window already closed: not offered.
    vencidas: u32,
    /// Pending in the journal, receipt does not check out: not offered.
    ilegibles: u32,
}

#[derive(Serialize)]
struct InboxItemView {
    referencia: String,
    situacion: &'static str,
    pedida: String,
    agente: String,
    queria: String,
    sobre: String,
    vale_hasta: String,
    queda: String,
    puede_decidir: bool,
    puede_ejecutar: bool,
}

fn set_security_headers(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; \
             img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::historia::{JournalColumns, facts_from_columns};
    use axum::body::to_bytes;
    use praetore_core::{
        Action, AgentId, AgentKeyPair, Authority, Decision, Evidence, EvidenceAttesterKey,
    };
    use praetore_gateway::{AttestedExecution, AuthorizationStatus, ExecutionStatus};
    use serde_json::{Value, json};
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
    use tower::ServiceExt;

    struct MemoryHistory {
        receipts: Vec<ReceiptFacts>,
        reads: AtomicUsize,
    }

    impl HistoryStore for MemoryHistory {
        fn list(&self, query: &ListRequest) -> Result<HistoryPage, HistoryError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let mut matched: Vec<_> = self
                .receipts
                .iter()
                .filter(|facts| {
                    if query
                        .situation
                        .is_some_and(|wanted| situation(facts) != wanted)
                    {
                        return false;
                    }
                    if query.from.is_some_and(|from| facts.created_at < from) {
                        return false;
                    }
                    if query.until.is_some_and(|until| facts.created_at >= until) {
                        return false;
                    }
                    true
                })
                .cloned()
                .collect();
            matched.sort_by(|left, right| {
                right
                    .created_at
                    .cmp(&left.created_at)
                    .then(left.agent_id.cmp(&right.agent_id))
                    .then(left.request_id.cmp(&right.request_id))
            });
            let total = i64::try_from(matched.len()).unwrap_or(i64::MAX);
            let offset = usize::try_from(query.offset).unwrap_or(usize::MAX);
            let limit = usize::try_from(query.limit).unwrap_or(0);
            let receipts = matched.into_iter().skip(offset).take(limit).collect();
            let mut agents: Vec<Uuid> = self.receipts.iter().map(|facts| facts.agent_id).collect();
            agents.sort();
            agents.dedup();
            Ok(HistoryPage {
                total,
                receipts,
                agents,
            })
        }
    }

    fn session() -> LocalSession {
        LocalSession::from_secret([0x11; 32])
    }

    fn app(receipts: Vec<ReceiptFacts>) -> (Router, Arc<MemoryHistory>) {
        let store = Arc::new(MemoryHistory {
            receipts,
            reads: AtomicUsize::new(0),
        });
        let state = ConsoleState::new(store.clone(), session(), HashMap::new());
        (state.router(), store)
    }

    fn authed(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header(
                header::COOKIE,
                format!("{}={}", sesion::COOKIE_NAME, hex::encode([0x11; 32])),
            )
            .body(Body::empty())
            .unwrap()
    }

    async fn body_text(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn at(stamp: &str) -> OffsetDateTime {
        OffsetDateTime::parse(stamp, &Rfc3339).unwrap()
    }

    fn manual(
        stamp: &str,
        agent: u128,
        request: u128,
        kind: &str,
        wanted: &str,
        target: &str,
    ) -> ReceiptFacts {
        let (authorization, execution, attested) = match kind {
            "aprobado" => (
                AuthorizationStatus::RequiresApproval,
                ExecutionStatus::ApprovedPendingDispatch,
                None,
            ),
            "denegado" => (
                AuthorizationStatus::Denied,
                ExecutionStatus::NotDispatched,
                Some(AttestedExecution::NotDispatched),
            ),
            _ => panic!("kind"),
        };
        ReceiptFacts {
            created_at: at(stamp),
            updated_at: at(stamp),
            agent_id: Uuid::from_u128(agent),
            request_id: Uuid::from_u128(request),
            authorization,
            execution,
            attested,
            reason: None,
            legible: true,
            wanted: wanted.into(),
            target: Some(target.into()),
        }
    }

    #[test]
    fn bind_is_loopback_only() {
        assert!(validate_bind_address("127.0.0.1:8090".parse().unwrap()).is_ok());
        assert!(validate_bind_address("[::1]:8090".parse().unwrap()).is_ok());
        assert!(validate_bind_address("0.0.0.0:8090".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn the_page_does_not_ask_for_a_token_and_sets_a_local_cookie() {
        let (app, _) = app(Vec::new());
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        let secret = hex::encode([0x11; 32]);
        assert!(cookie.contains(&secret));
        let html = body_text(response).await;
        assert!(!html.contains(&secret));
        assert!(html.contains("Historial"));
        assert!(html.contains("Bandeja"));
        assert!(html.contains(NOTICE));
        assert!(html.contains("pendiente de aprobación"));
        assert!(html.contains("aprobado, pendiente de ejecución"));
        assert!(!html.to_lowercase().contains("bearer"));
        assert!(!html.contains("password"));
        assert!(!html.contains("RFC"));
        assert!(!html.contains("UUID"));
        assert!(!html.contains("awaiting_approval"));
        assert!(!html.contains("descargar"));
        let script = app
            .oneshot(
                Request::builder()
                    .uri("/app.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let script = body_text(script).await;
        assert!(!script.contains("innerHTML"));
        assert!(script.contains(ACTION_HEADER));
        assert!(!script.contains("localStorage"));
        assert!(!script.contains(&secret));
        assert!(!script.contains(sesion::COOKIE_NAME));
    }

    #[tokio::test]
    async fn history_lists_plain_words_target_and_hides_the_evidence() {
        let (json, agent_id, request_id) = signed_evidence();
        let pending = facts_from_columns(JournalColumns {
            created_at: at("2026-10-24T15:04:00Z"),
            updated_at: at("2026-10-24T15:04:00Z"),
            agent_id,
            request_id,
            authorization: AuthorizationStatus::RequiresApproval,
            execution: ExecutionStatus::NotDispatched,
            attested: Some(AttestedExecution::AwaitingApproval),
            reason: None,
            evidence_json: json,
        })
        .unwrap();
        let approved = manual(
            "2026-10-23T09:00:00Z",
            4,
            5,
            "aprobado",
            "borrar_archivo",
            "archivo-viejo",
        );
        let denied = manual(
            "2026-10-22T09:00:00Z",
            8,
            9,
            "denegado",
            "leer_archivo",
            "notas",
        );
        let (app, store) = app(vec![denied, approved, pending]);
        let response = app.clone().oneshot(authed("/api/historial")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let text = body_text(response).await;
        let list: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(list["recibos"][0]["situacion"], "pendiente de aprobación");
        assert_eq!(list["recibos"][0]["sobre"], "informe-trimestral");
        assert_eq!(list["recibos"][0]["queria"], "escribir_archivo");
        assert_eq!(
            list["recibos"][0]["cuando"],
            "24 de octubre de 2026, 15:04 UTC"
        );
        assert_eq!(
            list["recibos"][1]["situacion"],
            "aprobado, pendiente de ejecución"
        );
        assert_eq!(list["recibos"][1]["sobre"], "archivo-viejo");
        assert_eq!(list["recibos"][2]["situacion"], "denegado");
        assert!(text.contains(NOTICE));
        assert!(!text.contains("parameter-secret"));
        assert!(!text.contains("context-secret"));
        assert!(!text.contains("motivo-interno"));
        assert!(!text.contains("awaiting_approval"));
        assert!(!text.contains(&agent_id.to_string()));
        assert!(!text.contains(&request_id.to_string()));
        assert!(!text.contains("2026-10-24T"));
        assert!(agent_label_is_plain(&list["recibos"][0]["agente"]));

        let filtered = app
            .clone()
            .oneshot(authed(
                "/api/historial?situacion=pendiente%20de%20aprobaci%C3%B3n",
            ))
            .await
            .unwrap();
        let filtered: Value = serde_json::from_str(&body_text(filtered).await).unwrap();
        assert_eq!(filtered["total"], 1);
        assert_eq!(filtered["recibos"][0]["sobre"], "informe-trimestral");
        assert_eq!(
            filtered["recibos"][0]["situacion"],
            "pendiente de aprobación"
        );

        let pending_execution = app
            .clone()
            .oneshot(authed(
                "/api/historial?situacion=aprobado,%20pendiente%20de%20ejecuci%C3%B3n",
            ))
            .await
            .unwrap();
        assert_eq!(pending_execution.status(), StatusCode::OK);
        let pending_execution: Value =
            serde_json::from_str(&body_text(pending_execution).await).unwrap();
        assert_eq!(pending_execution["total"], 1);
        assert_eq!(pending_execution["recibos"][0]["sobre"], "archivo-viejo");
        assert_eq!(
            pending_execution["recibos"][0]["situacion"],
            "aprobado, pendiente de ejecución"
        );

        let approved_only = app
            .clone()
            .oneshot(authed("/api/historial?situacion=aprobado"))
            .await
            .unwrap();
        let approved_only: Value = serde_json::from_str(&body_text(approved_only).await).unwrap();
        assert_eq!(approved_only["total"], 0);

        let detail = app
            .clone()
            .oneshot(authed("/api/historial/1"))
            .await
            .unwrap();
        assert_eq!(detail.status(), StatusCode::OK);
        let detail_text = body_text(detail).await;
        let detail: Value = serde_json::from_str(&detail_text).unwrap();
        assert_eq!(detail["situacion"], "pendiente de aprobación");
        assert_eq!(detail["sobre"], "informe-trimestral");
        assert_eq!(detail["queria"], "escribir_archivo");
        assert!(
            detail["relato"]
                .as_str()
                .unwrap()
                .contains("pendiente de aprobación")
        );
        assert_eq!(detail["aviso"], NOTICE);
        assert!(!detail_text.contains("parameter-secret"));
        assert!(!detail_text.contains(&agent_id.to_string()));
        assert!(!detail_text.contains(&request_id.to_string()));
        assert_eq!(store.reads.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn technical_filters_and_mutations_are_refused() {
        let (app, store) = app(Vec::new());
        for uri in [
            "/api/historial?situacion=awaiting_approval",
            "/api/historial?desde=2026-10-24T00:00:00Z&hasta=2026-10-25T00:00:00Z",
            "/api/historial?pagina=0",
            "/api/historial?tenant_id=1",
        ] {
            let response = app.clone().oneshot(authed(uri)).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
        assert_eq!(store.reads.load(Ordering::SeqCst), 0);
        for (method, uri) in [
            ("POST", "/api/historial"),
            ("POST", "/api/historial/1"),
            ("POST", "/"),
            ("DELETE", "/api/historial/1"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header(
                            header::COOKIE,
                            format!("{}={}", sesion::COOKIE_NAME, hex::encode([0x11; 32])),
                        )
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {uri}"
            );
        }
        assert_eq!(store.reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_api_requires_the_local_cookie() {
        let (app, store) = app(Vec::new());
        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/historial")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert!(missing.headers().get(header::WWW_AUTHENTICATE).is_none());
        let text = body_text(missing).await;
        assert!(text.contains("este computador"));
        assert!(!text.to_lowercase().contains("bearer"));
        let wrong = app
            .oneshot(
                Request::builder()
                    .uri("/api/historial")
                    .header(
                        header::COOKIE,
                        format!("{}={}", sesion::COOKIE_NAME, "ab".repeat(32)),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(store.reads.load(Ordering::SeqCst), 0);
    }

    fn agent_label_is_plain(value: &Value) -> bool {
        let Some(label) = value.as_str() else {
            return false;
        };
        label.starts_with("Agente") && Uuid::parse_str(label).is_err()
    }

    fn signed_evidence() -> (String, Uuid, Uuid) {
        let agent_key = AgentKeyPair::from_secret_bytes(&[0x31; 32]);
        let agent = agent_key.identity(AgentId::new());
        let agent_id = *agent.id.as_uuid();
        let authority = Authority::new(
            agent.id.clone(),
            "consola-test",
            vec!["archivo:escribir".into()],
        )
        .with_constraint("tenant_id", Uuid::from_u128(1).to_string());
        let action = Action::new(
            "escribir_archivo",
            Some("informe-trimestral".into()),
            json!({"value": "parameter-secret"}),
        )
        .unwrap()
        .with_capability("archivo:escribir");
        let mut context = BTreeMap::new();
        context.insert("nota".into(), json!("context-secret"));
        let mut evidence = Evidence::new_with_context(
            Uuid::from_u128(7),
            agent,
            authority,
            action,
            Decision::allow("motivo-interno", praetore_core::DecidedBy::rule("regla")),
            None,
            context,
        )
        .unwrap();
        evidence.bind_policy_digest("cd".repeat(32)).unwrap();
        let attester = EvidenceAttesterKey::from_secret_bytes(&[0x32; 32]);
        evidence.sign(&attester).unwrap();
        let request_id = evidence.request_id;
        (evidence.to_json().unwrap(), agent_id, request_id)
    }
}
