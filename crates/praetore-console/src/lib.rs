//! Local operator console for a PRÆTORE journal.
//!
//! A separate surface from `praetore-observe`: loopback, a session file the
//! page never shows, and receipts retold in plain language (D1). With an
//! approver configured it also shows the approvals inbox (D2): the console
//! signs the operator's decision on this computer, as `praetore approve`
//! does, and the gateway verifies, records and dispatches it. With a policy
//! file and attester pins configured it also builds the compliance package
//! (D3), read only: the tenant's signed journal, the policy and its digest,
//! the pins, `SHA256SUMS` and instructions for a third party.

mod aprobador;
mod bandeja;
mod historia;
mod lectura;
mod paquete;
mod sesion;
#[cfg(test)]
mod tests_bandeja;
#[cfg(test)]
mod tests_paquete;

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
pub use paquete::{
    CompliancePack, JournalExportStore, MAX_ATTESTER_PINS, PACK_DIR, PACK_FILENAME,
    PackConfigError, PackError, PackSettings,
};
pub use sesion::LocalSession;

const INDEX_HTML: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const APP_CSS: &str = include_str!("../ui/styles.css");

pub struct ConsoleState {
    store: Arc<dyn HistoryStore>,
    session: LocalSession,
    names: HashMap<Uuid, String>,
    inbox: Option<Inbox>,
    /// D3. Present only with a policy file and attester pins.
    pack: Option<Arc<CompliancePack>>,
    /// One package is built at a time: each holds the shared database
    /// client for the whole export.
    pack_gate: Arc<tokio::sync::Semaphore>,
    address: SocketAddr,
    /// `Host` values the console answers to (DNS rebinding).
    hosts: Vec<String>,
    /// `http://host:port` values a mutating request may come from.
    origins: Vec<String>,
    /// Code of the opening link printed in the terminal: single use, five
    /// minutes at most. The session cookie is handed out only to a request
    /// that carries it, so another local process that just asks for the
    /// page gets no cookie.
    opener: sesion::Opener,
    /// Where opening links go: the console's stderr by default.
    printer: Arc<dyn Fn(&str) + Send + Sync>,
}

const DEFAULT_ADDRESS: &str = "127.0.0.1:8090";

/// D2. Present only when the console has an approver key, its gateway token
/// and the gateway address.
pub struct Inbox {
    store: Arc<dyn InboxStore>,
    gateway: Arc<dyn ApprovalGateway>,
    signer: Arc<ApproverSigner>,
    references: References,
}

impl Inbox {
    pub fn new(
        store: Arc<dyn InboxStore>,
        gateway: Arc<dyn ApprovalGateway>,
        signer: ApproverSigner,
    ) -> Self {
        Self {
            store,
            gateway,
            signer: Arc::new(signer),
            references: References::default(),
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
    /// More rows wait than one read returns.
    pub truncated: bool,
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
        let mut state = Self {
            store,
            session,
            names,
            inbox: None,
            pack: None,
            pack_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            address: DEFAULT_ADDRESS.parse().expect("fixed address"),
            hosts: Vec::new(),
            origins: Vec::new(),
            opener: sesion::Opener::new(sesion::MAX_OPENING_TTL),
            printer: Arc::new(|link: &str| {
                eprintln!(
                    "Abre la consola en este computador con este enlace (vale una vez, 5 minutos):\n  {link}"
                );
            }),
        };
        state.set_address(state.address);
        state
    }

    /// The console's own address: the page and its actions are answered
    /// only under it (and `localhost` on the same port for 127.0.0.1).
    pub fn with_address(mut self, address: SocketAddr) -> Self {
        self.set_address(address);
        self
    }

    fn set_address(&mut self, address: SocketAddr) {
        self.address = address;
        self.hosts = vec![address.to_string()];
        if address.ip() == std::net::IpAddr::from([127, 0, 0, 1]) {
            self.hosts.push(format!("localhost:{}", address.port()));
        }
        self.origins = self
            .hosts
            .iter()
            .map(|host| format!("http://{host}"))
            .collect();
    }

    /// At most five minutes; shorter in tests.
    pub fn with_opening_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.opener = sesion::Opener::new(ttl);
        self
    }

    /// Where opening links are written. Default: stderr, which under systemd
    /// ends up in the journal.
    pub fn with_link_printer(mut self, printer: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.printer = Arc::new(printer);
        self
    }

    /// Issues a new single-use opening link, writes it to the printer and
    /// returns it. Any earlier link stops working.
    pub fn issue_opening_link(&self) -> Option<String> {
        let link = self.link_for(self.opener.issue()?);
        (self.printer)(&link);
        Some(link)
    }

    fn link_for(&self, code: String) -> String {
        format!("http://{}/?abrir={code}", self.address)
    }

    pub fn with_inbox(mut self, inbox: Inbox) -> Self {
        self.inbox = Some(inbox);
        self
    }

    pub fn with_compliance_pack(mut self, pack: CompliancePack) -> Self {
        self.pack = Some(Arc::new(pack));
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
            .route("/paquete", get(download_pack))
            .route("/paquete/estado", get(pack_status))
            .route_layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                require_session,
            ));
        Router::new()
            .route("/", get(index))
            .route("/app.js", get(app_js))
            .route("/styles.css", get(app_css))
            .nest("/api", api)
            .layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                require_own_host,
            ))
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

/// Refuses a request whose `Host` is not the console's own address: a page
/// whose name was re-pointed at 127.0.0.1 (DNS rebinding) reads nothing.
async fn require_own_host(
    State(state): State<Arc<ConsoleState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let mut values = request.headers().get_all(header::HOST).iter();
    let host = match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok(),
        _ => None,
    };
    if host.is_some_and(|host| state.hosts.iter().any(|own| own == host)) {
        next.run(request).await
    } else {
        api_message(
            StatusCode::MISDIRECTED_REQUEST,
            "Esta consola no atiende ese nombre.",
        )
    }
}

/// Header the console page sends on every action. A page from another
/// origin cannot add it without a preflight the console never answers.
pub const ACTION_HEADER: &str = "x-praetore-consola";

/// A mutation must come from the console's own page: exact `Origin`, the
/// action header, and, when the browser sends it, `Sec-Fetch-Site:
/// same-origin`. The cookie alone is not enough: another local port is the
/// same site for `SameSite=Strict`.
fn same_page(state: &ConsoleState, headers: &HeaderMap) -> bool {
    let single = |name: &str| {
        let mut values = headers.get_all(name).iter();
        match (values.next(), values.next()) {
            (Some(value), None) => value.to_str().ok(),
            _ => None,
        }
    };
    let origin_ok = single(header::ORIGIN.as_str())
        .is_some_and(|origin| state.origins.iter().any(|allowed| allowed == origin));
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
const INBOX_NOTICE: &str = "Cada solicitud muestra sus parámetros: la firma los cubre. El primer clic muestra el resumen y el segundo firma una sola decisión. «Aprobar y ejecutar» registra la aprobación y pide la única ejecución; si la ejecución no se puede hacer, la solicitud queda aprobada, pendiente de ejecución, y solo se reintenta la ejecución. Rechazar es final. La firma la hace esta consola en este computador; el registro y la ejecución los hace el sistema.";

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
        let awaiting = facts.kind == PendingKind::AwaitingApproval;
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
                historia::quoted_text(&facts.wanted)
            },
            sobre: facts
                .target
                .as_deref()
                .map(historia::quoted_text)
                .unwrap_or_else(|| "sin objetivo indicado".to_owned()),
            vale_hasta: readable_deadline(facts.expires_at),
            queda: time_left(facts.expires_at, now),
            parametros: facts
                .parameters
                .iter()
                .flatten()
                .map(|parameter| match &parameter.value {
                    bandeja::ParameterValue::Text(valor) => ParameterView {
                        clave: parameter.key.clone(),
                        valor: Some(valor.clone()),
                        lista: None,
                    },
                    bandeja::ParameterValue::List(lista) => ParameterView {
                        clave: parameter.key.clone(),
                        valor: None,
                        lista: Some(lista.clone()),
                    },
                })
                .collect(),
            parametros_visibles: facts.parameters.is_some(),
            puede_aprobar: awaiting && facts.parameters.is_some(),
            puede_rechazar: awaiting,
            puede_ejecutar: facts.kind == PendingKind::ApprovedPendingExecution,
            nota: (awaiting && facts.parameters.is_none()).then_some(PARAMETERS_TOO_BIG),
        });
    }
    api_json(
        StatusCode::OK,
        InboxView {
            aviso: INBOX_NOTICE,
            solicitudes,
            vencidas,
            ilegibles: page.unreadable,
            hay_mas: page.truncated,
        },
    )
}

const PACK_OFF: &str = "El paquete de compliance no está configurado en esta consola.";

/// D3: read only. Asked for by the console's own page (the action header,
/// and `Sec-Fetch-Site: same-origin` when the browser sends it), so another
/// local page cannot make the console build packages. The package is built
/// whole in memory; on any failure the page gets a plain message and no
/// file.
async fn download_pack(State(state): State<Arc<ConsoleState>>, headers: HeaderMap) -> Response {
    if !same_page_read(&headers) {
        return api_message(
            StatusCode::FORBIDDEN,
            "La descarga solo se pide desde la página de esta consola.",
        );
    }
    let Some(pack) = state.pack.clone() else {
        return api_message(StatusCode::SERVICE_UNAVAILABLE, PACK_OFF);
    };
    let Ok(permit) = Arc::clone(&state.pack_gate).try_acquire_owned() else {
        return api_text(StatusCode::TOO_MANY_REQUESTS, PackError::Busy.message());
    };
    let signer = state.inbox.as_ref().map(|inbox| Arc::clone(&inbox.signer));
    let built = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        paquete::generate(&pack, signer.as_deref(), time::OffsetDateTime::now_utc())
    })
    .await;
    let bytes = match built {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) => return api_text(StatusCode::SERVICE_UNAVAILABLE, error.message()),
        Err(_) => {
            return api_text(
                StatusCode::SERVICE_UNAVAILABLE,
                PackError::Archive.message(),
            );
        }
    };
    let mut response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/gzip".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{PACK_FILENAME}\""),
            ),
        ],
        bytes,
    )
        .into_response();
    set_security_headers(response.headers_mut());
    response
}

/// Whether the page should offer the package at all.
async fn pack_status(State(state): State<Arc<ConsoleState>>) -> Response {
    #[derive(Serialize)]
    struct PackStatus {
        configurado: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        mensaje: Option<&'static str>,
    }
    let configurado = state.pack.is_some();
    api_json(
        StatusCode::OK,
        PackStatus {
            configurado,
            mensaje: (!configurado).then_some(PACK_OFF),
        },
    )
}

/// A read the page asks for with `fetch`: same-origin GETs carry no
/// `Origin`, so only the action header and `Sec-Fetch-Site` are checked.
fn same_page_read(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(ACTION_HEADER).iter();
    let marker_ok =
        matches!((values.next(), values.next()), (Some(value), None) if value.as_bytes() == b"1");
    let fetch_site_ok = match headers.get("sec-fetch-site") {
        None => true,
        Some(value) => value.as_bytes() == b"same-origin",
    };
    marker_ok && fetch_site_ok
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
    if !same_page(&state, &headers) {
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
    if matches!(
        what,
        Act::Decide(praetore_gateway::HumanApprovalOutcome::Approve)
    ) && !pending.approvable
    {
        return api_json(
            StatusCode::OK,
            ActOutcome {
                situacion: "sin cambios",
                mensaje: PARAMETERS_TOO_BIG,
                puede_ejecutar: false,
            },
        );
    }
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

#[derive(serde::Deserialize)]
struct OpenQuery {
    abrir: Option<String>,
}

/// The page itself holds no secret. The session cookie is set only when the
/// request carries a live opening code, which is then consumed; the browser
/// is sent to `/` so the code leaves the address bar. Asking for the page
/// never issues a link: only the operator does (see `issue_opening_link`).
async fn index(
    State(state): State<Arc<ConsoleState>>,
    query: Result<Query<OpenQuery>, QueryRejection>,
) -> Response {
    let offered = query.ok().and_then(|Query(query)| query.abrir);
    let Some(offered) = offered else {
        return static_response(StatusCode::OK, "text/html; charset=utf-8", INDEX_HTML);
    };
    if !state.opener.redeem(&offered) {
        tracing::warn!(failure = "opening_code", "console opening link refused");
        return static_response(StatusCode::OK, "text/html; charset=utf-8", INDEX_HTML);
    }
    let mut response = (StatusCode::SEE_OTHER, [(header::LOCATION, "/")]).into_response();
    set_security_headers(response.headers_mut());
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
    api_text(status, mensaje.into())
}

fn api_text(status: StatusCode, mensaje: std::borrow::Cow<'static, str>) -> Response {
    api_json(status, Message { mensaje })
}

#[derive(Serialize)]
struct Message {
    mensaje: std::borrow::Cow<'static, str>,
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
    /// Older requests wait beyond what one read shows.
    hay_mas: bool,
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
    /// `clave: valor` lines, keys sorted. Empty with `parametros_visibles`
    /// false when they do not fit the inbox.
    parametros: Vec<ParameterView>,
    parametros_visibles: bool,
    puede_aprobar: bool,
    puede_rechazar: bool,
    puede_ejecutar: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    nota: Option<&'static str>,
}

#[derive(Serialize)]
struct ParameterView {
    clave: String,
    /// A text (quoted), a number, `sí`/`no`, `(nulo)` or `(objeto vacío)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    valor: Option<String>,
    /// A list, each element apart (possibly empty).
    #[serde(skip_serializing_if = "Option::is_none")]
    lista: Option<Vec<String>>,
}

const PARAMETERS_TOO_BIG: &str = "Los parámetros de esta solicitud no se pueden mostrar aquí sin ambigüedad (más de 20 líneas, valores de más de 200 caracteres, más de 2 niveles, claves con punto o repetidas, o texto Unicode no normalizado). Aquí solo se puede rechazar; para revisarla completa y aprobarla usa praetore approve en la terminal.";

fn set_security_headers(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
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
            .header(header::HOST, "127.0.0.1:8090")
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
        let printed = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = printed.clone();
        let state = ConsoleState::new(
            Arc::new(MemoryHistory {
                receipts: Vec::new(),
                reads: AtomicUsize::new(0),
            }),
            session(),
            HashMap::new(),
        )
        .with_link_printer(move |link| sink.lock().unwrap().push(link.to_owned()));
        let link = state.issue_opening_link().unwrap();
        assert_eq!(*printed.lock().unwrap(), vec![link.clone()]);
        let code = link.split_once("?abrir=").unwrap().1.to_owned();
        assert!(link.starts_with("http://127.0.0.1:8090/?abrir="));
        assert!(Uuid::parse_str(&code).is_err());
        assert!(!code.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let app = state.router();
        let page = |uri: String| {
            Request::builder()
                .header(header::HOST, "127.0.0.1:8090")
                .uri(uri)
                .body(Body::empty())
                .unwrap()
        };
        // Asking for the page is not enough to get the session, and the
        // live link is not replaced.
        for uri in [
            "/".to_owned(),
            "/?abrir=otro".to_owned(),
            format!("/?abrir={code}x"),
        ] {
            let plain = app.clone().oneshot(page(uri.clone())).await.unwrap();
            assert_eq!(plain.status(), StatusCode::OK, "{uri}");
            assert!(plain.headers().get(header::SET_COOKIE).is_none(), "{uri}");
        }
        assert_eq!(printed.lock().unwrap().len(), 1);
        let opened = app
            .clone()
            .oneshot(page(format!("/?abrir={code}")))
            .await
            .unwrap();
        assert_eq!(opened.status(), StatusCode::SEE_OTHER);
        assert_eq!(opened.headers().get(header::LOCATION).unwrap(), "/");
        let cookie = opened
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
        // The link works once.
        let again = app
            .clone()
            .oneshot(page(format!("/?abrir={code}")))
            .await
            .unwrap();
        assert_eq!(again.status(), StatusCode::OK);
        assert!(again.headers().get(header::SET_COOKIE).is_none());
        let response = app.clone().oneshot(page("/".to_owned())).await.unwrap();
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
        // The only download is D3's compliance package.
        assert_eq!(html.matches("<button").count(), 5, "{html}");
        assert!(html.contains(">Descargar paquete de compliance</button>"));
        let script = app
            .oneshot(
                Request::builder()
                    .header(header::HOST, "127.0.0.1:8090")
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
    async fn an_expired_link_is_refused_and_a_restart_drops_the_old_cookie() {
        let printed = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = printed.clone();
        let first = ConsoleState::new(
            Arc::new(MemoryHistory {
                receipts: Vec::new(),
                reads: AtomicUsize::new(0),
            }),
            LocalSession::random().unwrap(),
            HashMap::new(),
        )
        .with_opening_ttl(std::time::Duration::ZERO)
        .with_link_printer(move |link| sink.lock().unwrap().push(link.to_owned()));
        let expired = first.issue_opening_link().unwrap();
        let first = Arc::new(first);
        let app = ConsoleState::router_from(Arc::clone(&first));
        let request = |uri: &str, cookie: Option<&str>| {
            let mut builder = Request::builder()
                .header(header::HOST, "127.0.0.1:8090")
                .uri(uri);
            if let Some(cookie) = cookie {
                builder = builder.header(header::COOKIE, cookie);
            }
            builder.body(Body::empty()).unwrap()
        };
        let path = expired.split_once("8090").unwrap().1.to_owned();
        let refused = app.clone().oneshot(request(&path, None)).await.unwrap();
        assert_eq!(refused.status(), StatusCode::OK);
        assert!(refused.headers().get(header::SET_COOKIE).is_none());
        // Asking for the page never issues a link; nothing reaches the page.
        let plain = app.clone().oneshot(request("/", None)).await.unwrap();
        assert!(plain.headers().get(header::SET_COOKIE).is_none());
        assert_eq!(printed.lock().unwrap().len(), 1);
        assert!(!body_text(refused).await.contains("abrir="));

        // A cookie from one run does not open the next one.
        let old_cookie = format!("{}={}", sesion::COOKIE_NAME, first.session.cookie_value());
        let ok = app
            .clone()
            .oneshot(request("/api/historial", Some(&old_cookie)))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        let restarted = ConsoleState::new(
            Arc::new(MemoryHistory {
                receipts: Vec::new(),
                reads: AtomicUsize::new(0),
            }),
            LocalSession::random().unwrap(),
            HashMap::new(),
        )
        .router();
        let stale = restarted
            .oneshot(request("/api/historial", Some(&old_cookie)))
            .await
            .unwrap();
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
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
                        .header(header::HOST, "127.0.0.1:8090")
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
                    .header(header::HOST, "127.0.0.1:8090")
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
                    .header(header::HOST, "127.0.0.1:8090")
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
