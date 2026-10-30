use crate::{AuthorizationStatus, Gateway, GatewayError, JournalError};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, WWW_AUTHENTICATE},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use praetore_core::{AuthorizationRequest, ErrorKind, canonical::parse_json_rejecting_duplicates};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, io, net::SocketAddr, sync::Arc};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::net::TcpListener;
use uuid::Uuid;

const MAX_REQUEST_BYTES: usize = 65_536;
const MAX_CREDENTIALS_BYTES: usize = 1_048_576;
const MAX_CREDENTIALS: usize = 4096;
/// Bearer tokens must carry at least 128 bits of entropy in practice; the
/// length bounds only reject obviously weak or oversized values.
pub const MIN_TOKEN_BYTES: usize = 32;
pub const MAX_TOKEN_BYTES: usize = 256;

/// What a caller credential may do. Agent and approver credentials are
/// deliberately disjoint: an agent can submit and observe its tenant's
/// requests but can never read approval challenges, record decisions or
/// trigger the dispatch of an approved action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiRole {
    /// `POST /v1/execute` and `GET .../status` for its tenant.
    Agent,
    /// Approval challenge, decision, status and dispatch for its tenant.
    Approver,
}

/// An authenticated caller: always bound to exactly one tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPrincipal {
    pub name: String,
    pub tenant_id: Uuid,
    pub role: ApiRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ApiCredentialsError {
    #[error("API credential configuration is not valid strict JSON")]
    InvalidDocument,
    #[error("API credential configuration has an unsupported version or size")]
    UnsupportedVersionOrSize,
    #[error("API credential names must be 1-64 characters of [a-z0-9._-] and unique")]
    InvalidName,
    #[error("API credentials must name a non-nil tenant")]
    InvalidTenant,
    #[error("API credential token_sha256 must be 64 lowercase hex characters and unique")]
    InvalidTokenHash,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiCredentialsFile {
    schema_version: u8,
    credentials: Vec<ApiCredentialEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiCredentialEntry {
    name: String,
    tenant_id: Uuid,
    role: ApiRole,
    token_sha256: String,
}

/// Tenant-scoped bearer credentials for the HTTP API. Only SHA-256 digests
/// of the tokens are stored; presented tokens are hashed and compared in
/// constant time against every configured digest.
///
/// File format (`schema_version` 1):
///
/// ```json
/// {"schema_version":1,"credentials":[
///   {"name":"tenant-a-agent","tenant_id":"<uuid>","role":"agent","token_sha256":"<64 hex>"},
///   {"name":"tenant-a-approver","tenant_id":"<uuid>","role":"approver","token_sha256":"<64 hex>"}
/// ]}
/// ```
#[derive(Debug, Clone)]
pub struct ApiCredentials {
    entries: Vec<([u8; 32], ApiPrincipal)>,
}

impl ApiCredentials {
    pub fn from_json(document: &str) -> Result<Self, ApiCredentialsError> {
        if document.len() > MAX_CREDENTIALS_BYTES {
            return Err(ApiCredentialsError::UnsupportedVersionOrSize);
        }
        let value = parse_json_rejecting_duplicates(document)
            .map_err(|_| ApiCredentialsError::InvalidDocument)?;
        let file: ApiCredentialsFile =
            serde_json::from_value(value).map_err(|_| ApiCredentialsError::InvalidDocument)?;
        if file.schema_version != 1
            || file.credentials.is_empty()
            || file.credentials.len() > MAX_CREDENTIALS
        {
            return Err(ApiCredentialsError::UnsupportedVersionOrSize);
        }
        let mut names = HashSet::with_capacity(file.credentials.len());
        let mut digests = HashSet::with_capacity(file.credentials.len());
        let mut entries = Vec::with_capacity(file.credentials.len());
        for entry in file.credentials {
            let valid_name = !entry.name.is_empty()
                && entry.name.len() <= 64
                && entry.name.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                });
            if !valid_name || !names.insert(entry.name.clone()) {
                return Err(ApiCredentialsError::InvalidName);
            }
            if entry.tenant_id.is_nil() {
                return Err(ApiCredentialsError::InvalidTenant);
            }
            let digest: [u8; 32] = hex::decode(&entry.token_sha256)
                .ok()
                .filter(|bytes| hex::encode(bytes) == entry.token_sha256)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(ApiCredentialsError::InvalidTokenHash)?;
            if !digests.insert(digest) {
                return Err(ApiCredentialsError::InvalidTokenHash);
            }
            entries.push((
                digest,
                ApiPrincipal {
                    name: entry.name,
                    tenant_id: entry.tenant_id,
                    role: entry.role,
                },
            ));
        }
        Ok(Self { entries })
    }

    /// Lowercase hex SHA-256 of a token, as stored in `token_sha256`.
    pub fn token_sha256_hex(token: &str) -> String {
        hex::encode(Sha256::digest(token.as_bytes()))
    }

    /// Returns the principal for a presented token. Every configured digest
    /// is compared, in constant time, regardless of earlier matches.
    pub fn authenticate(&self, token: &str) -> Option<&ApiPrincipal> {
        if !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&token.len()) {
            return None;
        }
        let presented: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut found = None;
        for (digest, principal) in &self.entries {
            if bool::from(digest.ct_eq(&presented)) {
                found = Some(principal);
            }
        }
        found
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Caller authentication mode of the HTTP API.
#[derive(Debug, Clone)]
pub enum ApiAuth {
    /// Every endpoint except `/healthz` requires `Authorization: Bearer`
    /// with a credential for the tenant in the path (or, for
    /// `/v1/execute`, the tenant of the submitted authority) and the role
    /// the endpoint needs.
    Required(Arc<ApiCredentials>),
    /// No caller authentication. Only for a single-tenant local demo whose
    /// listener is bound to loopback; callers that bind a non-loopback
    /// address must refuse to start in this mode.
    UnauthenticatedLoopbackDemo,
}

impl ApiAuth {
    pub fn required(credentials: ApiCredentials) -> Self {
        Self::Required(Arc::new(credentials))
    }

    pub fn is_required(&self) -> bool {
        matches!(self, Self::Required(_))
    }
}

#[derive(Clone)]
struct ApiState {
    gateway: Arc<Gateway>,
    auth: ApiAuth,
    options: HttpOptions,
}

/// Transport options for [`router_with_options`].
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpOptions {
    /// Set when the configured dispatcher performs the effects itself (for
    /// example the filesystem [`crate::sandbox::SandboxDispatcher`]). The API
    /// then requires [`EXEC_MODE_HEADER`] on every execution-path endpoint,
    /// and `/status` of an approved action answers 409
    /// `cooperative_exec_rejected` instead of `approved`, so a polling agent
    /// never runs the effect itself. Receipts of effects performed by the
    /// gateway carry the header `praetore-executed-by: gateway`.
    ///
    /// This option never changes who executes, what is authorized, or what
    /// is journaled: it only refuses requests earlier.
    pub gateway_executes_effects: bool,
}

const EXECUTED_BY_HEADER: &str = "praetore-executed-by";

/// Request header a client must send, with the exact value `gateway`, on
/// every execution-path request (`POST /v1/execute`, approval challenge,
/// approval decision, dispatch and `/status`) when
/// [`HttpOptions::gateway_executes_effects`] is set. It is an unverifiable
/// declaration by the client that it will not perform the effect itself; it
/// grants nothing. It is checked only after caller authentication.
pub const EXEC_MODE_HEADER: &str = "praetore-exec-mode";
pub const EXEC_MODE_GATEWAY: &str = "gateway";
const MAX_EXEC_MODE_BYTES: usize = 16;

/// Fail-closed check of [`EXEC_MODE_HEADER`]. Without gateway-executed
/// effects the header is ignored (unchanged behaviour). Otherwise exactly
/// one header with the exact value `gateway` (at most 16 bytes) is accepted;
/// a missing, repeated, oversized, `cooperative` or any other value is
/// refused with 409 `exec_mode_gateway_required` before the gateway is
/// called, so nothing is evaluated, journaled, approved or executed.
fn exec_mode_accepted(options: HttpOptions, headers: &HeaderMap) -> bool {
    if !options.gateway_executes_effects {
        return true;
    }
    let mut values = headers.get_all(EXEC_MODE_HEADER).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => {
            value.len() <= MAX_EXEC_MODE_BYTES && value.as_bytes() == EXEC_MODE_GATEWAY.as_bytes()
        }
        _ => false,
    }
}

fn exec_mode_refused() -> Response {
    error_response(StatusCode::CONFLICT, "exec_mode_gateway_required")
}

fn executed_by_gateway(options: HttpOptions, execution: crate::ExecutionStatus) -> bool {
    options.gateway_executes_effects
        && matches!(
            execution,
            crate::ExecutionStatus::Executed | crate::ExecutionStatus::Confirmed
        )
}

fn with_executed_by(
    options: HttpOptions,
    execution: crate::ExecutionStatus,
    mut response: Response,
) -> Response {
    if executed_by_gateway(options, execution) {
        response
            .headers_mut()
            .insert(EXECUTED_BY_HEADER, HeaderValue::from_static("gateway"));
    }
    response
}

/// Why a request was refused before reaching the gateway.
enum AccessDenied {
    Unauthenticated,
    Forbidden,
}

impl AccessDenied {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthenticated => {
                let mut response =
                    error_response(StatusCode::UNAUTHORIZED, "authentication_required");
                response
                    .headers_mut()
                    .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
                response
            }
            Self::Forbidden => error_response(StatusCode::FORBIDDEN, "caller_not_authorized"),
        }
    }
}

impl ApiState {
    /// Authenticates the caller and checks role and tenant. Runs before any
    /// journal lookup, so a caller cannot probe another tenant's keys.
    fn authorize(
        &self,
        headers: &HeaderMap,
        allowed: &[ApiRole],
        tenant_id: Option<Uuid>,
    ) -> Result<(), AccessDenied> {
        let credentials = match &self.auth {
            ApiAuth::UnauthenticatedLoopbackDemo => return Ok(()),
            ApiAuth::Required(credentials) => credentials,
        };
        let principal = bearer_token(headers)
            .and_then(|token| credentials.authenticate(token))
            .ok_or(AccessDenied::Unauthenticated)?;
        if !allowed.contains(&principal.role) {
            return Err(AccessDenied::Forbidden);
        }
        match tenant_id {
            Some(tenant_id) if tenant_id == principal.tenant_id => Ok(()),
            _ => Err(AccessDenied::Forbidden),
        }
    }

    fn authenticate_role(&self, headers: &HeaderMap, role: ApiRole) -> Result<(), AccessDenied> {
        let credentials = match &self.auth {
            ApiAuth::UnauthenticatedLoopbackDemo => return Ok(()),
            ApiAuth::Required(credentials) => credentials,
        };
        let principal = bearer_token(headers)
            .and_then(|token| credentials.authenticate(token))
            .ok_or(AccessDenied::Unauthenticated)?;
        if principal.role != role {
            return Err(AccessDenied::Forbidden);
        }
        Ok(())
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return None;
    }
    Some(token)
}

/// Marks credentials sensitive so that `Debug` output and tracing layers do
/// not print them.
async fn mark_credentials_sensitive(mut request: Request) -> Request {
    if let axum::http::header::Entry::Occupied(mut entry) =
        request.headers_mut().entry(AUTHORIZATION)
    {
        for value in entry.iter_mut() {
            value.set_sensitive(true);
        }
    }
    request
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    /// Present only on approval endpoints when the execution key exists and
    /// required approval: `pending`, `approved`, `rejected` or `expired`.
    #[serde(skip_serializing_if = "Option::is_none")]
    resolution: Option<crate::ApprovalResolution>,
    /// SAF-10: on 410 `approval_expired`, the `receipt_id` of the signed
    /// `ApprovalExpiredReceipt` persisted for this key.
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration_receipt_id: Option<uuid::Uuid>,
    /// Only on 409 `cooperative_exec_rejected`: the execution state of the
    /// approved action, which the gateway (never the client) performs.
    #[serde(skip_serializing_if = "Option::is_none")]
    execution: Option<crate::ExecutionStatus>,
}

/// State of the same key reported alongside approval errors.
struct ApprovalErrorContext {
    resolution: Option<crate::ApprovalResolution>,
    expiration_receipt_id: Option<uuid::Uuid>,
}

/// Creates the HTTP API for signed tool authorization requests.
///
/// With [`ApiAuth::Required`], every endpoint except `/healthz` requires a
/// tenant-scoped bearer credential (see [`ApiCredentials`]): `agent`
/// credentials may call `POST /v1/execute` (only for requests whose
/// issuer-signed authority names the credential's tenant) and the status
/// endpoint; `approver` credentials may read challenges, record decisions,
/// read status and dispatch. The `{tenant_id}` path segment must equal the
/// credential's tenant. Missing or unknown credentials get 401
/// `authentication_required`; a wrong role or tenant gets 403
/// `caller_not_authorized`, checked before any journal lookup.
///
/// `GET /v1/approvals/{tenant_id}/{agent_id}/{request_id}` returns
/// `{"challenge": ApprovalChallenge, "action": Action}`: the persisted
/// action whose digest the challenge binds, so an approver can see what it
/// signs and recompute `challenge.action_digest`.
///
/// The two approval `GET` endpoints are not purely read-only: when they are
/// the first to observe that a pending window has closed, they persist the
/// single signed `ApprovalExpiredReceipt` (idempotent; never dispatches).
///
/// `GET /v1/approvals/{tenant_id}/{agent_id}/{request_id}/status` reports the
/// human-approval state (`pending`, `approved`, `rejected`, `expired`,
/// `not_dispatched`) for that exact key together with the resulting
/// `execution` state and any signed `not_dispatched_reason`; 409/410 approval errors carry the same `resolution` field, and
/// 410 also carries `expiration_receipt_id`.
///
/// `POST /v1/approvals/{tenant_id}/{agent_id}/{request_id}` with a signed
/// approval answers `{"status": "approved_pending_dispatch", ...}`: nothing
/// has run yet. `POST .../dispatch` claims and performs the single dispatch
/// and returns the signed receipt; it never retries.
///
/// `POST /v1/execute` accepts the serialized `AuthorizationRequest`. The
/// gateway returns its signed receipt for every completed policy decision,
/// including denials and approval requirements. Request bodies are size
/// limited and parsed through PRÆTORE's duplicate-key rejecting parser.
pub fn router(gateway: Arc<Gateway>, auth: ApiAuth) -> Router {
    router_with_options(gateway, auth, HttpOptions::default())
}

/// Like [`router`], with explicit transport options. Caller authentication
/// is unchanged and always runs before the [`EXEC_MODE_HEADER`] check.
pub fn router_with_options(gateway: Arc<Gateway>, auth: ApiAuth, options: HttpOptions) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/execute", post(execute))
        .route(
            "/v1/approvals/{tenant_id}/{agent_id}/{request_id}",
            get(approval_challenge).post(resolve_approval),
        )
        .route(
            "/v1/approvals/{tenant_id}/{agent_id}/{request_id}/status",
            get(approval_status),
        )
        .route(
            "/v1/approvals/{tenant_id}/{agent_id}/{request_id}/dispatch",
            post(dispatch_approved),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(axum::middleware::map_request(mark_credentials_sensitive))
        .with_state(ApiState {
            gateway,
            auth,
            options,
        })
}

/// Runs the service on IPv4 loopback only. It has no TLS and must not be
/// exposed beyond local development.
pub async fn serve_local(port: u16, gateway: Arc<Gateway>, auth: ApiAuth) -> io::Result<()> {
    serve_local_with_options(port, gateway, auth, HttpOptions::default()).await
}

/// Like [`serve_local`], with explicit transport options.
pub async fn serve_local_with_options(
    port: u16,
    gateway: Arc<Gateway>,
    auth: ApiAuth,
    options: HttpOptions,
) -> io::Result<()> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(address).await?;
    axum::serve(listener, router_with_options(gateway, auth, options)).await
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn execute(State(state): State<ApiState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(denied) = state.authenticate_role(&headers, ApiRole::Agent) {
        return denied.into_response();
    }
    let request = match std::str::from_utf8(&body)
        .ok()
        .and_then(|json| AuthorizationRequest::from_json(json).ok())
    {
        Some(request) => request,
        None => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_authorization_request");
        }
    };
    // The authority is only verified by the engine; binding the caller to
    // its claimed tenant here keeps one tenant's credential from submitting
    // (and consuming) another tenant's signed request.
    let Some(request_tenant) = crate::authority_tenant_id(&request.authority) else {
        return error_response(StatusCode::BAD_REQUEST, "tenant_identity_invalid");
    };
    if let Err(denied) = state.authorize(&headers, &[ApiRole::Agent], Some(request_tenant)) {
        return denied.into_response();
    }
    if !exec_mode_accepted(state.options, &headers) {
        return exec_mode_refused();
    }
    let options = state.options;
    let gateway = state.gateway;

    let result = tokio::task::spawn_blocking(move || gateway.execute(request)).await;
    let receipt = match result {
        Ok(Ok(receipt)) => receipt,
        Ok(Err(error)) => {
            tracing::warn!(error = %error, "gateway request failed");
            return gateway_error_response(error);
        }
        Err(error) => {
            tracing::error!(error = %error, "gateway execution task failed");
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "gateway_unavailable");
        }
    };

    let status = match receipt.authorization {
        AuthorizationStatus::Allowed => StatusCode::OK,
        AuthorizationStatus::RequiresApproval => StatusCode::ACCEPTED,
        AuthorizationStatus::Denied => StatusCode::FORBIDDEN,
    };
    let execution = receipt.execution;
    with_executed_by(options, execution, (status, Json(receipt)).into_response())
}

async fn approval_challenge(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((tenant_id, agent_id, request_id)): Path<(uuid::Uuid, uuid::Uuid, uuid::Uuid)>,
) -> Response {
    if let Err(denied) = state.authorize(&headers, &[ApiRole::Approver], Some(tenant_id)) {
        return denied.into_response();
    }
    if !exec_mode_accepted(state.options, &headers) {
        return exec_mode_refused();
    }
    let gateway = state.gateway;
    let key = crate::ExecutionKey {
        tenant_id,
        agent_id,
        request_id,
    };
    match tokio::task::spawn_blocking(move || {
        gateway
            .approval_challenge_view(key)
            .map_err(|error| with_resolution(&gateway, key, error))
    })
    .await
    {
        Ok(Ok(challenge)) => (StatusCode::OK, Json(challenge)).into_response(),
        Ok(Err((error, resolution))) => approval_error_response(error, resolution),
        Err(error) => {
            tracing::error!(error = %error, "approval challenge task failed");
            error_response(StatusCode::SERVICE_UNAVAILABLE, "gateway_unavailable")
        }
    }
}

async fn resolve_approval(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((tenant_id, agent_id, request_id)): Path<(uuid::Uuid, uuid::Uuid, uuid::Uuid)>,
    body: Bytes,
) -> Response {
    if let Err(denied) = state.authorize(&headers, &[ApiRole::Approver], Some(tenant_id)) {
        return denied.into_response();
    }
    if !exec_mode_accepted(state.options, &headers) {
        return exec_mode_refused();
    }
    let gateway = state.gateway;
    let decision = match std::str::from_utf8(&body)
        .ok()
        .and_then(|json| crate::HumanApprovalDecision::from_json(json).ok())
    {
        Some(decision) => decision,
        None => return error_response(StatusCode::BAD_REQUEST, "invalid_approval_decision"),
    };
    if decision.challenge.tenant_id != tenant_id
        || decision.challenge.agent_id != agent_id
        || decision.challenge.request_id != request_id
    {
        return error_response(StatusCode::BAD_REQUEST, "approval_challenge_mismatch");
    }
    let key = crate::ExecutionKey {
        tenant_id,
        agent_id,
        request_id,
    };
    match tokio::task::spawn_blocking(move || {
        gateway
            .resolve_human_approval(decision)
            .map_err(|error| with_resolution(&gateway, key, error))
    })
    .await
    {
        Ok(Ok(resolution)) => (StatusCode::OK, Json(resolution)).into_response(),
        Ok(Err((error, resolution))) => approval_error_response(error, resolution),
        Err(error) => {
            tracing::error!(error = %error, "human approval task failed");
            error_response(StatusCode::SERVICE_UNAVAILABLE, "gateway_unavailable")
        }
    }
}

/// Claims and performs the single dispatch of an approved execution.
async fn dispatch_approved(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((tenant_id, agent_id, request_id)): Path<(uuid::Uuid, uuid::Uuid, uuid::Uuid)>,
) -> Response {
    // Agents must never be able to trigger the dispatch of an approved
    // action: only an approver/operator credential for the tenant can.
    if let Err(denied) = state.authorize(&headers, &[ApiRole::Approver], Some(tenant_id)) {
        return denied.into_response();
    }
    if !exec_mode_accepted(state.options, &headers) {
        return exec_mode_refused();
    }
    let options = state.options;
    let gateway = state.gateway;
    let key = crate::ExecutionKey {
        tenant_id,
        agent_id,
        request_id,
    };
    match tokio::task::spawn_blocking(move || gateway.dispatch_approved(key)).await {
        Ok(Ok(receipt)) => {
            let execution = receipt.execution;
            with_executed_by(
                options,
                execution,
                (StatusCode::OK, Json(receipt)).into_response(),
            )
        }
        Ok(Err(error)) => gateway_error_response(error),
        Err(error) => {
            tracing::error!(error = %error, "approved dispatch task failed");
            error_response(StatusCode::SERVICE_UNAVAILABLE, "gateway_unavailable")
        }
    }
}

/// Approval state for one tenant/agent/request key. Never dispatches; may
/// persist the signed expiration receipt on first observation of expiry.
async fn approval_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((tenant_id, agent_id, request_id)): Path<(uuid::Uuid, uuid::Uuid, uuid::Uuid)>,
) -> Response {
    if let Err(denied) = state.authorize(
        &headers,
        &[ApiRole::Agent, ApiRole::Approver],
        Some(tenant_id),
    ) {
        return denied.into_response();
    }
    if !exec_mode_accepted(state.options, &headers) {
        return exec_mode_refused();
    }
    let options = state.options;
    let gateway = state.gateway;
    let key = crate::ExecutionKey {
        tenant_id,
        agent_id,
        request_id,
    };
    match tokio::task::spawn_blocking(move || gateway.approval_state(key)).await {
        // With gateway-executed effects an approved action is never handed
        // to the client to run, whether or not it was dispatched yet.
        Ok(Ok(state))
            if options.gateway_executes_effects
                && state.resolution == crate::ApprovalResolution::Approved =>
        {
            with_executed_by(
                options,
                state.execution,
                (
                    StatusCode::CONFLICT,
                    Json(ErrorResponse {
                        code: "cooperative_exec_rejected",
                        resolution: Some(state.resolution),
                        expiration_receipt_id: None,
                        execution: Some(state.execution),
                    }),
                )
                    .into_response(),
            )
        }
        Ok(Ok(state)) => (StatusCode::OK, Json(state)).into_response(),
        Ok(Err(error)) => gateway_error_response(error),
        Err(error) => {
            tracing::error!(error = %error, "approval status task failed");
            error_response(StatusCode::SERVICE_UNAVAILABLE, "gateway_unavailable")
        }
    }
}

/// For conflicts and expiry on the approval endpoints, looks up the state of
/// the same (path-scoped) key so the caller can tell approve from reject.
/// Lookup failures simply omit the field; the error itself is unchanged.
fn with_resolution(
    gateway: &Gateway,
    key: crate::ExecutionKey,
    error: GatewayError,
) -> (GatewayError, ApprovalErrorContext) {
    let reportable = matches!(
        error,
        GatewayError::Approval(crate::ApprovalError::NotPending | crate::ApprovalError::Expired)
            | GatewayError::Journal(JournalError::ApprovalAlreadyRecorded)
    );
    let resolution = if reportable {
        gateway.approval_resolution(key).ok()
    } else {
        None
    };
    let expiration_receipt_id =
        if matches!(error, GatewayError::Approval(crate::ApprovalError::Expired)) {
            gateway
                .approval_expiration(key)
                .ok()
                .flatten()
                .map(|receipt| receipt.receipt_id)
        } else {
            None
        };
    (
        error,
        ApprovalErrorContext {
            resolution,
            expiration_receipt_id,
        },
    )
}

fn approval_error_response(error: GatewayError, context: ApprovalErrorContext) -> Response {
    let response = gateway_error_response(error);
    let code = match response.status() {
        StatusCode::CONFLICT => "approval_not_pending",
        StatusCode::GONE => "approval_expired",
        _ => return response,
    };
    if context.resolution.is_none() && context.expiration_receipt_id.is_none() {
        return response;
    }
    (
        response.status(),
        Json(ErrorResponse {
            code,
            resolution: context.resolution,
            expiration_receipt_id: context.expiration_receipt_id,
            execution: None,
        }),
    )
        .into_response()
}

fn gateway_error_response(error: GatewayError) -> Response {
    match error {
        GatewayError::Authorization(error) => match error.kind() {
            ErrorKind::InvalidRequest => {
                error_response(StatusCode::BAD_REQUEST, "invalid_authorization_request")
            }
            ErrorKind::ReplayDetected => {
                error_response(StatusCode::CONFLICT, "authorization_request_already_used")
            }
            ErrorKind::ReplayGuardFailure
            | ErrorKind::FreshnessUnavailable
            | ErrorKind::PolicyIntegrityFailure
            | ErrorKind::PolicyEvaluationFailure
            | ErrorKind::EvidenceFailure
            | ErrorKind::FreshnessInvalid
            | ErrorKind::FreshnessLeaseTooLong
            | ErrorKind::TrustedClockUnavailable => {
                error_response(StatusCode::SERVICE_UNAVAILABLE, "authorization_unavailable")
            }
            _ => error_response(StatusCode::FORBIDDEN, "authorization_failed"),
        },
        GatewayError::Journal(JournalError::AlreadyRecorded) => {
            error_response(StatusCode::CONFLICT, "execution_request_already_recorded")
        }
        GatewayError::Journal(JournalError::ConflictingRequest) => {
            error_response(StatusCode::CONFLICT, "execution_request_conflict")
        }
        GatewayError::Journal(JournalError::ApprovalAlreadyRecorded) => {
            error_response(StatusCode::CONFLICT, "approval_not_pending")
        }
        GatewayError::Journal(JournalError::InvalidTransition) => {
            error_response(StatusCode::CONFLICT, "execution_state_conflict")
        }
        GatewayError::Journal(JournalError::ApprovalExpired) => {
            error_response(StatusCode::GONE, "approval_expired")
        }
        GatewayError::Journal(_)
        | GatewayError::OutcomeNotRecorded(_)
        | GatewayError::ExecutionAttestation(_) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "execution_state_unavailable",
        ),
        GatewayError::HighAssuranceRequired | GatewayError::InvalidEvidence => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway_configuration_error",
        ),
        GatewayError::TenantIdentityInvalid => {
            error_response(StatusCode::BAD_REQUEST, "tenant_identity_invalid")
        }
        GatewayError::DispatchRefused { .. } => {
            error_response(StatusCode::FORBIDDEN, "action_not_dispatchable")
        }
        GatewayError::ExecutionNotFound(_) => {
            error_response(StatusCode::NOT_FOUND, "execution_not_found")
        }
        GatewayError::Approval(crate::ApprovalError::InvalidSignature) => {
            error_response(StatusCode::FORBIDDEN, "invalid_approval_signature")
        }
        GatewayError::Approval(crate::ApprovalError::SelfApproval) => {
            error_response(StatusCode::FORBIDDEN, "self_approval_forbidden")
        }
        GatewayError::Approval(crate::ApprovalError::Expired) => {
            error_response(StatusCode::GONE, "approval_expired")
        }
        GatewayError::Approval(crate::ApprovalError::NotPending) => {
            error_response(StatusCode::CONFLICT, "approval_not_pending")
        }
        GatewayError::Approval(crate::ApprovalError::NotConfigured) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "approval_not_configured")
        }
        GatewayError::Approval(_) => {
            error_response(StatusCode::BAD_REQUEST, "invalid_approval_decision")
        }
    }
}

fn error_response(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        Json(ErrorResponse {
            code,
            resolution: None,
            expiration_receipt_id: None,
            execution: None,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use praetore_core::PraetoreError;

    fn exec_headers(values: &[&[u8]]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for value in values {
            map.append(EXEC_MODE_HEADER, HeaderValue::from_bytes(value).unwrap());
        }
        map
    }

    #[test]
    fn exec_mode_header_is_validated_strictly_only_with_gateway_effects() {
        let on = HttpOptions {
            gateway_executes_effects: true,
        };
        assert!(exec_mode_accepted(on, &exec_headers(&[b"gateway"])));
        for bad in [
            &[][..],
            &[&b"cooperative"[..]][..],
            &[&b"Gateway"[..]][..],
            &[&b"gateway "[..]][..],
            &[&b""[..]][..],
            &[&b"gatewaygatewaygateway"[..]][..],
            &[&b"gateway"[..], &b"gateway"[..]][..],
            &[&b"gateway"[..], &b"cooperative"[..]][..],
        ] {
            assert!(!exec_mode_accepted(on, &exec_headers(bad)), "{bad:?}");
        }
        let off = HttpOptions::default();
        assert!(exec_mode_accepted(off, &exec_headers(&[])));
        assert_eq!(exec_mode_refused().status(), StatusCode::CONFLICT);
        assert!(exec_mode_accepted(off, &exec_headers(&[b"cooperative"])));
    }

    #[test]
    fn dispatch_refusal_maps_to_forbidden() {
        let response = gateway_error_response(GatewayError::DispatchRefused {
            key: crate::ExecutionKey {
                tenant_id: Uuid::nil(),
                agent_id: Uuid::nil(),
                request_id: Uuid::nil(),
            },
            reason: "path_traversal",
        });
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn bearer_token_requires_exactly_one_bearer_header() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abc"));
        assert_eq!(bearer_token(&headers), Some("abc"));
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer_token(&headers), None);
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abc"));
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer def"));
        assert_eq!(bearer_token(&headers), None);
    }

    #[tokio::test]
    async fn credentials_are_marked_sensitive() {
        let request = Request::builder()
            .header(AUTHORIZATION, "Bearer secret-token")
            .body(axum::body::Body::empty())
            .unwrap();
        let request = mark_credentials_sensitive(request).await;
        assert!(request.headers()[AUTHORIZATION].is_sensitive());
        assert!(!format!("{:?}", request.headers()).contains("secret-token"));
    }

    #[test]
    fn trusted_clock_failure_maps_to_service_unavailable() {
        let response = gateway_error_response(GatewayError::Authorization(
            PraetoreError::TrustedClockUnavailable,
        ));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
