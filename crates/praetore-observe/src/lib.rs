use axum::{
    Json, Router,
    body::Body,
    extract::{Extension, Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use praetore_core::{VerifiedPublicKey, canonical::parse_json_rejecting_duplicates};
use praetore_gateway::{AuthorizationStatus, ExecutionKey, ExecutionStatus};
use praetore_replay_postgres::{
    ExecutionFilters, ExecutionPage, ExecutionTransition, ObservedExecution,
    PostgresObservabilityReader,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

const INDEX_HTML: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const APP_CSS: &str = include_str!("../ui/styles.css");
const MAX_PAGE_SIZE: u32 = 100;
const MAX_OFFSET: u32 = 10_000;
const MAX_TIME_RANGE: Duration = Duration::days(90);

#[derive(Clone)]
pub struct ObserveState {
    reader: Arc<dyn ObservationStore>,
    tenant_token_hashes: HashMap<[u8; 32], Uuid>,
    trusted_attester: Option<VerifiedPublicKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantTokenFile {
    schema_version: u8,
    tenants: Vec<TenantTokenEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantTokenEntry {
    tenant_id: Uuid,
    bearer_token_sha256: String,
}

#[derive(Clone, Copy)]
struct AuthenticatedTenant(Uuid);

pub trait ObservationStore: Send + Sync + 'static {
    fn list(
        &self,
        filters: &ExecutionFilters,
    ) -> Result<ExecutionPage, praetore_gateway::JournalError>;
    fn get(
        &self,
        key: ExecutionKey,
    ) -> Result<Option<(ObservedExecution, Vec<ExecutionTransition>)>, praetore_gateway::JournalError>;
    fn database_available(&self) -> bool;
}

impl ObservationStore for PostgresObservabilityReader {
    fn list(
        &self,
        filters: &ExecutionFilters,
    ) -> Result<ExecutionPage, praetore_gateway::JournalError> {
        PostgresObservabilityReader::list(self, filters)
    }

    fn get(
        &self,
        key: ExecutionKey,
    ) -> Result<Option<(ObservedExecution, Vec<ExecutionTransition>)>, praetore_gateway::JournalError>
    {
        PostgresObservabilityReader::get(self, key)
    }

    fn database_available(&self) -> bool {
        PostgresObservabilityReader::database_available(self)
    }
}

impl ObserveState {
    pub fn new(
        reader: Arc<dyn ObservationStore>,
        tenant_token_hashes: HashMap<Uuid, String>,
        trusted_attester: Option<VerifiedPublicKey>,
    ) -> Result<Self, ConfigError> {
        if tenant_token_hashes.is_empty() {
            return Err(ConfigError::InvalidTokenConfiguration);
        }
        let mut token_hashes = HashMap::with_capacity(tenant_token_hashes.len());
        for (tenant_id, digest) in tenant_token_hashes {
            if tenant_id.is_nil() {
                return Err(ConfigError::InvalidTokenConfiguration);
            }
            let digest = parse_token_digest(&digest)?;
            if token_hashes.insert(digest, tenant_id).is_some() {
                return Err(ConfigError::InvalidTokenConfiguration);
            }
        }
        Ok(Self {
            reader,
            tenant_token_hashes: token_hashes,
            trusted_attester,
        })
    }

    pub fn router(self) -> Router {
        let state = Arc::new(self);
        let api = Router::new()
            .route("/operations", get(list_operations))
            .route(
                "/operations/{tenant_id}/{agent_id}/{request_id}",
                get(operation_detail),
            )
            .route("/health", get(system_health))
            .route("/assurance", get(assurance))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                require_bearer,
            ));

        Router::new()
            .route("/", get(index))
            .route("/app.js", get(app_js))
            .route("/styles.css", get(app_css))
            .route("/assets/app.js", get(app_js))
            .route("/assets/styles.css", get(app_css))
            .nest("/api/v1", api)
            .with_state(state)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    InvalidTokenConfiguration,
    NonLoopbackBind,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTokenConfiguration => {
                f.write_str("tenant bearer token configuration is invalid")
            }
            Self::NonLoopbackBind => f.write_str("observability bind address must be loopback"),
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn validate_bind_address(address: SocketAddr) -> Result<SocketAddr, ConfigError> {
    if address.ip().is_loopback() {
        Ok(address)
    } else {
        Err(ConfigError::NonLoopbackBind)
    }
}

fn parse_token_digest(digest_hex: &str) -> Result<[u8; 32], ConfigError> {
    let digest = hex::decode(digest_hex).map_err(|_| ConfigError::InvalidTokenConfiguration)?;
    if digest.len() != 32 || hex::encode(&digest) != digest_hex {
        return Err(ConfigError::InvalidTokenConfiguration);
    }
    digest
        .try_into()
        .map_err(|_| ConfigError::InvalidTokenConfiguration)
}

pub fn parse_tenant_token_hashes(document: &str) -> Result<HashMap<Uuid, String>, ConfigError> {
    if document.len() > 1_048_576 {
        return Err(ConfigError::InvalidTokenConfiguration);
    }
    let value = parse_json_rejecting_duplicates(document)
        .map_err(|_| ConfigError::InvalidTokenConfiguration)?;
    let config: TenantTokenFile =
        serde_json::from_value(value).map_err(|_| ConfigError::InvalidTokenConfiguration)?;
    if config.schema_version != 1 || config.tenants.is_empty() || config.tenants.len() > 4096 {
        return Err(ConfigError::InvalidTokenConfiguration);
    }

    let mut tokens = HashMap::with_capacity(config.tenants.len());
    let mut seen_hashes = std::collections::HashSet::with_capacity(config.tenants.len());
    for entry in config.tenants {
        let digest = parse_token_digest(&entry.bearer_token_sha256)?;
        if entry.tenant_id.is_nil()
            || !seen_hashes.insert(digest)
            || tokens
                .insert(entry.tenant_id, entry.bearer_token_sha256)
                .is_some()
        {
            return Err(ConfigError::InvalidTokenConfiguration);
        }
    }
    Ok(tokens)
}

async fn require_bearer(
    State(state): State<Arc<ObserveState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(|value| hex::decode(value).ok())
        .filter(|value| value.len() == 32);
    let authenticated_tenant = token.and_then(|token| {
        let digest: [u8; 32] = Sha256::digest(token).into();
        let mut matched_tenant = None;
        for (expected, tenant_id) in &state.tenant_token_hashes {
            if bool::from(expected.as_slice().ct_eq(digest.as_slice())) {
                matched_tenant = Some(*tenant_id);
            }
        }
        matched_tenant
    });
    if let Some(tenant_id) = authenticated_tenant {
        request
            .extensions_mut()
            .insert(AuthenticatedTenant(tenant_id));
        next.run(request).await
    } else {
        let mut response = api_error(StatusCode::UNAUTHORIZED, "unauthorized");
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        response
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    tenant_id: Option<String>,
    agent_id: Option<String>,
    decision: Option<String>,
    execution_state: Option<String>,
    from: Option<String>,
    to: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Serialize)]
struct OperationPage {
    total: i64,
    limit: u32,
    offset: u32,
    operations: Vec<OperationSummary>,
}

#[derive(Debug, Serialize)]
struct OperationSummary {
    tenant_id: Uuid,
    agent_id: Uuid,
    request_id: Uuid,
    created_at: String,
    updated_at: String,
    action_type: String,
    capability: Option<String>,
    action_digest: String,
    request_digest: String,
    decision: &'static str,
    execution_state: &'static str,
    evidence_available: bool,
    evidence_integrity: &'static str,
    attester_signature: &'static str,
    agent_intent_signature: &'static str,
    authority_signature: &'static str,
    historical_decision_only: bool,
    sensitive_fields_redacted: bool,
}

#[derive(Debug, Serialize)]
struct OperationDetail {
    operation: OperationSummary,
    policy_digest: Option<String>,
    policy_semantics_version: Option<u8>,
    decision_rationale: &'static str,
    target_redacted: bool,
    parameters_redacted: bool,
    context_redacted: bool,
    adapter_output: &'static str,
    transition_history: &'static str,
    execution_interpretation: &'static str,
    transitions: Vec<TransitionView>,
    current_authorization: bool,
}

#[derive(Debug, Serialize)]
struct TransitionView {
    from: Option<&'static str>,
    to: &'static str,
    occurred_at: String,
}

#[derive(Debug, Serialize)]
struct HealthView {
    database: &'static str,
    adapter_telemetry: &'static str,
    journal_error_telemetry: &'static str,
}

#[derive(Debug, Serialize)]
struct AssuranceView {
    scope: &'static str,
    authorization_commit: &'static str,
    execution_guarantee: &'static str,
    reconciliation: &'static str,
    transition_history: &'static str,
    evidence: &'static str,
    deployment_boundary: &'static str,
}

async fn list_operations(
    State(state): State<Arc<ObserveState>>,
    Extension(tenant): Extension<AuthenticatedTenant>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(_) => return api_error(StatusCode::BAD_REQUEST, "invalid_query"),
    };
    let mut filters = match validate_query(query) {
        Ok(filters) => filters,
        Err(message) => return api_error(StatusCode::BAD_REQUEST, message),
    };
    if filters
        .tenant_id
        .is_some_and(|requested| requested != tenant.0)
    {
        return api_error(StatusCode::FORBIDDEN, "tenant_access_denied");
    }
    filters.tenant_id = Some(tenant.0);
    let reader = state.reader.clone();
    let response_limit = filters.limit;
    let response_offset = filters.offset;
    let page = match tokio::task::spawn_blocking(move || reader.list(&filters)).await {
        Ok(Ok(page)) => page,
        Ok(Err(error)) => {
            log_store_error(error);
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable");
        }
        Err(_) => {
            tracing::error!(failure = "database_worker", "observability query failed");
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable");
        }
    };
    let operations = page
        .rows
        .iter()
        .map(|row| operation_summary(row, state.trusted_attester.as_ref()))
        .collect();
    api_json(
        StatusCode::OK,
        OperationPage {
            total: page.total,
            limit: response_limit,
            offset: response_offset,
            operations,
        },
    )
}

async fn operation_detail(
    State(state): State<Arc<ObserveState>>,
    Extension(tenant): Extension<AuthenticatedTenant>,
    Path((tenant_id, agent_id, request_id)): Path<(String, String, String)>,
) -> Response {
    let key = match parse_key(&tenant_id, &agent_id, &request_id) {
        Ok(key) => key,
        Err(()) => return api_error(StatusCode::BAD_REQUEST, "invalid_execution_identity"),
    };
    if key.tenant_id != tenant.0 {
        return api_error(StatusCode::NOT_FOUND, "operation_not_found");
    }
    let reader = state.reader.clone();
    let stored = match tokio::task::spawn_blocking(move || reader.get(key)).await {
        Ok(Ok(Some(stored))) => stored,
        Ok(Ok(None)) => return api_error(StatusCode::NOT_FOUND, "operation_not_found"),
        Ok(Err(error)) => {
            log_store_error(error);
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable");
        }
        Err(_) => {
            tracing::error!(
                failure = "database_worker",
                "observability detail query failed"
            );
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable");
        }
    };
    let (row, transitions) = stored;
    let operation = operation_summary(&row, state.trusted_attester.as_ref());
    let transitions: Vec<_> = transitions.iter().map(transition_view).collect();
    api_json(
        StatusCode::OK,
        OperationDetail {
            operation,
            policy_digest: row.evidence.policy_digest.clone(),
            policy_semantics_version: row.evidence.semantics_version,
            decision_rationale: "redacted_policy_supplied_text",
            target_redacted: true,
            parameters_redacted: true,
            context_redacted: true,
            adapter_output: if row.output_available {
                "stored_but_redacted"
            } else {
                "not_recorded"
            },
            transition_history: if transitions.is_empty() {
                "not_available"
            } else {
                "recorded"
            },
            execution_interpretation: execution_interpretation(row.execution),
            transitions,
            current_authorization: false,
        },
    )
}

async fn system_health(State(state): State<Arc<ObserveState>>) -> Response {
    let reader = state.reader.clone();
    let database_available =
        match tokio::task::spawn_blocking(move || reader.database_available()).await {
            Ok(available) => available,
            Err(_) => {
                tracing::error!(failure = "database_worker", "health probe failed");
                false
            }
        };
    let view = HealthView {
        database: if database_available {
            "available"
        } else {
            "unavailable"
        },
        adapter_telemetry: "not_instrumented",
        journal_error_telemetry: "not_recorded",
    };
    api_json(
        if database_available {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        view,
    )
}

async fn assurance() -> Response {
    api_json(
        StatusCode::OK,
        AssuranceView {
            scope: "read_only_observability_not_an_authorization_or_execution_control",
            authorization_commit: "postgresql_commits_a_new_replay_claim_with_its_verified_high_assurance_evidence_in_one_transaction",
            execution_guarantee: "no_exactly_once_external_execution_guarantee; dispatched_and_ambiguous_operations_are_not_automatically_retried",
            reconciliation: "requires_operator_quiescence_and_adapter_authoritative_evidence",
            transition_history: "append_only_events_are_recorded_after_migration; older_operations_have_no_reconstructed_history",
            evidence: "integrity_and_configured_attester_signature_are_historical_receipt_checks_not_current_authorization",
            deployment_boundary: "loopback_only_listener_and_operator_bearer_token; remote_access_requires_a_separately_reviewed_authenticated_tls_proxy",
        },
    )
}

fn validate_query(query: ListQuery) -> Result<ExecutionFilters, &'static str> {
    let limit = query.limit.unwrap_or(25);
    let offset = query.offset.unwrap_or(0);
    if limit == 0 || limit > MAX_PAGE_SIZE || offset > MAX_OFFSET {
        return Err("invalid_pagination");
    }
    let tenant_id = query
        .tenant_id
        .map(|value| Uuid::parse_str(&value).map_err(|_| "invalid_tenant_id"))
        .transpose()?;
    let agent_id = query
        .agent_id
        .map(|value| Uuid::parse_str(&value).map_err(|_| "invalid_agent_id"))
        .transpose()?;
    let decision = query.decision.as_deref().map(parse_decision).transpose()?;
    let execution = query
        .execution_state
        .as_deref()
        .map(parse_execution)
        .transpose()?;
    let from = query.from.map(parse_timestamp).transpose()?;
    let to = query.to.map(parse_timestamp).transpose()?;
    if from.is_some() != to.is_some() {
        return Err("time_range_requires_both_bounds");
    }
    if let (Some(from), Some(to)) = (&from, &to) {
        if from >= to {
            return Err("invalid_time_range");
        }
        if *to - *from > MAX_TIME_RANGE {
            return Err("time_range_too_large");
        }
    }
    Ok(ExecutionFilters {
        tenant_id,
        agent_id,
        decision,
        execution,
        from,
        to,
        limit,
        offset,
    })
}

fn parse_timestamp(value: String) -> Result<OffsetDateTime, &'static str> {
    if value.len() > 40 {
        return Err("invalid_timestamp");
    }
    let parsed = OffsetDateTime::parse(&value, &Rfc3339).map_err(|_| "invalid_timestamp")?;
    Ok(parsed)
}

fn parse_decision(value: &str) -> Result<AuthorizationStatus, &'static str> {
    match value {
        "allowed" => Ok(AuthorizationStatus::Allowed),
        "requires_approval" => Ok(AuthorizationStatus::RequiresApproval),
        "denied" => Ok(AuthorizationStatus::Denied),
        _ => Err("invalid_decision"),
    }
}

fn parse_execution(value: &str) -> Result<ExecutionStatus, &'static str> {
    match value {
        "not_dispatched" => Ok(ExecutionStatus::NotDispatched),
        "authorized" => Ok(ExecutionStatus::Authorized),
        "dispatched" => Ok(ExecutionStatus::Dispatched),
        "executed" => Ok(ExecutionStatus::Executed),
        "confirmed" => Ok(ExecutionStatus::Confirmed),
        "outcome_unknown" => Ok(ExecutionStatus::OutcomeUnknown),
        "failed" => Ok(ExecutionStatus::Failed),
        _ => Err("invalid_execution_state"),
    }
}

fn parse_key(tenant_id: &str, agent_id: &str, request_id: &str) -> Result<ExecutionKey, ()> {
    Ok(ExecutionKey {
        tenant_id: Uuid::parse_str(tenant_id).map_err(|_| ())?,
        agent_id: Uuid::parse_str(agent_id).map_err(|_| ())?,
        request_id: Uuid::parse_str(request_id).map_err(|_| ())?,
    })
}

fn operation_summary(
    row: &ObservedExecution,
    trusted_attester: Option<&VerifiedPublicKey>,
) -> OperationSummary {
    let integrity = row.evidence.verify_integrity();
    let signature_status = match (integrity, row.evidence.attester_signature.as_ref()) {
        (false, _) => "invalid",
        (true, None) => "missing",
        (true, Some(_)) => match trusted_attester {
            None => "not_configured",
            Some(key) if row.evidence.verify_attester_signature(key).is_ok() => "verified",
            Some(_) => "invalid",
        },
    };
    OperationSummary {
        tenant_id: row.key.tenant_id,
        agent_id: row.key.agent_id,
        request_id: row.key.request_id,
        created_at: row.created_at.clone(),
        updated_at: row.updated_at.clone(),
        action_type: row.evidence.action.action_type.clone(),
        capability: row.evidence.action.capability.clone(),
        action_digest: row.action_digest.clone(),
        request_digest: row.request_digest.clone(),
        decision: decision_label(row.authorization),
        execution_state: execution_label(row.execution),
        evidence_available: true,
        evidence_integrity: if integrity { "valid" } else { "invalid" },
        attester_signature: signature_status,
        agent_intent_signature: if !integrity {
            "invalid"
        } else if row.evidence.agent_signature.is_none() {
            "missing"
        } else if row.evidence.verify_agent_intent().is_ok() {
            "valid_self_asserted"
        } else {
            "invalid"
        },
        authority_signature: if row.evidence.authority.signature.is_some() {
            "present_not_trust_verified"
        } else {
            "missing"
        },
        historical_decision_only: true,
        sensitive_fields_redacted: true,
    }
}

fn transition_view(transition: &ExecutionTransition) -> TransitionView {
    TransitionView {
        from: transition.from.map(execution_label),
        to: execution_label(transition.to),
        occurred_at: transition.occurred_at.clone(),
    }
}

fn decision_label(status: AuthorizationStatus) -> &'static str {
    match status {
        AuthorizationStatus::Allowed => "allowed",
        AuthorizationStatus::RequiresApproval => "requires_approval",
        AuthorizationStatus::Denied => "denied",
    }
}

fn execution_label(status: ExecutionStatus) -> &'static str {
    match status {
        ExecutionStatus::NotDispatched => "not_dispatched",
        ExecutionStatus::Authorized => "authorized",
        ExecutionStatus::Dispatched => "dispatched",
        ExecutionStatus::Executed => "executed",
        ExecutionStatus::Confirmed => "confirmed",
        ExecutionStatus::OutcomeUnknown => "outcome_unknown",
        ExecutionStatus::Failed => "failed",
    }
}

fn execution_interpretation(status: ExecutionStatus) -> &'static str {
    match status {
        ExecutionStatus::NotDispatched => "the journal records no dispatch attempt",
        ExecutionStatus::Authorized => {
            "authorization is recorded; restart recovery must not dispatch automatically"
        }
        ExecutionStatus::Dispatched => {
            "dispatch commitment is durable; whether the external effect occurred is unknown"
        }
        ExecutionStatus::OutcomeUnknown => {
            "external outcome is unresolved; no automatic retry is permitted"
        }
        ExecutionStatus::Executed => {
            "the adapter reported execution; independent external confirmation is not implied"
        }
        ExecutionStatus::Confirmed => "the adapter reported confirmation under its contract",
        ExecutionStatus::Failed => {
            "the adapter or reconciler reported a failed/not-applied outcome"
        }
    }
}

fn log_store_error(error: praetore_gateway::JournalError) {
    tracing::error!(
        failure = match error {
            praetore_gateway::JournalError::Unavailable => "storage_unavailable",
            _ => "invalid_stored_record",
        },
        "observability storage request failed"
    );
}

async fn index() -> Response {
    static_response(StatusCode::OK, "text/html; charset=utf-8", INDEX_HTML)
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

fn api_error(status: StatusCode, code: &'static str) -> Response {
    api_json(status, JsonError { error: code })
}

#[derive(Serialize)]
struct JsonError {
    error: &'static str,
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
    use axum::body::to_bytes;
    use praetore_core::{
        Action, AgentId, AgentKeyPair, Authority, Decision, Evidence, EvidenceAttesterKey,
    };
    use praetore_gateway::JournalError;
    use praetore_replay_postgres::ExecutionPage;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{
        collections::{BTreeMap, HashMap},
        sync::atomic::{AtomicUsize, Ordering},
    };
    use tower::ServiceExt;

    const TOKEN: &str = "4242424242424242424242424242424242424242424242424242424242424242";
    const TEST_TENANT_ID: Uuid = Uuid::from_u128(1);

    struct MemoryStore {
        row: ObservedExecution,
        reads: AtomicUsize,
        writes: AtomicUsize,
        database_available: bool,
        listed_tenant: std::sync::Mutex<Option<Uuid>>,
    }

    impl ObservationStore for MemoryStore {
        fn list(&self, filters: &ExecutionFilters) -> Result<ExecutionPage, JournalError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            *self.listed_tenant.lock().unwrap() = filters.tenant_id;
            Ok(ExecutionPage {
                total: 1,
                rows: vec![self.row.clone()],
            })
        }

        fn get(
            &self,
            key: ExecutionKey,
        ) -> Result<Option<(ObservedExecution, Vec<ExecutionTransition>)>, JournalError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok((key == self.row.key).then(|| (self.row.clone(), Vec::new())))
        }

        fn database_available(&self) -> bool {
            self.database_available
        }
    }

    #[test]
    fn pagination_and_filters_are_bounded_and_validated() {
        assert!(validate_query(query_with("limit=101")).is_err());
        assert!(validate_query(query_with("offset=10001")).is_err());
        assert!(validate_query(query_with("decision=maybe")).is_err());
        assert!(validate_query(query_with("execution_state=running")).is_err());
        assert!(
            validate_query(query_with(
                "from=2026-02-01T00%3A00%3A00Z&to=2026-01-01T00%3A00%3A00Z"
            ))
            .is_err()
        );
        assert!(
            validate_query(query_with(
                "from=2026-01-01T00%3A00%3A00Z&to=2026-05-01T00%3A00%3A00Z"
            ))
            .is_err()
        );
    }

    #[test]
    fn default_pagination_is_bounded() {
        let filters = validate_query(query_with("")).unwrap();
        assert_eq!(filters.limit, 25);
        assert_eq!(filters.offset, 0);
    }

    #[test]
    fn bind_is_loopback_only() {
        assert!(validate_bind_address("127.0.0.1:8088".parse().unwrap()).is_ok());
        assert!(validate_bind_address("[::1]:8088".parse().unwrap()).is_ok());
        assert!(validate_bind_address("0.0.0.0:8088".parse().unwrap()).is_err());
    }

    #[test]
    fn tenant_token_configuration_requires_unique_tenant_scoped_hashes() {
        let tenant = Uuid::from_u128(1);
        let digest = hex::encode(Sha256::digest([0x42; 32]));
        let valid = format!(
            r#"{{"schema_version":1,"tenants":[{{"tenant_id":"{tenant}","bearer_token_sha256":"{digest}"}}]}}"#
        );
        assert_eq!(parse_tenant_token_hashes(&valid).unwrap()[&tenant], digest);
        assert!(parse_tenant_token_hashes(r#"{"schema_version":1,"tenants":[]}"#).is_err());
        assert!(
            parse_tenant_token_hashes(r#"{"schema_version":1,"schema_version":1,"tenants":[]}"#)
                .is_err()
        );
        assert!(parse_tenant_token_hashes(
            &format!(
                r#"{{"schema_version":1,"tenants":[{{"tenant_id":"{tenant}","bearer_token_sha256":"{digest}"}},{{"tenant_id":"{tenant}","bearer_token_sha256":"{}"}}]}}"#,
                hex::encode(Sha256::digest([0x43; 32]))
            )
        )
        .is_err()
        );
        assert!(
        parse_tenant_token_hashes(
            &format!(
                r#"{{"schema_version":1,"tenants":[{{"tenant_id":"{tenant}","bearer_token_sha256":"{digest}"}},{{"tenant_id":"{}","bearer_token_sha256":"{digest}"}}]}}"#,
                Uuid::from_u128(2)
            )
        )
        .is_err());
    }

    #[tokio::test]
    async fn api_rejects_unauthenticated_operations_and_evidence_detail() {
        let (state, _) = test_state(true, true);
        let app = state.router();
        for uri in [
            "/api/v1/operations",
            "/api/v1/operations/cccccccc-cccc-4ccc-8ccc-cccccccccccc/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header(header::AUTHORIZATION, format!("Bearer {}", "00".repeat(32)))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn relative_ui_assets_are_served_and_legacy_asset_paths_remain_available() {
        let (state, _) = test_state(true, true);
        let app = state.router();
        for (path, expected_type, expected_content) in [
            ("/styles.css", "text/css; charset=utf-8", "--bg: #fbfbfd"),
            (
                "/assets/styles.css",
                "text/css; charset=utf-8",
                "--bg: #fbfbfd",
            ),
            (
                "/app.js",
                "text/javascript; charset=utf-8",
                "const tokenInput",
            ),
            (
                "/assets/app.js",
                "text/javascript; charset=utf-8",
                "const tokenInput",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                expected_type,
                "{path}"
            );
            let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            assert!(
                String::from_utf8(body.to_vec())
                    .unwrap()
                    .contains(expected_content),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn listing_and_detail_are_read_only_and_redact_sensitive_data() {
        let (state, store) = test_state(true, true);
        let key = store.row.key;
        let app = state.router();
        let list = authorized_request("/api/v1/operations?limit=1");
        let list_response = app.clone().oneshot(list).await.unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_json: Value = serde_json::from_slice(
            &to_bytes(list_response.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(list_json["operations"][0]["execution_state"], "authorized");

        let detail_response = app
            .clone()
            .oneshot(authorized_request(&format!(
                "/api/v1/operations/{}/{}/{}",
                key.tenant_id, key.agent_id, key.request_id
            )))
            .await
            .unwrap();
        assert_eq!(detail_response.status(), StatusCode::OK);
        let detail_body = to_bytes(detail_response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let detail_text = String::from_utf8(detail_body.to_vec()).unwrap();
        let detail_json: Value = serde_json::from_str(&detail_text).unwrap();
        assert_eq!(detail_json["current_authorization"], false);
        assert_eq!(detail_json["operation"]["historical_decision_only"], true);
        assert_eq!(detail_json["operation"]["attester_signature"], "verified");
        for secret in [
            "target-secret",
            "parameter-secret",
            "context-secret",
            "adapter-secret",
            "reason-secret",
        ] {
            assert!(!detail_text.contains(secret));
        }
        assert_eq!(store.reads.load(Ordering::SeqCst), 2);
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);

        let mutation_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/operations")
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mutation_response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pagination_and_filters_are_rejected_at_api_boundary() {
        let (state, store) = test_state(true, true);
        let app = state.router();
        for uri in [
            "/api/v1/operations?limit=101",
            "/api/v1/operations?offset=10001",
            "/api/v1/operations?decision=maybe",
            "/api/v1/operations?execution_state=running",
            "/api/v1/operations?unknown=value",
            "/api/v1/operations?from=2026-01-01T00%3A00%3A00Z",
        ] {
            let response = app.clone().oneshot(authorized_request(uri)).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
        assert_eq!(store.reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn tenant_token_scopes_operation_lists_and_details() {
        let (state, store) = test_state(true, true);
        let app = state.router();
        let allowed_list = app
            .clone()
            .oneshot(authorized_request("/api/v1/operations"))
            .await
            .unwrap();
        assert_eq!(allowed_list.status(), StatusCode::OK);
        assert_eq!(*store.listed_tenant.lock().unwrap(), Some(TEST_TENANT_ID));

        let cross_tenant_list = app
            .clone()
            .oneshot(authorized_request(&format!(
                "/api/v1/operations?tenant_id={}",
                Uuid::from_u128(2)
            )))
            .await
            .unwrap();
        assert_eq!(cross_tenant_list.status(), StatusCode::FORBIDDEN);

        let cross_tenant_detail = app
            .oneshot(authorized_request(&format!(
                "/api/v1/operations/{}/{}/{}",
                Uuid::from_u128(2),
                store.row.key.agent_id,
                store.row.key.request_id
            )))
            .await
            .unwrap();
        assert_eq!(cross_tenant_detail.status(), StatusCode::NOT_FOUND);
        assert_eq!(store.reads.load(Ordering::SeqCst), 1);

        let other_tenant = Uuid::from_u128(2);
        let other_token = hex::encode([0x43; 32]);
        let other_state = ObserveState::new(
            store.clone(),
            HashMap::from([(other_tenant, hex::encode(Sha256::digest([0x43; 32])))]),
            None,
        )
        .unwrap();
        let other_app = other_state.router();
        let cross_tenant_access = other_app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/operations/{}/{}/{}",
                        store.row.key.tenant_id, store.row.key.agent_id, store.row.key.request_id
                    ))
                    .header(header::AUTHORIZATION, format!("Bearer {other_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_tenant_access.status(), StatusCode::NOT_FOUND);
        assert_eq!(store.reads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn missing_health_telemetry_is_never_reported_healthy() {
        let (state, _) = test_state(false, true);
        let app = state.router();
        let response = app
            .oneshot(authorized_request("/api/v1/health"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["database"], "unavailable");
        assert_eq!(json["adapter_telemetry"], "not_instrumented");
        assert_eq!(json["journal_error_telemetry"], "not_recorded");
    }

    #[test]
    fn every_execution_state_has_a_distinct_label() {
        let states = [
            ExecutionStatus::NotDispatched,
            ExecutionStatus::Authorized,
            ExecutionStatus::Dispatched,
            ExecutionStatus::OutcomeUnknown,
            ExecutionStatus::Executed,
            ExecutionStatus::Confirmed,
            ExecutionStatus::Failed,
        ];
        let labels: Vec<_> = states.into_iter().map(execution_label).collect();
        assert_eq!(labels.len(), 7);
        assert_eq!(
            labels
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            7
        );
        assert_eq!(
            execution_label(ExecutionStatus::OutcomeUnknown),
            "outcome_unknown"
        );
        assert!(execution_interpretation(ExecutionStatus::Dispatched).contains("unknown"));
        assert!(execution_interpretation(ExecutionStatus::OutcomeUnknown).contains("unresolved"));
    }

    #[tokio::test]
    async fn invalid_evidence_is_not_reported_as_verified() {
        let (state, store) = test_state(true, false);
        let key = store.row.key;
        let app = state.router();
        let response = app
            .oneshot(authorized_request(&format!(
                "/api/v1/operations/{}/{}/{}",
                key.tenant_id, key.agent_id, key.request_id
            )))
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["operation"]["evidence_integrity"], "invalid");
        assert_eq!(json["operation"]["attester_signature"], "invalid");
    }

    fn authorized_request(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap()
    }

    fn test_state(
        database_available: bool,
        evidence_valid: bool,
    ) -> (ObserveState, Arc<MemoryStore>) {
        let agent_key = AgentKeyPair::from_secret_bytes(&[0x31; 32]);
        let agent = agent_key.identity(AgentId::new());
        let authority = Authority::new(
            agent.id.clone(),
            "observability-test-issuer",
            vec!["local:write".into()],
        )
        .with_constraint("tenant_id", Uuid::from_u128(1).to_string());
        let action = Action::new(
            "local:set_value",
            Some("target-secret".into()),
            json!({"value": "parameter-secret"}),
        )
        .unwrap()
        .with_capability("local:write");
        let mut context = BTreeMap::new();
        context.insert("private_context".into(), json!("context-secret"));
        let mut evidence = Evidence::new_with_context(
            Uuid::new_v4(),
            agent,
            authority,
            action,
            Decision::allow("reason-secret"),
            None,
            context,
        )
        .unwrap();
        let attester = EvidenceAttesterKey::from_secret_bytes(&[0x32; 32]);
        let trusted_attester = attester.public_key().unwrap();
        evidence.bind_policy_digest("cd".repeat(32)).unwrap();
        evidence.sign(&attester).unwrap();
        if !evidence_valid {
            evidence.action.parameters = json!({"value": "tampered-secret"});
        }
        let key = ExecutionKey {
            tenant_id: praetore_gateway::authority_tenant_id(&evidence.authority).unwrap(),
            agent_id: *evidence.agent.id.as_uuid(),
            request_id: evidence.request_id,
        };
        let store = Arc::new(MemoryStore {
            row: ObservedExecution {
                key,
                created_at: "2026-10-24T12:00:00Z".into(),
                updated_at: "2026-10-24T12:00:01Z".into(),
                request_digest: "a".repeat(64),
                action_digest: "b".repeat(64),
                authorization: AuthorizationStatus::Allowed,
                execution: ExecutionStatus::Authorized,
                evidence,
                output_available: true,
            },
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            database_available,
            listed_tenant: std::sync::Mutex::new(None),
        });
        let tenant_tokens = HashMap::from([(
            Uuid::from_u128(1),
            hex::encode(Sha256::digest(hex::decode(TOKEN).unwrap())),
        )]);
        let state =
            ObserveState::new(store.clone(), tenant_tokens, Some(trusted_attester)).unwrap();
        (state, store)
    }

    fn query_with(query: &str) -> ListQuery {
        serde_urlencoded::from_str(query).unwrap_or(ListQuery {
            tenant_id: None,
            agent_id: None,
            decision: None,
            execution_state: None,
            from: None,
            to: None,
            limit: None,
            offset: None,
        })
    }
}
