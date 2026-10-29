use crate::{AuthorizationStatus, Gateway, GatewayError, JournalError};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use praetore_core::{AuthorizationRequest, ErrorKind};
use serde::Serialize;
use std::{io, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;

const MAX_REQUEST_BYTES: usize = 65_536;

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    /// Present only on approval endpoints when the execution key exists and
    /// required approval: `pending`, `approved`, `rejected` or `expired`.
    #[serde(skip_serializing_if = "Option::is_none")]
    resolution: Option<crate::ApprovalResolution>,
}

#[derive(Serialize)]
struct ResolutionResponse {
    resolution: crate::ApprovalResolution,
}

/// Creates the local HTTP API for signed tool authorization requests.
///
/// `GET /v1/approvals/{tenant_id}/{agent_id}/{request_id}/status` reports the
/// human-approval state (`pending`, `approved`, `rejected`, `expired`) for that
/// exact key; 409/410 approval errors carry the same `resolution` field.
///
/// `POST /v1/execute` accepts the serialized `AuthorizationRequest`. The
/// gateway returns its signed receipt for every completed policy decision,
/// including denials and approval requirements. Request bodies are size
/// limited and parsed through PRÆTORE's duplicate-key rejecting parser.
pub fn router(gateway: Arc<Gateway>) -> Router {
    router_with_options(gateway, HttpOptions::default())
}

/// Transport options for [`router_with_options`].
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpOptions {
    /// Set when the configured dispatcher performs the effects itself (for
    /// example the filesystem [`crate::sandbox::SandboxDispatcher`]). The
    /// API then refuses cooperative execution: `/status` of an approved
    /// action that the gateway already executed answers 409
    /// `cooperative_exec_rejected` instead of `approved`, so a polling agent
    /// never runs the effect a second time. Receipts of effects performed by
    /// the gateway carry the header `praetore-executed-by: gateway`.
    pub gateway_executes_effects: bool,
}

const EXECUTED_BY_HEADER: &str = "praetore-executed-by";

/// Request header a client must send, with the exact value `gateway`, on
/// every execution-path request (`POST /v1/execute`, approval challenge,
/// approval decision and `/status`) when
/// [`HttpOptions::gateway_executes_effects`] is set. It declares that the
/// client will not perform the effect itself.
pub const EXEC_MODE_HEADER: &str = "praetore-exec-mode";
pub const EXEC_MODE_GATEWAY: &str = "gateway";
const MAX_EXEC_MODE_BYTES: usize = 16;

/// Fail-closed check of [`EXEC_MODE_HEADER`]. Without gateway-executed
/// effects the header is ignored (unchanged behaviour). Otherwise exactly
/// one header with the exact value `gateway` (at most 16 bytes) is accepted;
/// a missing, repeated, oversized, `cooperative` or any other value is
/// refused (see `exec_mode_refused`) with 409 `exec_mode_gateway_required` before the gateway is
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

/// Like [`router`], with explicit transport options.
pub fn router_with_options(gateway: Arc<Gateway>, options: HttpOptions) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route(
            "/v1/execute",
            post(move |state, headers, body| execute(state, headers, body, options)),
        )
        .route(
            "/v1/approvals/{tenant_id}/{agent_id}/{request_id}",
            get(move |state, path, headers| approval_challenge(state, path, headers, options))
                .post(move |state, path, headers, body| {
                    resolve_approval(state, path, headers, body, options)
                }),
        )
        .route(
            "/v1/approvals/{tenant_id}/{agent_id}/{request_id}/status",
            get(move |state, path, headers| approval_status(state, path, headers, options)),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(gateway)
}

/// Runs the service on IPv4 loopback only; this endpoint has no network
/// authentication or TLS and must not be exposed beyond local development.
pub async fn serve_local(port: u16, gateway: Arc<Gateway>) -> io::Result<()> {
    serve_local_with_options(port, gateway, HttpOptions::default()).await
}

/// Like [`serve_local`], with explicit transport options.
pub async fn serve_local_with_options(
    port: u16,
    gateway: Arc<Gateway>,
    options: HttpOptions,
) -> io::Result<()> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(address).await?;
    axum::serve(listener, router_with_options(gateway, options)).await
}

fn executed_by_gateway(options: HttpOptions, execution: crate::ExecutionStatus) -> bool {
    options.gateway_executes_effects
        && matches!(
            execution,
            crate::ExecutionStatus::Executed | crate::ExecutionStatus::Confirmed
        )
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn execute(
    State(gateway): State<Arc<Gateway>>,
    headers: HeaderMap,
    body: Bytes,
    options: HttpOptions,
) -> Response {
    if !exec_mode_accepted(options, &headers) {
        return exec_mode_refused();
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
    if executed_by_gateway(options, receipt.execution) {
        return (status, [(EXECUTED_BY_HEADER, "gateway")], Json(receipt)).into_response();
    }
    (status, Json(receipt)).into_response()
}

async fn approval_challenge(
    State(gateway): State<Arc<Gateway>>,
    Path((tenant_id, agent_id, request_id)): Path<(uuid::Uuid, uuid::Uuid, uuid::Uuid)>,
    headers: HeaderMap,
    options: HttpOptions,
) -> Response {
    if !exec_mode_accepted(options, &headers) {
        return exec_mode_refused();
    }
    let key = crate::ExecutionKey {
        tenant_id,
        agent_id,
        request_id,
    };
    match tokio::task::spawn_blocking(move || {
        gateway
            .approval_challenge(key)
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
    State(gateway): State<Arc<Gateway>>,
    Path((tenant_id, agent_id, request_id)): Path<(uuid::Uuid, uuid::Uuid, uuid::Uuid)>,
    headers: HeaderMap,
    body: Bytes,
    options: HttpOptions,
) -> Response {
    if !exec_mode_accepted(options, &headers) {
        return exec_mode_refused();
    }
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
        Ok(Ok(resolution)) if executed_by_gateway(options, resolution.receipt.execution) => (
            StatusCode::OK,
            [(EXECUTED_BY_HEADER, "gateway")],
            Json(resolution),
        )
            .into_response(),
        Ok(Ok(resolution)) => (StatusCode::OK, Json(resolution)).into_response(),
        Ok(Err((error, resolution))) => approval_error_response(error, resolution),
        Err(error) => {
            tracing::error!(error = %error, "human approval task failed");
            error_response(StatusCode::SERVICE_UNAVAILABLE, "gateway_unavailable")
        }
    }
}

/// Read-only approval state for one tenant/agent/request key.
async fn approval_status(
    State(gateway): State<Arc<Gateway>>,
    Path((tenant_id, agent_id, request_id)): Path<(uuid::Uuid, uuid::Uuid, uuid::Uuid)>,
    headers: HeaderMap,
    options: HttpOptions,
) -> Response {
    if !exec_mode_accepted(options, &headers) {
        return exec_mode_refused();
    }
    let key = crate::ExecutionKey {
        tenant_id,
        agent_id,
        request_id,
    };
    let result = tokio::task::spawn_blocking(move || {
        let resolution = gateway.approval_resolution(key)?;
        let execution = match resolution {
            crate::ApprovalResolution::Approved => Some(gateway.execution_status(key)?),
            _ => None,
        };
        Ok::<_, GatewayError>((resolution, execution))
    })
    .await;
    match result {
        Ok(Ok((resolution, Some(execution)))) if executed_by_gateway(options, execution) => (
            StatusCode::CONFLICT,
            [(EXECUTED_BY_HEADER, "gateway")],
            Json(ErrorResponse {
                code: "cooperative_exec_rejected",
                resolution: Some(resolution),
            }),
        )
            .into_response(),
        Ok(Ok((resolution, _))) => {
            (StatusCode::OK, Json(ResolutionResponse { resolution })).into_response()
        }
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
) -> (GatewayError, Option<crate::ApprovalResolution>) {
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
    (error, resolution)
}

fn approval_error_response(
    error: GatewayError,
    resolution: Option<crate::ApprovalResolution>,
) -> Response {
    let response = gateway_error_response(error);
    let code = match response.status() {
        StatusCode::CONFLICT => "approval_not_pending",
        StatusCode::GONE => "approval_expired",
        _ => return response,
    };
    match resolution {
        Some(resolution) => (
            response.status(),
            Json(ErrorResponse {
                code,
                resolution: Some(resolution),
            }),
        )
            .into_response(),
        None => response,
    }
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
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use praetore_core::PraetoreError;

    fn headers(values: &[&[u8]]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for value in values {
            map.append(
                EXEC_MODE_HEADER,
                axum::http::HeaderValue::from_bytes(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn exec_mode_header_is_validated_strictly_only_with_gateway_effects() {
        let on = HttpOptions {
            gateway_executes_effects: true,
        };
        assert!(exec_mode_accepted(on, &headers(&[b"gateway"])));
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
            assert!(!exec_mode_accepted(on, &headers(bad)), "{bad:?}");
        }
        let off = HttpOptions::default();
        assert!(exec_mode_accepted(off, &headers(&[])));
        assert_eq!(exec_mode_refused().status(), StatusCode::CONFLICT);
        assert!(exec_mode_accepted(off, &headers(&[b"cooperative"])));
    }

    #[test]
    fn trusted_clock_failure_maps_to_service_unavailable() {
        let response = gateway_error_response(GatewayError::Authorization(
            PraetoreError::TrustedClockUnavailable,
        ));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
