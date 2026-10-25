use crate::{AuthorizationStatus, Gateway, GatewayError, JournalError};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
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
}

/// Creates the local HTTP API for signed tool authorization requests.
///
/// `POST /v1/execute` accepts the serialized `AuthorizationRequest`. The
/// gateway returns its signed receipt for every completed policy decision,
/// including denials and approval requirements. Request bodies are size
/// limited and parsed through PRÆTORE's duplicate-key rejecting parser.
pub fn router(gateway: Arc<Gateway>) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/execute", post(execute))
        .route(
            "/v1/approvals/{agent_id}/{request_id}",
            get(approval_challenge).post(resolve_approval),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(gateway)
}

/// Runs the service on IPv4 loopback only; this endpoint has no network
/// authentication or TLS and must not be exposed beyond local development.
pub async fn serve_local(port: u16, gateway: Arc<Gateway>) -> io::Result<()> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(address).await?;
    axum::serve(listener, router(gateway)).await
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn execute(State(gateway): State<Arc<Gateway>>, body: Bytes) -> Response {
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
    (status, Json(receipt)).into_response()
}

async fn approval_challenge(
    State(gateway): State<Arc<Gateway>>,
    Path((agent_id, request_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Response {
    let key = crate::ExecutionKey {
        agent_id,
        request_id,
    };
    match tokio::task::spawn_blocking(move || gateway.approval_challenge(key)).await {
        Ok(Ok(challenge)) => (StatusCode::OK, Json(challenge)).into_response(),
        Ok(Err(error)) => gateway_error_response(error),
        Err(error) => {
            tracing::error!(error = %error, "approval challenge task failed");
            error_response(StatusCode::SERVICE_UNAVAILABLE, "gateway_unavailable")
        }
    }
}

async fn resolve_approval(
    State(gateway): State<Arc<Gateway>>,
    Path((agent_id, request_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    body: Bytes,
) -> Response {
    let decision = match std::str::from_utf8(&body)
        .ok()
        .and_then(|json| crate::HumanApprovalDecision::from_json(json).ok())
    {
        Some(decision) => decision,
        None => return error_response(StatusCode::BAD_REQUEST, "invalid_approval_decision"),
    };
    if decision.challenge.agent_id != agent_id || decision.challenge.request_id != request_id {
        return error_response(StatusCode::BAD_REQUEST, "approval_challenge_mismatch");
    }
    match tokio::task::spawn_blocking(move || gateway.resolve_human_approval(decision)).await {
        Ok(Ok(resolution)) => (StatusCode::OK, Json(resolution)).into_response(),
        Ok(Err(error)) => gateway_error_response(error),
        Err(error) => {
            tracing::error!(error = %error, "human approval task failed");
            error_response(StatusCode::SERVICE_UNAVAILABLE, "gateway_unavailable")
        }
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
            | ErrorKind::FreshnessLeaseTooLong => {
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
        GatewayError::ExecutionNotFound(_) => {
            error_response(StatusCode::NOT_FOUND, "execution_not_found")
        }
        GatewayError::Approval(crate::ApprovalError::InvalidSignature) => {
            error_response(StatusCode::FORBIDDEN, "invalid_approval_signature")
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
    (status, Json(ErrorResponse { code })).into_response()
}
