use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use praetore_core::{Action, Authority, canonical::parse_json_rejecting_duplicates};
use praetore_gateway::{DispatchReport, ExecutionKey, action_digest, authority_tenant_id};
use reqwest::{Client, StatusCode as ClientStatus, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs, net::SocketAddr, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, Semaphore, oneshot};
use uuid::Uuid;

const NAMESPACE: &str = "praetore-sandbox";
const MAX_REQUEST_BYTES: usize = 65_536;
const MAX_OUTPUT_BYTES: usize = 65_536;
const MAX_KUBERNETES_RESPONSE_BYTES: usize = 1_048_576;
const RESULT_TOKEN_ANNOTATION: &str = "praetore.io/result-token-sha256";
const EXECUTION_ID_LABEL: &str = "praetore.io/execution-id";
const ACTION_DIGEST_LABEL: &str = "praetore.io/action-digest";
const EXECUTION_KEY_ANNOTATION: &str = "praetore.io/execution-key-sha256";
const ACTION_DIGEST_ANNOTATION: &str = "praetore.io/action-sha256";

#[derive(Clone)]
pub struct SandboxSupervisor {
    kubernetes: KubernetesApi,
    runner_image: String,
    routes: Arc<HashMap<(Uuid, String, String, String), String>>,
    pending: Arc<Mutex<HashMap<ExecutionKey, oneshot::Sender<Value>>>>,
    concurrency: Arc<Semaphore>,
}

#[derive(Clone)]
pub struct KubernetesApi {
    client: Client,
    base_url: Url,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SupervisorConfig {
    schema_version: u8,
    runner_image: String,
    routes: Vec<ProfileRoute>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileRoute {
    tenant_id: Uuid,
    action_type: String,
    target: String,
    capability: String,
    tool_profile: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchRequest {
    schema_version: u8,
    execution_key: ExecutionKey,
    authority: Authority,
    action: Action,
    action_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultRequest {
    schema_version: u8,
    execution_key: ExecutionKey,
    action_digest: String,
    result_token: String,
    output: Value,
}

#[derive(Serialize)]
struct Invocation<'a> {
    schema_version: u8,
    execution_key: ExecutionKey,
    action_digest: &'a str,
    tool_profile: &'a str,
    action: &'a Action,
}

struct ExecutionMetadata<'a> {
    execution_id: &'a str,
    action_prefix: &'a str,
    execution_key_hash: &'a str,
    action_hash: &'a str,
    profile: &'a str,
    result_token_hash: &'a str,
}

#[derive(Debug)]
enum KubernetesError {
    Conflict,
    NotFound,
    Unavailable,
    InvalidResponse,
}

impl KubernetesApi {
    pub fn in_cluster() -> Result<Self, Box<dyn std::error::Error>> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT_HTTPS")
            .or_else(|_| std::env::var("KUBERNETES_SERVICE_PORT"))?;
        let base_url = Url::parse(&format!("https://{host}:{port}/"))?;
        let token = read_small_secret(
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            16_384,
        )?;
        if std::str::from_utf8(&token)?.trim().is_empty() {
            return Err("Kubernetes service account token is empty".into());
        }
        let ca_pem = read_small_secret(
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            1_048_576,
        )?;
        let ca = reqwest::Certificate::from_pem(&ca_pem)?;
        let client = Client::builder()
            .https_only(true)
            .add_root_certificate(ca)
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self { client, base_url })
    }

    fn authenticate(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, KubernetesError> {
        let token = read_small_secret(
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            16_384,
        )
        .map_err(|_| KubernetesError::Unavailable)?;
        let token = std::str::from_utf8(&token)
            .map_err(|_| KubernetesError::Unavailable)?
            .trim();
        if token.is_empty() {
            return Err(KubernetesError::Unavailable);
        }
        Ok(request.bearer_auth(token))
    }

    async fn create_job(&self, job: &Value) -> Result<Value, KubernetesError> {
        let url = self
            .base_url
            .join(&format!("apis/batch/v1/namespaces/{NAMESPACE}/jobs"))
            .map_err(|_| KubernetesError::Unavailable)?;
        self.request_json(
            self.authenticate(self.client.post(url))?
                .header(CONTENT_TYPE, "application/json")
                .json(job),
        )
        .await
    }

    async fn create_secret(&self, secret: &Value) -> Result<Value, KubernetesError> {
        let url = self
            .base_url
            .join(&format!("api/v1/namespaces/{NAMESPACE}/secrets"))
            .map_err(|_| KubernetesError::Unavailable)?;
        self.request_json(
            self.authenticate(self.client.post(url))?
                .header(CONTENT_TYPE, "application/json")
                .json(secret),
        )
        .await
    }

    async fn create_execution_claim(&self, claim: &Value) -> Result<Value, KubernetesError> {
        let url = self
            .base_url
            .join(&format!("api/v1/namespaces/{NAMESPACE}/configmaps"))
            .map_err(|_| KubernetesError::Unavailable)?;
        self.request_json(
            self.authenticate(self.client.post(url))?
                .header(CONTENT_TYPE, "application/json")
                .json(claim),
        )
        .await
    }

    async fn get_job(&self, name: &str) -> Result<Value, KubernetesError> {
        let url = self
            .base_url
            .join(&format!("apis/batch/v1/namespaces/{NAMESPACE}/jobs/{name}"))
            .map_err(|_| KubernetesError::Unavailable)?;
        self.request_json(self.authenticate(self.client.get(url))?)
            .await
    }

    async fn unsuspend_job(&self, name: &str) -> Result<(), KubernetesError> {
        let url = self
            .base_url
            .join(&format!("apis/batch/v1/namespaces/{NAMESPACE}/jobs/{name}"))
            .map_err(|_| KubernetesError::Unavailable)?;
        let response = self
            .authenticate(self.client.patch(url))?
            .header("Content-Type", "application/merge-patch+json")
            .body(r#"{"spec":{"suspend":false}}"#)
            .send()
            .await
            .map_err(|_| KubernetesError::Unavailable)?;
        match response.status() {
            ClientStatus::OK => Ok(()),
            ClientStatus::NOT_FOUND => Err(KubernetesError::NotFound),
            ClientStatus::CONFLICT => Err(KubernetesError::Conflict),
            status if status.is_success() => Ok(()),
            _ => Err(KubernetesError::Unavailable),
        }
    }

    async fn delete_suspended_job(&self, name: &str, uid: &str) -> Result<(), KubernetesError> {
        let url = self
            .base_url
            .join(&format!("apis/batch/v1/namespaces/{NAMESPACE}/jobs/{name}"))
            .map_err(|_| KubernetesError::Unavailable)?;
        let response = self
            .authenticate(self.client.delete(url))?
            .header(CONTENT_TYPE, "application/json")
            .json(&json!({
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "preconditions": {"uid": uid},
                "propagationPolicy": "Foreground"
            }))
            .send()
            .await
            .map_err(|_| KubernetesError::Unavailable)?;
        if response.status().is_success() || response.status() == ClientStatus::NOT_FOUND {
            Ok(())
        } else {
            Err(KubernetesError::Unavailable)
        }
    }

    async fn request_json(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<Value, KubernetesError> {
        let response = request
            .send()
            .await
            .map_err(|_| KubernetesError::Unavailable)?;
        match response.status() {
            ClientStatus::CONFLICT => return Err(KubernetesError::Conflict),
            ClientStatus::NOT_FOUND => return Err(KubernetesError::NotFound),
            status if !status.is_success() => return Err(KubernetesError::Unavailable),
            _ => {}
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_KUBERNETES_RESPONSE_BYTES as u64)
        {
            return Err(KubernetesError::InvalidResponse);
        }
        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| KubernetesError::Unavailable)?
        {
            if body.len().saturating_add(chunk.len()) > MAX_KUBERNETES_RESPONSE_BYTES {
                return Err(KubernetesError::InvalidResponse);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| KubernetesError::InvalidResponse)
    }
}

impl SandboxSupervisor {
    pub fn new(
        kubernetes: KubernetesApi,
        config_json: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if config_json.len() > MAX_REQUEST_BYTES {
            return Err("sandbox supervisor configuration exceeds the size limit".into());
        }
        let config_value = parse_json_rejecting_duplicates(config_json)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let config: SupervisorConfig = serde_json::from_value(config_value)?;
        if config.schema_version != 1
            || config.routes.is_empty()
            || config.routes.len() > 128
            || !valid_runner_image(&config.runner_image)
        {
            return Err("sandbox supervisor configuration has an unsupported version, image, or route count".into());
        }
        let mut routes = HashMap::with_capacity(config.routes.len());
        for route in config.routes {
            if route.tenant_id.is_nil()
                || !valid_profile(&route.tool_profile)
                || !valid_route_text(&route.action_type)
                || !valid_route_text(&route.target)
                || !valid_route_text(&route.capability)
            {
                return Err("sandbox supervisor route contains invalid fields".into());
            }
            let key = (
                route.tenant_id,
                route.action_type,
                route.target,
                route.capability,
            );
            if routes.insert(key, route.tool_profile).is_some() {
                return Err("sandbox supervisor configuration contains duplicate routes".into());
            }
        }
        Ok(Self {
            kubernetes,
            runner_image: config.runner_image,
            routes: Arc::new(routes),
            pending: Arc::new(Mutex::new(HashMap::new())),
            concurrency: Arc::new(Semaphore::new(16)),
        })
    }

    pub fn gateway_router(self) -> Router {
        Router::new()
            .route("/v1/executions", post(dispatch))
            .route("/v1/executions/{tenant}/{agent}/{request}", get(reconcile))
            .route("/healthz", get(health))
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
            .with_state(self)
    }

    pub fn worker_router(self) -> Router {
        Router::new()
            .route("/v1/results", post(submit_result))
            .layer(DefaultBodyLimit::max(MAX_OUTPUT_BYTES + 4096))
            .with_state(self)
    }
}

async fn dispatch(
    State(supervisor): State<SandboxSupervisor>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<DispatchReport>, ApiError> {
    if !is_json_content_type(&headers) {
        return Err(ApiError::bad_request());
    }
    let request: DispatchRequest = parse_strict_json(&body)?;
    let _permit = supervisor
        .concurrency
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::busy())?;
    let idempotency = headers
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok());
    if idempotency.is_none_or(|value| !valid_dispatch_request(&request, value)) {
        return Err(ApiError::bad_request());
    }
    let tenant_id = request.execution_key.tenant_id;
    let target = request
        .action
        .target
        .as_deref()
        .ok_or_else(ApiError::bad_request)?;
    let capability = request
        .action
        .capability
        .as_deref()
        .ok_or_else(ApiError::bad_request)?;
    let profile = supervisor
        .routes
        .get(&(
            tenant_id,
            request.action.action_type.clone(),
            target.to_owned(),
            capability.to_owned(),
        ))
        .ok_or_else(ApiError::forbidden)?
        .clone();
    let execution_id = execution_id(request.execution_key);
    let action_prefix = request
        .action_digest
        .get(..52)
        .ok_or_else(ApiError::bad_request)?;
    let job_name = format!("tool-{execution_id}");
    let secret_name = format!("inv-{execution_id}");
    let result_token = Uuid::new_v4().to_string();
    let result_token_hash = hex::encode(Sha256::digest(result_token.as_bytes()));
    let action_digest_full = request.action_digest.clone();
    let execution_key_full = sha256_hex(idempotency_key(request.execution_key).as_bytes());
    let execution_metadata = ExecutionMetadata {
        execution_id: &execution_id,
        action_prefix,
        execution_key_hash: &execution_key_full,
        action_hash: &action_digest_full,
        profile: &profile,
        result_token_hash: &result_token_hash,
    };
    let invocation = serde_json::to_vec(&Invocation {
        schema_version: 1,
        execution_key: request.execution_key,
        action_digest: &request.action_digest,
        tool_profile: &profile,
        action: &request.action,
    })
    .map_err(|_| ApiError::bad_request())?;
    if invocation.len() > MAX_REQUEST_BYTES {
        return Err(ApiError::bad_request());
    }
    let claim = build_execution_claim(&execution_metadata);
    supervisor
        .kubernetes
        .create_execution_claim(&claim)
        .await
        .map_err(|error| {
            tracing::warn!(?error, %execution_id, "failed to reserve sandbox execution identity");
            match error {
                KubernetesError::Conflict => ApiError::conflict(),
                _ => ApiError::unavailable(),
            }
        })?;
    let job = build_job(&job_name, &execution_metadata, &supervisor.runner_image);
    let created_job = match supervisor.kubernetes.create_job(&job).await {
        Ok(job) => job,
        Err(error) => {
            tracing::warn!(?error, %execution_id, "failed to create sandbox Job");
            return Err(match error {
                KubernetesError::Conflict => ApiError::conflict(),
                _ => ApiError::unavailable(),
            });
        }
    };
    let job_uid = created_job
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .ok_or_else(ApiError::unavailable)?;

    let secret = build_invocation_secret(
        &secret_name,
        &execution_metadata,
        job_uid,
        &invocation,
        &result_token,
    );
    if let Err(secret_error) = supervisor.kubernetes.create_secret(&secret).await {
        tracing::warn!(?secret_error, %execution_id, "failed to create invocation Secret");
        if let Err(cleanup_error) = supervisor
            .kubernetes
            .delete_suspended_job(&job_name, job_uid)
            .await
        {
            tracing::error!(
                ?cleanup_error,
                %execution_id,
                "failed to delete suspended sandbox Job after Secret creation failed"
            );
            return Err(ApiError::unavailable());
        }
        return Err(ApiError::unavailable());
    }

    let (sender, receiver) = oneshot::channel();
    supervisor
        .pending
        .lock()
        .await
        .insert(request.execution_key, sender);
    if supervisor
        .kubernetes
        .unsuspend_job(&job_name)
        .await
        .is_err()
    {
        supervisor
            .pending
            .lock()
            .await
            .remove(&request.execution_key);
        tracing::warn!(%execution_id, "failed to start sandbox Job; execution outcome may be unknown");
        return Err(ApiError::unavailable());
    }
    let output = match tokio::time::timeout(Duration::from_secs(120), receiver).await {
        Ok(Ok(output)) => output,
        Ok(Err(_)) => return Err(ApiError::unavailable()),
        Err(_) => {
            supervisor
                .pending
                .lock()
                .await
                .remove(&request.execution_key);
            tracing::warn!(%execution_id, "sandbox execution callback timed out");
            return Err(ApiError::timeout());
        }
    };
    Ok(Json(DispatchReport::Executed(output)))
}

fn valid_dispatch_request(request: &DispatchRequest, idempotency: &str) -> bool {
    request.schema_version == 1
        && request.authority.validate().is_ok()
        && request.action.validate().is_ok()
        && authority_tenant_id(&request.authority) == Some(request.execution_key.tenant_id)
        && *request.authority.subject.as_uuid() == request.execution_key.agent_id
        && request
            .action
            .capability
            .as_ref()
            .is_some_and(|capability| request.authority.capabilities.contains(capability))
        && action_digest(&request.action).is_ok_and(|digest| digest == request.action_digest)
        && idempotency == idempotency_key(request.execution_key)
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn parse_strict_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    let body = std::str::from_utf8(body).map_err(|_| ApiError::bad_request())?;
    let value = parse_json_rejecting_duplicates(body).map_err(|_| ApiError::bad_request())?;
    serde_json::from_value(value).map_err(|_| ApiError::bad_request())
}

async fn submit_result(
    State(supervisor): State<SandboxSupervisor>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    if !is_json_content_type(&headers) {
        return Err(ApiError::bad_request());
    }
    let result: ResultRequest = parse_strict_json(&body)?;
    if result.schema_version != 1
        || result.result_token.is_empty()
        || result.result_token.len() > 128
        || result.output.to_string().len() > MAX_OUTPUT_BYTES
        || !valid_digest(&result.action_digest)
    {
        return Err(ApiError::bad_request());
    }
    let execution_id = execution_id(result.execution_key);
    let job = supervisor
        .kubernetes
        .get_job(&format!("tool-{execution_id}"))
        .await
        .map_err(|_| ApiError::unavailable())?;
    let annotations = job
        .pointer("/metadata/annotations")
        .ok_or_else(ApiError::forbidden)?;
    let expected_token_hash = annotations
        .get(RESULT_TOKEN_ANNOTATION)
        .and_then(Value::as_str)
        .ok_or_else(ApiError::forbidden)?;
    let expected_action_digest = annotations
        .get(ACTION_DIGEST_ANNOTATION)
        .and_then(Value::as_str)
        .ok_or_else(ApiError::forbidden)?;
    let expected_execution_key = annotations
        .get(EXECUTION_KEY_ANNOTATION)
        .and_then(Value::as_str)
        .ok_or_else(ApiError::forbidden)?;
    let supplied_token_hash = sha256_hex(result.result_token.as_bytes());
    let expected_execution_key_hash = sha256_hex(idempotency_key(result.execution_key).as_bytes());
    if !constant_time_digest_eq(&supplied_token_hash, expected_token_hash)
        || !constant_time_digest_eq(&result.action_digest, expected_action_digest)
        || !constant_time_digest_eq(expected_execution_key, &expected_execution_key_hash)
    {
        return Err(ApiError::forbidden());
    }
    let sender = supervisor
        .pending
        .lock()
        .await
        .remove(&result.execution_key)
        .ok_or_else(ApiError::conflict)?;
    sender
        .send(result.output)
        .map_err(|_| ApiError::conflict())?;
    Ok(StatusCode::NO_CONTENT)
}

async fn reconcile(
    State(_supervisor): State<SandboxSupervisor>,
    Path((tenant, agent, request)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let digest = headers
        .get("X-Praetore-Action-Digest")
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_digest(value))
        .ok_or_else(ApiError::bad_request)?;
    Ok(Json(json!({
        "schema_version": 1,
        "execution_key": {
            "tenant_id": tenant,
            "agent_id": agent,
            "request_id": request
        },
        "action_digest": digest,
        "status": "unknown",
        "output": null
    })))
}

async fn health() -> StatusCode {
    StatusCode::OK
}

#[derive(Clone)]
struct ApiError {
    status: StatusCode,
    message: &'static str,
}

impl ApiError {
    fn bad_request() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: "invalid sandbox request",
        }
    }

    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: "sandbox request is not authorized",
        }
    }

    fn conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: "execution identity already exists or has completed",
        }
    }

    fn unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "sandbox execution unavailable",
        }
    }

    fn busy() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "sandbox capacity is exhausted",
        }
    }

    fn timeout() -> Self {
        Self {
            status: StatusCode::GATEWAY_TIMEOUT,
            message: "sandbox execution outcome is unknown",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            [(CONTENT_TYPE, "application/json")],
            Json(json!({"error": self.message})),
        )
            .into_response()
    }
}

fn build_job(name: &str, metadata: &ExecutionMetadata<'_>, runner_image: &str) -> Value {
    let labels = json!({
        "praetore.io/component": "tool-invocation",
        EXECUTION_ID_LABEL: metadata.execution_id,
        ACTION_DIGEST_LABEL: metadata.action_prefix,
        "praetore.io/tool-profile": metadata.profile
    });
    let annotations = json!({
        EXECUTION_KEY_ANNOTATION: metadata.execution_key_hash,
        ACTION_DIGEST_ANNOTATION: metadata.action_hash,
        RESULT_TOKEN_ANNOTATION: metadata.result_token_hash
    });
    json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": labels,
            "annotations": annotations
        },
        "spec": {
            "suspend": true,
            "completions": 1,
            "parallelism": 1,
            "backoffLimit": 0,
            "activeDeadlineSeconds": 120,
            "ttlSecondsAfterFinished": 120,
            "template": {
                "metadata": {"labels": labels, "annotations": annotations},
                "spec": {
                    "runtimeClassName": "praetore-firecracker",
                    "restartPolicy": "Never",
                    "terminationGracePeriodSeconds": 5,
                    "automountServiceAccountToken": false,
                    "serviceAccountName": "praetore-sandbox-worker",
                    "enableServiceLinks": false,
                    "hostNetwork": false,
                    "hostPID": false,
                    "hostIPC": false,
                    "securityContext": {
                        "runAsNonRoot": true,
                        "runAsUser": 10001,
                        "runAsGroup": 10001,
                        "fsGroup": 10001,
                        "fsGroupChangePolicy": "OnRootMismatch",
                        "seccompProfile": {"type": "RuntimeDefault"}
                    },
                    "containers": [{
                        "name": "tool-runner",
                        "image": runner_image,
                        "imagePullPolicy": "Always",
                        "command": ["/usr/local/bin/praetore-tool-runner"],
                        "args": ["--invocation", "/run/praetore/invocation/invocation.json"],
                        "env": [
                            {"name": "PRAETORE_RESULT_URL", "value": "https://praetore-sandbox-supervisor.praetore-sandbox.svc.cluster.local:8444/v1/results"},
                            {"name": "PRAETORE_RESULT_TOKEN_FILE", "value": "/run/praetore/invocation/result-token"},
                            {"name": "PRAETORE_RESULT_CA_FILE", "value": "/run/praetore/supervisor-ca/ca.crt"},
                            {"name": "HTTPS_PROXY", "value": "http://egress-proxy.praetore-egress.svc.cluster.local:3128"},
                            {"name": "HTTP_PROXY", "value": "http://egress-proxy.praetore-egress.svc.cluster.local:3128"},
                            {"name": "NO_PROXY", "value": "praetore-sandbox-supervisor.praetore-sandbox.svc.cluster.local"}
                        ],
                        "resources": {
                            "requests": {"cpu": "100m", "memory": "128Mi", "ephemeral-storage": "64Mi"},
                            "limits": {"cpu": "1", "memory": "512Mi", "ephemeral-storage": "128Mi"}
                        },
                        "securityContext": {
                            "runAsNonRoot": true,
                            "runAsUser": 10001,
                            "runAsGroup": 10001,
                            "allowPrivilegeEscalation": false,
                            "readOnlyRootFilesystem": true,
                            "capabilities": {"drop": ["ALL"]}
                        },
                        "volumeMounts": [
                            {"name": "invocation", "mountPath": "/run/praetore/invocation", "readOnly": true},
                            {"name": "tmp", "mountPath": "/tmp"},
                            {"name": "supervisor-ca", "mountPath": "/run/praetore/supervisor-ca", "readOnly": true}
                        ]
                    }],
                    "volumes": [
                        {"name": "invocation", "secret": {"secretName": format!("inv-{}", metadata.execution_id), "defaultMode": 288}},
                        {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}},
                        {"name": "supervisor-ca", "configMap": {"name": "praetore-sandbox-supervisor-ca", "items": [{"key": "ca.crt", "path": "ca.crt"}]}}
                    ]
                }
            }
        }
    })
}

fn build_invocation_secret(
    name: &str,
    metadata: &ExecutionMetadata<'_>,
    job_uid: &str,
    invocation: &[u8],
    result_token: &str,
) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {
                "praetore.io/component": "invocation-input",
                EXECUTION_ID_LABEL: metadata.execution_id,
                ACTION_DIGEST_LABEL: metadata.action_prefix
            },
            "annotations": {
                EXECUTION_KEY_ANNOTATION: metadata.execution_key_hash,
                ACTION_DIGEST_ANNOTATION: metadata.action_hash
            },
            "ownerReferences": [{
                "apiVersion": "batch/v1",
                "kind": "Job",
                "name": format!("tool-{}", metadata.execution_id),
                "uid": job_uid,
                "controller": true,
                "blockOwnerDeletion": false
            }]
        },
        "type": "Opaque",
        "immutable": true,
        "data": {
            "invocation.json": BASE64.encode(invocation),
            "result-token": BASE64.encode(result_token)
        }
    })
}

fn build_execution_claim(metadata: &ExecutionMetadata<'_>) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": format!("claim-{}", metadata.execution_id),
            "namespace": NAMESPACE,
            "labels": {
                "praetore.io/component": "execution-claim",
                EXECUTION_ID_LABEL: metadata.execution_id,
                ACTION_DIGEST_LABEL: metadata.action_prefix
            },
            "annotations": {
                EXECUTION_KEY_ANNOTATION: metadata.execution_key_hash,
                ACTION_DIGEST_ANNOTATION: metadata.action_hash
            }
        },
        "immutable": true
    })
}

fn execution_id(key: ExecutionKey) -> String {
    sha256_hex(idempotency_key(key).as_bytes())[..52].to_owned()
}

fn idempotency_key(key: ExecutionKey) -> String {
    format!("{}:{}:{}", key.tenant_id, key.agent_id, key.request_id)
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(is_lowercase_hex)
}

fn constant_time_digest_eq(left: &str, right: &str) -> bool {
    if !valid_digest(left) || !valid_digest(right) {
        return false;
    }
    let Ok(left) = hex::decode(left) else {
        return false;
    };
    let Ok(right) = hex::decode(right) else {
        return false;
    };
    bool::from(left.as_slice().ct_eq(right.as_slice()))
}

fn is_lowercase_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn valid_profile(value: &str) -> bool {
    matches!(
        value.as_bytes().first(),
        Some(first)
            if first.is_ascii_lowercase()
                && value.len() <= 63
                && value.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                })
                && value.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
    )
}

fn valid_route_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value == value.trim()
        && value.len() <= 256
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_runner_image(value: &str) -> bool {
    let Some((repository, digest)) = value.split_once("@sha256:") else {
        return false;
    };
    repository == "registry.example.com/praetore/tool-runner"
        && digest.len() == 64
        && digest.bytes().all(is_lowercase_hex)
}

fn read_small_secret(path: &str, max_bytes: usize) -> Result<Vec<u8>, std::io::Error> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes as u64 {
        return Err(std::io::Error::other("secret file size is invalid"));
    }
    fs::read(path)
}

pub fn load_server_tls(
    certificate_path: &str,
    private_key_path: &str,
    client_ca_path: &str,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| std::io::Error::other("failed to install the ring crypto provider"))?;
    }
    let certificates = rustls_pemfile::certs(&mut std::io::BufReader::new(std::io::Cursor::new(
        read_small_secret(certificate_path, 1_048_576)?,
    )))
    .collect::<Result<Vec<_>, _>>()?;
    let private_key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::io::Cursor::new(read_small_secret(private_key_path, 1_048_576)?),
    ))?
    .ok_or("supervisor TLS private key is missing")?;
    let ca_certificates = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::io::Cursor::new(read_small_secret(client_ca_path, 1_048_576)?),
    ))
    .collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() || ca_certificates.is_empty() {
        return Err("supervisor TLS certificate or client CA is empty".into());
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in ca_certificates {
        roots.add(certificate)?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, private_key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub fn load_worker_tls(
    certificate_path: &str,
    private_key_path: &str,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let certificates = rustls_pemfile::certs(&mut std::io::BufReader::new(std::io::Cursor::new(
        read_small_secret(certificate_path, 1_048_576)?,
    )))
    .collect::<Result<Vec<_>, _>>()?;
    let private_key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::io::Cursor::new(read_small_secret(private_key_path, 1_048_576)?),
    ))?
    .ok_or("supervisor TLS private key is missing")?;
    if certificates.is_empty() {
        return Err("supervisor TLS certificate is empty".into());
    }
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub async fn serve_tls(
    address: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    router: Router,
) -> Result<(), Box<dyn std::error::Error>> {
    use hyper::{server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    use tokio_rustls::TlsAcceptor;
    use tower::Service;

    let listener = tokio::net::TcpListener::bind(address).await?;
    let acceptor = TlsAcceptor::from(tls);
    let connections = Arc::new(Semaphore::new(128));
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = router.clone();
        let permit = connections
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "TLS connection limiter is closed")?;
        tokio::spawn(async move {
            let stream =
                match tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        tracing::debug!(%error, "rejected sandbox TLS connection");
                        return;
                    }
                    Err(_) => {
                        tracing::debug!("sandbox TLS handshake timed out");
                        return;
                    }
                };
            let io = TokioIo::new(stream);
            let service = service_fn(move |request| {
                let mut app = app.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let request =
                        axum::http::Request::from_parts(parts, axum::body::Body::new(body));
                    app.call(request).await.map_err(|never| match never {})
                }
            });
            let connection = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(io, service)
                .with_upgrades();
            match tokio::time::timeout(Duration::from_secs(145), connection).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::debug!(%error, "sandbox HTTP connection closed with an error");
                }
                Err(_) => {
                    tracing::debug!("sandbox HTTP connection timed out");
                }
            }
            drop(permit);
        });
    }
}

pub fn parse_listen_address(value: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let address = value.parse::<SocketAddr>()?;
    if address.port() == 0 {
        return Err("supervisor listen port must not be zero".into());
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use praetore_core::{AgentId, authority::AuthorityConstraint};

    #[test]
    fn execution_identity_is_stable_and_name_safe() {
        let key = ExecutionKey {
            tenant_id: Uuid::from_u128(1),
            agent_id: Uuid::from_u128(2),
            request_id: Uuid::from_u128(3),
        };
        assert_eq!(execution_id(key), execution_id(key));
        assert_eq!(execution_id(key).len(), 52);
        assert!(execution_id(key).bytes().all(is_lowercase_hex));
    }

    #[test]
    fn job_and_secret_bind_exact_action_and_execution_digests() {
        let key = ExecutionKey {
            tenant_id: Uuid::from_u128(1),
            agent_id: Uuid::from_u128(2),
            request_id: Uuid::from_u128(3),
        };
        let id = execution_id(key);
        let action_hash = "a".repeat(64);
        let execution_key_hash = "b".repeat(64);
        let result_token_hash = "d".repeat(64);
        let runner_image = format!(
            "registry.example.com/praetore/tool-runner@sha256:{}",
            "c".repeat(64)
        );
        let metadata = ExecutionMetadata {
            execution_id: &id,
            action_prefix: &action_hash[..52],
            execution_key_hash: &execution_key_hash,
            action_hash: &action_hash,
            profile: "orders",
            result_token_hash: &result_token_hash,
        };
        let job = build_job(&format!("tool-{id}"), &metadata, &runner_image);
        let claim = build_execution_claim(&metadata);
        assert_eq!(job["spec"]["suspend"], true);
        assert_eq!(claim["metadata"]["name"], format!("claim-{id}"));
        assert_eq!(claim["immutable"], true);
        assert!(claim.get("data").is_none());
        assert!(claim.get("binaryData").is_none());
        assert_eq!(
            claim["metadata"]["annotations"][ACTION_DIGEST_ANNOTATION],
            action_hash
        );
        assert_eq!(job["metadata"]["name"], format!("tool-{id}"));
        assert_eq!(
            job["metadata"]["annotations"][ACTION_DIGEST_ANNOTATION],
            action_hash
        );
        assert_eq!(
            job["spec"]["template"]["spec"]["automountServiceAccountToken"],
            false
        );
        assert_eq!(
            job["spec"]["template"]["spec"]["containers"][0]["env"][0]["value"],
            "https://praetore-sandbox-supervisor.praetore-sandbox.svc.cluster.local:8444/v1/results"
        );
        assert_eq!(
            job["spec"]["template"]["spec"]["containers"][0]["env"]
                .as_array()
                .unwrap()
                .len(),
            6
        );
        assert_eq!(
            job["spec"]["template"]["spec"]["volumes"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(job["metadata"]["labels"][EXECUTION_ID_LABEL], id);
        let secret = build_invocation_secret(
            &format!("inv-{id}"),
            &metadata,
            "job-uid",
            br#"{"schema_version":1}"#,
            "one-time-result-token",
        );
        assert_eq!(secret["immutable"], true);
        assert_eq!(secret["metadata"]["ownerReferences"][0]["uid"], "job-uid");
        assert_eq!(
            secret["metadata"]["annotations"][EXECUTION_KEY_ANNOTATION],
            execution_key_hash
        );
        assert!(secret["data"]["result-token"].as_str().is_some());
        assert_eq!(
            BASE64
                .decode(secret["data"]["result-token"].as_str().unwrap())
                .unwrap(),
            b"one-time-result-token"
        );
    }

    #[test]
    fn route_and_runner_configuration_are_strict() {
        assert!(valid_profile("tool-a"));
        assert!(!valid_profile("-tool"));
        assert!(!valid_profile("Tool"));
        assert!(valid_runner_image(&format!(
            "registry.example.com/praetore/tool-runner@sha256:{}",
            "0".repeat(64)
        )));
        assert!(!valid_runner_image("registry.other/tool:latest"));
        assert!(valid_digest(&"a".repeat(64)));
        assert!(!valid_digest(&"z".repeat(64)));
    }

    #[test]
    fn callback_digest_comparison_accepts_only_equal_canonical_sha256_values() {
        let digest = "a".repeat(64);
        assert!(constant_time_digest_eq(&digest, &digest));

        let mut mismatch = digest.clone().into_bytes();
        mismatch[0] = b'b';
        let mismatch = String::from_utf8(mismatch).unwrap();
        assert!(!constant_time_digest_eq(&digest, &mismatch));
        assert!(!constant_time_digest_eq(&digest, &digest.to_uppercase()));
        assert!(!constant_time_digest_eq(&digest, "not-a-digest"));
    }

    #[test]
    fn strict_supervisor_json_rejects_duplicate_keys_inside_nested_values() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Callback {
            output: Value,
        }

        assert!(
            parse_strict_json::<Callback>(br#"{"output":{"status":"safe","status":"overridden"}}"#)
                .is_err()
        );
        assert!(
            parse_strict_json::<Callback>(br#"{"output":{"status":"safe"}}"#)
                .is_ok_and(|callback| callback.output["status"] == "safe")
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            "application/json; charset=utf-8".parse().unwrap(),
        );
        assert!(is_json_content_type(&headers));
        headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());
        assert!(!is_json_content_type(&headers));
    }

    #[test]
    fn supervisor_config_requires_a_digest_pinned_runner_and_unique_routes() {
        let kubernetes = || KubernetesApi {
            client: Client::new(),
            base_url: Url::parse("https://kubernetes.default.svc/").unwrap(),
        };
        let route = json!({
            "tenant_id": Uuid::from_u128(1),
            "action_type": "orders:create",
            "target": "orders-api",
            "capability": "orders:write",
            "tool_profile": "orders-create"
        });
        let valid = json!({
            "schema_version": 1,
            "runner_image": format!(
                "registry.example.com/praetore/tool-runner@sha256:{}",
                "a".repeat(64)
            ),
            "routes": [route]
        });
        assert!(SandboxSupervisor::new(kubernetes(), &valid.to_string()).is_ok());

        let duplicate_root_key = valid.to_string().replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        assert!(SandboxSupervisor::new(kubernetes(), &duplicate_root_key).is_err());

        let duplicate_route_key = valid.to_string().replacen(
            "\"action_type\":\"orders:create\"",
            "\"action_type\":\"orders:create\",\"action_type\":\"orders:delete\"",
            1,
        );
        assert!(SandboxSupervisor::new(kubernetes(), &duplicate_route_key).is_err());

        let invalid_image = json!({
            "schema_version": 1,
            "runner_image": "registry.example.com/praetore/tool-runner:latest",
            "routes": [route.clone()]
        });
        assert!(SandboxSupervisor::new(kubernetes(), &invalid_image.to_string()).is_err());

        let duplicate_route = json!({
            "schema_version": 1,
            "runner_image": format!(
                "registry.example.com/praetore/tool-runner@sha256:{}",
                "a".repeat(64)
            ),
            "routes": [route.clone(), route]
        });
        assert!(SandboxSupervisor::new(kubernetes(), &duplicate_route.to_string()).is_err());
    }

    #[test]
    fn dispatch_request_must_bind_key_authority_action_and_header() {
        let tenant_id = Uuid::from_u128(10);
        let agent_id = AgentId::new();
        let key = ExecutionKey {
            tenant_id,
            agent_id: *agent_id.as_uuid(),
            request_id: Uuid::from_u128(12),
        };
        let mut authority = Authority::new(agent_id, "test-issuer", vec!["orders:write".into()]);
        authority.constraints = vec![AuthorityConstraint::new("tenant_id", tenant_id.to_string())];
        let action = Action::new("orders:create", Some("orders-api".into()), json!({"id": 3}))
            .unwrap()
            .with_capability("orders:write");
        let request = DispatchRequest {
            schema_version: 1,
            execution_key: key,
            authority,
            action_digest: action_digest(&action).unwrap(),
            action,
        };
        assert!(valid_dispatch_request(&request, &idempotency_key(key)));
        assert!(!valid_dispatch_request(&request, "different-key"));

        let mut malformed_action = request.action.clone();
        malformed_action.action_type = " orders:create".into();
        let malformed_action_request = DispatchRequest {
            action_digest: action_digest(&malformed_action).unwrap(),
            action: malformed_action,
            ..request.clone()
        };
        assert!(!valid_dispatch_request(
            &malformed_action_request,
            &idempotency_key(key)
        ));

        let mut malformed_authority = request.authority.clone();
        malformed_authority.capabilities.push("orders:write".into());
        let malformed_authority_request = DispatchRequest {
            authority: malformed_authority,
            ..request.clone()
        };
        assert!(!valid_dispatch_request(
            &malformed_authority_request,
            &idempotency_key(key)
        ));

        let mut mismatched_key = key;
        mismatched_key.agent_id = Uuid::from_u128(99);
        let mismatched = DispatchRequest {
            execution_key: mismatched_key,
            ..request
        };
        assert!(!valid_dispatch_request(
            &mismatched,
            &idempotency_key(mismatched_key)
        ));
    }
}
