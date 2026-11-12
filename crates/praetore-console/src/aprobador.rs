//! Signing and sending an operator decision, server side.
//!
//! The approver key is read from a private file on this computer and never
//! reaches the browser. The flow is the one of `praetore approve` /
//! `praetore reject` / `praetore dispatch`: fetch the challenge from the
//! gateway, check it is the same request and the same action the operator
//! saw, sign, send. The gateway verifies the signature, records the decision
//! and runs the single dispatch; the console decides nothing.

use crate::bandeja::PendingRef;
use ed25519_dalek::{Signer, SigningKey};
use praetore_gateway::{
    ApprovalChallengeView, ExecutionKey, HumanApprovalDecision, HumanApprovalOutcome, http_api,
};
use serde::Serialize;
use std::{fs, io::Read, net::SocketAddr, path::Path, time::Duration};
use uuid::Uuid;

const MAX_GATEWAY_BODY: u64 = 1_048_576;
const DECISION_TIMEOUT: Duration = Duration::from_secs(10);
const DISPATCH_TIMEOUT: Duration = Duration::from_secs(60);

/// What the gateway said, or why it said nothing.
#[derive(Debug, Clone)]
pub enum GatewayReply {
    Answered {
        status: u16,
        body: String,
    },
    /// The request did not leave this computer: nothing was recorded.
    NotSent,
    /// The request may have reached the gateway and the answer was lost.
    Unconfirmed,
}

/// The three gateway calls the console makes, as the CLI does.
pub trait ApprovalGateway: Send + Sync + 'static {
    fn challenge(&self, key: &ExecutionKey) -> GatewayReply;
    fn decide(&self, key: &ExecutionKey, decision_json: &str) -> GatewayReply;
    fn dispatch(&self, key: &ExecutionKey) -> GatewayReply;
}

#[derive(Debug)]
pub enum ApproverConfigError {
    GatewayAddress,
    KeyId,
    KeyFile,
    TokenFile,
}

impl std::fmt::Display for ApproverConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::GatewayAddress => {
                "PRAETORE_CONSOLE_GATEWAY_URL debe ser http://<IP de este computador>:<puerto>"
            }
            Self::KeyId => {
                "PRAETORE_CONSOLE_APPROVER_KEY_ID debe tener de 1 a 64 caracteres de [a-z0-9._-]"
            }
            Self::KeyFile => {
                "la llave del aprobador debe ser un archivo regular 0600 con 32 bytes en hex"
            }
            Self::TokenFile => {
                "el token de aprobador debe ser un archivo regular 0600 de 32 a 256 caracteres visibles"
            }
        })
    }
}

impl std::error::Error for ApproverConfigError {}

/// The approver identity the console signs with.
pub struct ApproverSigner {
    key_id: String,
    key: SigningKey,
}

impl std::fmt::Debug for ApproverSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApproverSigner")
    }
}

impl ApproverSigner {
    pub fn new(key_id: &str, secret: [u8; 32]) -> Result<Self, ApproverConfigError> {
        if !valid_key_id(key_id) {
            return Err(ApproverConfigError::KeyId);
        }
        Ok(Self {
            key_id: key_id.to_owned(),
            key: SigningKey::from_bytes(&secret),
        })
    }

    /// Same file format as `approver.key` from `praetore init`.
    pub fn from_file(key_id: &str, path: &Path) -> Result<Self, ApproverConfigError> {
        let text = read_private_text(path, 128).map_err(|()| ApproverConfigError::KeyFile)?;
        let decoded = hex::decode(text.trim());
        let mut text = text.into_bytes();
        text.iter_mut().for_each(|byte| *byte = 0);
        let mut bytes = decoded.map_err(|_| ApproverConfigError::KeyFile)?;
        let secret = <[u8; 32]>::try_from(bytes.as_slice());
        bytes.iter_mut().for_each(|byte| *byte = 0);
        let mut secret = secret.map_err(|_| ApproverConfigError::KeyFile)?;
        let signer = Self::new(key_id, secret);
        secret.iter_mut().for_each(|byte| *byte = 0);
        signer
    }

    /// True when `candidate` is this approver's public key or its secret:
    /// such a value must never be written as an attester pin.
    pub(crate) fn is_key_material(&self, candidate: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        let public = self.key.verifying_key().to_bytes();
        bool::from(public.ct_eq(candidate) | self.key.as_bytes().ct_eq(candidate))
    }

    /// True when `candidate` is this approver's secret. Its public key is a
    /// valid approver pin; its secret never is.
    pub(crate) fn is_secret(&self, candidate: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.key.as_bytes().ct_eq(candidate))
    }

    pub fn sign(
        &self,
        view: ApprovalChallengeView,
        outcome: HumanApprovalOutcome,
    ) -> Option<HumanApprovalDecision> {
        let mut decision = HumanApprovalDecision {
            schema_version: 1,
            approval_id: Uuid::new_v4(),
            approver_key_id: self.key_id.clone(),
            challenge: view.challenge,
            outcome,
            signature: String::new(),
        };
        let message = decision.signing_message().ok()?;
        decision.signature = hex::encode(self.key.sign(&message).to_bytes());
        Some(decision)
    }
}

fn valid_key_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

/// Reads the approver bearer token from a private file.
pub fn read_token_file(path: &Path) -> Result<String, ApproverConfigError> {
    let text = read_private_text(path, 1024).map_err(|()| ApproverConfigError::TokenFile)?;
    let token = text.trim();
    if !(http_api::MIN_TOKEN_BYTES..=http_api::MAX_TOKEN_BYTES).contains(&token.len())
        || !token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ApproverConfigError::TokenFile);
    }
    Ok(token.to_owned())
}

/// Opens without following a final symlink and checks the open file: a
/// regular file owned by this user, no group or other bits, at most `max`
/// bytes. The bytes read are cleared after decoding.
#[cfg(unix)]
fn read_private_text(path: &Path, max: u64) -> Result<String, ()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    let euid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_file()
        || metadata.len() > max
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != euid
    {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(max).unwrap_or(0));
    let read = file.take(max + 1).read_to_end(&mut bytes);
    let text = match read {
        Ok(_) if bytes.len() as u64 <= max => std::str::from_utf8(&bytes).map(str::to_owned).ok(),
        _ => None,
    };
    bytes.iter_mut().for_each(|byte| *byte = 0);
    text.ok_or(())
}

#[cfg(not(unix))]
fn read_private_text(_path: &Path, _max: u64) -> Result<String, ()> {
    Err(())
}

/// `http://127.0.0.1:8080` or `http://[::1]:8080`. Names are not resolved:
/// the approver token only travels to this computer.
pub fn parse_gateway_address(value: &str) -> Result<SocketAddr, ApproverConfigError> {
    let rest = value
        .strip_prefix("http://")
        .ok_or(ApproverConfigError::GatewayAddress)?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let address: SocketAddr = rest
        .parse()
        .map_err(|_| ApproverConfigError::GatewayAddress)?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(ApproverConfigError::GatewayAddress);
    }
    Ok(address)
}

/// HTTP client for the local gateway. Blocking: call it off the runtime.
pub struct HttpApprovalGateway {
    address: SocketAddr,
    token: String,
}

impl std::fmt::Debug for HttpApprovalGateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpApprovalGateway")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl HttpApprovalGateway {
    pub fn new(address: SocketAddr, token: String) -> Self {
        Self { address, token }
    }

    fn url(&self, key: &ExecutionKey, suffix: &str) -> String {
        format!(
            "http://{}/v1/approvals/{}/{}/{}{suffix}",
            self.address, key.tenant_id, key.agent_id, key.request_id
        )
    }

    fn call(
        &self,
        method: reqwest::Method,
        url: String,
        body: Option<String>,
        timeout: Duration,
    ) -> GatewayReply {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            http_api::EXEC_MODE_HEADER,
            reqwest::header::HeaderValue::from_static(http_api::EXEC_MODE_GATEWAY),
        );
        let client = match reqwest::blocking::Client::builder()
            .default_headers(headers)
            .no_proxy()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(client) => client,
            Err(_) => return GatewayReply::NotSent,
        };
        let mut request = client.request(method, url).bearer_auth(&self.token);
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        let response = match request.send() {
            Ok(response) => response,
            Err(error) if error.is_connect() || error.is_builder() => return GatewayReply::NotSent,
            Err(_) => return GatewayReply::Unconfirmed,
        };
        let status = response.status().as_u16();
        let mut body = Vec::new();
        if response
            .take(MAX_GATEWAY_BODY + 1)
            .read_to_end(&mut body)
            .is_err()
            || body.len() as u64 > MAX_GATEWAY_BODY
        {
            return GatewayReply::Unconfirmed;
        }
        match String::from_utf8(body) {
            Ok(body) => GatewayReply::Answered { status, body },
            Err(_) => GatewayReply::Unconfirmed,
        }
    }
}

impl ApprovalGateway for HttpApprovalGateway {
    fn challenge(&self, key: &ExecutionKey) -> GatewayReply {
        self.call(
            reqwest::Method::GET,
            self.url(key, ""),
            None,
            DECISION_TIMEOUT,
        )
    }

    fn decide(&self, key: &ExecutionKey, decision_json: &str) -> GatewayReply {
        self.call(
            reqwest::Method::POST,
            self.url(key, ""),
            Some(decision_json.to_owned()),
            DECISION_TIMEOUT,
        )
    }

    fn dispatch(&self, key: &ExecutionKey) -> GatewayReply {
        self.call(
            reqwest::Method::POST,
            self.url(key, "/dispatch"),
            None,
            DISPATCH_TIMEOUT,
        )
    }
}

/// What the operator sees after acting. `puede_ejecutar` is true only when
/// the request is approved and its single execution can still be asked for;
/// a decision is never offered again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActOutcome {
    pub situacion: &'static str,
    pub mensaje: &'static str,
    pub puede_ejecutar: bool,
}

const APPROVED_PENDING: &str = "aprobado, pendiente de ejecución";

fn outcome(situacion: &'static str, mensaje: &'static str) -> ActOutcome {
    ActOutcome {
        situacion,
        mensaje,
        puede_ejecutar: false,
    }
}

fn unchanged(mensaje: &'static str) -> ActOutcome {
    outcome("sin cambios", mensaje)
}

/// Approve or reject: one signed decision, never resent by the console.
pub fn decide(
    gateway: &dyn ApprovalGateway,
    signer: &ApproverSigner,
    pending: &PendingRef,
    decision: HumanApprovalOutcome,
) -> ActOutcome {
    let view = match gateway.challenge(&pending.key) {
        GatewayReply::Answered { status: 200, body } => {
            match ApprovalChallengeView::from_json(&body) {
                Ok(view) => view,
                Err(_) => {
                    return unchanged(
                        "El sistema respondió algo que no se entiende. No se firmó nada.",
                    );
                }
            }
        }
        GatewayReply::Answered { status, .. } => return challenge_refusal(status),
        GatewayReply::NotSent | GatewayReply::Unconfirmed => {
            return unchanged("No se pudo hablar con el sistema. No se firmó nada.");
        }
    };
    // The whole challenge must be the one rebuilt from the journal evidence
    // the operator was shown: same key, evidence, action, policy and window.
    if view.challenge != pending.expected
        || view.challenge.action_digest != pending.action_digest
        || !view.action_matches_challenge()
    {
        tracing::warn!(failure = "challenge_mismatch", "console refused to sign");
        return unchanged(
            "Lo que el sistema pide firmar no es lo que se mostró. No se firmó nada.",
        );
    }
    let Some(signed) = signer.sign(view, decision) else {
        return unchanged("No se pudo firmar. No se envió nada.");
    };
    let Ok(json) = serde_json::to_string(&signed) else {
        return unchanged("No se pudo firmar. No se envió nada.");
    };
    match gateway.decide(&pending.key, &json) {
        GatewayReply::Answered { status: 200, body } => {
            let status = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| {
                    value
                        .get("status")
                        .and_then(|s| s.as_str())
                        .map(str::to_owned)
                });
            match (decision, status.as_deref()) {
                (HumanApprovalOutcome::Approve, Some("approved_pending_dispatch")) => ActOutcome {
                    situacion: APPROVED_PENDING,
                    mensaje: "Quedó aprobado. Todavía no se ejecutó.",
                    puede_ejecutar: true,
                },
                (HumanApprovalOutcome::Reject, Some("rejected")) => outcome(
                    "rechazado",
                    "Quedó rechazado. El rechazo es final y no se ejecutó.",
                ),
                _ => unconfirmed_decision(),
            }
        }
        GatewayReply::Answered { status, body } => decision_refusal(status, &body),
        GatewayReply::NotSent => {
            unchanged("No se pudo hablar con el sistema. No quedó ninguna decisión registrada.")
        }
        GatewayReply::Unconfirmed => unconfirmed_decision(),
    }
}

fn unconfirmed_decision() -> ActOutcome {
    unchanged(
        "No se pudo confirmar si la decisión quedó registrada. Revisa el historial antes de seguir.",
    )
}

fn challenge_refusal(status: u16) -> ActOutcome {
    match status {
        404 => unchanged("Esta solicitud ya no está."),
        409 => unchanged("Esta solicitud ya tiene una decisión. No se firmó nada."),
        410 => outcome(
            "expirado",
            "La ventana de aprobación cerró sin una decisión. No se ejecutó.",
        ),
        401 | 403 => unchanged("El sistema no reconoce a esta consola como aprobadora."),
        _ => unchanged("El sistema no pudo atender ahora. No se firmó nada."),
    }
}

fn decision_refusal(status: u16, body: &str) -> ActOutcome {
    match (status, error_code(body).as_deref()) {
        (409, _) => unchanged("Esta solicitud ya tiene una decisión. No se registró otra."),
        (410, _) => outcome(
            "expirado",
            "La ventana de aprobación cerró antes de registrar la decisión. No se ejecutó.",
        ),
        (403, Some("action_not_dispatchable")) => outcome(
            "no se ejecutó",
            "El sistema se negó a ejecutarlo antes de tocar el objetivo. La solicitud quedó cerrada.",
        ),
        (403, Some("self_approval_forbidden")) => {
            unchanged("Esta llave pertenece al agente que lo pidió y no puede aprobarlo.")
        }
        (401 | 403, _) => {
            unchanged("El sistema no aceptó la firma de esta consola. No quedó ninguna decisión.")
        }
        (404, _) => unchanged("Esta solicitud ya no está."),
        (503, Some("approval_not_configured")) => {
            unchanged("El sistema no tiene aprobadores configurados.")
        }
        (400, _) => unchanged("El sistema no aceptó la decisión. No quedó registrada."),
        _ => unconfirmed_decision(),
    }
}

/// The single dispatch of an approved request. Retrying is safe: the gateway
/// claims the dispatch once and refuses any later claim.
pub fn dispatch(gateway: &dyn ApprovalGateway, pending: &PendingRef) -> ActOutcome {
    match gateway.dispatch(&pending.key) {
        GatewayReply::Answered { status: 200, body } => {
            let execution = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| {
                    value
                        .get("execution")
                        .and_then(|s| s.as_str())
                        .map(str::to_owned)
                });
            match execution.as_deref() {
                Some("executed" | "confirmed") => {
                    outcome("aprobado", "Se ejecutó. El registro dice que ocurrió.")
                }
                Some("failed") => outcome("aprobado", "Se intentó y falló."),
                Some("outcome_unknown") => outcome(
                    "aprobado",
                    "Se inició y no quedó claro si llegó a ocurrir. Revisa el historial.",
                ),
                _ => outcome("aprobado", "El sistema respondió. Revisa el historial."),
            }
        }
        GatewayReply::Answered { status, body } => match (status, error_code(&body).as_deref()) {
            (403, Some("action_not_dispatchable")) => outcome(
                "no se ejecutó",
                "El sistema se negó a ejecutarlo antes de tocar el objetivo.",
            ),
            (502, _) => outcome(
                "aprobado",
                "Se intentó y falló. Puede haber quedado un efecto parcial.",
            ),
            (410, _) => outcome(
                "expirado",
                "Se había aprobado, y la ventana cerró antes de ejecutarlo.",
            ),
            (409, _) => outcome(
                "sin cambios",
                "Ya no está pendiente de ejecución. Revisa el historial.",
            ),
            (404, _) => unchanged("Esta solicitud ya no está."),
            // Refused before the claim: nothing ran.
            (503, Some("dispatch_temporarily_refused" | "authorization_unavailable")) => {
                retry_dispatch(
                    "Sigue aprobado, sin ejecutar. El sistema no pudo ejecutarlo ahora; puedes reintentar la ejecución.",
                )
            }
            (401 | 403, _) => ActOutcome {
                situacion: APPROVED_PENDING,
                mensaje: "El sistema no reconoce a esta consola como aprobadora. Sigue aprobado, sin ejecutar.",
                puede_ejecutar: false,
            },
            // Any other failure may come after the effect (for example the
            // outcome could not be recorded): never say it did not run.
            // Retrying is safe, the gateway claims the dispatch only once.
            _ => unconfirmed_dispatch(),
        },
        GatewayReply::NotSent => retry_dispatch(
            "Sigue aprobado, sin ejecutar. No se pudo hablar con el sistema; puedes reintentar la ejecución.",
        ),
        GatewayReply::Unconfirmed => unconfirmed_dispatch(),
    }
}

fn unconfirmed_dispatch() -> ActOutcome {
    ActOutcome {
        situacion: "sin confirmar",
        mensaje: "No se pudo confirmar si se ejecutó. Revisa el historial; si sigue pendiente de ejecución, puedes reintentar.",
        puede_ejecutar: true,
    }
}

fn retry_dispatch(mensaje: &'static str) -> ActOutcome {
    ActOutcome {
        situacion: APPROVED_PENDING,
        mensaje,
        puede_ejecutar: true,
    }
}

fn error_code(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("code")?
        .as_str()
        .map(str::to_owned)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::Path as AxumPath,
        http::{HeaderMap, StatusCode},
        routing::{get, post},
    };
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("praetore-consola-{name}-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_private(path: &Path, contents: &str, mode: u32) {
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn the_gateway_address_is_a_loopback_ip_literal() {
        assert!(parse_gateway_address("http://127.0.0.1:8080").is_ok());
        assert!(parse_gateway_address("http://127.0.0.1:8080/").is_ok());
        assert!(parse_gateway_address("http://[::1]:8080").is_ok());
        for refused in [
            "https://127.0.0.1:8080",
            "http://localhost:8080",
            "http://10.0.0.5:8080",
            "http://0.0.0.0:8080",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:8080/v1",
            "http://user@127.0.0.1:8080",
            "127.0.0.1:8080",
        ] {
            assert!(parse_gateway_address(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn key_and_token_files_must_be_private_and_well_formed() {
        let dir = temp("llaves");
        let key = dir.join("approver.key");
        write_private(&key, &format!("{}\n", "11".repeat(32)), 0o600);
        assert!(ApproverSigner::from_file("local-approver", &key).is_ok());
        assert!(ApproverSigner::from_file("Local Approver", &key).is_err());
        assert!(ApproverSigner::from_file("", &key).is_err());
        write_private(&key, &"11".repeat(32), 0o640);
        assert!(ApproverSigner::from_file("local-approver", &key).is_err());
        write_private(&key, &"11".repeat(31), 0o600);
        assert!(ApproverSigner::from_file("local-approver", &key).is_err());
        let link = dir.join("enlace.key");
        write_private(&key, &"11".repeat(32), 0o600);
        std::os::unix::fs::symlink(&key, &link).unwrap();
        assert!(ApproverSigner::from_file("local-approver", &link).is_err());

        let token = dir.join("approver-api.token");
        write_private(&token, &format!("{}\n", "ab".repeat(32)), 0o600);
        assert_eq!(read_token_file(&token).unwrap(), "ab".repeat(32));
        write_private(&token, "corto", 0o600);
        assert!(read_token_file(&token).is_err());
        write_private(&token, &"ab".repeat(32), 0o644);
        assert!(read_token_file(&token).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_signer_debug_output_hides_the_key() {
        let signer = ApproverSigner::new("local-approver", [7; 32]).unwrap();
        let shown = format!("{signer:?}");
        assert!(!shown.contains("local-approver"));
        assert!(!shown.contains("07"));
        let gateway = HttpApprovalGateway::new("127.0.0.1:1".parse().unwrap(), "t".repeat(40));
        assert!(!format!("{gateway:?}").contains(&"t".repeat(40)));
    }

    type Seen = Arc<Mutex<Vec<(String, String, Option<String>, Option<String>)>>>;

    fn record(seen: &Seen, what: &str, path: String, headers: &HeaderMap) {
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        seen.lock().unwrap().push((
            what.to_owned(),
            path,
            header("authorization"),
            header(http_api::EXEC_MODE_HEADER),
        ));
    }

    #[test]
    fn the_http_client_sends_the_approver_token_and_the_gateway_mode() {
        let seen: Seen = Arc::default();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (a, b, c) = (seen.clone(), seen.clone(), seen.clone());
        let app = Router::new()
            .route(
                "/v1/approvals/{t}/{a}/{r}",
                get(
                    move |AxumPath((t, a_, r)): AxumPath<(String, String, String)>,
                          headers: HeaderMap| {
                        let seen = a.clone();
                        async move {
                            record(&seen, "challenge", format!("{t}/{a_}/{r}"), &headers);
                            (StatusCode::CONFLICT, "{\"code\":\"approval_not_pending\"}")
                        }
                    },
                )
                .post(
                    move |AxumPath((t, a_, r)): AxumPath<(String, String, String)>,
                          headers: HeaderMap,
                          body: String| {
                        let seen = b.clone();
                        async move {
                            assert!(body.contains("\"outcome\""));
                            record(&seen, "decide", format!("{t}/{a_}/{r}"), &headers);
                            (StatusCode::OK, "{\"status\":\"rejected\"}")
                        }
                    },
                ),
            )
            .route(
                "/v1/approvals/{t}/{a}/{r}/dispatch",
                post(
                    move |AxumPath((t, a_, r)): AxumPath<(String, String, String)>,
                          headers: HeaderMap| {
                        let seen = c.clone();
                        async move {
                            record(&seen, "dispatch", format!("{t}/{a_}/{r}"), &headers);
                            (StatusCode::OK, "{\"execution\":\"confirmed\"}")
                        }
                    },
                ),
            );
        runtime.spawn(async move { axum::serve(listener, app).await.unwrap() });

        let token = "f".repeat(64);
        let gateway = HttpApprovalGateway::new(address, token.clone());
        let key = ExecutionKey {
            tenant_id: Uuid::from_u128(1),
            agent_id: Uuid::from_u128(2),
            request_id: Uuid::from_u128(3),
        };
        let path = format!("{}/{}/{}", key.tenant_id, key.agent_id, key.request_id);
        assert!(matches!(
            gateway.challenge(&key),
            GatewayReply::Answered { status: 409, .. }
        ));
        assert!(matches!(
            gateway.decide(&key, "{\"outcome\":\"reject\"}"),
            GatewayReply::Answered { status: 200, .. }
        ));
        assert!(matches!(
            gateway.dispatch(&key),
            GatewayReply::Answered { status: 200, .. }
        ));
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 3);
        for (index, what) in ["challenge", "decide", "dispatch"].into_iter().enumerate() {
            assert_eq!(seen[index].0, what);
            assert_eq!(seen[index].1, path);
            assert_eq!(
                seen[index].2.as_deref(),
                Some(format!("Bearer {token}").as_str())
            );
            assert_eq!(seen[index].3.as_deref(), Some(http_api::EXEC_MODE_GATEWAY));
        }

        // Nothing listening: the request never left this computer.
        let closed = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap()
        };
        let nobody = HttpApprovalGateway::new(closed, token);
        assert!(matches!(nobody.dispatch(&key), GatewayReply::NotSent));
        runtime.shutdown_background();
    }
}
