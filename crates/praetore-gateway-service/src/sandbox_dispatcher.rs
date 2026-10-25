use praetore_core::{Action, Authority};
use praetore_gateway::{
    ActionDispatcher, DispatchError, DispatchReport, ExecutionKey, ReconciliationReport,
    action_digest, authority_tenant_id,
};
use reqwest::{
    Url,
    blocking::{Client, Response},
    header::{CONTENT_TYPE, HeaderValue},
};
use serde::{Deserialize, Serialize};
use std::{io::Read, time::Duration};

const MAX_REQUEST_BYTES: usize = 65_536;
const MAX_RESPONSE_BYTES: usize = 65_536;
const MAX_TLS_FILE_BYTES: u64 = 1_048_576;

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DispatchRequest<'a> {
    schema_version: u8,
    execution_key: ExecutionKey,
    authority: &'a Authority,
    action: &'a Action,
    action_digest: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconciliationResponse {
    schema_version: u8,
    execution_key: ExecutionKey,
    action_digest: String,
    status: ReconciliationStatus,
    output: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReconciliationStatus {
    Applied,
    NotApplied,
    Unknown,
}

/// Sends authorized actions to the isolated sandbox supervisor over mTLS.
///
/// The endpoint is startup-configured and requests contain no caller-selected
/// URL, method, credential, or tool profile. The supervisor must independently
/// enforce the execution identity and action digest as an idempotency key.
pub struct SandboxActionDispatcher {
    client: Client,
    endpoint: Url,
}

impl SandboxActionDispatcher {
    pub fn from_pem_files(
        endpoint: &str,
        ca_path: &str,
        client_identity_path: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut endpoint = Url::parse(endpoint)?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err("sandbox supervisor endpoint must be fixed HTTPS without credentials, query, or fragment".into());
        }
        if !endpoint.path().ends_with('/') {
            let path = format!("{}/", endpoint.path());
            endpoint.set_path(&path);
        }

        let ca_pem = read_limited(ca_path, MAX_TLS_FILE_BYTES)?;
        let identity_pem = read_limited(client_identity_path, MAX_TLS_FILE_BYTES)?;
        let ca = reqwest::Certificate::from_pem(&ca_pem)?;
        let identity = reqwest::Identity::from_pem(&identity_pem)?;
        let client = Client::builder()
            .https_only(true)
            .add_root_certificate(ca)
            .identity(identity)
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(150))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self { client, endpoint })
    }

    fn bounded_json(response: Response) -> Result<serde_json::Value, DispatchError> {
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(DispatchError);
        }
        let mut body = Vec::new();
        response
            .take((MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut body)
            .map_err(|_| DispatchError)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(DispatchError);
        }
        serde_json::from_slice(&body).map_err(|_| DispatchError)
    }

    fn execution_url(&self, key: ExecutionKey) -> Result<Url, DispatchError> {
        let url = self
            .endpoint
            .join(&format!(
                "v1/executions/{}/{}/{}",
                key.tenant_id, key.agent_id, key.request_id
            ))
            .map_err(|_| DispatchError)?;
        Ok(url)
    }
}

impl ActionDispatcher for SandboxActionDispatcher {
    fn dispatch(
        &self,
        key: ExecutionKey,
        authority: &Authority,
        action: &Action,
        expected_digest: &str,
    ) -> Result<DispatchReport, DispatchError> {
        if authority_tenant_id(authority) != Some(key.tenant_id)
            || action_digest(action).map_err(|_| DispatchError)? != expected_digest
        {
            return Err(DispatchError);
        }
        let request = DispatchRequest {
            schema_version: 1,
            execution_key: key,
            authority,
            action,
            action_digest: expected_digest,
        };
        let body = serde_json::to_vec(&request).map_err(|_| DispatchError)?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(DispatchError);
        }
        let url = self
            .endpoint
            .join("v1/executions")
            .map_err(|_| DispatchError)?;
        let idempotency_key = format!("{}:{}:{}", key.tenant_id, key.agent_id, key.request_id);
        let idempotency_key = HeaderValue::from_str(&idempotency_key).map_err(|_| DispatchError)?;
        let response = self
            .client
            .post(url)
            .header("Idempotency-Key", idempotency_key)
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .map_err(|_| DispatchError)?;
        let value = Self::bounded_json(response)?;
        serde_json::from_value(value).map_err(|_| DispatchError)
    }

    fn reconcile(
        &self,
        key: ExecutionKey,
        authority: &Authority,
        action: &Action,
        expected_digest: &str,
    ) -> ReconciliationReport {
        if authority_tenant_id(authority) != Some(key.tenant_id)
            || !action_digest(action).is_ok_and(|digest| digest == expected_digest)
        {
            return ReconciliationReport::Unknown;
        }
        let Ok(url) = self.execution_url(key) else {
            return ReconciliationReport::Unknown;
        };
        let Ok(action_digest_header) = HeaderValue::from_str(expected_digest) else {
            return ReconciliationReport::Unknown;
        };
        let Ok(response) = self
            .client
            .get(url)
            .header("X-Praetore-Action-Digest", action_digest_header)
            .send()
        else {
            return ReconciliationReport::Unknown;
        };
        let Ok(value) = Self::bounded_json(response) else {
            return ReconciliationReport::Unknown;
        };
        let Ok(result) = serde_json::from_value::<ReconciliationResponse>(value) else {
            return ReconciliationReport::Unknown;
        };
        if result.schema_version != 1
            || result.execution_key != key
            || result.action_digest != expected_digest
        {
            return ReconciliationReport::Unknown;
        }
        match result.status {
            ReconciliationStatus::Applied => result
                .output
                .map(ReconciliationReport::Applied)
                .unwrap_or(ReconciliationReport::Unknown),
            ReconciliationStatus::NotApplied => ReconciliationReport::NotApplied,
            ReconciliationStatus::Unknown => ReconciliationReport::Unknown,
        }
    }
}

fn read_limited(path: &str, max_bytes: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(
            format!("{path} must be a non-empty file no larger than {max_bytes} bytes").into(),
        );
    }
    Ok(std::fs::read(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use praetore_core::{AgentId, authority::AuthorityConstraint};
    use serde_json::json;
    use uuid::Uuid;

    fn action() -> Action {
        Action::new("orders:create", Some("orders-api".into()), json!({"id": 3}))
            .unwrap()
            .with_capability("orders:write")
    }

    fn authority() -> Authority {
        let mut authority =
            Authority::new(AgentId::new(), "test-issuer", vec!["orders:write".into()]);
        authority.constraints = vec![AuthorityConstraint::new(
            "tenant_id",
            Uuid::from_u128(10).to_string(),
        )];
        authority
    }

    #[test]
    fn endpoint_rejects_non_tls_and_url_credentials() {
        for endpoint in [
            "http://supervisor.internal/",
            "https://user:password@supervisor.internal/",
            "https://supervisor.internal/?override=true",
        ] {
            assert!(
                SandboxActionDispatcher::from_pem_files(endpoint, "missing-ca", "missing-id")
                    .is_err()
            );
        }
    }

    #[test]
    fn dispatcher_request_is_bound_to_tenant_and_action_digest() {
        let authority = authority();
        let action = action();
        let digest = action_digest(&action).unwrap();
        let request = DispatchRequest {
            schema_version: 1,
            execution_key: ExecutionKey {
                tenant_id: Uuid::from_u128(10),
                agent_id: Uuid::from_u128(11),
                request_id: Uuid::from_u128(12),
            },
            authority: &authority,
            action: &action,
            action_digest: &digest,
        };
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["action_digest"], digest);
        assert_eq!(
            value["execution_key"]["tenant_id"],
            Uuid::from_u128(10).to_string()
        );
        assert!(serde_json::to_vec(&value).unwrap().len() < MAX_REQUEST_BYTES);
    }
}
