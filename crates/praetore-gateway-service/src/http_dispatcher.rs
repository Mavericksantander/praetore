use praetore_core::{Action, Authority, canonical::parse_json_rejecting_duplicates};
use praetore_gateway::{
    ActionDispatcher, DispatchError, DispatchReport, ExecutionKey, ReconciliationReport,
    action_digest, authority_tenant_id,
};
use reqwest::{
    Url,
    blocking::Client,
    header::{AUTHORIZATION, HeaderValue},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, io::Read, net::IpAddr, time::Duration};
use uuid::Uuid;

const MAX_CONFIG_BYTES: usize = 65_536;
const MAX_ACTION_BYTES: usize = 65_536;
const MAX_RESPONSE_BYTES: usize = 65_536;
const MAX_ROUTES: usize = 128;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatcherConfig {
    schema_version: u8,
    #[serde(default)]
    egress_proxy: Option<String>,
    routes: Vec<RouteConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteConfig {
    tenant_id: Uuid,
    action_type: String,
    target: String,
    capability: String,
    endpoint: String,
    bearer_token_env: Option<String>,
}

struct Route {
    capability: String,
    endpoint: Url,
    authorization: Option<HeaderValue>,
}

/// Dispatches only to startup-configured HTTP endpoints. Tool requests cannot
/// choose a URL, HTTP method, or credential.
pub struct HttpActionDispatcher {
    client: Client,
    routes: HashMap<(Uuid, String, String), Route>,
}

impl HttpActionDispatcher {
    pub fn from_json(config_json: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::parse_json(config_json, false)
    }

    pub fn from_json_with_required_egress_proxy(
        config_json: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::parse_json(config_json, true)
    }

    fn parse_json(
        config_json: &str,
        require_egress_proxy: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if config_json.len() > MAX_CONFIG_BYTES {
            return Err("tool route configuration exceeds the size limit".into());
        }
        let value = parse_json_rejecting_duplicates(config_json)?;
        let config: DispatcherConfig = serde_json::from_value(value)?;
        if config.schema_version != 1
            || config.routes.is_empty()
            || config.routes.len() > MAX_ROUTES
        {
            return Err(
                "tool route configuration has an unsupported version or route count".into(),
            );
        }
        if require_egress_proxy && config.egress_proxy.is_none() {
            return Err("HTTP tool routes require a policy-enforcing egress proxy".into());
        }

        let mut routes = HashMap::with_capacity(config.routes.len());
        for route in config.routes {
            validate_route_text(&route.action_type, "action_type")?;
            validate_route_text(&route.target, "target")?;
            validate_route_text(&route.capability, "capability")?;
            let endpoint = Url::parse(&route.endpoint)?;
            validate_endpoint(&endpoint)?;
            let authorization = route
                .bearer_token_env
                .map(|name| -> Result<HeaderValue, Box<dyn std::error::Error>> {
                    validate_env_name(&name)?;
                    let token = std::env::var(&name)
                        .map_err(|_| format!("configured credential {name} is unavailable"))?;
                    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_control()) {
                        return Err(format!("configured credential {name} is invalid").into());
                    }
                    let mut authorization = Vec::with_capacity(b"Bearer ".len() + token.len());
                    authorization.extend_from_slice(b"Bearer ");
                    authorization.extend_from_slice(token.as_bytes());
                    let mut value = HeaderValue::from_bytes(&authorization)?;
                    value.set_sensitive(true);
                    Ok(value)
                })
                .transpose()?;

            let key = (route.tenant_id, route.action_type, route.target);
            if routes
                .insert(
                    key,
                    Route {
                        capability: route.capability,
                        endpoint,
                        authorization,
                    },
                )
                .is_some()
            {
                return Err(
                    "tool route configuration contains a duplicate tenant, action, and target"
                        .into(),
                );
            }
        }

        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        if let Some(proxy) = config.egress_proxy {
            let proxy = Url::parse(&proxy)?;
            validate_proxy(&proxy)?;
            client_builder = client_builder.proxy(reqwest::Proxy::all(proxy.as_str())?);
        }
        let client = client_builder.build()?;
        Ok(Self { client, routes })
    }
}

impl ActionDispatcher for HttpActionDispatcher {
    fn dispatch(
        &self,
        key: ExecutionKey,
        authority: &Authority,
        action: &Action,
        expected_digest: &str,
    ) -> Result<DispatchReport, DispatchError> {
        if action_digest(action).map_err(|_| DispatchError)? != expected_digest {
            return Err(DispatchError);
        }
        let tenant_id = authority_tenant_id(authority).ok_or(DispatchError)?;
        if key.tenant_id != tenant_id {
            return Err(DispatchError);
        }
        let route = self
            .routes
            .get(&(
                tenant_id,
                action.action_type.clone(),
                action.target.clone().ok_or(DispatchError)?,
            ))
            .ok_or(DispatchError)?;
        if action.capability.as_deref() != Some(route.capability.as_str()) {
            return Err(DispatchError);
        }
        let request_body = serde_json::to_vec(&action.parameters).map_err(|_| DispatchError)?;
        if request_body.len() > MAX_ACTION_BYTES {
            return Err(DispatchError);
        }

        let idempotency_key = format!("{tenant_id}:{}:{}", key.agent_id, key.request_id);
        let mut request = self
            .client
            .post(route.endpoint.clone())
            .header("Idempotency-Key", idempotency_key)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request_body);
        if let Some(authorization) = &route.authorization {
            request = request.header(AUTHORIZATION, authorization.clone());
        }

        let mut response = request.send().map_err(|_| DispatchError)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(DispatchError);
        }
        let status = response.status();
        let mut response_body = Vec::new();
        response
            .by_ref()
            .take((MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut response_body)
            .map_err(|_| DispatchError)?;
        if response_body.len() > MAX_RESPONSE_BYTES {
            return Err(DispatchError);
        }

        let body = if response_body.is_empty() {
            Value::Null
        } else {
            match serde_json::from_slice(&response_body) {
                Ok(body) => body,
                Err(_) => {
                    Value::String(String::from_utf8(response_body).map_err(|_| DispatchError)?)
                }
            }
        };
        Ok(DispatchReport::Executed(json!({
            "http_status": status.as_u16(),
            "body": body,
        })))
    }

    fn reconcile(
        &self,
        _key: ExecutionKey,
        _authority: &Authority,
        _action: &Action,
        _action_digest: &str,
    ) -> ReconciliationReport {
        ReconciliationReport::Unknown
    }
}

fn validate_route_text(value: &str, field: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value.trim().is_empty()
        || value != value.trim()
        || value.len() > 256
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(format!("tool route {field} is invalid").into());
    }
    Ok(())
}

fn validate_env_name(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("tool route credential environment variable name is invalid".into());
    }
    Ok(())
}

fn validate_endpoint(endpoint: &Url) -> Result<(), Box<dyn std::error::Error>> {
    let is_loopback = endpoint.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if endpoint.username() != ""
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || (endpoint.scheme() != "https" && !(endpoint.scheme() == "http" && is_loopback))
        || endpoint.host_str().is_none()
    {
        return Err("tool route endpoint must be fixed HTTPS (or loopback HTTP for tests) without credentials, query, or fragment".into());
    }
    Ok(())
}

fn validate_proxy(proxy: &Url) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(proxy.scheme(), "http" | "https")
        || proxy.host_str().is_none()
        || !proxy.username().is_empty()
        || proxy.password().is_some()
        || proxy.query().is_some()
        || proxy.fragment().is_some()
    {
        return Err(
            "egress proxy must use a fixed HTTP(S) URL without credentials or query".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use praetore_core::Action;
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        thread,
    };
    use uuid::Uuid;

    fn route_config(endpoint: &str) -> String {
        serde_json::to_string(&json!({
            "schema_version": 1,
            "egress_proxy": null,
            "routes": [{
                "tenant_id": Uuid::from_u128(10).to_string(),
                "action_type": "orders:create",
                "target": "orders-api",
                "capability": "orders:write",
                "endpoint": endpoint
            }]
        }))
        .unwrap()
    }

    fn action() -> Action {
        Action::new(
            "orders:create",
            Some("orders-api".into()),
            json!({"customer_id": "cust-123", "amount": 42}),
        )
        .unwrap()
        .with_capability("orders:write")
    }

    fn authority(tenant_id: Option<&str>) -> Authority {
        let mut authority = Authority::new(
            praetore_core::AgentId::new(),
            "test-issuer",
            vec!["orders:write".into()],
        );
        authority.constraints = tenant_id
            .map(|tenant| {
                vec![praetore_core::authority::AuthorityConstraint::new(
                    "tenant_id",
                    tenant,
                )]
            })
            .unwrap_or_default();
        authority
    }

    #[test]
    fn forwards_only_configured_action_and_persisted_idempotency_key() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut request = Vec::new();
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line
                    .strip_prefix("Content-Length:")
                    .or_else(|| line.strip_prefix("content-length:"))
                {
                    content_length = value.trim().parse::<usize>().unwrap();
                }
                request.extend_from_slice(line.as_bytes());
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("POST /v1/orders HTTP/1.1\r\n"));
            assert!(request.to_ascii_lowercase().contains(&format!(
                "idempotency-key: {}:{}:{}\r\n",
                Uuid::from_u128(10),
                Uuid::from_u128(1),
                Uuid::from_u128(2)
            )));
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap(),
                json!({"customer_id": "cust-123", "amount": 42})
            );
            let mut stream = reader.into_inner();
            let response_body = br#"{"order_id":"ord-1"}"#;
            write!(
                stream,
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            )
            .unwrap();
            stream.write_all(response_body).unwrap();
        });

        let dispatcher =
            HttpActionDispatcher::from_json(&route_config(&format!("http://{address}/v1/orders")))
                .unwrap();
        let action = action();
        let digest = action_digest(&action).unwrap();
        let report = dispatcher
            .dispatch(
                ExecutionKey {
                    tenant_id: Uuid::from_u128(10),
                    agent_id: Uuid::from_u128(1),
                    request_id: Uuid::from_u128(2),
                },
                &authority(Some(&Uuid::from_u128(10).to_string())),
                &action,
                &digest,
            )
            .unwrap();
        assert_eq!(
            report,
            DispatchReport::Executed(json!({
                "http_status": 201,
                "body": {"order_id": "ord-1"}
            }))
        );
        server.join().unwrap();
    }

    #[test]
    fn refuses_unconfigured_or_mismatched_actions_before_network_access() {
        let dispatcher =
            HttpActionDispatcher::from_json(&route_config("https://orders.internal/v1/orders"))
                .unwrap();
        let matching_action = action();
        assert_eq!(
            dispatcher.dispatch(
                ExecutionKey {
                    tenant_id: Uuid::from_u128(11),
                    agent_id: Uuid::new_v4(),
                    request_id: Uuid::new_v4(),
                },
                &authority(Some(&Uuid::from_u128(10).to_string())),
                &matching_action,
                &action_digest(&matching_action).unwrap(),
            ),
            Err(DispatchError)
        );
        let mut changed_action = action();
        changed_action.capability = Some("orders:admin".into());
        let digest = action_digest(&changed_action).unwrap();
        assert_eq!(
            dispatcher.dispatch(
                ExecutionKey {
                    tenant_id: Uuid::from_u128(10),
                    agent_id: Uuid::new_v4(),
                    request_id: Uuid::new_v4(),
                },
                &authority(Some(&Uuid::from_u128(10).to_string())),
                &changed_action,
                &digest,
            ),
            Err(DispatchError)
        );
        let unconfigured = Action::new(
            "orders:delete",
            Some("orders-api".into()),
            json!({"order_id": "ord-1"}),
        )
        .unwrap()
        .with_capability("orders:write");
        assert_eq!(
            dispatcher.dispatch(
                ExecutionKey {
                    tenant_id: Uuid::from_u128(10),
                    agent_id: Uuid::new_v4(),
                    request_id: Uuid::new_v4(),
                },
                &authority(Some(&Uuid::from_u128(11).to_string())),
                &unconfigured,
                &action_digest(&unconfigured).unwrap(),
            ),
            Err(DispatchError)
        );
    }

    #[test]
    fn rejects_external_plain_http_and_duplicate_routes() {
        assert!(HttpActionDispatcher::from_json(&route_config("http://example.com/api")).is_err());
        assert!(
            HttpActionDispatcher::from_json(r#"{"schema_version":1,"routes":[],"routes":[]}"#)
                .is_err()
        );
        let duplicate = json!({
            "schema_version": 1,
            "routes": [
                {
                    "tenant_id": Uuid::from_u128(10),
                    "action_type": "orders:create",
                    "target": "orders-api",
                    "capability": "orders:write",
                    "endpoint": "https://orders.internal/v1/orders"
                },
                {
                    "tenant_id": Uuid::from_u128(10),
                    "action_type": "orders:create",
                    "target": "orders-api",
                    "capability": "orders:write",
                    "endpoint": "https://attacker.internal/collect"
                }
            ]
        });
        assert!(HttpActionDispatcher::from_json(&duplicate.to_string()).is_err());
    }

    #[test]
    fn validates_explicit_egress_proxy_configuration() {
        assert!(validate_proxy(&Url::parse("http://egress-proxy.internal:3128").unwrap()).is_ok());
        assert!(validate_proxy(&Url::parse("https://egress-proxy.internal:8443").unwrap()).is_ok());
        let mut credentialed_proxy = Url::parse("http://egress-proxy.internal:3128").unwrap();
        credentialed_proxy.set_username("proxy-user").unwrap();
        let password = "x".repeat(16);
        credentialed_proxy.set_password(Some(&password)).unwrap();
        assert!(validate_proxy(&credentialed_proxy).is_err());
        assert!(
            validate_proxy(
                &Url::parse("http://egress-proxy.internal:3128/?target=attacker").unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn production_route_parser_requires_an_explicit_egress_proxy() {
        assert!(
            HttpActionDispatcher::from_json_with_required_egress_proxy(&route_config(
                "https://orders.internal/v1/orders"
            ))
            .is_err()
        );

        let configuration = serde_json::to_string(&json!({
            "schema_version": 1,
            "egress_proxy": "http://127.0.0.1:3128",
            "routes": [{
                "tenant_id": Uuid::from_u128(10),
                "action_type": "orders:create",
                "target": "orders-api",
                "capability": "orders:write",
                "endpoint": "https://orders.internal/v1/orders"
            }]
        }))
        .unwrap();
        assert!(HttpActionDispatcher::from_json_with_required_egress_proxy(&configuration).is_ok());
    }

    #[test]
    fn requires_exactly_one_issuer_signed_tenant_constraint() {
        let dispatcher =
            HttpActionDispatcher::from_json(&route_config("https://orders.internal/v1/orders"))
                .unwrap();
        let action = action();
        let digest = action_digest(&action).unwrap();
        let key = ExecutionKey {
            tenant_id: Uuid::from_u128(10),
            agent_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
        };
        assert_eq!(
            dispatcher.dispatch(key, &authority(None), &action, &digest),
            Err(DispatchError)
        );

        let tenant = Uuid::from_u128(10).to_string();
        let mut duplicate_tenant = authority(Some(&tenant));
        duplicate_tenant
            .constraints
            .push(praetore_core::authority::AuthorityConstraint::new(
                "tenant_id",
                tenant,
            ));
        assert_eq!(
            dispatcher.dispatch(key, &duplicate_tenant, &action, &digest),
            Err(DispatchError)
        );
    }
}
