//! Caller-authentication policy for the gateway service listener.

use praetore_gateway::http_api::{ApiAuth, ApiCredentials};
use std::net::SocketAddr;

/// Chooses the HTTP API authentication mode, failing closed:
///
/// - with a credentials document, every request must be authenticated;
/// - without one, the service starts only with the `local-demo` adapter on a
///   loopback listener. Production adapters (`http`, `sandbox`) and any
///   non-loopback address refuse to start.
pub fn select_api_auth(
    production_adapter: bool,
    address: SocketAddr,
    credentials_document: Option<&str>,
) -> Result<ApiAuth, Box<dyn std::error::Error>> {
    if let Some(document) = credentials_document {
        return Ok(ApiAuth::required(ApiCredentials::from_json(document)?));
    }
    if production_adapter {
        return Err(
            "PRAETORE_GATEWAY_API_CREDENTIALS_FILE is required with the http and sandbox adapters"
                .into(),
        );
    }
    if !address.ip().is_loopback() {
        return Err(
            "PRAETORE_GATEWAY_API_CREDENTIALS_FILE is required for a non-loopback listen address"
                .into(),
        );
    }
    Ok(ApiAuth::UnauthenticatedLoopbackDemo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn credentials() -> String {
        serde_json::json!({
            "schema_version": 1,
            "credentials": [{
                "name": "agent",
                "tenant_id": Uuid::from_u128(1),
                "role": "agent",
                "token_sha256": ApiCredentials::token_sha256_hex(&"t".repeat(40)),
            }]
        })
        .to_string()
    }

    #[test]
    fn unauthenticated_mode_is_limited_to_the_loopback_local_demo() {
        let loopback: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let loopback_v6: SocketAddr = "[::1]:8080".parse().unwrap();
        let any: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:8080".parse().unwrap();
        let private: SocketAddr = "10.0.0.5:8080".parse().unwrap();

        assert!(
            !select_api_auth(false, loopback, None)
                .unwrap()
                .is_required()
        );
        assert!(
            !select_api_auth(false, loopback_v6, None)
                .unwrap()
                .is_required()
        );
        for address in [any, mapped, private] {
            assert!(select_api_auth(false, address, None).is_err(), "{address}");
        }
        assert!(select_api_auth(true, loopback, None).is_err());
    }

    #[test]
    fn credentials_enable_authentication_everywhere() {
        let document = credentials();
        for (production, address) in [
            (true, "0.0.0.0:8080"),
            (true, "127.0.0.1:8080"),
            (false, "0.0.0.0:8080"),
            (false, "127.0.0.1:8080"),
        ] {
            assert!(
                select_api_auth(production, address.parse().unwrap(), Some(&document))
                    .unwrap()
                    .is_required()
            );
        }
        assert!(select_api_auth(true, "0.0.0.0:8080".parse().unwrap(), Some("{}")).is_err());
    }
}
