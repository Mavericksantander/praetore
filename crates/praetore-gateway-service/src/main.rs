use ed25519_dalek::{Signer, SigningKey};
use postgres::{Client, NoTls};
use praetore_core::{
    EvidenceAttesterKey, FreshnessProvider, HighAssuranceConfig, Policy, TrustedAuthorityIssuer,
    canonical::parse_json_rejecting_duplicates, engine::AuthorizationEngine,
};
use praetore_gateway::{
    ActionDispatcher, ExecutionAttestationError, ExecutionAttestationSigner, Gateway,
    HumanApprovalVerifier, http_api, local_demo::LocalDemoDispatcher,
};
use praetore_gateway_service::{
    api_auth::select_api_auth,
    approver_bindings::{parse_approver_bindings, single_approver},
    chrony_clock::ChronyClock,
    file_freshness::{DemoFreshnessProvider, FileFreshnessLimits, FileFreshnessProvider},
};
use praetore_replay_postgres::{PostgresExecutionJournal, PostgresReplayGuard};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::Path,
    str::FromStr,
    sync::Arc,
    time::Duration as StdDuration,
};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

struct LocalExecutionSigner {
    key_id: String,
    signing_key: SigningKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantIssuerBindingsFile {
    schema_version: u8,
    tenants: Vec<TenantIssuerBinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantIssuerBinding {
    tenant_id: Uuid,
    issuer_key_ids: Vec<String>,
}

struct GatewayAdapterSetup {
    dispatcher: Arc<dyn ActionDispatcher>,
    tenant_issuer_bindings: Option<HashMap<Uuid, Vec<String>>>,
    audience: String,
    require_trusted_clock: bool,
    /// `http` and `sandbox`: refuse demo freshness, unauthenticated API
    /// access and unscoped multi-tenant approver keys.
    production_adapter: bool,
}

impl LocalExecutionSigner {
    fn from_hex(value: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = hex::decode(value)?;
        let secret: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "execution attester key must be exactly 32 bytes")?;
        let signing_key = SigningKey::from_bytes(&secret);
        Ok(Self {
            key_id: format!(
                "local-demo-{}",
                hex::encode(signing_key.verifying_key().as_bytes())
            ),
            signing_key,
        })
    }
}

impl ExecutionAttestationSigner for LocalExecutionSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ExecutionAttestationError> {
        Ok(self.signing_key.sign(message).to_bytes().to_vec())
    }
}

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn read_limited(path: &str, max_bytes: u64) -> Result<String, Box<dyn std::error::Error>> {
    let metadata = fs::metadata(Path::new(path))?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(format!("{path} must be a file no larger than {max_bytes} bytes").into());
    }
    Ok(fs::read_to_string(path)?)
}

fn load_issuer_pins(
    document: &str,
) -> Result<Vec<TrustedAuthorityIssuer>, Box<dyn std::error::Error>> {
    if document.len() > 1_048_576 {
        return Err("issuer pin configuration exceeds the size limit".into());
    }
    let value = parse_json_rejecting_duplicates(document)?;
    let pin_documents = match value {
        Value::Array(pins) if !pins.is_empty() && pins.len() <= 4096 => pins
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?,
        Value::Array(_) => return Err("issuer pin list must contain 1 to 4096 pins".into()),
        _ => vec![document.to_owned()],
    };
    let pins = pin_documents
        .iter()
        .map(|pin| TrustedAuthorityIssuer::from_pin_json(pin))
        .collect::<Result<Vec<_>, _>>()?;
    let mut key_ids = HashSet::with_capacity(pins.len());
    if pins.iter().any(|pin| !key_ids.insert(pin.key_id())) {
        return Err("issuer pin list contains duplicate key ids".into());
    }
    Ok(pins)
}

fn parse_tenant_issuer_bindings(
    document: &str,
) -> Result<HashMap<Uuid, Vec<String>>, Box<dyn std::error::Error>> {
    if document.len() > 1_048_576 {
        return Err("tenant issuer binding configuration exceeds the size limit".into());
    }
    let value = parse_json_rejecting_duplicates(document)?;
    let bindings: TenantIssuerBindingsFile = serde_json::from_value(value)?;
    if bindings.schema_version != 1 || bindings.tenants.is_empty() || bindings.tenants.len() > 4096
    {
        return Err(
            "tenant issuer binding configuration has an unsupported version or size".into(),
        );
    }

    let mut tenants = HashMap::with_capacity(bindings.tenants.len());
    let mut assigned_key_ids = HashSet::new();
    for binding in bindings.tenants {
        if binding.tenant_id.is_nil()
            || binding.issuer_key_ids.is_empty()
            || binding.issuer_key_ids.len() > 16
        {
            return Err("tenant issuer binding contains an invalid tenant or key list".into());
        }
        for key_id in &binding.issuer_key_ids {
            let valid_key_id = key_id.len() == 64
                && hex::decode(key_id).is_ok_and(|bytes| hex::encode(bytes) == *key_id);
            if !valid_key_id || !assigned_key_ids.insert(key_id.clone()) {
                return Err(
                    "issuer key ids must be canonical and assigned to exactly one tenant".into(),
                );
            }
        }
        if tenants
            .insert(binding.tenant_id, binding.issuer_key_ids)
            .is_some()
        {
            return Err("tenant issuer binding contains a duplicate tenant id".into());
        }
    }
    Ok(tenants)
}

fn apply_migrations(database_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    validate_local_database_url(database_url)?;
    let mut client = Client::connect(database_url, NoTls)?;
    praetore_replay_postgres::apply_migrations(&mut client)?;
    Ok(())
}

fn validate_local_database_url(database_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = postgres::Config::from_str(database_url)?;
    if config.get_hosts().is_empty()
        || config.get_hosts().iter().any(|host| match host {
            postgres::config::Host::Tcp(host) => {
                host != "localhost"
                    && !host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            }
            #[cfg(unix)]
            postgres::config::Host::Unix(_) => false,
        })
    {
        return Err("local demo gateway requires a loopback or Unix-socket PostgreSQL host".into());
    }
    Ok(())
}

fn build_gateway(
    database_url: &str,
    dispatcher: Arc<dyn ActionDispatcher>,
    tenant_issuer_bindings: Option<HashMap<Uuid, Vec<String>>>,
    audience: &str,
    require_trusted_clock: bool,
    production_adapter: bool,
    approval_verifiers: Vec<HumanApprovalVerifier>,
) -> Result<Gateway, Box<dyn std::error::Error>> {
    let policy_path = required_env("PRAETORE_GATEWAY_POLICY_FILE")?;
    let issuer_pin_path = required_env("PRAETORE_GATEWAY_ISSUER_PIN_FILE")?;
    let policy = Policy::from_json(&read_limited(&policy_path, 1_048_576)?)?;
    if policy.semantics_version != 2 {
        return Err("gateway service requires policy semantics version 2".into());
    }
    let policy_digest = policy.digest()?;
    let issuer_pins = load_issuer_pins(&read_limited(&issuer_pin_path, 1_048_576)?)?;
    let evidence_key_hex = required_env("PRAETORE_GATEWAY_EVIDENCE_ATTESTER_KEY_HEX")?;
    let evidence_key_bytes: [u8; 32] = hex::decode(evidence_key_hex)?
        .try_into()
        .map_err(|_| "evidence attester key must be exactly 32 bytes")?;
    let evidence_attester = EvidenceAttesterKey::from_secret_bytes(&evidence_key_bytes);

    let mut config =
        HighAssuranceConfig::new(policy_digest.clone(), issuer_pins, evidence_attester)?
            .with_audience(audience)
            .with_replay_guard(Arc::new(PostgresReplayGuard::from_client(Client::connect(
                database_url,
                NoTls,
            )?)))
            .with_freshness_provider(freshness_provider(production_adapter, policy_digest)?);
    if let Some(bindings) = tenant_issuer_bindings {
        config = config.with_tenant_issuer_bindings(bindings);
    }
    let engine = if require_trusted_clock {
        let chronyc_path =
            env::var("PRAETORE_GATEWAY_CHRONYC_PATH").unwrap_or_else(|_| "/usr/bin/chronyc".into());
        let poll_interval = env_duration_ms("PRAETORE_GATEWAY_CHRONY_POLL_INTERVAL_MS", 500)?;
        let max_sample_age = env_duration_ms("PRAETORE_GATEWAY_CHRONY_MAX_SAMPLE_AGE_MS", 2_000)?;
        let max_error = env_duration_ms("PRAETORE_GATEWAY_CHRONY_MAX_ERROR_MS", 100)?;
        let clock = ChronyClock::new(&chronyc_path, poll_interval, max_sample_age, max_error)
            .map_err(std::io::Error::other)?;
        AuthorizationEngine::production_with_trusted_clock(policy, config, clock)?
    } else {
        AuthorizationEngine::production(policy, config)?
    };

    let journal = Arc::new(PostgresExecutionJournal::from_connection_factory({
        let database_url = database_url.to_owned();
        move || Client::connect(&database_url, NoTls)
    })?);
    let execution_signer = Arc::new(LocalExecutionSigner::from_hex(&required_env(
        "PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_HEX",
    )?)?);
    let mut gateway = Gateway::new(engine, journal, dispatcher, execution_signer)?;
    for verifier in approval_verifiers {
        gateway = gateway.with_human_approval_verifier(verifier);
    }
    Ok(gateway)
}

/// `http`/`sandbox` require the file-based revocation snapshot; only the
/// local demo may fall back to the demo provider that never checks
/// revocation.
fn freshness_provider(
    production_adapter: bool,
    policy_digest: String,
) -> Result<Arc<dyn FreshnessProvider>, Box<dyn std::error::Error>> {
    match env::var("PRAETORE_GATEWAY_FRESHNESS_FILE") {
        Ok(path) => {
            let defaults = FileFreshnessLimits::default();
            let limits = FileFreshnessLimits {
                reload_interval: env_duration_ms(
                    "PRAETORE_GATEWAY_FRESHNESS_RELOAD_INTERVAL_MS",
                    defaults.reload_interval.as_millis() as u64,
                )?,
                lease: time::Duration::try_from(env_duration_ms(
                    "PRAETORE_GATEWAY_FRESHNESS_LEASE_MS",
                    defaults.lease.whole_milliseconds() as u64,
                )?)?,
                max_snapshot_validity: time::Duration::try_from(env_duration_ms(
                    "PRAETORE_GATEWAY_FRESHNESS_MAX_SNAPSHOT_VALIDITY_MS",
                    defaults.max_snapshot_validity.whole_milliseconds() as u64,
                )?)?,
            };
            if limits.lease > time::Duration::minutes(1) {
                return Err("PRAETORE_GATEWAY_FRESHNESS_LEASE_MS must be at most 60000".into());
            }
            Ok(Arc::new(FileFreshnessProvider::new(
                path,
                policy_digest,
                limits,
            )?))
        }
        Err(_) if production_adapter => Err(
            "PRAETORE_GATEWAY_FRESHNESS_FILE is required with the http and sandbox adapters; the demo freshness provider never checks revocation"
                .into(),
        ),
        Err(_) => {
            tracing::warn!(
                "local-demo adapter: demo freshness provider grants leases without checking revocation"
            );
            Ok(Arc::new(DemoFreshnessProvider::new(policy_digest)))
        }
    }
}

/// Per-tenant approver bindings, or a single approver key that is unscoped
/// only for the local demo and bound to the sole tenant otherwise.
fn approval_verifiers(
    tenant_issuer_bindings: Option<&HashMap<Uuid, Vec<String>>>,
) -> Result<Vec<HumanApprovalVerifier>, Box<dyn std::error::Error>> {
    let issuer_tenants: Option<HashSet<Uuid>> =
        tenant_issuer_bindings.map(|bindings| bindings.keys().copied().collect());
    let single_key = (
        env::var("PRAETORE_GATEWAY_APPROVER_KEY_ID"),
        env::var("PRAETORE_GATEWAY_APPROVER_PUBLIC_KEY_HEX"),
    );
    match (env::var("PRAETORE_GATEWAY_APPROVER_BINDINGS_FILE"), single_key) {
        (Ok(_), (Ok(_), _) | (_, Ok(_))) => Err(
            "set either PRAETORE_GATEWAY_APPROVER_BINDINGS_FILE or the single approver key variables, not both"
                .into(),
        ),
        (Ok(path), _) => parse_approver_bindings(
            &read_limited(&path, 1_048_576)?,
            issuer_tenants.as_ref(),
        ),
        (Err(_), (Ok(key_id), Ok(public_key_hex))) => Ok(vec![single_approver(
            &key_id,
            &public_key_hex,
            issuer_tenants.as_ref(),
        )?]),
        (Err(_), _) => Err(
            "PRAETORE_GATEWAY_APPROVER_BINDINGS_FILE or PRAETORE_GATEWAY_APPROVER_KEY_ID and PRAETORE_GATEWAY_APPROVER_PUBLIC_KEY_HEX are required"
                .into(),
        ),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let database_url = required_env("PRAETORE_GATEWAY_DATABASE_URL")?;
    let evidence_key_hex = required_env("PRAETORE_GATEWAY_EVIDENCE_ATTESTER_KEY_HEX")?;
    let execution_key_hex = required_env("PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_HEX")?;
    validate_secret_key(&evidence_key_hex, "evidence attester")?;
    validate_secret_key(&execution_key_hex, "execution attester")?;

    let adapter_setup = match env::var("PRAETORE_GATEWAY_ADAPTER").as_deref() {
        Ok("http") => {
            let route_path = required_env("PRAETORE_GATEWAY_TOOL_ROUTES_FILE")?;
            let route_config = read_limited(&route_path, 65_536)?;
            let bindings_path = required_env("PRAETORE_GATEWAY_TENANT_ISSUER_BINDINGS_FILE")?;
            let bindings = parse_tenant_issuer_bindings(&read_limited(&bindings_path, 1_048_576)?)?;
            let audience = required_env("PRAETORE_GATEWAY_AUDIENCE")?;
            GatewayAdapterSetup {
                dispatcher: Arc::new(
                    praetore_gateway_service::http_dispatcher::HttpActionDispatcher::from_json_with_required_egress_proxy(&route_config)?,
                ),
                tenant_issuer_bindings: Some(bindings),
                audience,
                require_trusted_clock: true,
                production_adapter: true,
            }
        }
        Ok("sandbox") => {
            let endpoint = required_env("PRAETORE_GATEWAY_SANDBOX_SUPERVISOR_URL")?;
            let ca_path = required_env("PRAETORE_GATEWAY_SANDBOX_CA_FILE")?;
            let identity_path = required_env("PRAETORE_GATEWAY_SANDBOX_CLIENT_IDENTITY_FILE")?;
            let bindings_path = required_env("PRAETORE_GATEWAY_TENANT_ISSUER_BINDINGS_FILE")?;
            let bindings = parse_tenant_issuer_bindings(&read_limited(&bindings_path, 1_048_576)?)?;
            let audience = required_env("PRAETORE_GATEWAY_AUDIENCE")?;
            GatewayAdapterSetup {
                dispatcher: Arc::new(
                    praetore_gateway_service::sandbox_dispatcher::SandboxActionDispatcher::from_pem_files(
                        &endpoint,
                        &ca_path,
                        &identity_path,
                    )?,
                ),
                tenant_issuer_bindings: Some(bindings),
                audience,
                require_trusted_clock: true,
                production_adapter: true,
            }
        }
        Ok("local-demo") | Err(_) => GatewayAdapterSetup {
            dispatcher: Arc::new(LocalDemoDispatcher::new()),
            tenant_issuer_bindings: None,
            audience: "praetore-local-demo".to_owned(),
            require_trusted_clock: false,
            production_adapter: false,
        },
        Ok(_) => {
            return Err("PRAETORE_GATEWAY_ADAPTER must be sandbox, http, or local-demo".into());
        }
    };
    let approval_verifiers = approval_verifiers(adapter_setup.tenant_issuer_bindings.as_ref())?;
    let gateway = Arc::new(build_gateway(
        &database_url,
        adapter_setup.dispatcher,
        adapter_setup.tenant_issuer_bindings,
        &adapter_setup.audience,
        adapter_setup.require_trusted_clock,
        adapter_setup.production_adapter,
        approval_verifiers,
    )?);
    apply_migrations(&database_url)?;
    let address = match env::var("PRAETORE_GATEWAY_LISTEN_ADDR") {
        Ok(address) => address.parse::<std::net::SocketAddr>()?,
        Err(_) => {
            let port = env::var("PRAETORE_GATEWAY_PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse::<u16>()?;
            if port == 0 {
                return Err("PRAETORE_GATEWAY_PORT must be between 1 and 65535".into());
            }
            std::net::SocketAddr::from(([127, 0, 0, 1], port))
        }
    };
    if address.port() == 0 {
        return Err("gateway listener port must be between 1 and 65535".into());
    }
    let credentials = env::var("PRAETORE_GATEWAY_API_CREDENTIALS_FILE")
        .ok()
        .map(|path| read_limited(&path, 1_048_576))
        .transpose()?;
    let api_auth = select_api_auth(
        adapter_setup.production_adapter,
        address,
        credentials.as_deref(),
    )?;
    if !api_auth.is_required() {
        tracing::warn!(
            %address,
            "local demo: HTTP API has no caller authentication; loopback only"
        );
    }

    tracing::warn!(
        %address,
        loopback_only = address.ip().is_loopback(),
        api_authentication = api_auth.is_required(),
        "plain HTTP service: do not expose without private-network policy and authenticated TLS termination"
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&address).await?;
        tracing::info!(%address, "PRÆTORE local demo gateway listening");
        axum::serve(listener, http_api::router(gateway, api_auth)).await?;
        Ok::<_, std::io::Error>(())
    })?;
    Ok(())
}

fn env_duration_ms(name: &str, default: u64) -> Result<StdDuration, Box<dyn std::error::Error>> {
    let value = env::var(name)
        .map(|value| value.parse::<u64>())
        .unwrap_or(Ok(default))?;
    if value == 0 {
        return Err(format!("{name} must be greater than zero").into());
    }
    Ok(StdDuration::from_millis(value))
}

fn validate_secret_key(value: &str, description: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        return Err(format!("{description} key must be exactly 32 bytes").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use praetore_core::VerifiedPublicKey;

    #[test]
    fn execution_signer_produces_ed25519_signatures_with_stable_key_id() {
        let signer = LocalExecutionSigner::from_hex(&hex::encode([21; 32])).unwrap();
        let signature = signer.sign(b"demo payload").unwrap();
        let public_key =
            VerifiedPublicKey::from_bytes(&signer.signing_key.verifying_key().to_bytes()).unwrap();

        assert!(
            public_key
                .verify_domain_message(b"", b"demo payload", &signature)
                .is_ok()
        );
        assert_eq!(
            signer.key_id(),
            LocalExecutionSigner::from_hex(&hex::encode([21; 32]))
                .unwrap()
                .key_id()
        );
    }

    #[test]
    fn invalid_secret_key_lengths_are_rejected() {
        assert!(validate_secret_key(&hex::encode([0; 31]), "test").is_err());
        assert!(validate_secret_key(&hex::encode([0; 32]), "test").is_ok());
    }

    #[test]
    fn tenant_issuer_bindings_reject_reused_keys_and_tenants() {
        let tenant_a = Uuid::from_u128(1);
        let tenant_b = Uuid::from_u128(2);
        let issuer_key_id = "0123456789abcdef".repeat(4);
        let valid = format!(
            r#"{{"schema_version":1,"tenants":[{{"tenant_id":"{tenant_a}","issuer_key_ids":["{issuer_key_id}"]}}]}}"#
        );
        let bindings = parse_tenant_issuer_bindings(&valid).unwrap();
        assert_eq!(bindings[&tenant_a], vec![issuer_key_id.clone()]);

        let duplicate_key = format!(
            r#"{{"schema_version":1,"tenants":[{{"tenant_id":"{tenant_a}","issuer_key_ids":["{issuer_key_id}"]}},{{"tenant_id":"{tenant_b}","issuer_key_ids":["{issuer_key_id}"]}}]}}"#
        );
        assert!(parse_tenant_issuer_bindings(&duplicate_key).is_err());

        let duplicate_tenant = format!(
            r#"{{"schema_version":1,"tenants":[{{"tenant_id":"{tenant_a}","issuer_key_ids":["{issuer_key_id}"]}},{{"tenant_id":"{tenant_a}","issuer_key_ids":["{}"]}}]}}"#,
            "fedcba9876543210".repeat(4)
        );
        assert!(parse_tenant_issuer_bindings(&duplicate_tenant).is_err());
    }

    #[test]
    fn issuer_pin_loader_accepts_single_pin_and_pin_array() {
        let first_key = praetore_core::AgentKeyPair::generate();
        let second_key = praetore_core::AgentKeyPair::generate();
        let first_pin = TrustedAuthorityIssuer::new("tenant-one", first_key.public_key()).unwrap();
        let second_pin =
            TrustedAuthorityIssuer::new("tenant-two", second_key.public_key()).unwrap();

        assert_eq!(
            load_issuer_pins(&first_pin.export_pin_json().unwrap())
                .unwrap()
                .len(),
            1
        );
        let pins = format!(
            "[{},{}]",
            first_pin.export_pin_json().unwrap(),
            second_pin.export_pin_json().unwrap()
        );
        assert_eq!(load_issuer_pins(&pins).unwrap().len(), 2);
    }

    #[test]
    fn remote_database_hosts_are_rejected_by_local_demo() {
        assert!(validate_local_database_url("postgres://localhost/praetore").is_ok());
        assert!(validate_local_database_url("postgres://127.0.0.1/praetore").is_ok());
        assert!(validate_local_database_url("postgres://db.internal/praetore").is_err());
    }
}
