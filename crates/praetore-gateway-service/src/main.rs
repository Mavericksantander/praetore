use ed25519_dalek::{Signer, SigningKey};
use postgres::{Client, NoTls};
use praetore_core::{
    EvidenceAttesterKey, FreshnessError, FreshnessLease, FreshnessProvider, HighAssuranceConfig,
    Policy, TrustedAuthorityIssuer, VerifiedPublicKey, engine::AuthorizationEngine,
    identity::AgentKeyFingerprint,
};
use praetore_gateway::{
    ExecutionAttestationError, ExecutionAttestationSigner, Gateway, HumanApprovalVerifier,
    http_api, local_demo::LocalDemoDispatcher,
};
use praetore_replay_postgres::{PostgresExecutionJournal, PostgresReplayGuard};
use std::{env, fs, path::Path, str::FromStr, sync::Arc};
use time::{Duration, OffsetDateTime};
use tracing_subscriber::EnvFilter;

const MIGRATIONS: [&str; 6] = [
    include_str!("../../praetore-replay-postgres/migrations/0001_replay_claims.sql"),
    include_str!("../../praetore-replay-postgres/migrations/0002_execution_journal.sql"),
    include_str!("../../praetore-replay-postgres/migrations/0003_execution_replay_link.sql"),
    include_str!("../../praetore-replay-postgres/migrations/0004_execution_journal_events.sql"),
    include_str!("../../praetore-replay-postgres/migrations/0005_execution_attestations.sql"),
    include_str!("../../praetore-replay-postgres/migrations/0006_human_approvals.sql"),
];

struct LocalFreshnessProvider {
    policy_digest: String,
}

impl FreshnessProvider for LocalFreshnessProvider {
    fn check(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &praetore_core::AuthorityId,
        policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        if policy_digest != self.policy_digest {
            return Err(FreshnessError::Revoked);
        }
        Ok(FreshnessLease {
            valid_until: now + Duration::seconds(30),
        })
    }

    fn check_authority(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &praetore_core::AuthorityId,
        authority_digest: &str,
        policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        if authority_digest.len() != 64
            || !authority_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || policy_digest != self.policy_digest
        {
            return Err(FreshnessError::InvalidResponse);
        }
        self.check(_agent, _authority_id, policy_digest, now)
    }
}

struct LocalExecutionSigner {
    key_id: String,
    signing_key: SigningKey,
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

fn apply_migrations(database_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    validate_local_database_url(database_url)?;
    let mut client = Client::connect(database_url, NoTls)?;
    for migration in MIGRATIONS {
        client.batch_execute(migration)?;
    }
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

fn build_gateway(database_url: &str) -> Result<Gateway, Box<dyn std::error::Error>> {
    let policy_path = required_env("PRAETORE_GATEWAY_POLICY_FILE")?;
    let issuer_pin_path = required_env("PRAETORE_GATEWAY_ISSUER_PIN_FILE")?;
    let policy = Policy::from_json(&read_limited(&policy_path, 1_048_576)?)?;
    if policy.semantics_version != 2 {
        return Err("gateway service requires policy semantics version 2".into());
    }
    let policy_digest = policy.digest()?;
    let issuer_pin = TrustedAuthorityIssuer::from_pin_json(&read_limited(&issuer_pin_path, 8192)?)?;
    let evidence_key_hex = required_env("PRAETORE_GATEWAY_EVIDENCE_ATTESTER_KEY_HEX")?;
    let evidence_key_bytes: [u8; 32] = hex::decode(evidence_key_hex)?
        .try_into()
        .map_err(|_| "evidence attester key must be exactly 32 bytes")?;
    let evidence_attester = EvidenceAttesterKey::from_secret_bytes(&evidence_key_bytes);

    let config =
        HighAssuranceConfig::new(policy_digest.clone(), vec![issuer_pin], evidence_attester)?
            .with_audience("praetore-local-demo")
            .with_replay_guard(Arc::new(PostgresReplayGuard::from_client(Client::connect(
                database_url,
                NoTls,
            )?)))
            .with_freshness_provider(Arc::new(LocalFreshnessProvider { policy_digest }));
    let engine = AuthorizationEngine::production(policy, config)?;

    let journal = Arc::new(PostgresExecutionJournal::from_connection_factory({
        let database_url = database_url.to_owned();
        move || Client::connect(&database_url, NoTls)
    })?);
    let dispatcher = Arc::new(LocalDemoDispatcher::new());
    let execution_signer = Arc::new(LocalExecutionSigner::from_hex(&required_env(
        "PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_HEX",
    )?)?);
    let approval_key_id = required_env("PRAETORE_GATEWAY_APPROVER_KEY_ID")?;
    let approval_public_key = VerifiedPublicKey::from_bytes(&hex::decode(required_env(
        "PRAETORE_GATEWAY_APPROVER_PUBLIC_KEY_HEX",
    )?)?)?;
    let approval_verifier = HumanApprovalVerifier::new(approval_key_id, approval_public_key)?;

    Ok(Gateway::new(engine, journal, dispatcher, execution_signer)?
        .with_human_approval_verifier(approval_verifier))
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

    apply_migrations(&database_url)?;
    let gateway = Arc::new(build_gateway(&database_url)?);
    let port = env::var("PRAETORE_GATEWAY_PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse::<u16>()?;
    if port == 0 {
        return Err("PRAETORE_GATEWAY_PORT must be between 1 and 65535".into());
    }
    let address = format!("127.0.0.1:{port}");

    tracing::warn!(
        %address,
        "local demo only: loopback HTTP, local freshness, in-memory tool adapter, no production API"
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&address).await?;
        tracing::info!(%address, "PRÆTORE local demo gateway listening");
        axum::serve(listener, http_api::router(gateway)).await?;
        Ok::<_, std::io::Error>(())
    })?;
    Ok(())
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
    fn remote_database_hosts_are_rejected_by_local_demo() {
        assert!(validate_local_database_url("postgres://localhost/praetore").is_ok());
        assert!(validate_local_database_url("postgres://127.0.0.1/praetore").is_ok());
        assert!(validate_local_database_url("postgres://db.internal/praetore").is_err());
    }
}
