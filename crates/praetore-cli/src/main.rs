use ed25519_dalek::SigningKey;
use postgres::{Client, NoTls};
use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, AuthorizationRequest, EvidenceAttesterKey,
    FreshnessError, FreshnessLease, FreshnessProvider, HighAssuranceConfig, Policy, PolicyEffect,
    PolicyRule, TrustedAuthorityIssuer, authority::Validity, engine::AuthorizationEngine,
    identity::AgentKeyFingerprint,
};
use praetore_gateway::{
    ActionDispatcher, ExecutionAttestationError, ExecutionAttestationSigner, Gateway, http_api,
    local_demo::LocalDemoDispatcher,
};
use praetore_replay_postgres::{PostgresExecutionJournal, PostgresReplayGuard};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fs,
    io::{self, Write},
    net::IpAddr,
    path::Path,
    str::FromStr,
    sync::Arc,
    time::Duration as StdDuration,
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const POLICY_FILE: &str = "policy.json";
const ISSUER_PIN_FILE: &str = "issuer-pin.json";
const ISSUER_KEY_FILE: &str = "issuer.key";
const EVIDENCE_KEY_FILE: &str = "evidence-attester.key";
const EXECUTION_KEY_FILE: &str = "execution-attester.key";
const CONFIG_FILE: &str = "config.json";
const MAX_POLICY_BYTES: u64 = 1_048_576;
const AUDIENCE: &str = "praetore-local-demo";
const REQUIRED_DATABASE_TABLES: [&str; 5] = [
    "praetore.replay_claims",
    "praetore.execution_journal",
    "praetore.execution_journal_events",
    "praetore.execution_attestations",
    "praetore.human_approvals",
];

const MIGRATIONS: [&str; 8] = [
    include_str!("../../praetore-replay-postgres/migrations/0001_replay_claims.sql"),
    include_str!("../../praetore-replay-postgres/migrations/0002_execution_journal.sql"),
    include_str!("../../praetore-replay-postgres/migrations/0003_execution_replay_link.sql"),
    include_str!("../../praetore-replay-postgres/migrations/0004_execution_journal_events.sql"),
    include_str!("../../praetore-replay-postgres/migrations/0005_execution_attestations.sql"),
    include_str!("../../praetore-replay-postgres/migrations/0006_human_approvals.sql"),
    include_str!("../../praetore-replay-postgres/migrations/0007_tenant_scoped_execution.sql"),
    include_str!("../../praetore-replay-postgres/migrations/0008_tenant_row_level_security.sql"),
];

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalConfig {
    schema_version: u8,
    tenant_id: Uuid,
    port: u16,
}

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
        agent: &AgentKeyFingerprint,
        authority_id: &praetore_core::AuthorityId,
        authority_digest: &str,
        policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        if authority_digest.len() != 64
            || !authority_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(FreshnessError::InvalidResponse);
        }
        self.check(agent, authority_id, policy_digest, now)
    }
}

struct LocalExecutionSigner {
    key_id: String,
    signing_key: SigningKey,
}

impl LocalExecutionSigner {
    fn from_secret(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        let key_id = format!(
            "local-demo-{}",
            hex::encode(signing_key.verifying_key().as_bytes())
        );
        Self {
            key_id,
            signing_key,
        }
    }
}

impl ExecutionAttestationSigner for LocalExecutionSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ExecutionAttestationError> {
        use ed25519_dalek::Signer;
        Ok(self.signing_key.sign(message).to_bytes().to_vec())
    }
}

fn main() {
    if let Err(error) = run_cli() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return Err("a command is required".into());
    };

    match command.as_str() {
        "init" => {
            let directory = required_argument(&mut args, "directory")?;
            let mut port = 8080;
            while let Some(argument) = args.next() {
                if argument != "--port" {
                    return Err(format!("unexpected argument: {argument}").into());
                }
                port = required_argument(&mut args, "port")?.parse()?;
                if port == 0 {
                    return Err("port must be between 1 and 65535".into());
                }
            }
            initialize(Path::new(&directory), port)
        }
        "doctor" => {
            let directory = required_argument(&mut args, "directory")?;
            ensure_no_arguments(args)?;
            doctor(Path::new(&directory))
        }
        "run" => {
            let directory = required_argument(&mut args, "directory")?;
            ensure_no_arguments(args)?;
            run_gateway(Path::new(&directory))
        }
        "demo" => {
            let directory = required_argument(&mut args, "directory")?;
            let action = required_argument(&mut args, "action")?;
            if action != "set" {
                return Err("the only supported demo action is 'set'".into());
            }
            let key = required_argument(&mut args, "key")?;
            let value = required_argument(&mut args, "value")?;
            ensure_no_arguments(args)?;
            execute_demo(Path::new(&directory), &key, &value)
        }
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        _ => {
            print_usage();
            Err(format!("unknown command: {command}").into())
        }
    }
}

fn required_argument(
    args: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| format!("missing {name} argument").into())
}

fn ensure_no_arguments(
    args: impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(argument) = args.into_iter().next() {
        return Err(format!("unexpected argument: {argument}").into());
    }
    Ok(())
}

fn print_usage() {
    println!(
        "PRÆTORE local PostgreSQL demo\n\
         \n\
         Commands:\n\
           praetore init <directory> [--port <port>]\n\
           praetore doctor <directory>\n\
           praetore run <directory>\n\
           praetore demo <directory> set <key> <value>\n\
         \n\
         Configure PRAETORE_GATEWAY_DATABASE_URL with a local PostgreSQL URL before doctor/run."
    );
}

fn initialize(directory: &Path, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    if port == 0 {
        return Err("port must be between 1 and 65535".into());
    }
    create_private_directory(directory)?;

    let now = OffsetDateTime::now_utc();
    let issuer_key_bytes = random_secret()?;
    let evidence_key_bytes = random_secret()?;
    let execution_key_bytes = random_secret()?;
    let issuer_key = AgentKeyPair::from_secret_bytes(&issuer_key_bytes);
    let issuer_pin =
        TrustedAuthorityIssuer::new("praetore-local-demo-issuer", issuer_key.public_key())?
            .with_validity(Validity {
                not_before: Some(timestamp(now - Duration::minutes(5))?),
                not_after: Some(timestamp(now + Duration::days(365))?),
            })?;
    let tenant_id = Uuid::new_v4();
    let policy = demo_policy();
    let config = LocalConfig {
        schema_version: 1,
        tenant_id,
        port,
    };

    write_private_file(
        &directory.join(CONFIG_FILE),
        &serde_json::to_vec_pretty(&config)?,
    )?;
    write_private_file(
        &directory.join(POLICY_FILE),
        &serde_json::to_vec_pretty(&policy)?,
    )?;
    write_private_file(
        &directory.join(ISSUER_PIN_FILE),
        issuer_pin.export_pin_json()?.as_bytes(),
    )?;
    write_private_file(
        &directory.join(ISSUER_KEY_FILE),
        hex::encode(issuer_key_bytes).as_bytes(),
    )?;
    write_private_file(
        &directory.join(EVIDENCE_KEY_FILE),
        hex::encode(evidence_key_bytes).as_bytes(),
    )?;
    write_private_file(
        &directory.join(EXECUTION_KEY_FILE),
        hex::encode(execution_key_bytes).as_bytes(),
    )?;

    println!("Initialized local demo at {}", directory.display());
    println!("Private keys were generated locally with owner-only file permissions.");
    println!("Next, set PRAETORE_GATEWAY_DATABASE_URL to a local PostgreSQL database URL.");
    println!("Then run: praetore doctor {}", directory.display());
    println!(
        "This demo has no authentication on its loopback HTTP API and is not production key custody."
    );
    Ok(())
}

fn demo_policy() -> Policy {
    Policy::new_v2(
        "praetore-local-demo",
        1,
        vec![
            PolicyRule::new("allow-demo-set", "demo:set_value", PolicyEffect::Allow)
                .with_capability("demo:write")
                .with_target("demo-state"),
        ],
    )
}

fn random_secret() -> Result<[u8; 32], io::Error> {
    let mut secret = [0u8; 32];
    OsRng.try_fill_bytes(&mut secret).map_err(|error| {
        io::Error::other(format!("operating-system key generation failed: {error}"))
    })?;
    Ok(secret)
}

fn timestamp(value: OffsetDateTime) -> Result<String, time::error::Format> {
    value.to_offset(time::UtcOffset::UTC).format(&Rfc3339)
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_directory(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Err("secure owner-only key storage is currently supported only on Unix".into())
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn load_config(directory: &Path) -> Result<LocalConfig, Box<dyn std::error::Error>> {
    let path = directory.join(CONFIG_FILE);
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err("config.json must be a regular file no larger than 4096 bytes".into());
    }
    let config: LocalConfig = serde_json::from_slice(&fs::read(path)?)?;
    if config.schema_version != 1 || config.tenant_id.is_nil() || config.port == 0 {
        return Err("unsupported or invalid local configuration".into());
    }
    Ok(config)
}

fn read_secret(directory: &Path, filename: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let path = directory.join(filename);
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() || metadata.len() > 128 {
        return Err(format!("{filename} must be a regular file no larger than 128 bytes").into());
    }
    check_private_permissions(&path, &metadata)?;
    let encoded = fs::read_to_string(path)?;
    let bytes = hex::decode(encoded.trim())?;
    bytes
        .try_into()
        .map_err(|_| format!("{filename} must contain exactly 32 key bytes").into())
}

#[cfg(unix)]
fn check_private_permissions(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "secret file {} is accessible by group/others; set permissions to 600",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_permissions(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("secret file permissions cannot be verified on this platform".into())
}

fn load_policy(directory: &Path) -> Result<Policy, Box<dyn std::error::Error>> {
    let path = directory.join(POLICY_FILE);
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() || metadata.len() > MAX_POLICY_BYTES {
        return Err("policy.json must be a regular file no larger than 1 MiB".into());
    }
    let policy = Policy::from_json(&fs::read_to_string(path)?)?;
    if policy.semantics_version != 2 {
        return Err("the local gateway requires policy semantics version 2".into());
    }
    Ok(policy)
}

fn load_issuer_pin(directory: &Path) -> Result<TrustedAuthorityIssuer, Box<dyn std::error::Error>> {
    let path = directory.join(ISSUER_PIN_FILE);
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() || metadata.len() > 8192 {
        return Err("issuer-pin.json must be a regular file no larger than 8192 bytes".into());
    }
    Ok(TrustedAuthorityIssuer::from_pin_json(&fs::read_to_string(
        path,
    )?)?)
}

fn doctor(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut healthy = true;
    let config = match load_config(directory) {
        Ok(config) => {
            println!("[ok] local configuration");
            Some(config)
        }
        Err(error) => {
            println!("[failed] local configuration: {error}");
            healthy = false;
            None
        }
    };
    let policy = match load_policy(directory) {
        Ok(policy) => {
            println!("[ok] policy is valid (v2, default-deny)");
            Some(policy)
        }
        Err(error) => {
            println!("[failed] policy: {error}");
            healthy = false;
            None
        }
    };
    let issuer_pin = match load_issuer_pin(directory) {
        Ok(pin) => {
            println!("[ok] issuer pin is valid");
            Some(pin)
        }
        Err(error) => {
            println!("[failed] issuer pin: {error}");
            healthy = false;
            None
        }
    };

    for secret_file in [ISSUER_KEY_FILE, EVIDENCE_KEY_FILE, EXECUTION_KEY_FILE] {
        match read_secret(directory, secret_file) {
            Ok(_) => println!("[ok] {secret_file} exists with owner-only permissions"),
            Err(error) => {
                println!("[failed] {secret_file}: {error}");
                healthy = false;
            }
        }
    }

    if let (Some(pin), Ok(secret)) = (issuer_pin.as_ref(), read_secret(directory, ISSUER_KEY_FILE))
    {
        if AgentKeyPair::from_secret_bytes(&secret)
            .public_key()
            .as_bytes()
            == pin.public_key().as_bytes()
        {
            println!("[ok] issuer key matches the configured trust pin");
        } else {
            println!("[failed] issuer key does not match the configured trust pin");
            healthy = false;
        }
    }

    match env::var("PRAETORE_GATEWAY_DATABASE_URL") {
        Ok(database_url) => match connect_local_database(&database_url) {
            Ok(mut client) => {
                match client.query_one("SELECT 1", &[]) {
                    Ok(_) => println!("[ok] local PostgreSQL connection"),
                    Err(error) => {
                        println!("[failed] PostgreSQL query: {error}");
                        healthy = false;
                    }
                }
                for table in REQUIRED_DATABASE_TABLES {
                    let exists: bool = client
                        .query_one("SELECT to_regclass($1)::text IS NOT NULL", &[&table])?
                        .get(0);
                    if exists {
                        println!("[ok] database table {table}");
                    } else {
                        println!(
                            "[missing] database table {table} (run `praetore run` to apply migrations)"
                        );
                        healthy = false;
                    }
                }
            }
            Err(error) => {
                println!("[failed] PostgreSQL: {error}");
                healthy = false;
            }
        },
        Err(_) => {
            println!("[failed] PRAETORE_GATEWAY_DATABASE_URL is not set");
            healthy = false;
        }
    }

    if let Some(config) = config {
        let endpoint = format!("http://127.0.0.1:{}/healthz", config.port);
        match http_client()?.get(endpoint).send() {
            Ok(response) if response.status().as_u16() == 204 => {
                println!("[ok] local gateway health endpoint")
            }
            Ok(response) => {
                println!(
                    "[failed] gateway health endpoint returned {}",
                    response.status()
                );
                healthy = false;
            }
            Err(_) => {
                println!("[info] gateway is not running on port {}", config.port);
            }
        }
    }

    if !healthy {
        return Err("one or more required checks failed; see diagnostics above".into());
    }
    if policy.is_none() {
        return Err("policy is unavailable".into());
    }
    println!("All required local demo checks passed.");
    Ok(())
}

fn connect_local_database(database_url: &str) -> Result<Client, Box<dyn std::error::Error>> {
    let mut config = postgres::Config::from_str(database_url)?;
    if config.get_hosts().is_empty()
        || config.get_hosts().iter().any(|host| match host {
            postgres::config::Host::Tcp(host) => {
                host != "localhost"
                    && !host
                        .parse::<IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            }
            #[cfg(unix)]
            postgres::config::Host::Unix(_) => false,
        })
    {
        return Err(
            "local demo requires PostgreSQL on localhost, a loopback IP, or a Unix socket".into(),
        );
    }
    config.connect_timeout(StdDuration::from_secs(3));
    Ok(config.connect(NoTls)?)
}

fn apply_migrations(database_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect_local_database(database_url)?;
    for migration in MIGRATIONS {
        client.batch_execute(migration)?;
    }
    Ok(())
}

fn build_gateway(
    directory: &Path,
    config: &LocalConfig,
    database_url: &str,
) -> Result<Gateway, Box<dyn std::error::Error>> {
    let policy = load_policy(directory)?;
    let policy_digest = policy.digest()?;
    let pin = load_issuer_pin(directory)?;
    let issuer_secret = read_secret(directory, ISSUER_KEY_FILE)?;
    if AgentKeyPair::from_secret_bytes(&issuer_secret)
        .public_key()
        .as_bytes()
        != pin.public_key().as_bytes()
    {
        return Err("issuer key does not match the configured trust pin".into());
    }

    let evidence_secret = read_secret(directory, EVIDENCE_KEY_FILE)?;
    let evidence_attester = EvidenceAttesterKey::from_secret_bytes(&evidence_secret);
    let replay_guard = Arc::new(PostgresReplayGuard::from_client(connect_local_database(
        database_url,
    )?));
    let bindings = HashMap::from([(config.tenant_id, vec![pin.key_id().to_owned()])]);
    let high_assurance =
        HighAssuranceConfig::new(policy_digest.clone(), vec![pin], evidence_attester)?
            .with_audience(AUDIENCE)
            .with_tenant_issuer_bindings(bindings)
            .with_replay_guard(replay_guard)
            .with_freshness_provider(Arc::new(LocalFreshnessProvider { policy_digest }));
    let engine = AuthorizationEngine::production(policy, high_assurance)?;
    let journal = Arc::new(PostgresExecutionJournal::from_connection_factory({
        let database_url = database_url.to_owned();
        move || Client::connect(&database_url, NoTls)
    })?);
    let execution_secret = read_secret(directory, EXECUTION_KEY_FILE)?;
    let signer = Arc::new(LocalExecutionSigner::from_secret(&execution_secret));
    let dispatcher: Arc<dyn ActionDispatcher> = Arc::new(LocalDemoDispatcher::new());
    Ok(Gateway::new(engine, journal, dispatcher, signer)?)
}

fn run_gateway(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(directory)?;
    let database_url = env::var("PRAETORE_GATEWAY_DATABASE_URL")
        .map_err(|_| "PRAETORE_GATEWAY_DATABASE_URL must point to local PostgreSQL")?;
    apply_migrations(&database_url)?;
    let gateway = Arc::new(build_gateway(directory, &config, &database_url)?);

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    tracing::warn!(
        port = config.port,
        "local demo uses unauthenticated HTTP on loopback, local freshness, and in-memory tool effects; do not expose or use for production"
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        http_api::serve_local(config.port, gateway).await?;
        Ok::<_, io::Error>(())
    })?;
    Ok(())
}

fn execute_demo(
    directory: &Path,
    key: &str,
    value: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if key.is_empty() || key.len() > 128 || value.len() > 1024 {
        return Err("demo key must be 1-128 bytes and value must be at most 1024 bytes".into());
    }
    let config = load_config(directory)?;
    let policy = load_policy(directory)?;
    let request = build_demo_request(directory, &config, &policy, key, value)?;

    let response = http_client()?
        .post(format!("http://127.0.0.1:{}/v1/execute", config.port))
        .json(&request)
        .send()
        .map_err(|error| {
            format!(
                "could not confirm the gateway response ({error}); execution may have occurred, and the CLI did not retry. Inspect the durable execution journal before taking further action"
            )
        })?;
    let status = response.status();
    let body = response.text()?;
    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
        Err(_) => println!("{body}"),
    }
    if !status.is_success() {
        return Err(format!("gateway returned HTTP {status}; review the receipt above").into());
    }
    Ok(())
}

fn build_demo_request(
    directory: &Path,
    config: &LocalConfig,
    policy: &Policy,
    key: &str,
    value: &str,
) -> Result<AuthorizationRequest, Box<dyn std::error::Error>> {
    let policy_digest = policy.digest()?;
    let issuer_key = AgentKeyPair::from_secret_bytes(&read_secret(directory, ISSUER_KEY_FILE)?);
    let agent_key = AgentKeyPair::generate();
    let agent = agent_key.identity(AgentId::new());
    let now = OffsetDateTime::now_utc();
    let mut authority = Authority::new(
        agent.id.clone(),
        "praetore-local-demo-issuer",
        vec!["demo:write".into()],
    )
    .with_constraint("tenant_id", config.tenant_id.to_string())
    .with_validity(Validity {
        not_before: Some(timestamp(now - Duration::minutes(1))?),
        not_after: Some(timestamp(now + Duration::hours(1))?),
    });
    authority.sign_for_agent(&issuer_key, &agent)?;
    let action = Action::new(
        "demo:set_value",
        Some("demo-state".into()),
        serde_json::json!({"key": key, "value": value}),
    )?
    .with_capability("demo:write");
    let mut request = AuthorizationRequest::new(agent, authority, action)?;
    request.sign_intent_v2(
        &agent_key,
        AUDIENCE,
        now,
        now + Duration::seconds(60),
        policy_digest,
    )?;
    Ok(request)
}

fn http_client() -> Result<reqwest::blocking::Client, reqwest::Error> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(StdDuration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn initialization_creates_owner_only_keys_and_default_deny_policy() {
        let directory = env::temp_dir().join(format!("praetore-cli-test-{}", Uuid::new_v4()));
        initialize(&directory, 8080).unwrap();
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );

        for filename in [ISSUER_KEY_FILE, EVIDENCE_KEY_FILE, EXECUTION_KEY_FILE] {
            let metadata = fs::metadata(directory.join(filename)).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(read_secret(&directory, filename).unwrap().len(), 32);
        }

        let policy = load_policy(&directory).unwrap();
        let encoded = serde_json::to_string(&policy).unwrap();
        let parsed = Policy::from_json(&encoded).unwrap();
        assert_eq!(parsed.semantics_version, 2);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn initialization_refuses_to_overwrite_an_existing_directory() {
        let directory = env::temp_dir().join(format!("praetore-cli-test-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        assert!(initialize(&directory, 8080).is_err());
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn demo_request_is_signed_for_the_local_policy_audience_and_tenant() {
        let directory = env::temp_dir().join(format!("praetore-cli-test-{}", Uuid::new_v4()));
        initialize(&directory, 8080).unwrap();
        let config = load_config(&directory).unwrap();
        let policy = load_policy(&directory).unwrap();
        let request = build_demo_request(&directory, &config, &policy, "status", "ready").unwrap();

        request.verify_intent_signature().unwrap();
        load_issuer_pin(&directory)
            .unwrap()
            .verify_authority_at(&request.authority, OffsetDateTime::now_utc())
            .unwrap();
        assert_eq!(
            request
                .intent_v2
                .as_ref()
                .map(|intent| intent.audience.as_str()),
            Some(AUDIENCE)
        );
        assert_eq!(request.authority.tenant_id(), Some(config.tenant_id));
        assert_eq!(request.action.action_type, "demo:set_value");
        assert_eq!(request.action.target.as_deref(), Some("demo-state"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn demo_policy_denies_actions_outside_its_single_allow_rule() {
        let policy = demo_policy();
        let agent = AgentKeyPair::generate().identity(AgentId::new());
        let authority = Authority::new(
            agent.id.clone(),
            "praetore-local-demo-issuer",
            vec!["demo:write".into()],
        )
        .with_constraint("tenant_id", Uuid::new_v4().to_string());
        let action = Action::new(
            "demo:delete_all",
            Some("demo-state".into()),
            serde_json::json!({}),
        )
        .unwrap()
        .with_capability("demo:write");

        assert_eq!(
            policy
                .evaluate(&agent, &authority, &action)
                .unwrap()
                .outcome,
            praetore_core::DecisionOutcome::Deny
        );
    }

    #[test]
    fn secret_files_with_group_or_other_permissions_are_rejected() {
        let directory = env::temp_dir().join(format!("praetore-cli-test-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join(ISSUER_KEY_FILE);
        fs::write(&path, hex::encode([1u8; 32])).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_secret(&directory, ISSUER_KEY_FILE).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
