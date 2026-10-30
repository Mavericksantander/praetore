use ed25519_dalek::{Signer, SigningKey};
use postgres::Client;
use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, AuthorizationRequest, EvidenceAttesterKey,
    FreshnessError, FreshnessLease, FreshnessProvider, HighAssuranceConfig, Policy, PolicyEffect,
    PolicyRule, TrustedAuthorityIssuer, authority::Validity, engine::AuthorizationEngine,
    identity::AgentKeyFingerprint,
};
use praetore_gateway::{
    ActionDispatcher, ApprovalChallenge, ApprovalChallengeView, ExecutionAttestationError,
    ExecutionAttestationSigner, Gateway, HumanApprovalDecision, HumanApprovalOutcome,
    HumanApprovalVerifier, http_api, local_demo::LocalDemoDispatcher,
};
use praetore_replay_postgres::{DatabaseConnector, PostgresExecutionJournal, PostgresReplayGuard};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fs,
    io::{self, Write},
    path::Path,
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
const APPROVER_KEY_FILE: &str = "approver.key";
const APPROVER_PIN_FILE: &str = "approver-pin.json";
const LOCAL_APPROVER_ID: &str = "local-approver";
/// Bearer token the demo agent (`praetore demo`) presents to the gateway.
const AGENT_TOKEN_FILE: &str = "agent-api.token";
/// Bearer token the human approver (`approve`/`reject`/`dispatch`) presents.
const APPROVER_TOKEN_FILE: &str = "approver-api.token";
const MAX_POLICY_BYTES: u64 = 1_048_576;
const AUDIENCE: &str = "praetore-local-demo";
const REQUIRED_DATABASE_TABLES: [&str; 6] = [
    "praetore.replay_claims",
    "praetore.execution_journal",
    "praetore.execution_journal_events",
    "praetore.execution_attestations",
    "praetore.human_approvals",
    "praetore.human_approval_expirations",
];

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalConfig {
    schema_version: u8,
    tenant_id: Uuid,
    port: u16,
}

/// Public pin of the human approver key. The gateway only needs this pin; the
/// private `approver.key` is used solely by `praetore approve` / `reject`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproverPin {
    schema_version: u8,
    key_id: String,
    public_key_hex: String,
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
        "approve" | "reject" => {
            let outcome = if command == "approve" {
                HumanApprovalOutcome::Approve
            } else {
                HumanApprovalOutcome::Reject
            };
            let directory = required_argument(&mut args, "directory")?;
            let execution_id = required_argument(&mut args, "execution_id")?;
            let mut approver = None;
            let mut agent = None;
            let mut confirmation = Confirmation::Prompt;
            while let Some(flag) = args.next() {
                if flag == "--yes" {
                    confirmation = Confirmation::AssumeYes;
                    continue;
                }
                let slot = match flag.as_str() {
                    "--approver" => &mut approver,
                    "--agent" => &mut agent,
                    _ => return Err(format!("unexpected argument: {flag}").into()),
                };
                if slot.is_some() {
                    return Err(format!("{flag} given more than once").into());
                }
                *slot = Some(required_argument(&mut args, &flag)?);
            }
            let approver = approver.ok_or("missing --approver argument")?;
            resolve_approval(
                Path::new(&directory),
                &execution_id,
                agent.as_deref(),
                &approver,
                outcome,
                confirmation,
            )
        }
        "dispatch" => {
            let directory = required_argument(&mut args, "directory")?;
            let execution_id = required_argument(&mut args, "execution_id")?;
            let agent = match args.next().as_deref() {
                None => None,
                Some("--agent") => Some(required_argument(&mut args, "--agent")?),
                Some(flag) => return Err(format!("unexpected argument: {flag}").into()),
            };
            ensure_no_arguments(args)?;
            dispatch_approved(Path::new(&directory), &execution_id, agent.as_deref())
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
           praetore approve <directory> <request_id> --approver <id> [--agent <agent_id>] [--yes]\n\
           praetore reject <directory> <request_id> --approver <id> [--agent <agent_id>] [--yes]\n\
           praetore dispatch <directory> <request_id> [--agent <agent_id>]\n\
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
    let approver_key_bytes = random_secret()?;
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

    write_private_file(
        &directory.join(APPROVER_KEY_FILE),
        hex::encode(approver_key_bytes).as_bytes(),
    )?;
    // Distinct API credentials for the agent and the approver: the gateway
    // only lets the approver token read challenges, decide and dispatch.
    write_private_file(
        &directory.join(AGENT_TOKEN_FILE),
        hex::encode(random_secret()?).as_bytes(),
    )?;
    write_private_file(
        &directory.join(APPROVER_TOKEN_FILE),
        hex::encode(random_secret()?).as_bytes(),
    )?;
    let approver_pin = ApproverPin {
        schema_version: 1,
        key_id: LOCAL_APPROVER_ID.into(),
        public_key_hex: hex::encode(
            SigningKey::from_bytes(&approver_key_bytes)
                .verifying_key()
                .to_bytes(),
        ),
    };
    write_private_file(
        &directory.join(APPROVER_PIN_FILE),
        &serde_json::to_vec_pretty(&approver_pin)?,
    )?;

    println!("Initialized local demo at {}", directory.display());
    println!("Human approver id: {LOCAL_APPROVER_ID}");
    println!("Private keys were generated locally with owner-only file permissions.");
    println!("Next, set PRAETORE_GATEWAY_DATABASE_URL to a local PostgreSQL database URL.");
    println!("Then run: praetore doctor {}", directory.display());
    println!(
        "The loopback HTTP API requires the generated {AGENT_TOKEN_FILE} / {APPROVER_TOKEN_FILE} bearer tokens; this demo is not production key custody."
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

    for secret_file in [
        ISSUER_KEY_FILE,
        EVIDENCE_KEY_FILE,
        EXECUTION_KEY_FILE,
        AGENT_TOKEN_FILE,
        APPROVER_TOKEN_FILE,
    ] {
        match read_secret(directory, secret_file) {
            Ok(_) => println!("[ok] {secret_file} exists with owner-only permissions"),
            Err(error) => {
                println!("[failed] {secret_file}: {error}");
                healthy = false;
            }
        }
    }

    match load_approver_pin(directory) {
        Ok(Some(pin)) => {
            println!("[ok] approver pin is valid (approver id: {})", pin.key_id);
            match read_secret(directory, APPROVER_KEY_FILE) {
                Ok(secret)
                    if hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
                        == pin.public_key_hex =>
                {
                    println!("[ok] {APPROVER_KEY_FILE} matches the approver pin");
                }
                Ok(_) => {
                    println!("[failed] {APPROVER_KEY_FILE} does not match the approver pin");
                    healthy = false;
                }
                Err(error) => println!("[info] {APPROVER_KEY_FILE} not usable here: {error}"),
            }
        }
        Ok(None) => {
            println!("[info] no {APPROVER_PIN_FILE}; human approval is disabled (fail-closed)")
        }
        Err(error) => {
            println!("[failed] approver pin: {error}");
            healthy = false;
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
                match praetore_replay_postgres::verify_runtime_role(&mut client) {
                    Ok(()) => println!("[ok] least-privilege runtime database role"),
                    Err(error) => println!("[warn] {error} (acceptable for the local demo only)"),
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

/// The demo only talks to loopback PostgreSQL (or a Unix socket). The URL is
/// validated, including its TLS policy, before any connection is made.
fn local_database(database_url: &str) -> Result<DatabaseConnector, Box<dyn std::error::Error>> {
    let connector =
        DatabaseConnector::from_url(database_url)?.connect_timeout(StdDuration::from_secs(3));
    if !connector.is_loopback() {
        return Err(
            "local demo requires PostgreSQL on localhost, a loopback IP, or a Unix socket".into(),
        );
    }
    Ok(connector)
}

fn connect_local_database(database_url: &str) -> Result<Client, Box<dyn std::error::Error>> {
    Ok(local_database(database_url)?.connect()?)
}

/// Development only: without PRAETORE_GATEWAY_MIGRATION_DATABASE_URL the demo
/// migrates with its runtime URL, so the runtime role owns the tables.
fn apply_migrations(database_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect_local_database(database_url)?;
    praetore_replay_postgres::apply_migrations(&mut client)?;
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
        let database = local_database(database_url)?;
        move || database.connect()
    })?);
    let execution_secret = read_secret(directory, EXECUTION_KEY_FILE)?;
    let signer = Arc::new(LocalExecutionSigner::from_secret(&execution_secret));
    let dispatcher: Arc<dyn ActionDispatcher> = Arc::new(LocalDemoDispatcher::new());
    let gateway = Gateway::new(engine, journal, dispatcher, signer)?;
    // Fail closed: without an approver pin the gateway has no verifier and
    // every approval attempt is refused with `approval_not_configured`.
    Ok(match load_approver_verifier(directory, config.tenant_id)? {
        Some(verifier) => gateway.with_human_approval_verifier(verifier),
        None => gateway,
    })
}

fn read_api_token(directory: &Path, filename: &str) -> Result<String, Box<dyn std::error::Error>> {
    read_secret(directory, filename).map(hex::encode).map_err(|error| {
        format!(
            "{filename}: {error}; demo directories created before API authentication need a fresh `praetore init`"
        )
        .into()
    })
}

/// The demo tenant's agent and approver credentials, derived from the
/// owner-only token files created by `praetore init`.
fn local_api_auth(
    directory: &Path,
    config: &LocalConfig,
) -> Result<http_api::ApiAuth, Box<dyn std::error::Error>> {
    let agent = read_api_token(directory, AGENT_TOKEN_FILE)?;
    let approver = read_api_token(directory, APPROVER_TOKEN_FILE)?;
    if agent == approver {
        return Err("agent and approver API tokens must differ".into());
    }
    let document = serde_json::json!({
        "schema_version": 1,
        "credentials": [
            {
                "name": "local-demo-agent",
                "tenant_id": config.tenant_id,
                "role": "agent",
                "token_sha256": http_api::ApiCredentials::token_sha256_hex(&agent),
            },
            {
                "name": "local-demo-approver",
                "tenant_id": config.tenant_id,
                "role": "approver",
                "token_sha256": http_api::ApiCredentials::token_sha256_hex(&approver),
            }
        ]
    });
    Ok(http_api::ApiAuth::required(
        http_api::ApiCredentials::from_json(&document.to_string())?,
    ))
}

fn run_gateway(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(directory)?;
    let database_url = env::var("PRAETORE_GATEWAY_DATABASE_URL")
        .map_err(|_| "PRAETORE_GATEWAY_DATABASE_URL must point to local PostgreSQL")?;
    let migration_url = env::var("PRAETORE_GATEWAY_MIGRATION_DATABASE_URL")
        .unwrap_or_else(|_| database_url.clone());
    apply_migrations(&migration_url)?;
    let runtime_role =
        praetore_replay_postgres::verify_runtime_role(&mut connect_local_database(&database_url)?);
    let api_auth = local_api_auth(directory, &config)?;
    let gateway = Arc::new(build_gateway(directory, &config, &database_url)?);

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    if let Err(error) = runtime_role {
        tracing::warn!(%error, "local demo database role is not least-privilege; development only");
    }
    tracing::warn!(
        port = config.port,
        "local demo uses plain HTTP on loopback with locally generated bearer tokens, local freshness, and in-memory tool effects; do not expose or use for production"
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        http_api::serve_local(config.port, gateway, api_auth).await?;
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
    let agent_token = read_api_token(directory, AGENT_TOKEN_FILE)?;

    let response = http_client()?
        .post(format!("http://127.0.0.1:{}/v1/execute", config.port))
        .bearer_auth(agent_token)
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
    if let Ok(receipt) = serde_json::from_str::<serde_json::Value>(&body)
        && receipt["authorization"] == "requires_approval"
        && let Some(request_id) = receipt["evidence"]["request_id"].as_str()
    {
        eprintln!(
            "Held for human approval. Approval window ends at {} (UTC). Resolve with:\n  praetore approve {} {request_id} --approver {LOCAL_APPROVER_ID}\n  praetore reject {} {request_id} --approver {LOCAL_APPROVER_ID}",
            receipt["evidence"]["freshness_valid_until"]
                .as_str()
                .unwrap_or("unknown"),
            directory.display(),
            directory.display(),
        );
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
    build_demo_request_with_agent_key(
        directory,
        config,
        policy,
        key,
        value,
        &AgentKeyPair::generate(),
    )
}

fn build_demo_request_with_agent_key(
    directory: &Path,
    config: &LocalConfig,
    policy: &Policy,
    key: &str,
    value: &str,
    agent_key: &AgentKeyPair,
) -> Result<AuthorizationRequest, Box<dyn std::error::Error>> {
    let policy_digest = policy.digest()?;
    let issuer_key = AgentKeyPair::from_secret_bytes(&read_secret(directory, ISSUER_KEY_FILE)?);
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
        agent_key,
        AUDIENCE,
        now,
        now + Duration::seconds(60),
        policy_digest,
    )?;
    Ok(request)
}

fn valid_approver_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn load_approver_pin(directory: &Path) -> Result<Option<ApproverPin>, Box<dyn std::error::Error>> {
    let path = directory.join(APPROVER_PIN_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err(format!(
            "{APPROVER_PIN_FILE} must be a regular file no larger than 4096 bytes"
        )
        .into());
    }
    let pin: ApproverPin = serde_json::from_str(&fs::read_to_string(path)?)?;
    if pin.schema_version != 1 || !valid_approver_id(&pin.key_id) {
        return Err(
            format!("{APPROVER_PIN_FILE} has an unsupported schema or invalid key_id").into(),
        );
    }
    let bytes = hex::decode(&pin.public_key_hex)?;
    if bytes.len() != 32 {
        return Err(format!("{APPROVER_PIN_FILE} public key must be 32 bytes").into());
    }
    praetore_core::VerifiedPublicKey::from_bytes(&bytes)?;
    Ok(Some(pin))
}

/// The demo approver is bound to the demo tenant only.
fn load_approver_verifier(
    directory: &Path,
    tenant_id: Uuid,
) -> Result<Option<HumanApprovalVerifier>, Box<dyn std::error::Error>> {
    let Some(pin) = load_approver_pin(directory)? else {
        return Ok(None);
    };
    let public_key =
        praetore_core::VerifiedPublicKey::from_bytes(&hex::decode(&pin.public_key_hex)?)?;
    Ok(Some(HumanApprovalVerifier::for_tenant(
        tenant_id, pin.key_id, public_key,
    )?))
}

/// Whether `approve`/`reject` asks before signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confirmation {
    Prompt,
    /// `--yes`: for scripts that have reviewed the action by other means.
    AssumeYes,
}

/// Escapes control and bidirectional-formatting characters so gateway- or
/// agent-supplied text cannot rewrite the terminal or disguise itself.
fn terminal_safe(text: &str) -> String {
    let mut safe = String::with_capacity(text.len());
    for character in text.chars() {
        let bidi = matches!(
            character,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        );
        if (character.is_control() && character != '\n') || bidi {
            safe.push_str(&format!("\\u{{{:04x}}}", character as u32));
        } else {
            safe.push(character);
        }
    }
    safe
}

/// Checks that the challenge belongs to this execution, that the shown
/// action is exactly the one the challenge's digest commits to, and that it
/// was evaluated under this demo's policy; then renders it for the human.
fn describe_challenge(
    view: &ApprovalChallengeView,
    config: &LocalConfig,
    agent_id: Uuid,
    request_id: Uuid,
    policy_digest: &str,
    outcome: HumanApprovalOutcome,
) -> Result<String, Box<dyn std::error::Error>> {
    let challenge = &view.challenge;
    if challenge.tenant_id != config.tenant_id
        || challenge.agent_id != agent_id
        || challenge.request_id != request_id
    {
        return Err("gateway returned a challenge for a different execution".into());
    }
    if !view.action_matches_challenge() {
        return Err(
            "the action returned by the gateway does not match the challenge's action digest; refusing to sign"
                .into(),
        );
    }
    if challenge.policy_digest != policy_digest {
        return Err(
            "the challenge was evaluated under a different policy than this demo's policy.json; refusing to sign"
                .into(),
        );
    }
    let action = &view.action;
    let quoted = |value: Option<&str>| {
        value
            .map(|value| serde_json::to_string(value).unwrap_or_default())
            .unwrap_or_else(|| "(none)".into())
    };
    let parameters = serde_json::to_string_pretty(&action.parameters)?
        .lines()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    let decision = match outcome {
        HumanApprovalOutcome::Approve => "APPROVE",
        HumanApprovalOutcome::Reject => "REJECT",
    };
    Ok(terminal_safe(&format!(
        "Approval request\n  \
         tenant:         {}\n  \
         agent:          {}\n  \
         request:        {}\n  \
         action type:    {}\n  \
         target:         {}\n  \
         capability:     {}\n  \
         parameters:\n{parameters}\n  \
         action digest:  {} (recomputed from the action above: match)\n  \
         policy digest:  {} (this demo's policy.json)\n  \
         expires at:     {} (UTC)\n\
         Decision to sign: {decision}",
        challenge.tenant_id,
        challenge.agent_id,
        challenge.request_id,
        quoted(Some(&action.action_type)),
        quoted(action.target.as_deref()),
        quoted(action.capability.as_deref()),
        challenge.action_digest,
        challenge.policy_digest,
        challenge.expires_at,
    )))
}

fn confirm_decision(confirmation: Confirmation) -> Result<(), Box<dyn std::error::Error>> {
    if confirmation == Confirmation::AssumeYes {
        return Ok(());
    }
    print!("Type 'yes' to sign and submit this decision: ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "yes" | "y") {
        Ok(())
    } else {
        Err("decision not confirmed; nothing was signed or sent".into())
    }
}

/// Looks up the pending execution for `request_id` in this demo's tenant.
/// Fails closed unless exactly one journal row matches.
fn find_pending_agent(
    database_url: &str,
    tenant_id: Uuid,
    request_id: Uuid,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let mut client = connect_local_database(database_url)?;
    let mut transaction = client.build_transaction().read_only(true).start()?;
    transaction.query_one(
        "SELECT set_config('praetore.tenant_id', $1, true)",
        &[&tenant_id.to_string()],
    )?;
    let rows = transaction.query(
        "SELECT agent_id FROM praetore.execution_journal \
         WHERE tenant_id = $1 AND request_id = $2 LIMIT 2",
        &[&tenant_id, &request_id],
    )?;
    transaction.commit()?;
    match rows.as_slice() {
        [row] => Ok(row.get(0)),
        [] => Err("execution not found for this demo tenant".into()),
        _ => Err("execution id is ambiguous; refusing to resolve approval".into()),
    }
}

fn sign_decision(
    challenge: ApprovalChallenge,
    approver_id: &str,
    outcome: HumanApprovalOutcome,
    signing_key: &SigningKey,
) -> Result<HumanApprovalDecision, Box<dyn std::error::Error>> {
    let mut decision = HumanApprovalDecision {
        schema_version: 1,
        approval_id: Uuid::new_v4(),
        approver_key_id: approver_id.to_owned(),
        challenge,
        outcome,
        signature: String::new(),
    };
    decision.signature = hex::encode(signing_key.sign(&decision.signing_message()?).to_bytes());
    Ok(decision)
}

fn resolve_approval(
    directory: &Path,
    execution_id: &str,
    agent_id: Option<&str>,
    approver_id: &str,
    outcome: HumanApprovalOutcome,
    confirmation: Confirmation,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_id = Uuid::parse_str(execution_id)
        .ok()
        .filter(|id| !id.is_nil())
        .ok_or("execution_id must be the request_id UUID from the demo receipt")?;
    if !valid_approver_id(approver_id) {
        return Err("approver id must be 1-64 characters of [a-z0-9-]".into());
    }
    let pin = load_approver_pin(directory)?
        .ok_or("this demo directory has no approver pin; human approval is disabled")?;
    if pin.key_id != approver_id {
        return Err("unknown approver id for this demo directory".into());
    }
    let signing_key = SigningKey::from_bytes(&read_secret(directory, APPROVER_KEY_FILE)?);
    if hex::encode(signing_key.verifying_key().to_bytes()) != pin.public_key_hex {
        return Err("approver.key does not match the approver pin".into());
    }
    let config = load_config(directory)?;
    let policy_digest = load_policy(directory)?.digest()?;
    let approver_token = read_api_token(directory, APPROVER_TOKEN_FILE)?;
    let agent_id = resolve_agent_id(&config, request_id, agent_id)?;

    let url = format!(
        "http://127.0.0.1:{}/v1/approvals/{}/{}/{}",
        config.port, config.tenant_id, agent_id, request_id
    );
    let client = http_client()?;
    let response = client.get(&url).bearer_auth(&approver_token).send()?;
    let status = response.status();
    let body = response.text()?;
    if !status.is_success() {
        println!("{}", terminal_safe(&body));
        return Err(format!("gateway refused the approval challenge (HTTP {status})").into());
    }
    let view = ApprovalChallengeView::from_json(&body)
        .map_err(|_| "gateway returned an invalid approval challenge")?;
    println!(
        "{}",
        describe_challenge(
            &view,
            &config,
            agent_id,
            request_id,
            &policy_digest,
            outcome
        )?
    );
    confirm_decision(confirmation)?;
    let decision = sign_decision(view.challenge, approver_id, outcome, &signing_key)?;
    let response = client
        .post(&url)
        .bearer_auth(&approver_token)
        .json(&decision)
        .send()
        .map_err(|error| {
            format!(
                "could not confirm the gateway response ({error}); the decision may have been recorded and the CLI did not retry. Inspect praetore.human_approvals before taking further action"
            )
        })?;
    let status = response.status();
    let body = response.text()?;
    let value = serde_json::from_str::<serde_json::Value>(&body).ok();
    match &value {
        Some(value) => println!("{}", serde_json::to_string_pretty(value)?),
        None => println!("{body}"),
    }
    if !status.is_success() {
        return Err(format!("gateway returned HTTP {status}; review the response above").into());
    }
    if value.as_ref().and_then(|value| value["status"].as_str())
        == Some("approved_pending_dispatch")
    {
        println!(
            "approved_pending_dispatch: the approval is recorded and the action has NOT run. Dispatch it once with:\n  praetore dispatch {} {request_id} --agent {agent_id}",
            directory.display()
        );
    }
    Ok(())
}

/// The endpoint is addressed by tenant/agent/request. The tenant comes from
/// config.json; the agent is either given explicitly or looked up.
fn resolve_agent_id(
    config: &LocalConfig,
    request_id: Uuid,
    agent_id: Option<&str>,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    match agent_id {
        Some(agent) => Ok(Uuid::parse_str(agent)
            .ok()
            .filter(|id| !id.is_nil())
            .ok_or("--agent must be the evidence.agent.id UUID from the demo receipt")?),
        None => {
            let database_url = env::var("PRAETORE_GATEWAY_DATABASE_URL").map_err(|_| {
                "PRAETORE_GATEWAY_DATABASE_URL must point to local PostgreSQL (or pass --agent)"
            })?;
            find_pending_agent(&database_url, config.tenant_id, request_id)
        }
    }
}

/// Claims and performs the single dispatch of an approved execution. Never
/// retried by the CLI: on a lost response, inspect the journal first.
fn dispatch_approved(
    directory: &Path,
    execution_id: &str,
    agent_id: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_id = Uuid::parse_str(execution_id)
        .ok()
        .filter(|id| !id.is_nil())
        .ok_or("execution_id must be the request_id UUID from the demo receipt")?;
    let config = load_config(directory)?;
    let approver_token = read_api_token(directory, APPROVER_TOKEN_FILE)?;
    let agent_id = resolve_agent_id(&config, request_id, agent_id)?;
    let url = format!(
        "http://127.0.0.1:{}/v1/approvals/{}/{}/{}/dispatch",
        config.port, config.tenant_id, agent_id, request_id
    );
    let response = http_client()?
        .post(&url)
        .bearer_auth(approver_token)
        .send()
        .map_err(|error| {
        format!(
            "could not confirm the gateway response ({error}); the action may have been dispatched and the CLI did not retry. Inspect praetore.execution_journal before taking further action"
        )
    })?;
    let status = response.status();
    let body = response.text()?;
    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
        Err(_) => println!("{body}"),
    }
    if !status.is_success() {
        return Err(format!("gateway returned HTTP {status}; review the response above").into());
    }
    Ok(())
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
    fn initialization_creates_distinct_owner_only_api_tokens() {
        let directory = env::temp_dir().join(format!("praetore-cli-test-{}", Uuid::new_v4()));
        initialize(&directory, 8080).unwrap();
        for filename in [AGENT_TOKEN_FILE, APPROVER_TOKEN_FILE] {
            let metadata = fs::metadata(directory.join(filename)).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
        let agent = read_api_token(&directory, AGENT_TOKEN_FILE).unwrap();
        let approver = read_api_token(&directory, APPROVER_TOKEN_FILE).unwrap();
        assert_eq!(agent.len(), 64);
        assert_ne!(agent, approver);
        let config = load_config(&directory).unwrap();
        assert!(local_api_auth(&directory, &config).unwrap().is_required());

        // Directories from before API authentication fail with guidance.
        fs::remove_file(directory.join(APPROVER_TOKEN_FILE)).unwrap();
        let error = local_api_auth(&directory, &config).unwrap_err();
        assert!(error.to_string().contains("praetore init"));
        fs::remove_dir_all(directory).unwrap();
    }

    fn challenge_view(directory: &Path, config: &LocalConfig) -> (ApprovalChallengeView, String) {
        let policy = load_policy(directory).unwrap();
        let request = build_demo_request(directory, config, &policy, "mode", "safe").unwrap();
        let action_digest = praetore_gateway::action_digest(&request.action).unwrap();
        let policy_digest = policy.digest().unwrap();
        let view = ApprovalChallengeView {
            challenge: ApprovalChallenge {
                schema_version: 1,
                tenant_id: config.tenant_id,
                agent_id: *request.agent.id.as_uuid(),
                request_id: request.request_id,
                evidence_id: Uuid::new_v4(),
                evidence_hash: "a".repeat(64),
                action_digest,
                policy_digest: policy_digest.clone(),
                expires_at: "2026-06-01T12:00:00Z".into(),
            },
            action: request.action,
        };
        (view, policy_digest)
    }

    #[test]
    fn approver_sees_the_exact_action_and_tampering_is_refused() {
        let directory = env::temp_dir().join(format!("praetore-cli-test-{}", Uuid::new_v4()));
        initialize(&directory, 8080).unwrap();
        let config = load_config(&directory).unwrap();
        let (view, policy_digest) = challenge_view(&directory, &config);
        let (agent, request) = (view.challenge.agent_id, view.challenge.request_id);

        let shown = describe_challenge(
            &view,
            &config,
            agent,
            request,
            &policy_digest,
            HumanApprovalOutcome::Approve,
        )
        .unwrap();
        for expected in [
            "\"demo:set_value\"",
            "\"demo-state\"",
            "\"demo:write\"",
            "\"value\": \"safe\"",
            view.challenge.action_digest.as_str(),
            policy_digest.as_str(),
            "2026-06-01T12:00:00Z",
            "APPROVE",
        ] {
            assert!(shown.contains(expected), "missing {expected} in {shown}");
        }

        // The gateway shows a different action than the one the digest binds.
        let mut swapped = view.clone();
        swapped.action.parameters = serde_json::json!({"key": "mode", "value": "unsafe"});
        assert!(
            describe_challenge(
                &swapped,
                &config,
                agent,
                request,
                &policy_digest,
                HumanApprovalOutcome::Approve
            )
            .unwrap_err()
            .to_string()
            .contains("does not match")
        );
        assert!(
            describe_challenge(
                &view,
                &config,
                agent,
                request,
                &"0".repeat(64),
                HumanApprovalOutcome::Approve
            )
            .is_err()
        );
        assert!(
            describe_challenge(
                &view,
                &config,
                Uuid::new_v4(),
                request,
                &policy_digest,
                HumanApprovalOutcome::Approve
            )
            .is_err()
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn terminal_output_escapes_control_and_bidi_characters() {
        assert_eq!(
            terminal_safe("ok\n\u{1b}[2Jx\u{202e}y"),
            "ok\n\\u{001b}[2Jx\\u{202e}y"
        );
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
    fn local_demo_database_must_be_loopback_and_is_checked_before_connecting() {
        assert!(local_database("postgres://postgres@127.0.0.1:1/praetore").is_ok());
        assert!(local_database("host=/tmp user=postgres").is_ok());
        assert!(local_database("postgres://postgres@db.internal/praetore").is_err());
        // Even with TLS the demo stays local; a missing root fails before I/O.
        assert!(
            local_database(
                "postgres://postgres@db.internal/praetore?sslmode=verify-full&sslrootcert=%2Fmissing"
            )
            .is_err()
        );
    }

    #[test]
    fn approver_ids_are_strictly_validated() {
        assert!(valid_approver_id("local-approver"));
        for bad in ["", "Local", "a b", "x;drop", "../key", &"a".repeat(65)] {
            assert!(!valid_approver_id(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn init_creates_approver_pin_and_owner_only_approver_key() {
        let directory = env::temp_dir().join(format!("praetore-cli-test-{}", Uuid::new_v4()));
        initialize(&directory, 8080).unwrap();
        let metadata = fs::metadata(directory.join(APPROVER_KEY_FILE)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let pin = load_approver_pin(&directory).unwrap().unwrap();
        assert_eq!(pin.key_id, LOCAL_APPROVER_ID);
        let secret = read_secret(&directory, APPROVER_KEY_FILE).unwrap();
        assert_eq!(
            hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes()),
            pin.public_key_hex
        );
        assert!(
            load_approver_verifier(&directory, load_config(&directory).unwrap().tenant_id)
                .unwrap()
                .is_some()
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn missing_approver_pin_disables_approval_and_cli_refuses() {
        let directory = env::temp_dir().join(format!("praetore-cli-test-{}", Uuid::new_v4()));
        initialize(&directory, 8080).unwrap();
        fs::remove_file(directory.join(APPROVER_PIN_FILE)).unwrap();
        assert!(
            load_approver_verifier(&directory, load_config(&directory).unwrap().tenant_id)
                .unwrap()
                .is_none()
        );
        let error = resolve_approval(
            &directory,
            &Uuid::new_v4().to_string(),
            None,
            LOCAL_APPROVER_ID,
            HumanApprovalOutcome::Approve,
            Confirmation::AssumeYes,
        )
        .unwrap_err();
        assert!(error.to_string().contains("human approval is disabled"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn approve_rejects_malformed_ids_and_unknown_approvers_before_any_io() {
        let directory = env::temp_dir().join(format!("praetore-cli-test-{}", Uuid::new_v4()));
        initialize(&directory, 8080).unwrap();
        for id in [
            "not-a-uuid",
            "00000000-0000-0000-0000-000000000000",
            "'; drop table x;--",
        ] {
            assert!(
                resolve_approval(
                    &directory,
                    id,
                    None,
                    LOCAL_APPROVER_ID,
                    HumanApprovalOutcome::Approve,
                    Confirmation::AssumeYes,
                )
                .is_err()
            );
        }
        let error = resolve_approval(
            &directory,
            &Uuid::new_v4().to_string(),
            Some("not-a-uuid"),
            LOCAL_APPROVER_ID,
            HumanApprovalOutcome::Approve,
            Confirmation::AssumeYes,
        )
        .unwrap_err();
        assert!(error.to_string().contains("--agent must be"));
        let error = resolve_approval(
            &directory,
            &Uuid::new_v4().to_string(),
            None,
            "someone-else",
            HumanApprovalOutcome::Approve,
            Confirmation::AssumeYes,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown approver"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn tampered_approver_pin_is_rejected() {
        let directory = env::temp_dir().join(format!("praetore-cli-test-{}", Uuid::new_v4()));
        initialize(&directory, 8080).unwrap();
        fs::write(
            directory.join(APPROVER_PIN_FILE),
            r#"{"schema_version":1,"key_id":"local-approver","public_key_hex":"zz"}"#,
        )
        .unwrap();
        assert!(load_approver_pin(&directory).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    /// Real PostgreSQL end-to-end test of the approval flow through the same
    /// gateway the CLI runs. Run with:
    /// `PRAETORE_TEST_DATABASE_URL=postgresql://user@127.0.0.1:port/db cargo test -p praetore-cli -- --ignored`
    #[test]
    #[ignore = "requires PRAETORE_TEST_DATABASE_URL pointing to a disposable local PostgreSQL"]
    fn postgres_approval_dispatches_once_and_rejection_is_final() {
        use praetore_gateway::{
            ApprovalError, ApprovalResolution, ExecutionKey, ExecutionStatus, GatewayError,
            HumanApprovalResult,
        };
        let database_url = env::var("PRAETORE_TEST_DATABASE_URL").unwrap();
        apply_migrations(&database_url).unwrap();
        let directory = env::temp_dir().join(format!("praetore-cli-test-{}", Uuid::new_v4()));
        initialize(&directory, 8080).unwrap();
        let mut policy = load_policy(&directory).unwrap();
        policy.rules[0].effect = PolicyEffect::RequireApproval;
        fs::write(
            directory.join(POLICY_FILE),
            serde_json::to_vec_pretty(&policy).unwrap(),
        )
        .unwrap();
        let config = load_config(&directory).unwrap();
        let policy = load_policy(&directory).unwrap();
        let gateway = build_gateway(&directory, &config, &database_url).unwrap();
        let approver = SigningKey::from_bytes(&read_secret(&directory, APPROVER_KEY_FILE).unwrap());

        let pending = |value: &str| {
            let request = build_demo_request(&directory, &config, &policy, "k", value).unwrap();
            let receipt = gateway.execute(request).unwrap();
            assert_eq!(receipt.execution, ExecutionStatus::NotDispatched);
            let request_id = receipt.evidence.request_id;
            let agent_id = find_pending_agent(&database_url, config.tenant_id, request_id).unwrap();
            assert_eq!(agent_id, *receipt.evidence.agent.id.as_uuid());
            ExecutionKey {
                tenant_id: config.tenant_id,
                agent_id,
                request_id,
            }
        };

        // Approve: dispatched exactly once, then the decision cannot be reused.
        let key = pending("approved");
        let decision = sign_decision(
            gateway.approval_challenge(key).unwrap(),
            LOCAL_APPROVER_ID,
            HumanApprovalOutcome::Approve,
            &approver,
        )
        .unwrap();
        assert_eq!(
            gateway.approval_resolution(key).unwrap(),
            ApprovalResolution::Pending
        );
        let resolution = gateway.resolve_human_approval(decision.clone()).unwrap();
        assert!(matches!(
            resolution,
            HumanApprovalResult::ApprovedPendingDispatch { .. }
        ));
        assert_eq!(
            serde_json::to_value(&resolution).unwrap()["status"],
            "approved_pending_dispatch"
        );
        assert_eq!(
            gateway.approval_resolution(key).unwrap(),
            ApprovalResolution::Approved
        );
        assert!(gateway.resolve_human_approval(decision).is_err());
        let receipt = gateway.dispatch_approved(key).unwrap();
        assert_eq!(receipt.execution, ExecutionStatus::Confirmed);
        assert!(gateway.dispatch_approved(key).is_err());
        assert!(matches!(
            gateway.approval_challenge(key),
            Err(GatewayError::Approval(ApprovalError::NotPending))
        ));

        // Reject: never dispatched, and a later approval is refused.
        let key = pending("rejected");
        let challenge = gateway.approval_challenge(key).unwrap();
        let reject = sign_decision(
            challenge.clone(),
            LOCAL_APPROVER_ID,
            HumanApprovalOutcome::Reject,
            &approver,
        )
        .unwrap();
        let HumanApprovalResult::Rejected { receipt, .. } =
            gateway.resolve_human_approval(reject).unwrap()
        else {
            panic!("a rejection must return its receipt");
        };
        assert_eq!(receipt.execution, ExecutionStatus::NotDispatched);
        assert_eq!(
            gateway.approval_resolution(key).unwrap(),
            ApprovalResolution::Rejected
        );
        let late_approve = sign_decision(
            challenge,
            LOCAL_APPROVER_ID,
            HumanApprovalOutcome::Approve,
            &approver,
        )
        .unwrap();
        assert!(gateway.resolve_human_approval(late_approve).is_err());

        // A signature from a key that is not the pinned approver is refused.
        let key = pending("forged");
        let forged = sign_decision(
            gateway.approval_challenge(key).unwrap(),
            LOCAL_APPROVER_ID,
            HumanApprovalOutcome::Approve,
            &SigningKey::from_bytes(&[7; 32]),
        )
        .unwrap();
        assert!(matches!(
            gateway.resolve_human_approval(forged),
            Err(GatewayError::Approval(ApprovalError::InvalidSignature))
        ));

        // Unknown execution id is not found.
        assert!(find_pending_agent(&database_url, config.tenant_id, Uuid::new_v4()).is_err());

        // Fail closed: a gateway built without an approver pin refuses even a
        // correctly signed decision and never dispatches.
        let key = pending("unconfigured");
        let challenge = gateway.approval_challenge(key).unwrap();
        let pin_path = directory.join(APPROVER_PIN_FILE);
        let pin_backup = fs::read(&pin_path).unwrap();
        fs::remove_file(&pin_path).unwrap();
        let unconfigured = build_gateway(&directory, &config, &database_url).unwrap();
        fs::write(&pin_path, pin_backup).unwrap();
        let decision = sign_decision(
            challenge,
            LOCAL_APPROVER_ID,
            HumanApprovalOutcome::Approve,
            &approver,
        )
        .unwrap();
        assert!(matches!(
            unconfigured.resolve_human_approval(decision),
            Err(GatewayError::Approval(ApprovalError::NotConfigured))
        ));
        assert!(gateway.approval_challenge(key).is_ok(), "still pending");

        // Self-approval: the approver pin is the requesting agent's own key.
        let agent_key = AgentKeyPair::from_secret_bytes(&[9; 32]);
        let request = build_demo_request_with_agent_key(
            &directory, &config, &policy, "k", "self", &agent_key,
        )
        .unwrap();
        let receipt = gateway.execute(request).unwrap();
        let key = ExecutionKey {
            tenant_id: config.tenant_id,
            agent_id: *receipt.evidence.agent.id.as_uuid(),
            request_id: receipt.evidence.request_id,
        };
        let self_pin = ApproverPin {
            schema_version: 1,
            key_id: LOCAL_APPROVER_ID.into(),
            public_key_hex: hex::encode(agent_key.public_key().as_bytes()),
        };
        let original_pin = fs::read(&pin_path).unwrap();
        fs::write(&pin_path, serde_json::to_vec(&self_pin).unwrap()).unwrap();
        let self_gateway = build_gateway(&directory, &config, &database_url).unwrap();
        fs::write(&pin_path, original_pin).unwrap();
        let self_decision = sign_decision(
            self_gateway.approval_challenge(key).unwrap(),
            LOCAL_APPROVER_ID,
            HumanApprovalOutcome::Approve,
            &SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap();
        assert!(matches!(
            self_gateway.resolve_human_approval(self_decision),
            Err(GatewayError::Approval(ApprovalError::SelfApproval))
        ));
        assert!(gateway.approval_challenge(key).is_ok(), "still pending");

        // Expiry uses the real clock here: the local approval window is at most
        // 30 s (freshness lease), so wait it out and confirm fail-closed.
        let key = pending("expires");
        let challenge = gateway.approval_challenge(key).unwrap();
        std::thread::sleep(StdDuration::from_secs(31));
        assert_eq!(
            gateway.approval_resolution(key).unwrap(),
            ApprovalResolution::Expired
        );
        assert!(matches!(
            gateway.approval_challenge(key),
            Err(GatewayError::Approval(ApprovalError::Expired))
        ));
        let late = sign_decision(
            challenge,
            LOCAL_APPROVER_ID,
            HumanApprovalOutcome::Approve,
            &approver,
        )
        .unwrap();
        assert!(gateway.resolve_human_approval(late).is_err());
        assert_eq!(
            gateway.approval_resolution(key).unwrap(),
            ApprovalResolution::Expired
        );
        assert!(
            gateway
                .approval_resolution(ExecutionKey {
                    tenant_id: Uuid::new_v4(),
                    ..key
                })
                .is_err()
        );

        // human_approvals holds exactly the two accepted decisions.
        let mut client = connect_local_database(&database_url).unwrap();
        let mut transaction = client.transaction().unwrap();
        transaction
            .query_one(
                "SELECT set_config('praetore.tenant_id', $1, true)",
                &[&config.tenant_id.to_string()],
            )
            .unwrap();
        let rows = transaction
            .query(
                "SELECT outcome FROM praetore.human_approvals WHERE tenant_id = $1 ORDER BY created_at",
                &[&config.tenant_id],
            )
            .unwrap();
        let outcomes: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
        assert_eq!(outcomes, ["approve", "reject"]);
        transaction.commit().unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn example_policies_produce_their_documented_outcomes() {
        use praetore_core::DecisionOutcome;
        let cases = [
            (
                include_str!("../examples/policies/allow.json"),
                "allow-demo-set",
                DecisionOutcome::Allow,
            ),
            (
                include_str!("../examples/policies/deny.json"),
                "deny-demo-set",
                DecisionOutcome::Deny,
            ),
            (
                include_str!("../examples/policies/require-approval.json"),
                "approval-demo-set",
                DecisionOutcome::RequireApproval,
            ),
        ];
        for (json, rule_id, expected) in cases {
            let directory = env::temp_dir().join(format!("praetore-cli-test-{}", Uuid::new_v4()));
            initialize(&directory, 8080).unwrap();
            fs::write(directory.join(POLICY_FILE), json).unwrap();
            let config = load_config(&directory).unwrap();
            let policy = load_policy(&directory).unwrap();
            assert_eq!(policy.rules.len(), 1);
            assert_eq!(policy.rules[0].id, rule_id);
            let request =
                build_demo_request(&directory, &config, &policy, "greeting", "hello").unwrap();
            assert_eq!(request.action.action_type, "demo:set_value");
            assert_eq!(request.action.capability.as_deref(), Some("demo:write"));
            let decision = policy
                .evaluate(&request.agent, &request.authority, &request.action)
                .unwrap();
            assert_eq!(decision.outcome, expected, "policy rule {rule_id}");
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn default_policy_matches_the_allow_example() {
        let example = Policy::from_json(include_str!("../examples/policies/allow.json")).unwrap();
        assert_eq!(example.digest().unwrap(), demo_policy().digest().unwrap());
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
