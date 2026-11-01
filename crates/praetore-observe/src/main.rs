use praetore_core::VerifiedPublicKey;
use praetore_observe::{ObserveState, parse_tenant_token_hashes, validate_bind_address};
use praetore_replay_postgres::{DatabaseConnector, PostgresObservabilityReader};
use std::{env, fs, net::SocketAddr, path::Path, sync::Arc};
use tracing_subscriber::EnvFilter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let token_file = env::var("PRAETORE_OBSERVE_TENANT_TOKENS_FILE")
        .map_err(|_| "PRAETORE_OBSERVE_TENANT_TOKENS_FILE is required")?;
    let metadata = fs::metadata(Path::new(&token_file))?;
    if !metadata.is_file() || metadata.len() > 1_048_576 {
        return Err("tenant token file must be a file no larger than 1048576 bytes".into());
    }
    let tenant_token_hashes = parse_tenant_token_hashes(&fs::read_to_string(token_file)?)?;
    // Validated (TLS policy included) before any connection is opened.
    let database = DatabaseConnector::from_url(
        &env::var("PRAETORE_OBSERVE_DATABASE_URL")
            .map_err(|_| "PRAETORE_OBSERVE_DATABASE_URL is required")?,
    )?;
    let address: SocketAddr = env::var("PRAETORE_OBSERVE_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8088".into())
        .parse()?;
    let address = validate_bind_address(address)?;
    let trusted_attester = env::var("PRAETORE_OBSERVE_ATTESTER_PUBLIC_KEY_HEX")
        .ok()
        .map(|key| {
            let bytes = hex::decode(key).map_err(|error| error.to_string())?;
            VerifiedPublicKey::from_bytes(&bytes).map_err(|error| error.to_string())
        })
        .transpose()?;
    let mut client = database.connect()?;
    // The same startup check as the gateway runtime: refuse an owner,
    // superuser, BYPASSRLS or write-capable role, and a session in which
    // triggers or row-level security could be switched off. It runs once,
    // at startup; queries pin their search_path per transaction regardless.
    let allow_settings_env = praetore_replay_postgres::RuntimeRoleOptions::ALLOW_SETTINGS_ENV;
    let options = praetore_replay_postgres::RuntimeRoleOptions::from_allow_settings(
        &env::var(allow_settings_env).unwrap_or_default(),
    )?;
    let relaxed = options.relaxed();
    if relaxed.is_empty() {
        tracing::info!("runtime role check: no refusal relaxed");
    } else {
        tracing::warn!(
            ?relaxed,
            "runtime role check relaxed by {allow_settings_env}"
        );
    }
    praetore_replay_postgres::verify_runtime_role_with(&mut client, &options)?;
    let reader = Arc::new(PostgresObservabilityReader::from_client(client)?);
    let state = ObserveState::new(reader, tenant_token_hashes, trusted_attester)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(address).await?;
        tracing::info!(%address, "PRÆTORE read-only observability service listening");
        axum::serve(listener, state.router()).await?;
        Ok::<_, std::io::Error>(())
    })?;
    Ok(())
}
