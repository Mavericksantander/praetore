use praetore_core::VerifiedPublicKey;
use praetore_observe::{ObserveState, parse_tenant_token_hashes, validate_bind_address};
use praetore_replay_postgres::{DatabaseConnector, PostgresObservabilityReader};
use std::{env, fs, future::IntoFuture, net::SocketAddr, path::Path, sync::Arc};
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
    let options =
        praetore_replay_postgres::RuntimeRoleOptions::from_config(|name| env::var(name).ok())?;
    let relaxed = options.relaxed();
    if relaxed.is_empty() {
        tracing::info!("runtime role check: no refusal relaxed");
    } else {
        tracing::warn!(
            ?relaxed,
            trusted_security_definer = ?options.trusted_security_definer(),
            "runtime role check relaxed explicitly"
        );
    }
    match options.schema_owner() {
        Some(owner) => tracing::info!(schema_owner = owner, "praetore schema owner is pinned"),
        None => tracing::warn!(
            "PRAETORE_SCHEMA_OWNER is not set: the runtime accepts whichever role owns the \
             praetore schema (set it in production)"
        ),
    }
    for function in
        praetore_replay_postgres::describe_trusted_security_definer(&mut client, &options)?
    {
        if function.owner_is_superuser {
            tracing::warn!(
                function = %function.resolved,
                owner = %function.owner,
                "trusted SECURITY DEFINER function is owned by a superuser"
            );
        }
    }
    praetore_replay_postgres::verify_runtime_role_with(&mut client, &options)?;
    let reader = Arc::new(PostgresObservabilityReader::from_client(client)?);
    let state = ObserveState::new(reader, tenant_token_hashes, trusted_attester)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    // The reader holds a blocking PostgreSQL client, whose drop must not run
    // on a runtime thread: bind before anything moves into the runtime, and
    // keep the last reference (`state`) out here, so that a port in use is
    // reported as the bind error instead of aborting the process.
    let listener = runtime.block_on(tokio::net::TcpListener::bind(address))?;
    tracing::info!(%address, "PRÆTORE read-only observability service listening");
    let served = runtime.block_on(axum::serve(listener, state.clone().router()).into_future());
    drop(runtime);
    drop(state);
    served?;
    Ok(())
}
