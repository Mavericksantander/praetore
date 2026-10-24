use postgres::{Client, NoTls};
use praetore_core::VerifiedPublicKey;
use praetore_observe::{ObserveState, validate_bind_address};
use praetore_replay_postgres::PostgresObservabilityReader;
use std::{env, net::SocketAddr, sync::Arc};
use tracing_subscriber::EnvFilter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let bearer_token = env::var("PRAETORE_OBSERVE_BEARER_TOKEN")
        .map_err(|_| "PRAETORE_OBSERVE_BEARER_TOKEN is required (32 random bytes, hex encoded)")?;
    let database_url = env::var("PRAETORE_OBSERVE_DATABASE_URL")
        .map_err(|_| "PRAETORE_OBSERVE_DATABASE_URL is required")?;
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
    let reader = Arc::new(PostgresObservabilityReader::from_client(Client::connect(
        &database_url,
        NoTls,
    )?)?);
    let state = ObserveState::new(reader, &bearer_token, trusted_attester)?;
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
