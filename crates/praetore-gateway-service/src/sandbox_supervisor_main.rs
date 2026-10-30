use praetore_gateway_service::sandbox_supervisor::{
    ConnectionLimits, KubernetesApi, SandboxSupervisor, load_server_tls, load_worker_tls,
    parse_listen_address, serve_tls,
};
use std::{env, fs, path::Path};
use tracing_subscriber::EnvFilter;

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn read_limited(path: &str, max_bytes: u64) -> Result<String, Box<dyn std::error::Error>> {
    let metadata = fs::metadata(Path::new(path))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(
            format!("{path} must be a non-empty file no larger than {max_bytes} bytes").into(),
        );
    }
    Ok(fs::read_to_string(path)?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config_path = required_env("PRAETORE_SANDBOX_SUPERVISOR_CONFIG_FILE")?;
    let config = read_limited(&config_path, 65_536)?;
    let supervisor = SandboxSupervisor::new(KubernetesApi::in_cluster()?, &config)?;

    let certificate_path = required_env("PRAETORE_SANDBOX_SUPERVISOR_TLS_CERT_FILE")?;
    let private_key_path = required_env("PRAETORE_SANDBOX_SUPERVISOR_TLS_KEY_FILE")?;
    let client_ca_path = required_env("PRAETORE_SANDBOX_SUPERVISOR_GATEWAY_CA_FILE")?;
    let server_tls = load_server_tls(&certificate_path, &private_key_path, &client_ca_path)?;
    let worker_tls = load_worker_tls(&certificate_path, &private_key_path)?;

    let gateway_address = env::var("PRAETORE_SANDBOX_SUPERVISOR_GATEWAY_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8443".into());
    let worker_address = env::var("PRAETORE_SANDBOX_SUPERVISOR_WORKER_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8444".into());

    tracing::info!(
        gateway_listener = %gateway_address,
        worker_callback_listener = %worker_address,
        "sandbox supervisor starting with mTLS gateway ingress and token-authenticated worker callback"
    );
    tokio::try_join!(
        serve_tls(
            parse_listen_address(&gateway_address)?,
            server_tls,
            supervisor.clone().gateway_router(),
            ConnectionLimits::gateway_ingress(),
        ),
        serve_tls(
            parse_listen_address(&worker_address)?,
            worker_tls,
            supervisor.worker_router(),
            ConnectionLimits::worker_callback(),
        ),
    )?;
    Ok(())
}
