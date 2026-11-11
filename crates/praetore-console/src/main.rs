use praetore_console::{
    ConsoleState, LocalSession, PostgresHistory, parse_agent_names, validate_bind_address,
};
use praetore_replay_postgres::{DatabaseConnector, RuntimeRoleOptions, verify_runtime_role_with};
use std::{
    collections::HashMap, env, fs, future::IntoFuture, net::SocketAddr, path::PathBuf, sync::Arc,
};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let tenant_id: Uuid = env::var("PRAETORE_CONSOLE_TENANT_ID")
        .map_err(|_| "PRAETORE_CONSOLE_TENANT_ID es obligatorio")?
        .parse()
        .map_err(|_| "PRAETORE_CONSOLE_TENANT_ID no se pudo leer")?;
    if tenant_id.is_nil() {
        return Err("PRAETORE_CONSOLE_TENANT_ID no se pudo leer".into());
    }
    let database_url = env::var("PRAETORE_CONSOLE_DATABASE_URL")
        .map_err(|_| "PRAETORE_CONSOLE_DATABASE_URL es obligatorio")?;
    let database = DatabaseConnector::from_url(&database_url)
        .map_err(|_| "la dirección de la base no se puede usar")?;
    let address: SocketAddr = env::var("PRAETORE_CONSOLE_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8090".into())
        .parse()?;
    let address = validate_bind_address(address)?;
    let session_path = match env::var_os("PRAETORE_CONSOLE_SESSION_FILE") {
        Some(path) => PathBuf::from(path),
        None => default_session_path()?,
    };
    let session = LocalSession::load_or_create(&session_path)?;
    let names = match env::var("PRAETORE_CONSOLE_AGENT_NAMES_FILE") {
        Ok(path) => parse_agent_names(&fs::read_to_string(path)?)?,
        Err(env::VarError::NotPresent) => HashMap::new(),
        Err(_) => return Err("PRAETORE_CONSOLE_AGENT_NAMES_FILE no se pudo leer".into()),
    };

    let mut client = database.connect().map_err(|_| "no se pudo abrir la base")?;
    let options = RuntimeRoleOptions::from_config(|name| env::var(name).ok())?;
    verify_runtime_role_with(&mut client, &options)?;
    let history = PostgresHistory::from_client(client, tenant_id)
        .map_err(|_| "no se pudo preparar la lectura del registro")?;
    let state = Arc::new(ConsoleState::new(Arc::new(history), session, names));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let listener = runtime.block_on(tokio::net::TcpListener::bind(address))?;
    tracing::info!(%address, "consola local de historial escuchando");
    let served = runtime.block_on(
        axum::serve(listener, ConsoleState::router_from(Arc::clone(&state))).into_future(),
    );
    drop(runtime);
    drop(state);
    served?;
    Ok(())
}

fn default_session_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home =
        env::var_os("HOME").ok_or("HOME no está definido; indica PRAETORE_CONSOLE_SESSION_FILE")?;
    Ok(PathBuf::from(home).join(".local/share/praetore/consola-sesion"))
}
