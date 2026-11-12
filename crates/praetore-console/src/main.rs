//! `praetore-console`: local operator console. Linux first.
//!
//! Required: `PRAETORE_CONSOLE_TENANT_ID`, `PRAETORE_CONSOLE_DATABASE_URL`
//! (the journal is read in transactions opened read only by the console).
//! Optional: `PRAETORE_CONSOLE_BIND` (loopback
//! only, default `127.0.0.1:8090`), `PRAETORE_CONSOLE_AGENT_NAMES_FILE`.
//!
//! Opening: at startup the console writes a link `http://<bind>/?abrir=<code>`
//! to stderr. Under systemd stderr goes to the journal, so whoever can read
//! that journal can open the console while the link is live. The link works
//! once and for at most five minutes. A new link is issued only by the
//! operator: when stdin and stderr are a terminal, pressing Enter there
//! writes a new one (and the earlier one stops working); otherwise, restart
//! the console. Asking for the page never issues a link. The session secret
//! is new on every start and is never written to disk.
//!
//! Approvals inbox (D2), all four or none:
//! - `PRAETORE_CONSOLE_GATEWAY_URL`: `http://127.0.0.1:<port>` of the gateway;
//! - `PRAETORE_CONSOLE_APPROVER_KEY_ID`: the approver key id the gateway pins;
//! - `PRAETORE_CONSOLE_APPROVER_KEY_FILE`: owner-only file, 32 bytes in hex
//!   (`approver.key` of `praetore init`);
//! - `PRAETORE_CONSOLE_APPROVER_TOKEN_FILE`: owner-only file with the
//!   gateway's `approver` bearer token (`approver-api.token`).

use praetore_console::{
    ApproverSigner, ConsoleState, HttpApprovalGateway, Inbox, LocalSession, PostgresHistory,
    parse_agent_names, parse_gateway_address, read_token_file, validate_bind_address,
};
use praetore_replay_postgres::{DatabaseConnector, RuntimeRoleOptions, verify_runtime_role_with};
use std::io::IsTerminal;
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
    if env::var_os("PRAETORE_CONSOLE_SESSION_FILE").is_some() {
        tracing::warn!(
            "PRAETORE_CONSOLE_SESSION_FILE ya no se usa: la sesión es nueva en cada arranque"
        );
    }
    // New on every start: a cookie from an earlier run stops working.
    let session = LocalSession::random()?;
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
    let history = Arc::new(history);
    let mut state = ConsoleState::new(history.clone(), session, names).with_address(address);
    let inbox = approver_settings()?;
    match inbox {
        Some((gateway, signer)) => {
            state = state.with_inbox(Inbox::new(history, Arc::new(gateway), signer));
            tracing::info!("bandeja de aprobaciones activa");
        }
        None => tracing::info!("bandeja de aprobaciones sin configurar: solo historial"),
    }
    let state = Arc::new(state);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let listener = runtime.block_on(tokio::net::TcpListener::bind(address))?;
    tracing::info!(%address, "consola local escuchando");
    // To stderr only (under systemd, also the journal): whoever has the
    // link first gets the session. Single use, five minutes.
    state
        .issue_opening_link()
        .ok_or("no se pudo crear el enlace de apertura de la consola")?;
    // A new link only by the operator's hand: Enter in this terminal.
    if operator_terminal() {
        eprintln!("Para un enlace nuevo, pulsa Enter en esta terminal.");
        let operator = Arc::clone(&state);
        std::thread::spawn(move || read_enter_for_links(&operator));
    }
    let served = runtime.block_on(
        axum::serve(listener, ConsoleState::router_from(Arc::clone(&state))).into_future(),
    );
    drop(runtime);
    drop(state);
    served?;
    Ok(())
}

/// D2 is on only when all four settings are present; a partial set is an
/// error, so a typo never leaves the operator with a silent read-only page.
fn approver_settings()
-> Result<Option<(HttpApprovalGateway, ApproverSigner)>, Box<dyn std::error::Error>> {
    const NAMES: [&str; 4] = [
        "PRAETORE_CONSOLE_GATEWAY_URL",
        "PRAETORE_CONSOLE_APPROVER_KEY_ID",
        "PRAETORE_CONSOLE_APPROVER_KEY_FILE",
        "PRAETORE_CONSOLE_APPROVER_TOKEN_FILE",
    ];
    let mut values = Vec::with_capacity(NAMES.len());
    for name in NAMES {
        match env::var(name) {
            Ok(value) if !value.trim().is_empty() => values.push(Some(value)),
            Ok(_) | Err(env::VarError::NotPresent) => values.push(None),
            Err(_) => return Err(format!("{name} no se pudo leer").into()),
        }
    }
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    let [Some(url), Some(key_id), Some(key_file), Some(token_file)] =
        <[Option<String>; 4]>::try_from(values).map_err(|_| "configuración incompleta")?
    else {
        return Err(format!(
            "la bandeja de aprobaciones necesita las cuatro variables: {}",
            NAMES.join(", ")
        )
        .into());
    };
    let address = parse_gateway_address(&url)?;
    let signer = ApproverSigner::from_file(&key_id, &PathBuf::from(key_file))?;
    let token = read_token_file(&PathBuf::from(token_file))?;
    Ok(Some((HttpApprovalGateway::new(address, token), signer)))
}

/// True when stdin and stderr are a terminal and this process is in that
/// terminal's foreground: started with `&`, it never reads the terminal.
/// SIGTTIN is then ignored, so if the console is later sent to the
/// background (Ctrl-Z, `bg`) a read fails with EIO instead of the system
/// stopping the whole process.
#[cfg(unix)]
fn operator_terminal() -> bool {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() || !std::io::stderr().is_terminal() {
        return false;
    }
    let foreground =
        rustix::termios::tcgetpgrp(&stdin).is_ok_and(|group| group == rustix::process::getpgrp());
    if !foreground {
        return false;
    }
    // SAFETY: setting SIGTTIN to SIG_IGN installs no handler and runs no
    // code in signal context; it only changes the disposition.
    let previous = unsafe { libc::signal(libc::SIGTTIN, libc::SIG_IGN) };
    previous != libc::SIG_ERR
}

#[cfg(not(unix))]
fn operator_terminal() -> bool {
    false
}

/// Each Enter writes a new link. In the background a read fails (EIO, as
/// SIGTTIN is ignored): wait and try again, so Enter works once the console
/// is back in the foreground. End of input ends the thread.
fn read_enter_for_links(state: &ConsoleState) {
    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        line.clear();
        match stdin.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => {
                if state.issue_opening_link().is_none() {
                    return;
                }
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_secs(1)),
        }
    }
}
