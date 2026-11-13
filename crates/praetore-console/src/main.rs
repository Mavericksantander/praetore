//! `praetore-console`: local operator console. Linux first.
//!
//! Required: `PRAETORE_CONSOLE_TENANT_ID`, `PRAETORE_CONSOLE_DATABASE_URL`
//! (the journal is read in transactions opened read only by the console).
//! Optional: `PRAETORE_CONSOLE_BIND` (loopback
//! only, default `127.0.0.1:8090`), `PRAETORE_CONSOLE_AGENT_NAMES_FILE`.
//!
//! Opening: at startup the console writes a link `http://<bind>/#abrir=<code>`
//! to stderr. The code travels in the URL fragment, which the browser never
//! sends to the server; the page reads it and redeems it for a session token
//! over `POST /api/sesion`. Under systemd stderr goes to the journal, so
//! whoever can read that journal can open the console while the link is live.
//! The link works once and for at most five minutes. A new link is issued
//! only by the operator: when stdin and stderr are a terminal, pressing Enter
//! there writes a new one (and the earlier one stops working); otherwise,
//! restart the console. Asking for the page never issues a link. The session
//! token is kept only in the browser tab (sessionStorage, per origin and
//! port) and sent as `Authorization: Bearer`; no session cookie is set, and
//! no secret is written to disk.
//!
//! Approvals inbox (D2), all four or none:
//! - `PRAETORE_CONSOLE_GATEWAY_URL`: `http://127.0.0.1:<port>` of the gateway;
//! - `PRAETORE_CONSOLE_APPROVER_KEY_ID`: the approver key id the gateway pins;
//! - `PRAETORE_CONSOLE_APPROVER_KEY_FILE`: owner-only file, 32 bytes in hex
//!   (`approver.key` of `praetore init`);
//! - `PRAETORE_CONSOLE_APPROVER_TOKEN_FILE`: owner-only file with the
//!   gateway's `approver` bearer token (`approver-api.token`).
//!
//! Attester pins and local policy (D3), both or none, and both required
//! when the inbox is configured:
//! - `PRAETORE_CONSOLE_POLICY_FILE`: the policy file the gateway loads;
//! - `PRAETORE_CONSOLE_ATTESTER_PIN_FILES`: one or more attester public-key
//!   files (lowercase hex), separated like `PATH` (`:` on Unix).
//!
//! They are read once at startup for the inbox and the history: the inbox
//! offers a request only when its evidence is signed by one of the pins and
//! records the local policy's digest; the history checks the signature.
//! A change to these files takes effect on restart. With them the
//! compliance package is also available, and it reads them again at every
//! download, so the package carries the files as they are at that moment.

use praetore_console::{
    ApproverSigner, CompliancePack, ConsoleState, EvidenceTrust, HttpApprovalGateway, Inbox,
    LocalSession, PINS_VARIABLE, POLICY_VARIABLE, PackSettings, PostgresHistory, parse_agent_names,
    parse_gateway_address, read_token_file, require_for_inbox, validate_bind_address,
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
    // New on every start: a token from an earlier run stops working.
    let session = LocalSession::random()?;
    let names = match env::var("PRAETORE_CONSOLE_AGENT_NAMES_FILE") {
        Ok(path) => parse_agent_names(&fs::read_to_string(path)?)?,
        Err(env::VarError::NotPresent) => HashMap::new(),
        Err(_) => return Err("PRAETORE_CONSOLE_AGENT_NAMES_FILE no se pudo leer".into()),
    };

    // Configuration first: an inbox without the pins and the policy that
    // verify its evidence never starts.
    let inbox = approver_settings()?;
    require_for_inbox(
        inbox.is_some(),
        env::var_os(POLICY_VARIABLE).as_deref(),
        env::var_os(PINS_VARIABLE).as_deref(),
    )?;
    let pack = pack_settings()?;
    let trust = trust_settings(inbox.as_ref().map(|(_, signer)| signer))?;

    let mut client = database.connect().map_err(|_| "no se pudo abrir la base")?;
    let options = RuntimeRoleOptions::from_config(|name| env::var(name).ok())?;
    verify_runtime_role_with(&mut client, &options)?;
    let mut history = PostgresHistory::from_client(client, tenant_id)
        .map_err(|_| "no se pudo preparar la lectura del registro")?;
    match &trust {
        Some(trust) => {
            history = history.with_attester_pins(trust.pins());
            tracing::info!("historial: firma del atestador verificada con los pins configurados");
        }
        None => tracing::info!("historial: sin pins del atestador, solo hash de integridad"),
    }
    let history = Arc::new(history);
    let mut state = ConsoleState::new(history.clone(), session, names).with_address(address);
    match (inbox, trust) {
        (Some((gateway, signer)), Some(trust)) => {
            state = state.with_inbox(Inbox::new(
                history.clone(),
                Arc::new(gateway),
                signer,
                trust,
            ));
            tracing::info!("bandeja de aprobaciones activa");
        }
        (Some(_), None) => {
            return Err(
                "la bandeja de aprobaciones necesita la política y los pins del atestador".into(),
            );
        }
        (None, _) => tracing::info!("bandeja de aprobaciones sin configurar: solo historial"),
    }
    match pack {
        Some(settings) => {
            state = state.with_compliance_pack(CompliancePack::new(settings, history.clone()));
            tracing::info!("paquete de compliance disponible");
        }
        None => tracing::info!("paquete de compliance sin configurar"),
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

/// D3 is on only with both settings; one without the other is an error.
fn pack_settings() -> Result<Option<PackSettings>, Box<dyn std::error::Error>> {
    const POLICY: &str = "PRAETORE_CONSOLE_POLICY_FILE";
    const PINS: &str = "PRAETORE_CONSOLE_ATTESTER_PIN_FILES";
    let read = |name: &str| match env::var_os(name) {
        Some(value) if !value.is_empty() => Some(value),
        _ => None,
    };
    // D3.1: the pins that verify approvals.jsonl; optional, and only with
    // the two above.
    const EXECUTION_PINS: &str = "PRAETORE_CONSOLE_EXECUTION_PIN_FILES";
    const APPROVER_PINS: &str = "PRAETORE_CONSOLE_APPROVER_PIN_FILES";
    let paths = |value: Option<std::ffi::OsString>| -> Vec<PathBuf> {
        value.map_or_else(Vec::new, |value| {
            env::split_paths(&value)
                .filter(|path| !path.as_os_str().is_empty())
                .collect()
        })
    };
    let execution = read(EXECUTION_PINS);
    let approvers = read(APPROVER_PINS);
    match (read(POLICY), read(PINS)) {
        (None, None) if execution.is_none() && approvers.is_none() => Ok(None),
        (Some(policy), Some(pins)) => Ok(Some(
            PackSettings::new(PathBuf::from(policy), paths(Some(pins)))?
                .with_outcome_pins(paths(execution), paths(approvers))?,
        )),
        _ => Err(format!(
            "el paquete de compliance necesita las dos variables {POLICY} y {PINS} (y {EXECUTION_PINS} y {APPROVER_PINS} solo junto con ellas)"
        )
        .into()),
    }
}

/// The attester pins and the policy, read once, when both are set (a set
/// with only one of them is refused by `pack_settings`).
fn trust_settings(
    approver: Option<&ApproverSigner>,
) -> Result<Option<EvidenceTrust>, Box<dyn std::error::Error>> {
    let (Some(policy), Some(pins)) = (
        env::var_os(POLICY_VARIABLE).filter(|value| !value.is_empty()),
        env::var_os(PINS_VARIABLE).filter(|value| !value.is_empty()),
    ) else {
        return Ok(None);
    };
    let pins: Vec<PathBuf> = env::split_paths(&pins)
        .filter(|path| !path.as_os_str().is_empty())
        .collect();
    let trust = EvidenceTrust::load(&PathBuf::from(policy), &pins, approver)?;
    Ok(Some(trust))
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
    // code in signal context; it only changes the disposition. That
    // disposition is process-wide (every thread) and is inherited by child
    // processes across fork and exec; the console starts none today.
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
