//! `praetore-safety-ingest`: post-hoc ingestion of safety actions (G1,
//! SAF-09.5).
//!
//! A separate process with its own database role (a member of
//! `praetore_safety_ingest`, not of `praetore_runtime`), its own key (the
//! ingestion key) and its own socket. It reads signed safety events from a
//! local Unix datagram socket, verifies them against pinned source keys,
//! classifies their names against a signed safety namespace manifest and
//! stores signed records, one hash chain per source, in
//! `praetore.safety_records`. Nothing on the decision path reads them.
//!
//! Failure modes, by design:
//!
//! * Startup fails closed **for ingestion only**: a missing or invalid
//!   manifest, a key shared by two roles, an unsafe database role or a
//!   schema that is not current makes this process refuse to start. The
//!   executors do not depend on it: their client never blocks, and their
//!   events are dropped locally while no ingester runs (the next event that
//!   arrives shows the gap, recorded as a signed loss record).
//! * A full queue or an unavailable database drops messages inside the
//!   ingester; they are counted and recorded as a signed loss record on the
//!   `_unattributed` chain as soon as one can be stored.
//!
//! Configuration (environment; key material only through files):
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `PRAETORE_SAFETY_SOCKET` | socket path; its directory must be owned by this user and not writable by others |
//! | `PRAETORE_SAFETY_SOCKET_GROUP` | optional numeric gid: the socket is `0660` with that group (default `0600`) |
//! | `PRAETORE_SAFETY_TENANT_ID` | the tenant of every record (UUID) |
//! | `PRAETORE_SAFETY_INGEST_KEY_FILE` | the ingestion key: 64 lowercase hex characters, owner-only file |
//! | `PRAETORE_SAFETY_MANIFEST_FILE` | the safety namespace manifest (`praetore policy safety-manifest`) |
//! | `PRAETORE_SAFETY_NAMESPACE_PIN_FILE` | the namespace public key (64 hex) |
//! | `PRAETORE_SAFETY_ATTESTER_PIN_FILE` | the gateway's evidence attester public key (64 hex), only to refuse sharing it |
//! | `PRAETORE_SAFETY_PREVIOUS_INGEST_PINS_FILE` | optional: previous ingestion public keys (64 hex each, one per line, at most 16), the registered rotation. A chain whose last record is signed by any other key makes the ingester refuse to start |
//! | `PRAETORE_SAFETY_SOURCE_PINS_FILE` | JSONL, one `{"source_id","public_key"}` per line |
//! | `PRAETORE_SAFETY_DATABASE_URL` or `PRAETORE_SAFETY_DATABASE_URL_FILE` | the ingester's own database role (TLS `verify-full` unless loopback) |
//! | `PRAETORE_SAFETY_QUEUE_CAPACITY` | messages buffered between the socket and the database (default 256, 1 to 4096) |
//! | `PRAETORE_SAFETY_MAX_CLOCK_SKEW_SECONDS` | an event whose `occurred_at` differs from the ingester's clock by more than this (default 300) keeps its status and carries `clock_skew_seconds` |
//! | `PRAETORE_SAFETY_MAX_SEQ_JUMP` | largest accepted step of `source_seq` above a chain's high-water mark (default 1000000, 1 to 2^53 - 1); a verified event further ahead is recorded as `rejected` (`seq_jump_too_large`) on `_unattributed` |
//!
//! The runtime-role relaxations of the gateway (`PRAETORE_RUNTIME_ALLOW_SETTINGS`,
//! `PRAETORE_SCHEMA_OWNER`, ...) apply to the ingester's role check too.
//!
//! Commands: `praetore-safety-ingest run` (the default) and
//! `praetore-safety-ingest doctor` (the startup checks only, without
//! binding the socket).

#[path = "secret_file.rs"]
mod secret_file;

use std::{
    io::Read,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixDatagram,
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use praetore_core::{
    SafetyNamespaceManifest, VerifiedPublicKey,
    safety_ingest::{
        DEFAULT_FLOOD_LIMITS, DEFAULT_MAX_CLOCK_SKEW_SECONDS, DEFAULT_MAX_SEQ_JUMP, FloodControl,
        FloodLimits, IngestorConfig, LossReason, MAX_FLOOD_LIMIT, MAX_SAFETY_EVENT_BYTES,
        PreparedRecords, SafetyIngestKey, SafetyIngestor, SafetyRecord, SafetyRecordStatus,
        SourcePins,
    },
};
use praetore_replay_postgres::{
    DatabaseConnector, PostgresSafetyStore, RuntimeRoleOptions, verify_safety_ingest_role_with,
    verify_schema_current,
};
use time::OffsetDateTime;
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const MAX_KEY_FILE_BYTES: u64 = 128;
const MAX_PIN_FILE_BYTES: u64 = 128;
const MAX_MANIFEST_BYTES: u64 = 128 * 1024;
const MAX_SOURCE_PINS_BYTES: u64 = 64 * 1024;
const MAX_URL_FILE_BYTES: u64 = 4096;
/// Largest datagram read. Longer ones are cut by the kernel; anything over
/// `MAX_SAFETY_EVENT_BYTES` is recorded as `rejected` (`too_large`).
const RECEIVE_BYTES: usize = 64 * 1024 + 1;
const _: () = assert!(RECEIVE_BYTES > MAX_SAFETY_EVENT_BYTES);
const RECEIVE_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_QUEUE_CAPACITY: usize = 256;
const MAX_QUEUE_CAPACITY: usize = 4096;
const POLL: Duration = Duration::from_millis(200);
/// 2^53 - 1, the largest `source_seq`.
const MAX_SAFE_SEQ: u64 = (1 << 53) - 1;
/// Counts of suppressed or dropped messages are recorded at most this
/// often (and when the ingester is idle or stops), so that a flood adds
/// about one record per reason per interval.
const COUNT_INTERVAL: Duration = Duration::from_secs(1);
const MAX_ALLOWED_UIDS: usize = 32;

fn main() {
    let mut args = std::env::args().skip(1);
    let command = args.next();
    let result = match (command.as_deref(), args.next()) {
        (None | Some("run"), None) => run(),
        (Some("doctor"), None) => doctor(),
        (Some("public-key"), Some(path)) if args.next().is_none() => public_key(Path::new(&path)),
        (Some("help" | "--help" | "-h"), None) => {
            println!(
                "Usage: praetore-safety-ingest [run|doctor]\n       \
                 praetore-safety-ingest public-key <secret key file>\n\nConfigured through \
                 PRAETORE_SAFETY_* environment variables; see docs/operations.md. public-key \
                 prints the Ed25519 public key (64 hex) of a 32-byte secret key file (the \
                 ingestion key, or a source key), the value to pin."
            );
            Ok(())
        }
        _ => {
            Err("usage: praetore-safety-ingest [run|doctor] | public-key <secret key file>".into())
        }
    };
    if let Err(error) = result {
        eprintln!("praetore-safety-ingest: {error}");
        std::process::exit(1);
    }
}

fn log(message: impl std::fmt::Display) {
    eprintln!("praetore-safety-ingest: {message}");
}

// ---------------------------------------------------------------------------
// Configuration.

struct Config {
    socket: PathBuf,
    socket_gid: Option<u32>,
    tenant_id: Uuid,
    ingest_key: SafetyIngestKey,
    manifest: SafetyNamespaceManifest,
    namespace_pin: VerifiedPublicKey,
    attester_pin: VerifiedPublicKey,
    previous_ingest_pins: Vec<VerifiedPublicKey>,
    sources: SourcePins,
    database: DatabaseConnector,
    queue_capacity: usize,
    max_seq_jump: u64,
    max_clock_skew_seconds: u64,
    flood: FloodLimits,
    allowed_uids: Option<Vec<u32>>,
    role_options: RuntimeRoleOptions,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn required(name: &str) -> Result<String> {
    var(name).ok_or_else(|| format!("{name} is required").into())
}

fn read_bounded(path: &Path, max: u64, what: &str) -> Result<Vec<u8>> {
    let file =
        std::fs::File::open(path).map_err(|error| format!("{what} {}: {error}", path.display()))?;
    if !file.metadata()?.is_file() {
        return Err(format!("{what} {} is not a regular file", path.display()).into());
    }
    let mut contents = Vec::new();
    file.take(max + 1).read_to_end(&mut contents)?;
    if contents.len() as u64 > max {
        return Err(format!("{what} {} is larger than {max} bytes", path.display()).into());
    }
    Ok(contents)
}

fn hex32(contents: &[u8], what: &str) -> Result<[u8; 32]> {
    let encoded = contents.strip_suffix(b"\n").unwrap_or(contents);
    if encoded.len() != 64
        || !encoded
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!("{what} must be 64 lowercase hex characters").into());
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(encoded, &mut bytes)?;
    Ok(bytes)
}

fn read_pin(variable: &str, what: &str) -> Result<VerifiedPublicKey> {
    let path = PathBuf::from(required(variable)?);
    let bytes = hex32(&read_bounded(&path, MAX_PIN_FILE_BYTES, what)?, what)?;
    Ok(VerifiedPublicKey::from_bytes(&bytes)
        .map_err(|_| format!("{what} is not a valid Ed25519 public key"))?)
}

/// The previous ingestion public keys: one 64-hex key per line.
fn read_previous_pins(path: &Path) -> Result<Vec<VerifiedPublicKey>> {
    const MAX_PREVIOUS_PINS: usize = 16;
    let what = "the previous ingestion pins";
    let text = String::from_utf8(read_bounded(path, MAX_PIN_FILE_BYTES * 17, what)?)
        .map_err(|_| format!("{what} are not UTF-8"))?;
    let mut pins: Vec<VerifiedPublicKey> = Vec::new();
    for line in text.lines() {
        let bytes = hex32(line.as_bytes(), what)?;
        let pin = VerifiedPublicKey::from_bytes(&bytes)
            .map_err(|_| format!("{what}: not a valid Ed25519 public key"))?;
        if pins.iter().any(|known| known.as_bytes() == pin.as_bytes()) {
            return Err(format!("{what}: a key is repeated").into());
        }
        pins.push(pin);
    }
    if pins.is_empty() || pins.len() > MAX_PREVIOUS_PINS {
        return Err(format!("{what}: between 1 and {MAX_PREVIOUS_PINS} keys").into());
    }
    Ok(pins)
}

fn read_secret(path: &Path, what: &str) -> Result<Vec<u8>> {
    secret_file::read_private_file(path, MAX_KEY_FILE_BYTES.max(MAX_URL_FILE_BYTES))
        .map_err(|error| format!("{what} {} {error}", path.display()).into())
}

fn load_config() -> Result<Config> {
    for refused in [
        "PRAETORE_SAFETY_INGEST_KEY",
        "PRAETORE_SAFETY_INGEST_KEY_HEX",
    ] {
        if std::env::var_os(refused).is_some() {
            return Err(format!(
                "{refused} is set: key material is read only from a file \
                 (PRAETORE_SAFETY_INGEST_KEY_FILE)"
            )
            .into());
        }
    }
    let socket = PathBuf::from(required("PRAETORE_SAFETY_SOCKET")?);
    if !socket.is_absolute() {
        return Err("PRAETORE_SAFETY_SOCKET must be an absolute path".into());
    }
    let socket_gid = var("PRAETORE_SAFETY_SOCKET_GROUP")
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| "PRAETORE_SAFETY_SOCKET_GROUP must be a numeric gid")
        })
        .transpose()?;
    let tenant_id = Uuid::parse_str(&required("PRAETORE_SAFETY_TENANT_ID")?)
        .map_err(|_| "PRAETORE_SAFETY_TENANT_ID must be a UUID")?;
    let key_path = PathBuf::from(required("PRAETORE_SAFETY_INGEST_KEY_FILE")?);
    let key_contents = read_secret(&key_path, "the ingestion key file")?;
    if key_contents.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err("the ingestion key file is too large".into());
    }
    let ingest_key =
        SafetyIngestKey::from_secret_bytes(&hex32(&key_contents, "the ingestion key")?);
    let manifest_path = PathBuf::from(required("PRAETORE_SAFETY_MANIFEST_FILE")?);
    let manifest_text = String::from_utf8(read_bounded(
        &manifest_path,
        MAX_MANIFEST_BYTES,
        "the safety namespace manifest",
    )?)
    .map_err(|_| "the safety namespace manifest is not UTF-8")?;
    let manifest = SafetyNamespaceManifest::from_file(&manifest_text)
        .map_err(|error| format!("the safety namespace manifest: {error}"))?;
    let namespace_pin = read_pin("PRAETORE_SAFETY_NAMESPACE_PIN_FILE", "the namespace pin")?;
    let attester_pin = read_pin("PRAETORE_SAFETY_ATTESTER_PIN_FILE", "the attester pin")?;
    let previous_ingest_pins = match var("PRAETORE_SAFETY_PREVIOUS_INGEST_PINS_FILE") {
        None => Vec::new(),
        Some(path) => read_previous_pins(Path::new(&path))?,
    };
    let pins_path = PathBuf::from(required("PRAETORE_SAFETY_SOURCE_PINS_FILE")?);
    let pins_text = String::from_utf8(read_bounded(
        &pins_path,
        MAX_SOURCE_PINS_BYTES,
        "the source pins",
    )?)
    .map_err(|_| "the source pins are not UTF-8")?;
    let sources =
        SourcePins::from_jsonl(&pins_text).map_err(|error| format!("the source pins: {error}"))?;
    let url = match (
        var("PRAETORE_SAFETY_DATABASE_URL"),
        var("PRAETORE_SAFETY_DATABASE_URL_FILE"),
    ) {
        (Some(url), None) => url,
        (None, Some(path)) => {
            let contents = read_secret(Path::new(&path), "the database URL file")?;
            String::from_utf8(contents)
                .map_err(|_| "the database URL file is not UTF-8")?
                .trim_end()
                .to_owned()
        }
        _ => {
            return Err("set exactly one of PRAETORE_SAFETY_DATABASE_URL and \
                 PRAETORE_SAFETY_DATABASE_URL_FILE"
                .into());
        }
    };
    let database = DatabaseConnector::from_url(&url)
        .map_err(|error| format!("PRAETORE_SAFETY_DATABASE_URL: {error}"))?
        .connect_timeout(Duration::from_secs(3));
    let queue_capacity = match var("PRAETORE_SAFETY_QUEUE_CAPACITY") {
        None => DEFAULT_QUEUE_CAPACITY,
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|capacity| (1..=MAX_QUEUE_CAPACITY).contains(capacity))
            .ok_or(format!(
                "PRAETORE_SAFETY_QUEUE_CAPACITY must be between 1 and {MAX_QUEUE_CAPACITY}"
            ))?,
    };
    let max_seq_jump = match var("PRAETORE_SAFETY_MAX_SEQ_JUMP") {
        None => DEFAULT_MAX_SEQ_JUMP,
        Some(value) => value
            .parse::<u64>()
            .ok()
            .filter(|jump| (1..=MAX_SAFE_SEQ).contains(jump))
            .ok_or("PRAETORE_SAFETY_MAX_SEQ_JUMP must be between 1 and 2^53 - 1")?,
    };
    let max_clock_skew_seconds = match var("PRAETORE_SAFETY_MAX_CLOCK_SKEW_SECONDS") {
        None => DEFAULT_MAX_CLOCK_SKEW_SECONDS,
        Some(value) => value
            .parse::<u64>()
            .ok()
            .filter(|seconds| *seconds <= MAX_SAFE_SEQ)
            .ok_or("PRAETORE_SAFETY_MAX_CLOCK_SKEW_SECONDS must be a number of seconds")?,
    };
    let limit = |name: &str, default: u64| -> Result<u64> {
        match var(name) {
            None => Ok(default),
            Some(value) => value
                .parse::<u64>()
                .ok()
                .filter(|limit| (1..=MAX_FLOOD_LIMIT).contains(limit))
                .ok_or_else(|| format!("{name} must be between 1 and {MAX_FLOOD_LIMIT}").into()),
        }
    };
    let flood = FloodLimits {
        source_rate: limit(
            "PRAETORE_SAFETY_SOURCE_RATE",
            DEFAULT_FLOOD_LIMITS.source_rate,
        )?,
        source_burst: limit(
            "PRAETORE_SAFETY_SOURCE_BURST",
            DEFAULT_FLOOD_LIMITS.source_burst,
        )?,
        rejected_rate: limit(
            "PRAETORE_SAFETY_REJECTED_RATE",
            DEFAULT_FLOOD_LIMITS.rejected_rate,
        )?,
        rejected_burst: limit(
            "PRAETORE_SAFETY_REJECTED_BURST",
            DEFAULT_FLOOD_LIMITS.rejected_burst,
        )?,
    };
    let allowed_uids = var("PRAETORE_SAFETY_ALLOWED_UIDS")
        .map(|value| parse_allowed_uids(&value))
        .transpose()?;
    if allowed_uids.is_some() && !cfg!(target_os = "linux") {
        return Err("PRAETORE_SAFETY_ALLOWED_UIDS needs Linux (SO_PASSCRED and \
                    SCM_CREDENTIALS); on this platform the socket permissions \
                    (0600, or 0660 with PRAETORE_SAFETY_SOCKET_GROUP) are the only check of \
                    who may send"
            .into());
    }
    let role_options = RuntimeRoleOptions::from_config(|name| std::env::var(name).ok())?;
    Ok(Config {
        socket,
        socket_gid,
        tenant_id,
        ingest_key,
        manifest,
        namespace_pin,
        attester_pin,
        previous_ingest_pins,
        sources,
        database,
        queue_capacity,
        max_seq_jump,
        max_clock_skew_seconds,
        flood,
        allowed_uids,
        role_options,
    })
}

/// `PRAETORE_SAFETY_ALLOWED_UIDS`: comma-separated numeric user ids, at
/// least one, at most 32, no repeats.
fn parse_allowed_uids(value: &str) -> Result<Vec<u32>> {
    let mut uids = Vec::new();
    for part in value.split(',') {
        let uid = part
            .trim()
            .parse::<u32>()
            .map_err(|_| format!("PRAETORE_SAFETY_ALLOWED_UIDS: {part:?} is not a user id"))?;
        if uids.contains(&uid) {
            return Err(format!("PRAETORE_SAFETY_ALLOWED_UIDS lists {uid} twice").into());
        }
        uids.push(uid);
    }
    if uids.len() > MAX_ALLOWED_UIDS {
        return Err(
            format!("PRAETORE_SAFETY_ALLOWED_UIDS lists more than {MAX_ALLOWED_UIDS}").into(),
        );
    }
    Ok(uids)
}

// ---------------------------------------------------------------------------
// Startup checks.

/// Verifies the manifest and the distinct keys (no flag skips either).
fn build_ingestor(config: Config) -> Result<(SafetyIngestor, Runtime)> {
    let ingest_pin = config.ingest_key.public_key()?;
    if config
        .previous_ingest_pins
        .iter()
        .any(|pin| pin.as_bytes() == ingest_pin.as_bytes())
    {
        return Err(
            "PRAETORE_SAFETY_PREVIOUS_INGEST_PINS_FILE lists the current ingestion key".into(),
        );
    }
    let mut head_pins = vec![ingest_pin.clone()];
    head_pins.extend(config.previous_ingest_pins);
    let ingestor = SafetyIngestor::new(IngestorConfig {
        ingest_key: config.ingest_key,
        tenant_id: config.tenant_id,
        manifest: config.manifest,
        namespace_pin: config.namespace_pin,
        attester_pin: config.attester_pin,
        sources: config.sources,
        max_seq_jump: config.max_seq_jump,
        max_clock_skew_seconds: config.max_clock_skew_seconds,
    })?;
    Ok((
        ingestor,
        Runtime {
            ingest_pin,
            head_pins,
            socket: config.socket,
            socket_gid: config.socket_gid,
            database: config.database,
            queue_capacity: config.queue_capacity,
            flood: config.flood,
            allowed_uids: config.allowed_uids,
            role_options: config.role_options,
        },
    ))
}

impl Runtime {
    /// The previous ingestion keys of a registered rotation.
    fn previous_pins(&self) -> &[VerifiedPublicKey] {
        &self.head_pins[1..]
    }
}

struct Runtime {
    ingest_pin: VerifiedPublicKey,
    /// The current ingestion key, then the previous ones: a chain head must
    /// be signed by one of them.
    head_pins: Vec<VerifiedPublicKey>,
    socket: PathBuf,
    socket_gid: Option<u32>,
    database: DatabaseConnector,
    queue_capacity: usize,
    flood: FloodLimits,
    allowed_uids: Option<Vec<u32>>,
    role_options: RuntimeRoleOptions,
}

/// Connects, checks the role and the schema, takes the tenant lock and
/// loads the chain heads.
fn open_store(
    runtime: &Runtime,
    ingestor: &SafetyIngestor,
) -> Result<(PostgresSafetyStore, Vec<SafetyRecord>)> {
    let mut client = runtime.database.connect()?;
    verify_safety_ingest_role_with(&mut client, &runtime.role_options)?;
    verify_schema_current(&mut client)?;
    let mut store = PostgresSafetyStore::from_client(client);
    store.check_registration(ingestor.tenant_id(), Some(ingestor.key_id()))?;
    if !store.try_lock_tenant(ingestor.tenant_id())? {
        return Err(format!(
            "another praetore-safety-ingest holds the lock of tenant {}; refusing to start",
            ingestor.tenant_id()
        )
        .into());
    }
    let mut heads = Vec::new();
    for (chain, stored) in store.load_heads(ingestor.tenant_id(), &runtime.head_pins)? {
        if stored.key_id != ingestor.key_id() {
            log(format!(
                "the last record of chain {chain} is signed by the previous ingestion key {}; \
                 the chain continues under this key (pin both to verify it)",
                stored.key_id
            ));
        }
        heads.push(stored.record);
    }
    Ok((store, heads))
}

/// The socket directory must be a real directory owned by this user and
/// not writable by others (nor by the group, unless a group is configured).
/// An existing entry at the path must be a socket nobody listens on.
fn check_socket_path(socket: &Path, group: Option<u32>) -> Result<bool> {
    let directory = socket
        .parent()
        .ok_or("PRAETORE_SAFETY_SOCKET has no parent directory")?;
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|error| format!("socket directory {}: {error}", directory.display()))?;
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "socket directory {} is not a directory (or is a symlink)",
            directory.display()
        )
        .into());
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(format!(
            "socket directory {} is not owned by this user",
            directory.display()
        )
        .into());
    }
    let mode = metadata.permissions().mode();
    let forbidden = if group.is_some() { 0o002 } else { 0o022 };
    if mode & forbidden != 0 {
        return Err(format!(
            "socket directory {} is writable by {} (mode {:o})",
            directory.display(),
            if group.is_some() {
                "others"
            } else {
                "group or others"
            },
            mode & 0o777
        )
        .into());
    }
    match std::fs::symlink_metadata(socket) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("socket {}: {error}", socket.display()).into()),
        Ok(existing) if !existing.file_type().is_socket() => Err(format!(
            "{} exists and is not a socket; refusing to replace it",
            socket.display()
        )
        .into()),
        Ok(_) => {
            let probe = UnixDatagram::unbound()?;
            probe.set_nonblocking(true)?;
            match probe.send_to(&[], socket) {
                Ok(_) => Err(format!(
                    "another process listens on {}; refusing to start",
                    socket.display()
                )
                .into()),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => Ok(true),
                Err(error) => Err(format!("socket {}: {error}", socket.display()).into()),
            }
        }
    }
}

fn bind_socket(socket: &Path, group: Option<u32>) -> Result<(UnixDatagram, (u64, u64))> {
    if check_socket_path(socket, group)? {
        log(format!("removing the stale socket {}", socket.display()));
        std::fs::remove_file(socket)?;
    }
    // Created 0600 (umask 0177): no window in which others could connect.
    let previous = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o177));
    let bound = UnixDatagram::bind(socket);
    rustix::process::umask(previous);
    let listener = bound.map_err(|error| format!("bind {}: {error}", socket.display()))?;
    if let Some(gid) = group {
        rustix::fs::chown(socket, None, Some(rustix::fs::Gid::from_raw(gid)))
            .map_err(|error| format!("chown {} to gid {gid}: {error}", socket.display()))?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660))?;
    }
    let metadata = std::fs::symlink_metadata(socket)?;
    if !metadata.file_type().is_socket() || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(format!("{} is not the socket this process bound", socket.display()).into());
    }
    let _ = rustix::net::sockopt::set_socket_recv_buffer_size(&listener, RECEIVE_BUFFER_BYTES);
    listener.set_read_timeout(Some(POLL))?;
    Ok((listener, (metadata.dev(), metadata.ino())))
}

/// Prints the public key of a secret key file (read as a private file).
fn public_key(path: &Path) -> Result<()> {
    let contents = read_secret(path, "the key file")?;
    if contents.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err("the key file is too large".into());
    }
    let key = SafetyIngestKey::from_secret_bytes(&hex32(&contents, "the key")?);
    println!("{}", hex::encode(key.public_key()?.as_bytes()));
    Ok(())
}

fn doctor() -> Result<()> {
    let mut healthy = true;
    let mut report = |ok: bool, what: String| {
        println!("[{}] {what}", if ok { "ok" } else { "failed" });
        healthy &= ok;
    };
    let config = match load_config() {
        Ok(config) => {
            report(true, "configuration, key, pins and manifest files".into());
            config
        }
        Err(error) => {
            report(false, format!("configuration: {error}"));
            return Err("doctor found problems".into());
        }
    };
    let socket = config.socket.clone();
    let group = config.socket_gid;
    match build_ingestor(config) {
        Ok((ingestor, runtime)) => {
            report(
                true,
                format!(
                    "ingestion key id {} (public key {})",
                    ingestor.key_id(),
                    hex::encode(runtime.ingest_pin.as_bytes())
                ),
            );
            report(
                true,
                format!(
                    "manifest verified against the namespace pin (policy {} v{}, {} safety \
                     names); ingestion, namespace, attester and {} source keys are distinct",
                    ingestor.manifest().policy_id(),
                    ingestor.manifest().policy_version(),
                    ingestor.manifest().safety_actions().len(),
                    ingestor.sources().len()
                ),
            );
            match open_store(&runtime, &ingestor) {
                Ok((_, heads)) => report(
                    true,
                    format!(
                        "database role, schema, tenant registration and tenant lock ({} \
                         chains)",
                        heads.len()
                    ),
                ),
                Err(error) => report(false, format!("database: {error}")),
            }
        }
        Err(error) => report(false, format!("{error}")),
    }
    match check_socket_path(&socket, group) {
        Ok(stale) => report(
            true,
            format!(
                "socket path {}{}",
                socket.display(),
                if stale {
                    " (a stale socket will be replaced)"
                } else {
                    ""
                }
            ),
        ),
        Err(error) => report(false, format!("socket: {error}")),
    }
    if healthy {
        Ok(())
    } else {
        Err("doctor found problems".into())
    }
}

// ---------------------------------------------------------------------------
// Running.

fn run() -> Result<()> {
    let (mut ingestor, runtime) = build_ingestor(load_config()?)?;
    let (store, heads) = open_store(&runtime, &ingestor)?;
    ingestor.resume_heads(heads, runtime.previous_pins())?;
    let (listener, identity) = bind_socket(&runtime.socket, runtime.socket_gid)?;
    log(format!(
        "listening on {} (tenant {}, ingestion key {}, {} sources, manifest policy {} v{}, \
         queue {})",
        runtime.socket.display(),
        ingestor.tenant_id(),
        ingestor.key_id(),
        ingestor.sources().len(),
        ingestor.manifest().policy_id(),
        ingestor.manifest().policy_version(),
        runtime.queue_capacity
    ));

    let stop = Arc::new(AtomicBool::new(false));
    spawn_signal_thread(Arc::clone(&stop))?;
    let overflow = Arc::new(AtomicU64::new(0));
    let refused = Arc::new(AtomicU64::new(0));
    let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(runtime.queue_capacity);
    let peers = PeerCheck::new(&listener, runtime.allowed_uids.clone())?;
    let reader = {
        let stop = Arc::clone(&stop);
        let overflow = Arc::clone(&overflow);
        let refused = Arc::clone(&refused);
        thread::Builder::new()
            .name("safety-socket".into())
            .spawn(move || read_socket(listener, sender, &stop, &overflow, &peers, &refused))?
    };

    let started = Instant::now();
    let mut worker = Worker {
        ingestor,
        store: Some(store),
        runtime: &runtime,
        overflow: &overflow,
        refused: &refused,
        storage_dropped: 0,
        flood: FloodControl::new(runtime.flood)?,
        started,
        last_count: started,
    };
    loop {
        match receiver.recv_timeout(POLL) {
            Ok(message) => worker.handle(&message),
            Err(mpsc::RecvTimeoutError::Timeout) => worker.flush_dropped(),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    // The reader has stopped and the queue is drained: record what was
    // dropped, then remove the socket if it is still ours.
    let _ = reader.join();
    worker.flush_dropped();
    if let Ok(metadata) = std::fs::symlink_metadata(&runtime.socket)
        && (metadata.dev(), metadata.ino()) == identity
    {
        let _ = std::fs::remove_file(&runtime.socket);
    }
    let pending = worker.overflow.load(Ordering::Relaxed)
        + worker.refused.load(Ordering::Relaxed)
        + worker.storage_dropped
        + u64::from(worker.flood.has_pending());
    log(format!(
        "stopped{}",
        if pending > 0 {
            format!("; {pending} dropped messages could not be recorded")
        } else {
            String::new()
        }
    ));
    Ok(())
}

fn spawn_signal_thread(stop: Arc<AtomicBool>) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    thread::Builder::new()
        .name("safety-signals".into())
        .spawn(move || {
            runtime.block_on(async {
                use tokio::signal::unix::{SignalKind, signal};
                let (Ok(mut terminate), Ok(mut interrupt)) = (
                    signal(SignalKind::terminate()),
                    signal(SignalKind::interrupt()),
                ) else {
                    return;
                };
                tokio::select! {
                    _ = terminate.recv() => {}
                    _ = interrupt.recv() => {}
                }
            });
            log("shutting down");
            stop.store(true, Ordering::SeqCst);
        })?;
    Ok(())
}

/// The sender check of `PRAETORE_SAFETY_ALLOWED_UIDS` (Linux only): with
/// `SO_PASSCRED` the kernel attaches the sending process's credentials to
/// every datagram (`SCM_CREDENTIALS`), and a datagram from any other user
/// id is counted (`peer_refused`) and not read.
struct PeerCheck {
    allowed: Option<Vec<u32>>,
}

impl PeerCheck {
    fn new(listener: &UnixDatagram, allowed: Option<Vec<u32>>) -> Result<Self> {
        #[cfg(target_os = "linux")]
        if allowed.is_some() {
            rustix::net::sockopt::set_socket_passcred(listener, true)
                .map_err(|error| format!("SO_PASSCRED on the socket: {error}"))?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = listener;
            if allowed.is_some() {
                return Err("PRAETORE_SAFETY_ALLOWED_UIDS needs Linux".into());
            }
        }
        Ok(Self { allowed })
    }

    /// Receives one datagram: its length, and whether its sender is
    /// allowed.
    fn recv(&self, listener: &UnixDatagram, buffer: &mut [u8]) -> std::io::Result<(usize, bool)> {
        let Some(allowed) = &self.allowed else {
            return listener.recv(buffer).map(|read| (read, true));
        };
        #[cfg(target_os = "linux")]
        {
            use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};
            let mut space =
                [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
            let mut control = RecvAncillaryBuffer::new(&mut space);
            let mut iov = [std::io::IoSliceMut::new(buffer)];
            let received = recvmsg(listener, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC)?;
            let mut sender = None;
            for message in control.drain() {
                if let RecvAncillaryMessage::ScmCredentials(credentials) = message {
                    sender = Some(credentials.uid.as_raw());
                }
            }
            Ok((
                received.bytes,
                sender.is_some_and(|uid| allowed.contains(&uid)),
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (allowed, listener, buffer);
            Err(std::io::Error::other(
                "PRAETORE_SAFETY_ALLOWED_UIDS needs Linux",
            ))
        }
    }
}

/// Reads datagrams into the bounded queue. Never waits for the database:
/// when the queue is full the message is counted and dropped.
fn read_socket(
    listener: UnixDatagram,
    sender: mpsc::SyncSender<Vec<u8>>,
    stop: &AtomicBool,
    overflow: &AtomicU64,
    peers: &PeerCheck,
    refused: &AtomicU64,
) {
    let mut buffer = vec![0; RECEIVE_BYTES];
    while !stop.load(Ordering::SeqCst) {
        match peers.recv(&listener, &mut buffer) {
            Ok((_, false)) => {
                refused.fetch_add(1, Ordering::Relaxed);
            }
            // A zero-length datagram is a liveness probe (another ingester
            // starting); it is not an event.
            Ok((0, true)) => {}
            Ok((read, true)) => match sender.try_send(buffer[..read.min(RECEIVE_BYTES)].to_vec()) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(_)) => {
                    overflow.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::TrySendError::Disconnected(_)) => return,
            },
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => {
                log(format!("socket read failed: {error}"));
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

struct Worker<'a> {
    ingestor: SafetyIngestor,
    store: Option<PostgresSafetyStore>,
    runtime: &'a Runtime,
    overflow: &'a AtomicU64,
    refused: &'a AtomicU64,
    storage_dropped: u64,
    flood: FloodControl,
    started: Instant,
    last_count: Instant,
}

impl Worker<'_> {
    fn handle(&mut self, message: &[u8]) {
        if self.last_count.elapsed() >= COUNT_INTERVAL {
            self.flush_dropped();
        }
        let Some(store) = self.store.as_mut() else {
            self.storage_dropped += 1;
            self.reconnect();
            return;
        };
        let prepared = match self.ingestor.prepare_limited(
            message,
            OffsetDateTime::now_utc(),
            self.started.elapsed(),
            store,
            &mut self.flood,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                log(format!("message not recorded: {error}"));
                self.storage_dropped += 1;
                self.after_failure();
                return;
            }
        };
        if let Some(suppressed) = &prepared.suppressed {
            self.flood.count(suppressed);
            return;
        }
        if self.persist(&prepared) {
            for record in &prepared.records {
                let payload = record.payload();
                if payload.status != SafetyRecordStatus::Accepted {
                    log(format!(
                        "recorded {} on chain {} at {}{}",
                        payload.status.as_str(),
                        payload.chain,
                        payload.chain_seq,
                        payload
                            .reason
                            .as_deref()
                            .map(|reason| format!(" ({reason})"))
                            .unwrap_or_default()
                    ));
                }
            }
        } else {
            self.storage_dropped += 1;
        }
    }

    fn persist(&mut self, prepared: &PreparedRecords) -> bool {
        let Some(store) = self.store.as_mut() else {
            return false;
        };
        match store.store(self.ingestor.tenant_id(), prepared) {
            Ok(()) => match self.ingestor.commit(prepared) {
                Ok(()) => true,
                // Stored, but not on the head this ingester holds: read the
                // heads again from the database.
                Err(error) => {
                    log(format!("{error}"));
                    self.after_failure();
                    true
                }
            },
            Err(error) => {
                log(format!("storing failed: {error}"));
                self.after_failure();
                false
            }
        }
    }

    /// After a storage error: reconnect when the connection is gone, and
    /// read the heads again either way (the database is the truth).
    fn after_failure(&mut self) {
        let closed = self
            .store
            .as_mut()
            .is_none_or(|store| store.client().is_closed());
        if closed {
            self.store = None;
            self.reconnect();
        } else if let Some(store) = self.store.as_mut() {
            match store.load_heads(self.ingestor.tenant_id(), &self.runtime.head_pins) {
                Ok(heads) => {
                    if let Err(error) = self.ingestor.resume_heads(
                        heads.into_values().map(|stored| stored.record),
                        self.runtime.previous_pins(),
                    ) {
                        log(format!("the stored chain heads were refused: {error}"));
                    }
                }
                Err(error) => log(format!("reading the chain heads failed: {error}")),
            }
        }
    }

    fn reconnect(&mut self) {
        match open_store(self.runtime, &self.ingestor) {
            Ok((store, heads)) => {
                if self
                    .ingestor
                    .resume_heads(heads, self.runtime.previous_pins())
                    .is_ok()
                {
                    log("database connection restored");
                    self.store = Some(store);
                }
            }
            Err(error) => {
                log(format!("database unavailable: {error}"));
                thread::sleep(Duration::from_millis(500));
            }
        }
    }

    /// Records the messages dropped so far (a full queue, the database
    /// unavailable) and the counts of suppressed ones (rate limits, exact
    /// duplicates, refused peers) as signed records on the unattributed
    /// chain.
    fn flush_dropped(&mut self) {
        self.last_count = Instant::now();
        self.flood.add(
            LossReason::PeerRefused,
            None,
            self.refused.swap(0, Ordering::Relaxed),
        );
        if self.store.is_none() {
            if self.overflow.load(Ordering::Relaxed) + self.storage_dropped > 0
                || self.flood.has_pending()
            {
                self.reconnect();
            }
            if self.store.is_none() {
                return;
            }
        }
        for count in self.flood.take_pending() {
            let stored = match self.ingestor.prepare_count(
                count.reason,
                count.count,
                count.detail.as_deref(),
                OffsetDateTime::now_utc(),
            ) {
                Ok(prepared) => self.persist(&prepared),
                Err(error) => {
                    log(format!("cannot sign a count record: {error}"));
                    false
                }
            };
            if stored {
                log(format!(
                    "recorded {} messages not stored one by one ({})",
                    count.count,
                    count.reason.as_str()
                ));
            } else {
                self.flood.restore(count);
            }
        }
        let overflow = self.overflow.swap(0, Ordering::Relaxed);
        for (reason, count) in [
            (LossReason::QueueOverflow, overflow),
            (
                LossReason::StorageError,
                std::mem::take(&mut self.storage_dropped),
            ),
        ] {
            if count == 0 {
                continue;
            }
            let stored =
                match self
                    .ingestor
                    .prepare_dropped(reason, count, OffsetDateTime::now_utc())
                {
                    Ok(prepared) => self.persist(&prepared),
                    Err(error) => {
                        log(format!("cannot sign a loss record: {error}"));
                        false
                    }
                };
            if stored {
                log(format!(
                    "recorded the loss of {count} messages ({})",
                    reason.as_str()
                ));
            } else {
                match reason {
                    LossReason::QueueOverflow => {
                        self.overflow.fetch_add(count, Ordering::Relaxed);
                    }
                    _ => self.storage_dropped += count,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str, mode: u32) -> Self {
            let path = PathBuf::from("/tmp").join(format!("psi-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            Self(path)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_socket_is_created_owner_only_or_with_its_group() {
        let dir = Dir::new("mode", 0o700);
        let socket = dir.0.join("s");
        let (listener, _) = bind_socket(&socket, None).unwrap();
        let mode = std::fs::symlink_metadata(&socket)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        drop(listener);
        // A stale socket (nobody listens) is replaced.
        let (listener, _) = bind_socket(&socket, None).unwrap();
        // A live one is not.
        assert!(
            bind_socket(&socket, None)
                .unwrap_err()
                .to_string()
                .contains("another process listens")
        );
        drop(listener);
        std::fs::remove_file(&socket).unwrap();
        let gid = std::fs::metadata(&dir.0).unwrap().gid();
        let (_listener, _) = bind_socket(&socket, Some(gid)).unwrap();
        let metadata = std::fs::symlink_metadata(&socket).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
        assert_eq!(metadata.gid(), gid);
    }

    #[test]
    fn an_unsafe_socket_path_is_refused() {
        // Not a socket: never replaced.
        let dir = Dir::new("file", 0o700);
        let socket = dir.0.join("s");
        std::fs::write(&socket, b"keep").unwrap();
        assert!(
            bind_socket(&socket, None)
                .unwrap_err()
                .to_string()
                .contains("is not a socket")
        );
        assert_eq!(std::fs::read(&socket).unwrap(), b"keep");
        // A symlink at the path is not followed or replaced.
        std::fs::remove_file(&socket).unwrap();
        std::os::unix::fs::symlink("/tmp", &socket).unwrap();
        assert!(bind_socket(&socket, None).is_err());
        // A directory writable by group or others.
        let open = Dir::new("open", 0o777);
        assert!(
            bind_socket(&open.0.join("s"), None)
                .unwrap_err()
                .to_string()
                .contains("writable")
        );
        let group = Dir::new("group", 0o770);
        assert!(bind_socket(&group.0.join("s"), None).is_err());
        let gid = std::fs::metadata(&group.0).unwrap().gid();
        assert!(bind_socket(&group.0.join("s"), Some(gid)).is_ok());
    }
}
