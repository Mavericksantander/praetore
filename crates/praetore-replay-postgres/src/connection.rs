//! Database URL policy and TLS for every PRÆTORE PostgreSQL connection.
//!
//! The URL is checked before any socket is opened:
//!
//! - `sslmode=verify-full` (URL form only) connects with rustls, verifies the
//!   server certificate chain against `sslrootcert` (a PEM file, required)
//!   and checks that the certificate names the host. Plaintext fallback is
//!   impossible: the connection is configured with TLS required.
//! - `sslmode=disable` or no `sslmode` is accepted only when every host is a
//!   Unix socket, `localhost` or a loopback IP (and every `hostaddr` is a
//!   loopback IP).
//! - `prefer`, `require` and `verify-ca` are refused: none of them binds the
//!   certificate to the host name.
//!
//! SCRAM channel binding is not offered (`tls-server-end-point` is not
//! computed); the server is authenticated by `verify-full` instead, so
//! `channel_binding=require` is not supported.

use postgres::{
    Client, NoTls, Socket,
    config::{Host, SslMode},
    tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream},
};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_ROOT_CERT_BYTES: u64 = 1_048_576;

#[derive(Debug)]
pub enum DatabaseUrlError {
    /// The URL could not be parsed.
    Invalid(String),
    /// TLS is required (non-loopback host) and `sslmode=verify-full` is absent.
    TlsRequired,
    /// An `sslmode` that does not authenticate the server host.
    UnsupportedSslMode(String),
    /// `sslmode=verify-full` without a usable `sslrootcert`.
    RootCertificate(String),
}

impl fmt::Display for DatabaseUrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid PostgreSQL URL: {reason}"),
            Self::TlsRequired => write!(
                f,
                "PostgreSQL hosts other than loopback or a Unix socket require \
                 sslmode=verify-full and sslrootcert in the URL"
            ),
            Self::UnsupportedSslMode(mode) => write!(
                f,
                "sslmode={mode} does not verify the server host; use verify-full \
                 (or disable for loopback only)"
            ),
            Self::RootCertificate(reason) => {
                write!(f, "sslmode=verify-full root certificate: {reason}")
            }
        }
    }
}

impl std::error::Error for DatabaseUrlError {}

/// A validated connection target. Cloning shares the TLS configuration.
#[derive(Clone)]
pub struct DatabaseConnector {
    config: postgres::Config,
    tls: Option<RustlsConnect>,
}

impl fmt::Debug for DatabaseConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the config: it may hold a password.
        f.debug_struct("DatabaseConnector")
            .field("tls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

impl DatabaseConnector {
    /// Validates the URL and the TLS policy without connecting.
    pub fn from_url(url: &str) -> Result<Self, DatabaseUrlError> {
        let (stripped, ssl) = extract_tls_parameters(url)?;
        let mut config = postgres::Config::from_str(&stripped)
            .map_err(|error| DatabaseUrlError::Invalid(error.to_string()))?;
        if config.get_hosts().is_empty() {
            return Err(DatabaseUrlError::Invalid("no host".into()));
        }
        let mode = match ssl.mode.as_deref() {
            None => config_ssl_mode(&config),
            Some(mode) => mode.to_owned(),
        };
        let tls = match mode.as_str() {
            "disable" | "" => {
                if !is_loopback(&config) {
                    return Err(DatabaseUrlError::TlsRequired);
                }
                config.ssl_mode(SslMode::Disable);
                None
            }
            "verify-full" => {
                let path = ssl.root_cert.ok_or_else(|| {
                    DatabaseUrlError::RootCertificate("sslrootcert is required".into())
                })?;
                config.ssl_mode(SslMode::Require);
                Some(RustlsConnect::from_root_file(&path)?)
            }
            other => return Err(DatabaseUrlError::UnsupportedSslMode(other.to_owned())),
        };
        // Defence in depth: every session starts with the runtime search
        // path, whatever the database, role or ALTER SYSTEM set. Runtime
        // transactions also pin it with SET LOCAL (`set_tenant_context`).
        let options = match config.get_options() {
            Some(existing) if !existing.trim().is_empty() => {
                // A trailing unescaped backslash would join the pin to the
                // last option; such an URL is refused.
                let trailing = existing.chars().rev().take_while(|c| *c == '\\').count();
                if trailing % 2 == 1 {
                    return Err(DatabaseUrlError::Invalid(
                        "options must not end with an unescaped backslash".into(),
                    ));
                }
                format!("{existing} -c search_path=pg_catalog,pg_temp")
            }
            _ => "-c search_path=pg_catalog,pg_temp".to_owned(),
        };
        config.options(&options);
        Ok(Self { config, tls })
    }

    pub fn connect(&self) -> Result<Client, postgres::Error> {
        match &self.tls {
            Some(tls) => self.config.connect(tls.clone()),
            None => self.config.connect(NoTls),
        }
    }

    pub fn uses_tls(&self) -> bool {
        self.tls.is_some()
    }

    pub fn is_loopback(&self) -> bool {
        is_loopback(&self.config)
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout(timeout);
        self
    }
}

fn config_ssl_mode(config: &postgres::Config) -> String {
    // `sslmode` given in key/value form is parsed by `postgres::Config`.
    match config.get_ssl_mode() {
        SslMode::Disable => "disable".into(),
        SslMode::Require => "require".into(),
        // Prefer is the library default when the URL names no mode.
        _ => String::new(),
    }
}

fn is_loopback(config: &postgres::Config) -> bool {
    let hosts_loopback = config.get_hosts().iter().all(|host| match host {
        Host::Tcp(host) => {
            host == "localhost"
                || host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        }
        #[cfg(unix)]
        Host::Unix(_) => true,
    });
    hosts_loopback
        && config
            .get_hostaddrs()
            .iter()
            .all(|address| address.is_loopback())
}

#[derive(Default)]
struct TlsParameters {
    mode: Option<String>,
    root_cert: Option<String>,
}

/// Removes `sslmode` and `sslrootcert` from a URL-form connection string,
/// because `postgres::Config` does not know `verify-full` or `sslrootcert`.
/// Key/value strings are returned unchanged.
fn extract_tls_parameters(url: &str) -> Result<(String, TlsParameters), DatabaseUrlError> {
    let mut parameters = TlsParameters::default();
    if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
        return Ok((url.to_owned(), parameters));
    }
    let Some((base, query)) = url.split_once('?') else {
        return Ok((url.to_owned(), parameters));
    };
    let mut kept = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let slot = match key {
            "sslmode" => &mut parameters.mode,
            "sslrootcert" => &mut parameters.root_cert,
            _ => {
                kept.push(pair);
                continue;
            }
        };
        if slot.is_some() {
            return Err(DatabaseUrlError::Invalid(format!("duplicate {key}")));
        }
        *slot = Some(percent_decode(value)?);
    }
    let stripped = if kept.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{}", kept.join("&"))
    };
    Ok((stripped, parameters))
}

fn percent_decode(value: &str) -> Result<String, DatabaseUrlError> {
    let invalid = || DatabaseUrlError::Invalid("invalid percent-encoding".into());
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = value.get(index + 1..index + 3).ok_or_else(invalid)?;
            decoded.push(u8::from_str_radix(hex, 16).map_err(|_| invalid())?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| invalid())
}

/// rustls connector for `postgres`: WebPKI chain validation against the
/// configured roots plus host name verification (libpq `verify-full`).
#[derive(Clone)]
pub struct RustlsConnect {
    config: Arc<rustls::ClientConfig>,
}

impl RustlsConnect {
    fn from_root_file(path: &str) -> Result<Self, DatabaseUrlError> {
        let error = |reason: String| DatabaseUrlError::RootCertificate(format!("{path}: {reason}"));
        let metadata = std::fs::metadata(path).map_err(|e| error(e.to_string()))?;
        if !metadata.is_file() || metadata.len() > MAX_ROOT_CERT_BYTES {
            return Err(error("must be a file of at most 1 MiB".into()));
        }
        let pem = std::fs::read(path).map_err(|e| error(e.to_string()))?;
        Self::from_root_pem(&pem).map_err(error)
    }

    pub fn from_root_pem(pem: &[u8]) -> Result<Self, String> {
        let certificates = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        if certificates.is_empty() {
            return Err("no certificates found".into());
        }
        let mut roots = rustls::RootCertStore::empty();
        for certificate in certificates {
            roots.add(certificate).map_err(|e| e.to_string())?;
        }
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            config: Arc::new(config),
        })
    }
}

impl MakeTlsConnect<Socket> for RustlsConnect {
    type Stream = RustlsStream;
    type TlsConnect = RustlsConnector;
    type Error = io::Error;

    fn make_tls_connect(&mut self, domain: &str) -> Result<RustlsConnector, io::Error> {
        let domain = domain.trim_start_matches('[').trim_end_matches(']');
        let server_name = ServerName::try_from(domain.to_owned())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;
        Ok(RustlsConnector {
            connector: tokio_rustls::TlsConnector::from(self.config.clone()),
            server_name,
        })
    }
}

pub struct RustlsConnector {
    connector: tokio_rustls::TlsConnector,
    server_name: ServerName<'static>,
}

type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<RustlsStream>> + Send>>;

impl TlsConnect<Socket> for RustlsConnector {
    type Stream = RustlsStream;
    type Error = io::Error;
    type Future = ConnectFuture;

    fn connect(self, stream: Socket) -> ConnectFuture {
        Box::pin(async move {
            self.connector
                .connect(self.server_name, stream)
                .await
                .map(|stream| RustlsStream(Box::new(stream)))
        })
    }
}

pub struct RustlsStream(Box<tokio_rustls::client::TlsStream<Socket>>);

impl AsyncRead for RustlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for RustlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

impl TlsStream for RustlsStream {
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}

/// Why the runtime connection is not allowed to serve requests.
#[derive(Debug)]
pub enum RuntimeRoleError {
    Database(postgres::Error),
    /// The role is, or can become, a superuser, BYPASSRLS or CREATEROLE role
    /// (CREATEROLE can grant itself membership in the owner role on older
    /// PostgreSQL versions).
    PrivilegedRole(String),
    /// The role owns (or can act as the owner of) the `praetore` schema or
    /// objects in it, so it could disable RLS or the append-only triggers.
    OwnsSchemaObjects(String),
    /// The role may create objects in the `praetore` schema.
    CanCreateInSchema(String),
    /// The role holds a table privilege the runtime never needs (DELETE,
    /// TRUNCATE, table-wide UPDATE, TRIGGER or REFERENCES) on a `praetore`
    /// table, e.g. a leftover `GRANT ALL` or membership in `pg_write_all_data`.
    ExcessTablePrivilege(String),
    /// The session does not fire triggers or enforce foreign keys:
    /// `session_replication_role` (here the value) is not `origin`.
    TriggersDisabled(String),
    /// A setting or parameter grant that could disable triggers or row-level
    /// security, or a search_path that puts a schema before `pg_catalog`.
    UnsafeSetting(String),
    /// An object in `praetore` (policy, constraint, default, trigger,
    /// function, view or rule) depends on a function, operator, type or
    /// collation outside `pg_catalog` and `praetore`, so its behaviour is
    /// defined by whoever owns that schema.
    ForeignDependency(String),
    /// The role may execute a SECURITY DEFINER function that runs with the
    /// rights of the `praetore` schema owner.
    OwnerFunctionExecutable(String),
    /// A privilege on the `praetore` schema or an object in it that neither
    /// the owner nor the migrations grant (see `unexpected_grants`).
    UnexpectedGrant(String),
    /// An object in `praetore` is not owned by the schema owner.
    MixedOwnership(String),
    /// A role other than the explicitly allowed ones can act as the
    /// praetore owner, read or write all data, or use praetore_runtime.
    UnexpectedMember(String),
    /// An object outside `praetore` depends on a praetore relation,
    /// function or type (a view, rule, trigger, constraint or function).
    ExternalDependent(String),
    /// A runtime option could not be applied.
    InvalidConfiguration(String),
    /// `PRAETORE_SCHEMA_OWNER` names a role, and the `praetore` schema is
    /// owned by another one (or does not exist).
    UnexpectedSchemaOwner {
        expected: String,
        actual: Option<String>,
    },
    /// An extension is installed in `praetore`, or an object in `praetore`
    /// belongs to an extension (`pg_depend` deptype `e`) or depends on one
    /// (`DEPENDS ON EXTENSION`, deptype `x`). Since PostgreSQL
    /// 13, a role with CREATE on the database can install a trusted
    /// extension into any schema; its objects are owned by the bootstrap
    /// superuser.
    ExtensionObjects(String),
}

impl fmt::Display for RuntimeRoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "runtime role check failed: {error}"),
            Self::PrivilegedRole(role) => write!(
                f,
                "runtime database role {role} is (or is a member of) a SUPERUSER, BYPASSRLS or CREATEROLE role; \
                 tenant isolation would not apply"
            ),
            Self::OwnsSchemaObjects(role) => write!(
                f,
                "runtime database role {role} owns the praetore schema or its objects; \
                 run migrations with a separate owner role (PRAETORE_GATEWAY_MIGRATION_DATABASE_URL)"
            ),
            Self::CanCreateInSchema(role) => {
                write!(
                    f,
                    "runtime database role {role} has CREATE on schema praetore"
                )
            }
            Self::TriggersDisabled(value) => write!(
                f,
                "runtime session has session_replication_role = {value}; the append-only \
                 triggers and foreign keys would not fire (it must be origin)"
            ),
            Self::ForeignDependency(dependencies) => write!(
                f,
                "praetore objects depend on objects outside pg_catalog and praetore: {dependencies}"
            ),
            Self::UnsafeSetting(setting) => write!(
                f,
                "runtime database session is exposed to {setting}; the append-only triggers, \
                 row-level security or name resolution could be changed"
            ),
            Self::MixedOwnership(objects) => write!(
                f,
                "praetore objects are not all owned by the schema owner: {objects}"
            ),
            Self::UnexpectedMember(members) => write!(f, "unexpected role membership: {members}"),
            Self::ExternalDependent(objects) => write!(
                f,
                "objects outside praetore depend on praetore objects: {objects}"
            ),
            Self::InvalidConfiguration(reason) => {
                write!(f, "invalid runtime role configuration: {reason}")
            }
            Self::UnexpectedSchemaOwner { expected, actual } => match actual {
                Some(actual) => write!(
                    f,
                    "schema praetore is owned by {actual}, but {} is {expected}",
                    RuntimeRoleOptions::SCHEMA_OWNER_ENV
                ),
                None => write!(
                    f,
                    "schema praetore does not exist ({} is {expected})",
                    RuntimeRoleOptions::SCHEMA_OWNER_ENV
                ),
            },
            Self::ExtensionObjects(objects) => write!(
                f,
                "extension objects are in schema praetore (members of an extension, or marked \
                 DEPENDS ON EXTENSION), which only its migrations may populate: {objects}"
            ),
            Self::UnexpectedGrant(grants) => write!(
                f,
                "praetore objects carry grants the migrations do not make: {grants}"
            ),
            Self::OwnerFunctionExecutable(function) => write!(
                f,
                "runtime database role may execute SECURITY DEFINER function(s) {function} \
                 that run with the rights of the praetore schema owner"
            ),
            Self::ExcessTablePrivilege(role) => write!(
                f,
                "runtime database role {role} holds DELETE, TRUNCATE, table-wide UPDATE, TRIGGER or \
                 REFERENCES on a praetore table; grant it only membership in praetore_runtime"
            ),
        }
    }
}

impl std::error::Error for RuntimeRoleError {}

impl From<postgres::Error> for RuntimeRoleError {
    fn from(error: postgres::Error) -> Self {
        Self::Database(error)
    }
}

/// Refuses a runtime connection whose session or current role could bypass
/// row-level security or the append-only triggers: superuser or BYPASSRLS
/// (directly or through membership), owner of the `praetore` schema, of any
/// relation or function in it (directly or through membership), holder of
/// CREATE on the schema, CREATEROLE, or holder of a table privilege beyond
/// `praetore_runtime`'s grants (DELETE, TRUNCATE, table-wide UPDATE, TRIGGER,
/// REFERENCES) on any `praetore` table. Also refuses a session in which
/// triggers do not fire or row-level security could be switched off
/// (`session_replication_role`, `row_security`: the current value, a
/// per-database or per-role setting, a non-default session-start value such
/// as one from `ALTER SYSTEM`, or a parameter grant), a per-database or
/// per-role `search_path` setting, and a session search_path that puts
/// another schema before `pg_catalog`. The `search_path` refusals can be
/// relaxed only explicitly, with `RuntimeRoleOptions`.
///
/// The checks run in a read-only transaction under `RUNTIME_SEARCH_PATH`, so
/// they cannot be shadowed themselves. They run once, when the caller starts
/// (the gateway and the CLI do this at startup); reconnections of a
/// connection factory are not checked again. Every runtime transaction pins
/// its search_path (`set_tenant_context`) regardless.
pub fn verify_runtime_role(client: &mut Client) -> Result<(), RuntimeRoleError> {
    verify_runtime_role_with(client, &RuntimeRoleOptions::default())
}

/// Refusals of `verify_runtime_role` that an operator may relax explicitly.
/// Everything is refused by default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeRoleOptions {
    allow_search_path: bool,
    trusted_security_definer: Vec<String>,
    runtime_logins: Vec<String>,
    schema_owner_members: Vec<String>,
    schema_owner: Option<String>,
}

impl RuntimeRoleOptions {
    /// Environment variable the gateway and praetore-observe read (exact
    /// names, comma-separated).
    pub const ALLOW_SETTINGS_ENV: &'static str = "PRAETORE_RUNTIME_ALLOW_SETTINGS";

    /// Parses the value of `PRAETORE_RUNTIME_ALLOW_SETTINGS`: exact,
    /// comma-separated names. The only relaxable setting is `search_path`
    /// (a per-database or per-role `search_path`, or a session search_path
    /// that puts another schema before `pg_catalog`). Any other name, for
    /// example `row_security` or `session_replication_role`, is an error.
    pub fn from_allow_settings(value: &str) -> Result<Self, String> {
        let mut options = Self::default();
        for name in value
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            match name {
                "search_path" => options.allow_search_path = true,
                other => {
                    return Err(format!(
                        "{}: unknown or non-relaxable setting {other:?} (allowed: search_path)",
                        Self::ALLOW_SETTINGS_ENV
                    ));
                }
            }
        }
        Ok(options)
    }

    /// Environment variable the gateway and praetore-observe read for
    /// trusted SECURITY DEFINER functions (semicolon-separated
    /// `regprocedure` names, for example `public.helper(integer)`).
    pub const TRUSTED_SECURITY_DEFINER_ENV: &'static str =
        "PRAETORE_TRUSTED_SECURITY_DEFINER_FUNCTIONS";

    /// Trusts the SECURITY DEFINER functions named in `value`
    /// (semicolon-separated `regprocedure` names): they are not reported by
    /// the owner-rights check. Nothing is trusted by default.
    pub fn with_trusted_security_definer(mut self, value: &str) -> Self {
        self.trusted_security_definer = split_names(value, ';');
        self
    }

    /// Environment variable for `with_runtime_logins` (comma-separated
    /// exact role names).
    pub const RUNTIME_LOGINS_ENV: &'static str = "PRAETORE_RUNTIME_LOGINS";
    /// Environment variable for `with_schema_owner_members` (comma-separated
    /// exact role names).
    pub const SCHEMA_OWNER_MEMBERS_ENV: &'static str = "PRAETORE_SCHEMA_OWNER_MEMBERS";

    /// The login roles allowed to be members of `praetore_runtime`. When
    /// set, any other login member is refused; when empty, other login
    /// members are only reported (`runtime_role_members`), because
    /// `praetore_runtime` is a cluster-wide role shared by every instance
    /// and database.
    pub fn with_runtime_logins(mut self, value: &str) -> Self {
        self.runtime_logins = split_names(value, ',');
        self
    }

    /// Roles allowed to be members of the praetore schema owner (for
    /// example the migrating role of a NOLOGIN owner group). Any other
    /// member is refused; none is allowed by default.
    pub fn with_schema_owner_members(mut self, value: &str) -> Self {
        self.schema_owner_members = split_names(value, ',');
        self
    }

    /// Environment variable for `with_schema_owner` (one exact role name).
    pub const SCHEMA_OWNER_ENV: &'static str = "PRAETORE_SCHEMA_OWNER";

    /// The role that must own the `praetore` schema (exact name, trimmed;
    /// empty means unset). When set, a schema owned by any other role, or
    /// no schema, is refused. Without it the runtime trusts whichever role
    /// owns `praetore`: the structure is compared with the migrations only
    /// when migrating.
    pub fn with_schema_owner(mut self, value: &str) -> Self {
        let value = value.trim();
        self.schema_owner = (!value.is_empty()).then(|| value.to_owned());
        self
    }

    /// The configured schema owner, for the startup log.
    pub fn schema_owner(&self) -> Option<&str> {
        self.schema_owner.as_deref()
    }

    /// The trusted SECURITY DEFINER functions, for the startup log.
    pub fn trusted_security_definer(&self) -> &[String] {
        &self.trusted_security_definer
    }

    /// All runtime-role options from configuration values (the binaries
    /// pass their environment): `PRAETORE_RUNTIME_ALLOW_SETTINGS`,
    /// `PRAETORE_TRUSTED_SECURITY_DEFINER_FUNCTIONS`,
    /// `PRAETORE_RUNTIME_LOGINS`, `PRAETORE_SCHEMA_OWNER_MEMBERS` and
    /// `PRAETORE_SCHEMA_OWNER`. The library itself reads no environment.
    pub fn from_config(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let value = |name: &str| lookup(name).unwrap_or_default();
        Ok(Self::from_allow_settings(&value(Self::ALLOW_SETTINGS_ENV))?
            .with_trusted_security_definer(&value(Self::TRUSTED_SECURITY_DEFINER_ENV))
            .with_runtime_logins(&value(Self::RUNTIME_LOGINS_ENV))
            .with_schema_owner_members(&value(Self::SCHEMA_OWNER_MEMBERS_ENV))
            .with_schema_owner(&value(Self::SCHEMA_OWNER_ENV)))
    }

    /// The relaxed refusals, for the startup log.
    pub fn relaxed(&self) -> Vec<&'static str> {
        let mut relaxed = Vec::new();
        if self.allow_search_path {
            relaxed.push("search_path");
        }
        if !self.trusted_security_definer.is_empty() {
            relaxed.push("trusted SECURITY DEFINER functions");
        }
        if !self.schema_owner_members.is_empty() {
            relaxed.push("schema owner members");
        }
        relaxed
    }
}

fn split_names(value: &str, separator: char) -> Vec<String> {
    value
        .split(separator)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A trusted SECURITY DEFINER function, resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedSecurityDefiner {
    /// The configured entry.
    pub name: String,
    /// The function it resolved to, as `regprocedure` renders it.
    pub resolved: String,
    pub oid: u32,
    pub owner: String,
    pub owner_is_superuser: bool,
}

/// Resolves trusted SECURITY DEFINER entries with `to_regprocedure` under
/// `pg_catalog, pg_temp`, so aliases (`int4` and `integer`) resolve alike.
/// Every entry must be schema-qualified with a full signature
/// (`schema.name(argtypes)`) and must resolve; otherwise it is a
/// configuration error.
pub(crate) fn resolve_trusted_security_definer(
    transaction: &mut impl postgres::GenericClient,
    names: &[String],
) -> Result<Vec<TrustedSecurityDefiner>, String> {
    let mut resolved = Vec::new();
    for name in names {
        let qualified = name
            .split_once('(')
            .is_some_and(|(function, _)| function.contains('.'))
            && name.ends_with(')');
        if !qualified {
            return Err(format!(
                "trusted SECURITY DEFINER function {name:?} must be schema-qualified with its \
                 full signature, e.g. public.helper(integer)"
            ));
        }
        let row = transaction
            .query_one(
                "SELECT f.oid::pg_catalog.regprocedure::pg_catalog.text, f.oid, \
                        pg_catalog.pg_get_userbyid(p.proowner)::pg_catalog.text, r.rolsuper \
                 FROM (SELECT pg_catalog.to_regprocedure($1)::pg_catalog.oid AS oid) f \
                 LEFT JOIN pg_catalog.pg_proc p ON p.oid OPERATOR(pg_catalog.=) f.oid \
                 LEFT JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) p.proowner",
                &[name],
            )
            .map_err(|error| format!("cannot resolve {name:?}: {error}"))?;
        let Some(text) = row.get::<_, Option<String>>(0) else {
            return Err(format!(
                "trusted SECURITY DEFINER function {name:?} does not exist"
            ));
        };
        resolved.push(TrustedSecurityDefiner {
            name: name.clone(),
            resolved: text,
            oid: row.get(1),
            owner: row.get(2),
            owner_is_superuser: row.get(3),
        });
    }
    Ok(resolved)
}

/// Resolves the trusted SECURITY DEFINER functions of `options` for the
/// startup log (the binaries warn about those owned by a superuser).
pub fn describe_trusted_security_definer(
    client: &mut Client,
    options: &RuntimeRoleOptions,
) -> Result<Vec<TrustedSecurityDefiner>, RuntimeRoleError> {
    let mut transaction = client.build_transaction().read_only(true).start()?;
    transaction.batch_execute(&format!(
        "SET LOCAL search_path = {}",
        crate::RUNTIME_SEARCH_PATH
    ))?;
    let resolved =
        resolve_trusted_security_definer(&mut transaction, &options.trusted_security_definer)
            .map_err(RuntimeRoleError::InvalidConfiguration);
    transaction.rollback()?;
    resolved
}

/// Login members of `praetore_runtime` other than this session's roles, for
/// the startup log and `praetore doctor`.
pub fn runtime_role_members(client: &mut Client) -> Result<Vec<String>, RuntimeRoleError> {
    let mut transaction = client.build_transaction().read_only(true).start()?;
    transaction.batch_execute(&format!(
        "SET LOCAL search_path = {}",
        crate::RUNTIME_SEARCH_PATH
    ))?;
    let members = other_runtime_logins(&mut transaction)?;
    transaction.rollback()?;
    Ok(members)
}

fn other_runtime_logins(
    transaction: &mut postgres::Transaction<'_>,
) -> Result<Vec<String>, RuntimeRoleError> {
    Ok(transaction
        .query(
            "WITH RECURSIVE members(role) AS ( \
                 SELECT m.member FROM pg_catalog.pg_auth_members m \
                 JOIN pg_catalog.pg_roles g ON g.oid OPERATOR(pg_catalog.=) m.roleid \
                 WHERE g.rolname OPERATOR(pg_catalog.=) 'praetore_runtime' \
                 UNION \
                 SELECT m.member FROM pg_catalog.pg_auth_members m \
                 JOIN members ON m.roleid OPERATOR(pg_catalog.=) members.role) \
             SELECT r.rolname::pg_catalog.text FROM members \
             JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) members.role \
             WHERE r.rolcanlogin \
               AND r.rolname OPERATOR(pg_catalog.<>) SESSION_USER \
               AND r.rolname OPERATOR(pg_catalog.<>) CURRENT_USER \
             ORDER BY 1",
            &[],
        )?
        .iter()
        .map(|row| row.get(0))
        .collect())
}

/// `verify_runtime_role` with explicitly relaxed refusals.
pub fn verify_runtime_role_with(
    client: &mut Client,
    options: &RuntimeRoleOptions,
) -> Result<(), RuntimeRoleError> {
    let mut transaction = client.build_transaction().read_only(true).start()?;
    // The session's own search_path, before it is pinned below.
    let schemas: Vec<String> = transaction
        .query_one(
            "SELECT pg_catalog.current_schemas(true)::pg_catalog.text[]",
            &[],
        )?
        .get(0);
    if !options.allow_search_path
        && let Some(first) = schemas.iter().find(|schema| !schema.starts_with("pg_temp"))
        && first != "pg_catalog"
    {
        return Err(RuntimeRoleError::UnsafeSetting(format!(
            "search_path that puts {first} before pg_catalog ({})",
            schemas.join(", ")
        )));
    }
    transaction.batch_execute(&format!(
        "SET LOCAL search_path = {}",
        crate::RUNTIME_SEARCH_PATH
    ))?;
    let result = verify_runtime_role_in(&mut transaction, options);
    transaction.rollback()?;
    result
}

fn verify_runtime_role_in(
    transaction: &mut postgres::Transaction<'_>,
    options: &RuntimeRoleOptions,
) -> Result<(), RuntimeRoleError> {
    let replication_role: String = transaction
        .query_one(
            "SELECT pg_catalog.current_setting('session_replication_role')",
            &[],
        )?
        .get(0);
    if replication_role != "origin" {
        return Err(RuntimeRoleError::TriggersDisabled(replication_role));
    }
    if let Some(expected) = &options.schema_owner {
        if expected.starts_with("pg_") {
            return Err(RuntimeRoleError::InvalidConfiguration(format!(
                "{} names {expected}, a predefined role, which cannot own the praetore schema",
                RuntimeRoleOptions::SCHEMA_OWNER_ENV
            )));
        }
        let actual = praetore_schema_owner(transaction)?;
        if actual.as_deref() != Some(expected.as_str()) {
            return Err(RuntimeRoleError::UnexpectedSchemaOwner {
                expected: expected.clone(),
                actual,
            });
        }
    }
    if let Some(setting) = unsafe_runtime_setting(transaction, options)? {
        return Err(RuntimeRoleError::UnsafeSetting(setting));
    }
    if let Some(dependencies) = foreign_dependencies(transaction)? {
        return Err(RuntimeRoleError::ForeignDependency(dependencies));
    }
    let row = transaction.query_one(
        "SELECT session_user::pg_catalog.text, current_user::pg_catalog.text",
        &[],
    )?;
    let mut roles: Vec<String> = vec![row.get(0), row.get(1)];
    roles.dedup();
    for role in roles {
        let row = transaction.query_one(
            "SELECT \
                 EXISTS (SELECT 1 FROM pg_catalog.pg_roles privileged \
                         WHERE (privileged.rolsuper OR privileged.rolbypassrls \
                                OR privileged.rolcreaterole) \
                           AND pg_catalog.pg_has_role($1, privileged.oid, 'MEMBER')), \
                 EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n \
                         WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore' \
                           AND pg_catalog.pg_has_role($1, n.nspowner, 'MEMBER')) \
                 OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c \
                         JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
                         WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore' \
                           AND pg_catalog.pg_has_role($1, c.relowner, 'MEMBER')) \
                 OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p \
                         JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) p.pronamespace \
                         WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore' \
                           AND pg_catalog.pg_has_role($1, p.proowner, 'MEMBER')), \
                 COALESCE((SELECT pg_catalog.has_schema_privilege($1, n.oid, 'CREATE') \
                           FROM pg_catalog.pg_namespace n WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore'), false), \
                 EXISTS (SELECT 1 FROM pg_catalog.pg_class c \
                         JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
                         WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore' \
                           AND (c.relkind OPERATOR(pg_catalog.=) 'r' OR c.relkind OPERATOR(pg_catalog.=) 'p') \
                           AND pg_catalog.has_table_privilege($1, c.oid, \
                               'DELETE, TRUNCATE, UPDATE, TRIGGER, REFERENCES'))",
            &[&role],
        )?;
        if row.get::<_, bool>(0) {
            return Err(RuntimeRoleError::PrivilegedRole(role));
        }
        if row.get::<_, bool>(1) {
            return Err(RuntimeRoleError::OwnsSchemaObjects(role));
        }
        if row.get::<_, bool>(2) {
            return Err(RuntimeRoleError::CanCreateInSchema(role));
        }
        if row.get::<_, bool>(3) {
            return Err(RuntimeRoleError::ExcessTablePrivilege(role));
        }
    }
    if let Some(function) = owner_function_executable(transaction, options)? {
        return Err(RuntimeRoleError::OwnerFunctionExecutable(function));
    }
    if let Some(grants) = unexpected_grants(transaction)? {
        return Err(RuntimeRoleError::UnexpectedGrant(grants));
    }
    if let Some(objects) = extension_objects(transaction)? {
        return Err(RuntimeRoleError::ExtensionObjects(objects));
    }
    if let Some(objects) = mixed_ownership(transaction)? {
        return Err(RuntimeRoleError::MixedOwnership(objects));
    }
    if let Some(members) = unexpected_members(transaction, options)? {
        return Err(RuntimeRoleError::UnexpectedMember(members));
    }
    if let Some(objects) = external_dependents(transaction)? {
        return Err(RuntimeRoleError::ExternalDependent(objects));
    }
    Ok(())
}

/// Objects in `praetore` that depend (`pg_depend`) on a function, operator,
/// type or collation in a schema other than `pg_catalog` and `praetore`.
/// Expressions in policies, constraints, defaults and trigger conditions
/// bind such objects when they are created, so a later search_path change
/// does not undo it. Up to ten entries.
fn foreign_dependencies(
    transaction: &mut postgres::Transaction<'_>,
) -> Result<Option<String>, RuntimeRoleError> {
    let row = transaction.query_one(
        "WITH ns AS (SELECT n.oid FROM pg_catalog.pg_namespace n \
                     WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore'), \
         dependent AS ( \
             SELECT d.classid, d.objid, d.objsubid, d.refclassid, d.refobjid, d.refobjsubid, \
                    CASE \
                        WHEN d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass \
                            THEN (SELECT c.relnamespace FROM pg_catalog.pg_class c \
                                  WHERE c.oid OPERATOR(pg_catalog.=) d.objid) \
                        WHEN d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass \
                            THEN (SELECT p.pronamespace FROM pg_catalog.pg_proc p \
                                  WHERE p.oid OPERATOR(pg_catalog.=) d.objid) \
                        WHEN d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_type'::pg_catalog.regclass \
                            THEN (SELECT t.typnamespace FROM pg_catalog.pg_type t \
                                  WHERE t.oid OPERATOR(pg_catalog.=) d.objid) \
                        WHEN d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_constraint'::pg_catalog.regclass \
                            THEN (SELECT con.connamespace FROM pg_catalog.pg_constraint con \
                                  WHERE con.oid OPERATOR(pg_catalog.=) d.objid) \
                        WHEN d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_policy'::pg_catalog.regclass \
                            THEN (SELECT c.relnamespace FROM pg_catalog.pg_policy pol \
                                  JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) pol.polrelid \
                                  WHERE pol.oid OPERATOR(pg_catalog.=) d.objid) \
                        WHEN d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_trigger'::pg_catalog.regclass \
                            THEN (SELECT c.relnamespace FROM pg_catalog.pg_trigger g \
                                  JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) g.tgrelid \
                                  WHERE g.oid OPERATOR(pg_catalog.=) d.objid) \
                        WHEN d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_attrdef'::pg_catalog.regclass \
                            THEN (SELECT c.relnamespace FROM pg_catalog.pg_attrdef ad \
                                  JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) ad.adrelid \
                                  WHERE ad.oid OPERATOR(pg_catalog.=) d.objid) \
                        WHEN d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_rewrite'::pg_catalog.regclass \
                            THEN (SELECT c.relnamespace FROM pg_catalog.pg_rewrite rw \
                                  JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) rw.ev_class \
                                  WHERE rw.oid OPERATOR(pg_catalog.=) d.objid) \
                    END AS dependent_namespace, \
                    CASE \
                        WHEN d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass \
                            THEN (SELECT p.pronamespace FROM pg_catalog.pg_proc p \
                                  WHERE p.oid OPERATOR(pg_catalog.=) d.refobjid) \
                        WHEN d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_operator'::pg_catalog.regclass \
                            THEN (SELECT o.oprnamespace FROM pg_catalog.pg_operator o \
                                  WHERE o.oid OPERATOR(pg_catalog.=) d.refobjid) \
                        WHEN d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_type'::pg_catalog.regclass \
                            THEN (SELECT t.typnamespace FROM pg_catalog.pg_type t \
                                  WHERE t.oid OPERATOR(pg_catalog.=) d.refobjid) \
                        WHEN d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_collation'::pg_catalog.regclass \
                            THEN (SELECT co.collnamespace FROM pg_catalog.pg_collation co \
                                  WHERE co.oid OPERATOR(pg_catalog.=) d.refobjid) \
                    END AS referenced_namespace \
             FROM pg_catalog.pg_depend d \
             WHERE d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass \
                OR d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_operator'::pg_catalog.regclass \
                OR d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_type'::pg_catalog.regclass \
                OR d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_collation'::pg_catalog.regclass), \
         foreign_refs AS ( \
             SELECT pg_catalog.concat(o.type, ' ', o.identity, ' -> ', r.type, ' ', r.identity) \
                        AS entry \
             FROM dependent dep CROSS JOIN ns \
             CROSS JOIN LATERAL pg_catalog.pg_identify_object(dep.classid, dep.objid, dep.objsubid) o \
             CROSS JOIN LATERAL \
                 pg_catalog.pg_identify_object(dep.refclassid, dep.refobjid, dep.refobjsubid) r \
             WHERE dep.dependent_namespace OPERATOR(pg_catalog.=) ns.oid \
               AND dep.referenced_namespace IS NOT NULL \
               AND dep.referenced_namespace OPERATOR(pg_catalog.<>) ns.oid \
               AND dep.referenced_namespace OPERATOR(pg_catalog.<>) \
                   'pg_catalog'::pg_catalog.regnamespace::pg_catalog.oid) \
         SELECT pg_catalog.string_agg(entry, ', ' ORDER BY entry) \
         FROM (SELECT DISTINCT entry FROM foreign_refs ORDER BY entry LIMIT 10) first_entries",
        &[],
    )?;
    Ok(row.get(0))
}

/// Settings that would disable the append-only triggers or row-level
/// security, or change name resolution, for this session: a `search_path`
/// (unless explicitly allowed), `row_security` or `session_replication_role`
/// set for this database or all databases and for this login role or all
/// roles (`pg_db_role_setting`); a session-start value of `row_security` or
/// `session_replication_role` that is not the built-in default (for example
/// from `ALTER SYSTEM`); and a `GRANT SET` or `GRANT ALTER SYSTEM` on one of
/// those parameters to PUBLIC or to a role the session or current role
/// belongs to (`pg_parameter_acl`, PostgreSQL 15 and later).
fn unsafe_runtime_setting(
    transaction: &mut postgres::Transaction<'_>,
    options: &RuntimeRoleOptions,
) -> Result<Option<String>, RuntimeRoleError> {
    let row = transaction.query_one(
        "SELECT ( \
             SELECT pg_catalog.string_agg(s.setting, ', ' ORDER BY s.setting) \
             FROM pg_catalog.pg_db_role_setting rs \
             CROSS JOIN LATERAL pg_catalog.unnest(rs.setconfig) s(setting) \
             WHERE (rs.setdatabase OPERATOR(pg_catalog.=) 0::pg_catalog.oid \
                    OR rs.setdatabase OPERATOR(pg_catalog.=) \
                       (SELECT d.oid FROM pg_catalog.pg_database d \
                        WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database())) \
               AND (rs.setrole OPERATOR(pg_catalog.=) 0::pg_catalog.oid \
                    OR rs.setrole OPERATOR(pg_catalog.=) \
                       (SELECT r.oid FROM pg_catalog.pg_roles r \
                        WHERE r.rolname OPERATOR(pg_catalog.=) SESSION_USER) \
                    OR rs.setrole OPERATOR(pg_catalog.=) \
                       (SELECT r.oid FROM pg_catalog.pg_roles r \
                        WHERE r.rolname OPERATOR(pg_catalog.=) CURRENT_USER)) \
               AND (pg_catalog.starts_with(s.setting, 'row_security=') \
                    OR pg_catalog.starts_with(s.setting, 'session_replication_role=') \
                    OR (NOT $1 AND pg_catalog.starts_with(s.setting, 'search_path=')))), \
             ( \
             SELECT pg_catalog.string_agg( \
                        pg_catalog.concat(p.name, '=', p.reset_val, ' (', p.source, ')'), ', ' \
                        ORDER BY p.name) \
             FROM pg_catalog.pg_settings p \
             WHERE (p.name OPERATOR(pg_catalog.=) 'row_security' \
                    OR p.name OPERATOR(pg_catalog.=) 'session_replication_role') \
               AND p.reset_val OPERATOR(pg_catalog.<>) p.boot_val), \
             pg_catalog.to_regclass('pg_catalog.pg_parameter_acl') IS NOT NULL",
        &[&options.allow_search_path],
    )?;
    if let Some(settings) = row.get::<_, Option<String>>(0) {
        return Ok(Some(format!("{settings} (ALTER DATABASE/ROLE ... SET)")));
    }
    if let Some(settings) = row.get::<_, Option<String>>(1) {
        return Ok(Some(settings));
    }
    if row.get::<_, bool>(2) {
        let granted: Option<String> = transaction
            .query_one(
                "SELECT pg_catalog.string_agg(DISTINCT pg_catalog.concat( \
                     'GRANT ', a.privilege_type, ' ON PARAMETER ', pa.parname, ' TO ', \
                     CASE WHEN a.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid THEN 'PUBLIC' \
                          ELSE pg_catalog.pg_get_userbyid(a.grantee)::pg_catalog.text END), ', ') \
                 FROM pg_catalog.pg_parameter_acl pa \
                 CROSS JOIN LATERAL pg_catalog.aclexplode(pa.paracl) a \
                 WHERE (pa.parname OPERATOR(pg_catalog.=) 'row_security' \
                        OR pa.parname OPERATOR(pg_catalog.=) 'session_replication_role') \
                   AND (a.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid \
                        OR pg_catalog.pg_has_role(SESSION_USER, a.grantee, 'MEMBER') \
                        OR pg_catalog.pg_has_role(CURRENT_USER, a.grantee, 'MEMBER'))",
                &[],
            )?
            .get(0);
        if let Some(granted) = granted {
            return Ok(Some(granted));
        }
    }
    Ok(None)
}

/// Every privilege on the `praetore` schema, its relations (sequences and
/// views included), their columns and its functions, against what the
/// migrations intend: the object owner's own; `praetore_runtime`'s grants
/// from 0011 (schema USAGE; SELECT on `schema_migrations` and
/// `execution_journal_events`; SELECT and INSERT on `replay_claims`,
/// `execution_journal`, `execution_attestations`, `human_approvals` and
/// `human_approval_expirations`; SELECT on `storage_records` (0015);
/// UPDATE of `execution_status`,
/// `output_json`, `not_dispatched_reason` and `updated_at`); the
/// documented `praetore_observe` shape exactly (schema USAGE; column SELECT
/// on the ten `execution_journal` and seven `execution_journal_events`
/// columns of docs/observability-mvp.md); and PUBLIC EXECUTE on functions
/// that are not SECURITY DEFINER. No grant other than the owner's may carry
/// WITH GRANT OPTION. Anything
/// else, for example a grant made through `ALTER DEFAULT PRIVILEGES` before
/// the first migration, is reported (up to ten entries).
fn unexpected_grants(
    transaction: &mut postgres::Transaction<'_>,
) -> Result<Option<String>, RuntimeRoleError> {
    let row = transaction.query_one(
        "WITH ns AS (SELECT n.oid, n.nspowner, n.nspacl FROM pg_catalog.pg_namespace n \
                     WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore'), \
         entries(object, kind, rel, col, owner, grantee, privilege, secdef, grantable) AS ( \
             SELECT 'schema praetore', 'n', ''::pg_catalog.text, ''::pg_catalog.text, \
                    ns.nspowner, a.grantee, a.privilege_type, false, a.is_grantable \
             FROM ns CROSS JOIN LATERAL pg_catalog.aclexplode( \
                 COALESCE(ns.nspacl, pg_catalog.acldefault('n', ns.nspowner))) a \
             UNION ALL \
             SELECT pg_catalog.concat('relation praetore.', c.relname), 'r', \
                    c.relname::pg_catalog.text, ''::pg_catalog.text, \
                    c.relowner, a.grantee, a.privilege_type, false, a.is_grantable \
             FROM ns JOIN pg_catalog.pg_class c ON c.relnamespace OPERATOR(pg_catalog.=) ns.oid \
             CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl, pg_catalog.acldefault( \
                 CASE WHEN c.relkind OPERATOR(pg_catalog.=) 'S' THEN 's' ELSE 'r' END::pg_catalog.\"char\", \
                 c.relowner))) a \
             WHERE NOT (c.relkind OPERATOR(pg_catalog.=) 'i' OR c.relkind OPERATOR(pg_catalog.=) 'I' \
                        OR c.relkind OPERATOR(pg_catalog.=) 'c' OR c.relkind OPERATOR(pg_catalog.=) 't') \
             UNION ALL \
             SELECT pg_catalog.concat('column praetore.', c.relname, '.', att.attname), 'c', \
                    c.relname::pg_catalog.text, att.attname::pg_catalog.text, \
                    c.relowner, a.grantee, a.privilege_type, false, a.is_grantable \
             FROM ns JOIN pg_catalog.pg_class c ON c.relnamespace OPERATOR(pg_catalog.=) ns.oid \
             JOIN pg_catalog.pg_attribute att ON att.attrelid OPERATOR(pg_catalog.=) c.oid \
             CROSS JOIN LATERAL pg_catalog.aclexplode(att.attacl) a \
             WHERE att.attacl IS NOT NULL \
             UNION ALL \
             SELECT pg_catalog.concat('function ', p.oid::pg_catalog.regprocedure), 'f', \
                    ''::pg_catalog.text, ''::pg_catalog.text, \
                    p.proowner, a.grantee, a.privilege_type, p.prosecdef, a.is_grantable \
             FROM ns JOIN pg_catalog.pg_proc p ON p.pronamespace OPERATOR(pg_catalog.=) ns.oid \
             CROSS JOIN LATERAL pg_catalog.aclexplode( \
                 COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) a), \
         runtime_allowed(kind, rel, col, privilege) AS (VALUES \
             ('n', '', '', 'USAGE'), \
             ('r', 'schema_migrations', '', 'SELECT'), \
             ('r', 'storage_records', '', 'SELECT'), \
             ('r', 'replay_claims', '', 'SELECT'), ('r', 'replay_claims', '', 'INSERT'), \
             ('r', 'execution_journal', '', 'SELECT'), ('r', 'execution_journal', '', 'INSERT'), \
             ('r', 'execution_journal_events', '', 'SELECT'), \
             ('r', 'execution_attestations', '', 'SELECT'), \
             ('r', 'execution_attestations', '', 'INSERT'), \
             ('r', 'human_approvals', '', 'SELECT'), ('r', 'human_approvals', '', 'INSERT'), \
             ('r', 'human_approval_expirations', '', 'SELECT'), \
             ('r', 'human_approval_expirations', '', 'INSERT'), \
             ('c', 'execution_journal', 'execution_status', 'UPDATE'), \
             ('c', 'execution_journal', 'output_json', 'UPDATE'), \
             ('c', 'execution_journal', 'not_dispatched_reason', 'UPDATE'), \
             ('c', 'execution_journal', 'updated_at', 'UPDATE')), \
         observe_allowed(rel, col) AS (VALUES \
             ('execution_journal', 'tenant_id'), ('execution_journal', 'agent_id'), \
             ('execution_journal', 'request_id'), ('execution_journal', 'request_digest'), \
             ('execution_journal', 'action_digest'), \
             ('execution_journal', 'authorization_status'), \
             ('execution_journal', 'execution_status'), ('execution_journal', 'evidence_json'), \
             ('execution_journal', 'created_at'), ('execution_journal', 'updated_at'), \
             ('execution_journal_events', 'event_id'), ('execution_journal_events', 'tenant_id'), \
             ('execution_journal_events', 'agent_id'), ('execution_journal_events', 'request_id'), \
             ('execution_journal_events', 'from_status'), \
             ('execution_journal_events', 'to_status'), \
             ('execution_journal_events', 'occurred_at')), \
         unexpected AS ( \
             SELECT pg_catalog.concat(e.object, ': ', e.privilege, \
                        CASE WHEN e.grantable THEN ' WITH GRANT OPTION' ELSE '' END, ' to ', \
                        CASE WHEN e.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid THEN 'PUBLIC' \
                             ELSE pg_catalog.pg_get_userbyid(e.grantee)::pg_catalog.text END) AS entry \
             FROM entries e \
             LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid OPERATOR(pg_catalog.=) e.grantee \
             WHERE NOT ( \
                 e.grantee OPERATOR(pg_catalog.=) e.owner \
                 OR (e.grantee OPERATOR(pg_catalog.=) 0::pg_catalog.oid \
                     AND e.kind OPERATOR(pg_catalog.=) 'f' \
                     AND e.privilege OPERATOR(pg_catalog.=) 'EXECUTE' AND NOT e.secdef \
                     AND NOT e.grantable) \
                 OR (grantee.rolname OPERATOR(pg_catalog.=) 'praetore_runtime' AND NOT e.grantable \
                     AND EXISTS (SELECT 1 FROM runtime_allowed ra \
                                 WHERE ra.kind OPERATOR(pg_catalog.=) e.kind \
                                   AND ra.rel OPERATOR(pg_catalog.=) e.rel \
                                   AND ra.col OPERATOR(pg_catalog.=) e.col \
                                   AND ra.privilege OPERATOR(pg_catalog.=) e.privilege)) \
                 OR (grantee.rolname OPERATOR(pg_catalog.=) 'praetore_observe' AND NOT e.grantable \
                     AND ((e.kind OPERATOR(pg_catalog.=) 'n' \
                           AND e.privilege OPERATOR(pg_catalog.=) 'USAGE') \
                          OR (e.kind OPERATOR(pg_catalog.=) 'c' \
                              AND e.privilege OPERATOR(pg_catalog.=) 'SELECT' \
                              AND EXISTS (SELECT 1 FROM observe_allowed oa \
                                          WHERE oa.rel OPERATOR(pg_catalog.=) e.rel \
                                            AND oa.col OPERATOR(pg_catalog.=) e.col)))))) \
         SELECT pg_catalog.string_agg(entry, ', ' ORDER BY entry) \
         FROM (SELECT entry FROM unexpected ORDER BY entry LIMIT 10) first_entries",
        &[],
    )?;
    Ok(row.get(0))
}

/// The role that owns the `praetore` schema, if it exists.
pub(crate) fn praetore_schema_owner(
    client: &mut impl postgres::GenericClient,
) -> Result<Option<String>, postgres::Error> {
    Ok(client
        .query_opt(
            "SELECT pg_catalog.pg_get_userbyid(n.nspowner)::pg_catalog.text \
             FROM pg_catalog.pg_namespace n WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore'",
            &[],
        )?
        .map(|row| row.get(0)))
}

/// Extensions installed in `praetore`, objects in `praetore` that belong
/// to an extension (`pg_depend` deptype `e`), and objects in `praetore`
/// marked `DEPENDS ON EXTENSION` (deptype `x`), which `DROP EXTENSION`
/// drops with the extension: whoever owns that extension could drop them.
/// Whatever schema the extension itself is in. The migrations create no
/// such dependency. Up to ten entries.
pub(crate) fn extension_objects(
    client: &mut impl postgres::GenericClient,
) -> Result<Option<String>, postgres::Error> {
    let row = client.query_one(
        "WITH ns AS (SELECT n.oid FROM pg_catalog.pg_namespace n \
                     WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore'), \
         objects(entry) AS ( \
             SELECT pg_catalog.concat('extension ', e.extname, ' (installed in praetore)') \
             FROM ns JOIN pg_catalog.pg_extension e \
                 ON e.extnamespace OPERATOR(pg_catalog.=) ns.oid \
             UNION ALL \
             SELECT pg_catalog.concat(o.type, ' ', o.identity, \
                        CASE WHEN d.deptype OPERATOR(pg_catalog.=) 'e' THEN ' (member of extension ' \
                             ELSE ' (depends on extension ' END, e.extname, ')') \
             FROM pg_catalog.pg_depend d \
             JOIN pg_catalog.pg_extension e ON e.oid OPERATOR(pg_catalog.=) d.refobjid \
             CROSS JOIN LATERAL pg_catalog.pg_identify_object(d.classid, d.objid, d.objsubid) o \
             WHERE (d.deptype OPERATOR(pg_catalog.=) 'e' \
                    OR d.deptype OPERATOR(pg_catalog.=) 'x') \
               AND d.refclassid OPERATOR(pg_catalog.=) \
                   'pg_catalog.pg_extension'::pg_catalog.regclass \
               AND o.schema OPERATOR(pg_catalog.=) 'praetore') \
         SELECT pg_catalog.string_agg(entry, ', ' ORDER BY entry) \
         FROM (SELECT entry FROM objects ORDER BY entry LIMIT 10) first_entries",
        &[],
    )?;
    Ok(row.get(0))
}

/// Objects in `praetore` (relations, functions, types) not owned by the
/// schema owner. Up to ten entries.
fn mixed_ownership(
    transaction: &mut postgres::Transaction<'_>,
) -> Result<Option<String>, RuntimeRoleError> {
    let row = transaction.query_one(
        "WITH ns AS (SELECT n.oid, n.nspowner FROM pg_catalog.pg_namespace n \
                     WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore'), \
         objects(entry) AS ( \
             SELECT pg_catalog.concat('relation praetore.', c.relname, ' (', \
                        pg_catalog.pg_get_userbyid(c.relowner), ')') \
             FROM ns JOIN pg_catalog.pg_class c ON c.relnamespace OPERATOR(pg_catalog.=) ns.oid \
             WHERE c.relowner OPERATOR(pg_catalog.<>) ns.nspowner \
             UNION ALL \
             SELECT pg_catalog.concat('function ', p.oid::pg_catalog.regprocedure, ' (', \
                        pg_catalog.pg_get_userbyid(p.proowner), ')') \
             FROM ns JOIN pg_catalog.pg_proc p ON p.pronamespace OPERATOR(pg_catalog.=) ns.oid \
             WHERE p.proowner OPERATOR(pg_catalog.<>) ns.nspowner \
             UNION ALL \
             SELECT pg_catalog.concat('type praetore.', t.typname, ' (', \
                        pg_catalog.pg_get_userbyid(t.typowner), ')') \
             FROM ns JOIN pg_catalog.pg_type t ON t.typnamespace OPERATOR(pg_catalog.=) ns.oid \
             WHERE t.typowner OPERATOR(pg_catalog.<>) ns.nspowner) \
         SELECT pg_catalog.string_agg(entry, ', ' ORDER BY entry) \
         FROM (SELECT entry FROM objects ORDER BY entry LIMIT 10) first_entries",
        &[],
    )?;
    Ok(row.get(0))
}

/// Memberships that grant another role the owner's rights or blanket data
/// access: any member (direct or not) of the praetore schema owner that is
/// not explicitly allowed (`with_schema_owner_members`); any
/// non-superuser member of `pg_read_all_data` or `pg_write_all_data`; and,
/// when `with_runtime_logins` is set, any other login member of
/// `praetore_runtime`.
fn unexpected_members(
    transaction: &mut postgres::Transaction<'_>,
    options: &RuntimeRoleOptions,
) -> Result<Option<String>, RuntimeRoleError> {
    let mut problems: Vec<String> = transaction
        .query(
            "WITH RECURSIVE owner_members(role) AS ( \
                 SELECT m.member FROM pg_catalog.pg_auth_members m \
                 JOIN pg_catalog.pg_namespace n ON n.nspowner OPERATOR(pg_catalog.=) m.roleid \
                 WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore' \
                 UNION \
                 SELECT m.member FROM pg_catalog.pg_auth_members m \
                 JOIN owner_members o ON m.roleid OPERATOR(pg_catalog.=) o.role), \
             data_members(role, via) AS ( \
                 SELECT m.member, g.rolname FROM pg_catalog.pg_auth_members m \
                 JOIN pg_catalog.pg_roles g ON g.oid OPERATOR(pg_catalog.=) m.roleid \
                 WHERE g.rolname OPERATOR(pg_catalog.=) 'pg_read_all_data' \
                    OR g.rolname OPERATOR(pg_catalog.=) 'pg_write_all_data' \
                 UNION \
                 SELECT m.member, d.via FROM pg_catalog.pg_auth_members m \
                 JOIN data_members d ON m.roleid OPERATOR(pg_catalog.=) d.role) \
             SELECT pg_catalog.concat('role ', r.rolname, ' is a member of the praetore owner') \
             FROM owner_members o JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) o.role \
             WHERE NOT (r.rolname::pg_catalog.text OPERATOR(pg_catalog.=) ANY ($1::pg_catalog.text[])) \
             UNION ALL \
             SELECT pg_catalog.concat('role ', r.rolname, ' is a member of ', d.via) \
             FROM data_members d JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) d.role \
             WHERE NOT r.rolsuper \
             ORDER BY 1",
            &[&options.schema_owner_members],
        )?
        .iter()
        .map(|row| row.get(0))
        .collect();
    if !options.runtime_logins.is_empty() {
        for login in other_runtime_logins(transaction)? {
            if !options.runtime_logins.contains(&login) {
                problems.push(format!(
                    "login {login} is a member of praetore_runtime but not in {}",
                    RuntimeRoleOptions::RUNTIME_LOGINS_ENV
                ));
            }
        }
    }
    problems.truncate(10);
    Ok((!problems.is_empty()).then(|| problems.join(", ")))
}

/// Objects outside `praetore` and `pg_toast` that depend (`pg_depend`) on a
/// praetore relation, function or type: views, materialized views, rules,
/// triggers, constraints, defaults, policies or functions elsewhere that
/// would act on praetore data with their own owner's rights. Up to ten.
fn external_dependents(
    transaction: &mut postgres::Transaction<'_>,
) -> Result<Option<String>, RuntimeRoleError> {
    let row = transaction.query_one(
        "WITH ns AS (SELECT n.oid FROM pg_catalog.pg_namespace n \
                     WHERE n.nspname OPERATOR(pg_catalog.=) 'praetore'), \
         referenced AS ( \
             SELECT d.classid, d.objid, d.objsubid FROM pg_catalog.pg_depend d CROSS JOIN ns \
             WHERE (d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass \
                    AND EXISTS (SELECT 1 FROM pg_catalog.pg_class x \
                                WHERE x.oid OPERATOR(pg_catalog.=) d.refobjid \
                                  AND x.relnamespace OPERATOR(pg_catalog.=) ns.oid)) \
                OR (d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass \
                    AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc x \
                                WHERE x.oid OPERATOR(pg_catalog.=) d.refobjid \
                                  AND x.pronamespace OPERATOR(pg_catalog.=) ns.oid)) \
                OR (d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_type'::pg_catalog.regclass \
                    AND EXISTS (SELECT 1 FROM pg_catalog.pg_type x \
                                WHERE x.oid OPERATOR(pg_catalog.=) d.refobjid \
                                  AND x.typnamespace OPERATOR(pg_catalog.=) ns.oid))), \
         dependents AS ( \
             SELECT pg_catalog.concat(o.type, ' ', o.identity) AS entry, \
                    CASE \
                        WHEN r.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass \
                            THEN (SELECT c.relnamespace FROM pg_catalog.pg_class c \
                                  WHERE c.oid OPERATOR(pg_catalog.=) r.objid) \
                        WHEN r.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass \
                            THEN (SELECT p.pronamespace FROM pg_catalog.pg_proc p \
                                  WHERE p.oid OPERATOR(pg_catalog.=) r.objid) \
                        WHEN r.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_type'::pg_catalog.regclass \
                            THEN (SELECT t.typnamespace FROM pg_catalog.pg_type t \
                                  WHERE t.oid OPERATOR(pg_catalog.=) r.objid) \
                        WHEN r.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_constraint'::pg_catalog.regclass \
                            THEN (SELECT con.connamespace FROM pg_catalog.pg_constraint con \
                                  WHERE con.oid OPERATOR(pg_catalog.=) r.objid) \
                        WHEN r.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_policy'::pg_catalog.regclass \
                            THEN (SELECT c.relnamespace FROM pg_catalog.pg_policy pol \
                                  JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) pol.polrelid \
                                  WHERE pol.oid OPERATOR(pg_catalog.=) r.objid) \
                        WHEN r.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_trigger'::pg_catalog.regclass \
                            THEN (SELECT c.relnamespace FROM pg_catalog.pg_trigger g \
                                  JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) g.tgrelid \
                                  WHERE g.oid OPERATOR(pg_catalog.=) r.objid) \
                        WHEN r.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_attrdef'::pg_catalog.regclass \
                            THEN (SELECT c.relnamespace FROM pg_catalog.pg_attrdef ad \
                                  JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) ad.adrelid \
                                  WHERE ad.oid OPERATOR(pg_catalog.=) r.objid) \
                        WHEN r.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_rewrite'::pg_catalog.regclass \
                            THEN (SELECT c.relnamespace FROM pg_catalog.pg_rewrite rw \
                                  JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) rw.ev_class \
                                  WHERE rw.oid OPERATOR(pg_catalog.=) r.objid) \
                    END AS dependent_namespace \
             FROM referenced r \
             CROSS JOIN LATERAL pg_catalog.pg_identify_object(r.classid, r.objid, r.objsubid) o) \
         SELECT pg_catalog.string_agg(entry, ', ' ORDER BY entry) \
         FROM (SELECT DISTINCT entry FROM dependents CROSS JOIN ns \
               WHERE dependents.dependent_namespace IS NOT NULL \
                 AND dependents.dependent_namespace OPERATOR(pg_catalog.<>) ns.oid \
                 AND dependents.dependent_namespace OPERATOR(pg_catalog.<>) \
                     'pg_toast'::pg_catalog.regnamespace::pg_catalog.oid \
               ORDER BY entry LIMIT 10) first_entries",
        &[],
    )?;
    Ok(row.get(0))
}

/// A SECURITY DEFINER function, in any schema but `pg_catalog` and
/// `information_schema`, that runs with the rights of the `praetore` schema
/// owner (its owner has that owner's privileges, superusers included) and
/// that any role other than its owner may execute (PUBLIC included): calling
/// it would act as the owner. Functions the operator trusts explicitly
/// (`RuntimeRoleOptions::with_trusted_security_definer`) are not reported;
/// nothing is trusted by default.
fn owner_function_executable(
    transaction: &mut postgres::Transaction<'_>,
    options: &RuntimeRoleOptions,
) -> Result<Option<String>, RuntimeRoleError> {
    let trusted: Vec<u32> =
        resolve_trusted_security_definer(transaction, &options.trusted_security_definer)
            .map_err(RuntimeRoleError::InvalidConfiguration)?
            .iter()
            .map(|function| function.oid)
            .collect();
    let row = transaction.query_one(
        "SELECT pg_catalog.string_agg(p.oid::pg_catalog.regprocedure::pg_catalog.text, ', ' \
                    ORDER BY p.oid::pg_catalog.regprocedure::pg_catalog.text) \
         FROM pg_catalog.pg_proc p \
         JOIN pg_catalog.pg_namespace fn ON fn.oid OPERATOR(pg_catalog.=) p.pronamespace \
         JOIN pg_catalog.pg_namespace owner_ns \
           ON owner_ns.nspname OPERATOR(pg_catalog.=) 'praetore' \
         WHERE p.prosecdef \
           AND fn.nspname OPERATOR(pg_catalog.<>) 'pg_catalog' \
           AND fn.nspname OPERATOR(pg_catalog.<>) 'information_schema' \
           AND pg_catalog.pg_has_role(p.proowner, owner_ns.nspowner, 'USAGE') \
           AND NOT (p.oid OPERATOR(pg_catalog.=) ANY ($1::pg_catalog.oid[])) \
           AND EXISTS (SELECT 1 FROM pg_catalog.aclexplode( \
                           COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) a \
                       WHERE a.privilege_type OPERATOR(pg_catalog.=) 'EXECUTE' \
                         AND a.grantee OPERATOR(pg_catalog.<>) p.proowner)",
        &[&trusted],
    )?;
    Ok(row.get(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(contents: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "praetore-root-{}-{}.pem",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    // Self-signed test CA (not used for any real service).
    const TEST_ROOT_PEM: &str = include_str!("../tests/fixtures/test-root-ca.pem");

    #[test]
    fn pinned_options_refuse_a_trailing_unescaped_backslash() {
        let url =
            |options: &str| format!("postgres://gateway@127.0.0.1/praetore?options={options}");
        assert!(DatabaseConnector::from_url(&url("-c%20application_name%3Dx")).is_ok());
        assert!(DatabaseConnector::from_url(&url("-c%20application_name%3Dx%5C%5C")).is_ok());
        assert!(matches!(
            DatabaseConnector::from_url(&url("-c%20application_name%3Dx%5C")),
            Err(DatabaseUrlError::Invalid(_))
        ));
        let connector = DatabaseConnector::from_url(&url("-c%20application_name%3Dx")).unwrap();
        assert_eq!(
            connector.config.get_options(),
            Some("-c application_name=x -c search_path=pg_catalog,pg_temp")
        );
    }

    #[test]
    fn runtime_role_options_accept_only_exact_relaxable_names() {
        assert_eq!(
            RuntimeRoleOptions::from_allow_settings("").unwrap(),
            RuntimeRoleOptions::default()
        );
        assert!(RuntimeRoleOptions::default().relaxed().is_empty());
        let relaxed = RuntimeRoleOptions::from_allow_settings(" search_path ").unwrap();
        assert_eq!(relaxed.relaxed(), vec!["search_path"]);
        for refused in [
            "row_security",
            "session_replication_role",
            "SEARCH_PATH",
            "search-path",
        ] {
            assert!(
                RuntimeRoleOptions::from_allow_settings(refused).is_err(),
                "{refused}"
            );
        }
        assert!(RuntimeRoleOptions::from_allow_settings("search_path,row_security").is_err());
    }

    #[test]
    fn loopback_and_unix_hosts_may_connect_without_tls() {
        for url in [
            "postgres://postgres@localhost/praetore",
            "postgres://postgres@127.0.0.1:5432/praetore",
            "postgres://postgres@[::1]:5432/praetore",
            "postgres://postgres@127.0.0.1/praetore?sslmode=disable",
            "host=/var/run/postgresql user=postgres dbname=praetore",
            "host=127.0.0.1 user=postgres sslmode=disable",
        ] {
            let connector = DatabaseConnector::from_url(url).unwrap();
            assert!(!connector.uses_tls(), "{url}");
            assert!(connector.is_loopback(), "{url}");
        }
    }

    #[test]
    fn remote_hosts_require_verify_full_before_any_connection() {
        for url in [
            "postgres://gateway@db.internal/praetore",
            "postgres://gateway@db.internal/praetore?sslmode=disable",
            "postgres://gateway@10.0.0.5/praetore",
            "host=db.internal user=gateway",
            // A loopback host name with a remote hostaddr is remote.
            "host=localhost hostaddr=10.0.0.5 user=gateway",
            // One remote host in a list is enough.
            "postgres://gateway@localhost,db.internal/praetore",
        ] {
            assert!(
                matches!(
                    DatabaseConnector::from_url(url),
                    Err(DatabaseUrlError::TlsRequired)
                ),
                "{url}"
            );
        }
        for mode in ["prefer", "require", "verify-ca", "allow"] {
            let url = format!("postgres://gateway@db.internal/praetore?sslmode={mode}");
            assert!(
                matches!(
                    DatabaseConnector::from_url(&url),
                    Err(DatabaseUrlError::UnsupportedSslMode(_))
                ),
                "{url}"
            );
        }
        assert!(matches!(
            DatabaseConnector::from_url("host=db.internal user=gateway sslmode=require"),
            Err(DatabaseUrlError::UnsupportedSslMode(_))
        ));
        assert!(matches!(
            DatabaseConnector::from_url(
                "postgres://gateway@db.internal/praetore?sslmode=verify-full"
            ),
            Err(DatabaseUrlError::RootCertificate(_))
        ));
        assert!(matches!(
            DatabaseConnector::from_url(
                "postgres://gateway@db.internal/praetore?sslmode=verify-full&sslrootcert=%2Fmissing"
            ),
            Err(DatabaseUrlError::RootCertificate(_))
        ));
        assert!(matches!(
            DatabaseConnector::from_url(
                "postgres://gateway@db.internal/praetore?sslmode=disable&sslmode=verify-full"
            ),
            Err(DatabaseUrlError::Invalid(_))
        ));
    }

    #[test]
    fn verify_full_with_a_root_certificate_is_accepted_for_remote_hosts() {
        let root = write_temp(TEST_ROOT_PEM.as_bytes());
        let encoded = root.display().to_string().replace('/', "%2F");
        let url = format!(
            "postgres://gateway@postgres.praetore-data.svc:5432/praetore?sslmode=verify-full&sslrootcert={encoded}&application_name=gateway"
        );
        let connector = DatabaseConnector::from_url(&url).unwrap();
        assert!(connector.uses_tls());
        assert!(!connector.is_loopback());
        assert!(
            !format!("{connector:?}").contains("gateway@"),
            "debug output must not contain the URL"
        );
        // A loopback host may opt into verify-full too.
        let url = format!(
            "postgres://gateway@localhost/praetore?sslmode=verify-full&sslrootcert={}",
            root.display()
        );
        assert!(DatabaseConnector::from_url(&url).unwrap().uses_tls());

        let empty = write_temp(b"not a certificate");
        let url = format!(
            "postgres://gateway@db.internal/praetore?sslmode=verify-full&sslrootcert={}",
            empty.display()
        );
        assert!(matches!(
            DatabaseConnector::from_url(&url),
            Err(DatabaseUrlError::RootCertificate(_))
        ));
        let _ = std::fs::remove_file(root);
        let _ = std::fs::remove_file(empty);
    }

    /// Answers a PostgreSQL SSLRequest with `S` and runs a rustls server
    /// handshake; returns whether the handshake completed.
    fn fake_tls_postgres(
        certificate_pem: &'static str,
        key_pem: &'static str,
    ) -> (u16, std::thread::JoinHandle<bool>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            let mut ssl_request = [0_u8; 8];
            tcp.read_exact(&mut ssl_request).unwrap();
            assert_eq!(ssl_request, [0, 0, 0, 8, 4, 210, 22, 47], "SSLRequest");
            tcp.write_all(b"S").unwrap();
            let certificates = CertificateDer::pem_slice_iter(certificate_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
            let mut connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            while connection.is_handshaking() {
                if connection.complete_io(&mut tcp).is_err() {
                    return false;
                }
            }
            true
        });
        (port, handle)
    }

    fn verify_full_url(host: &str, port: u16, root: &std::path::Path) -> String {
        format!(
            "postgres://gateway@{host}:{port}/praetore?sslmode=verify-full&sslrootcert={}&connect_timeout=5",
            root.display()
        )
    }

    #[test]
    fn verify_full_completes_a_handshake_only_with_a_trusted_matching_certificate() {
        let root = write_temp(TEST_ROOT_PEM.as_bytes());
        let server_pem = include_str!("../tests/fixtures/test-server.pem");
        let server_key = include_str!("../tests/fixtures/test-server.key");

        // Trusted chain and matching names: the TLS handshake completes (the
        // fake server then hangs up, so connect itself fails afterwards).
        for host in ["localhost", "127.0.0.1"] {
            let (port, server) = fake_tls_postgres(server_pem, server_key);
            let connector =
                DatabaseConnector::from_url(&verify_full_url(host, port, &root)).unwrap();
            assert!(connector.connect().is_err());
            assert!(server.join().unwrap(), "handshake with {host}");
        }

        // Certificate for another name: refused by the client.
        let (port, server) = fake_tls_postgres(
            include_str!("../tests/fixtures/test-wrong-name.pem"),
            include_str!("../tests/fixtures/test-wrong-name.key"),
        );
        let connector =
            DatabaseConnector::from_url(&verify_full_url("127.0.0.1", port, &root)).unwrap();
        assert!(connector.connect().is_err());
        assert!(
            !server.join().unwrap(),
            "name mismatch must fail the handshake"
        );

        // Untrusted root: the server certificate is its own (non-CA) root.
        let wrong_root = write_temp(server_pem.as_bytes());
        let (port, server) = fake_tls_postgres(server_pem, server_key);
        let connector =
            DatabaseConnector::from_url(&verify_full_url("localhost", port, &wrong_root)).unwrap();
        assert!(connector.connect().is_err());
        assert!(
            !server.join().unwrap(),
            "untrusted chain must fail the handshake"
        );
        let _ = std::fs::remove_file(root);
        let _ = std::fs::remove_file(wrong_root);
    }

    #[test]
    fn tls_parameters_are_stripped_and_decoded() {
        let (stripped, parameters) = extract_tls_parameters(
            "postgresql://u@h/db?application_name=x&sslmode=verify-full&sslrootcert=%2Fetc%2Fca.pem",
        )
        .unwrap();
        assert_eq!(stripped, "postgresql://u@h/db?application_name=x");
        assert_eq!(parameters.mode.as_deref(), Some("verify-full"));
        assert_eq!(parameters.root_cert.as_deref(), Some("/etc/ca.pem"));
        assert!(extract_tls_parameters("postgres://u@h/db?sslrootcert=%zz").is_err());
    }
}
