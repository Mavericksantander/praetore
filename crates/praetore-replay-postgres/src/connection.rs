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
            Self::UnsafeSetting(setting) => write!(
                f,
                "runtime database session is exposed to {setting}; the append-only triggers, \
                 row-level security or name resolution could be changed"
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
/// as one from `ALTER SYSTEM`, or a parameter grant), and a session
/// search_path that puts another schema before `pg_catalog`.
///
/// The checks run in a read-only transaction under `RUNTIME_SEARCH_PATH`, so
/// they cannot be shadowed themselves. They run once, when the caller starts
/// (the gateway and the CLI do this at startup); reconnections of a
/// connection factory are not checked again. Every runtime transaction pins
/// its search_path (`set_tenant_context`) regardless.
pub fn verify_runtime_role(client: &mut Client) -> Result<(), RuntimeRoleError> {
    let mut transaction = client.build_transaction().read_only(true).start()?;
    // The session's own search_path, before it is pinned below. A harmless
    // value (pg_catalog implicitly or explicitly first, e.g. "$user", public)
    // is accepted: runtime transactions pin search_path anyway.
    let schemas: Vec<String> = transaction
        .query_one(
            "SELECT pg_catalog.current_schemas(true)::pg_catalog.text[]",
            &[],
        )?
        .get(0);
    if let Some(first) = schemas.iter().find(|schema| !schema.starts_with("pg_temp"))
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
    let result = verify_runtime_role_in(&mut transaction);
    transaction.rollback()?;
    result
}

fn verify_runtime_role_in(
    transaction: &mut postgres::Transaction<'_>,
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
    if let Some(setting) = unsafe_runtime_setting(transaction)? {
        return Err(RuntimeRoleError::UnsafeSetting(setting));
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
    Ok(())
}

/// Settings that would disable the append-only triggers or row-level
/// security for this session: a `row_security` or `session_replication_role`
/// set for this database or all databases and for this login role or all
/// roles (`pg_db_role_setting`); a session-start value of `row_security` or
/// `session_replication_role` that is not the built-in default (for example
/// from `ALTER SYSTEM`); and a `GRANT SET` or `GRANT ALTER SYSTEM` on one of
/// those parameters to PUBLIC or to a role the session or current role
/// belongs to (`pg_parameter_acl`, PostgreSQL 15 and later).
fn unsafe_runtime_setting(
    transaction: &mut postgres::Transaction<'_>,
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
                    OR pg_catalog.starts_with(s.setting, 'session_replication_role='))), \
             ( \
             SELECT pg_catalog.string_agg( \
                        pg_catalog.concat(p.name, '=', p.reset_val, ' (', p.source, ')'), ', ' \
                        ORDER BY p.name) \
             FROM pg_catalog.pg_settings p \
             WHERE (p.name OPERATOR(pg_catalog.=) 'row_security' \
                    OR p.name OPERATOR(pg_catalog.=) 'session_replication_role') \
               AND p.reset_val OPERATOR(pg_catalog.<>) p.boot_val), \
             pg_catalog.to_regclass('pg_catalog.pg_parameter_acl') IS NOT NULL",
        &[],
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
