use postgres::{Client, Transaction};
use praetore_core::replay::{ReplayGuard, ReplayGuardError};
use std::sync::Mutex;
use uuid::Uuid;

mod connection;
mod execution;
mod migrations;
mod observability;

pub use connection::{
    DatabaseConnector, DatabaseUrlError, RuntimeRoleError, RustlsConnect, verify_runtime_role,
};
pub use execution::PostgresExecutionJournal;
pub use migrations::{MIGRATIONS, MigrationError, apply_migrations, verify_schema_current};
pub use observability::{
    ExecutionFilters, ExecutionPage, ExecutionTransition, ObservedExecution,
    PostgresObservabilityReader,
};

pub struct PostgresReplayGuard {
    client: Mutex<Client>,
}

impl PostgresReplayGuard {
    pub fn from_client(client: Client) -> Self {
        Self {
            client: Mutex::new(client),
        }
    }
}

impl ReplayGuard for PostgresReplayGuard {
    fn claim_once(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        request_id: Uuid,
    ) -> std::result::Result<(), ReplayGuardError> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| ReplayGuardError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| ReplayGuardError::Unavailable)?;
        transaction
            .batch_execute("SET LOCAL synchronous_commit = on")
            .map_err(|_| ReplayGuardError::Unavailable)?;
        set_tenant_context(&mut transaction, tenant_id)
            .map_err(|_| ReplayGuardError::Unavailable)?;
        let inserted = transaction
            .execute(
                "INSERT INTO praetore.replay_claims (tenant_id, agent_id, request_id) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (tenant_id, agent_id, request_id) DO NOTHING",
                &[&tenant_id, &agent_id, &request_id],
            )
            .map_err(|_| ReplayGuardError::Unavailable)?;

        match inserted {
            1 => transaction
                .commit()
                .map_err(|_| ReplayGuardError::Unavailable),
            0 => Err(ReplayGuardError::AlreadyClaimed),
            _ => Err(ReplayGuardError::Unavailable),
        }
    }
}

/// Search path for every runtime transaction. All runtime SQL names
/// `praetore.` tables explicitly, so only `pg_catalog` needs to be visible;
/// a `public.set_config` or `public.=` cannot be picked up, whatever
/// search_path the database, the role, `ALTER SYSTEM` or the session set.
pub const RUNTIME_SEARCH_PATH: &str = "pg_catalog, pg_temp";

/// Starts every runtime transaction: pins `search_path` for the transaction
/// (`SET LOCAL`) and sets `praetore.tenant_id`, which the `tenant_isolation`
/// RLS policies read, with the schema-qualified `pg_catalog.set_config`.
pub fn set_tenant_context(
    transaction: &mut Transaction<'_>,
    tenant_id: Uuid,
) -> Result<(), postgres::Error> {
    transaction.batch_execute(&format!("SET LOCAL search_path = {RUNTIME_SEARCH_PATH}"))?;
    transaction.query_one(
        "SELECT pg_catalog.set_config('praetore.tenant_id', $1, true)",
        &[&tenant_id.to_string()],
    )?;
    Ok(())
}
