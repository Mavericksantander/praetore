use postgres::{Client, Transaction};
use praetore_core::replay::{ReplayGuard, ReplayGuardError};
use std::sync::Mutex;
use uuid::Uuid;

mod execution;
mod migrations;
mod observability;

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

pub(crate) fn set_tenant_context(
    transaction: &mut Transaction<'_>,
    tenant_id: Uuid,
) -> Result<(), postgres::Error> {
    transaction.query_one(
        "SELECT set_config('praetore.tenant_id', $1, true)",
        &[&tenant_id.to_string()],
    )?;
    Ok(())
}
