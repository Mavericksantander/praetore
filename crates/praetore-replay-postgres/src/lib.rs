use postgres::Client;
use praetore_core::replay::{ReplayGuard, ReplayGuardError};
use std::sync::Mutex;
use uuid::Uuid;

mod execution;
mod observability;

pub use execution::PostgresExecutionJournal;
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
        client
            .batch_execute("SET synchronous_commit = on")
            .map_err(|_| ReplayGuardError::Unavailable)?;
        let inserted = client
            .execute(
                "INSERT INTO praetore.replay_claims (tenant_id, agent_id, request_id) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (tenant_id, agent_id, request_id) DO NOTHING",
                &[&tenant_id, &agent_id, &request_id],
            )
            .map_err(|_| ReplayGuardError::Unavailable)?;

        match inserted {
            1 => Ok(()),
            0 => Err(ReplayGuardError::AlreadyClaimed),
            _ => Err(ReplayGuardError::Unavailable),
        }
    }
}
