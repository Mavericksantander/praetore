use postgres::Client;
use praetore_core::replay::{ReplayGuard, ReplayGuardError};
use std::sync::Mutex;
use uuid::Uuid;

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
                "INSERT INTO praetore.replay_claims (agent_id, request_id) \
                 VALUES ($1, $2) ON CONFLICT (agent_id, request_id) DO NOTHING",
                &[&agent_id, &request_id],
            )
            .map_err(|_| ReplayGuardError::Unavailable)?;

        match inserted {
            1 => Ok(()),
            0 => Err(ReplayGuardError::AlreadyClaimed),
            _ => Err(ReplayGuardError::Unavailable),
        }
    }
}
