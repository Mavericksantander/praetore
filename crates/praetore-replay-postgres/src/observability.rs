use postgres::{Client, Row};
use praetore_core::Evidence;
use praetore_gateway::{AuthorizationStatus, ExecutionKey, ExecutionStatus, JournalError};
use std::sync::Mutex;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct ExecutionFilters {
    pub tenant_id: Option<Uuid>,
    pub agent_id: Option<Uuid>,
    pub decision: Option<AuthorizationStatus>,
    pub execution: Option<ExecutionStatus>,
    pub from: Option<OffsetDateTime>,
    pub to: Option<OffsetDateTime>,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug, Clone)]
pub struct ObservedExecution {
    pub key: ExecutionKey,
    pub created_at: String,
    pub updated_at: String,
    pub request_digest: String,
    pub action_digest: String,
    pub authorization: AuthorizationStatus,
    pub execution: ExecutionStatus,
    pub evidence: Evidence,
    pub output_available: bool,
}

#[derive(Debug, Clone)]
pub struct ExecutionTransition {
    pub from: Option<ExecutionStatus>,
    pub to: ExecutionStatus,
    pub occurred_at: String,
}

#[derive(Debug, Clone)]
pub struct ExecutionPage {
    pub total: i64,
    pub rows: Vec<ObservedExecution>,
}

pub struct PostgresObservabilityReader {
    client: Mutex<Client>,
}

impl PostgresObservabilityReader {
    pub fn from_client(mut client: Client) -> Result<Self, JournalError> {
        client
            .batch_execute(
                "SET default_transaction_read_only = on; \
                 SET statement_timeout = '5s'; \
                 SET lock_timeout = '1s'",
            )
            .map_err(|_| JournalError::Unavailable)?;
        Ok(Self {
            client: Mutex::new(client),
        })
    }

    pub fn list(&self, filters: &ExecutionFilters) -> Result<ExecutionPage, JournalError> {
        validate_filters(filters)?;
        let mut client = self.client.lock().map_err(|_| JournalError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| JournalError::Unavailable)?;
        transaction
            .batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .map_err(|_| JournalError::Unavailable)?;
        let decision = filters.decision.map(crate::execution::authorization_as_db);
        let execution = filters.execution.map(crate::execution::execution_as_db);
        let total: i64 = transaction
            .query_one(
                "SELECT COUNT(*) FROM praetore.execution_journal \
                 WHERE ($1::uuid IS NULL OR tenant_id = $1) \
                   AND ($2::uuid IS NULL OR agent_id = $2) \
                   AND ($3::text IS NULL OR authorization_status = $3) \
                   AND ($4::text IS NULL OR execution_status = $4) \
                   AND ($5::timestamptz IS NULL OR created_at >= $5) \
                   AND ($6::timestamptz IS NULL OR created_at <= $6)",
                &[
                    &filters.tenant_id,
                    &filters.agent_id,
                    &decision,
                    &execution,
                    &filters.from,
                    &filters.to,
                ],
            )
            .map_err(|_| JournalError::Unavailable)?
            .get(0);
        let rows = transaction
            .query(
                "SELECT tenant_id, agent_id, request_id, request_digest, action_digest, \
                        authorization_status, execution_status, evidence_json, \
                        to_char(created_at AT TIME ZONE 'UTC', \
                            'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), \
                        to_char(updated_at AT TIME ZONE 'UTC', \
                            'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
                 FROM praetore.execution_journal \
                 WHERE ($1::uuid IS NULL OR tenant_id = $1) \
                   AND ($2::uuid IS NULL OR agent_id = $2) \
                   AND ($3::text IS NULL OR authorization_status = $3) \
                   AND ($4::text IS NULL OR execution_status = $4) \
                   AND ($5::timestamptz IS NULL OR created_at >= $5) \
                   AND ($6::timestamptz IS NULL OR created_at <= $6) \
                 ORDER BY created_at DESC, agent_id, request_id \
                 LIMIT $7 OFFSET $8",
                &[
                    &filters.tenant_id,
                    &filters.agent_id,
                    &decision,
                    &execution,
                    &filters.from,
                    &filters.to,
                    &i64::from(filters.limit),
                    &i64::from(filters.offset),
                ],
            )
            .map_err(|_| JournalError::Unavailable)?
            .into_iter()
            .map(parse_observed)
            .collect::<Result<Vec<_>, _>>()?;
        transaction
            .commit()
            .map_err(|_| JournalError::Unavailable)?;
        Ok(ExecutionPage { total, rows })
    }

    pub fn get(
        &self,
        key: ExecutionKey,
    ) -> Result<Option<(ObservedExecution, Vec<ExecutionTransition>)>, JournalError> {
        let mut client = self.client.lock().map_err(|_| JournalError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| JournalError::Unavailable)?;
        transaction
            .batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .map_err(|_| JournalError::Unavailable)?;
        let row = transaction
            .query_opt(
                "SELECT tenant_id, agent_id, request_id, request_digest, action_digest, \
                        authorization_status, execution_status, evidence_json, \
                        to_char(created_at AT TIME ZONE 'UTC', \
                            'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), \
                        to_char(updated_at AT TIME ZONE 'UTC', \
                            'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
                 FROM praetore.execution_journal \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?;
        let Some(row) = row else {
            transaction
                .commit()
                .map_err(|_| JournalError::Unavailable)?;
            return Ok(None);
        };
        let operation = parse_observed(row)?;
        let transitions = transaction
            .query(
                "SELECT from_status, to_status, \
                        to_char(occurred_at AT TIME ZONE 'UTC', \
                            'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
                 FROM praetore.execution_journal_events \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3 ORDER BY event_id",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?
            .iter()
            .map(parse_transition)
            .collect::<Result<Vec<_>, _>>()?;
        transaction
            .commit()
            .map_err(|_| JournalError::Unavailable)?;
        Ok(Some((operation, transitions)))
    }

    pub fn database_available(&self) -> bool {
        let Ok(mut client) = self.client.lock() else {
            return false;
        };
        client.query_one("SELECT 1", &[]).is_ok()
    }
}

fn validate_filters(filters: &ExecutionFilters) -> Result<(), JournalError> {
    if filters.limit == 0 || filters.limit > 100 || filters.offset > 10_000 {
        return Err(JournalError::InvalidRecord);
    }
    Ok(())
}

fn parse_observed(row: Row) -> Result<ObservedExecution, JournalError> {
    let key = ExecutionKey {
        tenant_id: row.get(0),
        agent_id: row.get(1),
        request_id: row.get(2),
    };
    let request_digest: String = row.get(3);
    let action_digest: String = row.get(4);
    let authorization = crate::execution::parse_authorization(&row.get::<_, String>(5))?;
    let execution = crate::execution::parse_execution(&row.get::<_, String>(6))?;
    let evidence_json: String = row.get(7);
    let evidence = Evidence::from_json(&evidence_json).map_err(|_| JournalError::InvalidRecord)?;
    let created_at: String = row.get(8);
    let updated_at: String = row.get(9);
    crate::execution::validate_evidence(key, &evidence, authorization)?;
    let (expected_request_digest, expected_action_digest) =
        crate::execution::execution_digests(&evidence)?;
    if !crate::execution::is_digest(&request_digest)
        || !crate::execution::is_digest(&action_digest)
        || expected_request_digest != request_digest
        || expected_action_digest != action_digest
    {
        return Err(JournalError::InvalidRecord);
    }
    Ok(ObservedExecution {
        key,
        created_at,
        updated_at,
        request_digest,
        action_digest,
        authorization,
        execution,
        evidence,
        output_available: matches!(
            execution,
            ExecutionStatus::Executed | ExecutionStatus::Confirmed
        ),
    })
}

fn parse_transition(row: &Row) -> Result<ExecutionTransition, JournalError> {
    let from: Option<String> = row.get(0);
    let to: String = row.get(1);
    let occurred_at: String = row.get(2);
    Ok(ExecutionTransition {
        from: from
            .as_deref()
            .map(crate::execution::parse_execution)
            .transpose()?,
        to: crate::execution::parse_execution(&to)?,
        occurred_at,
    })
}
