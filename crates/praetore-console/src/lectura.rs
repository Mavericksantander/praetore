//! SELECT-only journal read for the console.
//!
//! The SELECT-only role needs the journal columns Observe already reads, plus
//! `execution_journal.not_dispatched_reason` and, on `execution_attestations`,
//! `tenant_id`, `agent_id`, `request_id`, `execution_status`, and
//! `not_dispatched_reason`. Those two fields are what separate
//! "pendiente de aprobación", "rechazado", and "expirado".

use crate::{
    HistoryError, HistoryPage, HistoryStore, InboxPage, InboxStore, ListRequest,
    bandeja::{INBOX_LIMIT, PendingColumns, PendingKind, pending_from_columns},
    historia::{JournalColumns, facts_from_columns, parse_journal_timestamp},
};
use postgres::{Client, Row};
use praetore_gateway::{
    AttestedExecution, AuthorizationStatus, ExecutionStatus, NotDispatchedReason,
};
use praetore_replay_postgres::set_tenant_context;
use std::sync::Mutex;
use uuid::Uuid;

pub struct PostgresHistory {
    client: Mutex<Client>,
    tenant_id: Uuid,
}

impl PostgresHistory {
    pub fn from_client(mut client: Client, tenant_id: Uuid) -> Result<Self, HistoryError> {
        client
            .batch_execute(
                "SET default_transaction_read_only = on; \
                 SET statement_timeout = '5s'; \
                 SET lock_timeout = '1s'",
            )
            .map_err(|_| HistoryError::Unavailable)?;
        Ok(Self {
            client: Mutex::new(client),
            tenant_id,
        })
    }
}

impl HistoryStore for PostgresHistory {
    fn list(&self, query: &ListRequest) -> Result<HistoryPage, HistoryError> {
        let mut client = self.client.lock().map_err(|_| HistoryError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| HistoryError::Unavailable)?;
        transaction
            .batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .map_err(|_| HistoryError::Unavailable)?;
        set_tenant_context(&mut transaction, self.tenant_id)
            .map_err(|_| HistoryError::Unavailable)?;
        let situation = query.situation.map(situation_sql).unwrap_or("TRUE");
        let total: i64 = transaction
            .query_one(
                &format!(
                    "SELECT COUNT(*) FROM praetore.execution_journal j \
                     WHERE {TIME_FILTER} AND ({situation})"
                ),
                &[&query.from, &query.until],
            )
            .map_err(|_| HistoryError::Unavailable)?
            .get(0);
        let rows = transaction
            .query(
                &format!(
                    "SELECT j.agent_id, j.request_id, j.authorization_status, j.execution_status, \
                            j.not_dispatched_reason, j.evidence_json, \
                            to_char(j.created_at AT TIME ZONE 'UTC', \
                                'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), \
                            to_char(j.updated_at AT TIME ZONE 'UTC', \
                                'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), \
                            (SELECT ea.execution_status \
                               FROM praetore.execution_attestations ea \
                              WHERE ea.tenant_id = j.tenant_id \
                                AND ea.agent_id = j.agent_id \
                                AND ea.request_id = j.request_id \
                                AND ((ea.execution_status = j.execution_status \
                                      AND ea.not_dispatched_reason IS NOT DISTINCT FROM \
                                          j.not_dispatched_reason) \
                                  OR (ea.execution_status = 'awaiting_approval' \
                                      AND j.execution_status = 'not_dispatched' \
                                      AND j.not_dispatched_reason IS NULL)) \
                              ORDER BY (ea.execution_status = 'awaiting_approval') DESC \
                              LIMIT 1) \
                       FROM praetore.execution_journal j \
                      WHERE {TIME_FILTER} AND ({situation}) \
                      ORDER BY j.created_at DESC, j.agent_id, j.request_id \
                      LIMIT $3 OFFSET $4"
                ),
                &[
                    &query.from,
                    &query.until,
                    &i64::from(query.limit),
                    &i64::from(query.offset),
                ],
            )
            .map_err(|_| HistoryError::Unavailable)?;
        let mut receipts = Vec::with_capacity(rows.len());
        for row in rows {
            let facts = parse_row(row)?;
            if query
                .situation
                .is_some_and(|wanted| crate::historia::situation(&facts) != wanted)
            {
                continue;
            }
            receipts.push(facts);
        }
        let agents = transaction
            .query(
                "SELECT DISTINCT agent_id FROM praetore.execution_journal ORDER BY agent_id",
                &[],
            )
            .map_err(|_| HistoryError::Unavailable)?
            .iter()
            .map(|row| row.get(0))
            .collect();
        transaction
            .commit()
            .map_err(|_| HistoryError::Unavailable)?;
        Ok(HistoryPage {
            total,
            receipts,
            agents,
        })
    }
}

impl InboxStore for PostgresHistory {
    /// Requests that wait for the operator, oldest first. Same SELECT-only
    /// role and tenant context as the history; nothing is written.
    fn pending(&self) -> Result<InboxPage, HistoryError> {
        let mut client = self.client.lock().map_err(|_| HistoryError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| HistoryError::Unavailable)?;
        transaction
            .batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .map_err(|_| HistoryError::Unavailable)?;
        set_tenant_context(&mut transaction, self.tenant_id)
            .map_err(|_| HistoryError::Unavailable)?;
        let rows = transaction
            .query(
                &format!(
                    "SELECT j.agent_id, j.request_id, j.execution_status, j.evidence_json, \
                            to_char(j.created_at AT TIME ZONE 'UTC', \
                                'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
                       FROM praetore.execution_journal j \
                      WHERE j.tenant_id = $1 AND (({INBOX_SQL})) \
                      ORDER BY j.created_at ASC, j.agent_id, j.request_id \
                      LIMIT $2"
                ),
                &[&self.tenant_id, &i64::from(INBOX_LIMIT)],
            )
            .map_err(|_| HistoryError::Unavailable)?;
        let mut items = Vec::with_capacity(rows.len());
        let mut unreadable = 0u32;
        for row in rows {
            let kind = match row.get::<_, String>(2).as_str() {
                "approved_pending_dispatch" => PendingKind::ApprovedPendingExecution,
                "not_dispatched" => PendingKind::AwaitingApproval,
                _ => return Err(HistoryError::Invalid),
            };
            let created_at = parse_journal_timestamp(&row.get::<_, String>(4))
                .map_err(|_| HistoryError::Invalid)?;
            match pending_from_columns(
                self.tenant_id,
                PendingColumns {
                    created_at,
                    agent_id: row.get(0),
                    request_id: row.get(1),
                    kind,
                    evidence_json: row.get(3),
                },
            ) {
                Ok(facts) => items.push(facts),
                // Never offered for a decision. Counted so the page can say so.
                Err(()) => unreadable += 1,
            }
        }
        let agents = transaction
            .query(
                "SELECT DISTINCT agent_id FROM praetore.execution_journal ORDER BY agent_id",
                &[],
            )
            .map_err(|_| HistoryError::Unavailable)?
            .iter()
            .map(|row| row.get(0))
            .collect();
        transaction
            .commit()
            .map_err(|_| HistoryError::Unavailable)?;
        Ok(InboxPage {
            items,
            unreadable,
            agents,
        })
    }
}

/// Rows the operator can still act on: a hold with no decision yet, or an
/// approval whose single dispatch has not been claimed.
const INBOX_SQL: &str = "(j.authorization_status = 'requires_approval' \
       AND j.execution_status = 'not_dispatched' \
       AND j.not_dispatched_reason IS NULL) \
     OR (j.authorization_status = 'requires_approval' \
       AND j.execution_status = 'approved_pending_dispatch')";

const TIME_FILTER: &str = "($1::timestamptz IS NULL OR j.created_at >= $1) \
     AND ($2::timestamptz IS NULL OR j.created_at < $2)";

/// Fixed SQL, one arm per [`crate::historia::Situation`]. No request text is interpolated.
fn situation_sql(situation: crate::historia::Situation) -> &'static str {
    use crate::historia::Situation;
    match situation {
        Situation::Permitted => "j.authorization_status = 'allowed'",
        Situation::Denied => "j.authorization_status = 'denied'",
        Situation::ApprovedPendingExecution => "j.execution_status = 'approved_pending_dispatch'",
        Situation::Rejected => "j.not_dispatched_reason = 'approval_rejected'",
        Situation::Expired => {
            "j.not_dispatched_reason IN ('approval_expired', 'approved_claim_expired')"
        }
        Situation::AwaitingApproval => {
            "j.authorization_status = 'requires_approval' \
             AND j.execution_status = 'not_dispatched' \
             AND j.not_dispatched_reason IS NULL"
        }
        Situation::Approved => {
            "j.authorization_status = 'requires_approval' \
             AND j.execution_status IN ( \
                'dispatched', 'executed', 'confirmed', 'failed', 'outcome_unknown')"
        }
        Situation::NotExecuted => {
            "j.not_dispatched_reason IN ( \
                'dispatch_refused', 'dispatch_failed', 'crash_recovered')"
        }
        Situation::Unreadable => "FALSE",
    }
}

fn parse_row(row: Row) -> Result<crate::historia::ReceiptFacts, HistoryError> {
    let authorization = parse_authorization(&row.get::<_, String>(2))?;
    let execution = parse_execution(&row.get::<_, String>(3))?;
    let reason = parse_reason(row.get(4))?;
    let attested = parse_attested(row.get(8))?;
    let created_at =
        parse_journal_timestamp(&row.get::<_, String>(6)).map_err(|_| HistoryError::Invalid)?;
    let updated_at =
        parse_journal_timestamp(&row.get::<_, String>(7)).map_err(|_| HistoryError::Invalid)?;
    facts_from_columns(JournalColumns {
        created_at,
        updated_at,
        agent_id: row.get(0),
        request_id: row.get(1),
        authorization,
        execution,
        attested,
        reason,
        evidence_json: row.get(5),
    })
    .map_err(|_| HistoryError::Invalid)
}

fn parse_authorization(value: &str) -> Result<AuthorizationStatus, HistoryError> {
    match value {
        "allowed" => Ok(AuthorizationStatus::Allowed),
        "requires_approval" => Ok(AuthorizationStatus::RequiresApproval),
        "denied" => Ok(AuthorizationStatus::Denied),
        _ => Err(HistoryError::Invalid),
    }
}

fn parse_execution(value: &str) -> Result<ExecutionStatus, HistoryError> {
    match value {
        "not_dispatched" => Ok(ExecutionStatus::NotDispatched),
        "authorized" => Ok(ExecutionStatus::Authorized),
        "approved_pending_dispatch" => Ok(ExecutionStatus::ApprovedPendingDispatch),
        "dispatched" => Ok(ExecutionStatus::Dispatched),
        "executed" => Ok(ExecutionStatus::Executed),
        "confirmed" => Ok(ExecutionStatus::Confirmed),
        "outcome_unknown" => Ok(ExecutionStatus::OutcomeUnknown),
        "failed" => Ok(ExecutionStatus::Failed),
        _ => Err(HistoryError::Invalid),
    }
}

fn parse_reason(value: Option<String>) -> Result<Option<NotDispatchedReason>, HistoryError> {
    let Some(value) = value else {
        return Ok(None);
    };
    Ok(Some(match value.as_str() {
        "approval_expired" => NotDispatchedReason::ApprovalExpired,
        "approval_rejected" => NotDispatchedReason::ApprovalRejected,
        "dispatch_failed" => NotDispatchedReason::DispatchFailed,
        "crash_recovered" => NotDispatchedReason::CrashRecovered,
        "dispatch_refused" => NotDispatchedReason::DispatchRefused,
        "approved_claim_expired" => NotDispatchedReason::ApprovedClaimExpired,
        _ => return Err(HistoryError::Invalid),
    }))
}

fn parse_attested(value: Option<String>) -> Result<Option<AttestedExecution>, HistoryError> {
    let Some(value) = value else {
        return Ok(None);
    };
    Ok(Some(match value.as_str() {
        "not_dispatched" => AttestedExecution::NotDispatched,
        "awaiting_approval" => AttestedExecution::AwaitingApproval,
        "executed" => AttestedExecution::Executed,
        "confirmed" => AttestedExecution::Confirmed,
        "outcome_unknown" => AttestedExecution::OutcomeUnknown,
        "failed" => AttestedExecution::Failed,
        _ => return Err(HistoryError::Invalid),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::historia::Situation;

    #[test]
    fn inbox_sql_is_fixed_and_only_names_actionable_rows() {
        assert!(!INBOX_SQL.contains('$'));
        assert!(INBOX_SQL.contains("approved_pending_dispatch"));
        assert!(INBOX_SQL.contains("not_dispatched_reason IS NULL"));
        assert!(!INBOX_SQL.contains("allowed"));
        assert!(!INBOX_SQL.contains("denied"));
    }

    #[test]
    fn situation_sql_is_fixed_and_names_awaiting_approval_as_a_hold() {
        let pending = situation_sql(Situation::AwaitingApproval);
        assert!(pending.contains("requires_approval"));
        assert!(pending.contains("not_dispatched"));
        assert!(pending.contains("IS NULL"));
        assert!(
            situation_sql(Situation::ApprovedPendingExecution)
                .contains("approved_pending_dispatch")
        );
        assert!(situation_sql(Situation::Rejected).contains("approval_rejected"));
        assert!(situation_sql(Situation::Expired).contains("approved_claim_expired"));
        for situation in [
            Situation::Permitted,
            Situation::Denied,
            Situation::Approved,
            Situation::Rejected,
            Situation::Expired,
            Situation::AwaitingApproval,
            Situation::ApprovedPendingExecution,
            Situation::NotExecuted,
            Situation::Unreadable,
        ] {
            assert!(!situation_sql(situation).contains('$'));
        }
    }
}
