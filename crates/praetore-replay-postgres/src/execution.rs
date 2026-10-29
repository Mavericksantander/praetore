use postgres::{Client, Row};
use praetore_core::{
    AuthorizationCommitError, CompletedAuthorization, DecisionOutcome, Evidence, VerifiedPublicKey,
    canonical::canonicalize_json, replay::AtomicAuthorizationCommit,
};
use praetore_gateway::{
    ApprovalChallenge, ApprovalExpiredReceipt, AuthorizationStatus, ExecutionAttestation,
    ExecutionJournal, ExecutionKey, ExecutionRecord, ExecutionStatus, HumanApprovalDecision,
    HumanApprovalOutcome, JournalError, action_digest, authority_tenant_id,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use uuid::Uuid;

use crate::set_tenant_context;

const REQUEST_DIGEST_DOMAIN: &[u8] = b"PRAETORE_EXECUTION_REQUEST_V1\0";

/// PostgreSQL-backed durable gateway execution journal.
///
/// The atomic authorization path writes this journal row and its core replay
/// claim in one PostgreSQL transaction.
pub struct PostgresExecutionJournal {
    client: Mutex<Client>,
    recovery_client: std::sync::Arc<dyn Fn() -> Result<Client, postgres::Error> + Send + Sync>,
}

impl PostgresExecutionJournal {
    /// Creates a journal with a connection factory for verifying transactions
    /// whose commit acknowledgement was lost with the original connection.
    pub fn from_connection_factory(
        factory: impl Fn() -> Result<Client, postgres::Error> + Send + Sync + 'static,
    ) -> Result<Self, JournalError> {
        let factory = std::sync::Arc::new(factory);
        let client = factory().map_err(|_| JournalError::Unavailable)?;
        Ok(Self {
            client: Mutex::new(client),
            recovery_client: factory,
        })
    }
}

impl AtomicAuthorizationCommit for PostgresExecutionJournal {
    fn commit_authorization(
        &self,
        authorization: &CompletedAuthorization,
        trusted_attester: &VerifiedPublicKey,
    ) -> Result<(), AuthorizationCommitError> {
        let evidence = authorization.evidence();
        validate_atomic_evidence(evidence, trusted_attester)?;
        let key = ExecutionKey {
            tenant_id: authority_tenant_id(&evidence.authority)
                .ok_or(AuthorizationCommitError::InvalidRecord)?,
            agent_id: *evidence.agent.id.as_uuid(),
            request_id: evidence.request_id,
        };
        let authorization = authorization_from_evidence(evidence)?;
        let initial_status = if authorization == AuthorizationStatus::Allowed {
            "authorized"
        } else {
            "not_dispatched"
        };
        let evidence_json = evidence
            .to_json()
            .map_err(|_| AuthorizationCommitError::InvalidRecord)?;
        let (request_digest, action_digest) =
            execution_digests(evidence).map_err(|_| AuthorizationCommitError::InvalidRecord)?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| AuthorizationCommitError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| AuthorizationCommitError::Unavailable)?;
        transaction
            .batch_execute("SET LOCAL synchronous_commit = on")
            .map_err(|_| AuthorizationCommitError::Unavailable)?;

        set_tenant_context(&mut transaction, Uuid::nil())
            .map_err(|_| AuthorizationCommitError::Unavailable)?;
        let legacy_claim = transaction
            .query_opt(
                "SELECT 1 FROM praetore.replay_claims \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&Uuid::nil(), &key.agent_id, &key.request_id],
            )
            .map_err(|_| AuthorizationCommitError::Unavailable)?;
        if legacy_claim.is_some() {
            return Err(AuthorizationCommitError::OrphanedReplayClaim);
        }

        set_tenant_context(&mut transaction, key.tenant_id)
            .map_err(|_| AuthorizationCommitError::Unavailable)?;
        let claim_inserted = transaction
            .execute(
                "INSERT INTO praetore.replay_claims (tenant_id, agent_id, request_id) \
                 VALUES ($1, $2, $3) ON CONFLICT (tenant_id, agent_id, request_id) DO NOTHING",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| AuthorizationCommitError::Unavailable)?;

        if claim_inserted == 0 {
            transaction
                .query_opt(
                    "SELECT 1 FROM praetore.replay_claims \
                     WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                    &[&key.tenant_id, &key.agent_id, &key.request_id],
                )
                .map_err(|_| AuthorizationCommitError::Unavailable)?
                .ok_or(AuthorizationCommitError::Unavailable)?;
            let existing = transaction
                .query_opt(
                    "SELECT request_digest, action_digest, authorization_status, \
                     execution_status, evidence_json, output_json, \
                     (SELECT attestation_json FROM praetore.execution_attestations ea \
                      WHERE ea.tenant_id = execution_journal.tenant_id \
                        AND ea.agent_id = execution_journal.agent_id \
                        AND ea.request_id = execution_journal.request_id \
                        AND ea.execution_status = execution_journal.execution_status), \
                     (SELECT decision_json FROM praetore.human_approvals ha \
                      WHERE ha.tenant_id = execution_journal.tenant_id \
                        AND ha.agent_id = execution_journal.agent_id \
                        AND ha.request_id = execution_journal.request_id), \
                     (SELECT receipt_json FROM praetore.human_approval_expirations hx \
                      WHERE hx.tenant_id = execution_journal.tenant_id \
                        AND hx.agent_id = execution_journal.agent_id \
                        AND hx.request_id = execution_journal.request_id) \
                     FROM praetore.execution_journal \
                     WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3 FOR UPDATE",
                    &[&key.tenant_id, &key.agent_id, &key.request_id],
                )
                .map_err(|_| AuthorizationCommitError::Unavailable)?;
            let Some(existing) = existing else {
                return Err(AuthorizationCommitError::OrphanedReplayClaim);
            };
            let record =
                parse_record(key, existing).map_err(|_| AuthorizationCommitError::InvalidRecord)?;
            record
                .evidence
                .verify_attester_signature(trusted_attester)
                .map_err(|_| AuthorizationCommitError::InvalidRecord)?;
            transaction
                .commit()
                .map_err(|_| AuthorizationCommitError::Unavailable)?;
            return if record.action_digest != action_digest
                || record.authorization != authorization
                || request_digest_for_evidence(&record.evidence)
                    .map_err(|_| AuthorizationCommitError::InvalidRecord)?
                    != request_digest
            {
                Err(AuthorizationCommitError::ConflictingRequest)
            } else {
                Err(AuthorizationCommitError::AlreadyCommitted)
            };
        }

        let existing = transaction
            .query_opt(
                "SELECT 1 FROM praetore.execution_journal \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3 FOR UPDATE",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| AuthorizationCommitError::Unavailable)?;
        if existing.is_some() {
            return Err(AuthorizationCommitError::OrphanedReplayClaim);
        }

        transaction
            .execute(
                "INSERT INTO praetore.execution_journal \
                 (tenant_id, agent_id, request_id, request_digest, action_digest, \
                  authorization_status, execution_status, evidence_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &key.tenant_id,
                    &key.agent_id,
                    &key.request_id,
                    &request_digest,
                    &action_digest,
                    &authorization_as_db(authorization),
                    &initial_status,
                    &evidence_json,
                ],
            )
            .map_err(|_| AuthorizationCommitError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| AuthorizationCommitError::Unavailable)?;
        Ok(())
    }

    fn verify_committed_authorization(
        &self,
        authorization: &CompletedAuthorization,
        trusted_attester: &VerifiedPublicKey,
    ) -> Result<(), AuthorizationCommitError> {
        let evidence = authorization.evidence();
        validate_atomic_evidence(evidence, trusted_attester)?;
        let key = ExecutionKey {
            tenant_id: authority_tenant_id(&evidence.authority)
                .ok_or(AuthorizationCommitError::InvalidRecord)?,
            agent_id: *evidence.agent.id.as_uuid(),
            request_id: evidence.request_id,
        };
        let mut client = self
            .client
            .lock()
            .map_err(|_| AuthorizationCommitError::Unavailable)?;
        match verify_authorization_pair(&mut client, evidence, trusted_attester, key) {
            Err(AuthorizationCommitError::Unavailable) => {
                let mut recovery_client =
                    (self.recovery_client)().map_err(|_| AuthorizationCommitError::Unavailable)?;
                verify_authorization_pair(&mut recovery_client, evidence, trusted_attester, key)
            }
            result => result,
        }
    }
}

impl ExecutionJournal for PostgresExecutionJournal {
    fn mark_dispatched(&self, key: ExecutionKey) -> Result<(), JournalError> {
        let mut client = self.client.lock().map_err(|_| JournalError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| JournalError::Unavailable)?;
        transaction
            .batch_execute("SET LOCAL synchronous_commit = on")
            .map_err(|_| JournalError::Unavailable)?;
        set_tenant_context(&mut transaction, key.tenant_id)
            .map_err(|_| JournalError::Unavailable)?;
        let changed = transaction
            .execute(
                "UPDATE praetore.execution_journal \
                 SET execution_status = 'dispatched', updated_at = clock_timestamp() \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3 \
                   AND authorization_status = 'allowed' AND execution_status = 'authorized'",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| JournalError::Unavailable)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(JournalError::InvalidTransition)
        }
    }

    fn record_human_approval(
        &self,
        key: ExecutionKey,
        decision: &HumanApprovalDecision,
    ) -> Result<(), JournalError> {
        let decision_json =
            serde_json::to_value(decision).map_err(|_| JournalError::InvalidRecord)?;
        let expires_at = time::OffsetDateTime::parse(
            &decision.challenge.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| JournalError::InvalidRecord)?;
        let mut client = self.client.lock().map_err(|_| JournalError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| JournalError::Unavailable)?;
        transaction
            .batch_execute("SET LOCAL synchronous_commit = on")
            .map_err(|_| JournalError::Unavailable)?;
        set_tenant_context(&mut transaction, key.tenant_id)
            .map_err(|_| JournalError::Unavailable)?;
        let row = transaction
            .query_opt(
                "SELECT authorization_status, execution_status, evidence_json, action_digest \
                     FROM praetore.execution_journal \
                     WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3 FOR UPDATE",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?
            .ok_or(JournalError::InvalidTransition)?;
        let authorization = parse_authorization(&row.get::<_, String>(0))?;
        let execution = parse_execution(&row.get::<_, String>(1))?;
        let evidence = Evidence::from_json(&row.get::<_, String>(2))
            .map_err(|_| JournalError::InvalidRecord)?;
        let stored_action_digest: String = row.get(3);
        if transaction
            .query_opt(
                "SELECT 1 FROM praetore.human_approval_expirations \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?
            .is_some()
        {
            return Err(JournalError::ApprovalAlreadyRecorded);
        }
        if authorization != AuthorizationStatus::RequiresApproval
            || execution != ExecutionStatus::NotDispatched
            || decision.challenge.tenant_id != key.tenant_id
            || decision.challenge.agent_id != key.agent_id
            || decision.challenge.request_id != key.request_id
            || decision.challenge.action_digest != stored_action_digest
            || ApprovalChallenge::from_evidence(&evidence, &stored_action_digest)
                .map_err(|_| JournalError::InvalidRecord)?
                != decision.challenge
            || expires_at <= time::OffsetDateTime::now_utc()
        {
            return Err(JournalError::InvalidRecord);
        }

        transaction
            .execute(
                "INSERT INTO praetore.human_approvals \
                     (approval_id, tenant_id, agent_id, request_id, evidence_id, evidence_hash, \
                      action_digest, policy_digest, outcome, approver_key_id, expires_at, \
                      decision_json) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                &[
                    &decision.approval_id,
                    &key.tenant_id,
                    &key.agent_id,
                    &key.request_id,
                    &decision.challenge.evidence_id,
                    &decision.challenge.evidence_hash,
                    &decision.challenge.action_digest,
                    &decision.challenge.policy_digest,
                    &approval_outcome_as_db(decision.outcome),
                    &decision.approver_key_id,
                    &expires_at,
                    &decision_json,
                ],
            )
            .map_err(|error| {
                if error.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                    JournalError::ApprovalAlreadyRecorded
                } else {
                    JournalError::Unavailable
                }
            })?;

        if decision.outcome == HumanApprovalOutcome::Approve {
            let changed = transaction
                .execute(
                    "UPDATE praetore.execution_journal \
                         SET execution_status = 'dispatched', updated_at = clock_timestamp() \
                         WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3 \
                           AND authorization_status = 'requires_approval' \
                           AND execution_status = 'not_dispatched'",
                    &[&key.tenant_id, &key.agent_id, &key.request_id],
                )
                .map_err(|_| JournalError::Unavailable)?;
            if changed != 1 {
                return Err(JournalError::InvalidTransition);
            }
        }
        transaction
            .commit()
            .map_err(|_| JournalError::Unavailable)?;
        Ok(())
    }

    fn record_approval_expiration(
        &self,
        key: ExecutionKey,
        receipt: &ApprovalExpiredReceipt,
    ) -> Result<(), JournalError> {
        if receipt.key() != key {
            return Err(JournalError::InvalidRecord);
        }
        let receipt_json =
            serde_json::to_value(receipt).map_err(|_| JournalError::InvalidRecord)?;
        let rfc3339 = &time::format_description::well_known::Rfc3339;
        let expires_at = time::OffsetDateTime::parse(&receipt.expires_at, rfc3339)
            .map_err(|_| JournalError::InvalidRecord)?;
        let observed_at = time::OffsetDateTime::parse(&receipt.observed_at, rfc3339)
            .map_err(|_| JournalError::InvalidRecord)?;
        let mut client = self.client.lock().map_err(|_| JournalError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| JournalError::Unavailable)?;
        transaction
            .batch_execute("SET LOCAL synchronous_commit = on")
            .map_err(|_| JournalError::Unavailable)?;
        set_tenant_context(&mut transaction, key.tenant_id)
            .map_err(|_| JournalError::Unavailable)?;
        let row = transaction
            .query_opt(
                "SELECT authorization_status, execution_status, evidence_json \
                 FROM praetore.execution_journal \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3 FOR UPDATE",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?
            .ok_or(JournalError::InvalidTransition)?;
        let authorization = parse_authorization(&row.get::<_, String>(0))?;
        let execution = parse_execution(&row.get::<_, String>(1))?;
        let evidence = Evidence::from_json(&row.get::<_, String>(2))
            .map_err(|_| JournalError::InvalidRecord)?;
        // Read the resolution state in a separate statement, after the row
        // lock is held: under READ COMMITTED a subquery in the locking
        // statement keeps the snapshot taken before waiting for the lock,
        // so a concurrent expiration committed meanwhile would be missed.
        let resolution = transaction
            .query_one(
                "SELECT \
                 EXISTS (SELECT 1 FROM praetore.human_approvals \
                         WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3), \
                 EXISTS (SELECT 1 FROM praetore.human_approval_expirations \
                         WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3)",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?;
        let decided: bool = resolution.get(0);
        let expired: bool = resolution.get(1);
        if decided {
            return Err(JournalError::ApprovalAlreadyRecorded);
        }
        if expired {
            // Idempotent: the first receipt is kept unchanged.
            return transaction.commit().map_err(|_| JournalError::Unavailable);
        }
        if authorization != AuthorizationStatus::RequiresApproval
            || execution != ExecutionStatus::NotDispatched
            || receipt.validate_binding(&evidence).is_err()
        {
            return Err(JournalError::InvalidRecord);
        }
        transaction
            .execute(
                "INSERT INTO praetore.human_approval_expirations \
                     (tenant_id, agent_id, request_id, evidence_id, evidence_hash, \
                      action_digest, policy_digest, expires_at, observed_at, \
                      gateway_key_id, signature, receipt_json, receipt_id) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
                &[
                    &key.tenant_id,
                    &key.agent_id,
                    &key.request_id,
                    &receipt.evidence_id,
                    &receipt.evidence_hash,
                    &receipt.action_digest,
                    &receipt.policy_digest,
                    &expires_at,
                    &observed_at,
                    &receipt.gateway_key_id,
                    &receipt.signature,
                    &receipt_json,
                    &receipt.receipt_id,
                ],
            )
            .map_err(|_| JournalError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| JournalError::Unavailable)?;
        Ok(())
    }

    fn record_terminal_attested(
        &self,
        key: ExecutionKey,
        execution: ExecutionStatus,
        output: Option<&Value>,
        attestation: &ExecutionAttestation,
    ) -> Result<(), JournalError> {
        if !is_terminal(execution) {
            return Err(JournalError::InvalidTransition);
        }
        let output_json = output
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| JournalError::InvalidRecord)?;
        let attestation_json =
            serialize_attestation(attestation).map_err(|_| JournalError::InvalidRecord)?;
        let mut client = self.client.lock().map_err(|_| JournalError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| JournalError::Unavailable)?;
        transaction
            .batch_execute("SET LOCAL synchronous_commit = on")
            .map_err(|_| JournalError::Unavailable)?;
        set_tenant_context(&mut transaction, key.tenant_id)
            .map_err(|_| JournalError::Unavailable)?;
        let row = transaction
            .query_opt(
                "SELECT execution_status, output_json, evidence_json, authorization_status \
                 FROM praetore.execution_journal \
                WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3 FOR UPDATE",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?
            .ok_or(JournalError::InvalidTransition)?;
        let current: String = row.get(0);
        let current_output: Option<String> = row.get(1);
        let evidence: String = row.get(2);
        let authorization = super::execution::parse_authorization(&row.get::<_, String>(3))?;
        let evidence = Evidence::from_json(&evidence).map_err(|_| JournalError::InvalidRecord)?;
        attestation
            .validate_binding(&evidence, authorization, execution, output)
            .map_err(|_| JournalError::InvalidRecord)?;
        if current == execution_as_db(execution) {
            let same_output = current_output.as_deref() == output_json.as_deref();
            let stored = transaction
                .query_opt(
                    "SELECT attestation_json FROM praetore.execution_attestations \
                     WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3 \
                       AND execution_status = $4",
                    &[
                        &key.tenant_id,
                        &key.agent_id,
                        &key.request_id,
                        &execution_as_db(execution),
                    ],
                )
                .map_err(|_| JournalError::Unavailable)?;
            let same_attestation = stored.map(|row| row.get::<_, Value>(0) == attestation_json);
            let result = if same_output && same_attestation == Some(true) {
                Ok(())
            } else {
                Err(JournalError::InvalidTransition)
            };
            transaction
                .commit()
                .map_err(|_| JournalError::Unavailable)?;
            return result;
        }
        if is_terminal_db(&current) {
            return Err(JournalError::InvalidTransition);
        }
        if current != "dispatched" && current != "outcome_unknown" {
            return Err(JournalError::InvalidTransition);
        }
        transaction
            .execute(
                "UPDATE praetore.execution_journal \
                 SET execution_status = $4, output_json = $5, updated_at = clock_timestamp() \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[
                    &key.tenant_id,
                    &key.agent_id,
                    &key.request_id,
                    &execution_as_db(execution),
                    &output_json,
                ],
            )
            .map_err(|_| JournalError::Unavailable)?;
        insert_execution_attestation(&mut transaction, key, execution, &attestation_json)?;
        transaction
            .commit()
            .map_err(|_| JournalError::Unavailable)?;
        Ok(())
    }

    fn record_attestation(
        &self,
        key: ExecutionKey,
        execution: ExecutionStatus,
        output: Option<&Value>,
        attestation: &ExecutionAttestation,
    ) -> Result<(), JournalError> {
        let attestation_json =
            serialize_attestation(attestation).map_err(|_| JournalError::InvalidRecord)?;
        let mut client = self.client.lock().map_err(|_| JournalError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| JournalError::Unavailable)?;
        transaction
            .batch_execute("SET LOCAL synchronous_commit = on")
            .map_err(|_| JournalError::Unavailable)?;
        set_tenant_context(&mut transaction, key.tenant_id)
            .map_err(|_| JournalError::Unavailable)?;
        let row = transaction
            .query_opt(
                "SELECT execution_status, output_json, evidence_json, authorization_status \
                 FROM praetore.execution_journal \
                WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3 FOR UPDATE",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?
            .ok_or(JournalError::InvalidTransition)?;
        let current: String = row.get(0);
        let output_json: Option<String> = row.get(1);
        let expected_output_json = output
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| JournalError::InvalidRecord)?;
        if current != execution_as_db(execution) || output_json != expected_output_json {
            return Err(JournalError::InvalidTransition);
        }
        let evidence_json: String = row.get(2);
        let authorization = super::execution::parse_authorization(&row.get::<_, String>(3))?;
        let evidence =
            Evidence::from_json(&evidence_json).map_err(|_| JournalError::InvalidRecord)?;
        if !matches!(execution, ExecutionStatus::NotDispatched) && !is_terminal(execution) {
            return Err(JournalError::InvalidTransition);
        }
        attestation
            .validate_binding(&evidence, authorization, execution, output)
            .map_err(|_| JournalError::InvalidRecord)?;
        if let Some(existing) = transaction
            .query_opt(
                "SELECT attestation_json FROM praetore.execution_attestations \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3 \
                   AND execution_status = $4",
                &[
                    &key.tenant_id,
                    &key.agent_id,
                    &key.request_id,
                    &execution_as_db(execution),
                ],
            )
            .map_err(|_| JournalError::Unavailable)?
        {
            let result = if existing.get::<_, Value>(0) == attestation_json {
                Ok(())
            } else {
                Err(JournalError::InvalidTransition)
            };
            transaction
                .commit()
                .map_err(|_| JournalError::Unavailable)?;
            return result;
        }
        insert_execution_attestation(&mut transaction, key, execution, &attestation_json)?;
        transaction
            .commit()
            .map_err(|_| JournalError::Unavailable)?;
        Ok(())
    }

    fn get(&self, key: ExecutionKey) -> Result<Option<ExecutionRecord>, JournalError> {
        let mut client = self.client.lock().map_err(|_| JournalError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| JournalError::Unavailable)?;
        set_tenant_context(&mut transaction, key.tenant_id)
            .map_err(|_| JournalError::Unavailable)?;
        let row = transaction
            .query_opt(
                "SELECT request_digest, action_digest, authorization_status, execution_status, \
                 evidence_json, output_json, \
                 (SELECT attestation_json FROM praetore.execution_attestations ea \
                  WHERE ea.tenant_id = execution_journal.tenant_id \
                    AND ea.agent_id = execution_journal.agent_id \
                    AND ea.request_id = execution_journal.request_id \
                    AND ea.execution_status = execution_journal.execution_status), \
                 (SELECT decision_json FROM praetore.human_approvals ha \
                  WHERE ha.tenant_id = execution_journal.tenant_id \
                    AND ha.agent_id = execution_journal.agent_id \
                    AND ha.request_id = execution_journal.request_id), \
                 (SELECT receipt_json FROM praetore.human_approval_expirations hx \
                  WHERE hx.tenant_id = execution_journal.tenant_id \
                    AND hx.agent_id = execution_journal.agent_id \
                    AND hx.request_id = execution_journal.request_id) \
                 FROM praetore.execution_journal \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?;
        let record = row.map(|row| parse_record(key, row)).transpose()?;
        transaction
            .commit()
            .map_err(|_| JournalError::Unavailable)?;
        Ok(record)
    }

    fn mark_not_dispatched_attested(
        &self,
        key: ExecutionKey,
        attestation: &ExecutionAttestation,
    ) -> Result<(), JournalError> {
        let attestation_json =
            serialize_attestation(attestation).map_err(|_| JournalError::InvalidRecord)?;
        let mut client = self.client.lock().map_err(|_| JournalError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| JournalError::Unavailable)?;
        transaction
            .batch_execute("SET LOCAL synchronous_commit = on")
            .map_err(|_| JournalError::Unavailable)?;
        set_tenant_context(&mut transaction, key.tenant_id)
            .map_err(|_| JournalError::Unavailable)?;
        let row = transaction
            .query_opt(
                "SELECT execution_status, evidence_json, authorization_status \
                 FROM praetore.execution_journal \
                WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3 FOR UPDATE",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?
            .ok_or(JournalError::InvalidTransition)?;
        let current: String = row.get(0);
        let evidence_json: String = row.get(1);
        let authorization = parse_authorization(&row.get::<_, String>(2))?;
        let evidence =
            Evidence::from_json(&evidence_json).map_err(|_| JournalError::InvalidRecord)?;
        if authorization != AuthorizationStatus::Allowed {
            return Err(JournalError::InvalidTransition);
        }
        attestation
            .validate_binding(
                &evidence,
                authorization,
                ExecutionStatus::NotDispatched,
                None,
            )
            .map_err(|_| JournalError::InvalidRecord)?;

        if current == "not_dispatched" {
            let existing = transaction
                .query_opt(
                    "SELECT attestation_json FROM praetore.execution_attestations \
                     WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3 \
                       AND execution_status = 'not_dispatched'",
                    &[&key.tenant_id, &key.agent_id, &key.request_id],
                )
                .map_err(|_| JournalError::Unavailable)?;
            let result =
                if existing.map(|row| row.get::<_, Value>(0)) == Some(attestation_json.clone()) {
                    Ok(())
                } else {
                    Err(JournalError::InvalidTransition)
                };
            transaction
                .commit()
                .map_err(|_| JournalError::Unavailable)?;
            return result;
        }
        if current != "authorized" {
            return Err(JournalError::InvalidTransition);
        }
        transaction
            .execute(
                "UPDATE praetore.execution_journal \
                 SET execution_status = 'not_dispatched', updated_at = clock_timestamp() \
                 WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
                &[&key.tenant_id, &key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?;
        insert_execution_attestation(
            &mut transaction,
            key,
            ExecutionStatus::NotDispatched,
            &attestation_json,
        )?;
        transaction
            .commit()
            .map_err(|_| JournalError::Unavailable)?;
        Ok(())
    }
}

fn verify_authorization_pair(
    client: &mut Client,
    evidence: &Evidence,
    trusted_attester: &VerifiedPublicKey,
    key: ExecutionKey,
) -> Result<(), AuthorizationCommitError> {
    let mut transaction = client
        .transaction()
        .map_err(|_| AuthorizationCommitError::Unavailable)?;
    set_tenant_context(&mut transaction, key.tenant_id)
        .map_err(|_| AuthorizationCommitError::Unavailable)?;
    let replay_claim = transaction
        .query_opt(
            "SELECT 1 FROM praetore.replay_claims \
             WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
            &[&key.tenant_id, &key.agent_id, &key.request_id],
        )
        .map_err(|_| AuthorizationCommitError::Unavailable)?;
    if replay_claim.is_none() {
        return Err(AuthorizationCommitError::NotFound);
    }
    let row = transaction
        .query_opt(
            "SELECT request_digest, action_digest, authorization_status, \
             execution_status, evidence_json, output_json, \
             (SELECT attestation_json FROM praetore.execution_attestations ea \
              WHERE ea.tenant_id = execution_journal.tenant_id \
                AND ea.agent_id = execution_journal.agent_id \
                AND ea.request_id = execution_journal.request_id \
                AND ea.execution_status = execution_journal.execution_status), \
             (SELECT decision_json FROM praetore.human_approvals ha \
              WHERE ha.tenant_id = execution_journal.tenant_id \
                AND ha.agent_id = execution_journal.agent_id \
                AND ha.request_id = execution_journal.request_id), \
             (SELECT receipt_json FROM praetore.human_approval_expirations hx \
              WHERE hx.tenant_id = execution_journal.tenant_id \
                AND hx.agent_id = execution_journal.agent_id \
                AND hx.request_id = execution_journal.request_id) \
             FROM praetore.execution_journal \
             WHERE tenant_id = $1 AND agent_id = $2 AND request_id = $3",
            &[&key.tenant_id, &key.agent_id, &key.request_id],
        )
        .map_err(|_| AuthorizationCommitError::Unavailable)?
        .ok_or(AuthorizationCommitError::OrphanedReplayClaim)?;
    let record = parse_record(key, row).map_err(|_| AuthorizationCommitError::InvalidRecord)?;
    record
        .evidence
        .verify_attester_signature(trusted_attester)
        .map_err(|_| AuthorizationCommitError::InvalidRecord)?;

    let expected_status = if record.authorization == AuthorizationStatus::Allowed {
        ExecutionStatus::Authorized
    } else {
        ExecutionStatus::NotDispatched
    };
    let expected_authorization = authorization_from_evidence(evidence)?;
    if record.execution != expected_status
        || record.authorization != expected_authorization
        || record.action_digest
            != action_digest(&evidence.action)
                .map_err(|_| AuthorizationCommitError::InvalidRecord)?
        || canonical_evidence(&record.evidence)? != canonical_evidence(evidence)?
    {
        return Err(AuthorizationCommitError::InvalidRecord);
    }
    transaction
        .commit()
        .map_err(|_| AuthorizationCommitError::Unavailable)?;
    Ok(())
}

pub(super) fn validate_evidence(
    key: ExecutionKey,
    evidence: &Evidence,
    authorization: AuthorizationStatus,
) -> Result<(), JournalError> {
    let expected = match authorization {
        AuthorizationStatus::Allowed => DecisionOutcome::Allow,
        AuthorizationStatus::RequiresApproval => DecisionOutcome::RequireApproval,
        AuthorizationStatus::Denied => DecisionOutcome::Deny,
    };
    if key.agent_id != *evidence.agent.id.as_uuid()
        || key.request_id != evidence.request_id
        || Some(key.tenant_id) != authority_tenant_id(&evidence.authority)
        || evidence.decision.outcome != expected
        || !evidence.is_high_assurance_shape()
        || evidence.evaluation_mode.as_deref() != Some("high_assurance")
        || !evidence.verify_integrity()
    {
        return Err(JournalError::InvalidRecord);
    }
    Ok(())
}

fn validate_atomic_evidence(
    evidence: &Evidence,
    trusted_attester: &VerifiedPublicKey,
) -> Result<(), AuthorizationCommitError> {
    if !evidence.is_high_assurance_shape()
        || evidence.evaluation_mode.as_deref() != Some("high_assurance")
        || evidence.policy_digest.is_none()
        || authority_tenant_id(&evidence.authority).is_none()
        || !evidence.verify_integrity()
    {
        return Err(AuthorizationCommitError::InvalidRecord);
    }
    evidence
        .verify_attester_signature(trusted_attester)
        .map_err(|_| AuthorizationCommitError::InvalidRecord)
}

fn authorization_from_evidence(
    evidence: &Evidence,
) -> Result<AuthorizationStatus, AuthorizationCommitError> {
    match evidence.decision.outcome {
        DecisionOutcome::Allow => Ok(AuthorizationStatus::Allowed),
        DecisionOutcome::RequireApproval => Ok(AuthorizationStatus::RequiresApproval),
        DecisionOutcome::Deny => Ok(AuthorizationStatus::Denied),
    }
}

pub(super) fn execution_digests(evidence: &Evidence) -> Result<(String, String), JournalError> {
    let action_digest = action_digest(&evidence.action).map_err(|_| JournalError::InvalidRecord)?;

    Ok((request_digest_for_evidence(evidence)?, action_digest))
}

fn request_digest_for_evidence(evidence: &Evidence) -> Result<String, JournalError> {
    let request_value = serde_json::json!({
        "request_id": evidence.request_id,
        "agent": evidence.agent,
        "authority": evidence.authority,
        "action": evidence.action,
        "trace_id": evidence.trace_id,
        "context": evidence.context,
        "agent_signature": evidence.agent_signature,
        "intent_v2": evidence.intent_v2,
    });
    let request_json =
        serde_json::to_string(&request_value).map_err(|_| JournalError::InvalidRecord)?;
    let canonical_request =
        canonicalize_json(&request_json).map_err(|_| JournalError::InvalidRecord)?;

    Ok(digest(REQUEST_DIGEST_DOMAIN, &canonical_request))
}

fn canonical_evidence(evidence: &Evidence) -> Result<Vec<u8>, AuthorizationCommitError> {
    let json = evidence
        .to_json()
        .map_err(|_| AuthorizationCommitError::InvalidRecord)?;
    canonicalize_json(&json).map_err(|_| AuthorizationCommitError::InvalidRecord)
}

fn digest(domain: &[u8], canonical: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(canonical);
    hex::encode(hash.finalize())
}

pub(super) fn parse_record(key: ExecutionKey, row: Row) -> Result<ExecutionRecord, JournalError> {
    let request_digest: String = row.get(0);
    let action_digest: String = row.get(1);
    if !is_digest(&request_digest) || !is_digest(&action_digest) {
        return Err(JournalError::InvalidRecord);
    }
    let authorization = parse_authorization(&row.get::<_, String>(2))?;
    let execution = parse_execution(&row.get::<_, String>(3))?;
    let evidence_json: String = row.get(4);
    let evidence = Evidence::from_json(&evidence_json).map_err(|_| JournalError::InvalidRecord)?;
    let output_json: Option<String> = row.get(5);
    let output = output_json
        .map(|json| serde_json::from_str(&json).map_err(|_| JournalError::InvalidRecord))
        .transpose()?;
    let execution_attestation = row
        .get::<_, Option<Value>>(6)
        .map(|value| serde_json::from_value(value).map_err(|_| JournalError::InvalidRecord))
        .transpose()?;
    let human_approval = row
        .get::<_, Option<Value>>(7)
        .map(|value| serde_json::from_value(value).map_err(|_| JournalError::InvalidRecord))
        .transpose()?;
    let approval_expiration: Option<ApprovalExpiredReceipt> = row
        .get::<_, Option<Value>>(8)
        .map(|value| serde_json::from_value(value).map_err(|_| JournalError::InvalidRecord))
        .transpose()?;
    validate_evidence(key, &evidence, authorization)?;
    if let Some(receipt) = &approval_expiration
        && (human_approval.is_some()
            || receipt.key() != key
            || receipt.validate_binding(&evidence).is_err())
    {
        return Err(JournalError::InvalidRecord);
    }
    let (expected_request_digest, expected_action_digest) = execution_digests(&evidence)?;
    if expected_request_digest != request_digest || expected_action_digest != action_digest {
        return Err(JournalError::InvalidRecord);
    }
    Ok(ExecutionRecord {
        key,
        evidence,
        authorization,
        execution,
        action_digest,
        output,
        execution_attestation,
        human_approval,
        approval_expiration,
    })
}

fn approval_outcome_as_db(outcome: HumanApprovalOutcome) -> &'static str {
    match outcome {
        HumanApprovalOutcome::Approve => "approve",
        HumanApprovalOutcome::Reject => "reject",
    }
}

fn serialize_attestation(attestation: &ExecutionAttestation) -> Result<Value, JournalError> {
    serde_json::to_value(attestation).map_err(|_| JournalError::InvalidRecord)
}

fn insert_execution_attestation(
    transaction: &mut postgres::Transaction<'_>,
    key: ExecutionKey,
    execution: ExecutionStatus,
    attestation: &Value,
) -> Result<(), JournalError> {
    transaction
        .execute(
            "INSERT INTO praetore.execution_attestations \
             (attestation_id, tenant_id, agent_id, request_id, execution_status, \
              attestation_json) \
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &uuid::Uuid::new_v4(),
                &key.tenant_id,
                &key.agent_id,
                &key.request_id,
                &execution_as_db(execution),
                attestation,
            ],
        )
        .map_err(|error| {
            if error.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                JournalError::InvalidTransition
            } else {
                JournalError::Unavailable
            }
        })?;
    Ok(())
}

pub(super) fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_terminal(status: ExecutionStatus) -> bool {
    matches!(
        status,
        ExecutionStatus::Executed
            | ExecutionStatus::Confirmed
            | ExecutionStatus::OutcomeUnknown
            | ExecutionStatus::Failed
    )
}

fn is_terminal_db(status: &str) -> bool {
    matches!(status, "executed" | "confirmed" | "failed")
}

pub(super) fn authorization_as_db(status: AuthorizationStatus) -> &'static str {
    match status {
        AuthorizationStatus::Allowed => "allowed",
        AuthorizationStatus::RequiresApproval => "requires_approval",
        AuthorizationStatus::Denied => "denied",
    }
}

pub(super) fn parse_authorization(value: &str) -> Result<AuthorizationStatus, JournalError> {
    match value {
        "allowed" => Ok(AuthorizationStatus::Allowed),
        "requires_approval" => Ok(AuthorizationStatus::RequiresApproval),
        "denied" => Ok(AuthorizationStatus::Denied),
        _ => Err(JournalError::InvalidRecord),
    }
}

pub(super) fn execution_as_db(status: ExecutionStatus) -> &'static str {
    match status {
        ExecutionStatus::NotDispatched => "not_dispatched",
        ExecutionStatus::Authorized => "authorized",
        ExecutionStatus::Dispatched => "dispatched",
        ExecutionStatus::Executed => "executed",
        ExecutionStatus::Confirmed => "confirmed",
        ExecutionStatus::OutcomeUnknown => "outcome_unknown",
        ExecutionStatus::Failed => "failed",
    }
}

pub(super) fn parse_execution(value: &str) -> Result<ExecutionStatus, JournalError> {
    match value {
        "not_dispatched" => Ok(ExecutionStatus::NotDispatched),
        "authorized" => Ok(ExecutionStatus::Authorized),
        "dispatched" => Ok(ExecutionStatus::Dispatched),
        "executed" => Ok(ExecutionStatus::Executed),
        "confirmed" => Ok(ExecutionStatus::Confirmed),
        "outcome_unknown" => Ok(ExecutionStatus::OutcomeUnknown),
        "failed" => Ok(ExecutionStatus::Failed),
        _ => Err(JournalError::InvalidRecord),
    }
}
