use postgres::{Client, Row};
use praetore_core::{
    AuthorizationCommitError, CompletedAuthorization, DecisionOutcome, Evidence, VerifiedPublicKey,
    canonical::canonicalize_json, replay::AtomicAuthorizationCommit,
};
use praetore_gateway::{
    AuthorizationStatus, ExecutionJournal, ExecutionKey, ExecutionRecord, ExecutionStatus,
    JournalError, action_digest,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Mutex;

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

        let claim_inserted = transaction
            .execute(
                "INSERT INTO praetore.replay_claims (agent_id, request_id) \
                 VALUES ($1, $2) ON CONFLICT (agent_id, request_id) DO NOTHING",
                &[&key.agent_id, &key.request_id],
            )
            .map_err(|_| AuthorizationCommitError::Unavailable)?;

        if claim_inserted == 0 {
            transaction
                .query_opt(
                    "SELECT 1 FROM praetore.replay_claims \
                     WHERE agent_id = $1 AND request_id = $2",
                    &[&key.agent_id, &key.request_id],
                )
                .map_err(|_| AuthorizationCommitError::Unavailable)?
                .ok_or(AuthorizationCommitError::Unavailable)?;
            let existing = transaction
                .query_opt(
                    "SELECT request_digest, action_digest, authorization_status, \
                     execution_status, evidence_json, output_json \
                     FROM praetore.execution_journal \
                     WHERE agent_id = $1 AND request_id = $2 FOR UPDATE",
                    &[&key.agent_id, &key.request_id],
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
                 WHERE agent_id = $1 AND request_id = $2 FOR UPDATE",
                &[&key.agent_id, &key.request_id],
            )
            .map_err(|_| AuthorizationCommitError::Unavailable)?;
        if existing.is_some() {
            return Err(AuthorizationCommitError::OrphanedReplayClaim);
        }

        transaction
            .execute(
                "INSERT INTO praetore.execution_journal \
                 (agent_id, request_id, request_digest, action_digest, authorization_status, \
                  execution_status, evidence_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
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
        let changed = transaction
            .execute(
                "UPDATE praetore.execution_journal \
                 SET execution_status = 'dispatched', updated_at = clock_timestamp() \
                 WHERE agent_id = $1 AND request_id = $2 \
                   AND authorization_status = 'allowed' AND execution_status = 'authorized'",
                &[&key.agent_id, &key.request_id],
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

    fn record_terminal(
        &self,
        key: ExecutionKey,
        execution: ExecutionStatus,
        output: Option<&Value>,
    ) -> Result<(), JournalError> {
        if !is_terminal(execution) {
            return Err(JournalError::InvalidTransition);
        }
        let output_json = output
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| JournalError::InvalidRecord)?;
        let mut client = self.client.lock().map_err(|_| JournalError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| JournalError::Unavailable)?;
        transaction
            .batch_execute("SET LOCAL synchronous_commit = on")
            .map_err(|_| JournalError::Unavailable)?;
        let row = transaction
            .query_opt(
                "SELECT execution_status, output_json FROM praetore.execution_journal \
                 WHERE agent_id = $1 AND request_id = $2 FOR UPDATE",
                &[&key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?
            .ok_or(JournalError::InvalidTransition)?;
        let current: String = row.get(0);
        let current_output: Option<String> = row.get(1);
        if is_terminal_db(&current) {
            let same_output = current_output.as_deref() == output_json.as_deref();
            let result = if current == execution_as_db(execution) && same_output {
                Ok(())
            } else {
                Err(JournalError::InvalidTransition)
            };
            transaction
                .commit()
                .map_err(|_| JournalError::Unavailable)?;
            return result;
        }
        if current != "dispatched" && current != "outcome_unknown" {
            return Err(JournalError::InvalidTransition);
        }
        transaction
            .execute(
                "UPDATE praetore.execution_journal \
                 SET execution_status = $3, output_json = $4, updated_at = clock_timestamp() \
                 WHERE agent_id = $1 AND request_id = $2",
                &[
                    &key.agent_id,
                    &key.request_id,
                    &execution_as_db(execution),
                    &output_json,
                ],
            )
            .map_err(|_| JournalError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| JournalError::Unavailable)?;
        Ok(())
    }

    fn get(&self, key: ExecutionKey) -> Result<Option<ExecutionRecord>, JournalError> {
        let mut client = self.client.lock().map_err(|_| JournalError::Unavailable)?;
        let row = client
            .query_opt(
                "SELECT request_digest, action_digest, authorization_status, execution_status, \
                 evidence_json, output_json FROM praetore.execution_journal \
                 WHERE agent_id = $1 AND request_id = $2",
                &[&key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?;
        row.map(|row| parse_record(key, row)).transpose()
    }

    fn mark_not_dispatched(&self, key: ExecutionKey) -> Result<(), JournalError> {
        self.transition_or_idempotent(key, "authorized", "not_dispatched", "not_dispatched", true)
    }

    fn mark_outcome_unknown(&self, key: ExecutionKey) -> Result<(), JournalError> {
        self.transition_or_idempotent(
            key,
            "dispatched",
            "outcome_unknown",
            "outcome_unknown",
            true,
        )
    }
}

impl PostgresExecutionJournal {
    fn transition_or_idempotent(
        &self,
        key: ExecutionKey,
        from: &str,
        to: &str,
        already: &str,
        allow_already: bool,
    ) -> Result<(), JournalError> {
        let mut client = self.client.lock().map_err(|_| JournalError::Unavailable)?;
        let mut transaction = client
            .transaction()
            .map_err(|_| JournalError::Unavailable)?;
        transaction
            .batch_execute("SET LOCAL synchronous_commit = on")
            .map_err(|_| JournalError::Unavailable)?;
        let row = transaction
            .query_opt(
                "SELECT execution_status FROM praetore.execution_journal \
                 WHERE agent_id = $1 AND request_id = $2 FOR UPDATE",
                &[&key.agent_id, &key.request_id],
            )
            .map_err(|_| JournalError::Unavailable)?
            .ok_or(JournalError::InvalidTransition)?;
        let current: String = row.get(0);
        let result = if current == from {
            transaction
                .execute(
                    "UPDATE praetore.execution_journal \
                     SET execution_status = $3, updated_at = clock_timestamp() \
                     WHERE agent_id = $1 AND request_id = $2",
                    &[&key.agent_id, &key.request_id, &to],
                )
                .map_err(|_| JournalError::Unavailable)?;
            Ok(())
        } else if allow_already && current == already {
            Ok(())
        } else {
            Err(JournalError::InvalidTransition)
        };
        transaction
            .commit()
            .map_err(|_| JournalError::Unavailable)?;
        result
    }
}

fn verify_authorization_pair(
    client: &mut Client,
    evidence: &Evidence,
    trusted_attester: &VerifiedPublicKey,
    key: ExecutionKey,
) -> Result<(), AuthorizationCommitError> {
    let replay_claim = client
        .query_opt(
            "SELECT 1 FROM praetore.replay_claims WHERE agent_id = $1 AND request_id = $2",
            &[&key.agent_id, &key.request_id],
        )
        .map_err(|_| AuthorizationCommitError::Unavailable)?;
    if replay_claim.is_none() {
        return Err(AuthorizationCommitError::NotFound);
    }
    let row = client
        .query_opt(
            "SELECT request_digest, action_digest, authorization_status, \
             execution_status, evidence_json, output_json \
             FROM praetore.execution_journal \
             WHERE agent_id = $1 AND request_id = $2",
            &[&key.agent_id, &key.request_id],
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
    Ok(())
}

fn validate_evidence(
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
        || evidence.decision.outcome != expected
        || evidence.evidence_schema_version != 2
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
    if evidence.evidence_schema_version != 2
        || evidence.evaluation_mode.as_deref() != Some("high_assurance")
        || evidence.policy_digest.is_none()
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

fn execution_digests(evidence: &Evidence) -> Result<(String, String), JournalError> {
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

fn parse_record(key: ExecutionKey, row: Row) -> Result<ExecutionRecord, JournalError> {
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
    validate_evidence(key, &evidence, authorization)?;
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
    })
}

fn is_digest(value: &str) -> bool {
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

fn authorization_as_db(status: AuthorizationStatus) -> &'static str {
    match status {
        AuthorizationStatus::Allowed => "allowed",
        AuthorizationStatus::RequiresApproval => "requires_approval",
        AuthorizationStatus::Denied => "denied",
    }
}

fn parse_authorization(value: &str) -> Result<AuthorizationStatus, JournalError> {
    match value {
        "allowed" => Ok(AuthorizationStatus::Allowed),
        "requires_approval" => Ok(AuthorizationStatus::RequiresApproval),
        "denied" => Ok(AuthorizationStatus::Denied),
        _ => Err(JournalError::InvalidRecord),
    }
}

fn execution_as_db(status: ExecutionStatus) -> &'static str {
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

fn parse_execution(value: &str) -> Result<ExecutionStatus, JournalError> {
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
