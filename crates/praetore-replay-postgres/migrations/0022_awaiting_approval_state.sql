-- A held approval is signed in its own state, `awaiting_approval`, and an
-- approved execution claimed too late is closed with its own reason,
-- `approved_claim_expired` (T-016).
--
-- Until 0022 the 202 receipt of a held (requires_approval) request was a
-- signed `not_dispatched` attestation without a reason: the same shape a
-- verifier would read as "closed without dispatch", although the request
-- could still be approved and executed. Now:
--   * execution_attestations.execution_status admits `awaiting_approval`
--     (schema v5). It is never a journal state: the journal row of a held
--     request stays `not_dispatched` with a NULL reason. An `awaiting_approval`
--     attestation is accepted only while the row is in that held shape, with
--     no human decision and no expiration receipt;
--   * `approved_claim_expired` closes `approved_pending_dispatch` ->
--     `not_dispatched` when an approved execution is claimed after its
--     window. `approval_expired` now means only "the window closed without
--     a decision": it is refused on a new close of `approved_pending_dispatch`.
--
-- No row is rewritten. Attestations and closes written before 0022 (a held
-- request's v2 `not_dispatched` attestation, an `approved_pending_dispatch`
-- row closed as `approval_expired`) stay as they were. A held row written
-- before 0022 gets an `awaiting_approval` attestation in addition when the
-- gateway next reads it; the unique key includes execution_status.
--
-- Forward-only; 0001-0021 are not edited. Old constraints and triggers are
-- dropped by exact name; their functions stay (no trigger calls them) so
-- the manual rollback can put them back. Every new object has a new name.
-- Manual rollback: docs/rollback/0022-awaiting-approval-state.sql.
-- Applied inside the runner's transaction.

-- 1. Signed states of an attestation (0005's inline CHECK).
ALTER TABLE praetore.execution_attestations
    DROP CONSTRAINT execution_attestations_execution_status_check;
ALTER TABLE praetore.execution_attestations
    ADD CONSTRAINT execution_attestations_execution_status_v2 CHECK (execution_status IN (
        'not_dispatched', 'awaiting_approval', 'executed', 'confirmed',
        'outcome_unknown', 'failed'
    ));

-- 2. Journal reason vocabulary: 0020's plus approved_claim_expired.
ALTER TABLE praetore.execution_journal
    DROP CONSTRAINT execution_journal_not_dispatched_reason_v3;
ALTER TABLE praetore.execution_journal
    ADD CONSTRAINT execution_journal_not_dispatched_reason_v4 CHECK (
        not_dispatched_reason IS NULL
        OR (not_dispatched_reason IN (
                'approval_expired', 'approval_rejected', 'dispatch_failed',
                'crash_recovered', 'approved_claim_expired'
            )
            AND authorization_status = 'requires_approval'
            AND execution_status = 'not_dispatched')
        OR (not_dispatched_reason = 'dispatch_refused'
            AND authorization_status IN ('allowed', 'requires_approval')
            AND execution_status = 'not_dispatched')
    );

-- 3. Attestation reason vocabulary: 0020's plus approved_claim_expired.
ALTER TABLE praetore.execution_attestations
    DROP CONSTRAINT execution_attestations_not_dispatched_reason_v3;
ALTER TABLE praetore.execution_attestations
    ADD CONSTRAINT execution_attestations_not_dispatched_reason_v4 CHECK (
        not_dispatched_reason IS NOT DISTINCT FROM
            (attestation_json ->> 'not_dispatched_reason')
        AND (not_dispatched_reason IS NULL
            OR (not_dispatched_reason IN (
                    'approval_expired', 'approval_rejected', 'dispatch_failed',
                    'crash_recovered', 'dispatch_refused', 'approved_claim_expired'
                )
                AND execution_status = 'not_dispatched'))
    );

-- 4. Transition rules: 0020's, except that an approved_pending_dispatch
-- row closes without dispatch with any reason but approval_expired, and
-- with approved_claim_expired only when an approve decision exists.
CREATE FUNCTION praetore.validate_execution_journal_transition_v5()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, praetore, pg_temp
AS $$
DECLARE
    refused_close BOOLEAN;
    decided_close BOOLEAN;
BEGIN
    IF NEW.tenant_id <> OLD.tenant_id
        OR NEW.agent_id <> OLD.agent_id
        OR NEW.request_id <> OLD.request_id
        OR NEW.request_digest <> OLD.request_digest
        OR NEW.action_digest <> OLD.action_digest
        OR NEW.authorization_status <> OLD.authorization_status
        OR NEW.evidence_json <> OLD.evidence_json THEN
        RAISE EXCEPTION 'execution journal identity and authorization fields are immutable';
    END IF;

    refused_close := OLD.not_dispatched_reason IS NULL
        AND NEW.not_dispatched_reason = 'dispatch_refused'
        AND NEW.execution_status = 'not_dispatched'
        AND (
            (OLD.authorization_status = 'allowed'
                AND OLD.execution_status = 'authorized')
            OR (OLD.authorization_status = 'requires_approval'
                AND OLD.execution_status = 'approved_pending_dispatch')
            OR (OLD.authorization_status = 'requires_approval'
                AND OLD.execution_status = 'not_dispatched'
                AND NOT EXISTS (
                    SELECT 1 FROM praetore.human_approvals approval
                    WHERE approval.tenant_id = OLD.tenant_id
                      AND approval.agent_id = OLD.agent_id
                      AND approval.request_id = OLD.request_id
                )
                AND NOT EXISTS (
                    SELECT 1 FROM praetore.human_approval_expirations expiration
                    WHERE expiration.tenant_id = OLD.tenant_id
                      AND expiration.agent_id = OLD.agent_id
                      AND expiration.request_id = OLD.request_id
                ))
        );

    -- 0020: a held approval that a human rejected, or whose window closed
    -- with the signed expiration receipt, is closed in place with its own
    -- reason. The decision or the receipt must already exist, and never
    -- both.
    decided_close := OLD.not_dispatched_reason IS NULL
        AND OLD.authorization_status = 'requires_approval'
        AND OLD.execution_status = 'not_dispatched'
        AND NEW.execution_status = 'not_dispatched'
        AND (
            (NEW.not_dispatched_reason = 'approval_rejected'
                AND EXISTS (
                    SELECT 1 FROM praetore.human_approvals approval
                    WHERE approval.tenant_id = OLD.tenant_id
                      AND approval.agent_id = OLD.agent_id
                      AND approval.request_id = OLD.request_id
                      AND approval.outcome = 'reject'
                )
                AND NOT EXISTS (
                    SELECT 1 FROM praetore.human_approval_expirations expiration
                    WHERE expiration.tenant_id = OLD.tenant_id
                      AND expiration.agent_id = OLD.agent_id
                      AND expiration.request_id = OLD.request_id
                ))
            OR (NEW.not_dispatched_reason = 'approval_expired'
                AND EXISTS (
                    SELECT 1 FROM praetore.human_approval_expirations expiration
                    WHERE expiration.tenant_id = OLD.tenant_id
                      AND expiration.agent_id = OLD.agent_id
                      AND expiration.request_id = OLD.request_id
                )
                AND NOT EXISTS (
                    SELECT 1 FROM praetore.human_approvals approval
                    WHERE approval.tenant_id = OLD.tenant_id
                      AND approval.agent_id = OLD.agent_id
                      AND approval.request_id = OLD.request_id
                ))
        );

    -- The reason is written once: when closing APD without dispatch, as a
    -- dispatch_refused close, or as a rejected or expired close (0020).
    IF NEW.not_dispatched_reason IS DISTINCT FROM OLD.not_dispatched_reason
        AND NOT refused_close
        AND NOT decided_close
        AND NOT (OLD.execution_status = 'approved_pending_dispatch'
            AND NEW.execution_status = 'not_dispatched'
            AND OLD.not_dispatched_reason IS NULL) THEN
        RAISE EXCEPTION 'not_dispatched_reason is write-once when closing without dispatch';
    END IF;

    -- 0020 (D-B1): the failure class is written once, together with the
    -- transition to failed, and never changed afterwards.
    IF (NEW.failure_class IS DISTINCT FROM OLD.failure_class
            OR NEW.failure_reason IS DISTINCT FROM OLD.failure_reason)
        AND NOT (OLD.failure_class IS NULL
            AND OLD.failure_reason IS NULL
            AND OLD.execution_status IN ('dispatched', 'outcome_unknown')
            AND NEW.execution_status = 'failed') THEN
        RAISE EXCEPTION 'failure_class is write-once, with the transition to failed';
    END IF;

    IF NEW.execution_status = OLD.execution_status THEN
        IF NEW.output_json IS DISTINCT FROM OLD.output_json THEN
            RAISE EXCEPTION 'execution journal output is immutable within a state';
        END IF;
        RETURN NEW;
    END IF;

    IF (OLD.execution_status = 'authorized'
            AND OLD.authorization_status = 'allowed'
            AND NEW.execution_status IN ('dispatched', 'not_dispatched'))
        -- Enter APD once: an approve decision, no expiration, no reason,
        -- never before.
        OR (OLD.execution_status = 'not_dispatched'
            AND NEW.execution_status = 'approved_pending_dispatch'
            AND OLD.authorization_status = 'requires_approval'
            AND OLD.not_dispatched_reason IS NULL
            AND NEW.not_dispatched_reason IS NULL
            AND EXISTS (
                SELECT 1 FROM praetore.human_approvals approval
                WHERE approval.tenant_id = OLD.tenant_id
                  AND approval.agent_id = OLD.agent_id
                  AND approval.request_id = OLD.request_id
                  AND approval.outcome = 'approve'
            )
            AND NOT EXISTS (
                SELECT 1 FROM praetore.human_approval_expirations expiration
                WHERE expiration.tenant_id = OLD.tenant_id
                  AND expiration.agent_id = OLD.agent_id
                  AND expiration.request_id = OLD.request_id
            )
            AND NOT EXISTS (
                SELECT 1 FROM praetore.execution_journal_events event
                WHERE event.tenant_id = OLD.tenant_id
                  AND event.agent_id = OLD.agent_id
                  AND event.request_id = OLD.request_id
                  AND event.to_status = 'approved_pending_dispatch'
            ))
        OR (OLD.execution_status = 'approved_pending_dispatch'
            AND NEW.execution_status = 'dispatched'
            AND NEW.not_dispatched_reason IS NULL)
        -- 0022: approval_expired is no longer a close of APD, and
        -- approved_claim_expired needs the approve decision.
        OR (OLD.execution_status = 'approved_pending_dispatch'
            AND NEW.execution_status = 'not_dispatched'
            AND NEW.not_dispatched_reason IS NOT NULL
            AND NEW.not_dispatched_reason <> 'approval_expired'
            AND (NEW.not_dispatched_reason <> 'approved_claim_expired'
                OR EXISTS (
                    SELECT 1 FROM praetore.human_approvals approval
                    WHERE approval.tenant_id = OLD.tenant_id
                      AND approval.agent_id = OLD.agent_id
                      AND approval.request_id = OLD.request_id
                      AND approval.outcome = 'approve'
                )))
        OR (OLD.execution_status = 'dispatched'
            AND NEW.execution_status IN (
                'outcome_unknown', 'executed', 'confirmed', 'failed'
            ))
        OR (OLD.execution_status = 'outcome_unknown'
            AND NEW.execution_status IN ('executed', 'confirmed', 'failed')) THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'invalid execution journal state transition: % -> % (%)',
        OLD.execution_status, NEW.execution_status, NEW.not_dispatched_reason;
END;
$$;

REVOKE ALL ON FUNCTION praetore.validate_execution_journal_transition_v5() FROM PUBLIC;

DROP TRIGGER execution_journal_transition_v4 ON praetore.execution_journal;
CREATE TRIGGER execution_journal_transition_v5
BEFORE UPDATE ON praetore.execution_journal
FOR EACH ROW EXECUTE FUNCTION praetore.validate_execution_journal_transition_v5();

-- 5. Attestation INSERT rules: 0021's, plus `awaiting_approval` on a held
-- row with no reason, no failure class, no decision and no expiration.
CREATE FUNCTION praetore.validate_execution_attestation_insert_v2()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, praetore, pg_temp
AS $$
DECLARE
    journal RECORD;
    state_matches BOOLEAN;
BEGIN
    -- Invoker rights: the row must be visible to the inserting role under
    -- row level security, so an attestation for another tenant's row is
    -- refused like a missing one. FOR SHARE keeps the row's state fixed
    -- until this transaction ends.
    SELECT current_row.authorization_status, current_row.execution_status,
           current_row.not_dispatched_reason, current_row.failure_class,
           current_row.failure_reason, current_row.action_digest
      INTO journal
      FROM praetore.execution_journal current_row
     WHERE current_row.tenant_id = NEW.tenant_id
       AND current_row.agent_id = NEW.agent_id
       AND current_row.request_id = NEW.request_id
       FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'execution attestation has no visible journal row';
    END IF;

    IF NEW.execution_status = 'awaiting_approval' THEN
        state_matches := journal.authorization_status = 'requires_approval'
            AND journal.execution_status = 'not_dispatched'
            AND journal.not_dispatched_reason IS NULL
            AND journal.failure_class IS NULL
            AND journal.failure_reason IS NULL
            AND NEW.not_dispatched_reason IS NULL
            AND NEW.failure_class IS NULL
            AND NEW.failure_reason IS NULL
            AND NEW.attestation_json -> 'schema_version' = '5'::jsonb
            AND NOT EXISTS (
                SELECT 1 FROM praetore.human_approvals approval
                WHERE approval.tenant_id = NEW.tenant_id
                  AND approval.agent_id = NEW.agent_id
                  AND approval.request_id = NEW.request_id
            )
            AND NOT EXISTS (
                SELECT 1 FROM praetore.human_approval_expirations expiration
                WHERE expiration.tenant_id = NEW.tenant_id
                  AND expiration.agent_id = NEW.agent_id
                  AND expiration.request_id = NEW.request_id
            );
    ELSE
        state_matches := NEW.execution_status = journal.execution_status
            AND NEW.not_dispatched_reason IS NOT DISTINCT FROM journal.not_dispatched_reason
            AND NEW.failure_class IS NOT DISTINCT FROM journal.failure_class
            AND NEW.failure_reason IS NOT DISTINCT FROM journal.failure_reason;
    END IF;

    IF NOT COALESCE(
        state_matches
        AND jsonb_typeof(NEW.attestation_json) = 'object'
        AND NEW.attestation_json ->> 'execution' = NEW.execution_status
        AND NEW.attestation_json ->> 'authorization' = journal.authorization_status
        AND NEW.attestation_json ->> 'tenant_id' = NEW.tenant_id::text
        AND NEW.attestation_json ->> 'agent_id' = NEW.agent_id::text
        AND NEW.attestation_json ->> 'request_id' = NEW.request_id::text
        AND NEW.attestation_json ->> 'action_digest' = journal.action_digest,
        false) THEN
        RAISE EXCEPTION 'execution attestation does not match the journal state: % (journal %)',
            NEW.execution_status, journal.execution_status;
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION praetore.validate_execution_attestation_insert_v2() FROM PUBLIC;

DROP TRIGGER execution_attestations_journal_state_v1 ON praetore.execution_attestations;
CREATE TRIGGER execution_attestations_journal_state_v2
BEFORE INSERT ON praetore.execution_attestations
FOR EACH ROW EXECUTE FUNCTION praetore.validate_execution_attestation_insert_v2();
