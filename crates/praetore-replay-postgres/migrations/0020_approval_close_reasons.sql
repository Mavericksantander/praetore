-- approval_rejected and approval_expired close a held approval with a
-- signed, non-null reason (T-013, DISC-1).
--
-- Before 0020 a held (requires_approval) execution that a human rejected,
-- or whose approval window closed, stayed not_dispatched with a NULL
-- reason: the two could only be told apart by joining human_approvals and
-- human_approval_expirations. Now the gateway closes it in place with:
--   * 'approval_rejected' (new): a reject decision exists, no expiration;
--   * 'approval_expired' (already used when an approved execution is
--     claimed too late): an expiration receipt exists, no decision.
-- The reason is still written once and the row stays not_dispatched, so
-- no decision can be recorded afterwards (0013's trigger).
--
-- Rows closed before 0020 keep their NULL reason: their attestations are
-- signed and are not rewritten here.
--
-- Forward-only; 0001-0019 are not edited. Old constraints and the 0013
-- trigger are dropped by exact name; every new object has a new name.
-- Manual rollback: docs/rollback/0020-approval-close-reasons.sql.
-- Applied inside the runner's transaction.

-- 1. Journal reason vocabulary.
ALTER TABLE praetore.execution_journal
    DROP CONSTRAINT execution_journal_not_dispatched_reason_v2;
ALTER TABLE praetore.execution_journal
    ADD CONSTRAINT execution_journal_not_dispatched_reason_v3 CHECK (
        not_dispatched_reason IS NULL
        OR (not_dispatched_reason IN (
                'approval_expired', 'approval_rejected', 'dispatch_failed',
                'crash_recovered'
            )
            AND authorization_status = 'requires_approval'
            AND execution_status = 'not_dispatched')
        OR (not_dispatched_reason = 'dispatch_refused'
            AND authorization_status IN ('allowed', 'requires_approval')
            AND execution_status = 'not_dispatched')
    );

-- 2. Attestation reason vocabulary.
ALTER TABLE praetore.execution_attestations
    DROP CONSTRAINT execution_attestations_not_dispatched_reason_v2;
ALTER TABLE praetore.execution_attestations
    ADD CONSTRAINT execution_attestations_not_dispatched_reason_v3 CHECK (
        not_dispatched_reason IS NOT DISTINCT FROM
            (attestation_json ->> 'not_dispatched_reason')
        AND (not_dispatched_reason IS NULL
            OR (not_dispatched_reason IN (
                    'approval_expired', 'approval_rejected', 'dispatch_failed',
                    'crash_recovered', 'dispatch_refused'
                )
                AND execution_status = 'not_dispatched'))
    );

-- 3. Transition rules: 0013's rules plus the rejected and expired closes.
CREATE FUNCTION praetore.validate_execution_journal_transition_v4()
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
        OR (OLD.execution_status = 'approved_pending_dispatch'
            AND NEW.execution_status = 'not_dispatched'
            AND NEW.not_dispatched_reason IS NOT NULL)
        OR (OLD.execution_status = 'dispatched'
            AND NEW.execution_status IN (
                'outcome_unknown', 'executed', 'confirmed', 'failed'
            ))
        OR (OLD.execution_status = 'outcome_unknown'
            AND NEW.execution_status IN ('executed', 'confirmed', 'failed')) THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'invalid execution journal state transition: % -> %',
        OLD.execution_status, NEW.execution_status;
END;
$$;

REVOKE ALL ON FUNCTION praetore.validate_execution_journal_transition_v4() FROM PUBLIC;

-- The v3 function stays (invoker rights, no trigger calls it) so the manual
-- rollback can put its trigger back.
DROP TRIGGER execution_journal_transition_v3 ON praetore.execution_journal;
CREATE TRIGGER execution_journal_transition_v4
BEFORE UPDATE ON praetore.execution_journal
FOR EACH ROW EXECUTE FUNCTION praetore.validate_execution_journal_transition_v4();
