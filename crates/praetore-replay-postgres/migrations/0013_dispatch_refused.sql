-- dispatch_refused: an adapter refused an action before any effect (its
-- preflight check), and the execution is closed for good.
--
-- New reason 'dispatch_refused', valid only on a not_dispatched row:
--   * allowed:            authorized -> not_dispatched;
--   * requires_approval:  not_dispatched (no decision yet) -> not_dispatched,
--                         or approved_pending_dispatch -> not_dispatched.
-- A requires_approval row closed this way can never be approved: 0010
-- already refuses entering approved_pending_dispatch once a reason is set,
-- and this migration also refuses inserting any human decision for it.
--
-- Forward-only; 0001-0012 are not edited. Old constraints and the 0010
-- trigger are dropped by exact name; every new object has a new name.
-- Applied inside the runner's transaction.

-- 1. Journal reason vocabulary.
ALTER TABLE praetore.execution_journal
    DROP CONSTRAINT execution_journal_not_dispatched_reason_v1;
ALTER TABLE praetore.execution_journal
    ADD CONSTRAINT execution_journal_not_dispatched_reason_v2 CHECK (
        not_dispatched_reason IS NULL
        OR (not_dispatched_reason IN (
                'approval_expired', 'dispatch_failed', 'crash_recovered'
            )
            AND authorization_status = 'requires_approval'
            AND execution_status = 'not_dispatched')
        OR (not_dispatched_reason = 'dispatch_refused'
            AND authorization_status IN ('allowed', 'requires_approval')
            AND execution_status = 'not_dispatched')
    );

-- 2. Attestation reason vocabulary.
ALTER TABLE praetore.execution_attestations
    DROP CONSTRAINT execution_attestations_not_dispatched_reason_v1;
ALTER TABLE praetore.execution_attestations
    ADD CONSTRAINT execution_attestations_not_dispatched_reason_v2 CHECK (
        not_dispatched_reason IS NOT DISTINCT FROM
            (attestation_json ->> 'not_dispatched_reason')
        AND (not_dispatched_reason IS NULL
            OR (not_dispatched_reason IN (
                    'approval_expired', 'dispatch_failed', 'crash_recovered',
                    'dispatch_refused'
                )
                AND execution_status = 'not_dispatched'))
    );

-- 3. Transition rules: 0010's rules plus the dispatch_refused closes.
CREATE FUNCTION praetore.validate_execution_journal_transition_v3()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, praetore, pg_temp
AS $$
DECLARE
    refused_close BOOLEAN;
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

    -- The reason is written once: when closing APD without dispatch, or as
    -- a dispatch_refused close.
    IF NEW.not_dispatched_reason IS DISTINCT FROM OLD.not_dispatched_reason
        AND NOT refused_close
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

REVOKE ALL ON FUNCTION praetore.validate_execution_journal_transition_v3() FROM PUBLIC;

DROP TRIGGER execution_journal_transition_v2 ON praetore.execution_journal;
CREATE TRIGGER execution_journal_transition_v3
BEFORE UPDATE ON praetore.execution_journal
FOR EACH ROW EXECUTE FUNCTION praetore.validate_execution_journal_transition_v3();

-- 4. No human decision (approve or reject) for an execution already closed
-- with a reason.
CREATE FUNCTION praetore.refuse_decision_for_closed_execution()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, praetore, pg_temp
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM praetore.execution_journal journal
        WHERE journal.tenant_id = NEW.tenant_id
          AND journal.agent_id = NEW.agent_id
          AND journal.request_id = NEW.request_id
          AND journal.not_dispatched_reason IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'execution is closed without dispatch; no decision can be recorded';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION praetore.refuse_decision_for_closed_execution() FROM PUBLIC;

CREATE TRIGGER human_approvals_refuse_closed_execution
BEFORE INSERT ON praetore.human_approvals
FOR EACH ROW EXECUTE FUNCTION praetore.refuse_decision_for_closed_execution();
