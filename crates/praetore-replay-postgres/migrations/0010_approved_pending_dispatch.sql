-- approved_pending_dispatch (APD): an approval no longer dispatches.
-- Approve moves not_dispatched -> approved_pending_dispatch; only a claim
-- (compare-and-set under FOR UPDATE) moves APD -> dispatched; an unclaimed
-- APD is closed as not_dispatched with a write-once reason.
--
-- Forward-only and append-only (CTO): no down migration, 0001-0009 are not
-- edited. To revert, ship a compensating migration that blocks entry into APD
-- without touching stored rows. Applied exactly once by the migration runner
-- (praetore.schema_migrations), inside the runner's transaction, so this file
-- has no BEGIN/COMMIT of its own. Old constraints and the old trigger are
-- dropped by exact name; every new object has a new name.

-- 1. Status vocabulary.
ALTER TABLE praetore.execution_journal
    DROP CONSTRAINT execution_journal_execution_status_check;
ALTER TABLE praetore.execution_journal
    ADD CONSTRAINT execution_journal_execution_status_v2 CHECK (execution_status IN (
        'not_dispatched', 'authorized', 'approved_pending_dispatch', 'dispatched',
        'executed', 'confirmed', 'outcome_unknown', 'failed'
    ));

ALTER TABLE praetore.execution_journal_events
    DROP CONSTRAINT execution_journal_events_to_status_check;
ALTER TABLE praetore.execution_journal_events
    DROP CONSTRAINT execution_journal_events_from_status_check;
ALTER TABLE praetore.execution_journal_events
    ADD CONSTRAINT execution_journal_events_to_status_v2 CHECK (to_status IN (
        'not_dispatched', 'authorized', 'approved_pending_dispatch', 'dispatched',
        'executed', 'confirmed', 'outcome_unknown', 'failed'
    )),
    ADD CONSTRAINT execution_journal_events_from_status_v2 CHECK (
        from_status IS NULL OR from_status IN (
            'not_dispatched', 'authorized', 'approved_pending_dispatch', 'dispatched',
            'executed', 'confirmed', 'outcome_unknown', 'failed'
        )
    );

-- 2. Authorization/execution combinations: APD only for requires_approval.
ALTER TABLE praetore.execution_journal
    DROP CONSTRAINT execution_journal_authorization_execution_check;
ALTER TABLE praetore.execution_journal
    ADD CONSTRAINT execution_journal_authorization_execution_v2 CHECK (
        (authorization_status = 'allowed'
            AND execution_status IN (
                'authorized', 'not_dispatched', 'dispatched', 'executed',
                'confirmed', 'outcome_unknown', 'failed'
            ))
        OR (authorization_status = 'requires_approval'
            AND execution_status IN (
                'not_dispatched', 'approved_pending_dispatch', 'dispatched',
                'executed', 'confirmed', 'outcome_unknown', 'failed'
            ))
        OR (authorization_status = 'denied'
            AND execution_status = 'not_dispatched')
    );

-- 3. Terminal reason for closing APD without dispatch.
ALTER TABLE praetore.execution_journal
    ADD COLUMN not_dispatched_reason TEXT;
ALTER TABLE praetore.execution_journal
    ADD CONSTRAINT execution_journal_not_dispatched_reason_v1 CHECK (
        not_dispatched_reason IS NULL
        OR (not_dispatched_reason IN (
                'approval_expired', 'dispatch_failed', 'crash_recovered'
            )
            AND authorization_status = 'requires_approval'
            AND execution_status = 'not_dispatched')
    );

-- 4. The closing attestation is a second not_dispatched attestation for the
-- same key (the first one was signed when approval was requested). It is
-- distinguished by its signed reason.
ALTER TABLE praetore.execution_attestations
    ADD COLUMN not_dispatched_reason TEXT;
ALTER TABLE praetore.execution_attestations
    ADD CONSTRAINT execution_attestations_not_dispatched_reason_v1 CHECK (
        not_dispatched_reason IS NOT DISTINCT FROM
            (attestation_json ->> 'not_dispatched_reason')
        AND (not_dispatched_reason IS NULL
            OR (not_dispatched_reason IN (
                    'approval_expired', 'dispatch_failed', 'crash_recovered'
                )
                AND execution_status = 'not_dispatched'))
    );
ALTER TABLE praetore.execution_attestations
    DROP CONSTRAINT execution_attestations_identity_status_key;
ALTER TABLE praetore.execution_attestations
    ADD CONSTRAINT execution_attestations_identity_status_reason_key
        UNIQUE NULLS NOT DISTINCT
        (tenant_id, agent_id, request_id, execution_status, not_dispatched_reason);

-- 5. Transition rules. Retires not_dispatched -> dispatched (CTO decision 7).
CREATE FUNCTION praetore.validate_execution_journal_transition_v2()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
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

    -- The reason is written once, only when closing APD without dispatch.
    IF NEW.not_dispatched_reason IS DISTINCT FROM OLD.not_dispatched_reason
        AND NOT (OLD.execution_status = 'approved_pending_dispatch'
            AND NEW.execution_status = 'not_dispatched'
            AND OLD.not_dispatched_reason IS NULL) THEN
        RAISE EXCEPTION 'not_dispatched_reason is write-once when closing approved_pending_dispatch';
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
        -- Enter APD once: an approve decision, no expiration, never before.
        OR (OLD.execution_status = 'not_dispatched'
            AND NEW.execution_status = 'approved_pending_dispatch'
            AND OLD.authorization_status = 'requires_approval'
            AND OLD.not_dispatched_reason IS NULL
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

REVOKE ALL ON FUNCTION praetore.validate_execution_journal_transition_v2() FROM PUBLIC;

DROP TRIGGER execution_journal_transition ON praetore.execution_journal;
CREATE TRIGGER execution_journal_transition_v2
BEFORE UPDATE ON praetore.execution_journal
FOR EACH ROW EXECUTE FUNCTION praetore.validate_execution_journal_transition_v2();
