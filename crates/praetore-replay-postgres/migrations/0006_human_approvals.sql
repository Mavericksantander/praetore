CREATE TABLE IF NOT EXISTS praetore.human_approvals (
    approval_id UUID PRIMARY KEY,
    agent_id UUID NOT NULL,
    request_id UUID NOT NULL,
    evidence_id UUID NOT NULL,
    evidence_hash CHAR(64) NOT NULL CHECK (evidence_hash ~ '^[0-9a-f]{64}$'),
    action_digest CHAR(64) NOT NULL CHECK (action_digest ~ '^[0-9a-f]{64}$'),
    policy_digest CHAR(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    outcome TEXT NOT NULL CHECK (outcome IN ('approve', 'reject')),
    approver_key_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    decision_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (agent_id, request_id)
        REFERENCES praetore.execution_journal (agent_id, request_id)
        ON DELETE RESTRICT,
    UNIQUE (agent_id, request_id)
);

CREATE OR REPLACE FUNCTION praetore.reject_human_approval_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'human approval records are append-only';
END;
$$;

REVOKE ALL ON FUNCTION praetore.reject_human_approval_mutation() FROM PUBLIC;

DROP TRIGGER IF EXISTS human_approvals_immutable
    ON praetore.human_approvals;
CREATE TRIGGER human_approvals_immutable
BEFORE UPDATE OR DELETE ON praetore.human_approvals
FOR EACH ROW EXECUTE FUNCTION praetore.reject_human_approval_mutation();

DROP TRIGGER IF EXISTS human_approvals_no_truncate
    ON praetore.human_approvals;
CREATE TRIGGER human_approvals_no_truncate
BEFORE TRUNCATE ON praetore.human_approvals
FOR EACH STATEMENT EXECUTE FUNCTION praetore.reject_human_approval_mutation();

DO $$
DECLARE
    existing_constraint RECORD;
BEGIN
    FOR existing_constraint IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'praetore.execution_journal'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%authorization_status%'
          AND pg_get_constraintdef(oid) LIKE '%execution_status%'
    LOOP
        EXECUTE format(
            'ALTER TABLE praetore.execution_journal DROP CONSTRAINT %I',
            existing_constraint.conname
        );
    END LOOP;
END;
$$;

ALTER TABLE praetore.execution_journal
    ADD CONSTRAINT execution_journal_authorization_execution_check
    CHECK (
        (authorization_status = 'allowed'
            AND execution_status IN (
                'authorized', 'not_dispatched', 'dispatched', 'executed',
                'confirmed', 'outcome_unknown', 'failed'
            ))
        OR (authorization_status = 'requires_approval'
            AND execution_status IN (
                'not_dispatched', 'dispatched', 'executed', 'confirmed',
                'outcome_unknown', 'failed'
            ))
        OR (authorization_status = 'denied'
            AND execution_status = 'not_dispatched')
    );

CREATE OR REPLACE FUNCTION praetore.validate_execution_journal_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.agent_id <> OLD.agent_id
        OR NEW.request_id <> OLD.request_id
        OR NEW.request_digest <> OLD.request_digest
        OR NEW.action_digest <> OLD.action_digest
        OR NEW.authorization_status <> OLD.authorization_status
        OR NEW.evidence_json <> OLD.evidence_json THEN
        RAISE EXCEPTION 'execution journal identity and authorization fields are immutable';
    END IF;

    IF NEW.execution_status = OLD.execution_status THEN
        IF NEW.output_json IS DISTINCT FROM OLD.output_json THEN
            RAISE EXCEPTION 'execution journal output is immutable within a state';
        END IF;
        RETURN NEW;
    END IF;

    IF (OLD.execution_status = 'authorized'
            AND NEW.execution_status IN ('dispatched', 'not_dispatched'))
        OR (OLD.execution_status = 'not_dispatched'
            AND NEW.execution_status = 'dispatched'
            AND OLD.authorization_status = 'requires_approval'
            AND EXISTS (
                SELECT 1
                FROM praetore.human_approvals approval
                WHERE approval.agent_id = OLD.agent_id
                  AND approval.request_id = OLD.request_id
                  AND approval.outcome = 'approve'
            ))
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

DROP TRIGGER IF EXISTS execution_journal_transition
    ON praetore.execution_journal;
CREATE TRIGGER execution_journal_transition
BEFORE UPDATE ON praetore.execution_journal
FOR EACH ROW EXECUTE FUNCTION praetore.validate_execution_journal_transition();
