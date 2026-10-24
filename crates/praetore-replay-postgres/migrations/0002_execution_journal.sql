CREATE TABLE IF NOT EXISTS praetore.execution_journal (
    agent_id UUID NOT NULL,
    request_id UUID NOT NULL,
    request_digest CHAR(64) NOT NULL,
    action_digest CHAR(64) NOT NULL,
    authorization_status TEXT NOT NULL
        CHECK (authorization_status IN ('allowed', 'requires_approval', 'denied')),
    execution_status TEXT NOT NULL
        CHECK (execution_status IN (
            'not_dispatched', 'authorized', 'dispatched', 'executed',
            'confirmed', 'outcome_unknown', 'failed'
        )),
    evidence_json TEXT NOT NULL,
    output_json TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (agent_id, request_id),
    CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    CHECK (action_digest ~ '^[0-9a-f]{64}$'),
    CHECK (
        (authorization_status = 'allowed'
            AND execution_status IN (
                'authorized', 'not_dispatched', 'dispatched', 'executed',
                'confirmed', 'outcome_unknown', 'failed'
            ))
        OR (authorization_status IN ('requires_approval', 'denied')
            AND execution_status = 'not_dispatched')
    ),
    CHECK (
        (execution_status IN ('executed', 'confirmed') AND output_json IS NOT NULL)
        OR (execution_status NOT IN ('executed', 'confirmed') AND output_json IS NULL)
    )
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
