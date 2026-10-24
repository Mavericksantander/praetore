CREATE TABLE IF NOT EXISTS praetore.execution_journal_events (
    event_id BIGSERIAL PRIMARY KEY,
    agent_id UUID NOT NULL,
    request_id UUID NOT NULL,
    from_status TEXT,
    to_status TEXT NOT NULL CHECK (to_status IN (
        'not_dispatched', 'authorized', 'dispatched', 'executed',
        'confirmed', 'outcome_unknown', 'failed'
    )),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (agent_id, request_id)
        REFERENCES praetore.execution_journal (agent_id, request_id)
        ON DELETE RESTRICT,
    CHECK (
        from_status IS NULL OR from_status IN (
            'not_dispatched', 'authorized', 'dispatched', 'executed',
            'confirmed', 'outcome_unknown', 'failed'
        )
    )
);

CREATE INDEX IF NOT EXISTS execution_journal_events_identity
    ON praetore.execution_journal_events (agent_id, request_id, event_id);

CREATE INDEX IF NOT EXISTS execution_journal_created_at
    ON praetore.execution_journal (created_at DESC, agent_id, request_id);

CREATE OR REPLACE FUNCTION praetore.record_execution_journal_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, praetore, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO praetore.execution_journal_events
            (agent_id, request_id, from_status, to_status)
        VALUES (NEW.agent_id, NEW.request_id, NULL, NEW.execution_status);
    ELSIF NEW.execution_status IS DISTINCT FROM OLD.execution_status THEN
        INSERT INTO praetore.execution_journal_events
            (agent_id, request_id, from_status, to_status)
        VALUES (
            NEW.agent_id,
            NEW.request_id,
            OLD.execution_status,
            NEW.execution_status
        );
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION praetore.record_execution_journal_transition() FROM PUBLIC;

DROP TRIGGER IF EXISTS execution_journal_event_log
    ON praetore.execution_journal;
CREATE TRIGGER execution_journal_event_log
AFTER INSERT OR UPDATE OF execution_status ON praetore.execution_journal
FOR EACH ROW EXECUTE FUNCTION praetore.record_execution_journal_transition();

CREATE OR REPLACE FUNCTION praetore.reject_execution_journal_event_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'execution journal history is append-only';
END;
$$;

REVOKE ALL ON FUNCTION praetore.reject_execution_journal_event_mutation() FROM PUBLIC;

DROP TRIGGER IF EXISTS execution_journal_events_immutable
    ON praetore.execution_journal_events;
CREATE TRIGGER execution_journal_events_immutable
BEFORE UPDATE OR DELETE ON praetore.execution_journal_events
FOR EACH ROW EXECUTE FUNCTION praetore.reject_execution_journal_event_mutation();

DROP TRIGGER IF EXISTS execution_journal_events_no_truncate
    ON praetore.execution_journal_events;
CREATE TRIGGER execution_journal_events_no_truncate
BEFORE TRUNCATE ON praetore.execution_journal_events
FOR EACH STATEMENT EXECUTE FUNCTION praetore.reject_execution_journal_event_mutation();
