CREATE TABLE IF NOT EXISTS praetore.execution_attestations (
    attestation_id UUID PRIMARY KEY,
    agent_id UUID NOT NULL,
    request_id UUID NOT NULL,
    execution_status TEXT NOT NULL CHECK (execution_status IN (
        'not_dispatched', 'executed', 'confirmed', 'outcome_unknown', 'failed'
    )),
    attestation_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (agent_id, request_id)
        REFERENCES praetore.execution_journal (agent_id, request_id)
        ON DELETE RESTRICT,
    UNIQUE (agent_id, request_id, execution_status)
);

CREATE INDEX IF NOT EXISTS execution_attestations_identity
    ON praetore.execution_attestations (agent_id, request_id, created_at);

CREATE OR REPLACE FUNCTION praetore.reject_execution_attestation_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'execution attestations are append-only';
END;
$$;

REVOKE ALL ON FUNCTION praetore.reject_execution_attestation_mutation() FROM PUBLIC;

DROP TRIGGER IF EXISTS execution_attestations_immutable
    ON praetore.execution_attestations;
CREATE TRIGGER execution_attestations_immutable
BEFORE UPDATE OR DELETE ON praetore.execution_attestations
FOR EACH ROW EXECUTE FUNCTION praetore.reject_execution_attestation_mutation();

DROP TRIGGER IF EXISTS execution_attestations_no_truncate
    ON praetore.execution_attestations;
CREATE TRIGGER execution_attestations_no_truncate
BEFORE TRUNCATE ON praetore.execution_attestations
FOR EACH STATEMENT EXECUTE FUNCTION praetore.reject_execution_attestation_mutation();
