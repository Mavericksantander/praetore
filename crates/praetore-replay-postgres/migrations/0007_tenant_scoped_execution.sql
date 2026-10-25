BEGIN;

ALTER TABLE praetore.replay_claims
    ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE praetore.execution_journal
    ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE praetore.execution_journal_events
    ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE praetore.execution_attestations
    ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE praetore.human_approvals
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE praetore.execution_journal journal
SET tenant_id = (
    SELECT (constraint_value.item->>'value')::UUID
    FROM jsonb_array_elements(
        (journal.evidence_json::JSONB #> '{authority,constraints}')
    ) AS constraint_value(item)
    WHERE constraint_value.item->>'key' = 'tenant_id'
      AND constraint_value.item->>'value'
          ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    LIMIT 1
)
WHERE journal.tenant_id IS NULL;

UPDATE praetore.replay_claims claim
SET tenant_id = journal.tenant_id
FROM praetore.execution_journal journal
WHERE claim.tenant_id IS NULL
  AND claim.agent_id = journal.agent_id
  AND claim.request_id = journal.request_id;

UPDATE praetore.replay_claims
SET tenant_id = '00000000-0000-0000-0000-000000000000'
WHERE tenant_id IS NULL;
UPDATE praetore.execution_journal
SET tenant_id = '00000000-0000-0000-0000-000000000000'
WHERE tenant_id IS NULL;

UPDATE praetore.execution_journal_events event
SET tenant_id = journal.tenant_id
FROM praetore.execution_journal journal
WHERE event.tenant_id IS NULL
  AND event.agent_id = journal.agent_id
  AND event.request_id = journal.request_id;
UPDATE praetore.execution_attestations attestation
SET tenant_id = journal.tenant_id
FROM praetore.execution_journal journal
WHERE attestation.tenant_id IS NULL
  AND attestation.agent_id = journal.agent_id
  AND attestation.request_id = journal.request_id;
UPDATE praetore.human_approvals approval
SET tenant_id = journal.tenant_id
FROM praetore.execution_journal journal
WHERE approval.tenant_id IS NULL
  AND approval.agent_id = journal.agent_id
  AND approval.request_id = journal.request_id;

UPDATE praetore.execution_journal_events
SET tenant_id = '00000000-0000-0000-0000-000000000000'
WHERE tenant_id IS NULL;
UPDATE praetore.execution_attestations
SET tenant_id = '00000000-0000-0000-0000-000000000000'
WHERE tenant_id IS NULL;
UPDATE praetore.human_approvals
SET tenant_id = '00000000-0000-0000-0000-000000000000'
WHERE tenant_id IS NULL;

ALTER TABLE praetore.execution_journal_events
    DROP CONSTRAINT IF EXISTS execution_journal_events_agent_id_request_id_fkey;
ALTER TABLE praetore.execution_journal_events
    DROP CONSTRAINT IF EXISTS execution_journal_events_journal_fk;
ALTER TABLE praetore.execution_attestations
    DROP CONSTRAINT IF EXISTS execution_attestations_agent_id_request_id_fkey;
ALTER TABLE praetore.execution_attestations
    DROP CONSTRAINT IF EXISTS execution_attestations_journal_fk;
ALTER TABLE praetore.human_approvals
    DROP CONSTRAINT IF EXISTS human_approvals_agent_id_request_id_fkey;
ALTER TABLE praetore.human_approvals
    DROP CONSTRAINT IF EXISTS human_approvals_journal_fk;
ALTER TABLE praetore.execution_journal
    DROP CONSTRAINT IF EXISTS execution_journal_replay_claim_fk;
ALTER TABLE praetore.execution_journal
    DROP CONSTRAINT IF EXISTS execution_journal_pkey;
ALTER TABLE praetore.replay_claims
    DROP CONSTRAINT IF EXISTS replay_claims_pkey;
ALTER TABLE praetore.execution_attestations
    DROP CONSTRAINT IF EXISTS execution_attestations_agent_id_request_id_execution_status_key;
ALTER TABLE praetore.execution_attestations
    DROP CONSTRAINT IF EXISTS execution_attestations_identity_status_key;
ALTER TABLE praetore.human_approvals
    DROP CONSTRAINT IF EXISTS human_approvals_agent_id_request_id_key;
ALTER TABLE praetore.human_approvals
    DROP CONSTRAINT IF EXISTS human_approvals_identity_key;

ALTER TABLE praetore.replay_claims
    ALTER COLUMN tenant_id SET NOT NULL,
    ADD CONSTRAINT replay_claims_pkey PRIMARY KEY (tenant_id, agent_id, request_id);
ALTER TABLE praetore.execution_journal
    ALTER COLUMN tenant_id SET NOT NULL,
    ADD CONSTRAINT execution_journal_pkey PRIMARY KEY (tenant_id, agent_id, request_id),
    ADD CONSTRAINT execution_journal_replay_claim_fk
        FOREIGN KEY (tenant_id, agent_id, request_id)
        REFERENCES praetore.replay_claims (tenant_id, agent_id, request_id)
        NOT VALID;
ALTER TABLE praetore.execution_journal_events
    ALTER COLUMN tenant_id SET NOT NULL,
    ADD CONSTRAINT execution_journal_events_journal_fk
        FOREIGN KEY (tenant_id, agent_id, request_id)
        REFERENCES praetore.execution_journal (tenant_id, agent_id, request_id)
        ON DELETE RESTRICT
        NOT VALID;
ALTER TABLE praetore.execution_attestations
    ALTER COLUMN tenant_id SET NOT NULL,
    ADD CONSTRAINT execution_attestations_journal_fk
        FOREIGN KEY (tenant_id, agent_id, request_id)
        REFERENCES praetore.execution_journal (tenant_id, agent_id, request_id)
        ON DELETE RESTRICT
        NOT VALID,
    ADD CONSTRAINT execution_attestations_identity_status_key
        UNIQUE (tenant_id, agent_id, request_id, execution_status);
ALTER TABLE praetore.human_approvals
    ALTER COLUMN tenant_id SET NOT NULL,
    ADD CONSTRAINT human_approvals_journal_fk
        FOREIGN KEY (tenant_id, agent_id, request_id)
        REFERENCES praetore.execution_journal (tenant_id, agent_id, request_id)
        ON DELETE RESTRICT
        NOT VALID,
    ADD CONSTRAINT human_approvals_identity_key
        UNIQUE (tenant_id, agent_id, request_id);

CREATE INDEX IF NOT EXISTS execution_journal_events_tenant_identity
    ON praetore.execution_journal_events
        (tenant_id, agent_id, request_id, event_id);
CREATE INDEX IF NOT EXISTS execution_attestations_tenant_identity
    ON praetore.execution_attestations
        (tenant_id, agent_id, request_id, created_at);

CREATE OR REPLACE FUNCTION praetore.validate_execution_journal_transition()
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
                WHERE approval.tenant_id = OLD.tenant_id
                  AND approval.agent_id = OLD.agent_id
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

CREATE OR REPLACE FUNCTION praetore.record_execution_journal_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, praetore, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO praetore.execution_journal_events
            (tenant_id, agent_id, request_id, from_status, to_status)
        VALUES (
            NEW.tenant_id, NEW.agent_id, NEW.request_id,
            NULL, NEW.execution_status
        );
    ELSIF NEW.execution_status IS DISTINCT FROM OLD.execution_status THEN
        INSERT INTO praetore.execution_journal_events
            (tenant_id, agent_id, request_id, from_status, to_status)
        VALUES (
            NEW.tenant_id, NEW.agent_id, NEW.request_id,
            OLD.execution_status, NEW.execution_status
        );
    END IF;
    RETURN NEW;
END;
$$;

COMMIT;
