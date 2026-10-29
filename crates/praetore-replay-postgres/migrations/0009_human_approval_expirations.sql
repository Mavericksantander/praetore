-- SAF-10: signed approval-expiration receipts.
-- Forward-only (CTO, 29-oct-2026): this is append-only evidence, so there is
-- no down migration. To revert, ship a compensating migration that disables
-- writes without touching stored rows. Safe to re-apply.
BEGIN;

CREATE TABLE IF NOT EXISTS praetore.human_approval_expirations (
    tenant_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    request_id UUID NOT NULL,
    evidence_id UUID NOT NULL,
    evidence_hash CHAR(64) NOT NULL CHECK (evidence_hash ~ '^[0-9a-f]{64}$'),
    action_digest CHAR(64) NOT NULL CHECK (action_digest ~ '^[0-9a-f]{64}$'),
    policy_digest CHAR(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    expires_at TIMESTAMPTZ NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    gateway_key_id TEXT NOT NULL
        CHECK (length(gateway_key_id) BETWEEN 1 AND 256
               AND gateway_key_id = btrim(gateway_key_id)),
    signature CHAR(128) NOT NULL CHECK (signature ~ '^[0-9a-f]{128}$'),
    receipt_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT human_approval_expirations_observed_after_expiry
        CHECK (observed_at >= expires_at),
    CONSTRAINT human_approval_expirations_pkey
        PRIMARY KEY (tenant_id, agent_id, request_id)
);

-- The reference to execution_journal is enforced by triggers instead of a
-- FOREIGN KEY: migration 0007 is re-applied on every start and drops and
-- recreates execution_journal_pkey, which a FK from this table would block.
-- Insert requires the journal row (see enforce_approval_resolution_exclusive)
-- and deleting a journal row with an expiration is rejected (ON DELETE
-- RESTRICT semantics).
CREATE OR REPLACE FUNCTION praetore.restrict_journal_delete_with_expiration()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM praetore.human_approval_expirations expiration
        WHERE expiration.tenant_id = OLD.tenant_id
          AND expiration.agent_id = OLD.agent_id
          AND expiration.request_id = OLD.request_id
    ) THEN
        RAISE EXCEPTION 'execution journal row is referenced by an approval expiration';
    END IF;
    RETURN OLD;
END;
$$;

REVOKE ALL ON FUNCTION praetore.restrict_journal_delete_with_expiration() FROM PUBLIC;

DROP TRIGGER IF EXISTS execution_journal_expiration_restrict
    ON praetore.execution_journal;
CREATE TRIGGER execution_journal_expiration_restrict
BEFORE DELETE ON praetore.execution_journal
FOR EACH ROW EXECUTE FUNCTION praetore.restrict_journal_delete_with_expiration();

CREATE OR REPLACE FUNCTION praetore.reject_human_approval_expiration_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'human approval expiration records are append-only';
END;
$$;

REVOKE ALL ON FUNCTION praetore.reject_human_approval_expiration_mutation() FROM PUBLIC;

DROP TRIGGER IF EXISTS human_approval_expirations_immutable
    ON praetore.human_approval_expirations;
CREATE TRIGGER human_approval_expirations_immutable
BEFORE UPDATE OR DELETE ON praetore.human_approval_expirations
FOR EACH ROW EXECUTE FUNCTION praetore.reject_human_approval_expiration_mutation();

DROP TRIGGER IF EXISTS human_approval_expirations_no_truncate
    ON praetore.human_approval_expirations;
CREATE TRIGGER human_approval_expirations_no_truncate
BEFORE TRUNCATE ON praetore.human_approval_expirations
FOR EACH STATEMENT EXECUTE FUNCTION praetore.reject_human_approval_expiration_mutation();

-- Exclusion: a key never has both a human decision and an expiration. Each
-- insert locks the journal row first, so concurrent writers serialize.
CREATE OR REPLACE FUNCTION praetore.enforce_approval_resolution_exclusive()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    journal_authorization TEXT;
    journal_execution TEXT;
BEGIN
    SELECT authorization_status, execution_status
    INTO journal_authorization, journal_execution
    FROM praetore.execution_journal
    WHERE tenant_id = NEW.tenant_id
      AND agent_id = NEW.agent_id
      AND request_id = NEW.request_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'approval resolution requires a journal record';
    END IF;

    IF TG_TABLE_NAME = 'human_approval_expirations' THEN
        IF journal_authorization <> 'requires_approval'
            OR journal_execution <> 'not_dispatched' THEN
            RAISE EXCEPTION 'approval expiration requires a pending approval';
        END IF;
        IF EXISTS (
            SELECT 1 FROM praetore.human_approvals approval
            WHERE approval.tenant_id = NEW.tenant_id
              AND approval.agent_id = NEW.agent_id
              AND approval.request_id = NEW.request_id
        ) THEN
            RAISE EXCEPTION 'approval already decided by a human';
        END IF;
    ELSE
        IF EXISTS (
            SELECT 1 FROM praetore.human_approval_expirations expiration
            WHERE expiration.tenant_id = NEW.tenant_id
              AND expiration.agent_id = NEW.agent_id
              AND expiration.request_id = NEW.request_id
        ) THEN
            RAISE EXCEPTION 'approval already expired';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION praetore.enforce_approval_resolution_exclusive() FROM PUBLIC;

DROP TRIGGER IF EXISTS human_approval_expirations_exclusive
    ON praetore.human_approval_expirations;
CREATE TRIGGER human_approval_expirations_exclusive
BEFORE INSERT ON praetore.human_approval_expirations
FOR EACH ROW EXECUTE FUNCTION praetore.enforce_approval_resolution_exclusive();

DROP TRIGGER IF EXISTS human_approvals_exclusive
    ON praetore.human_approvals;
CREATE TRIGGER human_approvals_exclusive
BEFORE INSERT ON praetore.human_approvals
FOR EACH ROW EXECUTE FUNCTION praetore.enforce_approval_resolution_exclusive();

ALTER TABLE praetore.human_approval_expirations ENABLE ROW LEVEL SECURITY;
ALTER TABLE praetore.human_approval_expirations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON praetore.human_approval_expirations;
CREATE POLICY tenant_isolation ON praetore.human_approval_expirations
    USING (
        tenant_id = NULLIF(current_setting('praetore.tenant_id', true), '')::UUID
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('praetore.tenant_id', true), '')::UUID
    );

REVOKE ALL ON TABLE praetore.human_approval_expirations FROM PUBLIC;

COMMIT;
