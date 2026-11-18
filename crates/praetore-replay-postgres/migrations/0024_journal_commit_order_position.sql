-- A position per tenant for every journal row, assigned in commit order.
--
-- Until 0024 a tenant's chain was ordered by created_at, which
-- clock_timestamp() sets when the row is inserted, while the row becomes
-- visible only when its transaction commits. A transaction that inserted
-- before another and committed after it, or a database clock that stepped
-- back, placed a row in front of rows already exported, so a head anchored
-- before that moment could no longer be reproduced.
--
--   * praetore.journal_positions holds the next position of each tenant.
--     The BEFORE INSERT trigger execution_journal_position_v1 takes it with
--     INSERT ... ON CONFLICT DO UPDATE in the transaction of the journal
--     INSERT: the row lock is held until COMMIT, so the writers of one
--     tenant are serialized, and a snapshot that sees position k sees every
--     earlier position. A rollback returns the position with the row, so a
--     rolled-back insert leaves no gap. Writers of different tenants do not
--     wait for each other. A sequence or an identity column would assign at
--     INSERT, not in commit order, and leave gaps on rollback.
--   * The trigger always overwrites NEW.chain_seq: the runtime role holds
--     INSERT on the whole table (0011) and cannot choose its own position.
--     Its name sorts after execution_journal_initial_state_v1 (0021), so a
--     row refused by the initial-state rules never takes the lock.
--   * execution_journal.chain_seq is NOT NULL, UNIQUE per tenant and
--     immutable (BEFORE UPDATE trigger execution_journal_position_immutable_v1).
--     The column UPDATE grants of 0011 and 0020 do not include it.
--   * Rows written before 0024 are numbered in the order exports used until
--     now (created_at, request_id, agent_id), so every whole-chain export
--     and every range of an existing journal is the same, byte for byte, as
--     before. Rows that were already out of commit order keep that order.
--
-- The backfill runs with FORCE ROW LEVEL SECURITY lifted on
-- execution_journal for this transaction only (ADD COLUMN already holds
-- ACCESS EXCLUSIVE on the table, so no other session sees that state). The
-- UPDATE leaves execution_status unchanged, so the transition rules accept
-- it and execution_journal_event_log (AFTER UPDATE OF execution_status) is
-- not fired.
--
-- Forward-only; 0001-0023 are not edited. Every new object has a new name.
-- Manual rollback: docs/rollback/0024-journal-commit-order-position.sql.
-- Applied inside the runner's transaction.

CREATE TABLE praetore.journal_positions (
    tenant_id UUID PRIMARY KEY,
    next_seq BIGINT NOT NULL CHECK (next_seq >= 0)
);

REVOKE ALL ON TABLE praetore.journal_positions FROM PUBLIC;

ALTER TABLE praetore.execution_journal ADD COLUMN chain_seq BIGINT;

ALTER TABLE praetore.execution_journal NO FORCE ROW LEVEL SECURITY;

UPDATE praetore.execution_journal journal
SET chain_seq = ordered.position
FROM (
    SELECT tenant_id, agent_id, request_id,
           row_number() OVER (
               PARTITION BY tenant_id
               ORDER BY created_at, request_id, agent_id
           ) - 1 AS position
    FROM praetore.execution_journal
) ordered
WHERE journal.tenant_id = ordered.tenant_id
  AND journal.agent_id = ordered.agent_id
  AND journal.request_id = ordered.request_id;

INSERT INTO praetore.journal_positions (tenant_id, next_seq)
SELECT tenant_id, count(*)
FROM praetore.execution_journal
GROUP BY tenant_id;

ALTER TABLE praetore.execution_journal FORCE ROW LEVEL SECURITY;

ALTER TABLE praetore.execution_journal
    ALTER COLUMN chain_seq SET NOT NULL,
    ADD CONSTRAINT execution_journal_chain_seq_v1 CHECK (chain_seq >= 0),
    ADD CONSTRAINT execution_journal_tenant_chain_seq_v1 UNIQUE (tenant_id, chain_seq);

-- The trigger function runs as the schema owner, which is subject to this
-- policy too: it reaches only the row of the tenant the session writes as.
ALTER TABLE praetore.journal_positions ENABLE ROW LEVEL SECURITY;
ALTER TABLE praetore.journal_positions FORCE ROW LEVEL SECURITY;
CREATE POLICY journal_positions_tenant_isolation ON praetore.journal_positions
USING (
    tenant_id = NULLIF(current_setting('praetore.tenant_id', true), '')::UUID
)
WITH CHECK (
    tenant_id = NULLIF(current_setting('praetore.tenant_id', true), '')::UUID
);

CREATE FUNCTION praetore.assign_execution_journal_position_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, praetore, pg_temp
AS $$
DECLARE
    assigned BIGINT;
BEGIN
    INSERT INTO praetore.journal_positions AS current_position (tenant_id, next_seq)
    VALUES (NEW.tenant_id, 1)
    ON CONFLICT (tenant_id) DO UPDATE
        SET next_seq = current_position.next_seq + 1
    RETURNING current_position.next_seq - 1 INTO assigned;
    NEW.chain_seq := assigned;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION praetore.assign_execution_journal_position_v1() FROM PUBLIC;

CREATE TRIGGER execution_journal_position_v1
BEFORE INSERT ON praetore.execution_journal
FOR EACH ROW EXECUTE FUNCTION praetore.assign_execution_journal_position_v1();

CREATE FUNCTION praetore.reject_execution_journal_position_change_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, praetore, pg_temp
AS $$
BEGIN
    IF NEW.chain_seq IS DISTINCT FROM OLD.chain_seq THEN
        RAISE EXCEPTION 'execution journal chain_seq is immutable';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION praetore.reject_execution_journal_position_change_v1() FROM PUBLIC;

CREATE TRIGGER execution_journal_position_immutable_v1
BEFORE UPDATE ON praetore.execution_journal
FOR EACH ROW EXECUTE FUNCTION praetore.reject_execution_journal_position_change_v1();
