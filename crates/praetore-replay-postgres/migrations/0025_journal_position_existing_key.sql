-- An INSERT whose primary key is already in execution_journal must not
-- take a position.
--
-- The BEFORE INSERT trigger execution_journal_position_v1 (0024) assigned
-- chain_seq before PostgreSQL resolved a primary-key conflict. An
-- INSERT ... ON CONFLICT DO NOTHING, or DO UPDATE, therefore committed the
-- counter update in praetore.journal_positions and discarded the row. The
-- tenant's chain_seq values gained a permanent gap. chain_seq is immutable,
-- so the gap cannot be filled, and every later export or verification of
-- that tenant fails with an error that describes a deleted or hand-written
-- row.
--
-- assign_execution_journal_position_v2 takes the same tenant counter lock
-- as v1 and then refuses the row when that primary key is already present.
-- The exception aborts the INSERT, so the counter update is undone and no
-- position is consumed. v1 stays, and the rollback points the trigger back
-- at it. The trigger keeps its name, which still sorts after
-- execution_journal_initial_state_v1, so a row the initial-state rules
-- refuse still never takes the lock.
--
-- Forward-only; 0001-0024 are not edited. Every new object has a new name.
-- Manual rollback: docs/rollback/0025-journal-position-existing-key.sql.
-- Applied inside the runner's transaction.

CREATE FUNCTION praetore.assign_execution_journal_position_v2()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, praetore, pg_temp
AS $$
DECLARE
    assigned BIGINT;
BEGIN
    -- The row lock on the tenant's counter is held until this statement
    -- ends. A primary key that is already present raises below, which
    -- aborts the statement and undoes this update, so the position is not
    -- consumed. A new row keeps the value assigned here.
    INSERT INTO praetore.journal_positions AS current_position (tenant_id, next_seq)
    VALUES (NEW.tenant_id, 1)
    ON CONFLICT (tenant_id) DO UPDATE
        SET next_seq = current_position.next_seq + 1
    RETURNING current_position.next_seq - 1 INTO assigned;
    IF EXISTS (
        SELECT 1
        FROM praetore.execution_journal journal
        WHERE journal.tenant_id = NEW.tenant_id
          AND journal.agent_id = NEW.agent_id
          AND journal.request_id = NEW.request_id
    ) THEN
        RAISE EXCEPTION 'execution journal row already exists'
            USING ERRCODE = 'unique_violation';
    END IF;
    NEW.chain_seq := assigned;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION praetore.assign_execution_journal_position_v2() FROM PUBLIC;
REVOKE ALL ON FUNCTION praetore.assign_execution_journal_position_v2() FROM praetore_runtime;

DROP TRIGGER execution_journal_position_v1 ON praetore.execution_journal;
CREATE TRIGGER execution_journal_position_v1
BEFORE INSERT ON praetore.execution_journal
FOR EACH ROW EXECUTE FUNCTION praetore.assign_execution_journal_position_v2();
