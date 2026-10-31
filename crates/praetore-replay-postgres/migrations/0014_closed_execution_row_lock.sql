-- Lock the journal row inside refuse_decision_for_closed_execution, and
-- drop the transition function 0010 left behind.
--
-- 0013 refuses a human decision for an execution closed with a reason, but
-- its SELECT does not lock execution_journal. The insert only waits for a
-- concurrent close because human_approvals_exclusive (0009) takes FOR UPDATE
-- and its name sorts before human_approvals_refuse_closed_execution. This
-- replaces the function so the exclusion locks the journal row itself.
-- The predicate stays out of the locked query: a WHERE on
-- not_dispatched_reason would not wait for an update that is setting it.
--
-- 0013 dropped the trigger on validate_execution_journal_transition_v2 and
-- left the function. Drop it only after checking that no trigger still
-- calls it. 0013 is not edited. Forward-only; applied inside the runner's
-- transaction. The function stays invoker-rights (not SECURITY DEFINER).

CREATE OR REPLACE FUNCTION praetore.refuse_decision_for_closed_execution()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, praetore, pg_temp
AS $$
DECLARE
    closed_reason TEXT;
BEGIN
    SELECT journal.not_dispatched_reason
    INTO closed_reason
    FROM praetore.execution_journal journal
    WHERE journal.tenant_id = NEW.tenant_id
      AND journal.agent_id = NEW.agent_id
      AND journal.request_id = NEW.request_id
    FOR UPDATE;

    IF closed_reason IS NOT NULL THEN
        RAISE EXCEPTION 'execution is closed without dispatch; no decision can be recorded';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION praetore.refuse_decision_for_closed_execution() FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_trigger AS tg
        JOIN pg_catalog.pg_proc AS proc ON proc.oid = tg.tgfoid
        JOIN pg_catalog.pg_namespace AS ns ON ns.oid = proc.pronamespace
        WHERE ns.nspname = 'praetore'
          AND proc.proname = 'validate_execution_journal_transition_v2'
    ) THEN
        RAISE EXCEPTION
            'validate_execution_journal_transition_v2 is still referenced by a trigger';
    END IF;
END;
$$;

DROP FUNCTION praetore.validate_execution_journal_transition_v2();
