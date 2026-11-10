-- Rows of the execution journal and of its attestations are accepted on
-- INSERT only in the shapes the gateway's state machine writes (T-015).
--
-- Until 0021 the journal's transition rules (0002, 0010, 0012, 0013, 0020)
-- ran only BEFORE UPDATE: an INSERT could create a row in any state the
-- CHECK constraints allow, and an attestation row could name a state the
-- journal row never had. The gateway itself never writes such rows; these
-- triggers make the database refuse them too, as defense in depth for code
-- paths that skip the gateway's checks. They do not defend against the
-- schema owner or a superuser.
--
--   * execution_journal: a row starts as `authorized` (allowed) or
--     `not_dispatched` (requires_approval, denied), with no output, no
--     not_dispatched_reason and no failure class. Every later state is
--     reached through the UPDATE rules.
--   * execution_attestations: an attestation is accepted only for the
--     journal row's current state, with the same not_dispatched_reason and
--     failure class, and its signed JSON names that same tenant, agent,
--     request, action digest, authorization and state. The journal's
--     evidence_json is TEXT and is not parsed here: it may carry escapes
--     such as \u0000 that PostgreSQL's JSON types refuse. The gateway inserts each
--     attestation in the transaction that moves the row to that state, or
--     while the row is in it, so every attestation it writes passes.
--
-- Rows written before 0021 are not checked or rewritten.
--
-- Forward-only; 0001-0020 are not edited. Every new object has a new name.
-- Manual rollback: docs/rollback/0021-journal-insert-rules.sql.
-- Applied inside the runner's transaction.

CREATE FUNCTION praetore.validate_execution_journal_insert_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, praetore, pg_temp
AS $$
BEGIN
    IF NOT COALESCE(
        ((NEW.authorization_status = 'allowed'
                AND NEW.execution_status = 'authorized')
            OR (NEW.authorization_status IN ('requires_approval', 'denied')
                AND NEW.execution_status = 'not_dispatched'))
        AND NEW.output_json IS NULL
        AND NEW.not_dispatched_reason IS NULL
        AND NEW.failure_class IS NULL
        AND NEW.failure_reason IS NULL,
        false) THEN
        RAISE EXCEPTION 'invalid initial execution journal state: % / %',
            NEW.authorization_status, NEW.execution_status;
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION praetore.validate_execution_journal_insert_v1() FROM PUBLIC;

CREATE TRIGGER execution_journal_initial_state_v1
BEFORE INSERT ON praetore.execution_journal
FOR EACH ROW EXECUTE FUNCTION praetore.validate_execution_journal_insert_v1();

CREATE FUNCTION praetore.validate_execution_attestation_insert_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, praetore, pg_temp
AS $$
DECLARE
    journal RECORD;
BEGIN
    -- Invoker rights: the row must be visible to the inserting role under
    -- row level security, so an attestation for another tenant's row is
    -- refused like a missing one. FOR SHARE keeps the row's state fixed
    -- until this transaction ends.
    SELECT current_row.authorization_status, current_row.execution_status,
           current_row.not_dispatched_reason, current_row.failure_class,
           current_row.failure_reason, current_row.action_digest
      INTO journal
      FROM praetore.execution_journal current_row
     WHERE current_row.tenant_id = NEW.tenant_id
       AND current_row.agent_id = NEW.agent_id
       AND current_row.request_id = NEW.request_id
       FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'execution attestation has no visible journal row';
    END IF;

    IF NOT COALESCE(
        NEW.execution_status = journal.execution_status
        AND NEW.not_dispatched_reason IS NOT DISTINCT FROM journal.not_dispatched_reason
        AND NEW.failure_class IS NOT DISTINCT FROM journal.failure_class
        AND NEW.failure_reason IS NOT DISTINCT FROM journal.failure_reason
        AND jsonb_typeof(NEW.attestation_json) = 'object'
        AND NEW.attestation_json ->> 'execution' = NEW.execution_status
        AND NEW.attestation_json ->> 'authorization' = journal.authorization_status
        AND NEW.attestation_json ->> 'tenant_id' = NEW.tenant_id::text
        AND NEW.attestation_json ->> 'agent_id' = NEW.agent_id::text
        AND NEW.attestation_json ->> 'request_id' = NEW.request_id::text
        AND NEW.attestation_json ->> 'action_digest' = journal.action_digest,
        false) THEN
        RAISE EXCEPTION 'execution attestation does not match the journal state: % (journal %)',
            NEW.execution_status, journal.execution_status;
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION praetore.validate_execution_attestation_insert_v1() FROM PUBLIC;

CREATE TRIGGER execution_attestations_journal_state_v1
BEFORE INSERT ON praetore.execution_attestations
FOR EACH ROW EXECUTE FUNCTION praetore.validate_execution_attestation_insert_v1();
