-- Manual rollback of migration 0021 (INSERT rules of the execution journal
-- and of its attestations) alone. Run it as the owner of the praetore
-- schema with every gateway stopped:
--
--   psql "$OWNER_URL" -v ON_ERROR_STOP=1 -f docs/rollback/0021-journal-insert-rules.sql
--
-- No row is read or rewritten: 0021 only refuses new rows. It fails, and
-- changes nothing, if a migration newer than 0021 is recorded (roll that
-- one back first) or if 0021's triggers are not exactly the ones it
-- created. Afterwards only a release without 0021 can run against the
-- database, or `praetore migrate` applies 0021 again.

BEGIN;

-- The trigger changes need ACCESS EXCLUSIVE on the tables: fail after 5 s
-- instead of queueing every other session behind this one.
SET LOCAL lock_timeout = '5s';

DO $guard$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM praetore.schema_migrations
                   WHERE version = '0021_journal_insert_rules') THEN
        RAISE EXCEPTION '0021_journal_insert_rules is not recorded';
    END IF;
    IF EXISTS (SELECT 1 FROM praetore.schema_migrations
               WHERE version > '0021_journal_insert_rules') THEN
        RAISE EXCEPTION 'a migration newer than 0021 is recorded: roll it back first';
    END IF;
END
$guard$;

-- Exact names, no IF EXISTS: a missing object aborts the whole rollback.
DROP TRIGGER execution_journal_initial_state_v1 ON praetore.execution_journal;
DROP TRIGGER execution_attestations_journal_state_v1 ON praetore.execution_attestations;
DROP FUNCTION praetore.validate_execution_journal_insert_v1();
DROP FUNCTION praetore.validate_execution_attestation_insert_v1();

DELETE FROM praetore.schema_migrations WHERE version = '0021_journal_insert_rules';

COMMIT;
