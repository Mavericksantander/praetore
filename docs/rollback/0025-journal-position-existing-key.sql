-- Manual rollback of migration 0025 (an existing journal primary key must
-- not take a position) alone. Run it as the owner of the praetore schema
-- with every gateway stopped:
--
--   psql "$OWNER_URL" -v ON_ERROR_STOP=1 -f docs/rollback/0025-journal-position-existing-key.sql
--
-- It points execution_journal_position_v1 back at
-- assign_execution_journal_position_v1 and drops
-- assign_execution_journal_position_v2. No row is read or rewritten.
-- It fails, and changes nothing, if 0025 is not recorded, if a migration
-- newer than 0025 is recorded (roll that one back first), or if 0025's
-- function and trigger are not the ones it created. Afterwards only a
-- release without 0025 can run against the database, or
-- `praetore-gateway-demo migrate` (schema owner URL in
-- `PRAETORE_GATEWAY_MIGRATION_DATABASE_URL`) applies 0025 again, and
-- `praetore run` also applies pending migrations when it starts.

BEGIN;

-- Replacing the trigger needs ACCESS EXCLUSIVE on the journal: fail after
-- 5 s instead of queueing every other session behind this one.
SET LOCAL lock_timeout = '5s';

DO $guard$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM praetore.schema_migrations
                   WHERE version = '0025_journal_position_existing_key') THEN
        RAISE EXCEPTION '0025_journal_position_existing_key is not recorded';
    END IF;
    IF EXISTS (SELECT 1 FROM praetore.schema_migrations
               WHERE version > '0025_journal_position_existing_key') THEN
        RAISE EXCEPTION 'a migration newer than 0025 is recorded: roll it back first';
    END IF;
END
$guard$;

-- Exact names, no IF EXISTS: a missing object aborts the whole rollback.
DROP TRIGGER execution_journal_position_v1 ON praetore.execution_journal;
CREATE TRIGGER execution_journal_position_v1
BEFORE INSERT ON praetore.execution_journal
FOR EACH ROW EXECUTE FUNCTION praetore.assign_execution_journal_position_v1();
DROP FUNCTION praetore.assign_execution_journal_position_v2();

DELETE FROM praetore.schema_migrations WHERE version = '0025_journal_position_existing_key';

COMMIT;
