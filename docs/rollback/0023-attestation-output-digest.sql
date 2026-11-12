-- Manual rollback of migration 0023 (the attestation output_digest
-- comparison) alone. Run it as the owner of the praetore schema with every
-- gateway stopped:
--
--   psql "$OWNER_URL" -v ON_ERROR_STOP=1 -f docs/rollback/0023-attestation-output-digest.sql
--
-- No row is read or rewritten: 0023 only refuses a new attestation whose
-- output_digest does not match the journal row. It fails, and changes
-- nothing, if 0023 is not recorded, if a migration newer than 0023 is
-- recorded (roll that one back first), or if 0023's trigger and functions
-- are not the ones it created. Afterwards only a release without 0023 can
-- run against the database, or `praetore-gateway-demo migrate` applies
-- 0023 again.

BEGIN;

-- The trigger change needs ACCESS EXCLUSIVE on the attestation table:
-- fail after 5 s instead of queueing every other session behind this one.
SET LOCAL lock_timeout = '5s';

DO $guard$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM praetore.schema_migrations
                   WHERE version = '0023_attestation_output_digest') THEN
        RAISE EXCEPTION '0023_attestation_output_digest is not recorded';
    END IF;
    IF EXISTS (SELECT 1 FROM praetore.schema_migrations
               WHERE version > '0023_attestation_output_digest') THEN
        RAISE EXCEPTION 'a migration newer than 0023 is recorded: roll it back first';
    END IF;
END
$guard$;

-- Exact names, no IF EXISTS: a missing object aborts the whole rollback.
DROP TRIGGER execution_attestations_journal_state_v3 ON praetore.execution_attestations;
CREATE TRIGGER execution_attestations_journal_state_v2
BEFORE INSERT ON praetore.execution_attestations
FOR EACH ROW EXECUTE FUNCTION praetore.validate_execution_attestation_insert_v2();
DROP FUNCTION praetore.validate_execution_attestation_insert_v3();
DROP FUNCTION praetore.execution_output_digest_v1(pg_catalog.text);

DELETE FROM praetore.schema_migrations WHERE version = '0023_attestation_output_digest';

COMMIT;
