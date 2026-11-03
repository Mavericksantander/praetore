-- Manual rollback of the G1 safety-record storage: migrations 0017
-- (safety_records follow-ups) and 0016 (safety_records), together.
--
-- Outside the migration runner, which is forward-only. Run it as the owner
-- of the praetore schema with every ingester stopped:
--
--   psql "$OWNER_URL" -v ON_ERROR_STOP=1 \
--     -c "SET praetore.rollback_confirm = 'destroy-safety-records'" \
--     -f docs/rollback/g1-safety-records.sql
--
-- It DESTROYS every safety record. Export and verify every chain first
-- (`praetore journal-export --safety`, `praetore-verify safety-journal`).
-- Without the confirmation setting it refuses to run while records exist.
--
-- The NOLOGIN group praetore_safety_ingest is cluster-wide and other
-- databases may use it: this script only revokes what 0016 granted in this
-- database. Drop the group separately (DROP ROLE) once no database uses it.
-- Afterwards `praetore migrate` (apply_migrations) applies 0016 and 0017
-- again from scratch.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM praetore.safety_records)
       AND current_setting('praetore.rollback_confirm', true)
           IS DISTINCT FROM 'destroy-safety-records' THEN
        RAISE EXCEPTION 'praetore.safety_records holds records; export them, then SET praetore.rollback_confirm = ''destroy-safety-records''';
    END IF;
END;
$$;

DROP TABLE praetore.safety_records;
DROP TABLE praetore.safety_ingest_tenants;
DROP FUNCTION praetore.check_safety_record_link();
DROP FUNCTION praetore.reject_safety_record_mutation();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'praetore_safety_ingest') THEN
        REVOKE SELECT ON praetore.schema_migrations FROM praetore_safety_ingest;
        REVOKE USAGE ON SCHEMA praetore FROM praetore_safety_ingest;
    END IF;
END;
$$;

DELETE FROM praetore.schema_migrations
WHERE version IN ('0016_safety_records', '0017_safety_records_followups');

COMMIT;
