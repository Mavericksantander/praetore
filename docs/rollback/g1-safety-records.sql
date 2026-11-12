-- Manual rollback of the G1 safety-record storage: migrations 0018 (audit
-- role, registrations by OID), 0017 (safety_records follow-ups) and 0016
-- (safety_records), together.
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
-- The NOLOGIN groups praetore_safety_ingest and praetore_safety_audit are
-- cluster-wide and other databases may use them: this script only revokes
-- what 0016 and 0018 granted in this database. Drop them separately (DROP
-- ROLE) once no database uses them.
-- Afterwards `praetore-gateway-demo migrate` (schema owner URL in
-- `PRAETORE_GATEWAY_MIGRATION_DATABASE_URL`; `apply_migrations`) applies
-- 0016 to 0018 again from scratch, and `praetore run` also applies pending
-- migrations when it starts.

BEGIN;

-- safety_records has FORCE ROW LEVEL SECURITY: an owner that is not a
-- superuser (or BYPASSRLS) would see no row at all and the check below
-- would pass on a full table. Lifted inside this transaction (and only
-- possible for the owner), so the owner sees every row; the table is
-- dropped below either way.
ALTER TABLE praetore.safety_records NO FORCE ROW LEVEL SECURITY;

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
-- 0018 (absent on a database still at 0017).
DROP TABLE IF EXISTS praetore.safety_audit_tenants;
DROP FUNCTION praetore.check_safety_record_link();
DROP FUNCTION praetore.reject_safety_record_mutation();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'praetore_safety_ingest') THEN
        REVOKE SELECT ON praetore.schema_migrations FROM praetore_safety_ingest;
        REVOKE USAGE ON SCHEMA praetore FROM praetore_safety_ingest;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'praetore_safety_audit') THEN
        REVOKE SELECT ON praetore.schema_migrations FROM praetore_safety_audit;
        REVOKE USAGE ON SCHEMA praetore FROM praetore_safety_audit;
    END IF;
END;
$$;

DELETE FROM praetore.schema_migrations
WHERE version IN ('0016_safety_records', '0017_safety_records_followups',
                  '0018_safety_audit_and_role_oids', '0019_safety_ingest_row_lock');

COMMIT;
