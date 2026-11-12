-- Manual rollback of migration 0019 (tenant row lock of the safety
-- ingester) alone. Run it as the owner of the praetore schema with every
-- ingester stopped:
--
--   psql "$OWNER_URL" -v ON_ERROR_STOP=1 -f docs/rollback/0019-safety-ingest-row-lock.sql
--
-- No record is touched. Afterwards only a release before v0.3.3 can run
-- against the database (it takes the advisory lock again), or
-- `praetore-gateway-demo migrate` (schema owner URL in
-- `PRAETORE_GATEWAY_MIGRATION_DATABASE_URL`) applies 0019 again, and
-- `praetore run` also applies pending migrations when it starts.

BEGIN;

-- DROP COLUMN needs ACCESS EXCLUSIVE on the table: a running ingester holds
-- a row lock there, so fail after 5 s instead of waiting (and queueing every
-- other session behind this one).
SET LOCAL lock_timeout = '5s';

REVOKE UPDATE (lock_anchor) ON praetore.safety_ingest_tenants FROM praetore_safety_ingest;
DROP POLICY lock_own_registration ON praetore.safety_ingest_tenants;
ALTER TABLE praetore.safety_ingest_tenants DROP COLUMN lock_anchor;
DELETE FROM praetore.schema_migrations WHERE version = '0019_safety_ingest_row_lock';

COMMIT;
