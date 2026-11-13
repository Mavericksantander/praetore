-- Manual rollback of migration 0024 (the per-tenant journal position in
-- commit order) alone. Run it as the owner of the praetore schema with every
-- gateway stopped:
--
--   psql "$OWNER_URL" -v ON_ERROR_STOP=1 -f docs/rollback/0024-journal-commit-order-position.sql
--
-- It drops execution_journal.chain_seq and praetore.journal_positions:
-- exports order the tenant's rows by (created_at, request_id, agent_id)
-- again. Rows written while 0024 was applied are then ordered by
-- created_at, which may differ from their commit order, so a head anchored
-- while 0024 was applied may no longer be reproduced after the rollback.
-- It fails, and changes nothing, if 0024 is not recorded, if a migration
-- newer than 0024 is recorded (roll that one back first), or if 0024's
-- objects are not the ones it created. Afterwards only a release without
-- 0024 can run against the database, or `praetore-gateway-demo migrate`
-- applies 0024 again (it numbers every row again in created_at order).

BEGIN;

-- Dropping a column and triggers needs ACCESS EXCLUSIVE on the journal:
-- fail after 5 s instead of queueing every other session behind this one.
SET LOCAL lock_timeout = '5s';

DO $guard$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM praetore.schema_migrations
                   WHERE version = '0024_journal_commit_order_position') THEN
        RAISE EXCEPTION '0024_journal_commit_order_position is not recorded';
    END IF;
    IF EXISTS (SELECT 1 FROM praetore.schema_migrations
               WHERE version > '0024_journal_commit_order_position') THEN
        RAISE EXCEPTION 'a migration newer than 0024 is recorded: roll it back first';
    END IF;
END
$guard$;

-- Exact names, no IF EXISTS: a missing object aborts the whole rollback.
DROP TRIGGER execution_journal_position_immutable_v1 ON praetore.execution_journal;
DROP TRIGGER execution_journal_position_v1 ON praetore.execution_journal;
DROP FUNCTION praetore.reject_execution_journal_position_change_v1();
DROP FUNCTION praetore.assign_execution_journal_position_v1();
ALTER TABLE praetore.execution_journal
    DROP CONSTRAINT execution_journal_tenant_chain_seq_v1,
    DROP CONSTRAINT execution_journal_chain_seq_v1,
    DROP COLUMN chain_seq;
DROP POLICY journal_positions_tenant_isolation ON praetore.journal_positions;
DROP TABLE praetore.journal_positions;

DELETE FROM praetore.schema_migrations WHERE version = '0024_journal_commit_order_position';

COMMIT;
