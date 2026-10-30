-- Least-privilege group role for the gateway runtime connection.
--
-- The migration (owner) role and the runtime role must differ: a table owner
-- can ALTER TABLE ... NO FORCE ROW LEVEL SECURITY or DISABLE TRIGGER, and a
-- superuser or BYPASSRLS role ignores row-level security entirely. The
-- gateway refuses a runtime connection that is privileged, owns anything in
-- schema praetore or can CREATE in it (verify_runtime_role).
--
-- praetore_runtime is NOLOGIN. Operators create the login role and grant
-- membership, for example:
--   CREATE ROLE praetore_gateway LOGIN PASSWORD '...' IN ROLE praetore_runtime;
-- Roles are cluster-wide; the grants below are per database. Creating the
-- role needs CREATEROLE; a DBA may pre-create it instead, in which case this
-- migration only grants. Forward-only, applied inside the runner's
-- transaction (no BEGIN/COMMIT here).
--
-- Grants follow the statements in src/execution.rs and src/lib.rs:
--   replay_claims               SELECT, INSERT (ON CONFLICT DO NOTHING)
--   execution_journal           SELECT, INSERT, UPDATE of the mutable columns
--                               (SELECT ... FOR UPDATE needs UPDATE on a column)
--   execution_journal_events    SELECT (rows are written by the SECURITY
--                               DEFINER trigger, owned by the migration role)
--   execution_attestations      SELECT, INSERT
--   human_approvals             SELECT, INSERT
--   human_approval_expirations  SELECT, INSERT
--   schema_migrations           SELECT (startup schema check)
-- No DELETE, TRUNCATE, REFERENCES, TRIGGER or CREATE.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'praetore_runtime') THEN
        CREATE ROLE praetore_runtime
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
EXCEPTION
    -- Another database in the same cluster created it concurrently.
    WHEN duplicate_object OR unique_violation THEN NULL;
END;
$$;

REVOKE ALL ON SCHEMA praetore FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA praetore FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA praetore FROM PUBLIC;

GRANT USAGE ON SCHEMA praetore TO praetore_runtime;
GRANT SELECT ON praetore.schema_migrations TO praetore_runtime;
GRANT SELECT, INSERT ON praetore.replay_claims TO praetore_runtime;
GRANT SELECT, INSERT ON praetore.execution_journal TO praetore_runtime;
GRANT UPDATE (execution_status, output_json, not_dispatched_reason, updated_at)
    ON praetore.execution_journal TO praetore_runtime;
GRANT SELECT ON praetore.execution_journal_events TO praetore_runtime;
GRANT SELECT, INSERT ON praetore.execution_attestations TO praetore_runtime;
GRANT SELECT, INSERT ON praetore.human_approvals TO praetore_runtime;
GRANT SELECT, INSERT ON praetore.human_approval_expirations TO praetore_runtime;
