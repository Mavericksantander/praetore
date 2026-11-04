-- G1 (R7): the tenant lock of praetore-safety-ingest becomes a row lock on
-- the ingester's own registration in praetore.safety_ingest_tenants,
-- replacing the session advisory lock, which any role of the cluster could
-- take for any tenant.
--
-- SELECT ... FOR UPDATE needs UPDATE on a column and passes the table's
-- UPDATE policies. So:
-- * lock_anchor is a column with no meaning, the only one
--   praetore_safety_ingest may UPDATE;
-- * the UPDATE policy shows a login role only its own registration (by the
--   OID of SESSION_USER), and its WITH CHECK (false) refuses every actual
--   UPDATE: the row can be locked, never changed, by that role.
-- A role that is not registered, registered for another tenant or not a
-- member of praetore_safety_ingest locks nothing, and the ingester then
-- refuses to start. The table owner is not subject to row-level security
-- here (as before) and can still lock or change any row.
--
-- Applied inside the runner's transaction (no BEGIN/COMMIT here). Reversible
-- with docs/rollback/0019-safety-ingest-row-lock.sql.

ALTER TABLE praetore.safety_ingest_tenants
    ADD COLUMN lock_anchor BOOLEAN NOT NULL DEFAULT true;
CREATE POLICY lock_own_registration ON praetore.safety_ingest_tenants
FOR UPDATE
TO praetore_safety_ingest
USING (role_oid OPERATOR(pg_catalog.=)
       (SELECT r.oid FROM pg_catalog.pg_roles r
        WHERE r.rolname OPERATOR(pg_catalog.=) SESSION_USER))
WITH CHECK (false);
GRANT UPDATE (lock_anchor) ON praetore.safety_ingest_tenants TO praetore_safety_ingest;
