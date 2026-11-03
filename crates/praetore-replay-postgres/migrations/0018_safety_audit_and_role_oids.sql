-- G1: registrations by role OID, and a read-only role to export and audit
-- safety records.
--
-- * praetore.safety_ingest_tenants registers a login role by its OID, not
--   its name: a role dropped and created again with the same name (by
--   mistake, or by someone with CREATEROLE) is a new role and does not
--   inherit the old one's tenant. Existing rows are converted; a row whose
--   role no longer exists makes this migration fail (delete it first).
--   Register a role with its name cast to regrole:
--     INSERT INTO praetore.safety_ingest_tenants (role_oid, tenant_id, ingest_key_id)
--     VALUES ('<login role>'::regrole, '<tenant uuid>', '<ingestion key id>');
-- * praetore_safety_audit is the NOLOGIN group of read-only login roles that
--   export and audit safety records. The schema owner registers each one in
--   praetore.safety_audit_tenants for the tenants it may read (one row per
--   tenant). It can read those tenants' records and its own registrations,
--   and nothing else: no INSERT, no other table. Created here when it does
--   not exist (CREATEROLE, as for 0016), otherwise only granted to.
-- * The policy of praetore_safety_ingest's login roles now applies to that
--   group only, so that a role of the other group never evaluates it.
--
-- Forward-only, applied inside the runner's transaction (no BEGIN/COMMIT
-- here). docs/operations.md has the manual rollback of 0016 to 0018.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'praetore_safety_audit') THEN
        CREATE ROLE praetore_safety_audit
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
EXCEPTION
    -- Another database in the same cluster created it concurrently.
    WHEN duplicate_object OR unique_violation THEN NULL;
END;
$$;

-- Registrations by OID.
DROP POLICY registered_tenant ON praetore.safety_records;
DROP POLICY own_registration ON praetore.safety_ingest_tenants;
ALTER TABLE praetore.safety_ingest_tenants ADD COLUMN role_oid OID;
UPDATE praetore.safety_ingest_tenants t
SET role_oid = r.oid
FROM pg_catalog.pg_roles r
WHERE r.rolname OPERATOR(pg_catalog.=) t.role_name;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM praetore.safety_ingest_tenants WHERE role_oid IS NULL) THEN
        RAISE EXCEPTION 'praetore.safety_ingest_tenants registers a role that no longer exists; delete that row first';
    END IF;
END;
$$;
ALTER TABLE praetore.safety_ingest_tenants
    DROP CONSTRAINT safety_ingest_tenants_pkey,
    DROP COLUMN role_name,
    ALTER COLUMN role_oid SET NOT NULL,
    ADD CONSTRAINT safety_ingest_tenants_pkey PRIMARY KEY (role_oid);
CREATE POLICY own_registration ON praetore.safety_ingest_tenants
FOR SELECT
USING (role_oid OPERATOR(pg_catalog.=)
       (SELECT r.oid FROM pg_catalog.pg_roles r
        WHERE r.rolname OPERATOR(pg_catalog.=) SESSION_USER));
CREATE POLICY registered_tenant ON praetore.safety_records
TO praetore_safety_ingest
USING (
    tenant_id = (SELECT t.tenant_id FROM praetore.safety_ingest_tenants t
                 WHERE t.role_oid OPERATOR(pg_catalog.=)
                       (SELECT r.oid FROM pg_catalog.pg_roles r
                        WHERE r.rolname OPERATOR(pg_catalog.=) SESSION_USER))
)
WITH CHECK (
    tenant_id = (SELECT t.tenant_id FROM praetore.safety_ingest_tenants t
                 WHERE t.role_oid OPERATOR(pg_catalog.=)
                       (SELECT r.oid FROM pg_catalog.pg_roles r
                        WHERE r.rolname OPERATOR(pg_catalog.=) SESSION_USER))
);

-- The insert trigger compares the key of the registration by OID.
CREATE OR REPLACE FUNCTION praetore.check_safety_record_link()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    body JSONB;
    previous TEXT;
BEGIN
    body := NEW.record_json::JSONB;
    IF body->>'tenant_id' IS DISTINCT FROM NEW.tenant_id::TEXT
       OR body->>'chain' IS DISTINCT FROM NEW.chain
       OR (body->>'chain_seq')::BIGINT IS DISTINCT FROM NEW.chain_seq
       OR body->>'record_id' IS DISTINCT FROM NEW.record_id::TEXT
       OR body->>'status' IS DISTINCT FROM NEW.status
       OR (body->'event'->>'source_seq')::BIGINT IS DISTINCT FROM NEW.source_seq
       OR body->>'event_hash' IS DISTINCT FROM NEW.event_hash::TEXT
       OR body->>'prev_record_hash' IS DISTINCT FROM NEW.prev_record_hash::TEXT
       OR body->>'record_hash' IS DISTINCT FROM NEW.record_hash::TEXT
       OR COALESCE((body->>'high_water')::BIGINT, 0) IS DISTINCT FROM NEW.high_water
       OR (body->>'source_epoch')::BIGINT IS DISTINCT FROM NEW.source_epoch THEN
        RAISE EXCEPTION 'safety record columns do not match record_json';
    END IF;
    IF body->>'key_id' IS DISTINCT FROM
       (SELECT t.ingest_key_id::TEXT FROM praetore.safety_ingest_tenants t
        WHERE t.role_oid OPERATOR(pg_catalog.=)
              (SELECT r.oid FROM pg_catalog.pg_roles r
               WHERE r.rolname OPERATOR(pg_catalog.=) SESSION_USER)
          AND t.tenant_id = NEW.tenant_id) THEN
        RAISE EXCEPTION 'safety record is not signed by the ingestion key registered for its tenant';
    END IF;
    IF NEW.chain_seq = 0 THEN
        IF NEW.prev_record_hash::TEXT <> repeat('0', 64) THEN
            RAISE EXCEPTION 'the first safety record of a chain must link to 64 zeros';
        END IF;
    ELSE
        SELECT r.record_hash::TEXT INTO previous
        FROM praetore.safety_records r
        WHERE r.tenant_id = NEW.tenant_id
          AND r.chain = NEW.chain
          AND r.chain_seq = NEW.chain_seq - 1;
        IF previous IS NULL OR previous <> NEW.prev_record_hash::TEXT THEN
            RAISE EXCEPTION 'safety record does not extend its chain';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION praetore.check_safety_record_link() FROM PUBLIC;

-- Read-only export and audit.
CREATE TABLE praetore.safety_audit_tenants (
    role_oid OID NOT NULL,
    tenant_id UUID NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (role_oid, tenant_id)
);
REVOKE ALL ON TABLE praetore.safety_audit_tenants FROM PUBLIC;
ALTER TABLE praetore.safety_audit_tenants ENABLE ROW LEVEL SECURITY;
CREATE POLICY own_audit_registration ON praetore.safety_audit_tenants
FOR SELECT
USING (role_oid OPERATOR(pg_catalog.=)
       (SELECT r.oid FROM pg_catalog.pg_roles r
        WHERE r.rolname OPERATOR(pg_catalog.=) SESSION_USER));
CREATE POLICY audited_tenant ON praetore.safety_records
FOR SELECT
TO praetore_safety_audit
USING (
    tenant_id IN (SELECT a.tenant_id FROM praetore.safety_audit_tenants a
                  WHERE a.role_oid OPERATOR(pg_catalog.=)
                        (SELECT r.oid FROM pg_catalog.pg_roles r
                         WHERE r.rolname OPERATOR(pg_catalog.=) SESSION_USER))
);
GRANT USAGE ON SCHEMA praetore TO praetore_safety_audit;
GRANT SELECT ON praetore.schema_migrations TO praetore_safety_audit;
GRANT SELECT ON praetore.safety_records TO praetore_safety_audit;
GRANT SELECT ON praetore.safety_audit_tenants TO praetore_safety_audit;
