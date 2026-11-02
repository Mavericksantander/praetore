-- G1 (SAF-09.5): post-hoc safety records written by praetore-safety-ingest.
--
-- One hash chain per (tenant, chain): `chain` is a source id, or
-- `_unattributed` for input that did not verify and for losses inside the
-- ingester. Each row holds one SafetyRecord signed by the ingestion key
-- (record_json, canonical JSON); chain_seq, prev_record_hash and
-- record_hash are copies of signed fields, checked against record_json and
-- against the previous row of the chain by the insert trigger below.
-- high_water is the source_seq high-water mark after the row (every
-- source_seq up to it is an event or covered by a loss record), so the
-- ingester can resume without reading the whole chain.
--
-- Append-only: UPDATE, DELETE and TRUNCATE are refused by trigger. Row-level
-- security uses the same tenant_isolation policy as the journal tables
-- (migration 0008): `praetore.tenant_id` set with set_tenant_context.
--
-- praetore_safety_ingest is the NOLOGIN group of the ingester's login role,
-- distinct from praetore_runtime (the gateway): it may read the schema
-- version and read and insert safety records, nothing else. The gateway
-- runtime role gets no privilege on this table. Operators create the login
-- role, for example:
--   CREATE ROLE praetore_safety ... LOGIN PASSWORD '...' IN ROLE praetore_safety_ingest;
-- Creating the group needs CREATEROLE in the role that runs the migrations
-- (checked before any migration runs); a DBA may pre-create it instead, in
-- which case this migration only grants. Forward-only, applied inside the
-- runner's transaction (no BEGIN/COMMIT here).

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'praetore_safety_ingest') THEN
        CREATE ROLE praetore_safety_ingest
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
EXCEPTION
    -- Another database in the same cluster created it concurrently.
    WHEN duplicate_object OR unique_violation THEN NULL;
END;
$$;

CREATE TABLE praetore.safety_records (
    tenant_id UUID NOT NULL,
    chain TEXT NOT NULL
        CHECK (chain ~ '^(_unattributed|[a-z0-9][a-z0-9._-]{0,63})$'),
    chain_seq BIGINT NOT NULL CHECK (chain_seq >= 0),
    record_id UUID NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN (
        'accepted', 'undeclared', 'invalid_name', 'duplicate', 'conflict', 'late',
        'rejected', 'loss'
    )),
    source_seq BIGINT CHECK (source_seq >= 1),
    event_hash CHAR(64) CHECK (event_hash ~ '^[0-9a-f]{64}$'),
    high_water BIGINT NOT NULL CHECK (high_water >= 0),
    prev_record_hash CHAR(64) NOT NULL CHECK (prev_record_hash ~ '^[0-9a-f]{64}$'),
    record_hash CHAR(64) NOT NULL CHECK (record_hash ~ '^[0-9a-f]{64}$'),
    record_json TEXT NOT NULL CHECK (length(record_json) BETWEEN 2 AND 65536),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, chain, chain_seq),
    CHECK ((source_seq IS NULL) = (event_hash IS NULL)),
    CHECK ((status IN ('rejected', 'loss')) = (event_hash IS NULL))
);

CREATE INDEX safety_records_source_seq
    ON praetore.safety_records (tenant_id, chain, source_seq)
    WHERE source_seq IS NOT NULL;

CREATE FUNCTION praetore.reject_safety_record_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'safety records are append-only';
END;
$$;

-- The columns must be the signed fields of record_json, and a row must
-- extend its chain: chain_seq 0 links to 64 zeros, any other row to the
-- record_hash of the row before it (which the primary key makes unique).
CREATE FUNCTION praetore.check_safety_record_link()
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
       OR body->>'record_hash' IS DISTINCT FROM NEW.record_hash::TEXT THEN
        RAISE EXCEPTION 'safety record columns do not match record_json';
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

REVOKE ALL ON FUNCTION praetore.reject_safety_record_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION praetore.check_safety_record_link() FROM PUBLIC;

CREATE TRIGGER safety_records_link
BEFORE INSERT ON praetore.safety_records
FOR EACH ROW EXECUTE FUNCTION praetore.check_safety_record_link();

CREATE TRIGGER safety_records_immutable
BEFORE UPDATE OR DELETE ON praetore.safety_records
FOR EACH ROW EXECUTE FUNCTION praetore.reject_safety_record_mutation();

CREATE TRIGGER safety_records_no_truncate
BEFORE TRUNCATE ON praetore.safety_records
FOR EACH STATEMENT EXECUTE FUNCTION praetore.reject_safety_record_mutation();

ALTER TABLE praetore.safety_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE praetore.safety_records FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON praetore.safety_records
USING (
    tenant_id = NULLIF(current_setting('praetore.tenant_id', true), '')::UUID
)
WITH CHECK (
    tenant_id = NULLIF(current_setting('praetore.tenant_id', true), '')::UUID
);

REVOKE ALL ON TABLE praetore.safety_records FROM PUBLIC;

GRANT USAGE ON SCHEMA praetore TO praetore_safety_ingest;
GRANT SELECT ON praetore.schema_migrations TO praetore_safety_ingest;
GRANT SELECT, INSERT ON praetore.safety_records TO praetore_safety_ingest;
