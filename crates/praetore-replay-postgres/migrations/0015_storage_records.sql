-- Signed storage records about the journal database itself (for example the
-- adoption of a legacy 0001-0009 baseline), exported in the database-level
-- journal chain. Append-only. Idempotent: the runner also executes it inside
-- an adoption transaction, before this version is recorded.
CREATE TABLE IF NOT EXISTS praetore.storage_records (
    record_id UUID PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('legacy_baseline_adopted')),
    record_json TEXT NOT NULL CHECK (length(record_json) BETWEEN 2 AND 65536),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION praetore.reject_storage_record_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'storage records are append-only';
END;
$$;

REVOKE ALL ON FUNCTION praetore.reject_storage_record_mutation() FROM PUBLIC;

DROP TRIGGER IF EXISTS storage_records_immutable ON praetore.storage_records;
CREATE TRIGGER storage_records_immutable
BEFORE UPDATE OR DELETE ON praetore.storage_records
FOR EACH ROW EXECUTE FUNCTION praetore.reject_storage_record_mutation();

DROP TRIGGER IF EXISTS storage_records_no_truncate ON praetore.storage_records;
CREATE TRIGGER storage_records_no_truncate
BEFORE TRUNCATE ON praetore.storage_records
FOR EACH STATEMENT EXECUTE FUNCTION praetore.reject_storage_record_mutation();

REVOKE ALL ON TABLE praetore.storage_records FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'praetore_runtime') THEN
        GRANT SELECT ON praetore.storage_records TO praetore_runtime;
    END IF;
END;
$$;
