-- G1 follow-ups to 0016 (post-hoc safety records).
--
-- * high_water: every record of a source chain now signs its high-water
--   mark (`high_water` in record_json); the column must equal it (0 on the
--   unattributed chain, whose records carry none), so an ingester that
--   resumes from the column resumes from a signed value.
-- * source_epoch: events (schema version 2) carry the source's run, and
--   every record of a source chain signs the epoch of its segment. A
--   restarted source starts a new epoch whose source_seq starts at 1 again,
--   so duplicates and conflicts are looked up by (source_epoch,
--   source_seq). The column is the signed field (NULL on the unattributed
--   chain). Records of schema version 1 (no epoch) are not readable by this
--   version: export them before upgrading (docs/operations.md).
--
-- Forward-only, applied inside the runner's transaction (no BEGIN/COMMIT
-- here). docs/operations.md has the manual rollback of 0016 and 0017.

ALTER TABLE praetore.safety_records
    ADD COLUMN source_epoch BIGINT CHECK (source_epoch >= 1),
    ADD CONSTRAINT safety_records_epoch_per_chain
        CHECK ((source_epoch IS NULL) = (chain = '_unattributed')) NOT VALID;

DROP INDEX praetore.safety_records_source_seq;
CREATE INDEX safety_records_source_seq
    ON praetore.safety_records (tenant_id, chain, source_epoch, source_seq)
    WHERE source_seq IS NOT NULL;

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
