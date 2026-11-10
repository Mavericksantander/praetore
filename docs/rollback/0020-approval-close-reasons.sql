-- Manual rollback of migration 0020 (approval_rejected, the in-place
-- approval_expired close of a held approval, and the failure class of a
-- failed execution) alone. Run it as the owner of
-- the praetore schema with every gateway stopped:
--
--   psql "$OWNER_URL" -v ON_ERROR_STOP=1 -f docs/rollback/0020-approval-close-reasons.sql
--
-- No row is rewritten. It fails, and changes nothing, if a journal row or
-- an attestation already uses 'approval_rejected', or carries a
-- failure_class: those rows are signed, and neither the 0013 vocabulary nor
-- a schema without the failure columns can hold them. Afterwards only a release
-- without 0020 can run against the database, or `praetore migrate` applies
-- 0020 again. Rows closed as 'approval_expired' in place stay valid under
-- 0013. Migration 0021 reads the failure columns: roll it back first
-- (docs/rollback/0021-journal-insert-rules.sql); this script refuses to run
-- while a migration newer than 0020 is recorded.

BEGIN;

-- The constraint and trigger changes need ACCESS EXCLUSIVE on the tables:
-- fail after 5 s instead of queueing every other session behind this one.
SET LOCAL lock_timeout = '5s';

DO $guard$
BEGIN
    IF EXISTS (SELECT 1 FROM praetore.schema_migrations
               WHERE version > '0020_approval_close_reasons') THEN
        RAISE EXCEPTION 'a migration newer than 0020 is recorded: roll it back first';
    END IF;
END
$guard$;

-- Guard (D-B1): refuse while any row carries a failure class. Validating a
-- constraint scans every row, whatever the row level security policies.
ALTER TABLE praetore.execution_journal
    ADD CONSTRAINT execution_journal_rollback_0020_no_failure_class
    CHECK (failure_class IS NULL AND failure_reason IS NULL);
ALTER TABLE praetore.execution_attestations
    ADD CONSTRAINT execution_attestations_rollback_0020_no_failure_class
    CHECK (failure_class IS NULL AND failure_reason IS NULL);

DROP TRIGGER execution_journal_transition_v4 ON praetore.execution_journal;
CREATE TRIGGER execution_journal_transition_v3
BEFORE UPDATE ON praetore.execution_journal
FOR EACH ROW EXECUTE FUNCTION praetore.validate_execution_journal_transition_v3();
DROP FUNCTION praetore.validate_execution_journal_transition_v4();

-- Dropping the columns drops their constraints (the guards above included)
-- and the runtime role's column grant.
ALTER TABLE praetore.execution_journal
    DROP COLUMN failure_class,
    DROP COLUMN failure_reason;
ALTER TABLE praetore.execution_attestations
    DROP COLUMN failure_class,
    DROP COLUMN failure_reason;

ALTER TABLE praetore.execution_journal
    DROP CONSTRAINT execution_journal_not_dispatched_reason_v3;
ALTER TABLE praetore.execution_journal
    ADD CONSTRAINT execution_journal_not_dispatched_reason_v2 CHECK (
        not_dispatched_reason IS NULL
        OR (not_dispatched_reason IN (
                'approval_expired', 'dispatch_failed', 'crash_recovered'
            )
            AND authorization_status = 'requires_approval'
            AND execution_status = 'not_dispatched')
        OR (not_dispatched_reason = 'dispatch_refused'
            AND authorization_status IN ('allowed', 'requires_approval')
            AND execution_status = 'not_dispatched')
    );

ALTER TABLE praetore.execution_attestations
    DROP CONSTRAINT execution_attestations_not_dispatched_reason_v3;
ALTER TABLE praetore.execution_attestations
    ADD CONSTRAINT execution_attestations_not_dispatched_reason_v2 CHECK (
        not_dispatched_reason IS NOT DISTINCT FROM
            (attestation_json ->> 'not_dispatched_reason')
        AND (not_dispatched_reason IS NULL
            OR (not_dispatched_reason IN (
                    'approval_expired', 'dispatch_failed', 'crash_recovered',
                    'dispatch_refused'
                )
                AND execution_status = 'not_dispatched'))
    );

DELETE FROM praetore.schema_migrations WHERE version = '0020_approval_close_reasons';

COMMIT;
