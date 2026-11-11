-- Manual rollback of migration 0022 (the signed `awaiting_approval` state
-- of a held approval and the `approved_claim_expired` close) alone. Run it
-- as the owner of the praetore schema with every gateway stopped:
--
--   psql "$OWNER_URL" -v ON_ERROR_STOP=1 -f docs/rollback/0022-awaiting-approval-state.sql
--
-- No row is read into the rollback or rewritten. It fails, and changes
-- nothing, if 0022 is not recorded, if a migration newer than 0022 is
-- recorded (roll that one back first), or if an attestation is
-- `awaiting_approval` or a journal row or an attestation carries
-- `approved_claim_expired`: those rows are signed, and the 0021 vocabulary
-- cannot hold them. Afterwards only a release without 0022 can run against
-- the database, or `praetore-gateway-demo migrate` (schema owner URL in
-- `PRAETORE_GATEWAY_MIGRATION_DATABASE_URL`) applies 0022 again, and
-- `praetore run` also applies pending migrations when it starts.

BEGIN;

-- The constraint and trigger changes need ACCESS EXCLUSIVE on the tables:
-- fail after 5 s instead of queueing every other session behind this one.
SET LOCAL lock_timeout = '5s';

DO $guard$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM praetore.schema_migrations
                   WHERE version = '0022_awaiting_approval_state') THEN
        RAISE EXCEPTION '0022_awaiting_approval_state is not recorded';
    END IF;
    IF EXISTS (SELECT 1 FROM praetore.schema_migrations
               WHERE version > '0022_awaiting_approval_state') THEN
        RAISE EXCEPTION 'a migration newer than 0022 is recorded: roll it back first';
    END IF;
END
$guard$;

-- Guard: refuse while any row uses the 0022 vocabulary. Validating a
-- constraint scans every row, whatever the row level security policies.
ALTER TABLE praetore.execution_attestations
    ADD CONSTRAINT execution_attestations_rollback_0022_no_v5_rows CHECK (
        execution_status <> 'awaiting_approval'
        AND not_dispatched_reason IS DISTINCT FROM 'approved_claim_expired'
    );
ALTER TABLE praetore.execution_journal
    ADD CONSTRAINT execution_journal_rollback_0022_no_v5_rows CHECK (
        not_dispatched_reason IS DISTINCT FROM 'approved_claim_expired'
    );
ALTER TABLE praetore.execution_attestations
    DROP CONSTRAINT execution_attestations_rollback_0022_no_v5_rows;
ALTER TABLE praetore.execution_journal
    DROP CONSTRAINT execution_journal_rollback_0022_no_v5_rows;

-- Triggers: back to 0021's attestation rule and 0020's transitions.
-- Exact names, no IF EXISTS: a missing object aborts the whole rollback.
DROP TRIGGER execution_attestations_journal_state_v2 ON praetore.execution_attestations;
CREATE TRIGGER execution_attestations_journal_state_v1
BEFORE INSERT ON praetore.execution_attestations
FOR EACH ROW EXECUTE FUNCTION praetore.validate_execution_attestation_insert_v1();
DROP FUNCTION praetore.validate_execution_attestation_insert_v2();

DROP TRIGGER execution_journal_transition_v5 ON praetore.execution_journal;
CREATE TRIGGER execution_journal_transition_v4
BEFORE UPDATE ON praetore.execution_journal
FOR EACH ROW EXECUTE FUNCTION praetore.validate_execution_journal_transition_v4();
DROP FUNCTION praetore.validate_execution_journal_transition_v5();

-- Constraints: back to 0020's reason vocabulary and 0005's signed states.
ALTER TABLE praetore.execution_attestations
    DROP CONSTRAINT execution_attestations_not_dispatched_reason_v4;
ALTER TABLE praetore.execution_attestations
    ADD CONSTRAINT execution_attestations_not_dispatched_reason_v3 CHECK (
        not_dispatched_reason IS NOT DISTINCT FROM
            (attestation_json ->> 'not_dispatched_reason')
        AND (not_dispatched_reason IS NULL
            OR (not_dispatched_reason IN (
                    'approval_expired', 'approval_rejected', 'dispatch_failed',
                    'crash_recovered', 'dispatch_refused'
                )
                AND execution_status = 'not_dispatched'))
    );

ALTER TABLE praetore.execution_journal
    DROP CONSTRAINT execution_journal_not_dispatched_reason_v4;
ALTER TABLE praetore.execution_journal
    ADD CONSTRAINT execution_journal_not_dispatched_reason_v3 CHECK (
        not_dispatched_reason IS NULL
        OR (not_dispatched_reason IN (
                'approval_expired', 'approval_rejected', 'dispatch_failed',
                'crash_recovered'
            )
            AND authorization_status = 'requires_approval'
            AND execution_status = 'not_dispatched')
        OR (not_dispatched_reason = 'dispatch_refused'
            AND authorization_status IN ('allowed', 'requires_approval')
            AND execution_status = 'not_dispatched')
    );

ALTER TABLE praetore.execution_attestations
    DROP CONSTRAINT execution_attestations_execution_status_v2;
ALTER TABLE praetore.execution_attestations
    ADD CONSTRAINT execution_attestations_execution_status_check CHECK (execution_status IN (
        'not_dispatched', 'executed', 'confirmed', 'outcome_unknown', 'failed'
    ));

DELETE FROM praetore.schema_migrations WHERE version = '0022_awaiting_approval_state';

COMMIT;
