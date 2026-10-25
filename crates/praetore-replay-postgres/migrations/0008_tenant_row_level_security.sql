BEGIN;

DO $$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'replay_claims',
        'execution_journal',
        'execution_journal_events',
        'execution_attestations',
        'human_approvals'
    ] LOOP
        EXECUTE format(
            'ALTER TABLE praetore.%I ENABLE ROW LEVEL SECURITY',
            table_name
        );
        EXECUTE format(
            'ALTER TABLE praetore.%I FORCE ROW LEVEL SECURITY',
            table_name
        );
        EXECUTE format(
            'DROP POLICY IF EXISTS tenant_isolation ON praetore.%I',
            table_name
        );
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON praetore.%I
             USING (
                 tenant_id = NULLIF(
                     current_setting(''praetore.tenant_id'', true),
                     ''''
                 )::UUID
             )
             WITH CHECK (
                 tenant_id = NULLIF(
                     current_setting(''praetore.tenant_id'', true),
                     ''''
                 )::UUID
             )',
            table_name
        );
    END LOOP;
END;
$$;

COMMIT;
