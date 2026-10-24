DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'execution_journal_replay_claim_fk'
            AND conrelid = 'praetore.execution_journal'::regclass
    ) THEN
        ALTER TABLE praetore.execution_journal
            ADD CONSTRAINT execution_journal_replay_claim_fk
            FOREIGN KEY (agent_id, request_id)
            REFERENCES praetore.replay_claims (agent_id, request_id)
            NOT VALID;
    END IF;
END;
$$;
