CREATE SCHEMA IF NOT EXISTS praetore;

CREATE TABLE IF NOT EXISTS praetore.replay_claims (
    agent_id UUID NOT NULL,
    request_id UUID NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (agent_id, request_id)
);
