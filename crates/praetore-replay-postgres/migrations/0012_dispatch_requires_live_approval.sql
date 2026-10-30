-- Defense in depth for approved_pending_dispatch -> dispatched.
--
-- 0010 lets a claim move APD -> dispatched without looking at the approval
-- again; claim_dispatch checks it in Rust under the row lock. This trigger
-- repeats that check in SQL, so a bug in (or a bypass of) the gateway code
-- cannot dispatch an expired approval:
--   * an `approve` decision for the key must exist,
--   * no approval-expiration receipt may exist for the key, and
--   * the approval's expires_at must be later than the observation time the
--     gateway used for its own check.
--
-- Clock: the gateway decides expiry with its injected, trusted clock
-- (chrony-checked in production) and signs that time into expiration
-- receipts; the database clock is not part of that trust chain and may be
-- skewed. The claiming transaction therefore passes the same instant in the
-- transaction-local setting `praetore.dispatch_observed_at` (RFC 3339), and
-- the trigger compares expires_at with it. A dispatch without that setting is
-- refused. A caller that can choose the setting can also choose the clock the
-- Rust check uses; this check protects against code paths that skip the
-- check, not against a compromised gateway.
--
-- Forward-only; 0010 is not edited. Applied inside the runner's transaction.

CREATE FUNCTION praetore.enforce_dispatch_requires_live_approval()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, praetore, pg_temp
AS $$
DECLARE
    observed_text TEXT := NULLIF(current_setting('praetore.dispatch_observed_at', true), '');
    observed_at TIMESTAMPTZ;
    approval_expires_at TIMESTAMPTZ;
BEGIN
    IF observed_text IS NULL THEN
        RAISE EXCEPTION 'dispatch from approved_pending_dispatch requires praetore.dispatch_observed_at';
    END IF;
    observed_at := observed_text::TIMESTAMPTZ;

    IF EXISTS (
        SELECT 1 FROM praetore.human_approval_expirations expiration
        WHERE expiration.tenant_id = OLD.tenant_id
          AND expiration.agent_id = OLD.agent_id
          AND expiration.request_id = OLD.request_id
    ) THEN
        RAISE EXCEPTION 'approval has an expiration receipt; refusing dispatch';
    END IF;

    SELECT approval.expires_at INTO approval_expires_at
    FROM praetore.human_approvals approval
    WHERE approval.tenant_id = OLD.tenant_id
      AND approval.agent_id = OLD.agent_id
      AND approval.request_id = OLD.request_id
      AND approval.outcome = 'approve';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'dispatch requires an approve decision';
    END IF;
    IF approval_expires_at <= observed_at THEN
        RAISE EXCEPTION 'approval expired at %, dispatch observed at %',
            approval_expires_at, observed_at;
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION praetore.enforce_dispatch_requires_live_approval() FROM PUBLIC;

CREATE TRIGGER execution_journal_dispatch_requires_live_approval
BEFORE UPDATE ON praetore.execution_journal
FOR EACH ROW
WHEN (OLD.execution_status = 'approved_pending_dispatch'
      AND NEW.execution_status = 'dispatched')
EXECUTE FUNCTION praetore.enforce_dispatch_requires_live_approval();
