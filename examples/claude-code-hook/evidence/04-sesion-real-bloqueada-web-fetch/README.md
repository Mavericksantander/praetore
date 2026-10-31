# 04 · Real session stopped by a missing profile

Real session that stopped early. 8 receipts in `evidence/`, all Allow.

The `web-fetch` agent had no profile, and the hook version used here denied
calls from agents without a profile **without writing a receipt**. The
agent's own run summary (not included here) reports:

> las 33 llamadas a WebFetch de las 4 tandas (...) devolvieron
> `PRÆTORE: no authority has been issued for agent 'web-fetch'`.

So 33 denials happened and are not in this set. That number comes from the
agent's summary; since there are no receipts for those calls, it cannot be
checked from this evidence. This gap led the hook to sign those denials too
(see set 05 and set 03).

Verify: see [../VERIFY.md](../VERIFY.md).
