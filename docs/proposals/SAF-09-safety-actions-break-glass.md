# SAF-09 · Pre-authorized safety actions and audited break-glass (proposal)

Status: proposal only. No code changes. Baseline: `main` at ed05347.

## Problem

An operator needs to stop or contain an agent (kill a job, revoke a lease,
freeze a tenant) at the moment the normal authorization path is the thing
that fails: the issuer is unreachable, the policy denies, or approvers are
offline. Today every action, including a protective one, goes through the
same `evaluate` path, so a safety action can be blocked by the same fault it
is meant to contain.

## Current behavior this design must respect (verified)

| Claim | Location | Verified |
|---|---|---|
| Precedence is Deny > RequireApproval > Allow | `crates/praetore-core/src/decision.rs:5-6` (documented order), `:17-21` (enum), `:23-33` (`strongest`) | Correct. `Policy::evaluate_with_context` folds every matching rule with `strongest` (`policy.rs:104-123`); no match is a default Deny (`policy.rs:125-130`). |
| `evaluate_request` returns `Err` when the authority is missing | `crates/praetore-core/src/engine.rs:1136-1150` | **Imprecise.** `AuthorizationRequest.authority` is not optional (`authorization.rs:33`), so a request without an authority cannot be built. `evaluate_request` returns `Err` when the authority is invalid (`engine.rs:1142`), when its subject does not match the agent (`:1145-1149`), or when the issuer or trust binding fails in Strict/HA (`:1151-1198`, `TrustStoreFailure` or `AuthorityVerificationFailed`). An authority that exists but lacks the capability is **not** an `Err`: it returns `Ok(Decision::deny(..))` (`engine.rs:1241-1245`). |
| Synchronous evidence signing blocks | `engine.rs:1016` (`evidence.sign(attester)?`), `evidence.rs:299-318` (`Evidence::sign`) | **Partially correct.** Signing is synchronous and in-process: one Ed25519 signature and no I/O (`evidence.rs:317`). The HTTP gateway already runs `gateway.execute` in `tokio::task::spawn_blocking` (`crates/praetore-gateway/src/http_api.rs:63`), so it does not block the async runtime. The real synchronous wait on the hot path is the atomic commit to the journal (`crates/praetore-gateway/src/lib.rs:978`, `evaluate_with_atomic_commit`). |

## Design

### 1. Pre-authorized safety actions

- A closed list of **protective** `action_type`s, fixed in code and not
  configurable from policy: `safety:halt_agent`, `safety:revoke_lease`,
  `safety:quarantine_tenant`. They can only reduce capability; none of them
  dispatches tool calls.
- An issuer signs a dedicated authority in advance with capability
  `safety:*`, a long validity, and bound to the operator key. It is stored
  offline.
- Evaluation keeps the normal path. The precedence does not change: a policy
  Deny still wins. The proposal requires the policy validator to **reject**
  any Deny or RequireApproval rule whose `action_type` is in the safety list,
  so an operator cannot be blocked by misconfiguration. This reuses
  `PolicyRule::validate` (`policy.rs:305`) and adds no new evaluation step.
- Dispatch for safety actions skips the replay journal's exactly-once
  requirement only if the action is idempotent by definition (halting twice
  is safe). It does not skip evidence: the evidence is still signed
  (`engine.rs:1016`).

### 2. Audited break-glass

- A break-glass authority is a normal `Authority` with the constraint
  `break_glass = <incident id>` and a short `not_after` (≤ 1 h). It needs two
  issuer signatures (M-of-N). The current constraint check
  (`engine.rs:1228-1233`) already denies an
  unsatisfied constraint. Note that it compares the constraint against
  `action.target` or a parameter of the action, so the incident id has to
  travel as an action parameter. The new part is the second signature.
- It only lifts **RequireApproval**, never Deny. Precedence stays
  Deny > RequireApproval > Allow. Break-glass turns a RequireApproval result
  into Allow only when the matching rule declares `break_glass_eligible`.
- Every break-glass decision is written to the journal **before** dispatch,
  with the incident id, both issuer key ids and the evidence digest. If the
  write fails, there is no dispatch (fail-closed, same as
  `evaluate_with_atomic_commit` today).
- After the incident, an alert or report lists every break-glass use. The
  data is already in the journal and in observability (`praetore-observe`).

## Non-goals

- Bypassing a policy Deny.
- Removing evidence signing from the hot path (see the table above: it is not
  the bottleneck).
- Changing the HighAssurance configuration format.

## Open questions

1. Where the M-of-N for break-glass is validated: in `Authority`, or as a
   separate pin in `HighAssuranceConfig`.
2. Whether the safety list is fixed in code or versioned alongside the policy
   digest.
3. The maximum break-glass TTL and who can issue it.

## Proposed tests (when implemented)

- A Deny policy on `safety:halt_agent` fails validation.
- Break-glass without the second signature → Deny; with it, on a
  RequireApproval rule → Allow, and on a Deny rule → Deny.
- Break-glass with a journal failure → no dispatch.
