# SAF-09 · Pre-authorized safety actions and audited break-glass (proposal)

Status: proposal only, a nice-to-have for a pilot program. Baseline: `main` at ed05347.

**Scope:** an optional, opt-in extension that lives outside the core. It does
not change `praetore-core`, the gateway crates, their APIs or their semantics,
and it is not part of the roadmap. There is no committed timeline. If it is
never built, nothing in PRÆTORE changes.

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

## Design (optional extension)

Everything below is built only on the existing public API. If something cannot
be built that way, it stays out of this extension; it is not a reason to change
the core.

### 1. Pre-authorized safety actions

- The deployment that opts in defines its own protective `action_type`s (for
  example `safety:halt_agent`, `safety:revoke_lease`). They are ordinary policy
  rules with `required_capability`, which Strict/HA already require.
- An issuer signs, in advance, a normal `Authority` with those capabilities,
  and the operator keeps it offline.
- Precedence is not touched: a policy Deny still wins (`decision.rs:23-33`). To
  avoid self-blocking, the extension ships a **lint**, an external tool run
  over the policy JSON before it is deployed. It warns if any Deny or
  RequireApproval rule targets a safety action. The core validator does not
  change.
- These actions go through the normal path, including evidence signing
  (`engine.rs:1016`) and the journal. Nothing is skipped.

### 2. Audited break-glass

- A break-glass authority is a normal `Authority` with a short `not_after` and
  the constraint `break_glass = <incident id>`. The existing check
  (`engine.rs:1228-1233`) already denies it if the action does not carry that
  id as a parameter or target.
- It never lifts a Deny. The policy that opts in decides which rules accept
  that capability. Precedence does not change.
- The audit (who, when, which incident) is a report built outside the core over
  data that already exists: the journal and observability (`praetore-observe`).
- A second signature (M-of-N) is out of scope for this extension, because it
  would need changes in `Authority`. If it is ever wanted, it would be its own
  proposal.

## Non-goals

- Changing `praetore-core`, the gateway crates, the precedence or the
  HighAssurance configuration.
- Bypassing a policy Deny or skipping evidence or the journal.
- Getting on the roadmap or committing to dates.

## Open questions (only if the extension is ever built)

1. Who maintains the lint and the report, and in which repo, given that they
   live outside the core.
2. The maximum break-glass TTL that the issuer should sign.

## Possible tests (only if the extension is ever built)

- The lint warns on a policy with Deny on `safety:halt_agent`.
- A break-glass authority without the incident id in the action → Deny (the
  current behavior of `engine.rs:1228-1233`).
- The report lists every break-glass use present in the journal.
