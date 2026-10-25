# Tool gateway integration pattern

This document defines a conservative deployment pattern for placing PRÆTORE
at an agent tool-execution boundary. The workspace includes
[`praetore-gateway`](../crates/praetore-gateway) and an optional
PostgreSQL-backed journal in `praetore-replay-postgres`. They are reference
components, not a deployable service or a production-certified gateway.

## Security objective and scope

The gateway must be the only path from the agent runtime to protected tools.
It authenticates the caller, constructs the action that will actually be
executed, asks PRÆTORE to authorize that action, and dispatches only when the
decision is exactly `ALLOW`.

This pattern does not make the core an enforcement mechanism by itself. If an
agent can call a tool directly, use another credential, or reach an alternate
network path, it can bypass the gateway. The deployment must remove those
paths using process, network, credential, and tool configuration controls.

```text
agent runtime
     |
     | tool request (untrusted parameters)
     v
mandatory gateway -- authenticate + validate + normalize
     |                         |
     |                 construct exact request;
     |                 obtain agent intent signature
     |                         v
     |                 PRÆTORE HighAssurance
     |                         |
     |                 validate + evaluate + sign;
     |                 atomically persist replay claim + evidence
     |                         v
     +---- only ALLOW ----> durable execution journal
                                 |
                                 v
                        protected tool adapter
                                 |
                                 v
                         external side effect
```

## Required request-to-effect invariants

1. **No bypass:** agents cannot access protected credentials, tools, or
   alternate execution paths except through the gateway. The gateway must
   enforce this boundary; a policy decision alone cannot.
2. **Gateway-owned action construction:** treat the agent's tool name,
   arguments, tenant, resource, and other claims as untrusted. Authenticate
   the caller and derive authoritative context at the gateway. Validate
   against a strict per-tool schema, reject unknown or ambiguous fields, and
   normalize once before authorization.
3. **Same representation at execution:** dispatch the same validated,
   normalized operation that was authorized. Do not authorize one argument
   object and later re-parse, enrich, substitute, or broaden it. The adapter
   must not reinterpret an authorized field in a more privileged way.
4. **Least authority:** map each tool operation to an explicit action type,
   target/resource, parameters, context, and capability. Require an explicit
   `Action::with_capability` in Strict and HighAssurance. A policy allow is
   not a grant of authority; the authority and policy must both permit the
   operation.
5. **Fail closed:** execute only when the engine returns evidence with outcome
   exactly `ALLOW`, the expected policy digest is present, and all deployment
   verification checks succeed. `DENY`, `REQUIRE_APPROVAL`, an engine error,
   timeout, unavailable replay/freshness service, malformed evidence, or
   unknown outcome must result in no dispatch.
6. **Bind retries:** issue a unique request ID for one logical operation and
   use it consistently for authorization and gateway-side idempotency. Do not
   create a fresh request ID merely to retry an operation whose execution
   status is unknown.
7. **Persist before dispatch:** before invoking an external side effect,
   durably record the request ID, normalized operation digest, policy digest,
   evidence, and a pending execution state. If this record cannot be committed,
   do not dispatch. Restrict access to the journal and apply retention and
   integrity controls appropriate to the deployment.

Request signatures prove possession of the agent key and bind the supplied
request fields; they do not prove that a tool's real-world effects match the
gateway's action model. The gateway is responsible for that mapping.

## Recommended execution sequence

1. Accept a tool call and authenticate the calling workload. Enforce
   per-agent/resource input limits and reject duplicate, unknown, or
   ambiguous fields.
2. Resolve tool identity and resource at the gateway. Do not allow a caller
   to choose a more privileged adapter through an unvalidated string.
3. Convert the call into one normalized action and trusted request context.
   Include all authorization-relevant values that affect the side effect.
   Avoid logging secrets; if a secret affects authorization, define an
   explicit safe representation rather than silently omitting it. The agent
   intent signature must cover this exact normalized request. If normalization
   changes the signed bytes, use a gateway challenge/confirmation step so the
   agent signs the gateway-produced request; do not rewrite a previously
   signed request and treat its signature as still valid.
4. Evaluate with the configured HighAssurance engine using externally
   provisioned pins and caller-owned freshness implementations. The reference
   gateway requires an `ExecutionJournal` that also implements the core
   `AtomicAuthorizationCommit` contract. The PostgreSQL implementation commits
   the replay claim and completed, verified HighAssurance evidence in one
   transaction; no standalone replay write is used on this path. A legacy
   replay claim without a matching journal record is blocked as orphaned, not
   promoted or reconstructed.
5. The atomic commit must be confirmed before the gateway proceeds. If commit
   acknowledgement is uncertain, the core queries the same execution identity
   and validates the durable claim/evidence pair and initial execution state.
   If PostgreSQL is unavailable, the pair disagrees, or evidence verification
   fails, do not dispatch. `REQUIRE_APPROVAL` is not permission to execute by
   itself. The reference gateway supports a separate signed human decision for
   a persisted pending request, described in [Human approvals](#human-approvals).
   This is not an out-of-band bypass: it is bound to the original evidence and
   exact action digest, expires with the authorization intent/freshness lease,
   and is consumed once.
6. Commit the journal transition from `Authorized` to `Dispatched` before
   invoking the adapter. This prevents another gateway instance from claiming
   the same journal key; a crash after the transition is ambiguous even if the
   adapter call had not yet begun. Bind the journal entry to the adapter's
   idempotency key when the downstream tool supports one.
7. Invoke the adapter using the exact normalized operation. Record the
   downstream result and transition the journal entry to a terminal state.
   Return the result and receipt without allowing caller-controlled data to
   overwrite the journal record.
8. Reconcile incomplete records after restart using the adapter's
   authoritative operation status or idempotency facility. Do not blindly
   replay an operation whose side-effect status cannot be determined. The
   gateway exposes `reconcile`, which never dispatches and only resolves an
   ambiguous record when the adapter reports `Applied` or `NotApplied` under
   its documented contract.

The gateway should independently verify evidence before treating it as an
audit receipt: verify integrity, the expected policy digest, the agent intent,
issuer signature and subject binding, and the HighAssurance attester signature
against externally pinned keys. Do not trust a key embedded only in the
evidence. Evidence verification does not itself authorize execution; the
gateway must also ensure it is acting on the exact request it constructed.

## Reference implementation

`praetore-gateway::Gateway` accepts only `AuthorizationRequest`, rejects any
engine whose mode is not `HighAssurance`, and invokes the core engine for each
call. It checks the returned evidence integrity and HighAssurance metadata.
Only an evidence decision exactly equal to `ALLOW` can advance to dispatch.
The action passed to `ActionDispatcher` is the action inside that newly
produced evidence; the gateway does not accept a second action argument and
does not reconstruct tool parameters after authorization.

The adapter API receives an immutable `&Action`. Production adapters must
validate the allowed action type, target and parameter schema and consume
those exact values. Agent intent signatures bind the normalized request, so a
parameter change after signing is rejected by the core. Callers must normalize
the tool call before signing; this reference library does not authenticate a
network peer or implement a tool-schema registry.

The adapter also receives an `ExecutionKey` containing the signed request ID
and logical agent ID, which can be forwarded as a downstream idempotency key.
The reference gateway deduplicates only that exact key. A caller presenting
the same semantic operation under a new signed request ID is a distinct
operation unless the adapter or a higher-level journal applies a separate
business idempotency rule.

Before calling an adapter, the gateway records the authorization evidence in
an `ExecutionJournal` and commits a one-time dispatch transition. If either
write fails, it does not invoke the tool. It records a successful adapter
result as `Executed` or `Confirmed`; an adapter error is recorded as
`OutcomeUnknown` and is never retried automatically. `Confirmed` means only
that the adapter's own confirmation contract succeeded. The optional
`PostgresExecutionJournal` uses a unique `(agent_id, request_id)` key,
transactional state changes, and a database transition trigger. PostgreSQL
integration tests exercise concurrent gateways, restart recovery, and
ambiguous outcomes with a persistent test adapter. This does not establish
high availability, replication durability, or suitability for a specific
production deployment.

### Durable execution states

| Transition | Trigger and precondition | Durable operation | Safe automatic retry? | Restart meaning |
| --- | --- | --- | --- | --- |
| absent → `Authorized` | HighAssurance evaluation produced valid evidence and exact `ALLOW` | Insert immutable evidence, request digest, and action digest | No; the core replay claim may already be consumed | No dispatch is known. Recovery closes this as `NotDispatched`. |
| absent → `NotDispatched` | Evaluation produced DENY or REQUIRE_APPROVAL | Insert evidence and decision | No execution retry from this record | For DENY, terminal. For REQUIRE_APPROVAL, it may enter the one-time approval flow below before expiry. |
| `Authorized` → `Dispatched` | The unique journal claim exists and is allowed | Commit state transition before adapter call | No after restart | Dispatch may not have begun; treat as ambiguous and reconcile. |
| `NotDispatched` → `Dispatched` | Pending REQUIRE_APPROVAL has a valid signed approval | Persist append-only approval and transition in one PostgreSQL transaction | No after restart | Approval is consumed; do not redispatch automatically. |
| `Dispatched` → `Executed` / `Confirmed` | Adapter returned the corresponding report | Persist output and terminal state | No | Adapter report is durable gateway evidence, not proof beyond its contract. |
| `Dispatched` → `OutcomeUnknown` | Adapter returned an error or the caller cannot record its result | Persist ambiguity when possible; a crash may leave `Dispatched` | Never redispatch automatically | Reconcile read-only; preserve ambiguity without sufficient adapter evidence. |
| `Dispatched` / `OutcomeUnknown` → `Failed` | Adapter proves `NotApplied` | Persist terminal state without output | No | No automatic retry: the request/replay claim remains consumed. |
| `Dispatched` / `OutcomeUnknown` → `Confirmed` | Adapter proves `Applied` and supplies output | Persist output and terminal state | No | Return the reconciled result; do not call the adapter again. |

`Executed`, `Confirmed`, `Failed`, and `NotDispatched` cannot transition back
to a dispatchable state. `OutcomeUnknown` is intentionally reconcilable, but
not dispatchable. If the journal is unreachable or a transition commit is not
confirmed, the gateway does not intentionally call the adapter; if the
connection drops after PostgreSQL committed, the state is resolved from the
durable row rather than by retrying execution.

`Gateway::reconcile` is an operator/recovery operation, not a concurrent
worker loop. Before calling it for `Dispatched` or `OutcomeUnknown`, fence or
stop every process that could still be inside the original adapter call and
confirm it cannot resume. The journal does not hold a distributed execution
lease across adapter dispatch. Concurrently reconciling an `OutcomeUnknown`
row while its original worker is merely paused could otherwise let an adapter
report `NotApplied` before that worker later performs the effect.

The PostgreSQL atomic authorization path closes the gap between committing a
new replay claim and committing its verified authorization record. Legacy
replay claims without a journal row remain blocked and are never automatically
promoted. The `Dispatched` write and an external effect still cannot be atomic
without a shared transaction or a downstream idempotency/status protocol.
PostgreSQL's `synchronous_commit=on`
requests local WAL flush for each journal transaction; it does not guarantee
survival of host loss, asynchronous replica failover, storage corruption, or
operator rollback. Production use additionally depends on trustworthy clocks,
externally protected signing/trust keys, database access controls and backups,
and preventing the agent from reaching alternate execution paths.

Apply migrations in order: `0001_replay_claims.sql`, then
`0002_execution_journal.sql`, then `0003_execution_replay_link.sql`. The final
migration adds a `NOT VALID` foreign key so existing rows are not silently
rewritten or promoted; PostgreSQL still enforces it for new journal inserts.
Legacy orphan claims are explicitly detected by the atomic provider. Each
authorization transaction uses the default `READ COMMITTED` isolation level,
the replay table's `(agent_id, request_id)` primary key to serialize competing
claims, and locks a matching journal row while classifying an existing claim. The
transaction inserts the claim and journal evidence together and commits with
`synchronous_commit=on`; an error before commit rolls back both. If commit
acknowledgement is uncertain, the provider uses a fresh connection from its
configured factory to verify the durable pair before execution can continue.
Rollback of the schema migrations does not restore the previous atomicity
guarantee; do not run the gateway against an older schema or silently downgrade.

The integration test adapter records its invocation/effect in PostgreSQL in a
single transaction, so it can authoritatively reconcile by execution key and
action digest. Real adapters must separately document whether they can prove
`Applied` or `NotApplied`. If they cannot, operators must retain
`OutcomeUnknown`, investigate downstream logs/state, and resolve only with
independent evidence; a stable execution key alone does not provide
idempotency.

The returned `GatewayReceipt` keeps the core `Evidence` separate from the
gateway authorization/execution states. The core evidence signature covers
the authorization decision, not the gateway's later execution result. A
production deployment must persist and protect the wrapper/journal record
independently. The compile-fail API example and runtime tests demonstrate
that an `Evidence` object cannot be passed in place of a new
`AuthorizationRequest`.

The PostgreSQL journal stores the full serialized evidence and adapter output,
which can include action parameters or contextual data. Do not place raw
credentials or secrets in those fields. Restrict database roles, network access,
retention, exports, and backups; use storage encryption and redaction policies
appropriate to the data classification.

## Crash and retry behavior

The legacy core `evaluate` API continues to consume a standalone
`ReplayGuard` claim before returning evidence. Gateway execution does not use
that path: it calls `evaluate_with_atomic_commit`, which finishes the same
HighAssurance validation, policy, freshness, signing, and evidence verification
before asking the atomic provider to persist both records. The gateway's
`ExecutionJournal` trait requires that provider, so an old non-atomic journal
cannot be supplied accidentally.
For source compatibility, the existing HighAssurance engine constructor still
requires a configured `ReplayGuard`; the gateway's atomic evaluation method
does not call that guard. It uses the transaction provider instead.

| Failure point | Safe default | Recovery |
| --- | --- | --- |
| Before atomic commit | No dispatch | Neither claim nor authorization record is committed by the atomic transaction. The same signed request can be resubmitted, subject to full validation and freshness checks. |
| Atomic commit rolls back | No dispatch | PostgreSQL transaction rollback leaves neither new record. Do not compensate by deleting a claim. |
| Commit acknowledgement is uncertain | No dispatch until verified | Query by the same identity and verify the durable claim, request/action digests, evidence integrity/signature, and initial execution state. If the query is unavailable or inconsistent, remain blocked; do not re-evaluate to recover. |
| Legacy claim exists without authorization record | No dispatch | Treat as `OrphanedReplayClaim`; do not promote it or reconstruct evidence. Operator investigation is required. |
| After atomic commit but before `Dispatched` | No adapter call can have started | Reconcile to `NotDispatched`; the request ID remains consumed and cannot be authorized again. |
| After journal records `Authorized` but before `Dispatched` | No adapter call can have started | Reconcile to `NotDispatched`; the consumed request ID is not reusable. |
| After journal commits `Dispatched`, including before adapter invocation | Do not assume the adapter was or was not called | First fence all original workers, then reconcile. The state is ambiguous because the commit precedes the adapter call. |
| During dispatch or after effect but before result is journaled | Treat outcome as unknown; do not blindly repeat a non-idempotent operation | After fencing original workers, query downstream status by idempotency key or operation ID. If status is unavailable, quarantine for reconciliation. |
| After terminal result is recorded | A deployment may return the recorded result for a duplicate call; this reference API returns a replay error and has no lookup API | Do not execute again. Protect terminal records from rollback or deletion that would re-enable execution. |

For useful automated recovery, the downstream tool should provide an
idempotency key or a queryable operation ID that the gateway can bind to its
request ID. Prefer a transactional outbox or a downstream transaction when
available. Without cooperation from the side-effect system, exactly-once
execution cannot generally be guaranteed across process crashes. A journal
alone improves auditability but does not close the TOCTOU window.

The core atomic-authorization contract does not include the subsequent
`Dispatched` transition or external action in the same transaction.
Freshness is checked at evaluation time, not continuously through dispatch.
Keep the decision-to-dispatch interval short, enforce a gateway-side deadline,
and re-evaluate if the deadline or relevant state changes. This narrows but
does not eliminate TOCTOU risk.

## Human approvals

The gateway reference implements a minimal signed approval protocol for
`REQUIRE_APPROVAL`. It does not implement an enterprise approval service, UI,
OIDC/MFA integration, approver-role management, KMS/HSM signing, notification
delivery, or approval-key rotation.

The HTTP flow is:

1. `POST /v1/execute` returns `202 Accepted` and a receipt with
   `authorization = requires_approval`; the action remains `NotDispatched`.
2. `GET /v1/approvals/{agent_id}/{request_id}` returns the persisted
   `ApprovalChallenge` derived from the pending execution's stored evidence.
   Its fields bind the agent and request IDs, evidence ID/context hash, exact
   action digest, policy digest, and expiry.
3. An external approver system constructs a `HumanApprovalDecision` containing
   the challenge, a unique approval ID, the configured approver key ID, an
   `approve` or `reject` outcome, and an Ed25519 signature. The signature
   covers the canonical decision payload under the
   `PRAETORE_HUMAN_APPROVAL_V1\0` domain separator.
4. `POST /v1/approvals/{agent_id}/{request_id}` submits that signed decision.
   The gateway checks the fixed approver key, signature, exact pending
   challenge, path IDs, and expiration. PostgreSQL rechecks the pending
   execution and expiry while holding the journal row lock.
5. PostgreSQL stores the decision append-only. For `approve`, it records the
   approval and moves the journal to `Dispatched` in the same transaction.
   Only then does the gateway invoke the adapter with the action in persisted
   evidence. `reject` is recorded and never dispatches. The original
   authorization remains `RequiresApproval`; the human decision does not
   rewrite it as `ALLOW`.

An approval is valid only until the earlier of the signed intent expiration
and the freshness lease expiration. Once expired, the request cannot be
approved; submit a newly signed authorization request and obtain a fresh
decision instead. The decision is single-use per `(agent_id, request_id)`.

The demo service loads the approver key ID and public key from
`PRAETORE_GATEWAY_APPROVER_KEY_ID` and
`PRAETORE_GATEWAY_APPROVER_PUBLIC_KEY_HEX`. The matching private key must
remain in the external approver system. The demo HTTP listener is loopback-only
and has no network authentication or TLS; these endpoints must not be exposed
to an untrusted network.

There is a deliberate crash-safety tradeoff: after approval is durably
consumed and the journal reaches `Dispatched`, a process crash before or during
the adapter call does not trigger automatic redispatch. Reconcile using the
adapter's authoritative status or idempotency facility. Exactly-once effects
cannot be guaranteed by the journal alone.

## Delegation is not implemented

Signed Authority currently describes an issuer-granted capability set and
validity window. The core does not implement parent-child delegation,
attenuation proofs, or chain validation. Do not treat an agent's signature or
an authority presentation as permission to mint a narrower-looking child
authority. Delegation requires a separately designed and reviewed feature.

## Deployment acceptance checks

Before relying on this pattern, test and retain evidence that:

* direct tool access and alternate credentials are blocked for the agent;
* the gateway rejects malformed and ambiguous calls and cannot authorize one
  representation while executing another;
* every non-`ALLOW` decision and every relevant infrastructure failure
  produces zero downstream calls;
* concurrent duplicate requests cannot cause duplicate dispatch;
* crashes at every step in the table recover without silent re-execution;
* downstream idempotency/status behavior is verified, or unknown outcomes
  require manual reconciliation;
* journal rollback, loss, capacity exhaustion, and access control fail
  closed; and
* the final deployment adapter and bypass controls receive independent
  security review.

See the [threat model](threat-model.md) and
[pre-user deployment gates](pre-user-pilot-gates.md). This pattern is not a
certification or a claim of exactly-once execution.
