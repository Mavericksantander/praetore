# Tool gateway integration pattern

This document defines a conservative deployment pattern for placing PRÆTORE
at an agent tool-execution boundary. It is guidance for an application-owned
gateway, not a gateway implementation shipped by this repository.

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
     |                 evidence + decision
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
4. Before calling `evaluate`, durably create or transition the operation's
   journal record to `AUTHORIZATION_PENDING`, binding the request ID and
   normalized-operation digest. If this write fails, do not evaluate or
   dispatch. Then evaluate using the configured HighAssurance engine with
   externally provisioned pins and caller-owned replay/freshness
   implementations.
5. Stop unless the result is exactly `ALLOW`. Do not interpret
   `REQUIRE_APPROVAL` as permission to execute or automatically resume the
   same request after an out-of-band approval.
6. Verify and durably journal the evidence, expected policy digest, and
   operation binding as `AUTHORIZED_PENDING` before dispatch. Bind the journal
   entry to the adapter's idempotency key when the downstream tool supports
   one. Use an atomic journal transition or exclusive lease so another gateway
   worker cannot dispatch the same operation concurrently.
7. Invoke the adapter using the exact normalized operation. Record the
   downstream result and transition the journal entry to a terminal state.
   Return the result and receipt without allowing caller-controlled data to
   overwrite the journal record.
8. Reconcile incomplete records after restart using the adapter's
   authoritative operation status or idempotency facility. Do not blindly
   replay an operation whose side-effect status cannot be determined.

The gateway should independently verify evidence before treating it as an
audit receipt: verify integrity, the expected policy digest, the agent intent,
issuer signature and subject binding, and the HighAssurance attester signature
against externally pinned keys. Do not trust a key embedded only in the
evidence. Evidence verification does not itself authorize execution; the
gateway must also ensure it is acting on the exact request it constructed.

## Crash and retry behavior

HighAssurance's `ReplayGuard` atomically consumes an `(agent UUID, request
UUID)` during `evaluate`, before evidence is returned. This prevents reuse of
that signed request ID, but it does not record tool execution state and does
not make evaluation, evidence delivery, and an external side effect atomic.
The guard's claim must not be removed to make a retry convenient.

| Failure point | Safe default | Recovery |
| --- | --- | --- |
| Before evaluation | No dispatch | If the durable journal proves evaluation was never started, the gateway may proceed with that request. Otherwise leave it unresolved. |
| During evaluation, or result lost after evaluation | Do not retry with the same ID expecting another evaluation; do not mint a new ID automatically | The pre-evaluation journal record remains `AUTHORIZATION_PENDING`; no dispatch is permitted without a later durable `AUTHORIZED_PENDING` record. Reconcile the record. A new signed request is allowed only after the gateway proves no dispatch occurred and applies current policy/freshness; do not resolve ambiguity by deleting the replay claim. |
| After evidence/journal commit but before dispatch | Do not blindly dispatch from a stale authorization receipt | Re-evaluate only under a new, freshly signed request after proving no side effect occurred and applying current policy/freshness. |
| During dispatch or after effect but before result is journaled | Treat outcome as unknown; do not blindly repeat a non-idempotent operation | Query downstream status by idempotency key or operation ID. If status is unavailable, quarantine for reconciliation. |
| After terminal result is recorded | Return the recorded result for a duplicate gateway call | Do not execute again. Protect terminal records from rollback or deletion that would re-enable execution. |

For useful automated recovery, the downstream tool should provide an
idempotency key or a queryable operation ID that the gateway can bind to its
request ID. Prefer a transactional outbox or a downstream transaction when
available. Without cooperation from the side-effect system, exactly-once
execution cannot generally be guaranteed across process crashes. A journal
alone improves auditability but does not close the TOCTOU window.

The current core does not issue execution leases, expose a transactional
authorization-and-execution API, or store execution state in Evidence v1.
Freshness is checked at evaluation time, not continuously through dispatch.
Keep the decision-to-dispatch interval short, enforce a gateway-side deadline,
and re-evaluate if the deadline or relevant state changes. This narrows but
does not eliminate TOCTOU risk.

## Approvals and delegation are not implemented here

`REQUIRE_APPROVAL` is a decision outcome only. The core does not identify an
approver, collect approval, bind an approval credential to an action, or
resume execution. Until a separately reviewed approval protocol exists, the
gateway must hold the request and perform no side effect. A caller-built
approval mechanism must cryptographically bind approver identity, exact
normalized action, subject, authority, policy digest, expiry, and request
identifier, and must be independently validated before creating a new
authorization request; this document does not define that protocol.

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
