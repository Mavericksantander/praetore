# Delegated authority to approve

**Status: implemented** in the gateway, in `praetore-verify outcomes` and in
the receipt crate. The console still signs and shows version 1 decisions
only. The code is the reference; this note records the design and its
limits.

Enforcement stays cooperative: this changes who may sign a human decision,
not whether a protected side effect can be reached without the gateway.

## 1. Model

Until now a human decision (`HumanApprovalDecision`, schema version 1) was
signed by an approver key pinned for the tenant in
`PRAETORE_GATEWAY_APPROVER_BINDINGS_FILE`. Every new approver meant a new
pin and a gateway restart, and a pin approves every action of its tenant.

Delegation adds a second, optional way to authorize a signer:

- **One delegation root per tenant.** Its Ed25519 public key is pinned in
  the gateway's delegation file (`PRAETORE_GATEWAY_DELEGATION_FILE`). The
  root is an authority to delegate, not a signer of decisions by default.
- **Signed delegations.** A delegation names a subject key, a role
  (`delegator` or `approver`), an exact list of action types, a validity
  window and a `max_depth`. The root signs the first link; each delegator
  signs the next. An `approver` may sign decisions and may not delegate; a
  `delegator` may delegate and may not sign decisions.
- **Signed revocations.** A revocation names one delegation by its hash and
  is signed by that delegation's issuer or by the tenant's root. Revoking a
  delegation invalidates every delegation below it, because each chain
  is checked link by link from the root.
- **Schema version 2 decisions** carry `delegation_chain`: the hashes of the
  delegations from the root to the signer, inside the signed payload. An
  empty chain is the root signing in its own name, accepted only when the
  policy allows it (section 5).

Pinned approvers keep working unchanged. A gateway without the delegation
file behaves exactly as before.

### Formats

All three documents are canonical JSON signed with Ed25519 over a domain
prefix, like the other signed records:

| Document | Signing domain | Fields |
|---|---|---|
| Delegation | `PRAETORE_APPROVAL_DELEGATION_V1\0` | `schema_version` (1), `delegation_id` (UUID v4), `tenant_id`, `issuer_key_id`, `parent_delegation_hash` (absent only on a link the root signed), `subject_key_id`, `subject_public_key_hex`, `role`, `scope.action_types`, `not_before`, `not_after` (RFC 3339 UTC), `max_depth`, `signature` |
| Revocation | `PRAETORE_APPROVAL_REVOCATION_V1\0` | `schema_version` (1), `tenant_id`, `delegation_hash`, `issuer_key_id`, `effective_at`, `signature` |
| Decision v2 | the decision's existing domain | the version 1 fields plus `delegation_chain`, with `schema_version: 2` |

A delegation's hash is SHA-256 over `PRAETORE_APPROVAL_DELEGATION_HASH_V1\0`
followed by the canonical JSON of the whole signed delegation, signature
included. Golden vectors: [delegation](../golden/approval-delegation-v1.json),
[revocation](../golden/approval-revocation-v1.json),
[decision v2](../golden/human-approval-decision-v2.json), and the unchanged
[decision v1](../golden/human-approval-decision-v1.json).

The delegation file:

```json
{
  "schema_version": 1,
  "roots": [{"tenant_id": "...", "key_id": "...", "public_key_hex": "..."}],
  "delegations": [],
  "revocations": []
}
```

It is parsed like the approver bindings: duplicate keys and unknown fields
are refused, hex is lowercase, tenants are non-nil, the file is at most
1 MiB. Every root tenant must have an issuer binding. A root key may not be
another tenant's root, a pinned approver (key or key id), an authority
issuer or an attester; otherwise the gateway does not start. A root that
was also a pinned approver could sign a version 1 decision and approve
whatever the policy says about the root.

## 2. Attenuation

One function, `praetore_core::approval_delegation::verify_approval_chain`,
decides whether a chain authorizes a signer. The gateway and the offline
verifier both call it. A link is valid only if:

1. its parent signed it (its `issuer_key_id` and `parent_delegation_hash`
   name the previous link, and the signature verifies with its key);
2. it is for the same tenant as the root and the challenge;
3. its action types are a subset of its parent's (no wildcards);
4. its validity lies within its parent's;
5. its `max_depth` is lower than its parent's (the root counts as 4), and
   the chain has at most 4 links;
6. its parent is a `delegator`;
7. its subject is neither its issuer nor any earlier key or key id of the
   chain (no self-grant, no cycle).

Then, for the decision: the last link is an `approver`, its key id is the
decision's `approver_key_id` and its key signed the decision, its action
types include the request's `action_type`, no link is revoked, no key of the
chain is the requesting agent's, and every link covers the whole approval
window (section 4).

Each violation is a typed `DelegationError` with a stable code
(`DELEGATION_SCOPE_WIDENED`, `DELEGATION_VALIDITY_WIDENED`, ...). Nothing is
narrowed silently: a child that asks for more than its parent holds is
invalid, not trimmed to the parent's scope.

## 3. Revocation, and its limitation

Revocations are loaded from the delegation file at startup. A revocation
whose signer is neither the delegation's issuer nor the tenant's root makes
the file invalid, and the gateway does not start.

**Limitation of this step:** a new revocation takes effect only when the
gateway is restarted with it. Between signing a revocation and the restart,
the gateway still accepts decisions from the revoked chain. An operator who
needs a revocation to take effect at once must restart the gateway, or
remove the approver's chain from the file, or stop the gateway.

## 4. The time rule

A delegation must be valid for the whole window from the evidence's signed
`decided_at` to the challenge's `expires_at`, not just at one instant. The
gateway has a trusted clock when it records a decision, but the offline
verifier does not: a decision carries no signed time of its own. Requiring
the whole window means both sides check the same thing, from signed data
only, and a decision cannot depend on when it claims to have been made.

Revocations are where the two sides differ:

- **Gateway.** Any loaded revocation of a link refuses the decision, when it
  is recorded and again when its dispatch is claimed
  (`verify_recorded_approval` re-runs the whole check). `effective_at` does
  not matter to the gateway: once it knows a delegation is revoked, it does
  not act on it.
- **Offline.** A revocation counts when `effective_at` is at or before the
  challenge's `expires_at`, and fails the decision with
  `DELEGATION_REVOKED`.

The offline rule is conservative. Without a signed decision time, a
decision made before a revocation and one made after it look the same, so a
revocation inside the window counts against both. The cost: a decision that
was valid when it was made, and that the gateway executed, fails offline if
its chain was later revoked with an `effective_at` before the window
closed. The verifier then says the chain is not shown to have been valid,
which is true from what it can check, not that the gateway misbehaved.

A better alternative, not implemented: have the gateway sign the time it
recorded the decision (for example in the held request's execution
attestation), and let the offline verifier compare a revocation's
`effective_at` with that signed time instead of the window's end. That
moves trust to the gateway's clock and its attester key, which offline
verification already trusts for execution receipts.

## 5. The policy option

```json
"approval_delegation": {"root_may_approve": true}
```

This optional policy field decides whether the root may sign a decision in
its own name (an empty `delegation_chain`). It follows the pattern of the
other optional policy fields:

- **Absent** means `false`, and the policy's canonical form and digest are
  exactly what they were before the field existed.
- **Explicit `false`** behaves like absent but changes the digest, because
  the field is in the canonical form. Both are valid; pick one and pin it.
- One policy serves every tenant of a gateway; the option has no tenant
  ids. It applies to every tenant's root.

The default is `false` because the root is meant to be held offline and used
rarely: a root that approves day to day is a single key that can approve any
action of the tenant, which is what delegation exists to avoid. A refused
root decision fails with `ApprovalError::RootMayNotApprove` (HTTP 403
`root_may_not_approve`) before anything is written to the journal.

The gateway reads the option from its current policy only when that
policy's digest is the one the request's evidence recorded; otherwise the
root may not approve. Offline, `praetore-verify outcomes --policy` reads
the option from the given policy, whose digest must equal the challenge's
`policy_digest` (`DELEGATION_POLICY_MISMATCH` otherwise).

## 6. Compatibility

- A version 1 decision serializes, signs and verifies byte for byte as
  before (golden vector `human-approval-decision-v1.json`, produced before
  this change). A version 1 decision with a `delegation_chain`, or a version
  2 decision without one, does not verify.
- Existing policies keep their digest (`canonical-policy-v2.json` is
  unchanged).
- The gateway accepts version 2 decisions only with a delegation file; a
  gateway without it refuses them as an invalid signature.
- `praetore-verify outcomes` verifies version 1 decisions as before. A
  version 2 decision needs `--delegation-root-pin`, `--delegations` and
  `--policy` (all three, or none); without them it fails with
  `DELEGATION_UNVERIFIED`. The JSON report lists every version 2 decision
  in `delegated_decisions`, with its verified `delegation_chain` and
  `root_approved`.
- No migration: decisions are stored as JSON, and a version 2 decision is
  stored as it was signed.
- Rust API: `HumanApprovalDecision` gains `delegation_chain`,
  `OutcomeKeys` gains `delegation`, `ApprovalError` gains
  `RootMayNotApprove` and `Delegation`, `Policy` gains
  `approval_delegation`.

## 7. Not covered, and future work

- **Narrower scopes:** numeric limits on parameters, target and action type
  prefixes. Today a scope is an exact list of action types.
- **Quorum:** several approvers for one decision.
- **Issuing and revoking from the console**, and a command line tool to
  sign delegations and revocations. Today they are signed out of band and
  placed in the file.
- **Revocation without restart** (section 3), and the signed decision time
  of section 4.
- **Single sign-on** for approvers.
