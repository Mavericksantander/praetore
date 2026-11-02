# PRÆTORE local CLI

The `praetore` binary provides a local reference flow backed by PostgreSQL:

```sh
cargo install --path crates/praetore-cli
praetore init ./praetore-local
export PRAETORE_GATEWAY_DATABASE_URL='postgresql://localhost/praetore'
praetore doctor ./praetore-local
praetore run ./praetore-local
```

In another terminal, execute the only supported demo action:

```sh
praetore demo ./praetore-local set greeting hello
```

### Example policies

`crates/praetore-cli/examples/policies/` contains three ready-to-use policies
for the demo action (`demo:set_value`, capability `demo:write`, target
`demo-state`):

| File | Rule id | Outcome |
| --- | --- | --- |
| `allow.json` | `allow-demo-set` | `allowed`, executed (same as the `init` default) |
| `deny.json` | `deny-demo-set` | `denied`, not dispatched, HTTP 403 |
| `require-approval.json` | `approval-demo-set` | `requires_approval`, not dispatched |

Copy one over the generated policy **before** `praetore run` (the gateway loads
the policy at startup, and the CLI signs requests against the policy digest):

```sh
praetore init ./praetore-deny --port 8081
cp crates/praetore-cli/examples/policies/deny.json ./praetore-deny/policy.json
praetore run ./praetore-deny
```

A `requires_approval` action stays held until it is resolved with
`praetore approve` / `praetore reject` (see Human approval below).

All three are policy format 2: they declare `demo:set_value` as `Mission` in
`action_classes` (see
[docs/policy-language.md](../../docs/policy-language.md#action-classes-policy-format-2)).
A format 1 policy (no `format_version`) no longer loads.

### Migrating a policy to format 2

```sh
praetore policy classify --policy ./old/policy.json
```

prints a proposed `{"format_version": 2, "action_classes": {...}}` on stdout
(types starting with `safety:` as `Safety`, the rest as `Mission`) and, on
stderr, the document's current format and digest and anything that prevents
it from loading as format 2 (a rule on a `safety:` action, a name that
contains `safety` without the prefix); it then exits 1. It only reads the
file and never writes or rewrites it. Add the two fields yourself, review
every `Mission` entry, and keep the old document: receipts that recorded its
digest verify only against it (`praetore-verify --policy`).

### Safety namespace manifest (G2)

```sh
(umask 077; openssl rand -hex 32 > namespace.key)
praetore policy safety-manifest --policy ./policy.json --key namespace.key \
  --output safety-manifest.json
```

writes the signed safety namespace manifest of a format 2 policy (its
digest, id, version and the sorted list of its `Safety` names) and prints a
summary with the `public_key` that verifiers pin. It never overwrites: an
existing `--output` file is an error and is left as it was, and a failed
write leaves nothing (the manifest goes through a synced temporary file
hard-linked to the output name). The key is a dedicated 32-byte secret (64
lowercase hex characters): a regular file, not a symlink, owned by you, no
group or other permissions, at most 128 bytes. It is not the evidence or
issuer key; `--attester-pin <hex file>` refuses it if it is the attester
key. `--issued-at <RFC 3339>` fixes the time; the same
policy, time and key give the same bytes. Verify it with
`praetore-verify safety-manifest --manifest safety-manifest.json --pin
namespace.pin [--policy ./policy.json]`. The manifest authorizes nothing;
see [docs/policy-language.md](../../docs/policy-language.md#safety-namespace-manifest-g2).

### Human approval

`init` also creates a local human approver key (`approver.key`, owner-only)
and its public pin (`approver-pin.json`, approver id `local-approver`). The
gateway loads only the pin; without it, approval is disabled and every
approval attempt is refused (`approval_not_configured`).

When a policy rule has effect `RequireApproval`, `praetore demo` returns
`requires_approval` / `not_dispatched` and prints the commands to resolve it:

```sh
praetore approve ./praetore-local <request_id> --approver local-approver [--yes]
praetore reject  ./praetore-local <request_id> --approver local-approver [--yes]
praetore dispatch ./praetore-local <request_id>   # after approve, runs it once
```

`<request_id>` is `evidence.request_id` from the demo receipt. Pass
`--agent <evidence.agent.id>` to address the endpoint's tenant/agent/request
triple directly; otherwise the CLI looks up the agent id in the local journal
(parameterized SQL, tenant-scoped, fails unless exactly one row). It then fetches
the challenge and the persisted action from
`GET /v1/approvals/{tenant_id}/{agent_id}/{request_id}` and shows the action
type, target, capability, parameters, action digest, policy digest and expiry.
It refuses to sign if the shown action does not hash to the challenge's
`action_digest` or the challenge's policy digest differs from the directory's
`policy.json`, and otherwise asks you to type `yes` (`--yes` skips the prompt
for scripts). Only then does it sign the challenge with `approver.key` and post
it to the same path. The
gateway verifies the Ed25519 signature against the pin, records the decision
in `praetore.human_approvals` (append-only, one decision per execution) and
answers `approved_pending_dispatch`: the action has not run. `praetore
dispatch` then claims and performs the single dispatch (never retried; an
expired or already-claimed approval is refused). A decision cannot be reused, a rejection is final, an
approver key equal to the requesting agent key is refused, and the approval
window is short: it ends at the earlier of the intent expiry (60 s) and the
local freshness lease (30 s), after which the gateway answers
`approval_expired` (HTTP 410).

Approval state is observable without retrying. `GET
/v1/approvals/{tenant_id}/{agent_id}/{request_id}/status` returns
`{"resolution": "pending" | "approved" | "rejected" | "expired" | "not_dispatched", "execution": ..., "not_dispatched_reason"?: ...}`
(`not_dispatched` means approved but closed without dispatch, for example
after the window expired before `praetore dispatch` or a crash recovery), and the
409 (`approval_not_pending`) and 410 (`approval_expired`) responses of the
challenge and decision endpoints include the same `resolution` field. The
lookup is scoped to the exact tenant/agent/request key; unknown keys (including
another tenant's) return 404 `execution_not_found`, and executions that never
required approval return 409 without `resolution`. The field is additive, so
clients that only read `code` are unaffected. The challenge endpoint now also
returns 410 once the approval window has passed (previously only the decision
POST did).

The approver key sits next to the other demo keys; this is a local
demonstration of the protocol, not separation of duties or key custody. The
approver pin is bound to the demo tenant.

`init` creates fresh Ed25519 keys and configures their secret files with
owner-only permissions on Unix systems. Key initialization intentionally fails
on platforms where the CLI cannot verify those permissions. The database URL
is supplied by the operator and must refer to local PostgreSQL; the CLI applies
the workspace's replay and execution journal migrations at startup. Do not put
production credentials or production trust anchors in the generated demo
directory.

The HTTP API binds to IPv4 loopback only and has no TLS. It requires bearer
tokens that `init` generates with owner-only permissions: `agent-api.token`
(used by `praetore demo`; may only submit requests and read approval status)
and `approver-api.token` (used by `approve`, `reject` and `dispatch`; the only
credential that can read challenges, record decisions and dispatch). Approval
decisions are additionally authenticated by their Ed25519 signature. Demo
directories created before this change lack the token files; `praetore run`
then refuses to start and asks for a fresh `praetore init`.
The built-in policy allows only `demo:set_value` with capability `demo:write`
against `demo-state`; every non-matching action is denied. The adapter has no
network access, and its key/value effects live in memory and disappear when
the gateway stops. PostgreSQL durably records authorization and execution
state, but it does not make downstream effects atomic. A client timeout is
ambiguous, so the CLI does not retry and directs the operator to inspect the
journal.

### Gateway-executed filesystem sandbox (Unix)

`praetore init <dir> --sandbox-root <absolute dir>` makes `praetore run` load
`SandboxDispatcher`: the gateway itself performs `fs:write_file`
(capability `fs:write`, target `sandbox`, `{"path", "content"}`) and
`fs:delete_file` (`fs:delete`, `sandbox`, `{"path"}`) inside that directory.
The root must exist, be canonical, not be `/`, be owned by the gateway user,
not be group/other-writable, and neither contain nor sit inside the demo
directory. The default policy still allows only `demo:set_value`; add rules
for the two fs actions to `policy.json` before `run`. Then:

```sh
praetore demo ./praetore-local write notes/hello.txt "hola"
praetore demo ./praetore-local delete notes/hello.txt   # e.g. RequireApproval
praetore approve ./praetore-local <request_id> --approver local-approver
praetore dispatch ./praetore-local <request_id>
```

In this mode every execution-path request must carry
`praetore-exec-mode: gateway` (the CLI sends it), and `/status` answers 409
`cooperative_exec_rejected` for approved actions instead of `approved`. The
header is a declaration, not enforcement: give agents no write access to the
sandbox root. See the `sandbox` module documentation for the confinement
rules and residual risks.

This command is a development/reference experience, not a production gateway,
secure key custody system, external-agent integration, sandbox, or deployment
readiness claim. Use the main [deployment gates](../../docs/pre-user-pilot-gates.md)
before considering any real tool integration.
