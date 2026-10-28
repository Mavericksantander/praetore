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

### Human approval

`init` also creates a local human approver key (`approver.key`, owner-only)
and its public pin (`approver-pin.json`, approver id `local-approver`). The
gateway loads only the pin; without it, approval is disabled and every
approval attempt is refused (`approval_not_configured`).

When a policy rule has effect `RequireApproval`, `praetore demo` returns
`requires_approval` / `not_dispatched` and prints the commands to resolve it:

```sh
praetore approve ./praetore-local <request_id> --approver local-approver
praetore reject  ./praetore-local <request_id> --approver local-approver
```

`<request_id>` is `evidence.request_id` from the demo receipt. Pass
`--agent <evidence.agent.id>` to address the endpoint's tenant/agent/request
triple directly; otherwise the CLI looks up the agent id in the local journal
(parameterized SQL, tenant-scoped, fails unless exactly one row). It then fetches
the challenge from the existing `GET /v1/approvals/{tenant_id}/{agent_id}/{request_id}`
endpoint, signs it with `approver.key`, and posts it to the same path. The
gateway verifies the Ed25519 signature against the pin, records the decision
in `praetore.human_approvals` (append-only, one decision per execution) and
only then dispatches. A decision cannot be reused, a rejection is final, an
approver key equal to the requesting agent key is refused, and the approval
window is short: it ends at the earlier of the intent expiry (60 s) and the
local freshness lease (30 s), after which the gateway answers
`approval_expired` (HTTP 410).

The approver key sits next to the other demo keys; this is a local
demonstration of the protocol, not separation of duties or key custody.

`init` creates fresh Ed25519 keys and configures their secret files with
owner-only permissions on Unix systems. Key initialization intentionally fails
on platforms where the CLI cannot verify those permissions. The database URL
is supplied by the operator and must refer to local PostgreSQL; the CLI applies
the workspace's replay and execution journal migrations at startup. Do not put
production credentials or production trust anchors in the generated demo
directory.

The HTTP API has no transport authentication or TLS (approval decisions are
authenticated by their Ed25519 signature) and binds to IPv4 loopback only.
The built-in policy allows only `demo:set_value` with capability `demo:write`
against `demo-state`; every non-matching action is denied. The adapter has no
network access, and its key/value effects live in memory and disappear when
the gateway stops. PostgreSQL durably records authorization and execution
state, but it does not make downstream effects atomic. A client timeout is
ambiguous, so the CLI does not retry and directs the operator to inspect the
journal.

This command is a development/reference experience, not a production gateway,
secure key custody system, external-agent integration, sandbox, or deployment
readiness claim. Use the main [deployment gates](../../docs/pre-user-pilot-gates.md)
before considering any real tool integration.
