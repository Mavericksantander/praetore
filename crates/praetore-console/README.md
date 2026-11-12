# praetore-console

Local operator console for a PRÆTORE journal. It runs on the operator's computer, listens only on loopback, and has two parts:

- **Historial (D1):** past receipts in plain language. Read-only.
- **Bandeja (D2):** requests held for human approval. The operator approves, rejects, or runs the single dispatch of an approved request. The console signs the decision on this computer with the approver key, as `praetore approve` does. The gateway verifies the signature, records the decision and performs the dispatch.

It is not a hosted service. Linux first.

## Configuration

Required:

| Variable | What |
| --- | --- |
| `PRAETORE_CONSOLE_TENANT_ID` | Tenant whose journal is shown. |
| `PRAETORE_CONSOLE_DATABASE_URL` | PostgreSQL URL; the console reads with read-only transactions and the tenant's row-level security. |

Optional:

| Variable | What |
| --- | --- |
| `PRAETORE_CONSOLE_BIND` | Loopback address, default `127.0.0.1:8090`. A non-loopback address is refused. |
| `PRAETORE_CONSOLE_AGENT_NAMES_FILE` | `agent-uuid = nombre` lines, so agents show by name. |

Approvals inbox: all four or none. A partial set is a startup error.

| Variable | What |
| --- | --- |
| `PRAETORE_CONSOLE_GATEWAY_URL` | `http://127.0.0.1:<port>` (or `[::1]`) of the gateway. Host names are not accepted. |
| `PRAETORE_CONSOLE_APPROVER_KEY_ID` | The approver key id the gateway pins for this tenant. |
| `PRAETORE_CONSOLE_APPROVER_KEY_FILE` | File with the approver Ed25519 secret, 32 bytes in hex (`approver.key` of `praetore init`). It must be a regular file owned by this user, with no group or other permissions, and not a symlink. |
| `PRAETORE_CONSOLE_APPROVER_TOKEN_FILE` | The gateway's `approver` bearer token (`approver-api.token`), with the same file rules. |

## Opening the console

At every start the console writes a link to **stderr**:

```
Abre la consola en este computador con este enlace (vale una vez, 5 minutos):
  http://127.0.0.1:8090/?abrir=<código>
```

- **One use, five minutes at most.** The link works once and for at most five minutes. Opening it sets the session cookie (HttpOnly, SameSite=Strict) and redirects to `/`.
- **Cookie per run.** The session secret is new on every start and is never written to disk, so a cookie from an earlier run stops working.
- **Reissue.** Asking for the page without a session makes the console write a new link to stderr when none is live, at most once every 10 seconds. The new link is never sent to the requester.
- **Under systemd,** stderr goes to the journal. Whoever can read that journal can open the console while the link is live. Restrict who can read it, or run the console in a terminal.
- **Request checks.** Every request must carry the console's own `Host`. An action also needs the console's exact `Origin` and the `x-praetore-consola` header.

## What the inbox shows and checks

- **Each request:** who (agent name), what action, on what target, until when it is valid, and the action parameters.
- **Parameters:** shown as `clave: valor` lines with sorted keys. Agent-chosen text has control and bidirectional characters escaped. The limits are 20 keys, 200 characters per value and 2 levels.
- **Parameters that don't fit:** the signature covers the parameters, so a request whose parameters exceed those limits can only be rejected here. To approve it, review it in full with `praetore approve`.
- **Confirmation:** "Aprobar y ejecutar" and "Rechazar" each ask for a confirmation inside the same card before anything is signed.
- **Before signing**, the console fetches the gateway challenge and requires it to be identical to the one rebuilt from the journal evidence it showed: same key, evidence, action, policy and window.
  - It checks that evidence's **integrity hash**, not its attester signature against a pin, and it does not compare the policy with a local copy. The gateway verifies the decision's signature.
- **A rejection is final.** An approval is never resent. If the dispatch fails, only the dispatch is offered again.

## Limits

- **Same operating system user:** a process running as the same user as the console can read `approver.key`, the token file and the console's memory or files directly, and sign without the console. The console's protections (single-use link, Host, Origin, header) stand against other users and against web pages, not against that process. Real separation requires running the agent under another operating system user than the console and its key files.
- **Not shown:** the console does not show the browser any journal ids, keys, hex digests, RFC 3339 instants or raw evidence. Parameter values are shown as the agent sent them, escaped.
- **Expired windows:** requests whose approval window has closed are counted and not offered. The gateway records the expiry when it next sees the request.
- **Truncation:** the inbox reads the 200 newest pending requests and says when there are more.
