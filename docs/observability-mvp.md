# Read-only observability MVP

`praetore-observe` is an operator-facing read-only view over the PostgreSQL
execution journal. It is separate from `Gateway` and `AuthorizationEngine`; it
has no dispatch, reconciliation, policy, key, or authority mutation routes.
It must not be placed on an agent's request path.

## Start and access boundary

The service binds only to a loopback address. `PRAETORE_OBSERVE_BIND` defaults
to `127.0.0.1:8088`; startup rejects non-loopback addresses. Missing or
malformed required configuration aborts startup:

- `PRAETORE_OBSERVE_BEARER_TOKEN`: exactly 32 cryptographically random bytes
  encoded as 64 hexadecimal characters. Supply it through a secret manager;
  do not put it in shell history, source control, URLs, or logs.
- `PRAETORE_OBSERVE_DATABASE_URL`: connection information for a dedicated,
  SELECT-only PostgreSQL role.
- `PRAETORE_OBSERVE_ATTESTER_PUBLIC_KEY_HEX`: optional externally pinned
  32-byte Ed25519 attester public key. Without it, attester signatures report
  `not_configured`, never `verified`.

The API requires `Authorization: Bearer <64-hex-character-token>` on every
route. The token is compared in constant time after decoding. The embedded UI
shell and static assets contain no journal data and can be loaded without the
token; the UI holds the supplied token in memory only and sends it only in the
authorization header. No cookie, URL parameter, or local storage token flow
exists. Responses are `no-store` and include restrictive content-security and
MIME-sniffing headers.

Do not expose this listener to a network. Remote operator access requires a
separately reviewed authenticated TLS proxy and network boundary; forwarding
the loopback listener or changing its bind check is not an approved
deployment pattern. The current PostgreSQL client uses `NoTls`; use a local
socket or a trusted protected database network/tunnel. The API never connects
to PostgreSQL from the browser.

Apply migrations in order through `0004_execution_journal_events.sql`.
Grant the service role schema usage and SELECT only on the journal identity,
digest, status, evidence, and timestamp columns, plus event identity/status/
timestamp/sequence columns. Do not grant it access to `output_json`; output availability
is derived from the journal's enforced state/output constraint. The reader
sets PostgreSQL's default transaction mode to read-only and
uses explicit read-only repeatable-read transactions for list/detail queries.
The service code contains no mutation SQL. PostgreSQL ownership and superuser
roles can override database controls, so the process must not use an owner,
superuser, or role with write grants.

Minimal role grant shape (run as the schema owner; choose login and password
management out of band):

```sql
CREATE ROLE praetore_observe LOGIN;
GRANT USAGE ON SCHEMA praetore TO praetore_observe;
GRANT SELECT (
    agent_id, request_id, request_digest, action_digest, authorization_status,
    execution_status, evidence_json, created_at, updated_at
) ON praetore.execution_journal TO praetore_observe;
GRANT SELECT (
    event_id, agent_id, request_id, from_status, to_status, occurred_at
) ON praetore.execution_journal_events TO praetore_observe;
```

Run with `cargo run -p praetore-observe` after provisioning the required
environment variables from a secret manager and applying migrations.

## API v1

All API responses are JSON. Errors use generic codes; database error details
are logged only as a bounded error category, not query values or credentials.

| Method and route | Contract |
|---|---|
| `GET /api/v1/operations` | List; optional `agent_id`, `decision`, `execution_state`, `from`, `to`, `limit`, `offset`. |
| `GET /api/v1/operations/{agent_id}/{request_id}` | Detail for a stable `(agent UUID, request UUID)` key. |
| `GET /api/v1/health` | Live database `SELECT 1` probe; adapter and error telemetry are explicitly reported as unavailable. |
| `GET /api/v1/assurance` | Static, documented guarantees and limitations. |

There are no mutation routes. Pagination defaults to 25, permits 1–100 rows,
and caps offset at 10,000. Timestamps must be RFC 3339; time filters must be
provided as a pair with an increasing interval no greater than 90 days.
Decision and execution-state filters accept only persisted enumerated values.
Queries are parameterized; sorting is fixed and stable. List timestamps are
the journal row's creation and last-update times. The `from`/`to` filters
operate on row creation time, not dispatch time.

The detail response reports the current persisted execution state and the
append-only transition events recorded after the history migration. If no
events are available, it reports `not_available`; pre-migration operations
are not given a fabricated timeline. Initial insertion is recorded as an
event with a null `from` state.

Evidence status separates:

- `evidence_integrity`: the evidence payload's SHA-256 integrity check;
- `attester_signature`: verified only against the configured external pin;
- `agent_intent_signature`: a cryptographic self-assertion check, not an
  external identity trust decision;
- `authority_signature`: presence only; issuer trust is not configured in
  this service.

All evidence results are marked historical, and `current_authorization` is
always false. Integrity, signatures, and a stored ALLOW decision do not show
that authorization is still current or that an external effect occurred.

## Redaction and data sources

The journal is the durable source for execution key, authorization status,
execution status, request/action digests, serialized evidence, adapter output,
and journal timestamps. Evidence supplies the recorded decision, action type,
capability, policy digest/version, and signature material. The service returns
only the fields needed for observability:

- action type, capability, and cryptographic digests are visible;
- target, action parameters, request context, trace data, policy-supplied
  rationale, and raw evidence JSON are not returned;
- stored adapter output is reported as `stored_but_redacted` or
  `not_recorded`, never returned;
- public keys, signatures, authority constraints, and issuer metadata are not
  serialized into the API response.

The action type and capability may themselves disclose operational naming;
access remains restricted to the bearer-token operator. Review local
classification requirements before granting that access.

Migrations append state events on new journal inserts and actual state
changes. The event table rejects updates and deletes and has a foreign key
that prevents deleting a journal row while its events remain. Existing rows
are deliberately not backfilled. There is no automatic retention or pruning
policy; retention, backup, export, and deletion procedures must preserve
replay claims and comply with local policy.

## UI

The embedded UI has Operations, operation detail, System health, and Assurance
views. It uses static HTML, CSS, and vanilla JavaScript (no Node build chain).
State labels include text and are not conveyed by color alone. The detail
view repeats redaction and historical-evidence boundaries. UI/API errors do
not call or modify the gateway.

Health signals are intentionally narrow: `available` means a PostgreSQL
`SELECT 1` succeeded at probe time. Adapter health and journal-error counts
are `not_instrumented` / `not_recorded`; they are not inferred from the
absence of failures.

## Known gaps

- No per-operator identity, role separation, audit of operator reads, token
  rotation endpoint, rate limiter, or remote authentication is implemented.
- A shared bearer token grants all read access and is a single operator
  boundary. Protect and rotate it out of band.
- No metrics or adapter error history are persisted today.
- Output and action data remain in PostgreSQL even though API responses
  redact them; database access, backups, logs, and retention still require
  strict controls.
- An API view cannot fence a paused dispatcher or resolve an ambiguous effect.
  Reconciliation remains a separate, explicitly operator-controlled gateway
  action.
- History is available only for transitions recorded after the migration.
  It does not retroactively establish events for older journal rows.
- This service is not a production deployment platform or a claim of
  exactly-once external execution.
