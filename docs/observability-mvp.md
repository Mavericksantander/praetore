# Read-only observability MVP

`praetore-observe` is an operator-facing read-only view over the PostgreSQL
execution journal. It is separate from `Gateway` and `AuthorizationEngine`; it
has no dispatch, reconciliation, policy, key, or authority mutation routes.
It must not be placed on an agent's request path.

## Start and access boundary

The service binds only to a loopback address. `PRAETORE_OBSERVE_BIND` defaults
to `127.0.0.1:8088`; startup rejects non-loopback addresses. Missing or
malformed required configuration aborts startup:

- `PRAETORE_OBSERVE_TENANT_TOKENS_FILE`: JSON file with one SHA-256 digest of
  a 32-byte cryptographically random bearer token per tenant. Provision the
  raw tokens out of band through a secret manager and store only their SHA-256
  digests in this file. Protect the mounted file and rotate tokens when
  operators leave or credentials are suspected to be compromised.
- `PRAETORE_OBSERVE_DATABASE_URL`: connection information for a dedicated,
  SELECT-only PostgreSQL role.
- `PRAETORE_OBSERVE_ATTESTER_PUBLIC_KEY_HEX`: optional externally pinned
  32-byte Ed25519 attester public key. Without it, attester signatures report
  `not_configured`, never `verified`.

The API requires `Authorization: Bearer <64-hex-character-token>` on every
route. The token is SHA-256 hashed and matched in constant time against the
configured digests. Each token maps to exactly one non-nil tenant UUID. List
queries are always constrained to that authenticated tenant, and specifying a
different tenant is rejected. Detail routes for another tenant return the
same not-found response as an absent operation. Tenant ID in a URL or query is
never an identity claim. The embedded UI shell and static assets contain no
journal data and can be loaded without a token; the UI holds the supplied
token in memory only and sends it only in the authorization header. No cookie,
URL parameter, or local storage token flow exists. Responses are `no-store`
and include restrictive content-security and MIME-sniffing headers.

Do not expose this listener to a network. Remote operator access requires a
separately reviewed authenticated TLS proxy and network boundary; forwarding
the loopback listener or changing its bind check is not an approved
deployment pattern. `PRAETORE_OBSERVE_DATABASE_URL` follows the same TLS
rule as the gateway: loopback hosts and local sockets may use plaintext, any
other host requires `sslmode=verify-full` and `sslrootcert` (see
[PostgreSQL adapter](operations.md#postgresql-adapter)). The API never connects
to PostgreSQL from the browser.

Apply migrations in numeric order through
`0008_tenant_row_level_security.sql`.
Grant the service role schema usage and SELECT only on the journal identity,
digest, status, evidence, and timestamp columns, plus event identity/status/
timestamp/sequence columns. Do not grant it access to `output_json`; output availability
is derived from the journal's enforced state/output constraint. The reader
sets PostgreSQL's default transaction mode to read-only and
uses explicit read-only repeatable-read transactions for list/detail queries.
The service code contains no mutation SQL. PostgreSQL ownership and superuser
roles can override database controls, so the process must not use an owner,
superuser, or role with write grants.
At startup the service runs `verify_runtime_role` on its connection and
refuses to start if the role is an owner, superuser, `BYPASSRLS`, can
CREATE in `praetore`, holds DELETE/TRUNCATE/UPDATE/TRIGGER/REFERENCES, or
if triggers or row-level security could be switched off for the session.
The check runs once, at startup.

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

Tenant token file example:

```json
{
  "schema_version": 1,
  "tenants": [
    {
      "tenant_id": "replace-with-tenant-uuid",
      "bearer_token_sha256": "sha256-of-the-32-byte-token-in-lowercase-hex"
    }
  ]
}
```

Run with `cargo run -p praetore-observe` after provisioning the required
environment variables from a secret manager and applying migrations. Migration
0008 enables RLS on all tenant-keyed journal tables. Each observer query sets
`praetore.tenant_id` transaction-locally from the already authenticated token;
unset context returns no journal rows. The observer connection must use a
dedicated read-only role that is not a table owner, superuser, or
`BYPASSRLS` role. Migration 0008 uses `FORCE ROW LEVEL SECURITY`, so table
owners are subject to the policy too; PostgreSQL superusers and roles with
`BYPASSRLS` still bypass RLS and must not be used by the observer.

This RLS context prevents unscoped or incorrectly filtered SQL in the observer
from returning cross-tenant rows. PostgreSQL custom settings can be changed by
the connected role, so RLS with this shared connection is not protection
against compromise of the observer process or its database credential. Keep
that credential private to the service, keep operator tokens tenant-scoped,
and use separate database principals or a trusted database-side identity
mapping if the threat model requires RLS to resist a compromised application.

## API v1

All API responses are JSON. Errors use generic codes; database error details
are logged only as a bounded error category, not query values or credentials.

| Method and route | Contract |
|---|---|
| `GET /api/v1/operations` | Tenant-scoped list; optional `tenant_id` (must match the authenticated tenant), `agent_id`, `decision`, `execution_state`, `from`, `to`, `limit`, `offset`. |
| `GET /api/v1/operations/{tenant_id}/{agent_id}/{request_id}` | Detail for a tenant-scoped `(tenant UUID, agent UUID, request UUID)` key. |
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
