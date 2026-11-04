# Operations runbooks

These are operator procedures for deployments embedding the library. Praetore
Core does not persist trust state, distribute keys or policies, manage a secure
clock, or control application rollout. Use the `HighAssuranceConfig` production
profile and an authenticated configuration channel.

## Issuer key rotation

1. Generate the replacement Ed25519 issuer key in the approved key-protection
   boundary; do not place its private key in a pin document.
2. Export a new issuer pin with a bounded validity window overlapping the
   currently trusted pin. Validate and authenticate the pin document through
   the deployment's independent configuration channel.
3. Deploy both pins and confirm the effective configuration has the expected
   issuer names, key IDs, algorithms, and validity windows.
4. Issue new authorities with the replacement key and verify a staged
   authorization, including offline evidence verification.
5. After all old authorities have expired or been replaced, remove the old
   pin. Do not extend old pin validity merely to avoid an operational outage.
6. For suspected compromise, remove the affected pin immediately, reject
   authorities signed by it, and reissue necessary authorities. Expect fail
   closed behavior until a replacement pin is distributed.

## Agent key compromise

1. Stop or isolate the affected agent and prevent further use of its private
   key.
2. Remove or replace authorities bound to the compromised agent public key.
   The core has no revocation list. HighAssurance guards reject reuse of
   previously consumed request IDs, but a stolen key can create new IDs; a
   still-valid authority remains usable until relying deployments stop
   trusting it or it expires. With the gateway service's file-based freshness
   provider, add the agent's `AgentKeyFingerprint` (and/or the affected
   authority IDs) to the revocation snapshot (`PRAETORE_GATEWAY_FRESHNESS_FILE`);
   new checks refuse it within the reload interval (default 5 s) and existing
   leases end within the lease length (default 30 s). Approved executions
   still awaiting dispatch are revalidated at dispatch and closed as
   `dispatch_failed`.
3. Revoke the agent's gateway API credential by removing its entry from
   `PRAETORE_GATEWAY_API_CREDENTIALS_FILE` and restarting the gateway.
4. Provision a new agent key using the approved key-protection mechanism,
   issue a new subject-bound authority, and verify a signed request end to end.
5. Preserve existing evidence and separately identify the compromise window;
   do not rewrite evidence or claim the old signatures identify the legitimate
   agent operator.

## Gateway HTTP API credentials

The gateway service authenticates callers with tenant-scoped bearer tokens
listed by SHA-256 digest in `PRAETORE_GATEWAY_API_CREDENTIALS_FILE` (format in
[Tool gateway integration](tool-gateway-integration.md#http-api-authentication)).
It refuses to start without this file with the `http` or `sandbox` adapter.
The `local-demo` adapter listens on loopback only, with or without
credentials.

1. Issue one credential per agent workload and one per approver/operator
   system, each bound to a single tenant. Never give an agent workload an
   `approver` token: approver tokens can read approval challenges (including
   the action parameters) and dispatch approved actions.
2. Generate tokens with a CSPRNG (at least 32 bytes, e.g.
   `openssl rand -hex 32`) and store only the digest in the credentials file;
   deliver the token through the secret manager of the calling workload.
3. Rotate by adding the new digest under a new `name`, restarting the
   gateway, moving callers to the new token, then removing the old entry and
   restarting again. The file is read at startup only.
4. Monitor `401 authentication_required` and `403 caller_not_authorized`
   rates: repeated 403s with a valid token indicate a caller probing another
   tenant or an endpoint outside its role.

## Approver keys

Human-approval public keys are bound to tenants with
`PRAETORE_GATEWAY_APPROVER_BINDINGS_FILE` (format in
[Tool gateway integration](tool-gateway-integration.md#human-approvals)). An
approver key for one tenant never verifies another tenant's decisions. To
rotate, add the new key under a new `key_id` for the same tenant, restart,
move the approver system to the new key, then remove the old one. Decisions
already recorded but not yet dispatched are re-verified at dispatch against
the configured keys; removing a key before those are dispatched leaves them
`approved_pending_dispatch` (dispatch refused with
`invalid_approval_signature`) until an operator closes them with
`Gateway::reconcile` (`crash_recovered`). The single-key environment variables are accepted
only for the local demo or a gateway with exactly one issuer-bound tenant.

## Freshness snapshot

With the `http` and `sandbox` adapters the gateway requires
`PRAETORE_GATEWAY_FRESHNESS_FILE`, a revocation snapshot with a short
`valid_until` (format in
[Tool gateway integration](tool-gateway-integration.md#freshness-and-revocation-snapshot)).

1. Run a revocation publisher that rewrites the snapshot well before
   `valid_until` (for example every minute with a five-minute validity),
   writing a temporary file and renaming it into place.
2. Alert on `freshness snapshot unavailable` warnings and on
   `authorization_unavailable` (503) responses: once the snapshot is missing,
   invalid or stale, every authorization and every approved dispatch fails
   closed until it is refreshed. Approved executions stay
   `approved_pending_dispatch` meanwhile and can be dispatched again while
   their window is open.
3. Treat write access to the snapshot as equivalent to the ability to
   un-revoke an agent: the file is not signed.

## Policy rollback or substitution

1. Treat every policy digest as an immutable deployment identifier. Before
   rollout, calculate the digest using the crate's canonical codec and compare
   it to the independently approved pin.
2. For an approved rollback, explicitly approve and deploy the prior policy
   digest through the protected configuration channel. The core does not
   maintain monotonic policy version state, so deployment controls must prevent
   an unapproved rollback.
3. If the configured policy does not match its pin, do not downgrade to
   Development or remove the pin to restore service. Restore the approved
   policy/configuration pair and investigate the mismatch.
4. Confirm evaluation output includes the expected policy ID, version, and
   digest before resuming dependent operations.

## Clock source and validity boundaries

1. For an integration that must fail closed on clock-health loss, implement
   `TrustedClock` and construct the engine with
   `AuthorizationEngine::production_with_trusted_clock`. The HTTP gateway
   reference uses a Chrony tracking monitor; configure its polling interval,
   sample-age limit and error-bound threshold. Its provider must return an
   error whenever synchronization or source health is uncertain. `SystemClock`
   and `production_with_clock` do not establish time trust.
2. Provide a monitored UTC clock appropriate to the deployment's risk profile.
   The library applies exact inclusive `not_before` / `not_after` checks and
   adds no skew tolerance.
3. Keep operational margin when issuing authorities and issuer pins to account
   for measured clock uncertainty. Do not widen validity windows as a substitute
   for repairing clock synchronization.
4. Alert on clock-health loss and stop authorization if the configured clock
   cannot be trusted. `TrustedClock` failures fail closed; the core cannot
   detect manipulation in a provider that incorrectly reports healthy. For
   Chrony integration details and residual risks, see
   [`runtime-security-scaffold.md`](runtime-security-scaffold.md).
5. In tests and incident replay, use a fixed clock and preserve the exact
   timestamp supplied to evaluation.

## Production profile checks

Before deployment, verify that:

- engine construction uses `AuthorizationEngine::production` or
 `production_with_trusted_clock`, not `new`, `with_clock`, or `development`;
- deployments whose risk profile requires clock-health gating use a tested
 `TrustedClock` adapter and do not silently fall back to system time;
- the policy digest matches an approved pin;
- issuer pins are non-empty, time-bounded, and active;
- an evidence attester key is configured separately from agent and issuer
  keys, and evidence consumers trust its public key out of band;
- a durable `ReplayGuard` is shared across all engine instances in the
  authorization domain, persists claims across restart and failover, rejects
  duplicates atomically, and fails closed when unavailable or full;
- replay claims are not automatically expired, evicted, or removed during
  routine cleanup; backup and restore cannot silently roll back claims;
- the application fails closed on configuration errors and does not silently
  retry in Development mode.

The core supplies only the `ReplayGuard` contract, not a storage backend.
Storage atomicity, durability, access control, capacity monitoring, and
disaster-recovery behavior must be tested for the selected deployment.
Restoring an older replay-store backup can re-enable previously consumed
requests; treat rollback as a security incident and keep dependent actions
disabled until claims are reconciled. The library does not authenticate
deployment configuration, protect the host process, or provide a signed
deployment/rollback mechanism.

### PostgreSQL adapter

The optional `praetore-replay-postgres` crate implements the replay guard and
the gateway execution journal in the `praetore` schema.

#### Roles

Use two database roles:

- a **migration (owner) role** that owns the `praetore` schema and its tables,
  functions and triggers. It runs migrations and nothing else. Creating the
  `praetore_runtime` group role (migration 0011) needs `CREATEROLE`; a DBA may
  instead pre-create `praetore_runtime NOLOGIN`, and 0011 then only grants.
- a **runtime role** used by the gateway: a `LOGIN` member of
  `praetore_runtime`, for example
  `CREATE ROLE praetore_gateway LOGIN PASSWORD '...' IN ROLE praetore_runtime;`.
  It must not be `SUPERUSER` or `BYPASSRLS` (both ignore row-level security),
  must not own or be a member of the owner of anything in `praetore` (an owner
  can `ALTER TABLE ... NO FORCE ROW LEVEL SECURITY` or `DISABLE TRIGGER`, which
  defeats tenant isolation and the append-only triggers), must not have
  `CREATE` on the schema, must not be `CREATEROLE` (on PostgreSQL 15 and
  older it can grant itself the owner role), and must not hold `DELETE`,
  `TRUNCATE`, table-wide `UPDATE`, `TRIGGER` or `REFERENCES` on any
  `praetore` table, including through `pg_write_all_data` or a leftover
  `GRANT ALL` from an install where the gateway owned the tables.
  `verify_runtime_role` refuses each of these at startup in `http` and
  `sandbox` modes.
- The runtime session must also be one in which the append-only triggers
  and row-level security cannot be switched off and names resolve in
  `pg_catalog`. `verify_runtime_role` refuses: `session_replication_role`
  other than `origin` (`TriggersDisabled`); `row_security` or
  `session_replication_role` set for the database or the login role, a
  non-default session-start value of either (for example from
  `ALTER SYSTEM`), or a `GRANT SET`/`ALTER SYSTEM ON PARAMETER` on either
  (`UnsafeSetting`); a `search_path` set for the database or the login role,
  or a session search_path that does not start with `pg_catalog`
  (`UnsafeSetting`); and objects in `praetore` that depend on functions,
  operators, types or collations outside `pg_catalog` and `praetore`
  (`ForeignDependency`). Runtime transactions pin
  `search_path = pg_catalog, pg_temp` regardless, and `DatabaseConnector`
  starts sessions with it. The check runs once, at startup.
- Only the `search_path` refusals can be relaxed, explicitly:
  `PRAETORE_RUNTIME_ALLOW_SETTINGS=search_path` (exact names; any other
  value is a configuration error). The gateway and `praetore-observe` log
  the effective setting at startup, and `praetore doctor` reports it.
- `praetore_runtime` is a cluster-wide role, so a login member of it can
  connect to every database on the cluster that ran migration 0011. Use one
  PostgreSQL cluster per environment (staging and production never share a
  cluster), or `REVOKE CONNECT ON DATABASE ... FROM PUBLIC` and grant
  `CONNECT` per runtime role.

Migration 0011 grants `praetore_runtime` exactly what the code uses:

| Table | Privileges |
| --- | --- |
| `replay_claims` | `SELECT`, `INSERT` |
| `execution_journal` | `SELECT`, `INSERT`, `UPDATE (execution_status, output_json, not_dispatched_reason, updated_at)` |
| `execution_journal_events` | `SELECT` (rows are written by a `SECURITY DEFINER` trigger owned by the migration role) |
| `execution_attestations`, `human_approvals`, `human_approval_expirations` | `SELECT`, `INSERT` |
| `schema_migrations` | `SELECT` (startup schema check) |

No `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER` or `CREATE` is granted. All
tables carry `tenant_id` and use forced row-level security keyed on the
transaction-local `praetore.tenant_id` setting.

With `PRAETORE_GATEWAY_ADAPTER=http` or `sandbox`, `praetore-gateway-demo`
verifies at startup (before serving) that the runtime connection's session and
current role meet these rules and that the schema is current, and refuses to
start otherwise. The local demo adapter and the `praetore` CLI only warn: they
are development tools, and without a migration URL they migrate with the
runtime URL, so the runtime role owns the tables. Do not use that setup for
anything but local development.

#### Migrations

Migrations are applied by `praetore_replay_postgres::apply_migrations`. Run
them with the owner role, either as a separate step
(`PRAETORE_GATEWAY_MIGRATION_DATABASE_URL=... praetore-gateway-demo migrate`,
for example a Kubernetes init Job) or by setting
`PRAETORE_GATEWAY_MIGRATION_DATABASE_URL` for the service, which then migrates
with that URL before connecting with `PRAETORE_GATEWAY_DATABASE_URL`. Production
adapters never migrate with the runtime URL; without a migration URL they only
check that the schema is current.

Each migration runs once and is recorded with its SHA-256 in
`praetore.schema_migrations`; a recorded migration whose text changed is
refused. A migration and its record commit in one transaction owned by the
runner. Migrations 0007-0009 were written with their own `BEGIN;`/`COMMIT;`;
their text cannot change (checksums), so the runner strips one enclosing
top-level `BEGIN;`/`COMMIT;` pair and refuses any other transaction control.
Earlier releases executed those files as-is, so their `COMMIT` ended the
runner's transaction early; a crash between the body and the record could
leave such a migration applied but unrecorded, which the next start then
fails on (the migration is not idempotent everywhere). If that happens,
compare the schema with the migration and record it manually with the
owner role.

The comment in 0009 that says "migration 0007 is re-applied on every start"
describes the behavior before the runner existed; since the runner, every
migration runs exactly once. The file is kept byte-identical because its
checksum is recorded in existing databases.

A database migrated before the control table existed is adopted only if its
schema matches 0009 exactly: 0001-0009 are then recorded without executing
and only 0010+ run. A partial or unrecognized `praetore` schema is refused,
and a binary refuses to start if `schema_migrations` records a version it does
not know (for example after a rollback to an older binary).

Migration 0012 adds a defense-in-depth trigger on
`approved_pending_dispatch -> dispatched`: it requires an `approve` decision,
no approval-expiration receipt, and `expires_at` later than the gateway's
observation time, which `claim_dispatch` passes in the transaction-local
setting `praetore.dispatch_observed_at`. The database clock is deliberately
not used: the gateway's injected, trusted clock decides expiry (and is signed
into expiration receipts), and the database clock may be skewed relative to
it. A dispatch without the setting is refused.

Migrations are forward-only, including `0013_dispatch_refused` and
`0014_closed_execution_row_lock`. There is no down migration; rolling one
back means restoring a backup taken before it was applied.

#### TLS

Every connection (gateway, CLI, `praetore-observe`) validates its URL before
opening a socket:

- `sslmode=verify-full&sslrootcert=/path/ca.pem` (URL form) connects with
  rustls, verifies the server certificate chain against the given PEM roots
  and checks that the certificate names the host. There is no plaintext
  fallback.
- `sslmode=disable` or no `sslmode` is accepted only when every host is a Unix
  socket, `localhost` or a loopback IP (and every `hostaddr` is loopback).
- `prefer`, `require` and `verify-ca` are refused because they do not bind the
  certificate to the host.

Example for the Kubernetes layout (Postgres in namespace `praetore-data`):

```text
PRAETORE_GATEWAY_DATABASE_URL=postgres://praetore_gateway:...@postgres.praetore-data.svc.cluster.local:5432/praetore?sslmode=verify-full&sslrootcert=/etc/praetore/postgres-ca.pem
```

SCRAM channel binding is not offered, so do not set `channel_binding=require`;
the server is authenticated by `verify-full`. Client certificates are not
supported yet.

The library types also accept an already-created PostgreSQL client, so an
embedding deployment controls credentials, connection lifecycle and pool
topology; `DatabaseConnector` applies the TLS policy above. It sets
`synchronous_commit = on` for each claim. This flushes the primary's WAL, but
does not by itself guarantee that an asynchronous replica has the claim after
failover. HighAssurance deployments must configure and test synchronous
replication, fencing, stable storage, and restore procedures appropriate to
their recovery objectives. The table intentionally has no TTL or cleanup
mechanism; monitor its growth and fail closed rather than evicting claims.

CI exercises the adapter against a disposable PostgreSQL service, including
duplicate claims through newly created clients and concurrent connections.
That does not replace testing the target deployment's replication and
disaster-recovery configuration.


#### Read-only export and audit roles

Migration 0018 creates the NOLOGIN group `praetore_safety_audit` for login
roles that export and audit safety records without being able to write
them:

| Object | Privileges |
| --- | --- |
| schema `praetore` | `USAGE` |
| `schema_migrations` | `SELECT` |
| `safety_records` | `SELECT` (row-level security: only the registered tenants) |
| `safety_audit_tenants` | `SELECT` (only its own registrations) |

Create the role as a member of that group only and register it, as the
schema owner, for each tenant it may read:

```sql
CREATE ROLE praetore_audit_1 LOGIN PASSWORD '...' IN ROLE praetore_safety_audit;
INSERT INTO praetore.safety_audit_tenants (role_oid, tenant_id)
VALUES ('praetore_audit_1'::regrole, '<tenant uuid>');
```

`praetore journal-export --safety` accepts such a role
(`PRAETORE_SAFETY_DATABASE_URL`) and checks that it is registered for the
tenant. `verify_safety_audit_role_with` refuses an audit role that is
privileged, owns or can create in `praetore`, is a member of
`praetore_runtime` or `praetore_safety_ingest`, or holds any other
privilege on a `praetore` table. It cannot insert, update or delete safety
records, and it does not see `safety_ingest_tenants` or the ingestion key
ids registered there.
### Schema checks, allowlists and managed PostgreSQL

The migration runner and `verify_runtime_role` refuse database state that
could let another role act as the `praetore` owner or bypass the journal's
guarantees (see `docs/threat-model.md`, section "Threat model / Modelo de
amenaza: PostgreSQL journal schema", and GHSA-67vm-x598-vhg3). Some managed
platforms install such state. Each relaxation is an explicit allowlist, off
by default, logged at startup and reported by `praetore doctor`:

`PRAETORE_SCHEMA_OWNER` (one exact role name, optional) is not a relaxation
but a pin: the role that must own the `praetore` schema. When it is set,
`verify_runtime_role` refuses a schema owned by any other role (or no
schema), and migrating refuses a schema owned by another role or, when there
is no schema yet, a migrating role with another name (the schema it creates
is its own). Without it, the runtime check trusts whichever role owns
`praetore`, and the structure is compared with the migrations only when
migrating: a role with CREATE on the database that creates and migrates
`praetore` before the first legitimate migration would pass a runtime-only
startup (the next legitimate `migrate` refuses it). **Set it in production**,
in the gateway, the CLI and `praetore-observe`, to the owner role of the
migration step (each of them logs a warning while it is unset).

With a NOLOGIN owner group, install in this order (the first migration needs
the variable already set, so that the schema is created owned by the group):

1. As the database owner or a superuser: create the group `praetore_owner`
   (NOLOGIN) and the migrating login `praetore_migrator`, `GRANT praetore_owner
   TO praetore_migrator`, and `GRANT CREATE ON DATABASE <db> TO
   praetore_migrator, praetore_owner` (the migrating role creates the schema
   and the scratch schemas of the structure check; the migrations, which run
   as the group, start with `CREATE SCHEMA IF NOT EXISTS`). Grant the
   membership with its defaults (`WITH INHERIT TRUE, SET TRUE`), and do not
   make the migrating role NOINHERIT: it must both `SET ROLE` to the group
   and use its privileges. Unless the group has CREATEROLE, also create
   `CREATE ROLE praetore_runtime NOLOGIN` (migration 0011, which runs as the
   group, otherwise creates it). Do not create the `praetore` schema
   yourself: a schema without migration records is treated as a legacy
   baseline.
2. Set `PRAETORE_SCHEMA_OWNER=praetore_owner` for the migration step and
   migrate as `praetore_migrator`. With no schema yet, the runner accepts a
   migrating role that is the named role or a member of it, provided that a
   named role other than the migrating role is NOLOGIN; it creates `praetore`
   with `AUTHORIZATION praetore_owner` and runs every migration as the group
   (`SET LOCAL ROLE`), so the schema and all its objects belong to the group.
   Before anything is created, the runner refuses (`MigrationError::
   SchemaOwner`, naming the problem) a role the migrating role is not a
   member of, a membership without SET (PostgreSQL 16+) or without INHERIT
   (or a NOINHERIT migrating role), a LOGIN role, a role that does not
   exist, a predefined `pg_*` role, the bootstrap superuser, and a missing
   CREATE privilege on the database; and, if `praetore_runtime` does not
   exist and the group cannot create it, it refuses with
   `MigrationError::RuntimeGroupMissing` before migration 0001. The owner is
   checked again inside the transaction that creates or adopts the schema.
3. Set `PRAETORE_SCHEMA_OWNER=praetore_owner` and
   `PRAETORE_SCHEMA_OWNER_MEMBERS=praetore_migrator` for the gateway, the CLI
   and `praetore-observe`: the runtime check refuses any member of the owner
   that is not listed.

A database already migrated without the variable keeps its owner: set the
variable to that owner (or move ownership first, then set it). This is also
the only case in which the bootstrap superuser may be named: a legacy schema
it already owns. A new schema is never created under the pin for it.

The owner group, each of its members (the roles in
`PRAETORE_SCHEMA_OWNER_MEMBERS`) and the group's CREATE privilege on the
database are inside the trust perimeter: a member can act as the owner (for
example `SET ROLE` to the group and `ALTER TABLE ... NO FORCE ROW LEVEL
SECURITY`), and CREATE on the database allows installing trusted extensions.

A role with CREATE on the database can, since PostgreSQL 13, install a
trusted extension (`hstore`, `citext`, `pgcrypto`, ...) into any schema,
`praetore` included, without CREATE on that schema; the extension's objects
are then owned by the bootstrap superuser. The migrations create no
extension objects, so both the runtime check and the migration runner refuse
an extension installed in `praetore`, any object in `praetore` that belongs
to an extension (`pg_depend` deptype `e`), and any object in `praetore`
marked `DEPENDS ON EXTENSION` (deptype `x`), which `DROP EXTENSION` would
drop with the extension, at the request of whoever owns it; the errors name
them. Grant CREATE
on the database only to the roles that run migrations.

- `PRAETORE_RUNTIME_LOGINS` (comma-separated login roles): the logins allowed
  to be members of `praetore_runtime`. Without it, other login members are
  only reported. **Set it in production**, so that a login added to
  `praetore_runtime` by mistake is refused at startup.
- `PRAETORE_SCHEMA_OWNER_MEMBERS` (comma-separated roles): members of the
  `praetore` schema owner, for example the migrating role of a NOLOGIN owner
  group.
- `PRAETORE_TRUSTED_SECURITY_DEFINER_FUNCTIONS` (semicolon-separated,
  schema-qualified with the full signature, for example
  `public.helper(integer)`): SECURITY DEFINER functions with the owner's
  rights that other roles may execute. An entry that does not resolve is a
  configuration error. Whoever can execute an allowlisted function acts with
  its owner's privileges.
- `PRAETORE_TRUSTED_EVENT_TRIGGERS` (semicolon-separated exact names): event
  triggers that may exist while migrating. A listed trigger is accepted only
  if the trigger and its function are owned by superusers, the function is
  not in `praetore`, and neither owner is, belongs to, or has as member the
  `praetore` owner or the migrating role; otherwise migrating fails with an
  error naming the trigger. A listed event trigger fires on every migration
  DDL, in the migrating session. Its function runs with the privileges of
  the role that executes that DDL (the migrating role, or the `praetore`
  owner when the runner switches to a NOLOGIN owner group with `SET LOCAL
  ROLE`), not with its owner's, unless it is `SECURITY DEFINER`, in which
  case it runs with its owner's. PostgreSQL documents that a function
  "is to be executed with the privileges of the user that calls it" unless it
  is `SECURITY DEFINER` (`CREATE FUNCTION`), and its event-trigger chapter
  names no other identity; the test
  `postgres_migrations_trusted_event_triggers_allowlist` records
  `session_user = current_user =` the migrating role for every firing of a
  superuser-owned trigger function. The check verifies owners only, not
  what the function calls: list only triggers whose code does not depend on
  objects that other roles can change (functions of other owners, or
  unqualified names resolved through a `search_path` with a writable
  schema), because that code would run with the migrating role's rights.
- `PRAETORE_TRUSTED_DEFAULT_PRIVILEGES` (semicolon-separated
  `role:*:objtype`, objtype `r`, `S`, `f`, `T` or `n`): global default
  privileges of the `praetore` owner or the migrating role that only revoke
  privileges (for example a hardening `REVOKE EXECUTE ON FUNCTIONS FROM
  PUBLIC`). Default privileges in other schemas are not considered, because
  they never apply to `praetore` objects; entries in `praetore`, and global
  entries that grant privileges, are refused even when listed.

**Supabase (verify on your instance).** Supabase's public `supabase/postgres`
repository defines these event triggers: `issue_graphql_placeholder`,
`issue_pg_cron_access`, `issue_pg_graphql_access`, `issue_pg_net_access`,
`pgrst_ddl_watch` and `pgrst_drop_watch`. A configuration for such an
instance would be:

```
PRAETORE_TRUSTED_EVENT_TRIGGERS=issue_graphql_placeholder;issue_pg_cron_access;issue_pg_graphql_access;issue_pg_net_access;pgrst_ddl_watch;pgrst_drop_watch
```

The runner then verifies each one's owners at startup and refuses to migrate
if it cannot (for example if they are not owned by superusers unrelated to
the `praetore` owner and the migrating role). The names, their owners, the
platform's default privileges and its SECURITY DEFINER functions depend on
the instance and the platform version: check them on your instance
(`praetore doctor` lists every event trigger and why it is accepted or
refused) before adding entries.

## Post-hoc safety ingestion (G1)

`praetore-safety-ingest` records safety actions that executors of
AI-enabled systems already ran (SAF-09.5). Executors never wait for it; see
[the threat model](threat-model.md#post-hoc-safety-ingestion-g1) for what a
record shows and what it does not, and
[the format](proposals/safety-ingestion-jsonl.md).

### Deployment

- Run one ingester per tenant, on the host of the executors it serves
  (transport v1 is a local Unix datagram socket). A second ingester for the
  same tenant refuses to start: the tenant lock (migration 0019) is a row
  lock (`SELECT ... FOR UPDATE NOWAIT`) on the ingester's own registration
  in `praetore.safety_ingest_tenants`, held by an open transaction on a
  second connection. Row-level security shows that row only to the login
  role registered for the tenant, so the role of another tenant, the
  gateway's role or any other login cannot take it; they fail closed with
  "cannot lock tenant". The table owner is not subject to that policy and
  can still lock or change the row. The ingester checks the lock connection
  before each write and reconnects (taking the lock again) when it is gone.
  The lock is renewed every `PRAETORE_SAFETY_LOCK_RENEW_SECONDS` (default
  300): the ingester commits the lock's transaction and takes the lock again
  in a new one (`COMMIT; BEGIN; SELECT ... FOR UPDATE NOWAIT`), so the
  transaction id it holds (which holds back VACUUM and freezing) is never
  older than one interval. Keep the interval at 300 s or less: with a
  higher value (up to the allowed 86400 s) the ingester keeps one
  transaction id open for that whole time, which holds back VACUUM and
  freezing in the whole database just as long. Watch it with `age(backend_xid)` of the
  ingester's `idle in transaction` session in `pg_stat_activity`. The lock
  session sets `idle_in_transaction_session_timeout = 0` for itself; keep a
  server `transaction_timeout` (PostgreSQL 17) above the interval. A pooler
  in transaction mode between the ingester and PostgreSQL would break the
  lock, so connect directly. Each ingester uses two connections.
- **If the lock is lost** (a renewal finds it taken, or its connection is
  gone), the ingester keeps running: it stops writing, counts the messages
  it receives meanwhile as dropped (a signed loss record once it writes
  again), and retries taking the lock, logging each attempt. Executors are
  not affected. The lock excludes a second ingester; the integrity of a
  chain does not depend on it (the insert trigger refuses a record that
  does not extend its chain, and the ingester then reads the heads again).
- When the lock is busy, the refusal and `praetore-safety-ingest doctor`
  name the role and list its other sessions (`pid`, `application_name`,
  start time from `pg_stat_activity`): one of them holds the lock (or the
  schema owner does). Before v0.3.3 the lock was a PostgreSQL advisory lock
  that any role could take (R7); stop every v0.3.2 ingester before
  applying 0019, since the two locks do not exclude each other. To undo
  0019 alone, the schema owner runs
  [`docs/rollback/0019-safety-ingest-row-lock.sql`](rollback/0019-safety-ingest-row-lock.sql)
  with every ingester stopped (no record is touched; it sets
  `lock_timeout = '5s'`, so it fails instead of waiting behind a running
  ingester); the test
  `postgres_safety_row_lock_migration_rolls_back_and_applies_again` runs it.
- Give it its own OS user. The socket directory must be a directory (not a
  symbolic link), owned by that user, and not writable by group or others
  unless it has the sticky bit (`chmod 0700`, or `chmod 1770` with
  `PRAETORE_SAFETY_SOCKET_GROUP=<gid>` for executors in that group); since
  v0.3.3 a group- or world-writable directory without the sticky bit makes
  the ingester refuse to start, with or without a socket group (L95-1).
  The socket is created `0600`, or `0660` with that group. The ingester
  opens the directory with `O_DIRECTORY | O_NOFOLLOW` and checks it on that
  descriptor, binds in a private `0700` directory (`.bind-<pid>`) created
  and opened relative to it, and sets the group (`fchownat` with
  `AT_SYMLINK_NOFOLLOW`) and the mode on the staged entry relative to the
  private directory's descriptor, after checking that the entry is its own
  socket and before renaming it into place without replacing an existing
  entry (`RENAME_NOREPLACE` on Linux, `RENAME_EXCL` on macOS). On Linux `fchmodat` takes no
  `AT_SYMLINK_NOFOLLOW`, so the mode is set on that checked entry in a
  directory only the ingester's user can write. An existing non-socket entry
  at the path is never replaced; a stale socket nobody listens on is.
- The ingester never migrates. Apply migrations (0016 creates
  `praetore.safety_records` and the `praetore_safety_ingest` group) with the
  owner role first, as for the gateway; the ingester checks that the schema
  is current.
- It fails closed at startup, for ingestion only: a missing or invalid
  manifest, any two roles with the same key, an unsafe database role, a
  schema that is not current, the tenant lock held elsewhere, or an unsafe
  socket path. The executors are not affected; their events are dropped
  locally (counted by the client) until an ingester runs, and the gap shows
  as a loss record once events arrive again.
- `praetore-safety-ingest doctor` runs the same checks (configuration,
  manifest, distinct keys, database role, schema, tenant lock, socket path)
  without binding the socket and exits non-zero if one fails.
- `SIGTERM` or `SIGINT` stops reading, drains the queue, records pending
  losses and removes the socket.

| Variable | Meaning |
| --- | --- |
| `PRAETORE_SAFETY_SOCKET` | absolute socket path |
| `PRAETORE_SAFETY_SOCKET_GROUP` | optional numeric gid for a `0660` socket |
| `PRAETORE_SAFETY_LOCK_RENEW_SECONDS` | how often the tenant lock is renewed (default 300, 1 to 86400); a failed renewal stops writing until the lock is taken again, and the ingester keeps running and retries. Recommended: 300 or less, since a transaction id stays open for up to one interval (with 86400, a whole day) and holds back VACUUM and freezing that long |
| `PRAETORE_SAFETY_TENANT_ID` | the tenant of every record |
| `PRAETORE_SAFETY_INGEST_KEY_FILE` | the ingestion key, 64 lowercase hex characters; read with `O_NOFOLLOW`, owner-only, at most 128 bytes (a key in the environment is refused) |
| `PRAETORE_SAFETY_MANIFEST_FILE` | the signed safety namespace manifest (`praetore policy safety-manifest`), canonical file form |
| `PRAETORE_SAFETY_NAMESPACE_PIN_FILE` | the namespace public key the manifest must verify under |
| `PRAETORE_SAFETY_ATTESTER_PIN_FILE` | the gateway's evidence attester public key, only to refuse it as another role's key |
| `PRAETORE_SAFETY_PREVIOUS_INGEST_PINS_FILE` | optional: the previous ingestion public keys of a registered rotation, one 64-hex key per line (at most 16). A chain whose last record is signed by any other key makes the ingester refuse to start |
| `PRAETORE_SAFETY_SOURCE_PINS_FILE` | JSONL, one `{"source_id":"executor-1","public_key":"<64 hex>"}` per line, at most 256 sources, no key twice |
| `PRAETORE_SAFETY_DATABASE_URL` or `PRAETORE_SAFETY_DATABASE_URL_FILE` | the ingester's own role; the file form is read as an owner-only secret file. TLS `verify-full` is required unless the host is loopback or a Unix socket |
| `PRAETORE_SAFETY_QUEUE_CAPACITY` | messages buffered between the socket and the database (default 256, 1 to 4096); when full, messages are dropped and recorded as a `queue_overflow` loss |
| `PRAETORE_SAFETY_MAX_CLOCK_SKEW_SECONDS` | an event whose `occurred_at` (the source's clock) differs from the ingester's clock by more than this many seconds (default 300) keeps its status and carries the signed field `clock_skew_seconds` (`occurred_at - recorded_at`); `praetore-verify safety-journal` counts them as `clock_skew` |
| `PRAETORE_SAFETY_SOURCE_RATE`, `PRAETORE_SAFETY_SOURCE_BURST` | verified events recorded per second for one source (default 100), and the burst after a quiet period (default 1000), 1 to 1000000. Events above it are not recorded; they are counted in a signed `loss` record (`rate_limited`, `detail` names the sources), and the source's chain shows them as a `source_seq` gap when its next event is recorded |
| `PRAETORE_SAFETY_REJECTED_RATE`, `PRAETORE_SAFETY_REJECTED_BURST` | individual `rejected` records per second for all inputs that do not verify (default 10, burst 100); the rest are counted (`rejected_suppressed`) |
| `PRAETORE_SAFETY_ALLOWED_UIDS` | optional, Linux only: comma-separated user ids allowed to send (at most 32). The ingester turns on `SO_PASSCRED` and reads each datagram's `SCM_CREDENTIALS`; a datagram from another user id is not read and is counted (`peer_refused`). On any other platform setting it makes startup fail: there the socket permissions (`0600`, or `0660` with `PRAETORE_SAFETY_SOCKET_GROUP`) are the only check of who may send |
| `PRAETORE_SAFETY_MAX_SEQ_JUMP` | largest accepted step of `source_seq` above a chain's high-water mark (default 1000000, 1 to 2^53 - 1). A verified event further ahead is recorded as `rejected` (`seq_jump_too_large`) on `_unattributed` and does not move the source chain; `praetore-verify safety-journal` on `_unattributed` reports it as a warning |
| `PRAETORE_SAFETY_MAX_EPOCH_JUMP` | largest accepted step of `source_epoch` above a chain's epoch (default 1000000, 1 to 2^53 - 1). A chain without records is at epoch 0, so this also bounds its first epoch. A verified event further ahead is recorded as `rejected` (`epoch_jump_too_large`) on `_unattributed` and does not move the chain. A source's epoch advances on every start, also on starts that send nothing (a crash loop): keep this above the starts a source can make between two events. If a source is refused anyway (for example after the manual rollback, with an epoch file that kept counting), raise this setting or reset the source's epoch file to a value within it |

### Floods

A local process that can write to the socket can send as fast as it likes.
The ingester bounds what that costs. Only a verified event that can advance
its chain (a new `source_seq` above the high-water mark, or the start of a
newer epoch, within the jump limits) spends its source's budget, so only a
source key's holder spends it. Every other input, including verified events
that anyone can replay from an export (at or below the high-water mark, of
an older epoch, or beyond a jump limit), shares the budget of `rejected`
records (`PRAETORE_SAFETY_REJECTED_RATE`): a replay flood therefore grows
`_unattributed` no faster than garbage does, and a genuine `late` event
competes with that traffic. An exact duplicate of a recorded event creates
no record;
and everything not recorded one by one (rate limited, suppressed rejections,
exact duplicates, refused peers, a full queue, the database down) is added
to a signed count on `_unattributed` (`loss`, with `reason` and `dropped`),
written at most once per second (one record per reason) and when the
ingester stops. `praetore-verify safety-journal` reports the counts as
`dropped_by_reason`. None of this touches the executors: the client sends
one non-blocking datagram and never waits, so an executor's failsafe runs
whatever the ingester does.

**Exact duplicates (change to the G1 decision).** G1 first recorded every
resent event as a `duplicate` record, to keep replays visible. A replay of
captured datagrams could then grow a chain without bound, so an exact
duplicate is now only counted (`duplicate` in the signed counts, per
source). A different event with a used `source_seq` is still a `conflict`
record. Chains written before the change may hold `duplicate` records, and
the verifier still checks them.

### Source epochs

Every event carries `source_epoch`, the run of its source, and `source_seq`
starts at 1 in each epoch. A source persists its epoch with
`praetore_safety_client::EpochFile`: once per start, before the first event,
`EpochFile::start` reads the file (a missing file is epoch 0), adds one,
writes the new value to `<file>.tmp`, `fsync`s it, renames it over the file
and `fsync`s the directory. The file holds the decimal epoch and a newline,
for example `42`. Keep it on persistent storage, one file per `source_id`,
in a directory that only the source's user can write (the file and its
temporary are created owner-only, and a leftover temporary is replaced
without following links). If it cannot be read, holds anything else, or cannot be
written, `start` fails and the source must not report during that run:
falling back to 1 would make the ingester record every event as `rejected`
(`stale_epoch`). The failure must not stop or delay the executor either:
log it, alert the operator, and run without reporting (the crate example of
`praetore-safety-client` shows the pattern; never `unwrap` it).
Restoring the file from an old backup has the same effect until the epoch
passes the chain's again; set it to at least the epoch that
`praetore-verify safety-journal` reports (`source_epoch`).

An event of a newer epoch starts a new segment of the source's chain (a gap
from `source_seq` 1 is recorded as a loss of that epoch); an older epoch is
`rejected` (`stale_epoch`) on `_unattributed`. Events that a source did not
send before it stopped are not visible as a gap: the next epoch starts
afresh.

Records of the first G1 format (`schema_version` 1, before source epochs)
cannot be read by this version, and an ingester whose tenant holds them
refuses to start. They only exist on databases that ran an unreleased
build: export and verify those chains with that build, then remove the G1
storage with the manual rollback below and let the upgraded runner apply
0016 and 0017 again.

The runtime-role relaxations (`PRAETORE_RUNTIME_ALLOW_SETTINGS`,
`PRAETORE_SCHEMA_OWNER`, `PRAETORE_TRUSTED_SECURITY_DEFINER_FUNCTIONS`, ...)
apply to the ingester's role check as they do to the gateway's.

### Roles

Migration 0016 grants the NOLOGIN group `praetore_safety_ingest`:

| Object | Privileges |
| --- | --- |
| schema `praetore` | `USAGE` |
| `schema_migrations` | `SELECT` (startup schema check) |
| `safety_records` | `SELECT`, `INSERT` |
| `safety_ingest_tenants` | `SELECT` (migration 0017; row-level security shows only its own row) |

Create one login role per tenant, each a member of that group only, for
example `CREATE ROLE praetore_safety_t1 LOGIN PASSWORD '...' IN ROLE
praetore_safety_ingest;`, and register it as the schema owner with its
tenant and the id of its ingestion key (`praetore-safety-ingest doctor`
prints the key id, and the exact statement when the role is not
registered):

```sql
INSERT INTO praetore.safety_ingest_tenants (role_oid, tenant_id, ingest_key_id)
VALUES ('praetore_safety_t1'::regrole, '<tenant uuid>', '<ingestion key id>');
```

A registration names the role by its OID (migration 0018), not its name: a
role dropped and created again with the same name is a new role and is not
registered. List the registrations with `SELECT role_oid::regrole,
tenant_id, ingest_key_id FROM praetore.safety_ingest_tenants`; a row whose
role no longer exists shows a bare number and keeps the tenant (and key)
taken until the schema owner deletes it.

Row-level security on `safety_records` shows and accepts only the rows of
the tenant the session's login role (`session_user`) is registered for; the
`praetore.tenant_id` setting no longer matters for this table. The insert
trigger accepts only records that name the registered key (`key_id`); it does
not check the signature, which the ingester checks when it reads the heads
(a row with a bad signature makes it refuse to start) and the verifier
checks on export. A tenant has one
role and one key, and a key is registered for one tenant: registering one
key for two tenants is refused. The ingester and `praetore journal-export
--safety` check the registration before reading or writing and refuse a
role registered for another tenant (or, for the ingester, another key).
When rotating the ingestion key, update the row first (`UPDATE
praetore.safety_ingest_tenants SET ingest_key_id = '<new key id>' WHERE
role_oid = 'praetore_safety_t1'::regrole`), then restart the ingester with the new key. `verify_safety_ingest_role_with` refuses, at
startup, a role that is privileged, owns or can create in `praetore`, is a
member of `praetore_runtime`, or holds any privilege on another `praetore`
table (column privileges included), plus the database-wide checks of the
runtime role. The gateway's runtime role gets nothing on `safety_records`,
and `verify_runtime_role` refuses one that can insert into it. Export with
the tenant's registered role (`PRAETORE_SAFETY_DATABASE_URL`); any other
role sees no rows.

### Keys

| Key | Held by | Pinned by |
| --- | --- | --- |
| source key (one per `source_id`) | the executor | the ingester (`PRAETORE_SAFETY_SOURCE_PINS_FILE`) and the verifier (`--source-pins`) |
| ingestion key | the ingester only | the exporter and the verifier (`--ingest-pin`) |
| namespace key | whoever releases the policy (offline) | the ingester (`PRAETORE_SAFETY_NAMESPACE_PIN_FILE`) |

Generate each as 32 random bytes in hex (for example `(umask 077; openssl
rand -hex 32 > ingest.key)`); the public key is what you pin:
`praetore-safety-ingest public-key ingest.key > ingest.pub` prints it for any
of these secret key files (the file must be owner-only). A
compromised source key lets its holder sign any event for that source:
remove its pin, restart the ingester and treat that source's later records
as untrusted. After rotating the ingestion key, records keep the old key's
signature (the table is append-only): pin both keys when exporting and
verifying (`--ingest-pin` is repeatable). To rotate, list the old public
key in `PRAETORE_SAFETY_PREVIOUS_INGEST_PINS_FILE` (one 64-hex key per line),
update the tenant's `safety_ingest_tenants` row to the new key id, and start the ingester with the new key: each chain continues under the new
key, and the ingester logs every chain whose last record the previous key
signed. A chain whose last record is signed by a key that is neither the
current one nor listed there makes the ingester refuse to start: a key
change must be registered, and a row signed by an unknown key is never
continued.

### Rolling back the safety-record storage (0016 to 0019)

The migration runner is forward-only. To remove the G1 storage (for example
to downgrade to a release without it, or to start over after an unreleased
format), the schema owner runs
[`docs/rollback/g1-safety-records.sql`](rollback/g1-safety-records.sql) with
every ingester stopped:

```sh
# 1. Export and verify every chain of every tenant first.
# 2. Then, as the praetore schema owner:
psql "$OWNER_URL" -v ON_ERROR_STOP=1 \
  -c "SET praetore.rollback_confirm = 'destroy-safety-records'" \
  -f docs/rollback/g1-safety-records.sql
```

In one transaction it drops `praetore.safety_records` (with its triggers and
policies), `praetore.safety_ingest_tenants`, `praetore.safety_audit_tenants`
and the two trigger functions, revokes what 0016 and 0018 granted
`praetore_safety_ingest` and `praetore_safety_audit` in this database, and
deletes the `0016_safety_records`, `0017_safety_records_followups` and
`0018_safety_audit_and_role_oids` and `0019_safety_ingest_row_lock` rows of `praetore.schema_migrations`. It destroys every safety record, so without
the confirmation setting it refuses to run while the table holds any. The
table has `FORCE ROW LEVEL SECURITY`, so an owner without superuser or
`BYPASSRLS` would see no rows; the script lifts it first, inside the same
transaction, so the check counts every record. The test runs it as such an
owner. The
group roles are cluster-wide and are not dropped (`DROP ROLE
praetore_safety_ingest, praetore_safety_audit` once no database uses them). Afterwards
`apply_migrations` applies 0016 to 0018 again, and the tenant
registrations must be inserted again. The test
`postgres_safety_manual_rollback_removes_0016_and_0017_and_they_apply_again`
runs this script against a scratch database in CI.

### Export and verification

```sh
PRAETORE_SAFETY_DATABASE_URL=... praetore journal-export --safety \
  --tenant <uuid> --source executor-1 --ingest-pin ingest.pub --output executor-1.jsonl
praetore-verify safety-journal --journal executor-1.jsonl --ingest-pin ingest.pub \
  --source-pins sources.jsonl --expected-head <anchored head> --format json
```

Export `_unattributed` too (`--source _unattributed`): it holds the
`rejected` inputs and the losses inside the ingester. Anchor heads outside
the operator's control to detect truncation (SAF-13).

A whole-chain export holds at most 200000 records and 64 MiB. Export a
longer chain in ranges: `--from-seq 0 --limit N` writes the first range and
prints `next_from_seq`; each later range (`--from-seq <next_from_seq>`)
starts with its anchor, the record just before it. Verify each later range
with `--range --expected-anchor <head of the previous range>`; the last
range's head is the chain's head. A range never ends between a gap loss
record and the event that revealed it. `duplicate`, `conflict` and `late`
records whose earlier record is in an earlier range are reported as
`unchecked_references`, and **range verification does not check them**:
verifying each range alone does not prove that such a `late` seq was really
lost or that the referenced record (`original_record_hash`) exists and
matches. Only a whole-chain verification checks those references; when a
chain is too large for one, treat a non-zero `unchecked_references` as
unverified.

```sh
praetore journal-export --safety --tenant <uuid> --source executor-1 \
  --ingest-pin ingest.pub --from-seq 0 --limit 50000 --output part-0.jsonl
praetore journal-export --safety --tenant <uuid> --source executor-1 \
  --ingest-pin ingest.pub --from-seq <next_from_seq> --output part-1.jsonl
praetore-verify safety-journal --journal part-1.jsonl --ingest-pin ingest.pub \
  --range --expected-anchor <head of part-0> --format json
```

## Offline evidence and authority verification

Build the verifier from the locked workspace:

```sh
cargo install --path crates/praetore-verify --locked
# Or produce a local release binary:
cargo build --release --locked --package praetore-verify
```

Use an attester pin file containing the independently provisioned lowercase
hex Ed25519 public key. Issuer pins are supplied as JSON Lines, one
`TrustedAuthorityIssuer::export_pin_json()` document per line. Do not derive
trust pins from the evidence or authority being verified.

```sh
target/release/praetore-verify evidence \
  --evidence evidence.json \
  --attester-pin attester-public-key.hex \
  --issuer-pins issuer-pins.jsonl \
  --require-intent \
  --format json
```

`--issuer-pins` on evidence verification additionally validates the authority
signature, pin validity, and authority subject-key binding against the
evidence agent. The issuer pin and authority validity windows are checked at
the receipt's decision time, not at the verifier's clock: for HighAssurance
receipts this is `decided_at`, the engine's trusted clock when it evaluated
the request and checked the authority, which the context hash and attester
signature cover. A decision time before `not_before` or after `not_after`
fails (`TRUST_STORE_FAIL` for the pin, `AUTHORITY_EXPIRED` for the
authority). Receipts that record no decision time (v1, and v3/v4 without
HighAssurance metadata) carry no signed time, so they are checked at the
verifier's current time, as before, and stop verifying once their authority
or pin expires. JSON output reports the instant used as
`authority_checked_at` and its origin as `authority_checked_at_source`
(`receipt_decided_at` or `verifier_clock`); text output prints
`authority_checked_at_source` first, right after the result code. Success
shows that the authority was valid at that instant, not that it is valid now.

`--require-decision-time` (off by default) makes the evidence command fail
closed: a receipt that records no signed `decided_at` fails with
`DECISION_TIME_MISSING`, with or without `--issuer-pins`, and nothing falls
back to the verifier's clock. Use it when only HighAssurance receipts are
acceptable. The `journal` command does not check authorities and does not
accept the flag.

Known limit of the decision-time check: it is only as trustworthy as the
attester key. Anyone holding that key can sign a receipt with a back-dated
`decided_at`, and that receipt passes even after the issuer pin has expired,
because the issuer pin is also checked at `decided_at`. The attester pin is a
bare public key with no validity window, so the verifier cannot limit an
attester key to decisions made before a given date. An OK therefore proves
that the authority was valid at the signed decision time only as far as the
attester key is trusted; if an attester key is retired after compromise,
treat every receipt it signed as unverified.

Journal exports across an attester key rotation: storage records (such as
the adoption record of a legacy baseline) and receipts keep the signature of
the key that was current when they were written, and are never re-signed.
`praetore journal-export` and `praetore-verify journal` therefore take
`--attester-pin` more than once; pass the retired key's pin together with the
current one. With only the current pin, exporting any chain of a database
adopted before the rotation fails, naming the key that signed the adoption
record. Pinning a retired key keeps accepting everything it signed. After a
compromise, treat what that key signed as unverified and do not pin it; the
export of a database whose adoption record it signed then fails, because
`journal-export --tenant` verifies that record before it references the
database head (`docs/proposals/journal-chain-jsonl.md`).

Planned, when evidence sets 04 and 05 are re-recorded with HighAssurance
receipts (required before 2027-01-29, when their authorities and issuer pins
expire): `--require-decision-time` becomes the default, with an explicit
`--allow-verifier-clock` to keep the verifier-clock fallback, and the
attester pin gets a validity window that `decided_at` must fall inside. `--require-intent` requires `--issuer-pins`, preventing an
intent signature from being accepted under only a self-asserted embedded
agent key. For standalone authority documents, `--agent agent.json` is
optional; without it, the CLI verifies the signed subject-key hash is present
but cannot compare it to a separately supplied agent identity. Use JSON output
for machine consumption and check both exit status and `code`. Evidence
verification is historical receipt integrity/authenticity verification: it
does not establish that the intent or freshness lease is still current, that a
request ID has not already been consumed, or that an action may be executed
now. JSON output explicitly includes
`verification_scope=historical_receipt_integrity_and_attestation` and
`current_authorization=false`. Never use verifier success as a live
authorization decision or execution permit.

`praetore-verify policy-digest --policy policy.json --format json` prints the
canonical policy digest. This command computes a digest; it does not establish
that the policy is approved. Compare the result with the independently
provisioned production pin.

`praetore-verify receipt --receipt receipt.json --execution-pin key.hex
--key-id ID --evidence-attester-pin attester.hex --format json` verifies a
gateway receipt's signed execution attestation (schema v1, v2 or v3) and the
embedded evidence's `attester_signature` against the pinned evidence attester
key; a missing or invalid evidence signature fails with
`RECEIPT_EVIDENCE_SIGNATURE_INVALID`. Both signatures must be exactly 128
lowercase hex characters; uppercase or mixed case is rejected. The execution attestation binds the
evidence `context_hash`, which excludes that signature, so both checks are
required. A v3 attestation carries
`not_dispatched_reason` (`approval_expired`, `dispatch_failed` or
`crash_recovered`); unknown reasons fail with `RECEIPT_INVALID`, a reason that
does not match the signature fails with `RECEIPT_SIGNATURE_INVALID`. Like
`evidence`, this is historical verification only (`current_authorization=false`).

`praetore-verify safety-journal --journal executor-1.jsonl --ingest-pin
ingest.pub [--source-pins sources.jsonl] [--expected-head HEX] --format json`
verifies one exported chain of post-hoc safety records (G1; see
[Post-hoc safety ingestion](#post-hoc-safety-ingestion-g1)) and reports the
count of each status (`accepted`, `undeclared`, `invalid_name`, `duplicate`,
`conflict`, `late`, `rejected`, `loss`, lost events and dropped messages).
It does not show that an action ran or that every action was reported.

Receipt verification lives in the `praetore-receipt` crate, which has no
server dependencies (no axum or tokio); `praetore-gateway` re-exports it.
The receipt fixtures in `packages/praetore-python/tests/fixtures` are signed
with the test execution key; `receipt-evidence-attester-public-key.hex` is the
test evidence attester key that signed their evidence. Regenerate v2/v3 (and v1) with
`UPDATE_RECEIPT_FIXTURES=1 cargo test -p praetore-gateway --test enforcement receipt_fixtures`.
The gateway no longer emits v1, so `receipt-v1-confirmed.json` is the committed
v2 receipt re-signed as a legacy v1 attestation; regenerate only it with
`UPDATE_RECEIPT_V1_FIXTURE=1` and the same command. Regenerated receipts carry
evidence schema v4 (`decision.decided_by`). `fixtures/legacy-evidence/` keeps
receipts and evidence whose evidence predates v4 (schema v1/v2); they are
never regenerated and must keep verifying unchanged.

The Python package provides Rust-backed integrity and attester signature
verification only (`verify_gateway_receipt` covers execution attestations,
including v3). It does not evaluate policies or establish trust in a
public key supplied by an untrusted caller.

## Release artifact integrity

For a `v*` tag, CI builds `praetore-verify` and the `praetore-mcp` archives
for `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` and
`x86_64-apple-darwin`, writes one `SHA256SUMS` (`scripts/release-checksums.sh`;
the checks also run on every PR), signs it with Sigstore keyless signing
(`SHA256SUMS.sigstore.json`) and creates the GitHub Release with those files.
CI also uploads CycloneDX workspace SBOM files as workflow artifacts; they
are not attached to the release automatically. Follow the signed-tag
procedure in [CONTRIBUTING.md](../CONTRIBUTING.md) and verify a download with:

```sh
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity https://github.com/Mavericksantander/praetore/.github/workflows/assurance.yml@refs/tags/vX.Y.Z \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-sha "$(git rev-parse 'vX.Y.Z^{commit}')" \
  SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
```

The signature proves that `SHA256SUMS` was produced by this repository's
`assurance.yml` workflow for that tag at that commit
(`--certificate-github-workflow-sha`); it does not prove who pushed the tag
(check the signed tag with `git verify-tag`). The macOS binaries are not
signed or notarized.
