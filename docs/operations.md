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

### Schema checks, allowlists and managed PostgreSQL

The migration runner and `verify_runtime_role` refuse database state that
could let another role act as the `praetore` owner or bypass the journal's
guarantees (see `docs/threat-model.md`, section "Threat model / Modelo de
amenaza: PostgreSQL journal schema", and GHSA-67vm-x598-vhg3). Some managed
platforms install such state. Each relaxation is an explicit allowlist, off
by default, logged at startup and reported by `praetore doctor`:

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
  error naming the trigger. A listed event trigger runs with its function
  owner's privileges during every migration DDL.
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
