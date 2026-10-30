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
   trusting it or it expires.
3. Provision a new agent key using the approved key-protection mechanism,
   issue a new subject-bound authority, and verify a signed request end to end.
4. Preserve existing evidence and separately identify the compromise window;
   do not rewrite evidence or claim the old signatures identify the legitimate
   agent operator.

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
  defeats tenant isolation and the append-only triggers), and must not have
  `CREATE` on the schema.

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
evidence agent. `--require-intent` requires `--issuer-pins`, preventing an
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
`UPDATE_RECEIPT_V1_FIXTURE=1` and the same command.

The Python package provides Rust-backed integrity and attester signature
verification only (`verify_gateway_receipt` covers execution attestations,
including v3). It does not evaluate policies or establish trust in a
public key supplied by an untrusted caller.

## Release artifact integrity

For a `v*` tag, CI builds `praetore-verify` and uploads the binary and
`SHA256SUMS` as a workflow artifact. CI also uploads CycloneDX workspace SBOM
files. Follow the signed-tag procedure in [CONTRIBUTING.md](../CONTRIBUTING.md),
download those artifacts, verify the checksum, and publish them with the
release. CI does not sign artifacts or create releases automatically.
