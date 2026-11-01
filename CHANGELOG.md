# Changelog

## Unreleased

- The 0009 baseline check in `praetore-replay-postgres` (a `praetore`
  schema without migration records, recorded as 0001-0009 without running
  them) now compares the live schema with 0001-0009 applied by the same
  server, not names. In a transaction that is always rolled back, 0001-0009
  run in a scratch schema (schema name rewritten; the `praetore.tenant_id`
  setting is kept), and a canonical dump of both schemas must be identical:
  relations (kind, RLS and FORCE RLS, owner, ACL, index and view
  definitions), columns (type, NOT NULL, default, identity, collation,
  column ACL), constraints (`pg_get_constraintdef`), functions (`prosrc`,
  result, language, SECURITY DEFINER, `SET search_path`, volatility,
  STRICT, LEAKPROOF, parallel, owner, ACL; overloads are separate),
  triggers (`pg_get_triggerdef`, enabled, internal triggers), RLS policies
  (command, roles, USING, WITH CHECK), rewrite rules, inheritance and
  partitions, types, other objects in the schema, and objects in other
  schemas that depend on it. The schema owner must be the migrating role
  or one it is a member of; event triggers, default privileges for the
  schema or owner, and per-database or per-role `search_path`,
  `row_security` or `session_replication_role` settings are refused. Any
  difference refuses the migration and names the objects
  (`MigrationError::UnrecognizedSchema` now carries a `String`).
- The migration runner sends every statement with
  `search_path = pg_catalog, pg_temp` (the caller's value is restored) and
  catalog names qualified, so a `public.pg_proc` view or a `public.=`
  operator cannot shadow the catalog. It refuses a session with
  `session_replication_role` other than `origin`
  (`MigrationError::UnsafeSession`), fresh database or not, and
  `verify_runtime_role` refuses such a runtime session
  (`RuntimeRoleError::TriggersDisabled`).
- `crates/praetore-replay-postgres/migrations/.gitattributes` keeps the
  migrations LF (`*.sql text eol=lf`): their bytes are checksummed and
  compared.
- New ignored PostgreSQL tests, run in CI with `--exact`, one per case
  above.
- `examples/claude-code-hook/verify.sh` no longer exits with 141 on large
  bundles. It took the receipt for the tamper check with
  `ls evidence/*.json | head -1`; with a few hundred receipts `head` closed
  the pipe, `ls` got SIGPIPE and `pipefail` ended the script with 141 after
  every receipt had verified. It now uses a bash array from the glob. The
  policy binding is checked by `praetore-verify evidence --policy` instead of
  a Python comparison per receipt, so the exit code is 0 only when
  praetore-verify accepts every receipt and rejects the altered copy, and 1
  otherwise; the `index.json` summary is informational. New
  `examples/claude-code-hook/test-verify.sh` (in CI): 1000 receipts exit 0
  (141 before the fix), one altered receipt among them exits 1 and is named.
  `scripts/record-hook-demo.sh` had the same `ls | head` and is fixed too.
## 0.3.1-rc.1 - 2026-10-31

- CI builds `praetore-mcp` release binaries for `x86_64-unknown-linux-gnu`,
  `aarch64-apple-darwin` and `x86_64-apple-darwin` on every run, runs
  `scripts/mcp-smoke.py` on each (a real allowed and a real denied
  `tools/call` through `@modelcontextprotocol/server-filesystem@2.1.0`, then
  `verify`), and uploads `.tar.gz` archives with `.sha256` files as workflow
  artifacts. `Release checksums` now runs on every run, not only on `v*`
  tags: `scripts/release-checksums.sh` checks each runner's `.sha256`, that
  all three targets are present, that each archive holds only the binary,
  `LICENSE` and `NOTICE`, and that nothing else is in the set, then writes
  and re-checks one `SHA256SUMS` (the three archives and `praetore-verify`).
  `scripts/test-release-checksums.sh` covers those failures. Only a `v*` tag
  keeps the result as the `release-assets-<tag>` artifact.
- A pushed `v*` tag now creates the GitHub Release (job `release-publish`):
  `SHA256SUMS` is signed with Sigstore keyless signing
  (`SHA256SUMS.sigstore.json`, verified against the workflow identity before
  publishing), the notes are the tag's `CHANGELOG.md` section
  (`scripts/release-notes.sh`, tested by `scripts/test-release-notes.sh`), an
  existing release is never overwritten, and `-` tags are pre-releases. On
  every PR the signing tooling is exercised with a throwaway key, including a
  changed `SHA256SUMS` that must not verify. CI still holds no long-lived
  signing key. The macOS binaries are not signed or notarized.
- `release-publish` now needs every other `assurance.yml` gate, not only the
  release artifacts; a tag that does not equal `v` plus the workspace version
  fails before anything is published; its checkout keeps no token; the
  signature check also pins the tagged commit
  (`--certificate-github-workflow-sha`). CONTRIBUTING documents how to recover
  from a failed release job. The smoke test runs on Node 24, which
  `@modelcontextprotocol/server-filesystem@2.1.0` requires.
- **Breaking (sandbox supervisor configuration): `schema_version` 1 → 2.**
  Every route must now declare a closed schema of its action's top-level
  `parameters`. At dispatch, before any Kubernetes request, the supervisor
  answers 400 if `parameters` is not an object, has a key the route does not
  declare, has a value of another kind, or lacks a required key. Only `path`
  and `path_list` values get the lexical path check; free text in `string`
  values is not path-checked. The check is fail-closed and much stricter
  than in 0.3.0. A `path` value, and every `path_list` element, is split on
  both `/` and `\`; every segment must match `[A-Za-z0-9._-]+`, must not
  start with `.` or `-`, and must be at most 255 bytes; the whole value must
  be at most 1024 bytes (the in-process sandbox dispatcher's
  `MAX_COMPONENT_BYTES` and `MAX_PATH_BYTES`). As a consequence the
  supervisor refuses:
  - an empty value, an empty segment (`a//b`, a trailing separator as in
    `dir/`) and the segments `.` and `..`;
  - hidden names such as `.env` or `a/.git/config`, and `...` (a leading
    `.` is rejected on purpose; this may be relaxed later);
  - option-like names such as `-rf`, `--` or `a/-n`, in case a tool profile
    passes a path to a subprocess without `--`;
  - a segment longer than 255 bytes or a value longer than 1024 bytes;
  - a leading `/`, `\` or `~`, and a drive or UNC prefix;
  - spaces and punctuation outside `._-` (`+`, `@`, `~`, `%`, `:`, ...);
    `%` is always refused, including names such as `100%.txt`;
  - every non-ASCII character, including accented letters and homoglyphs
    such as Cyrillic `а` (U+0430) or full-width `ａ` (U+FF41);
  - control characters, Unicode format (Cf) and bidi characters, and
    U+2028/U+2029 (also checked explicitly, as defense in depth).
  - Not covered, because runners are Linux only: Windows reserved device
    names (`CON`, `NUL`, `COM1`, `aux.txt`) and trailing dots (`a.`, `x..`).
  - By design, only keys declared `path` or `path_list` are path-checked: a
    `string` value such as `../../etc/passwd` is accepted. Declare as `path`
    every key the runner uses as a path.
  - Path migration for callers: send `x` instead of `./x` and `dir`
    instead of `dir/`, and rename files whose names use spaces, non-ASCII
    letters, other punctuation or a leading `.` or `-` (for example
    `informe año 2026.txt` → `informe_ano_2026.txt`, `.env` → `env`) before
    routing them through a `path` or `path_list` parameter. Free text
    belongs in a `string` key.
  - Kinds: `path`, `path_list` (array of at most 64 `path` values, each
    checked), `string`, `integer`, `boolean`. Nested objects are not
    supported.
  - Schema keys must match `[a-z0-9_]+` (at most 256 bytes); otherwise the
    configuration is refused at startup. Rename keys such as `orderId`,
    `order-id` or `Path` to `order_id` or `path`.
  - `"key": "kind"` declares a **required** key. A key is optional only when
    written as `"key": {"kind": "...", "optional": true}`.
  - A version 1 file is refused at startup, not upgraded.
    `SandboxSupervisor::new` returns, and `praetore-sandbox-supervisor`
    exits with (`main` returns the error, so it is printed as
    `Error: "<message>"`):
    ```
    sandbox supervisor configuration must have schema_version 2 (version 1 has no per-route `parameters` schema; see the CHANGELOG for the migration)
    ```
  - Migration: set `"schema_version": 2` and add `parameters` to every route.
    Before (v1):
    ```json
    {"schema_version": 1, "runner_image": "…@sha256:…", "routes": [
      {"tenant_id": "…", "action_type": "orders:create", "target": "orders-api",
       "capability": "orders:write", "tool_profile": "orders-create"}]}
    ```
    After (v2):
    ```json
    {"schema_version": 2, "runner_image": "…@sha256:…", "routes": [
      {"tenant_id": "…", "action_type": "orders:create", "target": "orders-api",
       "capability": "orders:write", "tool_profile": "orders-create",
       "parameters": {
         "order_id": "string",
         "quantity": "integer",
         "attachments": {"kind": "path_list", "optional": true}}}]}
    ```
    Declare every key the tool actually receives: after the upgrade, a
    request with an undeclared key is refused.
- `praetore journal-export --tenant` orders the journal rows by
  `(created_at, request_id, agent_id)`. `(created_at, request_id)` was not a
  total order (the key is `(tenant_id, agent_id, request_id)`), so two exports
  of the same journal could differ. It now warns on stderr when the database
  role is not the least-privilege runtime role. New PostgreSQL tests: export
  as a login member of `praetore_runtime` confined by RLS without the SQL
  filter, fail closed without the tenant setting, no writes; row order with
  ties; and `praetore journal-export --tenant` plus `praetore-verify journal`
  end to end against two gateways.
- Hash-linked JSONL export of receipts, as specified in
  `docs/proposals/journal-chain-jsonl.md` (now marked implemented):
  - `praetore_core::journal_chain`: the format, the link
    (`SHA-256("PRAETORE_JOURNAL_LINK_V1\0" || u64_be(seq) || prev ||
    context_hash || attester_signature)`), a producer (`ChainExporter`) and a
    verifier (`verify_chain`) that share it.
  - `praetore journal-export (--receipts-dir DIR | --tenant UUID)
    --attester-pin HEX_FILE --output NEW_FILE` builds a chain from a
    directory of receipts or from one tenant's `praetore.execution_journal`
    rows, checking every receipt against the pinned attester key first. It
    never overwrites the output.
  - `praetore-verify journal --journal JSONL --attester-pin HEX_FILE
    [--expected-head HEX] [--policy PATH]`, brought from
    `feat/journal-chain-verifier` (`bfeade5`) by cherry-pick. Changes from
    `bfeade5`: it uses the shared core code; adds `--expected-head`
    (`JOURNAL_HEAD_MISMATCH`); every line, including the last, must end in
    `\n` and `\r` is rejected (before, `lines()` accepted CRLF and a missing
    final newline, and a file with only `\n` failed as `JOURNAL_CHAIN_FAIL`,
    now `INVALID_REQUEST`); failures print the entry on stderr; test fixtures
    updated for `Decision::allow(reason, DecidedBy)`.
  - `examples/claude-code-hook/evidence/0{3,4,5}-*/journal-chain.jsonl`
    (22, 8 and 118 entries; receipts unchanged), heads in `VERIFY.md`,
    `verify-chain.sh`, and a `journal-chain` CI job that rejects a deleted,
    deleted-and-relinked, truncated, reordered and altered copy.
  - Limit: the link is unkeyed. Anyone with the receipts can rebuild a chain
    over a subset, and the attester key holder can rebuild anything. A head
    only detects deletion or truncation if it was published outside the
    producer's control and passed as `--expected-head`; the heads in this
    repository are not such an anchor.
- **T-014, `praetore-mcp`:** arguments covered by a `PathPrefix` rule are
  resolved through the filesystem before evaluation. Unless an absolute value
  resolves to itself (no symlink, `.`/`..`, dangling link or missing parent),
  the engine sees `praetore-mcp:path-check-failed`, which core treats as an
  unsafe path (every DENY / REQUIRE_APPROVAL `PathPrefix` rule matches, no
  ALLOW one). Receipts record `context["praetore.path_check"]`; forwarded
  bytes are unchanged. Core's `PathPrefix` stays lexical. Behavior change: on
  macOS, `/tmp/...` arguments under such a rule are now refused or not
  allowed; use resolved paths. `policy` commands and `policy check` warn
  about prefixes that resolve elsewhere. The check is point-in-time (TOCTOU).
  A path that resolves to itself but is at or under a policy `PathPrefix`
  only when compared like the filesystem compares names (case folding and/or
  NFC: APFS, HFS+, casefolded ext4/f2fs, unknown filesystems), not byte for
  byte, is `ambiguous` and hidden the same way; this covers case and NFD
  variants of a denied name that does not exist yet. Case folding is full
  Unicode case folding (new dependency `caseless`) iterated to a fixed point
  (`ẞ`/`ß`/`ss`). A path that reaches a prefix's directory under another
  spelling, compared by `(st_dev, st_ino)` (macOS `/System/Volumes/Data`
  firmlinks, a bind mount of the prefix itself), is `ambiguous` too, and so
  is a path whose other macOS spelling (`/System/Volumes/Data` added or
  removed) is under a prefix (DENY `/System/Volumes/Data` covers
  `/Users/...`). `policy check` warns about prefixes that are `/System`,
  `/System/Volumes`, or at or under `/System/Volumes/Data`. On Linux, XFS
  folds (it may be `ascii-ci`), and case-folding filesystems ignore trailing
  dots and spaces. On macOS, an argument whose first segment starts with
  `.` (`/.nofollow/...`, `/.resolve/...`, `/.vol/...`) is `unresolved`, and
  so is, on every OS, anything under `/dev` or `/proc` (per-process names
  such as `/dev/fd/N`), and on macOS under `/System/Volumes/<X>` other than
  `Data`. When names fold, Unicode 16 `Default_Ignorable_Code_Point`s and
  U+F000-F0FF are dropped from the fold key (HFS+, macOS ExFAT), and a
  segment made only of them is `unresolved`. `wrap` warns at startup when
  the server command looks like `docker`, `podman`, `ssh`, `chroot`, ...
  and the policy has path rules. This is defense in depth for local
  servers in the same namespace, not a guarantee (structural fix: T-013B).
  Not covered: Linux bind mounts of a subdirectory of a prefix, hard links
  to files inside a prefix, TOCTOU, server-side decoding; not supported:
  other namespaces or hosts, network/FUSE loopback mounts.

## 0.3.0 - 2026-10-30

- The gateway-service sandbox supervisor rejects a dispatch request when any
  string value in `action.parameters`, at any depth, contains NUL, starts at
  a root (`/` or `\`), has a drive or UNC prefix, or has a `..` segment
  (T-013 fix A, lexical only; `/` and `\` are both checked on every OS).
  Symlinks are not resolved yet (fix B, stage 2).
- `crates/praetore-mcp/GUIDE.md`: a guide for external developers with a
  first-run walkthrough, the limits (only MCP `tools/call` through a wrapped
  server is governed; LOCAL/DEV keys; no approval flow for REQUIRE_APPROVAL;
  lexical path rules; TOCTOU) and a troubleshooting table.
- `praetore-mcp install`/`uninstall` process a config file once when two
  default paths name it (Cursor's `~/.cursor/mcp.json` and
  `./.cursor/mcp.json` when run from `~`, or a symlink). Before, it was
  listed twice; the second pass was skipped as already wrapped. The
  praetore-mcp README records the real-app check on macOS (Claude Desktop
  and Cursor).
- The praetore-mcp README documents installing without a clone:
  `cargo install --git https://github.com/Mavericksantander/praetore
  praetore-mcp --locked` (checked on macOS arm64 against `9735974`).
- `praetore-mcp <command> --help` / `-h` prints that command's usage and
  exits 0 (it used to fail with `unexpected argument "--help"`). `--help`
  after `wrap ... --` is still passed to the MCP server. `praetore-mcp
  version` is an alias of `--version`. Exit codes (0, 1, 2, and `wrap`'s
  server code / 127) are documented in `--help` and the praetore-mcp README.
- `praetore-mcp wrap --mode observe` no longer forwards `tools/call` without
  receipts when the home cannot be loaded at startup (not initialized, or
  invalid keys, pins, authority or policy). Both modes now refuse every
  `tools/call` in that case and print `every tools/call will be REFUSED`;
  other MCP traffic is still relayed. Per-call evaluation errors after a
  successful start keep the documented observe behavior.
- New receipts always record what decided them in `decision.decided_by`, as
  part of the hashed and Ed25519-signed evidence payload, in the new
  **evidence schema v4**:
  - `DecidedBy::Rule { rule_id }` (a rule's declared effect applied; a
    RECOVER rule's `rule_id` equals its recovery obligation's),
    `UnboundRule { rule_id }` (a REQUIRE_APPROVAL/RECOVER rule matched
    without its required capability or target and denied instead),
    `DefaultDeny` and `EngineGuard { guard }`. Combining decisions keeps the
    decider of the higher severity (`Recover > Deny > RequireApproval >
    Allow`), the earlier one on a tie.
  - Versioning: every new evidence is v4 (with or without HighAssurance
    metadata and recovery). v1-v3 must not carry `decided_by`, so existing
    receipts, golden vectors and fixtures keep verifying byte-for-byte; v4
    must carry it. `decided_by` must be consistent with the outcome,
    recovery obligation and contributions; unknown kinds, unknown fields and
    an explicit `null` are rejected.
  - Upgrade order: binaries without v4 support reject v4 evidence (fail
    closed). Upgrade every verifier, Python binding and gateway node before
    any node starts producing v4; during a mixed-version rollout or after a
    rollback, journal rows and pending approvals written by new nodes are
    unreadable (`InvalidRecord`) on old ones.
  - Breaking: `Decision` has a required `decided_by: DecidedBy` (JSON without
    it does not deserialize); `Decision::allow/deny/require_approval` take it
    as a second argument (`Decision::recover` derives it from the
    obligation). `Evidence.decision` is now a `RecordedDecision` (the read
    path) whose `decided_by` is optional, crate-private and read via
    `decided_by()`; `Decision` converts with `.into()`. `Evidence::new` and
    `attest` reject a decision that violates these invariants. Consumers that
    compared `evidence_schema_version` to 2/3 should use
    `is_high_assurance_shape()` and `decision.recovery`.
  - Dispatch revalidation compares a legacy (pre-v4) record on every field
    except `decided_by`, so approvals pending across the upgrade can still be
    dispatched; v4 records must match `decided_by` too.
  - Test fixtures in `packages/praetore-python/tests/fixtures` were
    regenerated as v4; the previous v1/v2 bytes are kept in
    `fixtures/legacy-evidence/` and still verify.
- New crate `praetore-mcp` (binary `praetore-mcp`): a local stdio MCP proxy
  for Claude Desktop, Cursor and VS Code that needs no PostgreSQL and no Rust.
  `init` creates LOCAL/DEV issuer, agent and attester keys (0600), a signed
  authority, `praetore-verify`-compatible trust pins and a default v2 policy.
  `wrap` evaluates every client→server `tools/call` in HighAssurance mode and
  appends attested evidence to an fsynced JSONL journal. In `observe` mode
  (the default) calls are always forwarded and only recorded. In `enforce`
  mode DENY and REQUIRE_APPROVAL are blocked with an MCP `isError` result,
  and errors fail closed. The mode is bound into the signed evidence as
  `context["praetore.mode"]`. `install` / `uninstall` rewrite and restore
  client configs, writing a backup and asking for confirmation first.
  `receipts` and `verify` read and check the journal. `policy
  list|check|deny|require-approval|allow|remove` manage rules without
  hand-written JSON. Each change is validated, written atomically with a
  backup, and refused when it would create an unscoped argument rule unless
  `--any-tool` is given. Limitations: stdio
  only, REQUIRE_APPROVAL is not supported, LOCAL/DEV keys only, and receipts
  attest the proxy's view of a call, not the upstream agent's intent. See
  `crates/praetore-mcp/README.md`. `praetore-core` is unchanged.
- `praetore-verify evidence` accepts `--policy PATH`: the receipt must record
  that policy's digest (`Evidence::verify_policy`); receipts without a digest
  fail with `POLICY_MISMATCH`.
- The hash-linked journal export (`praetore-verify journal`) is a proposal
  only (`docs/proposals/journal-chain-jsonl.md`). It is not shipped: the
  verifier is kept on branch `feat/journal-chain-verifier` until a Postgres
  exporter lands with it in one PR. As specified (unkeyed links, no signed
  or published head) it does not let a third party detect deletion,
  truncation, reordering or a recomputed chain; the proposal lists what is
  missing.
- `scripts/regen-legacy-evidence-fixture.sh` regenerates the legacy receipt
  fixture (no `policy_digest`) from commit 3db7b5e.

- Breaking (core): `Evidence::sign` now refuses to sign a receipt that does
  not record the full lowercase SHA-256 digest of the active policy
  (`policy_digest`, from `Policy::digest()` over the canonical JSON). The
  engine already bound it in every mode; this makes it a hard requirement of the write path, so the
  Ed25519 attester signature always covers which policy decided. Receipts
  signed before this change (no `policy_digest`) still deserialize and verify.
  Callers that sign evidence directly (not through `PolicyEngine`) must call
  `Evidence::bind_policy_digest` first.
- New `Evidence::verify_policy(&Policy)` checks that a receipt was decided
  under a given policy (digest present and equal). Legacy receipts without a
  digest return an error.
- Known limitation (accepted): legacy receipts whose `policy_digest` was
  recorded in uppercase hex still deserialize and verify, but cannot be
  re-signed, because `Evidence::sign` only accepts the lowercase SHA-256 hex
  produced by `Policy::digest()`; `verify_policy` also rejects them.
- Security (gateway HTTP API): caller authentication. `http_api::router` and
  `serve_local` now take an `ApiAuth`. `ApiAuth::Required(ApiCredentials)`
  requires `Authorization: Bearer` on every endpoint except `/healthz`, with
  tenant-scoped credentials (SHA-256 digests, constant-time comparison) whose
  tenant must match the `{tenant_id}` path segment or, for `/v1/execute`, the
  submitted authority's tenant. Roles are disjoint: `agent` may execute and
  read status; only `approver` may read challenges, decide and dispatch.
  Unauthenticated: 401 `authentication_required`; wrong role or tenant: 403
  `caller_not_authorized`.
  - Breaking (gateway service): `PRAETORE_GATEWAY_API_CREDENTIALS_FILE` is
    required with the `http` and `sandbox` adapters and for any non-loopback
    `PRAETORE_GATEWAY_LISTEN_ADDR`. Only `local-demo` on loopback may run
    unauthenticated, and `local-demo` never listens beyond loopback.
  - The freshness snapshot is read with a bounded read (not only a
    `metadata` size check), and a snapshot whose `issued_at` is older than
    one already loaded is refused (fail closed), so a stale sync or restored
    backup cannot undo a revocation.
  - Breaking (CLI): `praetore init` creates `agent-api.token` and
    `approver-api.token`; `run`, `demo`, `approve`, `reject` and `dispatch`
    use them. Older demo directories need a fresh `init`.
- Security (gateway): approver keys can be bound to a tenant
  (`HumanApprovalVerifier::for_tenant`); the gateway accepts several
  verifiers and a key never verifies another tenant's decision. Service:
  new `PRAETORE_GATEWAY_APPROVER_BINDINGS_FILE`; breaking: the single
  `PRAETORE_GATEWAY_APPROVER_KEY_ID`/`_PUBLIC_KEY_HEX` pair is rejected with
  `http`/`sandbox` unless exactly one tenant is issuer-bound (it is then bound
  to that tenant). The CLI demo approver is bound to the demo tenant.
- Security (gateway service): breaking: `http` and `sandbox` adapters require
  `PRAETORE_GATEWAY_FRESHNESS_FILE`, a file-based revocation snapshot
  (revoked authority IDs, agent key fingerprints, authority digests) with
  bounded staleness that fails closed when missing, invalid or stale
  (`PRAETORE_GATEWAY_FRESHNESS_RELOAD_INTERVAL_MS`, `_LEASE_MS`,
  `_MAX_SNAPSHOT_VALIDITY_MS`). The demo provider, which never checks
  revocation, is limited to `local-demo`.
- Security (gateway): `claim_dispatch` independently re-verifies the
  recorded approval (approve outcome, challenge bound to the persisted
  evidence and action digest, tenant-pinned approver signature, no
  self-approval) before dispatch, since `validate_evidence_for_dispatch`
  accepts `RequireApproval` evidence.
- Gateway: transient revalidation failures at dispatch claim (trusted clock,
  freshness source or replay storage unavailable) leave the execution
  `approved_pending_dispatch` instead of closing it as `dispatch_failed`.
- Gateway: new `ApprovalResolution::NotDispatched` (breaking for exhaustive
  matches) and `Gateway::approval_state`. The status endpoint reports
  `not_dispatched` plus `execution` and `not_dispatched_reason` for approved
  executions closed without dispatch, instead of `approved`.
- Breaking (gateway HTTP API): `GET /v1/approvals/{tenant}/{agent}/{request}`
  returns `{"challenge": ..., "action": ...}` (`ApprovalChallengeView`)
  instead of the bare challenge. `praetore approve`/`reject` show the action,
  verify its digest and policy digest, and require confirmation (`--yes` for
  scripts).
- Security (sandbox supervisor): worker callbacks are authenticated against
  the in-memory pending execution (constant time) before any Kubernetes API
  call; `serve_tls` takes `ConnectionLimits` (non-blocking accept, per-peer
  connection cap, header read timeout, 20 s worker connection lifetime).
- Dependencies: `praetore-gateway` now depends on `sha2` 0.11 and `subtle`
  2.6 (both already in the lockfile).

- Docs: HighAssurance replay claims are documented as keyed by
  `(tenant_id, agent_id, request_id)` (tenant from the signed authority, nil
  UUID when absent), matching the code; an action without a capability is
  documented as rejected (Strict/HighAssurance) or denied (Development), with
  no `action_type` fallback; canonical JSON key order is documented as UTF-8
  byte order, a deliberate deviation from RFC 8785's UTF-16 order (codec v1
  bytes unchanged).
- `AuthorizationEngine::validate_evidence_for_dispatch` is now documented as
  accepting ALLOW **and** REQUIRE_APPROVAL evidence (behavior unchanged; the
  gateway's post-approval path relies on it), and its error message says so.
  New `validate_allow_evidence_for_dispatch` additionally requires an ALLOW
  decision, for dispatch paths without a verified human approval.
- Security (breaking API): `Evidence::verify_key_rotation` now takes the
  trusted attester key (`&VerifiedPublicKey`) and requires a valid attester
  signature. It previously accepted an ALLOW decision protected only by the
  unkeyed `context_hash`, so anyone could forge an authorized rotation by
  rewriting the decision and recomputing the hash. Unsigned evidence (e.g.
  Development/Strict without an attester) no longer verifies as a rotation.
- Security (breaking for non-canonical input): uppercase or mixed-case hex is
  now rejected for authority signatures, `subject_key_hash` and
  `issuer_key_id` (`Authority::validate`), request intent signatures,
  evidence attester signatures, `Evidence::bind_policy_digest` and issuer pin
  public keys. `hex::decode` accepted both cases, so one signed document had
  several valid encodings. Everything this crate emits is lowercase.
- Fix: a gateway receipt for an executed or confirmed action whose adapter
  output was JSON `null` now verifies. `"output": null` deserializes to
  `None`, which verification rejected for those statuses although the
  attestation signs the digest of `null`. For `executed`/`confirmed`, an
  absent or `null` output is now verified as the JSON value `null`; other
  statuses still require no output. Serialization is unchanged, so existing
  receipts and fixtures are byte-identical.
- Security (behavior change, more restrictive, all semantics versions):
  DENY/REQUIRE_APPROVAL/RECOVER rules no longer stop applying because of
  their `required_capability` or `target`. An authority that lacks the rule's
  `required_capability` is still subject to the rule (previously
  `RequireApproval{transfer, payments:large, amount > 1000}` plus
  `Allow{transfer, payments:write}` let an authority without
  `payments:large` make large transfers without approval), and an action
  without a target matches a targeted restrictive rule (previously omitting
  the target bypassed `Deny target=prod-db`). ALLOW rules are unchanged.
  Targets stay exact, case-sensitive identifiers; this is now documented.
  Policies that used `required_capability` on a DENY rule to deny only the
  holders of that capability now deny everyone for that rule's scope.
  Such an *unbound* match (authority lacks the capability, or the action
  has no target) always contributes DENY, also for REQUIRE_APPROVAL and
  RECOVER rules: it never turns a default deny into an approvable request,
  and never emits a recovery obligation, for an authority the rule was not
  scoped to.
- Security (behavior change, more restrictive): an integer compared with a
  floating-point number no longer fails open in v1 policies. Previously a v1
  `Deny if amount > 10000` was bypassed with `"amount": 50000.0`, because
  every mixed integer/float comparison was "no match". Numeric operators now
  compare integer and float exactly (no lossy `f64` cast); `Exact`/`In`
  treat a numerically equal float as equal. In every semantics version the
  exact result applies to DENY/REQUIRE_APPROVAL/RECOVER rules, and an ALLOW
  rule never matches a mixed representation (unchanged). In v2 a mixed value
  that is definitively on the safe side of a restrictive rule (`5.0` against
  `> 10000`) no longer counts as unknown.
- **T-013:** `praetore_gateway::sandbox::SandboxDispatcher` (Unix), an
  `ActionDispatcher` executed by the gateway with a closed allowlist
  (`fs:write_file`, `fs:delete_file`) confined to a root directory.
  - Root: absolute, canonical, not `/`, owned by the gateway user, not
    group/other-writable and (macOS) without extended ACL entries; held open
    as a descriptor, refused (`sandbox_root_replaced`) if the path stops
    naming that directory and (`sandbox_root_insecure`) if owner, mode or
    ACL change later. Leftover temporary files are swept at open.
  - Paths: relative only; no `.`/`..`, empty components, NUL/control
    characters, `\`, Unicode bidi/zero-width format characters or the
    reserved `.praetore-tmp-` prefix (ASCII case-insensitive); bounded length and depth. Every
    component is opened with `openat(O_NOFOLLOW|O_DIRECTORY)`; symlinks at
    any level and mount points are refused. Targets must be absent or
    regular single-link files (no hard links, directories, FIFOs, sockets,
    devices).
  - Writes are atomic (`O_EXCL` temp file, `fsync`, `renameat`, directory
    `fsync`), mode `0600`, at most 16 KiB by default. Deletes use
    `unlinkat(…, 0)`: never a directory, never a symlink target.
  - Failures known to have happened before any effect reconcile as
    `not_applied`.
  - `praetore init --sandbox-root <dir>` / `sandbox_root` in `config.json`
    enables it in `praetore run` (fail closed if the root is invalid or
    contains/is inside the gateway directory); `praetore demo <dir> write
    <path> <content>` / `delete <path>` submit the two actions.
    `demo:set_value` is kept unchanged. No `exec`.
- New `ActionDispatcher::preflight` (default: admit) returning
  `DispatchRefused::terminal` / `::transient`. The gateway runs it at
  submission, on the approval challenge and decision, and in
  `claim_dispatch` after the approval is re-verified and the evidence
  revalidated, before the journal claim. Status never runs it (it reports
  journal state only).
  - A refusal at submission closes the execution (allowed or held for
    approval) as `not_dispatched` with the new signed reason
    `dispatch_refused`; a held approval closed this way is final and can
    never be approved, rejected or dispatched. HTTP 403
    `action_not_dispatchable` carries `reason` and the signed `receipt`.
  - At the claim, a terminal refusal closes `approved_pending_dispatch` as
    `not_dispatched` / `dispatch_refused`; a transient one leaves it
    `approved_pending_dispatch` (HTTP 503 `dispatch_temporarily_refused`).
  - A refused challenge or decision changes nothing and consumes nothing.
- New `NotDispatchedReason::DispatchRefused` (`dispatch_refused`, receipt
  schema v3), the only reason also valid for `allowed` executions
  (breaking for exhaustive matches; older verifiers reject it as unknown).
  Migration `0013_dispatch_refused` accepts it in the journal and
  attestation CHECKs, replaces the transition trigger with
  `validate_execution_journal_transition_v3` (the reason is write-once; an
  undecided requires_approval row may be closed with it), and refuses any
  human decision for an execution closed with a reason.
- **Breaking:** new `GatewayError::DispatchRefused { key, reason, transient,
  receipt }` variant.
- HTTP: `router_with_options` / `serve_local_with_options` (taking the same
  `ApiAuth`) with `HttpOptions::gateway_executes_effects`. Then
  `POST /v1/execute`, the approval challenge, decision, dispatch and
  `/status` require exactly one `praetore-exec-mode: gateway` header (exact
  value, at most 16 bytes), checked after caller authentication; otherwise
  409 `exec_mode_gateway_required` before the gateway is called. `/status`
  of an approved action answers 409 `cooperative_exec_rejected` with
  `resolution` and `execution` (also while `approved_pending_dispatch`), so
  an agent is never told to run it. Responses for effects performed by the
  gateway carry `praetore-executed-by: gateway`. The header is an
  unverifiable client declaration: it grants nothing and never changes who
  executes or what is journaled. The `praetore` CLI always sends it.
- Policy size and complexity limits are now public, documented constants in
  `praetore_core::policy`, and exceeding any of them rejects the whole policy
  with the typed `PraetoreError::PolicyLimitExceeded { limit: PolicyLimit, max }`
  (error code unchanged: `POLICY_EVALUATION_FAIL`). Nothing is ignored or
  partially applied.
  - Existing, now public: `MAX_CONDITIONS_PER_RULE` = 128 (per scope),
    `MAX_POLICY_TEXT_BYTES` = 1024 (ids, action type, target, condition key),
    canonical policy size `MAX_JSON_VALUE_BYTES` = 65 536.
  - `MAX_POLICY_RULES` = 512 (was 1024, unreachable). It sits above what
    fits in 64 KiB of canonical JSON (468 minimal rules with ids
    `r0`..`r467`; with minimal ids the canonical size limits it to fewer than 480 rules, below 512), so
    the canonical size remains the binding limit and no previously valid
    policy is rejected by the rule count.
  - Breaking: new `PraetoreError` variant; limit violations no longer surface
    as `PolicyEvaluationFailed(String)`.
  - Breaking: new limits that reject policies valid before this release:
    - capability longer than 1024 bytes (`MAX_POLICY_TEXT_BYTES`);
    - condition string (string or object key inside an expected value)
      longer than 1024 bytes (`MAX_CONDITION_STRING_BYTES`);
    - `In` (array value) with more than 256 values
      (`MAX_CONDITION_SET_VALUES`);
    - expected value nested deeper than 8 (`MAX_CONDITION_VALUE_DEPTH`).
  - The policy engine has no regular expressions, so there is no pattern limit.
- Policy validation now rejects contradictory `PathPrefix` conditions on the
  same key using segment semantics: two unrelated path prefixes (`/a` and
  `/b`), or an `Exact` safe path outside a `PathPrefix` (`/b/x` with `/a`).
  `PathPrefix` against `Prefix` is rejected only when the two are lexically
  unrelated (conservative).
- Documented over-restriction (fail closed): an unsafe value (`%`, `..`, and
  for `PathPrefix` anything not absolute and normalized) matches `Deny` and
  `RequireApproval` rules on `Prefix`/`PathPrefix` even if it lies outside the
  rule's prefix; for example a deny on `/srv/secret` also denies
  `/home/50%.txt`. Pinned by tests.

- Security: `MatchOperator::Prefix` treats a value with a `..` segment
  (split on `/` or `\`), any `%`, or a NUL as unsafe. Previously an allow
  rule with prefix `/srv/agent/` matched `/srv/agent/../../etc/passwd`.
- New `MatchOperator::PathPrefix` (`PolicyCondition::path_prefix`): purely
  lexical, whole-segment path prefix. Rule prefix and value must be absolute
  and normalized (no `.`, `..`, empty segments, `\`, NUL or `%`; the engine
  does not percent-decode). Invalid rule prefixes are rejected when the policy
  loads.
- Unsafe values for `Prefix` and `PathPrefix` always match `Deny` and
  `RequireApproval` rules and never match `Allow` rules, in both semantics
  v1 and v2 (fail closed; keeps v1 deny rules effective).
- Lexical limits, documented and pinned by tests: no filesystem access
  (symlinks out of scope), no Unicode folding (fullwidth `．．`, U+2215),
  spaces are significant, `...` is an ordinary name. No downstream layer may
  NFKC-normalize or percent-decode an authorized value.
- Behaviour change: allow rules using `Prefix` on values that contain `%`
  (for example percent-encoded URLs) no longer match.
- Breaking: `MatchOperator` is now `#[non_exhaustive]`; exhaustive `match`es
  outside `praetore-core` need a wildcard arm.

- Storage security (PostgreSQL journal and deployment templates):
  - Migrations: each migration and its `schema_migrations` row now commit in
    one transaction. 0007-0009 contain their own `BEGIN;`/`COMMIT;`, which
    used to end the runner's transaction early (a crash in between left the
    migration applied but unrecorded); the runner strips one enclosing
    top-level pair and refuses any other transaction control. Migration files
    and checksums are unchanged.
  - New migration 0011 creates the NOLOGIN group role `praetore_runtime`
    (needs `CREATEROLE`, or pre-create it) with least-privilege grants. New
    migration 0012 makes SQL refuse `approved_pending_dispatch -> dispatched`
    without an approve decision, with an expiration receipt, or with
    `expires_at` at or before the gateway observation time
    (`praetore.dispatch_observed_at`, set by `claim_dispatch`).
  - TLS: all PostgreSQL connections go through `DatabaseConnector`
    (rustls). Non-loopback hosts require `sslmode=verify-full` and
    `sslrootcert`; `prefer`/`require`/`verify-ca` are refused. The URL is
    checked before any socket is opened.
  - Breaking (gateway service): new `PRAETORE_GATEWAY_MIGRATION_DATABASE_URL`
    and `praetore-gateway-demo migrate`. With `PRAETORE_GATEWAY_ADAPTER=http`
    or `sandbox` the runtime URL no longer runs migrations, and startup
    refuses a runtime role that is superuser, `BYPASSRLS`, owns `praetore`
    objects or can create in the schema, or a schema that is not current.
    The loopback-only database check is replaced by the TLS rule above, so
    remote databases (for example in `praetore-data`) work with
    `verify-full`. The local demo and the CLI still migrate with the runtime
    URL when no migration URL is set and only warn (development only).
  - Breaking (public API): `MigrationError` has new variants
    `ExplicitTransactionControl` and `Pending`; new `DatabaseConnector`,
    `verify_runtime_role`, `verify_schema_current`.
  - Kubernetes templates (not cluster-tested): the execution-claim
    admission policy is scoped to claim ConfigMaps and the supervisor CA,
    handles DELETE via `oldObject`, no longer blocks `kube-root-ca.crt` or
    operator ConfigMaps, and lets a dedicated `claim-retention` identity (new
    Role) and namespace deletion remove claims. The Job policy exempts
    finalizer-only updates by the garbage collector / TTL / Job controllers
    on Jobs being deleted, so Foreground deletion can finish. Tool runners
    no longer share the gateway's proxy: the gateway uses
    `gateway-egress-proxy` (the only source protected tools accept) and
    runners keep `egress-proxy`, which may reach only allowed external
    destinations. Breaking: deploy the second proxy and update the gateway's
    `egress_proxy` route setting.

## 0.2.0 (not yet tagged or published)

Version bump from 0.1.0 to 0.2.0 (#10). Under Cargo's SemVer rules for `0.x`
releases, a minor-version bump is the breaking (major) bump; it is required
because #6 removed public API.

### Changes merged since the previous entries (#5, #6, #7, #8, #10, #11)

- **Breaking (#6):** removed the deprecated `AuthorizationEngine::new` and
  `AuthorizationEngine::with_clock` constructors. Use `development` /
  `development_with_clock`, or `production` with `HighAssuranceConfig`.
- **Breaking behavior (#6):** in Development mode, a matching `Allow` or
  `RequireApproval` rule without `required_capability` is denied unless the
  authority also grants the action's `action_type`; a caller-chosen
  capability alone no longer suffices.
- **Breaking (#11):** actions without an explicit capability are denied in all
  modes; the `action_type` fallback in Development is removed.
- **Dependencies (#5):** `praetore-gateway-service` no longer depends on
  `rustls-pemfile` (RUSTSEC-2025-0134); PEM parsing uses the
  `rustls-pki-types` PEM API.
- **Tests (#8):** the PostgreSQL replay-claim restart test now cleans up its
  claim using `TEST_TENANT_ID`.
- **Docs (#7):** added proposal SAF-09 (pre-authorized safety actions and
  audited break-glass), an optional opt-in extension outside the core with no
  roadmap or date commitment.
- **Release (#10):** version bump from 0.1.0 to 0.2.0.

### Earlier changes (previously listed as Unreleased)

#### Added

- A runnable end-to-end quick start covering signed identity, authority,
  request intents, Strict and HighAssurance evaluation, and evidence
  verification; expanded mode guidance and declarative policy documentation.
- A documented mandatory tool-gateway integration pattern covering action
  normalization, fail-closed dispatch, durable execution journaling, and
  crash/TOCTOU recovery limits.
- Versioned policy semantics v2: conditional DENY/REQUIRE_APPROVAL rules now
  match unknown or type-incompatible values conservatively; HighAssurance
  rejects legacy v1 policy semantics while v1 policy bytes remain stable.
- Ed25519 agent key generation, typed verified public keys, subject-key-bound
  authority issuance/verification, signed request intents, and strict engine
  issuer trust bindings.
- Canonical JSON encoding for authority and request signatures, policy SHA-256
  digests, and evidence integrity hashes.
- Deterministic exact, prefix, membership, and numeric policy conditions for
  action parameters and request context, plus policy validation and digesting.
- Evidence binding for request context and the evaluated policy digest.
- High-assurance production configuration with policy pins, bounded issuer
  trust pins, and required evidence attestation; stable evidence schema and
  canonical codec version fields.
- Domain-separated Ed25519 evidence signatures with offline verification,
  issuer key IDs/pin JSON import-export, and stricter duplicate-key-rejecting
  JSON import paths for policies, pins, and evidence.
- Explicit error kinds/codes and bounded canonical JSON validation. Evaluation
  now uses one clock snapshot for all validity checks in a request.
- Operator procedures for issuer rotation, agent key compromise, policy
  rollback, and clock validity.
- Offline `praetore-verify` commands for evidence, policy digests, and signed
  authorities, with machine-readable reason codes and explicit external pins.
- Bounded libFuzzer targets for canonical JSON, policy parsing, authority
  verification, evidence verification, and Development/HighAssurance
  evaluation, seeded from committed goldens and deterministic test fixtures.
- Pull-request/main CI gates for workspace tests, strict Clippy, formatting,
  RustSec audit, bounded fuzz smoke, Python verification tests, and CycloneDX
  SBOM artifacts; release tags produce a checksummed verifier binary artifact.
- Thin PyO3-backed Python evidence integrity and attester-signature verification
  functions, with fixtures generated by Rust test code.
- Required caller-owned one-time request claims in the HighAssurance profile;
  duplicate requests and unavailable replay storage fail closed.
- Optional PostgreSQL replay-guard adapter with atomic primary-key claims and
  CI integration tests for concurrency and persistence across clients.
- Strict unknown-field rejection for v1 typed documents, deterministic
  `AgentKeyFingerprint`, and proof-carrying key rotation evidence that does
  not imply revocation.
- Caller-supplied, veto-only freshness checks required by HighAssurance, with
  stable machine-readable failure codes.
- Versioned HighAssurance contracts: signed intents bind audience, expiry, and
  policy digest; HighAssurance requires policy semantics v2 and emits attested
  evidence schema v2 while retaining v1 verification/canonical bytes.
- HighAssurance freshness now binds the exact authority content digest and
  enforces a maximum lease; authorities must be bounded by validity dates and
  default to a 365-day maximum lifetime.
- Offline evidence-verifier output now explicitly marks its scope as historical
  receipt integrity/attestation and reports that it is not current
  authorization.
- Added a synchronous reference tool gateway that requires HighAssurance,
  dispatches the exact action from fresh ALLOW evidence, and fails closed on
  replay, journal, and adapter ambiguity. It includes adversarial tests but no
  network service or production deployment configuration.
- Added an optional PostgreSQL execution journal with unique execution claims,
  immutable authorization/action binding, monotonic durable transitions, and
  read-only recovery reconciliation. PostgreSQL CI covers concurrent
  gateways, server restart, ambiguous outcomes, and terminal-state rollback.
- Added `AtomicAuthorizationCommit` for the gateway path. PostgreSQL now
  commits the replay claim and completed, verified HighAssurance evidence in
  one transaction, verifies uncertain commit acknowledgements before
  dispatch, and blocks legacy orphan claims without reconstructing evidence.

#### Fixed

- Fixed the HighAssurance fuzz fixture to supply the required audience so
  fuzzing reaches request evaluation instead of panicking during setup.

#### Compatibility notes

- **Breaking:** in Strict and HighAssurance, a matching `Allow` or
  `RequireApproval` rule without `required_capability` now yields `Deny`.
  Add `with_capability(...)` (or `required_capability` in policy JSON) to
  those rules before upgrading. For Development rule handling, see #6 below.
- `AuthorizationEngine::evaluate(request) -> Result<Evidence>` is unchanged.
- **Breaking (fail-closed, #11):** in Development, an action without an explicit
  capability is now denied ("action does not declare a required capability")
  instead of falling back to its `action_type` as the required capability.
  Set `Action::with_capability(...)` on every action.
- **Breaking (#6):** constructor removal and the Development rule-capability
  change are described under "Changes merged since the previous entries" above.
- Public structs gained fields. Struct-literal construction may require source
  changes; constructors and builders are the preferred API ahead of v1.
- `Action::with_capability` separates action type from required authority
  capability. Actions without an explicit capability are denied in all modes
  (#11); Strict and HighAssurance already required an explicit capability.
- `Evidence::new` and `Evidence::new_with_context` return `Result` so oversized
  or invalid evidence cannot be constructed with an empty fallback integrity
  hash.
- HighAssurance callers must attach a durable, atomic `ReplayGuard` to
  `HighAssuranceConfig`; implementers must retain claims and fail closed on
  duplicate IDs or storage failure. The gateway additionally requires its
  journal to implement `AtomicAuthorizationCommit`; it cannot fall back to
  standalone replay-guard writes. Strict and Development modes are unchanged.
- HighAssurance callers must also attach a `FreshnessProvider`; non-current,
  unknown, revoked, expired, or unavailable results fail closed.
- Existing `FreshnessProvider` implementations must implement
  `check_authority` to bind freshness to the canonical authority digest. The
  compatibility default returns `FRESHNESS_INVALID`, so old providers compile
  but cannot authorize HighAssurance evaluations until migrated.
- PostgreSQL support is an optional crate. The deployment owns client
  construction, TLS, database provisioning, synchronous replication, backups,
  capacity monitoring, and application-role privileges.

#### Not yet delivered

- Python policy evaluation / authority issuance, signed release artifact
  attestations, and long-running fuzz campaigns remain follow-up work. The
  replay-guard trait is in core, but durable storage implementations and their
  operational validation remain deployment responsibilities. Release tag
  signing remains an operator-controlled procedure; CI does not hold signing
  keys.
