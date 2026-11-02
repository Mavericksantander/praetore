# Assurance traceability matrix

This matrix describes implemented checks and their routine CI coverage. Green
tests are evidence for the listed properties, not certification or proof of
absence of defects.

| Requirement | Implementation | Test / evidence | CI job |
|---|---|---|---|
| Stable canonical encoding and policy digest | `crates/praetore-core/src/canonical.rs`, `policy.rs` | `policy_canonical_bytes_match_committed_golden_vector`, `policy_digest_matches_canonical_golden_value`; `docs/golden/canonical-policy-v1.json` | `rust` |
| Agent key fingerprint v1 | `identity::AgentKeyFingerprint` and authority subject binding | deterministic seed/public-key/fingerprint vector in `docs/golden/agent-key-fingerprint-v1.json` | `rust` |
| Ed25519 identity keys are non-weak before fingerprinting or trust use | `VerifiedPublicKey::from_bytes` rejects small-order public keys | malformed-length and weak all-zero-point regression tests; strict signature verification continues to use `verify_strict` | `rust` |
| Evidence/policy v1 reject extensions and unsupported versions | strict Serde schemas and v1 version checks | `evidence_import_rejects_unknown_fields_and_versions`, `policy_import_rejects_unknown_fields_and_versions` | `rust` |
| Key rotation proof of possession | `key_rotation::KeyRotationProof`, `Evidence::verify_key_rotation(trusted_attester)` | unattested or differently attested evidence, missing/altered signature, wrong key, request replay, and evidence tampering tests | `rust` |
| Duplicate-key and bounded JSON input handling | core canonical parser and `Authority::from_json` | canonical, policy, authority, evidence, and pin parser unit tests | `rust`, `fuzz-smoke` |
| Offline historical evidence integrity and attester authentication | `crates/praetore-verify/src/main.rs` | trusted-signature/intent/authority integration case; expired, correctly signed v2 receipt verifies as historical only and a live engine rejects its expired request | `rust` |
| Signed authority and optional subject-key comparison | verifier authority command and `TrustedAuthorityIssuer::verify_authority_at` | `authority_and_policy_digest_commands_verify_and_report_stable_results` | `rust` |
| Policy digest reporting | `Policy::from_json` and `Policy::digest` in verifier | policy digest integration case and golden-vector unit tests | `rust` |
| Safety namespace manifest (G2): shared `safety:*` validator, deterministic signed manifest, domain separation | `crates/praetore-core/src/safety_namespace.rs`, `praetore policy safety-manifest`, `praetore-verify safety-manifest` | `crates/praetore-core/tests/safety_namespace.rs` (name rules, policy/validator equivalence, determinism, tampering, cross-domain, policy match), CLI tests in `praetore-cli` and `praetore-verify`; `docs/golden/safety-namespace-manifest-v1.json` | `rust`, `fuzz-smoke` |
| Parser/evaluator no-panic exploration | `fuzz/fuzz_targets/*.rs` | Seeded libFuzzer target corpora, including HighAssurance evaluation and the safety namespace manifest | `fuzz-smoke` (10 seconds per target) |
| `PathPrefix` confinement against an independent oracle | `fuzz/fuzz_targets/path_prefix.rs`, seeds in `fuzz/corpus/path_prefix`, `fuzz/path_prefix.dict` | Allow, Deny and RequireApproval rules agree with a separate whole-segment model under semantics v1 and v2 | `fuzz-path-prefix` (5 minutes on PRs touching `policy.rs` or `fuzz/`, 25 minutes daily, cached corpus) |
| Dependency advisory gate | committed `Cargo.lock` and RustSec audit | `cargo audit --locked` | `audit` |
| Python verification behavior stays Rust-backed | `crates/praetore-python/src/lib.rs` and `praetore` package | `packages/praetore-python/tests/test_verify.py` | `python-verify` |
| HighAssurance revalidates request, trust, freshness and policy at the replay-commit boundary | production engine before standalone replay claim or atomic authorization commit | advancing-clock regression proves an expired freshness lease is rejected without consuming the replay ID; request signature, intent, authority, active pins, production config and decision are also rechecked | `rust` |
| Gateway revalidates attested authorization and current freshness immediately before normal or approved dispatch | `AuthorizationEngine::validate_evidence_for_dispatch`, `Gateway::execute`, `Gateway::resolve_human_approval` and `Gateway::claim_dispatch` | evidence signature/integrity, intent expiry, issuer trust, current policy decision and recorded/live freshness lease are checked before approval consumption, after the allowed path's durable dispatch claim, and before the approved path's claim (whose compare-and-set rechecks approval expiry with the engine clock under the row lock); stale failure is terminally recorded without adapter invocation (approved path: `not_dispatched` with signed reason `approval_expired`/`dispatch_failed`); clock-advancing regressions assert no effect or retry | `rust` |
| Human-approval expiry uses the authorization engine's configured clock, not the gateway host wall clock | `AuthorizationEngine::validate_evidence_time_bounds`, `Gateway::resolve_human_approval` and `ExecutionJournal::{record_human_approval, claim_dispatch}` (engine `now` injected) | a clock-advancing rejection regression verifies that an expired signed decision is not consumed even when the host clock has not advanced | `rust` |
| HighAssurance consumes each signed request ID once and requires a live, representable freshness lease | `crates/praetore-core/src/replay.rs`, `freshness.rs`, and production engine | required-guard, duplicate-request, unavailable-store, freshness-status, zero-duration lease, expired-at-evaluation and unrepresentable-lease-bound tests | `rust` |
| HighAssurance rejects malformed startup trust configuration and invalid intent windows | `HighAssuranceConfig`, production engine validation, issuer pins and tenant-to-issuer bindings | focused tests cover non-canonical/oversized audience, non-positive and unrepresentable freshness limits, empty/nil/unknown/non-canonical/duplicate/incomplete tenant bindings, valid multi-tenant bindings, future-issued intents, overlong intent lifetimes, and signed intents expired at or before evaluation time | `rust` |
| Optional trusted-clock integration fails closed on health loss and permanently latches backward time movement | `TrustedClock`, fail-closed `TrustedClockSource`, `AuthorizationEngine::production_with_trusted_clock`, and stable `TRUSTED_CLOCK_UNAVAILABLE` error | unhealthy-clock test proves evaluation does not consume request before source recovery; regressing-clock test proves the source remains unusable even after its time catches up beyond the previous high-water mark | `rust` |
| Chrony health monitor bounds synchronization error and fails closed on source loss | `praetore-gateway-service/src/chrony_clock.rs` | tracking parser, error-bound, unsynchronized-source and background-health-loss tests | `rust` |
| Kubernetes deployment templates remain syntactically valid YAML | `.github/workflows/assurance.yml` manifest parsing step | Ruby YAML parser checks every `deploy/kubernetes/**/*.yaml` file; does not validate CRD schemas, CEL expressions, or live cluster enforcement | `rust` |
| HTTP tool adapter cannot start without an egress proxy | `HttpActionDispatcher::from_json_with_required_egress_proxy` | route-parser test rejects proxy-less production config | `rust` |
| Sandbox dispatcher requires HTTPS, mutual-TLS client identity, bounded request/response payloads, tenant/action binding, and a deterministic idempotency key | `crates/praetore-gateway-service/src/sandbox_dispatcher.rs` | endpoint validation and execution-key/action-digest binding unit tests; no live TLS or supervisor integration test yet | `rust` |
| Sandbox supervisor rejects ambiguous JSON in startup configuration and HTTP inputs, validates authority/action structure, and compares callback SHA-256 bindings in constant time before consuming a pending result | `crates/praetore-gateway-service/src/sandbox_supervisor.rs` | unit regressions cover duplicate root/route config keys, duplicate keys in nested arbitrary output, content-type handling, malformed duplicate-capability authority, non-canonical action, and equal/mismatched/malformed digest comparisons | `rust` |
| Sandbox supervisor claims each execution key in an immutable ConfigMap before creating a suspended, tenant/profile-bound Job and one-time input Secret; callbacks are token-bound | `crates/praetore-gateway-service/src/sandbox_supervisor.rs` and `deploy/kubernetes/sandbox-supervisor.template.yaml` | supervisor claim/Job construction unit tests; no target API-server, TLS handshake, runner, or cluster execution test yet | `rust` |
| PostgreSQL replay claims are atomic, fail closed on connection loss, and persist across restart | `crates/praetore-replay-postgres` and migration | disposable PostgreSQL tests for new clients, 12 concurrent clients, terminated backend/recovery, and staged abrupt server restart | `replay-postgres` |
| Gateway HighAssurance authorization and replay claim commit together | `AtomicAuthorizationCommit`, `AuthorizationEngine::evaluate_with_atomic_commit`, and `PostgresExecutionJournal` | real PostgreSQL rollback-trigger, lost-ack verification, unavailable verification, legacy orphan claim, identical duplicate, conflicting action, and independent-client concurrency tests assert both durable rows and adapter effects | `replay-postgres` |
| Reference gateway requires the atomic capability, rejects non-HighAssurance engines, and dispatches only evidence-bound ALLOW actions | `crates/praetore-gateway` | adversarial local-tool tests for deny, expired/tampered requests, backend failures, replay, ambiguity, and concurrency; historical receipts are a compile-time type mismatch | `rust` |
| PostgreSQL execution journal enforces monotonic durable transitions after atomic authorization commit | `crates/praetore-replay-postgres/src/execution.rs` and migrations `0002` / `0003` | real PostgreSQL tests for concurrent gateway instances, conflicting action content, fail-closed journal loss, restart recovery, effect/result-write crash, reconciliation, and terminal-state rollback | `replay-postgres` |
| Read-only observability reads journal state and actual post-migration transition events | `crates/praetore-observe` and migration `0004_execution_journal_events.sql` | authenticated router tests for access rejection, bounded filters, redaction, evidence status, health, and real PostgreSQL tests for history and SELECT-only role enforcement | `rust`, `replay-postgres` |
| End-to-end HighAssurance integration stays runnable | `crates/praetore-core/examples/high_assurance.rs` | workspace example command | `rust` |
| Rust tests, lint, format, patch hygiene | workspace CI workflow | workspace test suite; Clippy `-D warnings`; workspace and fuzz rustfmt; `git diff --check` | `rust` |
| Software inventory | CycloneDX Cargo integration | SBOMs for all workspace packages and standalone fuzz package uploaded as CI artifacts | `sbom` |
| Release binary integrity | verifier and `praetore-mcp` (Linux x86_64, macOS arm64/x86_64) build and checksum job on every run; artifact kept on tags | `SHA256SUMS` over the three `praetore-mcp` archives and `praetore-verify`; `scripts/test-release-checksums.sh`; Sigstore keyless signature `SHA256SUMS.sigstore.json` and GitHub Release on tags | `mcp-binaries`, `release-integrity`, `release-publish` |

## Scope limitations

- The verifier requires external attester pins and never treats a key embedded
  in evidence or authority as a trust anchor. Pin distribution is outside the
  CLI. `--require-intent` is only accepted with external issuer pins.
- Standalone authority verification can compare subject-key binding against an
  `AgentIdentity` only when the optional `--agent` input is provided.
- Fuzz CI runs bounded intervals (10-second smoke per target, 60 seconds daily,
  and 5 or 25 minutes for `path_prefix`). It is not an exhaustive campaign.
- Python exposes evidence verification only. Policy evaluation and authority
  verification remain in Rust/CLI.
- The legacy core `ReplayGuard` contract remains standalone. The reference
  gateway instead requires `AtomicAuthorizationCommit`; only the PostgreSQL
  implementation and its real-database tests demonstrate that the new claim
  and signed authorization row share one transaction. Other implementations
  must independently uphold the contract, including cross-process
  uniqueness, durable commit, and uncertain-commit verification.
- Core supplies a veto-only freshness contract only. Provider accuracy,
  freshness source integrity, and bypass prevention belong to the caller.
- The reference gateway supplies no network listener or production deployment
  configuration. The optional PostgreSQL journal provides durable primary
  database uniqueness and monotonic transitions, but operational access,
  backups, capacity, replication, failover, and deployment controls remain the
  deployer's responsibility. The core evidence signature covers authorization
  only, not later execution state.
- Kubernetes Firecracker/Kata, per-invocation Job, supervisor RBAC, admission
  policies, quotas, and network policies include templates plus a supervisor
  service and gateway mTLS client. The production runner image, durable result
  recovery across supervisor restart, and live-cluster enforcement tests are
  not implemented; syntax validation and unit tests do not establish sandbox
  execution isolation.
- CI runs the staged PostgreSQL 16 server-restart test against its service
  container. This verifies persisted rows across a primary restart, not
  replication/failover or backup guarantees. The effect adapter in tests
  shares a PostgreSQL transaction with its test effect table; arbitrary
  external adapters do not share that transaction and must supply their own
  idempotency or authoritative reconciliation contract.
- The atomic PostgreSQL authorization transaction does not include the later
  `Dispatched` transition or an external effect. Legacy replay claims without
  an authorization row remain orphaned and blocked; they are never
  automatically promoted. External effects still require a downstream
  idempotency or authoritative reconciliation contract, and PostgreSQL cannot
  fence an already-issued external call.
- The observability service binds loopback-only and authenticates API reads
  with one operator bearer token. It has no operator identity/audit trail,
  adapter-health telemetry, or remote authentication. The database reader
  depends on deployment-created SELECT-only credentials and protected local
  or tunneled PostgreSQL transport.
- CI produces an SBOM and checksums, but does not sign releases, attest
  artifacts, or protect the hosted runner/build supply chain.
