# Changelog

## Unreleased

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
