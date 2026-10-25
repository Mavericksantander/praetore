# PRÆTORE Core threat model

Status: engineering threat model; not a certification or security accreditation.

## Scope and assumptions

The core is a deterministic, in-process authorization library. It has no
network client, persistent storage backend, policy loader, audit daemon,
secure clock, or operating-system isolation of its own. HighAssurance can call
a caller-supplied replay-guard interface; that interface does not provide
storage itself. The caller supplies identities, authorities, a policy, trusted
issuer pins, a clock, replay storage, and any evidence consumer. Security
claims apply only when the caller validates and protects those inputs, selects
the production profile, and checks verification results.

The attacker may control an agent, submit arbitrary serialized inputs, replay
requests, modify evidence after export, or possess a stolen agent key. The
attacker may gain access to a caller/host process in the residual-risk model.
Issuer signing-key compromise, malicious build infrastructure, and privileged
host compromise cannot be repaired by an in-process authorization decision;
they require operational controls.

## Assets and trust boundaries

```text
                 deployment / operator trust domain
       +-----------------------------------------------+
       | issuer pins + validity | policy bytes + pin   |
       +-------------+----------+----------+------------+
                     |                      |
                     v                      v
+--------------------+----------------------+---------------------+
| Caller process                                                   |
| agent private key -> signed request -> AuthorizationEngine       |
|                                  ^            |                  |
|                         fixed/trusted clock   |                  |
|                                               v                  |
|                                        Evidence output           |
+-----------------------------------------------+-----------------+
                                                |
                                                v
                              evidence consumer / offline verifier
```

Trust boundaries are explicit:

* **Caller → engine:** all public structs and deserialized values are
  untrusted until validated. The caller chooses development or production
  configuration.
* **Trust store → engine:** issuer pins and attester pins must come from a
  protected, independently provisioned source. A key embedded in an authority
  or evidence document does not establish trust.
* **Policy source → engine:** a policy is executable authorization data. A
  production policy digest must be provisioned independently and compared
  before evaluation.
* **Engine → evidence consumer:** the context hash detects accidental or
  adversarial post-creation changes only if the hash itself is trusted.
  Attester signatures plus an independently trusted attester pin authenticate
  the evidence payload.
* **Host process boundary:** private keys, engine memory, clock values and
  caller configuration are exposed to a malicious or compromised host. The
  library does not provide process isolation, HSM access, or secure memory
  guarantees beyond the crypto crate's zeroization support.

## STRIDE and asset-centric threats

| Threat / asset | STRIDE | Mitigation and tests | Residual risk |
|---|---|---|---|
| Agent private-key theft; identity authenticity | Spoofing, Elevation | Strict mode verifies agent intent; HighAssurance consumes each request ID through a required guard and requires caller freshness approval; key-rotation proof and freshness-status tests | A stolen key can sign new request IDs if the caller freshness source is stale or compromised; the core has no revocation service |
| Issuer key compromise; delegated authority | Spoofing, Elevation, Repudiation | Exact issuer-name/key pins; time-bounded authority; invalid signature, wrong issuer/key, and boundary tests | A compromised trusted issuer can mint authority until operational rotation/removal |
| Policy substitution or rollback | Tampering, Elevation | Canonical SHA-256 policy digest, strict expected digest, mismatch fails closed; policy pin tests | Secure policy-pin distribution and anti-rollback persistence belong to host/operator |
| Evidence forgery/tampering | Tampering, Repudiation | SHA-256 integrity; separate attester signature and offline verification; bit-flip/wrong-key tests | Hash alone is not authenticity; trusted attester compromise permits forged evidence |
| Clock manipulation/skew | Elevation, Denial of Service | Injected clock, exact inclusive validity bounds, expired/not-yet-valid tests | Host clock and allowable skew are operational controls; no implicit tolerance |
| Development-mode misuse | Elevation | Explicit `development` constructor; deprecated compatibility constructors and HighAssurance configuration tests | Deprecation is a compile-time warning, not a runtime prohibition; deployment configuration must prohibit Development |
| Malicious host process | Information Disclosure, Tampering, Denial of Service | Core performs no implicit network or filesystem access; replay persistence is an explicit caller-owned trait; private-key wrapper redacts Debug; bounded input checks | Same-process attacker can alter memory, steal keys, patch code, falsify outputs, or bypass/roll back replay storage |
| Authority/policy rollback | Tampering, Elevation | Signed/versioned authorities and pinned policy digest; validity checks | Monotonic version state and rollback detection across restarts require external storage |
| Strict → Development downgrade | Tampering, Elevation | Production constructor creates a `HighAssurance` engine with no Development fallback; explicit profile constructors distinguish modes | A malicious deployer can change application code/configuration; signed deployment and process control required |
| Oversized/nested input | Denial of Service | Input byte/depth/count bounds tested at constructors and evaluation boundary | Runtime scheduling, memory limits, and rate limiting belong to caller |
| Weak algorithm negotiation or weak Ed25519 public point | Elevation | Ed25519-only key parser rejects malformed and small-order points; signatures use `verify_strict`; unsupported algorithm and weak-key tests | Future algorithm additions require a separate reviewed ADR |
| Verifier trusts attacker-supplied key | Spoofing, Repudiation | `praetore-verify` requires an external attester pin; issuer pins are external JSONL entries; CLI tests exercise trusted and wrong keys | The operator must provision pins independently and protect the verifier host |
| Ambiguous or malformed offline input | Tampering, Elevation | Evidence, authority, policy, identity, and pin imports use duplicate-key-rejecting bounded JSON parsing; CLI caps input size and rejects malformed pin files | CLI verifies the supplied artifact, not its provenance before it reaches the verifier |
| Fuzzer regression or panic in parser/evaluator | Denial of Service | Six dedicated libFuzzer targets, including HighAssurance evaluation, with seeded corpus; CI runs each target for a bounded smoke interval | Smoke duration is not proof of absence of defects; longer campaigns and sanitizer-supported hosts remain valuable |
| Vulnerable dependency or unreproducible Rust resolution | Tampering, Elevation, Denial of Service | Committed workspace/fuzz lockfiles, `cargo audit --locked`, CI checks, CycloneDX SBOM artifact | Advisory data can lag; SBOM and lockfile do not prove source or build-host integrity |
| Python/Rust behavior divergence | Tampering, Elevation | PyO3 binding delegates all verification to Rust; known-good/tampered fixtures test behavior in CI | Python is verify-only; the extension does not provide policy evaluation |
| Replay-store rollback, race, or outage | Elevation, Denial of Service | HighAssurance requires an atomic caller-owned guard; engine tests cover duplicate and unavailable-store fail-closed paths | Core cannot ensure storage durability, cross-process atomicity, backup integrity, or that callers use the configured engine |
| Stale or compromised freshness provider | Elevation, Denial of Service | HighAssurance binds freshness checks to the verified agent fingerprint, exact authority content digest, pinned policy digest, one clock snapshot, and a bounded lease; failures are veto-only | Provider truthfulness, source freshness, and bypass prevention are caller responsibilities |
| Cross-gateway or stale request intent | Elevation, Replay | HighAssurance requires a signed v2 intent bound to configured audience, policy digest, and bounded issue/expiry window; replay guard claims request IDs once | Audience naming, trusted time, policy-pin distribution, and guard durability remain caller responsibilities |
| Tool-gateway bypass or action substitution | Elevation | Deployment must ensure protected tools are reachable only through a gateway that constructs and executes the same normalized action it authorizes; see the [gateway integration pattern](tool-gateway-integration.md) | The core cannot prevent direct tool access, validate the real-world meaning of adapter parameters, or make external effects atomic with evaluation |
| Evidence schema extension or parser ambiguity | Tampering, Elevation | V1 evidence bytes remain frozen; v2 metadata uses a separate schema and attestation domain; unknown-field/version rejection and canonical goldens | Generic JSON values inside action parameters/context remain extensible; consumers must interpret only documented fields |

## Guarantees and non-guarantees

| Property | Guarantee | Non-guarantee |
|---|---|---|
| Integrity | Canonical SHA-256 detects evidence changes against its stored hash | Hash is unkeyed; a writer can recompute it |
| Authority authenticity | Strict profile validates an authority signature under a trusted issuer pin and binds it to the subject key | No certificate chain, discovery, revocation protocol, or implicit trust |
| Request authenticity | Strict verifies the v1 agent signature; HighAssurance verifies a v2 signature bound to audience, policy digest, and issue/expiry window, and consumes request IDs once when the caller supplies a conforming guard | No proof the agent is benign, no guarantee against new signed IDs from a stolen key, and no atomicity between authorization and action execution |
| Evidence authenticity | When required, Ed25519 attester signature is verified offline against an external attester pin | No non-repudiation against compromised keys, host, or signing device |
| Offline verifier | CLI validates historical evidence integrity, externally pinned attester signature, optional intent, and optional issuer signature/subject binding; output explicitly marks `current_authorization=false` | It does not establish current freshness, unconsumed replay state, permission to execute now, pin provenance, or that the evaluating host behaved honestly |
| Determinism | Policy decision is a deterministic fold of validated input and one supplied clock snapshot | HighAssurance evaluation success additionally depends on replay-store state and availability; evidence IDs are not deterministic |
| Availability | Bounded finite evaluation returns an explicit result or error | No availability/SLA, crash containment, memory isolation, or rate limiting |
| Time validity | Exact inclusive RFC 3339 validity checks against configured time | No clock synchronization or automatic skew compensation |
| Policy binding | HighAssurance rejects a policy or signed intent whose v2 canonical digest differs from the configured pin | Pin provisioning and anti-rollback storage remain outside the library |
| Tool enforcement | No guarantee from the library; the caller must place an unavoidable gateway before each protected side effect | Bypass prevention, action-to-effect fidelity, and crash reconciliation belong to the deployment |

## Invariants and traceability

| Invariant / requirement | Enforcing code | Test coverage | Threat |
|---|---|---|---|
| DENY dominates approval and allow | `Decision::strongest` | `policy_precedence_is_deny_then_approval_then_allow`, lattice pair matrix | Policy substitution / ambiguity |
| No matching rule defaults to DENY | `Policy::evaluate_with_context` | `unmatched_rule_denies_by_default` | Elevation |
| Strict never evaluates an unsigned authority | `AuthorizationEngine::evaluate_request` | `strict_engine_rejects_unsigned_authority` | Issuer spoofing |
| Strict proves subject key possession | authority key hash + request signature | `strict_engine_rejects_agent_key_mismatch_with_authority`, `strict_engine_requires_agent_signed_request_intent` | Agent spoofing/key substitution |
| Invalid signature cannot produce ALLOW | identity, authority and evidence verifiers | `generated_keypair_signatures_verify_only_for_matching_key_and_message`, `signed_authority_rejects_tampering_and_wrong_issuer`, strict invalid-intent tests | Forgery |
| Sandbox callback cannot consume a pending result using a mismatched token/action/execution binding | supervisor callback verifies fixed-size SHA-256 digests with constant-time comparison before removing the one-shot pending sender | `callback_digest_comparison_accepts_only_equal_canonical_sha256_values`; malformed action/authority dispatch test | Callback forgery / result substitution |
| Authority time bounds are enforced | `Validity::is_active_at` | `validity_bounds_are_inclusive`, `authority_not_yet_valid_is_rejected`, expired authority and issuer-pin tests | Clock/rollback |
| Policy pin equals evaluated policy | production engine construction/evaluation | `production_profile_rejects_policy_pin_mismatch` | Policy substitution |
| HighAssurance consumes request IDs once and checks content-bound freshness | required `ReplayGuard`; `FreshnessProvider::check_authority` receives authority digest and bounded lease is recorded in v2 evidence | required-guard, duplicate-request, unavailable-store, current/revoked/unknown/expired/too-long freshness tests | Replay / stale freshness source |
| Evidence mutation is detected | `Evidence::verify_integrity` | action/context/signature/policy digest mutation tests | Evidence tampering |
| Deterministic ordering/encoding | canonical codec and ordered context | `policy_canonical_bytes_match_committed_golden_vector`, `policy_digest_matches_canonical_golden_value`, duplicate-key parser tests | Platform/input-order variance |
| Work is bounded | request, authority and policy validators | maximum and over-limit tests | Resource exhaustion |
| Single timestamp per evaluation | `AuthorizationEngine::evaluate` passes one snapshot to all checks | `evaluation_uses_one_clock_snapshot` | Clock/rollback |
| CLI does not trust document-embedded keys | `praetore-verify` reads attester and issuer pins from separate command-line paths | `evidence_command_verifies_trusted_signature_intent_and_authority`, `evidence_command_rejects_tampered_documents_and_wrong_pins` | Operator pin provisioning |
| CLI emits stable machine result and failure status | verifier `Summary` and exit handling | `verify_cli` integration tests | Input/output transport is operator-controlled |
| Python verification is Rust-backed | `praetore-python` PyO3 crate calls core evidence APIs | Python `test_verify.py` good, tampered, and wrong-key fixtures | Python API intentionally has no evaluate or policy features |
| Parser surfaces are fuzzed in bounded CI smoke | `fuzz/fuzz_targets` and seed corpora | Each target is run by `fuzz-smoke` workflow job | A short smoke run is not exhaustive fuzz coverage |
| Build and dependency controls run in CI | `.github/workflows/assurance.yml` | `rust`, `audit`, `fuzz-smoke`, `python-verify`, `sbom`, and `release-integrity` jobs | Hosted CI and action supply chain remain trusted dependencies |

The [assurance matrix](assurance-matrix.md) maps shipped requirements to code,
tests, and CI jobs. Fuzz smoke, SBOM generation, and audit reduce risk but do
not constitute exhaustive proof, certification, or a clean-room build.

## Operational response

Rotation, compromise response, policy rollback, secure clock sourcing, and
signed deployment procedures are maintained in [operations.md](operations.md).
The vulnerability reporting path remains [SECURITY.md](../SECURITY.md).
