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
| Development-mode misuse | Elevation | No default mode: only explicitly named `development*` constructors (no `new`, no `Default`, `compile_fail` doc tests); no capability fallback to `action_type` in any mode; HighAssurance configuration tests | Calling `development` is still possible; deployment configuration must prohibit Development |
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

### Mission and safety actions (G7): limits

* Classification needs a readable, valid policy. If `policy.json` cannot be
  read or parsed (missing, not a regular file, invalid JSON, format 1), the
  Claude Code hook and the `praetore-mcp` gate cannot classify any tool call
  and refuse all of them, `safety:*` included (fail closed). `praetore-mcp`
  does the same when the rest of its home cannot be loaded: missing or
  mismatched agent or attester keys, issuer pins or authority. This is
  intentional and is not changed by G7.
* In `praetore-mcp` a JSON-RPC batch is all or nothing in enforce: a
  declared Safety call in a batch with a blocked call is not forwarded.
  Safety calls should not be batched.
* A safety failsafe of an AI-enabled system therefore must not depend on
  PRÆTORE. It runs outside PRÆTORE's decision loop and must not rely on the
  hook, the gate or the gateway being available. Routing a safety action
  through PRÆTORE gives an immediate `SAFETY_ACTION_NOT_GOVERNED` answer only
  while the policy is loaded; it is not a substitute for the executor's own
  path.
* With a loaded policy, a declared `Safety` action is answered before any
  evaluation, replay claim, journal write or signature, so an unavailable
  journal does not hold it. `praetore-mcp` forwards it to the wrapped server
  without a receipt in both modes (a line that praetore-mcp cannot parse and
  that may name a `safety*` tool is refused instead, because it cannot be
  checked against the declared actions). Safety actions are recorded only after
  the fact, by the separate ingestion path (SAF-09.5, G1; see
  [Post-hoc safety ingestion (G1)](#post-hoc-safety-ingestion-g1)), never
  on the decision path.
* An undeclared `safety:*` action is refused at every entry point.
* Upgrades: a release with G7 does not load a policy format 1 document.
  State written before G7 refuses every tool call after the upgrade until
  its policy is migrated to format 2, so the policy must be migrated before
  the binary is upgraded.
* Declaring an action `Safety` takes it out of governance entirely, and the
  trust rests with the policy author: PRÆTORE does not check what the action
  does. A `safety:` name is not bound to an executor; in `praetore-mcp` a
  tool with that name on any wrapped server is forwarded without a receipt.
* Before classification, the entry points can still refuse or delay a call
  for reasons unrelated to the decision path: the hook denies input it
  cannot read or parse (for example more than 32 MiB or invalid JSON) and
  parses the whole policy on every call; `praetore-mcp` handles client lines
  one at a time, so a `safety:*` call waits behind a mission call that is
  being evaluated, signed and journaled; the gateway authenticates and
  parses the request first.
* The diagnostics that the hook and `praetore-mcp` write to stderr for a
  safety action (`SAFETY_ACTION_NOT_GOVERNED ...`) are not evidence: they
  are unsigned, and hosts may keep them in their own logs.
* An undeclared action is refused with a signed DENY (engine guard
  `unclassified_action`), after the same verification as a mission request,
  so a forged or unauthenticated request gets no receipt. Every DENY gets
  the same client-facing answer at the gateway, in `praetore-mcp` and in the
  hook, so a DENY does not reveal whether an action type is declared or
  which rule matched. This applies to DENY only: a REQUIRE_APPROVAL answer
  still carries the receipt (gateway) or names the rule (`praetore-mcp`).
* Gateway exception for the reserved prefix: `POST /v1/execute` answers
  every action type that starts with `safety:` with the same 422
  `safety_action_not_governed`, before any verification, engine, journal or
  signing work, whether the policy declares it `Safety` or not. An
  undeclared `safety:*` therefore gets no receipt at the gateway. Every
  request at this gate, declared or not, writes the same unsigned WARN log
  line (claimed agent id and action type, bounded and escaped, and
  `declared=true|false`), so both branches do the same work and operators
  still see attempts on undeclared names. Only the exact lowercase prefix
  `safety:` takes this path: `SAFETY:x` or `safety：x` (full-width colon)
  cannot be declared and go through the unclassified path, which, for an
  authenticated and verified request, leaves a signed `unclassified` DENY. The reason is that the answer then depends only on the public prefix
  rule, so an authenticated agent cannot use it to enumerate the Safety part
  of `action_classes`. `praetore-mcp` and the hook keep the signed
  `unclassified` DENY for an undeclared `safety:*`; there the Safety part of
  the table is observable by design (a declared one is forwarded or gets no
  decision).
* Known limits: response timing is not uniform. An undeclared action skips
  rule evaluation. On the reserved-prefix path both branches now log the
  same line, which reduces the timing difference between a declared and an
  undeclared `safety:*` but does not eliminate it (the table lookup and the
  `declared` value still differ). In `praetore-mcp` observe mode a policy
  DENY is forwarded while an undeclared action is refused.
* Text meant for people escapes characters that render invisibly or reorder
  text (zero-width, bidi, control) as `\u{XXXX}`: `praetore-verify
  --format text`, `praetore-mcp` tables and stderr lines, the hook's stderr
  lines, and the gateway's WARN line. Receipts, JSONL exports and JSON output keep the exact bytes.
  `praetore journal-export` writes JSONL and a JSON summary only, so it has
  no text rendering of action types. Audits should select unclassified
  refusals by `decided_by` (`engine_guard` / `unclassified_action`), not by
  the action type.

### Safety namespace manifest (G2)

What a verified manifest shows: the holder of the pinned namespace key
stated that the format 2 policy with digest `policy_digest` (id
`policy_id`, version `policy_version`) declares exactly the `Safety` names
in `safety_actions`. With `--policy`, `praetore-verify safety-manifest` also
shows that the given policy file is that policy. An executor of an
AI-enabled system and PRÆTORE that both hold a verified manifest for the
same digest agree on the safety namespace, and an executor holding the
manifest of another version sees `POLICY_MISMATCH`.

What it does not show or do:

* It authorizes nothing. It grants no capability, and holding it permits no
  action, mission or safety.
* It is not consulted on the decision path. No engine, gateway, gate or
  hook reads it; a missing, stale or invalid manifest changes no decision
  and no G7 answer. A safety failsafe must still not depend on PRÆTORE.
* It says nothing about what a safety action does, whether an executor
  implements it, or whether it ran. A name in the manifest is only a name
  the policy author declared `Safety`.
* It is not a freshness or revocation statement: a manifest for an old
  policy version still verifies. Executors compare `policy_version` and
  `policy_digest` with the policy they expect; there is no anti-rollback.
* Pin provisioning is outside PRÆTORE, as for the other pins. Whoever holds
  the namespace key can sign any namespace for any digest.

Key separation: the namespace key (`SafetyNamespaceKey`) is a role of its
own. It is not the evidence attester key, which is online on the decision
path, and not the authority issuer key, which grants capabilities, so a
compromise of either does not let an attacker publish a namespace, and the
namespace key can stay offline with the policy release. Its signature
domain `PRAETORE_SAFETY_NAMESPACE_V1\0` and key id domain
`PRAETORE_SAFETY_NAMESPACE_KEY_V1\0ed25519\0` are distinct from, and
prefix-free with, every other domain in the repository
(`crates/praetore-core/tests/safety_namespace.rs` scans them), so even the
same key bytes used in two roles give signatures that do not verify across
roles and key ids that differ. Using one key for two roles is still a
deployment error, which `ensure_distinct_keys` detects wherever both keys
are present.

`ensure_distinct_keys` refuses the same public key in the namespace role
and in another role (`SameKeyForBothRoles`, `SAFETY_MANIFEST_SAME_KEY`).
`praetore policy safety-manifest` and `praetore-verify safety-manifest` call
it for each `--other-pin` (repeatable: the attester and every issuer key;
`--attester-pin` is an alias). There the check is opt-in, because an
offline command does not know a deployment's other keys. The ingestion path
(`praetore-safety-ingest`, G1) and any online loader that holds the namespace key or pin together
with the attester or issuer key must enforce it at startup, without a flag.

The namespace key file is opened once with `O_NOFOLLOW | O_NONBLOCK |
O_CLOEXEC` and checked with `fstat` on that descriptor (regular file, owned
by the effective uid, no group or other bits, at most 128 bytes) before it
is read through the same descriptor, so a symlink, a FIFO or a file swapped
between the check and the read is refused. On macOS a file with any
extended ACL entry (`chmod +a`), which the mode bits do not show, is
refused, and so is one whose ACL cannot be read; on Linux a POSIX ACL with
named entries sets the group bits to its mask, so the mode check already
covers it. Symlinks in parent directories are still followed. The local demo keys (`read_secret`) are still checked
by path; moving them to the same helper is a follow-up.

One manifest has one valid file: the canonical document and one newline.
Any other encoding is rejected, so a hash of the file identifies the
manifest. The manifest is written and synced to an anonymous file (Linux
`O_TMPFILE`) or a temporary name, then linked to the output name, which
never replaces an existing name. After the link the entry at the output
name (`lstat`, device and inode) must be the file this process wrote: if
another file or a symlink was swapped in for the temporary name between
the sync and the link, the command fails and names the output path. That
entry is left in place, not removed: removing it by path would race with
whoever put it there, it is evidence, and whoever can rename into the
directory could remove it anyway. A failed command must not be followed by
using a file at that path. The temporary name is removed only while it is
still the file this process created (its identity is read from the open
descriptor after the write, because macOS FAT changes the inode on the
first write). A filesystem without hard links (FAT, exFAT, some SMB or
FUSE mounts) is refused with a message that keeps the system error
(`EPERM` is worded "probably", since it also means "not permitted"); there
is no non-atomic fallback. A process killed between creating and
removing a temporary name can leave a `.tmp` file (not on Linux with
`O_TMPFILE`).

Names: `SafetyActionName::parse` is shared by policy loading and the
manifest, so a name the policy accepts is exactly a name the manifest and
the ingestion path accept. The entry points keep the G7 prefix rule
and do not call `parse`; a name that starts with `safety:` but fails it can
never be declared, so it fails closed:

| Entry point | `safety:` name that fails `parse` (`safety:`, `safety:_x`, over 128 bytes) |
| --- | --- |
| Gateway HTTP API | 422 `safety_action_not_governed`, no receipt (the same answer as every `safety:` name: it depends only on the public prefix rule) |
| `praetore-mcp` gate | signed DENY, `unclassified`; nothing forwarded |
| Claude Code hook | signed DENY, `unclassified` |
| Ingestion path (`praetore-safety-ingest`, G1) | records it, never drops it: status `invalid_name`, the error code as `reason`, the raw name kept exactly in the signed event, the error text bounded and escaped as `detail` |

Text output escapes invisible characters (a policy id may contain them).
JSON output and the manifest file keep the exact bytes, by design: a
consumer that shows JSON output to a person must escape it itself.

### Post-hoc safety ingestion (G1)

`praetore-safety-ingest` records safety actions after the fact (SAF-09.5).
The executor of an AI-enabled system runs the action without waiting for
PRÆTORE and then reports it with `praetore-safety-client`: one non-blocking
datagram on a local Unix socket, no retry. Format and verification:
[docs/proposals/safety-ingestion-jsonl.md](proposals/safety-ingestion-jsonl.md).

Isolation from the decision path:

* Its own process, database role (a LOGIN member of
  `praetore_safety_ingest`; `verify_safety_ingest_role_with` refuses a role
  that is also a member of `praetore_runtime` or holds any privilege on
  another `praetore` table, and `verify_runtime_role` refuses a gateway role
  that can insert safety records), key (the ingestion key, distinct from the
  attester, namespace and source keys, checked at startup without a flag)
  and socket.
* The client never blocks: a send is one non-blocking `sendto`. With no
  ingester, a dead one or one whose queue is full, it returns at once
  (measured in `crates/praetore-safety-client/tests/nonblocking.rs`) and the
  event is dropped and counted locally. Nothing in the executor's failsafe
  waits on the ingester or the database.
* The ingester fails closed at startup, for ingestion only: a missing or
  invalid manifest, a key shared by two roles, an unsafe database role, a
  schema that is not current, another ingester holding the tenant lock or an
  unsafe socket path makes it refuse to start. Executors keep working; their
  events are dropped locally until an ingester runs.

What a verified chain shows: the holder of the ingestion key recorded these
records, in this order, under this tenant; with source pins, each event was
signed by its source's key; every `source_seq` up to the high-water mark is
an event or covered by a signed loss record; input that did not verify is a
signed `rejected` record (bounded, escaped raw copy), not a silent drop.

What it does not show:

* **That an action ran, when, or what it did.** Events are post-hoc
  statements by the source. `occurred_at` is the source's clock;
  `recorded_at` is the ingester's. PRÆTORE decided nothing.
* **That every action was reported.** An executor can stay silent. An event
  the client dropped (no ingester, full queue) is visible only as a gap
  when a later event of that source arrives; the last events before a
  source stops are invisible. Messages dropped inside the ingester (full
  queue, database unavailable) are counted in an unattributed loss record,
  not attributed to a source.
* **Anything after a source key is compromised.** Its holder can sign any
  event for that source; reusing positions shows as `conflict`, new
  positions look legitimate.
* **Completeness against truncation or rewriting.** A prefix of a valid
  chain verifies; only `--expected-head` with a head anchored outside the
  operator's control detects truncation. The holder of the ingestion key
  can rebuild a whole chain. The table is append-only by trigger and the
  insert trigger refuses a row that does not extend its chain, but the
  schema owner and superusers are trusted, as for the journal.
* **Who wrote to the socket.** Authentication is the source signature;
  anyone who can write to the socket (mode `0600`, or `0660` with a group)
  can fill the unattributed chain with `rejected` records.

Row-level security uses the same `tenant_isolation` policy as the journal.
One ingester serves one tenant (a row lock on its own registration, that only the registered role can take, migration 0019). Like the
gateway, it sets the tenant context itself: RLS keeps each transaction to
the tenant it names, but does not stop a compromised ingester from naming
another tenant.

## Invariants and traceability

| Invariant / requirement | Enforcing code | Test coverage | Threat |
|---|---|---|---|
| DENY dominates approval and allow | `Decision::strongest` | `policy_precedence_is_deny_then_approval_then_allow`, lattice pair matrix | Policy substitution / ambiguity |
| No matching rule defaults to DENY | `Policy::evaluate_with_context` | `unmatched_rule_denies_by_default` | Elevation |
| Strict never evaluates an unsigned authority | `AuthorizationEngine::evaluate_request` | `strict_engine_rejects_unsigned_authority` | Issuer spoofing |
| Strict proves subject key possession | authority key hash + request signature | `strict_engine_rejects_agent_key_mismatch_with_authority`, `strict_engine_requires_agent_signed_request_intent` | Agent spoofing/key substitution |
| Invalid signature cannot produce ALLOW | identity, authority and evidence verifiers | `generated_keypair_signatures_verify_only_for_matching_key_and_message`, `signed_authority_rejects_tampering_and_wrong_issuer`, strict invalid-intent tests | Forgery |
| Sandbox callback cannot consume a pending result using a mismatched token/action/execution binding | supervisor callback verifies fixed-size SHA-256 digests with constant-time comparison before removing the one-shot pending sender | `callback_digest_comparison_accepts_only_equal_canonical_sha256_values`; malformed action/authority dispatch test | Callback forgery / result substitution |
| Duplicate JSON keys cannot create parser-dependent supervisor inputs | startup configuration, `dispatch`, and `submit_result` use the bounded duplicate-rejecting canonical JSON parser before typed deserialization | `supervisor_config_requires_a_digest_pinned_runner_and_unique_routes`, `strict_supervisor_json_rejects_duplicate_keys_inside_nested_values` | Parser ambiguity / signed-result interpretation |
| Authority time bounds are enforced | `Validity::is_active_at` | `validity_bounds_are_inclusive`, `authority_not_yet_valid_is_rejected`, expired authority and issuer-pin tests | Clock/rollback |
| Policy pin equals evaluated policy | production engine construction/evaluation | `production_profile_rejects_policy_pin_mismatch` | Policy substitution |
| HighAssurance consumes request IDs once and checks content-bound freshness | required `ReplayGuard`; `FreshnessProvider::check_authority` receives authority digest and bounded lease is recorded in v2 evidence | required-guard, duplicate-request, unavailable-store, current/revoked/unknown/expired/too-long freshness tests | Replay / stale freshness source |
| Evidence mutation is detected | `Evidence::verify_integrity` | action/context/signature/policy digest mutation tests | Evidence tampering |
| Deterministic ordering/encoding | canonical codec and ordered context | `policy_canonical_bytes_match_committed_golden_v2_vector`, `format_1_golden_vector_keeps_its_historical_digest`, `object_key_order_does_not_change_canonical_encoding`, duplicate-key parser tests | Platform/input-order variance |
| Work is bounded | request, authority and policy validators | maximum and over-limit tests | Resource exhaustion |
| Single timestamp per evaluation | `AuthorizationEngine::evaluate` passes one snapshot to all checks | `evaluation_uses_one_clock_snapshot` | Clock/rollback |
| CLI does not trust document-embedded keys | `praetore-verify` reads attester and issuer pins from separate command-line paths | `evidence_command_verifies_trusted_signature_intent_and_authority`, `evidence_command_rejects_tampered_documents_and_wrong_pins` | Operator pin provisioning |
| CLI emits stable machine result and failure status | verifier `Summary` and exit handling | `verify_cli` integration tests | Input/output transport is operator-controlled |
| One validator of `safety:*` names (G2) | `SafetyActionName::parse`, used by `Policy::validate` for every `Safety` entry and by `SafetyNamespaceManifest` | `safety_action_name_rules_are_pinned`, `policy_loading_accepts_a_safety_entry_exactly_when_the_shared_validator_does` | Homoglyph / invisible-character names |
| A safety namespace manifest verifies only under its pinned key and domain (G2) | `SafetyNamespaceManifest::verify`, `SAFETY_NAMESPACE_DOMAIN` | `tampering_with_any_signed_field_is_rejected`, `manifest_signatures_do_not_cross_domains`, `no_domain_is_a_prefix_of_another` | Namespace forgery / cross-protocol signature reuse |
| Safety ingestion never blocks the executor (G1) | `SafetyClient::send_bytes`: one non-blocking `sendto`, no retry | `no_ingester_returns_at_once_and_counts_the_drop`, `a_stalled_ingester_with_a_full_queue_never_blocks_the_sender`, `postgres_safety_ingest_records_overflow_and_storage_loss_without_blocking_the_client` | Denial of service of the failsafe through ingestion |
| Input that does not verify is recorded, never dropped (G1) | `SafetyIngestor::prepare` (`rejected` records) | `input_that_does_not_verify_is_recorded_as_rejected_never_dropped`; mutant `scripts/g1-mutants/rejected.patch` | Silent loss / repudiation |
| A `source_seq` gap is a signed loss record, and a gap without one fails verification (G1) | `SafetyIngestor::prepare`, `verify_safety_chain` | `a_source_seq_gap_is_recorded_as_a_signed_loss_record`, `a_gap_without_a_loss_record_fails_even_when_signed`; mutants `ingest-gap`, `verify-gap` | Deletion of events |
| An edited, removed or reordered safety record fails verification (G1) | record signature and in-payload chain (`chain_seq`, `prev_record_hash`) | `an_edited_removed_or_reordered_record_fails_verification`, `postgres_safety_ingest_end_to_end` | Journal tampering |
| The ingester's role is separate from the gateway's (G1) | `verify_safety_ingest_role_with`, `verify_runtime_role` | `postgres_safety_ingest_role_is_separate_from_the_runtime_role` | Privilege confusion |
| Python verification is Rust-backed | `praetore-python` PyO3 crate calls core evidence APIs | Python `test_verify.py` good, tampered, and wrong-key fixtures | Python API intentionally has no evaluate or policy features |
| Parser surfaces are fuzzed in bounded CI smoke | `fuzz/fuzz_targets` and seed corpora | Each target is run by `fuzz-smoke` workflow job | A short smoke run is not exhaustive fuzz coverage |
| Build and dependency controls run in CI | `.github/workflows/assurance.yml` | `rust`, `audit`, `fuzz-smoke`, `python-verify`, `sbom`, and `release-integrity` jobs | Hosted CI and action supply chain remain trusted dependencies |

The [assurance matrix](assurance-matrix.md) maps shipped requirements to code,
tests, and CI jobs. Fuzz smoke, SBOM generation, and audit reduce risk but do
not constitute exhaustive proof, certification, or a clean-room build.

## Threat model / Modelo de amenaza: PostgreSQL journal schema

This section covers the checks `praetore-replay-postgres` runs on the
database that holds the execution journal (`apply_migrations`,
`verify_schema_current`, `verify_runtime_role`). Advisory:
GHSA-67vm-x598-vhg3.

**Best effort.** These checks inspect a database from inside it, through
catalogs that the same database maintains. They are best effort: they detect
mistakes and drift and raise the bar for misuse, but a result computed from
inside an untrusted database cannot prove that database trustworthy.

**Inside the trust perimeter.** For the privileges on the `praetore` schema,
the **owner of the `praetore` schema and its objects, the owner of the
database, and every superuser are trusted**. When the owner is a NOLOGIN
group (`PRAETORE_SCHEMA_OWNER`), the group, every member of it (the roles
in `PRAETORE_SCHEMA_OWNER_MEMBERS`, which can `SET ROLE` to it and, for
example, turn off forced row-level security) and the group's CREATE
privilege on the database (which allows installing trusted extensions) are
inside the perimeter too. They can change any object,
row, grant or catalog entry after the checks run, or edit the system
catalogs directly. The checks do not defend against a malicious owner or
superuser.

**What the checks cover** (and refuse, fail closed):

- Runtime sessions pin `search_path = pg_catalog, pg_temp`; settings that
  disable triggers or row-level security for the runtime role; parameter
  grants on them; runtime roles that are superusers, owners, `BYPASSRLS`,
  `CREATEROLE`, or hold write or schema privileges beyond the migrations.
- Grants on `praetore` objects beyond what the migrations make and the
  documented `praetore_observe` shape, including `WITH GRANT OPTION`;
  objects in `praetore` not owned by the schema owner; other members of
  the owner role (unless listed explicitly); non-superuser members of
  `pg_read_all_data` or `pg_write_all_data`; objects outside `praetore`
  that depend on `praetore` objects; `praetore` objects that depend on
  functions, operators, types or collations outside `pg_catalog` and
  `praetore`; SECURITY DEFINER functions with the owner's rights that a
  role other than their owner may execute (unless listed explicitly).
  Whoever can execute an allowlisted function acts with its owner's
  privileges. Extensions installed in `praetore`, objects in `praetore`
  that belong to an extension (a role with CREATE on the database can
  install a trusted extension into any schema), and objects in `praetore`
  marked `DEPENDS ON EXTENSION`, which the extension's owner could drop.
- With `PRAETORE_SCHEMA_OWNER` set: a `praetore` schema owned by another
  role, at runtime and when migrating. Without it, `verify_runtime_role`
  trusts whichever role owns `praetore` and does not compare its structure
  with the migrations; that comparison runs only in `apply_migrations`.
- On every `apply_migrations`: the environment (event triggers, default
  privileges, owner memberships, settings) and the structure of `praetore`
  compared with a scratch apply of the recorded migrations; adopting a
  schema without migration records only with an explicit opt-in.

**Out of scope:** changes made by a trusted owner or superuser after the
checks ran; direct edits of the system catalogs; the contents of rows that
already exist (the checks are structural); anything outside the database
the journal uses; and other databases on the same cluster. The checks run
when the binaries start and when migrating, not continuously. The adoption
record in `praetore.schema_migrations` is informative and not
tamper-evident.

## Delegated approval

Delegation lets a tenant's root key authorize approver keys without a new
pin per approver ([design](proposals/approval-delegation.md)). It changes
who may sign a human decision; enforcement stays cooperative.

| Threat | Mitigation | Remaining risk |
|---|---|---|
| A delegate key is stolen | The thief can approve only the action types of that delegation's scope, within its validity; revoking it (signed by its issuer or the root) invalidates it and every delegation below it | Revocations take effect at the next gateway restart; until then the key approves within its scope |
| The root key is stolen | The root does not approve in its own name unless the policy allows it; the root key may not be a pinned approver, issuer, attester or another tenant's root, so it gains nothing outside delegation | The thief can sign new delegations for any action of the tenant and revoke legitimate ones. Response: replace the root in the delegation file and restart; every chain under the old root stops verifying |
| A delegate widens its own authority | A child that adds action types, outlives its parent, keeps or raises `max_depth`, is issued by an approver, exceeds 4 links, or grants to an earlier key is invalid; nothing is narrowed silently | None within the chain rules; the scope is only as narrow as the action types the issuers chose |
| Cross-tenant use | Each link must be for the root's tenant and the challenge's tenant; roots are unique across tenants | Depends on the gateway's issuer bindings and the delegation file being provisioned correctly |
| The requesting agent approves itself | No key of the chain, nor the root approving alone, may be the agent's key | An agent that holds another key in a chain is not detected |
| A decision is replayed onto another request or policy | The chain is inside the signed payload, the challenge binds the evidence and the `policy_digest`, and the gateway refuses a root decision when its policy is not the evidence's | None beyond the existing approval checks |
| Offline verification and revocations | Offline, a revocation effective by the challenge's `expires_at` fails the decision | No signed decision time: a decision made before a revocation inside its window also fails offline (conservative). A revocation the verifier is not given is not seen |

## Operational response

Rotation, compromise response, policy rollback, secure clock sourcing, and
signed deployment procedures are maintained in [operations.md](operations.md).
The vulnerability reporting path remains [SECURITY.md](../SECURITY.md).
