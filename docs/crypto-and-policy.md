# Crypto and policy semantics

This document describes the cryptographic and declarative policy surfaces in
`praetore-core`. The core performs no network access and does not distribute
trust anchors.

## Evaluation modes

Choose the mode explicitly; "production" is the HighAssurance constructor
name, not a certification or a guarantee about the caller's deployment.

| Mode | Behavior | Required caller configuration |
| --- | --- | --- |
| Development | Allows unsigned authorities for local compatibility. If a request signature is present, it must still verify. | Policy only; no issuer trust, policy pin, evidence attester, replay guard, or freshness provider. |
| Strict | Verifies the authority signature against an exact issuer pin, authority validity and subject-key binding, plus the agent-signed request intent. | Non-empty issuer pins. Policy digest pinning, attestation, replay protection, and freshness are not provided by this mode. |
| HighAssurance | Performs Strict checks and additionally binds a v2 policy digest, audience- and expiry-bound v2 request intent, v2 attested evidence, content-bound caller freshness, and one-time `(agent UUID, request UUID)` claims. | Time-bounded issuer pins, pinned v2 policy digest, audience, evidence attester, caller-supplied `FreshnessProvider`, and caller-owned `ReplayGuard`. |

`AuthorizationEngine::development` and
`AuthorizationEngine::development_with_clock` are explicit development
constructors. The compatibility constructors `new` and `with_clock` are
deprecated; they preserve their Development behavior. Use `strict` /
`strict_with_clock` when signature validation is required, or `production` /
`production_with_clock` with `HighAssuranceConfig` for the strongest profile.
The runnable [`quickstart` example](../crates/praetore-core/examples/quickstart.rs)
shows both Strict and HighAssurance paths.

None of these modes supplies an authoritative clock, identity registry, key
custody, revocation database, host isolation, or atomic execution of the
authorized side effect. HighAssurance uses caller-provided replay and
freshness implementations; their correctness, durability, and trustworthiness
are deployment responsibilities.

## Agent keys and authority signatures

`AgentKeyPair::generate()` creates an Ed25519 keypair from the operating
system's cryptographic random source. `AgentKeyPair::from_secret_bytes` is for
deterministic key restoration and tests; its 32-byte input must already be a
high-entropy secret. `AgentIdentity` stores the serialized algorithm-tagged
public key for interoperability. `verified_public_key()` parses it into the
typed `VerifiedPublicKey` used by verification. Parsing rejects malformed and
small-order (weak) Ed25519 points before they can be fingerprinted or admitted
as trust pins; signature verification also uses strict Ed25519 verification.

`Authority::sign_for_agent` signs the authority payload using Ed25519 and
binds the subject to a SHA-256 hash of the agent's Ed25519 public key.
`Authority::sign` is available for signatures that do not need strict subject
key binding. In strict mode, a trusted key is associated with an exact issuer
identifier using `TrustedAuthorityIssuer`; the authority's `issuer` text alone
is not a trust anchor. Strict evaluation rejects unsigned authorities, invalid
signatures, mismatched issuer names or subject keys, malformed Ed25519 agent
keys, and authorities outside their validity window.

`AuthorizationEngine::development` is the explicit development constructor.
`development_with_clock` is its fixed-clock variant; there is no implicit
default mode. Use `strict` or
`strict_with_clock` when signed authority and signed intent verification are
needed. For the production profile, use `AuthorizationEngine::production` with
a `HighAssuranceConfig`: it requires a pinned policy digest, non-empty
time-bounded issuer pins, an evidence attester key, and a caller-owned durable
`ReplayGuard` and `FreshnessProvider`. It verifies that at least one issuer pin is active at
construction and on each evaluation, and checks the matching issuer pin when
verifying each authority. Provision all trust data through an independently
authenticated configuration channel. The engine does not implement PKI,
issuer discovery, or revocation storage.

`production` uses the host `SystemClock`; this does not assert that host time
is trustworthy. Deployments needing a clock-health gate can implement
`TrustedClock` and use `production_with_trusted_clock`. Its timestamp is read
at construction and for each evaluation; a source failure returns
`TRUSTED_CLOCK_UNAVAILABLE` and prevents authorization. The trait is an
integration seam, not an NTP/PTP, cloud-time, or hardware-backed clock
implementation.

The caller-supplied `FreshnessProvider` is a veto-only check. HighAssurance
calls `check_authority` with the verified agent key fingerprint, authority ID,
SHA-256 digest of the exact canonical authority payload, pinned policy digest,
and the evaluation's single clock snapshot. A provider that only implements
the older ID-only `check` method remains source-compatible but fails closed:
the default `check_authority` returns `FRESHNESS_INVALID`. A successful lease
must include the evaluation time and may not exceed the configured maximum
(one minute by default). Provider errors map to stable codes, including
`FRESHNESS_REVOKED`, `FRESHNESS_UNKNOWN`, `FRESHNESS_EXPIRED`,
`FRESHNESS_UNAVAILABLE`, `FRESHNESS_INVALID`, and
`FRESHNESS_LEASE_TOO_LONG`; none can grant ALLOW. Freshness is only as current
and trustworthy as the caller's provider and its source. The core adds no
network or persistent storage. Evidence v1 has no freshness record; v2 binds
the lease deadline and authority digest, but still cannot prove the provider's
source or truthfulness.

New HighAssurance policies must use `Policy::new_v2` or declare
`"semantics_version": 2`. This version treats missing or type-incompatible
condition values as unknown; unknown conditions conservatively match DENY and
REQUIRE_APPROVAL rules. The semantics version contributes to the policy
digest. Policies created with `Policy::new` retain v1 behavior and canonical
bytes for Development/Strict compatibility, but are rejected by the
HighAssurance constructor. See the [policy language guide](policy-language.md).

HighAssurance also requires a v2 signed intent. Its `PRAETORE_INTENT_V2\0`
payload adds the intended audience, canonical UTC `issued_at` and `expires_at`,
and pinned policy digest. The default maximum intent lifetime is five minutes.
The engine rejects expired/not-yet-valid intents, a different audience or
policy digest, and invalid signatures. Authorities must have both validity
bounds; the default maximum lifetime is 365 days. These bounds are
configuration defaults, not secure-clock guarantees.

`AuthorizationRequest::sign_intent` binds an Ed25519 signature to the request
ID, identity, authority, action, trace ID, and request context. Strict mode
requires and verifies this signature, proving possession of the subject key
bound into the authority. Development mode permits unsigned requests, but
rejects any invalid signature that is present. The signature is retained in
evidence and can be checked offline with `Evidence::verify_agent_intent`.

HighAssurance evaluation atomically claims the signed `(agent_id, request_id)`
through the configured `ReplayGuard` before returning evidence. This applies
to ALLOW, REQUIRE_APPROVAL, and DENY results. Duplicate claims or storage
failure return an error; no evidence is returned. The caller's implementation
must be durable and shared across all engine instances in the authorization
domain, and must not expire or delete claims automatically. Use a bounded store
that rejects new claims when full rather than evicting old claims. Strict and
Development modes do not use the replay guard. This prevents re-submission of
the same request ID; it does not prevent an authorized agent from signing new
request IDs, revoke a stolen key, or make action execution atomic with
authorization. See [ADR-006](adr/006-high-assurance-replay-guard.md).

## Canonical encoding

Signatures and digests use compact UTF-8 JSON produced by the crate's canonical
encoder:

* Object keys are sorted lexicographically at every nesting level; there is no
  insignificant whitespace.
* JSON strings use `serde_json` escaping, numbers use the `serde_json::Number`
  representation, and array order is preserved.
* Authority capabilities are sorted lexicographically and constraints by key
  before signing. Duplicate values/keys are rejected by authority validation.
* The authority payload contains `canonical_version`, `schema_version`,
  `id`, `subject`, `issuer`, `capabilities`, `constraints`, `validity`,
  `version`, `subject_key_hash`, and `issuer_key_id`. The signature field is
  not part of the signed payload.
* V1 request-intent payloads contain `canonical_version`, `schema_version`,
  `request_id`, `agent`, `authority`, `action`, `trace_id`, and `context`.
  V2 adds the `intent_v2` object described above. The `agent_signature` field
  is not part of either signed payload.
* Policy digests are SHA-256 over the complete policy serialization, including
  its canonical version, under the same canonical JSON rules. Rule array
  order is preserved.

`canonical_version` is `1` in signed and digested payloads. Domain separation
uses these exact byte prefixes:

* Authority: `PRAETORE_AUTHORITY_V1\0`
* Request intent: `PRAETORE_INTENT_V1\0`
* Evidence attestation: `PRAETORE_EVIDENCE_V1\0`
* HighAssurance request intent: `PRAETORE_INTENT_V2\0`
* HighAssurance evidence attestation: `PRAETORE_EVIDENCE_V2\0`
* Agent key fingerprint: `PRAETORE_AGENT_KEY_V1\0ed25519\0`
* Issuer key ID: `PRAETORE_ISSUER_KEY_V1\0ed25519\0`

Authority signatures bind `issuer_key_id` as well as the subject key hash.
Signatures, fingerprints, and key IDs are lowercase hexadecimal. Parsing
helpers for policy, issuer pins, authority, and evidence reject duplicate JSON
object keys, trailing data, unknown fields, unsupported schema/canonical
versions, unsafe integral numbers, and values over the documented
size/depth/node limits. Unicode normalization is not performed; byte-distinct
Unicode strings remain distinct. JSON strings are UTF-8 and escaped by
`serde_json`; floating-point values are emitted using `serde_json::Number`'s
representation, and arrays preserve their order. These rules plus the
committed golden vectors define codec v1. A semantic or byte-level change
requires a new canonical version; v1 payload fields must not be extended.

`Evidence` v1 exposes its schema and codec version, evidence/request UUIDs,
agent identity, authority, action, decision, trace ID, context, request
signature, policy digest, attester key metadata/signature, and context hash.
The integrity hash covers the canonical `EvidenceIntegrityPayload` fields
listed in `evidence.rs`; the attester signature covers that payload, the
evidence ID, and context hash. The `context_hash` itself and the attester
signature are not members of the integrity payload. Evidence deserialization
is strict at every typed object boundary, so unknown fields are rejected
rather than ignored.

Evidence v1 is frozen: its existing payload fields and canonical bytes are
unchanged. HighAssurance emits evidence schema v2, which adds the signed v2
intent metadata, decision timestamp, `high_assurance` mode marker, freshness
lease deadline, authority content digest, and policy semantics version. The
v2 integrity payload and attester signature bind these fields. Import rejects
unknown fields for both schema versions, and v2 verification checks metadata
consistency; authenticity still requires checking the attester key against an
external pin. The `canonical_version` remains 1 because the canonical JSON
codec itself is unchanged.

`AgentId` remains a UUID alias and is not an authenticator. The key-derived
`AgentKeyFingerprint` is SHA-256 over
`PRAETORE_AGENT_KEY_V1\0ed25519\0 || verified_public_key_bytes`; its v1 test
vector is [agent-key-fingerprint-v1.json](golden/agent-key-fingerprint-v1.json).

Key rotation is represented as an ordinary `identity:rotate_key` action.
`KeyRotationProof` contains the old and new fingerprints, new public key,
subject, authority ID, and request ID; its proof-of-possession signature uses
`PRAETORE_KEY_ROTATION_V1\0`. The old key signs the request intent, which binds
the proof into evidence. `Evidence::verify_key_rotation` checks evidence
integrity, old-key intent, action type, an ALLOW decision, and the new-key
proof. It does not establish issuer/attester trust by itself; consumers must
also verify those signatures against their external pins. This receipt does
not update an agent registry or revoke the old key; those operations remain
caller-owned.

Evidence keeps the SHA-256 `context_hash` for integrity and can also carry an
Ed25519 signature from a separate `EvidenceAttesterKey`. The signature covers
the integrity payload and is verified offline with an independently trusted
`VerifiedPublicKey` using `Evidence::verify_attester_signature`. Integrity
alone is not authenticity. A valid signature proves only that the holder of
the attester key signed that payload; it does not prove honest evaluation,
non-repudiation against key/host compromise, or trusted key distribution.

## Declarative matching

Rules can match action parameters and request context with `PolicyCondition`:

* `Exact` compares JSON values, including their JSON type.
* `Prefix` only matches strings.
* `In` compares against a non-empty JSON array of permitted values.
* Numeric operators require JSON numbers on both sides. Integer comparisons
  retain integer precision; floating-point numbers compare as represented by
  `serde_json`. Comparisons between integer and floating-point representations
  fail closed.

For v1 policies, missing fields and operator/type mismatches do not match. In
v2, an unknown condition value on a DENY or REQUIRE_APPROVAL rule is treated
as a match, while it does not make an ALLOW rule match; a definitively false
condition still makes the rule fail. Conditions compose with AND within a
rule, and matching rules retain the existing strongest-outcome fold:
**DENY > REQUIRE_APPROVAL > ALLOW**. No matching rule still defaults to DENY.
Validation rejects duplicate rule IDs, invalid matcher shapes, and detectable
contradictions such as incompatible exact values or disjoint membership sets.

Authority capabilities use explicit names such as `data:read`, `data:write`,
`shell:execute`, `api:call`, and `deployment:create`. An action can select its
required authority capability with `Action::with_capability`; if omitted,
`action_type` is used for compatibility. A policy rule's optional
`with_capability` is an additional authority requirement. In Strict and
HighAssurance modes it is mandatory for `Allow` and `RequireApproval` rules: a
matching rule without it is denied, because the action's capability is chosen
by the caller and only the rule binds it to the `action_type`.

Example deny-by-default policy for common operations:

```rust
use praetore_core::{
    MatchOperator, Policy, PolicyCondition, PolicyEffect, PolicyRule,
};
use serde_json::json;

let policy = Policy::new_v2(
    "operations-v1",
    1,
    vec![
        PolicyRule::new("deny-shell", "execute_shell", PolicyEffect::Deny),
        PolicyRule::new("deny-api", "call_external_api", PolicyEffect::Deny),
        PolicyRule::new("approve-write", "write_data", PolicyEffect::RequireApproval)
            .with_capability("data:write"),
        PolicyRule::new("approve-deploy", "deploy", PolicyEffect::RequireApproval)
            .with_capability("deployment:create"),
        PolicyRule::new("allow-public-read", "read_data", PolicyEffect::Allow)
            .with_capability("data:read")
            .with_parameter_condition(PolicyCondition::exact("classification", json!("public")))
            .with_context_condition(PolicyCondition::new(
                "risk_level",
                MatchOperator::LessThanOrEqual,
                json!(2),
            )),
    ],
);
```

This example does not grant any authority by itself. The authority must also
contain the capability required by the action and policy rule. The caller
should set `Action::with_capability("data:read")` for the read action;
otherwise the compatibility fallback requires an additional capability named
`read_data`.

## Threat model and guarantees

* **Cooperative agent:** deterministic decisions follow the supplied policy,
  authority, request, and one clock snapshot per evaluation. Evidence includes
  the context and policy digest used by the engine. HighAssurance also consumes
  each authenticated request ID once through caller-owned replay storage.
* **Stolen agent key:** an attacker can create valid signatures for that key.
  HighAssurance replay storage rejects reuse of an already evaluated request
  ID. The core cannot detect compromise or revoke keys; a stolen key can sign
  new request IDs until authorities expire or operators remove trust.
* **Freshness source compromise or staleness:** HighAssurance asks a
  caller-provided freshness provider to veto stale/revoked state. A provider
  that lies, serves stale state as current, or is bypassed by the caller can
  defeat this check; the core cannot independently establish its source.
* **Tampered evidence:** `verify_integrity()` detects changes relative to the
  stored SHA-256 hash. Since the hash is not signed, an attacker who can rewrite
  the document can also recompute it. Production evidence is attester-signed;
  offline verification still requires a separately trusted attester key.
* **Clock skew:** validity is checked against the configured `Clock`, with no
  built-in skew allowance. Production callers are responsible for a
  trustworthy clock source and any required operational margin.
* **Replay:** HighAssurance requires a caller-supplied durable guard that
  atomically consumes each authenticated request ID. Storage rollback, bypass
  of the configured engine, or an unsafe guard implementation can re-enable
  replay; Strict and Development modes do not provide replay protection.
* **Policy or issuer substitution:** the production profile pins the policy
  digest and issuer public keys, but does not authenticate deployment
  configuration or persist anti-rollback state.

## Migration from unsigned authorities

Code that used the removed `AuthorizationEngine::new` must call
`AuthorizationEngine::development`, which keeps unsigned authorities. For production migration:

1. Generate and protect agent and issuer Ed25519 keypairs.
2. Sign each authority for its agent with `Authority::sign_for_agent` and
   retain its validity window.
3. Configure `AuthorizationEngine::strict` with issuer pins for strict
   signature verification, or use `AuthorizationEngine::production` with
   bounded issuer pins, the expected policy digest, and an evidence attester
   key plus a tested, durable `ReplayGuard` for the high-assurance profile.
4. Sign each strict-mode request intent with the agent key.
5. Verify issuer and attester key distribution out of band; do not treat
   serialized issuer labels or key IDs as proof of trust. Export and protect
   issuer pins as configuration artifacts, and rotate keys by deploying an
   overlapping valid pin set before removing the old pin.

`evaluate(request) -> Result<Evidence>` remains the evaluation API. Public
structs gained fields for signatures, capabilities, and context; callers should
prefer constructors and builders over struct literals. Before v1, integrations
that construct these public structs directly should migrate to the builder
methods.
