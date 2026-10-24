# Crypto and policy semantics

This document describes the cryptographic and declarative policy surfaces in
`praetore-core`. The core performs no network access and does not distribute
trust anchors.

## Agent keys and authority signatures

`AgentKeyPair::generate()` creates an Ed25519 keypair from the operating
system's cryptographic random source. `AgentKeyPair::from_secret_bytes` is for
deterministic key restoration and tests; its 32-byte input must already be a
high-entropy secret. `AgentIdentity` stores the serialized algorithm-tagged
public key for interoperability. `verified_public_key()` parses it into the
typed `VerifiedPublicKey` used by verification.

`Authority::sign_for_agent` signs the authority payload using Ed25519 and
binds the subject to a SHA-256 hash of the agent's Ed25519 public key.
`Authority::sign` is available for signatures that do not need strict subject
key binding. In strict mode, a trusted key is associated with an exact issuer
identifier using `TrustedAuthorityIssuer`; the authority's `issuer` text alone
is not a trust anchor. Strict evaluation rejects unsigned authorities, invalid
signatures, mismatched issuer names or subject keys, malformed Ed25519 agent
keys, and authorities outside their validity window.

`AuthorizationEngine::development` is the explicit development constructor.
`AuthorizationEngine::new` and `with_clock` remain development-mode
compatibility constructors for the unsigned model. Use `strict` or
`strict_with_clock` when signed authority and signed intent verification are
needed. For the production profile, use `AuthorizationEngine::production` with
a `HighAssuranceConfig`: it requires a pinned policy digest, non-empty
time-bounded issuer pins, and an evidence attester key. It verifies that at
least one issuer pin is active at construction and on each evaluation, and
checks the matching issuer pin when verifying each authority. Provision all
trust data through an independently authenticated configuration channel. The
engine does not implement PKI, issuer discovery, revocation, or key rotation.

`AuthorizationRequest::sign_intent` binds an Ed25519 signature to the request
ID, identity, authority, action, trace ID, and request context. Strict mode
requires and verifies this signature, proving possession of the subject key
bound into the authority. Development mode permits unsigned requests, but
rejects any invalid signature that is present. The signature is retained in
evidence and can be checked offline with `Evidence::verify_agent_intent`.

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
* Request-intent payloads contain `canonical_version`, `schema_version`,
  `request_id`, `agent`, `authority`, `action`, `trace_id`, and `context`.
  The `agent_signature` field is not part of the signed payload.
* Policy digests are SHA-256 over the complete policy serialization, including
  its canonical version, under the same canonical JSON rules. Rule array
  order is preserved.

`canonical_version` is `1` in signed and digested payloads. Domain separation
uses these exact byte prefixes:

* Authority: `PRAETORE_AUTHORITY_V1\0`
* Request intent: `PRAETORE_INTENT_V1\0`
* Evidence attestation: `PRAETORE_EVIDENCE_V1\0`
* Agent key fingerprint: `PRAETORE_AGENT_KEY_V1\0ed25519\0`
* Issuer key ID: `PRAETORE_ISSUER_KEY_V1\0ed25519\0`

Authority signatures bind `issuer_key_id` as well as the subject key hash.
Signatures, fingerprints, and key IDs are lowercase hexadecimal. Parsing
helpers for policy, issuer pins, and evidence reject duplicate JSON object
keys, trailing data, unsafe integral numbers, and values over the documented
size/depth/node limits. Unicode normalization is not performed; byte-distinct
Unicode strings remain distinct.

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

Missing fields and operator/type mismatches do not match. Conditions compose
with AND within a rule, and matching rules retain the existing strongest
outcome fold: **DENY > REQUIRE_APPROVAL > ALLOW**. No matching rule still
defaults to DENY. Validation rejects duplicate rule IDs, invalid matcher
shapes, and detectable contradictions such as incompatible exact values or
disjoint membership sets.

Authority capabilities use explicit names such as `data:read`, `data:write`,
`shell:execute`, `api:call`, and `deployment:create`. An action can select its
required authority capability with `Action::with_capability`; if omitted,
`action_type` is used for compatibility. A policy rule's optional
`with_capability` is an additional authority requirement.

Example deny-by-default policy for common operations:

```rust
use praetore_core::{
    MatchOperator, Policy, PolicyCondition, PolicyEffect, PolicyRule,
};
use serde_json::json;

let policy = Policy::new(
    "operations-v1",
    1,
    vec![
        PolicyRule::new("deny-shell", "execute_shell", PolicyEffect::Deny),
        PolicyRule::new("deny-api", "call_external_api", PolicyEffect::Deny),
        PolicyRule::new("approve-write", "write_data", PolicyEffect::RequireApproval),
        PolicyRule::new("approve-deploy", "deploy", PolicyEffect::RequireApproval),
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
  the context and policy digest used by the engine.
* **Stolen agent key:** an attacker can create valid signatures for that key.
  The core cannot detect compromise or revoke keys; applications need key
  protection, issuer controls, and revocation/rotation procedures.
* **Tampered evidence:** `verify_integrity()` detects changes relative to the
  stored SHA-256 hash. Since the hash is not signed, an attacker who can rewrite
  the document can also recompute it. Production evidence is attester-signed;
  offline verification still requires a separately trusted attester key.
* **Clock skew:** validity is checked against the configured `Clock`, with no
  built-in skew allowance. Production callers are responsible for a
  trustworthy clock source and any required operational margin.
* **Replay:** request signatures bind a unique request ID, but this library
  does not keep replay state or enforce one-time use.
* **Policy or issuer substitution:** the production profile pins the policy
  digest and issuer public keys, but does not authenticate deployment
  configuration or persist anti-rollback state.

## Migration from unsigned authorities

Existing code using `AuthorizationEngine::new` continues to run in
`Development` mode and can use unsigned authorities. For production migration:

1. Generate and protect agent and issuer Ed25519 keypairs.
2. Sign each authority for its agent with `Authority::sign_for_agent` and
   retain its validity window.
3. Configure `AuthorizationEngine::strict` with issuer pins for strict
   signature verification, or use `AuthorizationEngine::production` with
   bounded issuer pins, the expected policy digest, and an evidence attester
   key for the high-assurance profile.
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
