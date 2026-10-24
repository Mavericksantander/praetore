# Changelog

## Unreleased

### Added

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

### Compatibility notes

- `AuthorizationEngine::evaluate(request) -> Result<Evidence>` is unchanged.
- `new` and `with_clock` remain development-mode constructors and continue to
  permit unsigned authorities. Production callers should configure strict
  issuer trust.
- Public structs gained fields. Struct-literal construction may require source
  changes; constructors and builders are the preferred API ahead of v1.
- `Action::with_capability` separates action type from required authority
  capability. Existing actions without an explicit capability retain the
  legacy action-type capability mapping in Development; Strict and
  HighAssurance require an explicit capability.
- `Evidence::new` and `Evidence::new_with_context` return `Result` so oversized
  or invalid evidence cannot be constructed with an empty fallback integrity
  hash.

### Not yet delivered

- Fuzz targets, offline verifier CLI, CI advisory/SBOM/release-signing gates,
  and Python bindings remain follow-up work; the current
  threat model does not claim those deliverables are implemented.
