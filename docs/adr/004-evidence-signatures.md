# ADR-004: Evidence signatures

Status: accepted

## Decision

Evidence authenticity is a separate Ed25519 attester signature over the
canonical evidence payload (including integrity hash, decision, authority,
intent signature, context and policy digest). Agent, issuer, and attester keys
have separate operational roles. Evidence includes an attester key ID and
algorithm identifier; offline verification requires an externally trusted
attester pin. The evidence signature itself is excluded from the signed
payload.

The HighAssurance production profile requires an attester key. Strict mode
without that profile and the compatibility Development API can emit hash-only
evidence. `verify_integrity()` checks only the SHA-256 binding;
`verify_attester_signature()` additionally requires the independently trusted
attester public key.

## Consequences

Signatures establish that a holder of the attester key signed the evidence;
they do not guarantee that the host evaluated honestly or that the key was not
compromised. The context hash remains an integrity checksum, not authenticity.
