# ADR-001: Canonical encoding

Status: accepted

## Decision

Security signatures and SHA-256 digests use UTF-8 compact JSON with
lexicographically sorted object keys at every nesting level and preserved array
order. Strings are escaped by `serde_json`. Unicode is not normalized; canonically
equivalent but byte-distinct strings remain distinct. Floating point and
integers outside the interoperable safe-integer range are rejected in
security-bound payloads. The codec version is explicit and included in signed
or hashed payloads. Duplicate object keys, trailing JSON data, non-finite
numbers, unsafe integral values, and values exceeding fixed byte/depth/node
bounds are rejected at supported JSON import boundaries. Unicode normalization
is not performed.

Each signed payload uses a fixed domain prefix: `PRAETORE_AUTHORITY_V1\0`,
`PRAETORE_INTENT_V1\0`, or `PRAETORE_EVIDENCE_V1\0`. Key fingerprints use
separate `PRAETORE_AGENT_KEY_V1\0ed25519\0`,
`PRAETORE_ISSUER_KEY_V1\0ed25519\0`, and
`PRAETORE_ATTESTER_KEY_V1\0ed25519\0` prefixes.

## Rationale and consequences

JSON remains inspectable and the implementation is small. The explicit codec
version prevents silently changing serialization rules. Producers must use
exact Unicode strings and supported numbers; a future rule change requires a
new codec version and vectors.

## Verification

Committed golden vectors cover bytes and digests; tests compare insertion-order
variants and reject unsafe numeric values.
