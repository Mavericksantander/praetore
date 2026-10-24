# ADR-003: Issuer key pins

Status: accepted

## Decision

Trust is a local allowlist of pins containing exact issuer name, stable key ID,
algorithm (`ed25519` only), public key, and inclusive RFC 3339 `not_before` /
`not_after` bounds. Unknown names, key IDs, algorithms, malformed keys, empty
stores, duplicate pins, and out-of-window pins fail closed. No authority can
introduce its own trust anchor.

Pins are provisioned out of band. Rotation is overlap: deploy the new valid pin,
issue authorities with the new key, verify adoption, then remove the old pin.
Emergency compromise removes the pin and reissues affected authorities.

## Consequences

The library does not fetch pins, build PKI chains, or persist revocation and
rollback state.
