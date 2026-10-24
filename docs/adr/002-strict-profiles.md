# ADR-002: Strict and development profiles

Status: accepted

## Decision

`Strict` requires a non-empty issuer trust set and requires an explicit action
capability, signed authority bound to the agent public key, and signed request
intent. `HighAssurance` is built by the production constructor and additionally
requires a policy digest pin, bounded time-valid issuer pins, and an evidence
attester key. It validates policy binding and that an issuer pin is active at
construction and on each evaluation. No missing production setting falls back
to development mode.

Legacy `new` remains for source compatibility but is explicitly Development.
Applications must not use it for production decisions.

## Consequences

The engine remains pure and immutable after construction. The deployer remains
responsible for authenticating configuration and preventing downgrade.
