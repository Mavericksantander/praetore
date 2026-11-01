# ADR-002: Strict and development profiles

Status: accepted

## Decision

`Strict` requires a non-empty issuer trust set and requires an explicit action
capability, signed authority bound to the agent public key, and signed request
intent. `HighAssurance` is built by the production constructor and additionally
requires a policy digest pin, bounded time-valid issuer pins, an evidence
attester key, and a durable caller-owned replay guard. It validates policy
binding and that an issuer pin is active at construction and on each
evaluation. No missing production setting falls back to development mode.

There is no default profile. The legacy `new` / `with_clock` constructors are
removed and `AuthorizationEngine` has no `Default`; Development is reached only
through the explicitly named `development` / `development_with_clock`
constructors. Applications must not use it for production decisions.

## Consequences

Policy evaluation remains deterministic and has no network or filesystem
dependency. HighAssurance additionally calls its explicit replay-guard
interface, so successful evaluations require external state and fail closed
when that state is unavailable. The caller remains responsible for durable
atomic storage, authenticating configuration, and preventing downgrade.
