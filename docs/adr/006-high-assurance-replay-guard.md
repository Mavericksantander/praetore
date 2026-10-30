# ADR-006: One-time request claims in HighAssurance mode

## Status

Accepted.

## Context

Signed request intents prove possession of the agent key and bind a request
identifier, but a valid signed request can otherwise be submitted more than
once. The core has no persistent storage and cannot safely provide process-local
replay protection for engines shared across processes or restarts.

## Decision

HighAssurance configuration must include a caller-owned `ReplayGuard`.
HighAssurance evaluation claims the `(tenant_id, agent_id, request_id)` triple
after request validation, decision, evidence construction, and attestation,
but before returning evidence. `tenant_id` comes from the signed authority's
`tenant_id` constraint; an authority without a valid one uses the nil UUID,
one shared unscoped namespace. A previously claimed request returns `REPLAY_DETECTED`;
unavailable or full storage returns `REPLAY_GUARD_FAIL`. Neither condition
returns evidence or authorization.

Implementations must provide an atomic claim shared by all engine instances
within the authorization domain and retain claims durably without automatic
expiry. Deleting a claim can make a captured, still-valid signed request
usable again. Storage failure must fail closed. The trait carries no network
or database implementation and does not perform action execution.

Claims are recorded for every successfully evaluated signed request, including
DENY and REQUIRE_APPROVAL outcomes. This prevents the same signed request from
being re-evaluated under changed surrounding state. A failure after recording
but before the caller receives the result may require operator reconciliation;
the request remains consumed.

## Consequences

- `AuthorizationEngine::evaluate(request) -> Result<Evidence>` is unchanged.
- Existing `HighAssuranceConfig::new` callers must attach a replay guard before
  constructing a production engine.
- Strict and Development modes preserve their existing replay behavior.
- The caller must provide durable, atomic, appropriately capacity-managed
  storage. The core cannot guarantee replay protection if deployments bypass
  the configured engine or delete claims.
- Request IDs are treated as one-time identifiers for an agent within a
  tenant namespace. Storage must
  not expire claims automatically; a bounded store must fail closed when it
  cannot safely accept a new claim.

## Verification

Core tests verify required configuration, duplicate request rejection, and
fail-closed behavior when replay storage is unavailable. The store
implementation's atomicity, durability, disaster recovery, and capacity
behavior require separate deployment-specific tests.
