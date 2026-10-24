# ADR-005: Capability model

Status: accepted

## Decision

Authority capabilities are explicit names and are not intrinsically action
types. An action may declare its required capability. A missing capability
uses the historical action-type fallback only in Development mode. Strict
profiles reject actions without an explicit capability.

Recommended names are resource-verb pairs such as `data:read`, `data:write`,
`shell:execute`, `api:call`, and `deployment:create`.

## Consequences

Existing development integrations remain compatible. Production policies and
requests must migrate to explicit capability names to avoid ambiguity.
