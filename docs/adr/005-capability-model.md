# ADR-005: Capability model

Status: accepted

## Decision

Authority capabilities are explicit names and are not intrinsically action
types. An action may declare its required capability. An action without
an explicit capability is denied in Development mode (it is never mapped to
its action type or any other grant). Strict profiles reject such actions as
invalid requests.

Recommended names are resource-verb pairs such as `data:read`, `data:write`,
`shell:execute`, `api:call`, and `deployment:create`.

## Consequences

Development integrations that relied on the removed action-type fallback must
set `Action::with_capability`. All policies and requests use explicit
capability names to avoid ambiguity.
