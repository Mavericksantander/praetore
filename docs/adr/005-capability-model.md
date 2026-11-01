# ADR-005: Capability model

Status: accepted

## Decision

Authority capabilities are explicit names and are not intrinsically action
types. An action may declare its required capability. An action without
an explicit capability is denied in Development mode (it is never mapped to
its action type or any other grant). Strict profiles reject such actions as
invalid requests. In every mode, a matching `Allow` or `RequireApproval` rule
must declare `required_capability`; a grant of the action type does not stand
in for it.

Recommended names are resource-verb pairs such as `data:read`, `data:write`,
`shell:execute`, `api:call`, and `deployment:create`.

## Consequences

Development integrations that relied on the removed action-type fallback must
set `Action::with_capability`, and Development policies whose `Allow` or
`RequireApproval` rules relied on an action-type grant must declare
`required_capability`. All policies and requests use explicit
capability names to avoid ambiguity.
