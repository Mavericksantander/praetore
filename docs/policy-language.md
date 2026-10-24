# Policy language

PRÆTORE policies are bounded, declarative data. They are not scripts: policy
evaluation performs no I/O, does not call user code, and has no implicit
environment access. Values used in matching must be supplied explicitly as
action parameters or request context.

## Policy and rule shape

A policy has a non-empty `id`, a positive integer `version`, a canonical codec
version, and an ordered array of rules. Each rule has a unique non-empty `id`,
an exact `action_type`, an effect, and optional match criteria:

* `required_capability`: the authority must grant this capability for the rule
  to match.
* `target`: the action target must be exactly equal.
* `parameter_conditions`: conditions evaluated against the action's parameter
  object.
* `context_conditions`: conditions evaluated against the request's explicit
  context map.

All conditions in a rule are ANDed. A missing key, wrong JSON type, or failed
comparison means that rule does not match. An omitted criterion places no
additional restriction on that field. Rules do not inherit values from one
another.

```rust
use praetore_core::{Policy, PolicyCondition, PolicyEffect, PolicyRule};
use serde_json::json;

let policy = Policy::new(
    "data-access",
    1,
    vec![
        PolicyRule::new("deny-restricted", "read_data", PolicyEffect::Deny)
            .with_parameter_condition(PolicyCondition::exact(
                "classification",
                json!("restricted"),
            )),
        PolicyRule::new("allow-public", "read_data", PolicyEffect::Allow)
            .with_capability("data:read")
            .with_parameter_condition(PolicyCondition::exact(
                "classification",
                json!("public"),
            ))
            .with_context_condition(PolicyCondition::one_of(
                "region",
                vec![json!("west"), json!("central")],
            )),
    ],
);

policy.validate()?;
let digest = policy.digest()?;
assert_eq!(digest.len(), 64);
# Ok::<(), Box<dyn std::error::Error>>(())
```

When constructing conditions directly, `PolicyCondition::new` accepts a
`MatchOperator`; the convenience constructors `exact`, `prefix`,
`one_of`, and the numeric constructors are generally clearer.

## Condition operators

| Operator | Meaning | Required expected value |
| --- | --- | --- |
| `Exact` | JSON value equality; types matter (`1` is not `"1"`) | Any bounded JSON value |
| `Prefix` | Actual value is a string beginning with the expected string | Non-empty string |
| `In` | Actual JSON value equals one element of the expected array | Non-empty array |
| `GreaterThan`, `GreaterThanOrEqual`, `LessThan`, `LessThanOrEqual` | Numeric comparison | JSON number |

Prefix matching is string-only. Membership compares JSON values exactly.
Numeric comparisons require compatible number representations; incompatible
types do not match. Non-finite numbers are not JSON values. The core does not
coerce strings to numbers or otherwise normalize values to make a condition
match.

## Capabilities, actions, and authority

Action names and capability names are different namespaces. Use stable,
domain-oriented capability names such as `data:read`, `data:write`,
`process:execute`, `network:invoke`, or `deployment:release`. An authority
grants capabilities; it does not grant policy permission by itself.

Set the capability required by the action explicitly with
`Action::with_capability`. Strict and HighAssurance evaluation reject actions
without an explicit capability. Development retains a legacy fallback where
the action type is treated as the required capability. A policy rule's
`with_capability` is an additional rule match condition, not a grant: the
authority must contain that capability, and the action's own required
capability must also be granted by the engine.

Authority constraints are independently checked before policy evaluation.
They currently compare `target` to the action target, or another constraint
key to a string-valued action parameter. A failed authority constraint returns
a DENY decision. Policy conditions do not replace or broaden authority.

Common action/capability pairs can follow this convention:

| Action type | Suggested capability |
| --- | --- |
| `execute_shell` | `process:execute` |
| `call_external_api` | `network:invoke` |
| `read_data` | `data:read` |
| `write_data` | `data:write` |
| `deploy` | `deployment:release` |

These are naming recommendations only; the core has no built-in privilege
semantics for these action names.

## Effects and precedence

Each matching rule contributes its effect. The final outcome is the strongest
applicable outcome under the fixed precedence:

**DENY > REQUIRE_APPROVAL > ALLOW**

The fold is independent of rule order: a matching DENY dominates an approval
or allow, and a matching approval dominates an allow. Matching contributions
are retained in the decision for explanation and audit. Do not use rule order
to express priority or to weaken a restrictive result.

If no rule matches, the policy returns DENY. An ALLOW rule is therefore
required for every allowed case; the engine never treats a missing policy
match as permission.

## Request context

Request context is an explicit map, set by the caller on the
`AuthorizationRequest` (for example with `with_context`). It is bound into the
signed request intent and evidence. It is not trusted merely because it is
present: the caller must ensure each value comes from an appropriate source.
The policy engine does not fetch environment facts or infer `region`,
`risk_level`, tenant, or other attributes.

## Validation and digest pinning

`Policy::validate` rejects invalid identifiers, duplicate rule IDs,
contradictory conditions detectable within one rule, unsupported canonical
versions, and inputs beyond configured bounds. It does not prove that a rule
is reachable in the full system or that two rules are semantically
consistent. Review rules as data during policy authoring and test important
allow/deny cases explicitly.

`Policy::digest` computes the v1 canonical JSON SHA-256 digest. Rule array
order is preserved in the digest even though decision combination is
order-independent; changing the document order therefore changes the policy
digest and requires updating the external pin. See [canonical encoding and
signatures](crypto-and-policy.md#canonical-encoding) and the committed
[golden vectors](golden/trust-chain-v1.json).
