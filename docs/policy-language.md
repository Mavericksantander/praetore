# Policy language

PRÆTORE policies are bounded, declarative data. They are not scripts: policy
evaluation performs no I/O, does not call user code, and has no implicit
environment access. Values used in matching must be supplied explicitly as
action parameters or request context.

## Policy and rule shape

A policy has a non-empty `id`, a positive integer `version`, a canonical codec
version, and an ordered array of rules. Each rule has a unique non-empty `id`,
an exact `action_type`, an effect, and optional match criteria:

* `required_capability`: on an ALLOW rule, the authority must grant this
  capability for the rule to match. On a DENY, REQUIRE_APPROVAL or RECOVER
  (restrictive) rule it does not narrow matching: the rule applies whether or
  not the authority holds the capability, so an authority cannot escape an
  approval or deny rule by lacking the capability it names. Such an
  *unbound* match (the authority lacks the capability, or the action has no
  target) always contributes DENY: a REQUIRE_APPROVAL rule does not offer an
  approval, and a RECOVER rule does not emit a recovery obligation, to an
  authority the rule was never scoped to. The decision records it as
  `decided_by: {"kind": "unbound_rule", "rule_id": ...}` (an unbound DENY rule
  applied its declared effect and is an ordinary `rule`). (Strict and
  HighAssurance still require it on matching ALLOW and REQUIRE_APPROVAL rules;
  see below.)
* `target`: the action target must be exactly equal. Targets are exact,
  case-sensitive identifiers compared byte for byte; nothing is case-folded,
  trimmed or normalized, so `prod-db` and `PROD-DB` are different targets.
  Callers must normalize targets before building the action. An action
  **without** a target never matches a targeted ALLOW rule and always matches
  a targeted restrictive rule (fail closed), in every semantics version.
* `parameter_conditions`: conditions evaluated against the action's parameter
  object.
* `context_conditions`: conditions evaluated against the request's explicit
  context map.

All conditions in a rule are ANDed. An omitted criterion places no additional
restriction on that field. Rules do not inherit values from one another.
Policies created with `Policy::new` or imported without an explicit
`semantics_version` retain v1 matching for digest and signature compatibility:
a missing condition key, or a value of an incompatible JSON type (a string
where a number is expected), does not match any conditional rule, **including
DENY and REQUIRE_APPROVAL rules**. A v1 restrictive rule can therefore stop
applying when a parameter or context key is omitted or sent as a string. Do
not rely on v1 for restrictive conditions; use v2. The exceptions, which fail
closed in v1 as well: unsafe path-like values, integer/float comparisons (see
[Condition operators](#condition-operators)), a missing action target, and a
restrictive rule's `required_capability` (see above).

For new policies, use `Policy::new_v2`. In v2, a missing key or
type-incompatible value is an **unknown condition**. Unknown conditions do not
match an ALLOW rule, but they conservatively match DENY and REQUIRE_APPROVAL
rules. A definitely false condition still prevents the rule from matching;
conditions remain ANDed. This means a restrictive rule cannot silently stop
applying just because a condition field, or the action target, is absent or
arrives with an unexpected type, or because the authority lacks the rule's
`required_capability`. It still stops applying when a present value is
definitely different (another target, a value outside the condition).
The semantics version is included in the policy document and digest. The
HighAssurance constructor rejects v1 policy semantics; v1 policies remain
available to Development and Strict for compatibility.

```rust
use praetore_core::{Policy, PolicyCondition, PolicyEffect, PolicyRule};
use serde_json::json;

let policy = Policy::new_v2(
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
`path_prefix`, `one_of`, and the numeric constructors are generally clearer.

## Condition operators

| Operator | Meaning | Required expected value |
| --- | --- | --- |
| `Exact` | JSON value equality; types matter (`1` is not `"1"`) | Any bounded JSON value |
| `Prefix` | Actual value is a string beginning with the expected string | Non-empty string |
| `PathPrefix` | Actual value is an absolute, normalized path inside the expected path on whole segments (`/srv/agent` matches `/srv/agent` and `/srv/agent/x`, not `/srv/agentx`); purely lexical, byte for byte | Absolute, normalized path: no `.`, `..` or empty segments, no `\`, `%` or NUL; one trailing `/` allowed. `//` alone is accepted and means the root; `///`, `//srv` and `/srv//x` are rejected |
| `In` | Actual JSON value equals one element of the expected array | Non-empty array |
| `GreaterThan`, `GreaterThanOrEqual`, `LessThan`, `LessThanOrEqual` | Numeric comparison | JSON number |

`PathPrefix` applies the same rules to the actual value. A value that breaks
them (relative, `..`, `.`, an empty segment such as `/srv//x`, `\`, `%` or NUL)
is unsafe: it always matches DENY and REQUIRE_APPROVAL rules and never matches
ALLOW rules, in every semantics version, even when it lies outside the rule's
prefix. As with the rule prefix, the value `//` on its own is the root, not an
unsafe value. Symlinks, Unicode look-alikes and percent-decoding are out of
scope; see the `MatchOperator::PathPrefix` documentation.

Prefix matching is string-only. Membership compares JSON values exactly,
except that a numerically equal integer and float are equal (see below).
Numeric comparisons require JSON numbers; a non-number is unknown in v2.
An integer against a floating-point number (`50000` vs `50000.0`) is compared
exactly, without casting the integer to `f64`, and fails closed in every
semantics version: the exact result applies to DENY and REQUIRE_APPROVAL rules
(also for `Exact` and `In`, where `10000.0` equals `10000`), and an ALLOW rule
never matches a mixed integer/float representation. Non-finite numbers are
not JSON values. The core does
not coerce strings to numbers or otherwise normalize values to make a
condition match.

## Capabilities, actions, and authority

Action names and capability names are different namespaces. Use stable,
domain-oriented capability names such as `data:read`, `data:write`,
`process:execute`, `network:invoke`, or `deployment:release`. An authority
grants capabilities; it does not grant policy permission by itself.

Set the capability required by the action explicitly with
`Action::with_capability`. Strict and HighAssurance evaluation reject actions
without an explicit capability, and Development denies them: the action type
is never used as an implicit capability. In Development, a rule without
`with_capability` also requires the authority to grant the action type. A policy rule's
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

The decision's `decided_by` and `reason` name the same rule: the one with the
highest effective severity (RECOVER > DENY > REQUIRE_APPROVAL > ALLOW, where
RECOVER is a DENY that carries a recovery obligation). For a RECOVER decision
that is the rule that produced the obligation, even when a plain DENY rule
also matched. Between rules of equal severity the earlier-matching rule is
kept, so the outcome is order-independent but the named rule on a tie is
not.

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

`Policy::digest` computes SHA-256 over canonical JSON. For a v1 policy, the
omitted semantics field preserves the existing v1 canonical bytes and digest.
For v2 policies, `semantics_version: 2` is included in the document and
digest. Rule array order is preserved in the digest even though decision
combination is order-independent; changing the document order therefore
changes the policy digest and requires updating the external pin. See
[canonical encoding and signatures](crypto-and-policy.md#canonical-encoding)
and the committed [golden vectors](golden/trust-chain-v1.json).
