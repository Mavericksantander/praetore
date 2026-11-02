# Policy language

PRÆTORE policies are bounded, declarative data. They are not scripts: policy
evaluation performs no I/O, does not call user code, and has no implicit
environment access. Values used in matching must be supplied explicitly as
action parameters or request context.

## Policy and rule shape

A policy (policy format 2) has `"format_version": 2`, a non-empty `id`, a
positive integer `version`, a canonical codec version, an `action_classes`
table that classifies every action type the policy knows (see
[Action classes](#action-classes-policy-format-2)), and an ordered array of
rules. Each rule has a unique non-empty `id`, an exact `action_type` that
`action_classes` declares `Mission`, an effect, and optional match criteria:

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
)
// Policy format 2: every action type is classified explicitly.
.with_mission_actions(["read_data"]);

policy.validate()?;
let digest = policy.digest()?;
assert_eq!(digest.len(), 64);
# Ok::<(), Box<dyn std::error::Error>>(())
```

When constructing conditions directly, `PolicyCondition::new` accepts a
`MatchOperator`; the convenience constructors `exact`, `prefix`,
`path_prefix`, `one_of`, and the numeric constructors are generally clearer.

## Action classes (policy format 2)

Policy format 2 separates the actions PRÆTORE decides from the actions it
does not. `action_classes` maps each exact `action_type` to one of two
classes:

* `Mission`: PRÆTORE decides it. Every mission action requires a
  synchronously signed decision before it runs; fail closed, no decision
  means no execution (SAF-09.3).
* `Safety`: an action that the executor of an AI-enabled system runs without
  waiting for PRÆTORE, for example `safety:halt`, `safety:hold`,
  or `safety:stop_all`. PRÆTORE makes no decision about
  it.

```json
{
  "format_version": 2,
  "id": "operations",
  "version": 1,
  "canonical_version": 1,
  "semantics_version": 2,
  "action_classes": {
    "fs:write_file": "Mission",
    "mcp.tools/call": "Mission",
    "safety:halt": "Safety",
    "safety:stop_all": "Safety"
  },
  "rules": [
    {
      "id": "allow-writes",
      "action_type": "fs:write_file",
      "effect": "Allow",
      "required_capability": "fs:write",
      "target": null,
      "parameter_conditions": [],
      "context_conditions": []
    }
  ]
}
```

`Policy::validate` (and therefore `Policy::from_json` and every engine)
rejects the whole policy, with the typed error
`PraetoreError::PolicyActionClassInvalid(ActionClassError)`, when:

* a rule names an `action_type` that `action_classes` does not declare
  (`UndeclaredActionType`);
* an `action_type` starting with `safety:` is not declared `Safety`
  (`SafetyPrefixNotSafety`), or a `Safety` entry is not `safety:` followed by
  a name that starts with an ASCII letter or digit (`SafetyWithoutPrefix`),
  or is longer than `MAX_SAFETY_ACTION_NAME_BYTES` = 128 bytes
  (`SafetyNameTooLong`). A `Safety` entry is valid exactly when
  `SafetyActionName::parse` accepts it (see
  [the safety namespace manifest](#safety-namespace-manifest-g2));
* a key has a character outside printable ASCII (`!` to `~`): whitespace,
  a control or format character such as a zero-width space, or any
  non-ASCII character such as a homoglyph or a full-width letter
  (`NotPrintableAscii`). Every action type used with a class is therefore
  printable ASCII;
* an `action_type` without the `safety:` prefix contains `safety` in any
  ASCII case, such as `safety_halt`, `Safety:halt` or `ops:skip_safety`
  (`AmbiguousSafetyName`), so a name cannot sidestep the prefix;
* any rule targets a `Safety` action, whatever its effect
  (`RuleTargetsSafetyAction`);
* a key is empty or has surrounding whitespace (`InvalidActionType`), or the
  table has more than `MAX_ACTION_CLASSES` = 512 entries.

Mission action types need no prefix: existing names such as `fs:write_file`,
`mcp.tools/call` or `read_data` stay valid once declared. A format 2 document
without `action_classes` is rejected with `ActionClassError::MissingTable`.

`Policy::classify(action)` is the only way to build the request types:

* `ClassifiedAction::Mission(MissionAction)`: the only type an
  `AuthorizationRequest` accepts (`AuthorizationRequest.action` is a
  `MissionAction`), so the engine cannot receive a safety action. Passing a
  `SafetyAction` is a compile error (E0308).
* `ClassifiedAction::Safety(SafetyAction)`: there is no conversion to a
  `MissionAction`; `SafetyAction::not_governed()` is the typed refusal
  `PraetoreError::SafetyActionNotGoverned` (`SAFETY_ACTION_NOT_GOVERNED`).
* `PraetoreError::UnclassifiedAction` (`UNCLASSIFIED_ACTION`) when the table
  does not declare the action type, including an undeclared `safety:*` type.
  `Policy::unclassified(action)` then wraps it as an `UnclassifiedAction`,
  which only `AuthorizationEngine::refuse_unclassified` accepts (in an
  `AuthorizationRequest<UnclassifiedAction>`): the engine verifies the
  request exactly like a mission request, evaluates no rule, and signs a
  `Deny` with reason `unclassified` and
  `decided_by: {"kind": "engine_guard", "guard": "unclassified_action"}`.

The engine checks again, at evaluation time, that the action is a declared
`Mission` action of its own policy.

The entry points that accept JSON classify first. A `Safety` action is
answered with `SAFETY_ACTION_NOT_GOVERNED` before any replay claim, journal
write or signature. An undeclared one leaves a signed DENY receipt, recorded
like a policy DENY on that path, and the client sees the same answer as for
any DENY (this uniformity covers DENY only; REQUIRE_APPROVAL still returns
the receipt or names the rule):

| Entry point | Safety action | Undeclared action |
| --- | --- | --- |
| Gateway HTTP API (`POST /v1/execute`) | 422 `safety_action_not_governed` | signed DENY committed to the journal; 403 `authorization_denied`, the same body as every DENY. Exception: an undeclared type with the reserved `safety:` prefix gets the same 422 as a declared one, with no receipt (the same WARN log line as a declared one, with `declared=false`), so the answer depends only on the prefix. `SAFETY:x` and other near-prefixes are not the reserved prefix: they go through the unclassified path and get a signed DENY when the request is authenticated |
| `praetore-mcp` gate (a tool named `safety:*`) | not evaluated; forwarded to the wrapped server without a receipt, in enforce and observe (except inside a JSON-RPC batch with a blocked call, which enforce refuses as a whole) | signed DENY receipt in the journal; refused in enforce and observe with the same text as every DENY, nothing forwarded; this covers every tool name that starts with `safety` in any ASCII case and is not exactly a declared Safety action (a name that is not a valid action type is recorded as `praetore-mcp unclassified tool name`, with the raw name in `tool`), and an undeclared `mcp.tools/call` |
| Claude Code hook (a tool named `safety:*`) | no permission decision from PRÆTORE (the host's own rules apply), nothing signed or appended | signed DENY appended to `receipts.jsonl`; denied with the same text as every DENY |

**Trust model.** Declaring an action type `Safety` takes it out of
PRÆTORE's governance entirely: no rule applies, nothing is evaluated, signed
or recorded. PRÆTORE does not check that the action really is a safety
action; that trust rests with the policy author. A `safety:` name is not
bound to a particular executor: in `praetore-mcp` a tool with that name on
any wrapped server matches the entry and is forwarded without a receipt.
Declare only the safety actions the executor really runs, and keep the
policy under the same review as any other policy change.

Recording safety actions (SAF-09.5: isolated ingestion with its own process,
credentials and key) is not implemented; until it is, PRÆTORE keeps no
record of them.

Classification needs the policy. If `policy.json` cannot be read or parsed,
the hook and the `praetore-mcp` gate refuse every tool call, `safety:*`
included. `praetore-mcp` also refuses every call when the rest of its home
cannot be loaded (missing or mismatched keys, pins or authority). A safety failsafe must therefore not depend on PRÆTORE; see
[the threat model](threat-model.md#mission-and-safety-actions-g7-limits).

### Safety namespace manifest (G2)

`SafetyActionName::parse` is the one validator of `safety:*` names: the
exact ASCII prefix `safety:`, then a name that starts with an ASCII letter
or digit, printable ASCII only (no whitespace, control or format
characters, homoglyphs or full-width characters), at most 128 bytes. Each
failure is a typed `SafetyNameError` (`Empty`, `TooLong`,
`NotPrintableAscii`, `MissingPrefix`, `InvalidNameStart`). Policy loading
uses it for every `Safety` entry, and so will the ingestion path for safety
actions (SAF-09.5), so the two cannot disagree on what a safety name is.

A safety namespace manifest is a signed statement of the `Safety` names one
format 2 policy declares. An executor of an AI-enabled system and PRÆTORE
compare it to confirm that they share the same namespace, and an executor
can tell when it holds the manifest of another policy version.

```bash
# The namespace key: its own 32-byte secret, owner-only, not the attester
# or issuer key.
(umask 077; openssl rand -hex 32 > namespace.key)
praetore policy safety-manifest --policy policy.json --key namespace.key \
  --output safety-manifest.json
praetore-verify safety-manifest --manifest safety-manifest.json \
  --pin namespace.pin --policy policy.json
```

`praetore policy safety-manifest` prints the `public_key` to put in the pin
file (64 lowercase hex characters, the same format as an attester pin). It
never overwrites: an existing `--output` file (or a symlink at that name) is
an error and stays as it was. The manifest is written and synced to a file
without a name (Linux `O_TMPFILE`) or with a temporary name in the same
directory, then linked to the output name, and the linked entry is checked
to be that file, so a failed or interfered-with write leaves nothing there.
The output directory must be on a filesystem with hard links: on FAT,
exFAT and some SMB or FUSE mounts the command fails with a message that
says so (write to a local filesystem such as APFS or ext4 and copy the
file); there is no non-atomic fallback. `--issued-at <RFC 3339>` fixes the
issue time; the same policy, time and key always give the same bytes.
The key file is opened once without following a symlink and checked on the
open descriptor: a regular file owned by the current user, no group or
other permission bits, no extended ACL entries (macOS), at most 128 bytes,
64 lowercase hex characters and at most one final newline. Each
`--other-pin <hex file>` (repeatable; `--attester-pin` is an alias) names
the public key of another role, the evidence attester or an authority
issuer, and both commands refuse a namespace key equal to any of them
(`SAFETY_MANIFEST_SAME_KEY`). The flag is opt-in in these offline
commands; the ingestion path (G1) and online loaders that hold the
namespace key or pin together with another role's key run the check
without a flag.

The manifest (`SafetyNamespaceManifest`, schema version 1) is canonical
JSON (the repository's canonical encoding: keys sorted, no whitespace),
and a manifest file is exactly that document followed by one newline. Any
other encoding of the same content (indentation, another key order, a
`\u` escape, no final newline or two) is rejected as not canonical, so
one manifest has exactly one valid file and can be identified by the hash
of that file. The fields:

| Field | Value |
| --- | --- |
| `schema_version` | `1` |
| `policy_digest` | the policy's digest |
| `policy_id`, `policy_version` | the policy's `id` and `version` |
| `safety_actions` | every name declared `Safety`, sorted by byte value, without duplicates |
| `issued_at` | RFC 3339 UTC |
| `key_id` | `hex(SHA-256("PRAETORE_SAFETY_NAMESPACE_KEY_V1\0ed25519\0" \|\| public key))` |
| `signature` | `hex(Ed25519("PRAETORE_SAFETY_NAMESPACE_V1\0" \|\| canonical JSON of every other field))` |

`praetore-verify safety-manifest` checks the signature against the pinned
key; with `--policy` it also requires the same id, version, digest and
exactly the same list. A reordered or duplicated list, an unknown field or
another schema version is rejected. The reference vector is
[`docs/golden/safety-namespace-manifest-v1.json`](golden/safety-namespace-manifest-v1.json),
derived from `docs/golden/canonical-policy-v2.json`.

The manifest is signed by a dedicated namespace key
(`SafetyNamespaceKey`), held by whoever releases the policy. It is not the
evidence attester key, which is online on the decision path, and not the
authority issuer key, which grants capabilities. The key id has its own
domain, so the same public key never has the same id in two roles.

For the ingestion path, `manifest.classify_name(&name)` answers `Declared`
or `Undeclared`. An undeclared name is a value, not an error, so it can be
recorded (marked `undeclared`) rather than dropped.

The entry points keep the G7 prefix rule and do not call
`SafetyActionName::parse`. A name that starts with `safety:` but fails
`parse` (`safety:`, `safety:_x`, a name over 128 bytes) can never be
declared, so it is refused: the gateway answers it with the same 422
`safety_action_not_governed` as every `safety:` name, with no receipt;
`praetore-mcp` and the hook refuse it with a signed `unclassified` DENY.
The ingestion path must record such a name with its raw input (bounded,
and escaped for display) and the reason `invalid_name`, never drop it.

JSON output of both commands is exact by design (a `policy_id` with an
invisible character is printed as it is); text output escapes it.

The manifest authorizes nothing. No engine, gateway, gate or hook reads it;
see [the threat model](threat-model.md#safety-namespace-manifest-g2).

### Format 1 documents and historical evidence

A policy document without `format_version` is policy format 1 (every policy
written before G7). It is rejected for evaluation in every mode with
`PraetoreError::PolicyFormatUnsupported { found: 1, supported: 2 }`. Adding
`format_version` and `action_classes` changes the document, so the migrated
policy has a new digest.

Receipts and journals that recorded a format 1 digest keep verifying against
their format 1 document: `RecordedPolicy::from_json` reads format 1 or 2,
validates it as it was validated when it was written, and computes the same
digest. `RecordedPolicy` has no `evaluate` and does not convert into a
`Policy`, so a format 1 document can be digested and compared but never used
to decide. `praetore-verify --policy` and `policy-digest` use it, and so does
`Evidence::verify_recorded_policy`.

**Migrate before upgrading the binary.** A release with G7 does not load a
format 1 policy, so state written before G7 (a hook directory, a
`praetore-mcp` home, a gateway service configuration) refuses every tool call
after the upgrade, `safety:*` included, until its policy is migrated.

For a `praetore-mcp` home, the migrated policy must declare
`"mcp.tools/call": "Mission"`; without it every call is refused, in observe
mode too.

To migrate, run `praetore policy classify --policy <path>`. It prints a
proposed `{"format_version": 2, "action_classes": {...}}` (action types
starting with `safety:` as `Safety`, the rest as `Mission`) and lists what
prevents loading as format 2 (a rule on a `safety:` action, an ambiguous
name). It reads the file and never writes it. Review every `Mission` entry:
an action the executor runs without waiting for PRÆTORE must be renamed
`safety:<name>`, declared `Safety` and have no rule.

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
is never used as an implicit capability. In every mode, `AuthorizationEngine`
denies a matching `Allow` or `RequireApproval` rule without `with_capability`;
an authority that grants the action type itself does not satisfy it. The
lower-level `Policy::evaluate` only folds rule effects and does not apply this
check; use the engine to authorize. A policy rule's
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

`Policy::validate` rejects policy formats other than 2, the
[`action_classes`](#action-classes-policy-format-2) errors above, invalid
identifiers, duplicate rule IDs,
contradictory conditions detectable within one rule, unsupported canonical
versions, and inputs beyond configured bounds. It does not prove that a rule
is reachable in the full system or that two rules are semantically
consistent. Review rules as data during policy authoring and test important
allow/deny cases explicitly.

`Policy::digest` computes SHA-256 over canonical JSON, including
`format_version` and `action_classes`. For semantics v1, the omitted
`semantics_version` field keeps the canonical bytes it had; for semantics v2,
`semantics_version: 2` is included in the document and digest. (Semantics
versions are about unknown-condition matching; policy format versions are
about the document shape. Both are covered by the digest.) Rule array order is preserved in the digest even though decision
combination is order-independent; changing the document order therefore
changes the policy digest and requires updating the external pin. See
[canonical encoding and signatures](crypto-and-policy.md#canonical-encoding)
and the committed golden vectors ([trust chain](golden/trust-chain-v1.json),
[format 1 policy](golden/canonical-policy-v1.json), which keeps its digest
for historical verification, and [format 2 policy](golden/canonical-policy-v2.json)).
