# PRÆTORE

[![Assurance gates](https://github.com/Mavericksantander/praetore/actions/workflows/assurance.yml/badge.svg?branch=main)](https://github.com/Mavericksantander/praetore/actions/workflows/assurance.yml)
[![Rust](https://img.shields.io/badge/Rust-core-000000?logo=rust)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/Python-bindings-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-replay%20adapter-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)

Deterministic authorization and governance primitives for autonomous and
AI-enabled systems.

PRÆTORE Core is a Rust library for evaluating signed authorization requests
against declarative policy and delegated authority. It keeps identity,
authority, policy, decisions, and evidence as separate concepts and defaults
to deny when a policy has no applicable rule.

## Status

**Production readiness: not yet established.** PRÆTORE is under active
development and has not been independently certified or accredited. Passing
the repository's tests and assurance gates is not a substitute for deployment
validation, threat modeling, operational controls, or a security assessment
appropriate to your environment.

The repository includes the Rust authorization core, an offline evidence
verifier, verify-only Python bindings, a reference tool-gateway crate, a
PostgreSQL-backed local CLI demo, bounded fuzz targets, and an optional
PostgreSQL replay-guard adapter.

## Current state on `main`

This section lists only what is merged on `main`. Each item points to the
code or test that backs it. None of it is a security or production guarantee.

- **Signed human approve/reject (#14).** For a `RequireApproval` decision,
  `praetore approve` / `praetore reject` sign the gateway's approval challenge
  with a local Ed25519 approver key. The gateway verifies the signature
  against a pinned approver key, records the decision append-only in
  `praetore.human_approvals` as `approved_pending_dispatch`; a separate
  claim (`praetore dispatch`) performs the single dispatch. A decision cannot be
  reused, and a rejection is final. See the
  [CLI guide](crates/praetore-cli/README.md#human-approval) and the tests in
  [`crates/praetore-gateway/tests/enforcement.rs`](crates/praetore-gateway/tests/enforcement.rs)
  (for example `signed_human_approval_dispatches_the_exact_persisted_action_once`
  and `rejected_human_approval_is_persisted_without_dispatch`).
- **Policy digest in the receipt.** The engine binds the SHA-256 digest of
  the active policy's canonical JSON (`Policy::digest`) into the evidence
  `policy_digest` field. That field is part of the evidence integrity hash
  and of the payload covered by the Ed25519 attester signature. See
  [`crates/praetore-core/src/evidence.rs`](crates/praetore-core/src/evidence.rs)
  (test `policy_digest_is_bound_to_integrity_hash`). The engine binds the
  digest in every mode, and `HighAssurance` additionally requires it to
  equal the pinned policy digest. `Evidence::sign` itself does not yet
  require the field;
  [#17](https://github.com/Mavericksantander/praetore/pull/17) (draft)
  extends that requirement to all signing.
- **Policy size and complexity limits** ([#21](https://github.com/Mavericksantander/praetore/pull/21)).
  A policy that exceeds any limit is rejected when it loads with the typed
  error `PolicyLimitExceeded`; nothing is skipped or treated as allow.
  Raw policy JSON over 64 KiB, or deeper than the parser limit
  (`MAX_JSON_DEPTH` = 32), fails closed in `Policy::from_json` with an
  untyped `PolicyEvaluationFailed` (see
  [#23](https://github.com/Mavericksantander/praetore/issues/23)). The
  public constants in
  [`crates/praetore-core/src/policy.rs`](crates/praetore-core/src/policy.rs)
  (tests in [`crates/praetore-core/tests/policy_limits.rs`](crates/praetore-core/tests/policy_limits.rs)):
  - `MAX_POLICY_RULES` = 512 rules. The 64 KiB canonical JSON limit
    (`MAX_JSON_VALUE_BYTES` = 65,536) is reached first, at fewer than 480 minimal rules (468 measured).
  - `MAX_CONDITIONS_PER_RULE` = 128 parameter conditions, and separately 128
    context conditions, per rule.
  - `MAX_POLICY_TEXT_BYTES` = 1024 UTF-8 bytes for a policy id, rule id,
    action type, capability, target or condition key.
  - `MAX_CONDITION_STRING_BYTES` = 1024 UTF-8 bytes for any string inside a
    condition's expected value, including a `Prefix` / `PathPrefix` prefix.
  - `MAX_CONDITION_SET_VALUES` = 256 values in an `In` condition.
  - `MAX_CONDITION_VALUE_DEPTH` = 8 levels of nesting in an expected value
    (a scalar is 1).
  - The engine has no regex operator, so there is no regex limit.
- **`PathPrefix` condition operator.** A lexical, whole-segment path prefix
  (`/srv/agent` matches `/srv/agent/x`, not `/srv/agentx`).
  - Rule prefixes must be absolute and normalized. An invalid prefix rejects
    the policy when it loads.
  - A value that is not absolute and normalized is *unsafe*. That covers
    `.`, `..`, `//`, `\`, NUL, any `%`, and relative paths. An unsafe value
    never matches an `Allow` rule, and always matches `Deny` and
    `RequireApproval` rules, under both policy semantics versions.
  - `Prefix` applies the same unsafe rule to values containing a `..`
    segment, `%`, or NUL.
  - Pairs of `PathPrefix` / `PathPrefix`, `PathPrefix` / `Exact` and
    `PathPrefix` / `Prefix` conditions on the same key that have no lexical
    relation to each other are rejected. The check is conservative, not
    exhaustive.
  - **Lexical limits:** nothing is normalized. Fullwidth `．．` (U+FF0E), the
    division slash `∕` (U+2215), spaces (`" .."`), and `...` are ordinary
    characters. No layer downstream may NFKC-normalize or percent-decode a
    value after it was authorized.
  - **Over-restriction (accepted, fail closed):** an unsafe value triggers a
    `Deny` or `RequireApproval` rule even when it lies outside the rule's
    prefix. For example, a deny on `/srv/secret` also denies `/home/50%.txt`.
  - See [`crates/praetore-core/src/policy.rs`](crates/praetore-core/src/policy.rs),
    [`tests/path_prefix.rs`](crates/praetore-core/tests/path_prefix.rs) and
    [`tests/path_prefix_followups.rs`](crates/praetore-core/tests/path_prefix_followups.rs).
- **Tests ported from Canopy.**
  [`crates/praetore-core/tests/canopy_port.rs`](crates/praetore-core/tests/canopy_port.rs)
  rewrites the applicable behaviour cases of the earlier Canopy library
  (Apache-2.0) as Rust tests.
  - Where Canopy allowed by default, the expected result here is a default
    deny, and each test documents the difference.
  - Not ported: fixed-key HMAC witnesses, overwritable approvals, substring
    heuristics, reputation, and shell execution.

Run the tests listed above:

```sh
cargo test -p praetore-core --test canopy_port --test path_prefix --test path_prefix_followups
cargo test -p praetore-core --lib evidence::tests::policy_digest_is_bound_to_integrity_hash
cargo test -p praetore-gateway --test enforcement human_approval
```

## Limitations

- **Cooperative enforcement.** PRÆTORE governs only the actions an agent
  submits to it. It cannot stop an agent, or any other process, from
  performing an action directly. Any client that executes an action itself
  after an `allowed` answer does so outside PRÆTORE's control.
- **Path protection is local and lexical only.** `Prefix` and `PathPrefix`
  compare strings and never consult the filesystem. **Symlinks are out of
  scope.**
- **The journal does not independently confirm execution.**
  - Approval and dispatch are separate steps: an approval moves an execution
    from `not_dispatched` to `approved_pending_dispatch`, and a separate
    claim moves it to `dispatched`
    ([`crates/praetore-replay-postgres/src/execution.rs`](crates/praetore-replay-postgres/src/execution.rs),
    migration `0010_approved_pending_dispatch.sql`).
  - `executed` and `confirmed` record what the dispatcher adapter reported.
    The strength of `confirmed` depends on that adapter
    ([`DispatchReport`](crates/praetore-gateway/src/lib.rs)).
- **A client that executes an action by itself** (as the current test agent
  does) can leave a journal state that does not reflect who actually
  executed it. [#16](https://github.com/Mavericksantander/praetore/pull/16)
  addresses this; it is in development and not merged.
- **No sustained fuzzing campaign has been run.** A `path_prefix` fuzz
  target exists ([`fuzz/fuzz_targets/path_prefix.rs`](fuzz/fuzz_targets/path_prefix.rs)),
  but CI runs each target only as a 10-second smoke test.

## Not verified

The following were **not** exercised when this README was last checked:

- the local CLI guide that needs PostgreSQL
  ([`crates/praetore-cli/README.md`](crates/praetore-cli/README.md):
  `praetore init`, `run`, `demo`, `approve` / `reject`);
- `cargo install` (the verifier was built with `cargo build` instead);
- the Python package ([`packages/praetore-python/`](packages/praetore-python/));
- the three PostgreSQL server-restart tests in
  [`crates/praetore-replay-postgres/tests/postgres.rs`](crates/praetore-replay-postgres/tests/postgres.rs),
  which need a manual restart between their `before` and `after` phases;
- Windows.

The workspace tests, Clippy and rustfmt were run on macOS (Apple silicon).
The other PostgreSQL tests in `postgres.rs`, which are ignored without
`PRAETORE_TEST_DATABASE_URL`, were run there against PostgreSQL 16.

## In development

The following are **open pull requests, not merged** and not available on
`main`:

- [#15](https://github.com/Mavericksantander/praetore/pull/15): record the deciding rule (`decided_by`) inside signed decisions and receipts.
- [#16](https://github.com/Mavericksantander/praetore/pull/16): `SandboxDispatcher` executed by the gateway, and the `praetore-exec-mode` header.
- [#17](https://github.com/Mavericksantander/praetore/pull/17): require the active policy digest before a receipt can be signed.
- [#18](https://github.com/Mavericksantander/praetore/pull/18): `praetore-verify evidence --policy` (depends on #17).

## What it is — and is not

**PRÆTORE is:**

* An embeddable, deterministic authorization kernel that evaluates requests
  locally and produces verifiable evidence.
* A library with caller-supplied clocks, trust pins, freshness checks, and
  replay protection in its high-assurance profile.
* A security boundary between the requesting agent, delegated authority,
  policy decision, and evidence receipt.

**PRÆTORE is not:**

* A PKI, identity registry, revocation database, secure clock, or key
  management system.
* A general-purpose network service, policy distribution control plane, or
  administrative action executor.
* A sandbox or isolation boundary by itself. The repository includes a
  mTLS gateway dispatcher, a Kubernetes Job supervisor, and Firecracker/Kata
  deployment contracts, but not the production tool-runner implementation or
  validated target-cluster integration needed to establish an end-to-end
  sandbox.
* A certification, accreditation, or guarantee that a deployment is safe.

Trust anchors, key custody, freshness source, replay storage, host hardening,
and the atomic relationship between authorization and action execution remain
deployment responsibilities. A library decision does not stop a tool call
that bypasses the caller; deployments must mediate protected tools through a
mandatory enforcement point. The workspace now includes a synchronous reference gateway crate, a
tenant-scoped, fixed-route HTTP adapter, a durable PostgreSQL execution
journal, and a loopback-only authenticated read-only observability service.
The gateway service and adapter remain development/reference components, not a
production SaaS enforcement plane. See the [tool gateway
integration](docs/tool-gateway-integration.md), [threat model](docs/threat-model.md),
[observability MVP](docs/observability-mvp.md),
and [pre-user deployment gates](docs/pre-user-pilot-gates.md) before any
high-consequence pilot.

## Quick start

Run the self-contained example from the repository root:

```sh
cargo run -p praetore-core --example quickstart
```

It creates an agent keypair, issues an authority bound to that key, signs
requests, evaluates them in both **Strict** and **HighAssurance** modes, and
verifies the resulting evidence. The example uses ephemeral keys, an
in-memory replay guard, and a demonstration freshness provider; none is
suitable for production. See the [policy language guide](docs/policy-language.md)
for declarative rules and the [crypto and policy guide](docs/crypto-and-policy.md)
for signing and verification details.

## Local PostgreSQL gateway demo

The [local CLI guide](crates/praetore-cli/README.md) walks through initializing
a demo directory, checking local PostgreSQL and gateway health, running the
loopback-only gateway, and submitting its single signed key/value demo action.
The generated keys and in-memory adapter are for local development only; this
is not a production deployment or an external-agent integration.

## Documentation

* [Policy language and evaluation semantics](docs/policy-language.md)
* [Crypto, canonical encoding, and mode semantics](docs/crypto-and-policy.md)
* [Threat model and residual risks](docs/threat-model.md)
* [Mandatory tool gateway integration pattern](docs/tool-gateway-integration.md)
* [Reference gateway crate](crates/praetore-gateway)
* [Local PostgreSQL CLI demo](crates/praetore-cli/README.md)
* [Read-only observability MVP](docs/observability-mvp.md)
* [Assurance traceability matrix](docs/assurance-matrix.md)
* [Operations runbooks](docs/operations.md)
* [Runtime security scaffold: sandbox, trusted clocks, and network controls](docs/runtime-security-scaffold.md)
* [Pre-user deployment gates](docs/pre-user-pilot-gates.md)
* [Architecture decision records](docs/adr/README.md)
* [Offline verifier CLI](#verify-evidence-offline)
* [Contributing and validation](CONTRIBUTING.md)

## Core Concepts

PRÆTORE Core currently provides primitives for:

* Agent identity
* Authority
* Authorization requests
* Actions
* Policy evaluation
* Authorization decisions
* Decision contributions
* Verifiable evidence
* Context integrity verification

The architecture is designed around an explicit trust chain:

**Agent → Authority → Action → Policy → Decision → Evidence**

The goal is to make authorization decisions not only executable, but explainable and independently verifiable.

## Design Principles

### Deterministic Authorization

Authorization should be explicit and reproducible.

### Least Authority

Agents should operate only within the capabilities and constraints explicitly granted to them.

### Policy-Driven Decisions

Authorization is evaluated through explicit policies rather than implicit application behavior.

### Evidence

Authorization decisions should produce evidence that can be verified after the decision has been made.

### Fail Closed

When authorization requirements are not satisfied, the system should deny the action rather than silently broaden permissions.

### Security Boundaries

Identity, authority, policy, authorization, and evidence are treated as distinct security concepts.

## Repository Structure

```text
praetore/
├── crates/
│   ├── praetore-core/
│   ├── praetore-receipt/
│   ├── praetore-verify/
│   ├── praetore-python/
│   ├── praetore-replay-postgres/
│   ├── praetore-gateway/
│   ├── praetore-gateway-service/
│   ├── praetore-cli/
│   └── praetore-observe/
├── fuzz/
├── packages/praetore-python/
├── docs/
├── examples/
├── scripts/
├── Cargo.toml
├── Cargo.lock
├── LICENSE
├── NOTICE
├── SECURITY.md
├── TRADEMARKS.md
└── README.md
```

## Security and production use

There are three evaluation modes; choose deliberately:

| Mode | Intended use | Security checks |
| --- | --- | --- |
| **Development** | Local development and compatibility | Allows unsigned authorities; no issuer pins, policy pin, attester, replay guard, or freshness provider. Never use as a production boundary. |
| **Strict** | Signature-checked offline evaluation | Requires a signed authority from an explicitly pinned issuer, subject-key binding, and a signed agent request intent. Does not require the HighAssurance policy pin, evidence attestation, replay guard, or freshness provider. |
| **HighAssurance** | Strongest profile provided by this library | Strict checks plus v2 policy semantics/digest pin, audience- and expiry-bound signed intents, time-bounded authorities, v2 attested evidence, content-digest-bound freshness with a capped lease, and caller-owned replay guard. |

Use `AuthorizationEngine::production` for HighAssurance. When the deployment
requires a fail-closed clock-health check, implement `TrustedClock` and use
`production_with_trusted_clock`; `production` and `production_with_clock` do
not independently establish that the host time source is trustworthy. The deprecated
`new` and `with_clock` constructors remain Development-mode compatibility
APIs. The crate runs offline and in-process; it does not supply PKI, revocation
storage, a secure clock, deployment integrity, host isolation, or atomic action
execution.

See the linked documentation above before production integration. High-
consequence pilots must close the [pre-user deployment gates](docs/pre-user-pilot-gates.md);
these documents do not represent certification or accreditation.

## Development

PRÆTORE Core is written in Rust.

Requirements:

* Rust 1.88 or newer
* Cargo

Run the test suite:

```
cargo test --workspace
```

Run Clippy with warnings treated as errors:

```
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Check formatting:

```
cargo fmt --all -- --check
```

Check for whitespace and patch errors:

```
git diff --check
```

## Architecture

PRÆTORE Core separates the authorization pipeline into explicit components.

`AgentIdentity` represents the entity requesting an action.

`Authority` represents the capabilities, issuer, validity window, and constraints under which an agent may operate.

`Action` represents the operation being requested, including its type, target, and parameters.

`Policy` evaluates an action against explicit authorization rules.

`Decision` represents the resulting authorization outcome.

`Evidence` binds the authorization request, authority, action, decision, and trace context into verifiable evidence.

The `engine` coordinates these components and enforces the authorization flow.

## Authorization Model

PRÆTORE follows a fail-closed authorization model.

A request must satisfy the relevant identity, authority, capability, validity, constraint, and policy requirements before an action can be authorized.

Decision outcomes are ordered by security precedence:

**DENY > REQUIRE_APPROVAL > ALLOW**

When multiple applicable policy rules contribute to a decision, the strongest applicable outcome prevails.

This allows restrictive rules to override permissive rules without depending on policy rule ordering.

## Evidence and Integrity

Authorization evidence contains the request context and resulting decision.

PRÆTORE computes a SHA-256 context hash over the relevant authorization data so that subsequent modifications to the evidence can be detected.

Evidence verification provides an integrity primitive for downstream systems.

The hash is not a signature: anyone able to modify an evidence document can
recompute it. Signed authorities and optional signed request intents use
Ed25519 and are described in [Crypto and policy semantics](docs/crypto-and-policy.md).

## Verify evidence offline

Install the verifier with `cargo install --path crates/praetore-verify --locked`
(or build it with `cargo build --release --locked --package
praetore-verify`). The attester pin file is the trusted Ed25519 public key as
lowercase hex (32 bytes); it is provisioned separately from the evidence.
Issuer pin files are JSON Lines: one exported `TrustedAuthorityIssuer` pin
document per line.

The fixtures in [`examples/verify/`](examples/verify/) are generated with
fixed, public, test-only keys by
[`scripts/gen-verify-fixtures.sh`](scripts/gen-verify-fixtures.sh)
([`crates/praetore-core/examples/verify_fixtures.rs`](crates/praetore-core/examples/verify_fixtures.rs)).
They are not trust anchors for anything real. From the repository root:

```sh
cargo build --release --locked --package praetore-verify

# Valid receipt: integrity, attester signature, issuer-pinned authority and
# signed agent intent. Prints {"ok":true,...} and exits 0.
target/release/praetore-verify evidence \
  --evidence examples/verify/evidence.json \
  --attester-pin examples/verify/attester-public-key.hex \
  --issuer-pins examples/verify/issuer-pins.jsonl \
  --require-intent \
  --format json

# Tampered receipt (decision reason changed): prints
# {"ok":false,"command":"evidence","code":"EVIDENCE_FAIL"} and exits 1.
target/release/praetore-verify evidence \
  --evidence examples/verify/evidence-tampered.json \
  --attester-pin examples/verify/attester-public-key.hex \
  --issuer-pins examples/verify/issuer-pins.jsonl \
  --require-intent \
  --format json

target/release/praetore-verify policy-digest --policy examples/verify/policy.json --format json

target/release/praetore-verify authority \
  --authority examples/verify/authority.json \
  --issuer-pins examples/verify/issuer-pins.jsonl \
  --agent examples/verify/agent.json \
  --now 2026-10-24T00:00:00Z \
  --format json
```

Regenerating the fixtures changes `evidence.json` and
`evidence-tampered.json`, because `evidence_id` is random. The fixture authority is valid from 2026-01-01 to 2036-01-01. The `evidence`
command checks it against the current time, so regenerate the fixtures after
that date.

The optional `--agent` enables explicit subject-key binding verification for
standalone authority documents. When omitted, the verifier checks the issuer
signature, key ID, and time validity and reports that the subject identity was
not independently matched. Evidence verification with issuer pins checks the
subject binding against the embedded agent identity. `--require-intent` also
requires `--issuer-pins`, so intent verification is bound to an issuer-trusted
agent key rather than a self-asserted key in the evidence. The CLI never treats
public keys inside evidence or authority documents as trust anchors. Invalid
inputs return non-zero with stable reason codes.

The Python package is verify-only and calls the same Rust implementation:
`praetore.verify_evidence_integrity` and
`praetore.verify_evidence_attester_signature`. It does not implement policy
evaluation or authority issuance.

See [the assurance traceability matrix](docs/assurance-matrix.md) for
requirements, tests, and CI job mapping, and [CONTRIBUTING.md](CONTRIBUTING.md)
for exact local validation and release commands.

## End-to-end examples

Run the combined Strict and HighAssurance example:

```sh
cargo run -p praetore-core --example quickstart
```

For the narrower HighAssurance-only example, run
`cargo run -p praetore-core --example high_assurance`. Both examples use
ephemeral keys and demonstration adapters. Production deployments must use
protected keys, a durable atomic `ReplayGuard` shared by every engine instance
in the authorization domain, and a real freshness source. Duplicate requests,
storage outages, or freshness failures fail closed; neither example is a
revocation service.

## Security

PRÆTORE is security-sensitive infrastructure.

Please do not disclose suspected vulnerabilities through public issues.

See `SECURITY.md` for the project's security policy.

## License

PRÆTORE source code in this repository is released under the PRÆTORE Open Core License.

The license permits personal, educational, research, testing, and other non-commercial use only.

**Commercial use is not permitted.**

Commercial use includes using the software as part of a commercial product, service, infrastructure, internal business operation, or revenue-generating activity.

Any commercial use requires a separate written license from PRÆTOR TECHNOLOGIES.

See `LICENSE` for the complete terms.

## Trademarks

PRÆTOR, PRÆTORE, and associated names, logos, and product names are trademarks or intended trademarks of PRÆTOR TECHNOLOGIES.

The software license does not grant trademark rights.

See `TRADEMARKS.md` for additional information.

## Copyright

Copyright © 2026 PRÆTOR TECHNOLOGIES.

All rights reserved except where otherwise stated.
