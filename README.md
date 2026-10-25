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
verifier, verify-only Python bindings, a reference tool-gateway crate,
bounded fuzz targets, and an optional PostgreSQL replay-guard adapter.

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
* A sandbox or isolation boundary for the host that runs it.
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

## Documentation

* [Policy language and evaluation semantics](docs/policy-language.md)
* [Crypto, canonical encoding, and mode semantics](docs/crypto-and-policy.md)
* [Threat model and residual risks](docs/threat-model.md)
* [Mandatory tool gateway integration pattern](docs/tool-gateway-integration.md)
* [Reference gateway crate](crates/praetore-gateway)
* [Read-only observability MVP](docs/observability-mvp.md)
* [Assurance traceability matrix](docs/assurance-matrix.md)
* [Operations runbooks](docs/operations.md)
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
│   ├── praetore-verify/
│   ├── praetore-python/
│   ├── praetore-replay-postgres/
│   ├── praetore-gateway/
│   └── praetore-observe/
├── fuzz/
├── packages/praetore-python/
├── docs/
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

Use `AuthorizationEngine::production` for HighAssurance. The deprecated
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

* Rust 1.85 or newer
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

```sh
praetore-verify evidence \
  --evidence evidence.json \
  --attester-pin attester-public-key.hex \
  --issuer-pins issuer-pins.jsonl \
  --require-intent \
  --format json

praetore-verify policy-digest --policy policy.json --format json

praetore-verify authority \
  --authority authority.json \
  --issuer-pins issuer-pins.jsonl \
  --agent agent.json \
  --now 2026-10-24T00:00:00Z \
  --format json
```

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
