# PRÆTORE

Trusted authorization and governance infrastructure for autonomous and AI-enabled systems.

PRÆTORE is the core software infrastructure of PRÆTOR TECHNOLOGIES, designed to provide a deterministic foundation for authorization, policy enforcement, decision-making, and verifiable evidence.

## Status

PRÆTORE is currently under active development.

The current repository contains the `praetore-core` Rust crate.

The project is being developed from a security-first and verification-oriented foundation rather than as a conventional application framework.

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
│   └── praetore-core/
│       └── src/
│           ├── action.rs
│           ├── authority.rs
│           ├── authorization.rs
│           ├── canonical.rs
│           ├── decision.rs
│           ├── engine.rs
│           ├── error.rs
│           ├── evidence.rs
│           ├── identity.rs
│           ├── lib.rs
│           └── policy.rs
├── Cargo.toml
├── Cargo.lock
├── LICENSE
├── NOTICE
├── SECURITY.md
├── TRADEMARKS.md
└── README.md
```

## Security and production use

The `new` and `with_clock` constructors are compatibility Development-mode
APIs. For signature-checked evaluation use `strict`; for the production
high-assurance profile use `AuthorizationEngine::production` with a pinned
policy digest, bounded issuer pins, and a separate evidence attester key.
Evaluation remains offline and in-process. It does not provide PKI, revocation,
replay prevention, secure clocking, deployment integrity, or host isolation.

See [the crypto and policy guide](docs/crypto-and-policy.md), [the threat
model](docs/threat-model.md), [the operations runbooks](docs/operations.md),
and the [architecture decisions](docs/adr/README.md) before production
integration.

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

## Crypto and policy APIs

Use `AgentKeyPair::generate()` to create Ed25519 keypairs, sign authorities
for a subject with `Authority::sign_for_agent`, and construct
`AuthorizationEngine::strict` with explicit issuer-name/public-key trust
bindings for production evaluation. Strict mode also requires an agent-signed
request intent. The named `AuthorizationEngine::development` and compatibility
`AuthorizationEngine::new` constructors permit unsigned authorities.

Policy rules support typed exact, string-prefix, set-membership, and numeric
conditions against action parameters and request context. Missing fields or
type mismatches never satisfy a condition. Action types and authority
capabilities are separate: `Action::with_capability` declares the required
capability; when omitted, the legacy behavior uses the action type as the
capability name. See the linked documentation for canonical serialization,
migration guidance, and examples.

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
