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
