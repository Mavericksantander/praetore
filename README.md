# PRÆTORE

Trusted authorization and governance infrastructure for autonomous
and AI-enabled systems.

PRÆTORE is the core software infrastructure of PRÆTOR TECHNOLOGIES,
designed to provide a deterministic foundation for authorization,
policy enforcement, decision-making, and verifiable evidence.

## Status

PRÆTORE is currently under active development.

The current repository contains the `praetore-core` Rust crate.

The project is intentionally being developed from a security-first
and verification-oriented foundation rather than as a conventional
application framework.

## Core Concepts

PRÆTORE Core currently provides primitives for:

- Agent identity
- Authority
- Authorization requests
- Actions
- Policy evaluation
- Authorization decisions
- Decision contributions
- Verifiable evidence
- Context integrity verification

The architecture is designed around an explicit trust chain:

Agent → Authority → Action → Policy → Decision → Evidence

The goal is to make authorization decisions not only executable,
but explainable and independently verifiable.

## Design Principles

### Deterministic authorization

Authorization should be explicit and reproducible.

### Least authority

Agents should operate only within the capabilities and constraints
explicitly granted to them.

### Policy-driven decisions

Authorization is evaluated through explicit policies rather than
implicit application behavior.

### Evidence

Authorization decisions should produce evidence that can be
verified after the decision has been made.

### Fail closed

When authorization requirements are not satisfied, the system
should deny the action rather than silently broaden permissions.

### Security boundaries

Identity, authority, policy, authorization, and evidence are treated
as distinct security concepts.

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
├── LICENSE
├── NOTICE
├── SECURITY.md
├── TRADEMARKS.md
└── README.md
