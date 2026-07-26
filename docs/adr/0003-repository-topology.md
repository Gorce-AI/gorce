# ADR 0003: Use a layered Rust workspace

- Status: Accepted
- Date: 2026-07-26

## Context

The project has distinct protocol, domain, storage, process, client, and UI
concerns. A single package would make dependency direction and ownership
unclear.

## Decision

Use one Cargo workspace with focused crates under `crates/`, a standalone
`xtask` package, and API and documentation assets at the repository root.
Dependencies point from outer layers toward foundational contracts.

## Consequences

Crates can be tested and versioned as boundaries, while workspace checks keep
the repository coherent. The topology introduces package coordination overhead
that is accepted in exchange for explicit ownership.
