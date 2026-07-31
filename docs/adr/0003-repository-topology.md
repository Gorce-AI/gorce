# ADR 0003: Transitional Rust scaffold and TypeScript/Bun target

- Status: Superseded for the production target; retained as scaffold record
- Date: 2026-07-26

## Context

The repository was initially bootstrapped as a layered Rust workspace. The
approved architecture now fixes TypeScript 6.0.3 on Bun 1.3.14 for core and
tooling; Kotlin/Gradle remains sovereign to the JetBrains repository.

## Decision

The existing Cargo workspace and `xtask` are a temporary Rust scaffold only.
The production authority is the canonical TypeScript/Bun baseline in
`architecture/typescript-bun-baseline.v1.yaml`. Task 6 does not create the
future TypeScript workspace graph.

## Consequences

Rust checks preserve bootstrap confidence during migration, but Rust is not
final architecture compliance. New production implementation follows the
TypeScript/Bun baseline and the sovereign sibling-repository boundaries.
