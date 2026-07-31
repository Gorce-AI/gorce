# Architecture authority

The public architecture authority is the canonical, strictly parsed YAML in
`architecture/`. `typescript-bun-baseline.v1.yaml` fixes Bun 1.3.14,
TypeScript 6.0.3, Biome 2.2.4, ESM, compiler policy, required commands, and
native validation targets. `studio-host-gate.v1.yaml` is only the normative
Task-31 extension-versus-fork decision procedure; it is not an evaluation.

The core target is a TypeScript/Bun workspace. Task 6 intentionally adds only
the foundation rules, verifiers, and hermetic F2 fixtures. The future
`apps/`, `packages/`, `contracts/`, and other product build graph are not
materialized by this task.

## Transitional scaffold

The Rust crates currently present are a temporary Rust scaffold inherited from
repository bootstrap. They are superseded by the TypeScript/Bun target and are
not final compliance. They remain untouched so the existing Rust CI `checks`
job can continue to validate the scaffold while the TypeScript foundation is
introduced in parallel.

## Ownership and isolation

Core owns the runtime, contracts, generators, and verification tooling. Studio
and JetBrains remain sovereign sibling repositories. Core may contain generic
hermetic consumer fixtures, but never Studio or JetBrains production inventory,
source trees, or cross-repository path dependencies. Product acceptance uses
published immutable artifacts only.

Changes to the baseline or host gate require an explicit architecture change;
their canonical bytes and SHA-256 digests are consumed by later tasks.
