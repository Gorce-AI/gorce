# Architecture authority

The public architecture authority is the canonical, strictly parsed YAML in
`architecture/`. `typescript-bun-baseline.v1.yaml` fixes Bun 1.3.14,
TypeScript 6.0.3, Biome 2.2.4, ESM, compiler policy, required commands, and
native validation targets. `studio-host-gate.v1.yaml` is only the normative
Task-31 extension-versus-fork decision procedure; it is not an evaluation.

The core target is now the approved S1 TypeScript/Bun workspace. Its exact
private workspace graph is `packages/core` -> `packages/tui-harness` ->
`apps/tui-harness`; the only executable product artifact is the argument-free
`gorce-tui-harness` Bun-compiled hello artifact. S1 is a platform cutover and
packaging spike, not a terminal-regression product, semantic core, or
operational TUI.

## S1 boundary

Cargo, Rust, xtask, the daemon OpenAPI placeholder, and placeholder release
automation are retired from the active tree. CI and security use Bun only.
The historical Task-6 verifier still retains Cargo-negative F2 fixtures and
structural detection so those negative tests remain evidence, not production
toolchain claims. S1 does not introduce commands, events, sessions, work runs,
storage, rendering, input, daemon, transport, providers, or satellite code.

## Ownership and isolation

Core owns the runtime, contracts, generators, and verification tooling. Studio
and JetBrains remain sovereign sibling repositories. Core may contain generic
hermetic consumer fixtures, but never Studio or JetBrains production inventory,
source trees, or cross-repository path dependencies. Product acceptance uses
published immutable artifacts only.

The documented ecosystem layout is three clean Git siblings: `gorce`,
`gorce-studio`, and `gorce-jetbrains`, with origins
`Gorce-AI/gorce`, `Gorce-AI/gorce-studio`, and `Gorce-AI/gorce-jetbrains`.

Changes to the baseline or host gate require an explicit architecture change;
their canonical bytes and SHA-256 digests are consumed by later tasks.
