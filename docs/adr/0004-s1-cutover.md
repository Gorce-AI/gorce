# ADR 0004: S1 core-first TypeScript/Bun cutover

- Status: Accepted for S1; supersedes the implementation portion of ADR 0003
- Date: 2026-08-01

## Context

ADR 0003 records the historical Rust bootstrap and the TypeScript/Bun target.
S1 is the first implementation phase of the successor core-first plan. It
must establish the private workspace and native packaging evidence without
rewriting the historical daemon, storage, or topology decisions in ADRs
0001-0003.

## Decision

S1 production consists only of `packages/core`, `packages/tui-harness`, and
`apps/tui-harness`, with dependencies flowing app to harness to core. Bun
1.3.14 is the only active runtime. The production tree rejects Cargo/Rust,
the retired API tree, and non-Bun runtime artifacts. TypeScript verification is
no-emit, deterministic, and backed by an exact acyclic project-reference
graph. Native evidence is limited to the Linux x64, macOS arm64, and Windows
x64 hello lanes and is explicitly not release qualification.

## Scope boundary

Semantic core, durable storage, recovery, rendering, input, daemon/transport,
providers, runtime dependencies, satellite products, and release behavior are
deferred to later successor phases. ADRs 0001-0003 remain historical decisions
and are not reinterpreted by this S1 cutover.
