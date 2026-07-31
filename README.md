# Gorce

Gorce is a local-first service with a TypeScript/Bun core target. This
repository is the v0.1 bootstrap scaffold; the currently checked-in Rust
crates are temporary and are not final architecture compliance.

## Repository layout

- `architecture/` — canonical technology baseline and Studio host decision rule.
- `src/` — TypeScript verification and execution tooling.
- `crates/` — temporary Rust scaffold retained for the existing CI checks job.
- `api/` — OpenAPI and JSON Schema placeholders.
- `docs/` — architecture, operations, security, and decision records.
- `xtask/` — repository maintenance command skeleton.

See `docs/architecture.md` for the authoritative TypeScript/Bun target and
sovereign sibling-repository boundaries. Task 6 does not create the future
application/package workspace graph.

## Status

This is a public-ready scaffold, not a usable runtime. APIs, storage behavior,
authentication, and operational commands will be added in later milestones.

## Development

The foundation gate uses Bun 1.3.14, TypeScript 6.0.3, and Biome 2.2.4:

```text
bun install --frozen-lockfile
bun run verify:technology -- --bun=1.3.14 --typescript=6.0.3 --strict
bun run verify:architecture -- --strict
```

The Rust commands validate only the temporary scaffold:

```text
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

See `CONTRIBUTING.md` and `docs/development.md` for contribution and workflow
details.

## TypeScript execution tooling

The repository's signed execution gate is intentionally external-input based:
private manifests, signatures, and keys are never committed. With Bun 1.3.14,
run the complete tooling gate with an externally supplied manifest directory:

```text
bun install --frozen-lockfile
bun run verify:bootstrap -- --execution-manifest=/path/to/execution-manifest.json
bun run qa:task -- --task=03 --all --evidence=/path/to/evidence
bun run verify:plan-compliance
bun run docs:verify
```

All command output is human-readable by default and supports `--json`. The
bootstrap verifier validates the detached Ed25519 signature, the approved plan
binding, the complete blocker graph, command ownership, repository license,
private-artifact exclusions, and source-module limits.

## License

Gorce is licensed under the Apache License, Version 2.0. See `LICENSE` and
`NOTICE`.
