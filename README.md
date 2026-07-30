# Gorce

Gorce is a Rust monorepo for a local-first service with a daemon, agent,
filesystem-backed storage, SDK, and terminal interface. This repository is
the v0.1 scaffold. Runtime behavior is intentionally not implemented yet.

## Repository layout

- `crates/gorce-protocol` — shared wire and API contracts.
- `crates/gorce-core` — domain contracts and invariants.
- `crates/gorce-store` — storage contracts and format boundaries.
- `crates/gorce-agent` — agent contracts.
- `crates/gorce-daemon` — daemon process boundary.
- `crates/gorce-sdk` — client-facing library contracts.
- `crates/gorce-tui` — terminal interface contracts.
- `crates/gorce` — command-line application.
- `api/` — OpenAPI and JSON Schema placeholders.
- `docs/` — architecture, operations, security, and decision records.
- `xtask/` — repository maintenance command skeleton.

The dependency direction is from protocol and core foundations toward storage,
agent, daemon, and client layers. See `docs/architecture.md` for the intended
boundaries.

## Status

This is a public-ready scaffold, not a usable runtime. APIs, storage behavior,
authentication, and operational commands will be added in later milestones.

## Development

The repository requires the stable Rust toolchain with `rustfmt` and `clippy`.
Run the complete local gate:

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
