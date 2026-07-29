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

The repository requires Rust 1.88 or newer with `rustfmt` and `clippy`.
Run the complete local gate from the repository root:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
python3 tests/contract/test_contract.py
cargo audit --deny warnings
```

CI also runs the same check, test, and Clippy commands on Ubuntu with the
explicit Rust 1.88.0 MSRV toolchain. The pinned Rust 1.97.1 job remains the
three-platform release gate for Ubuntu, macOS, and Windows. A release requires
all of these gates, including a clean `cargo audit --deny warnings`; do not
release from an intermediate commit whose audit is still red.

See `CONTRIBUTING.md` and `docs/development.md` for contribution and workflow
details.

## License

Gorce is licensed under the Apache License, Version 2.0. See `LICENSE` and
`NOTICE`.
