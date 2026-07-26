# Development

## Prerequisites

Install stable Rust with `rustfmt` and `clippy`. The repository pins these
components in `rust-toolchain.toml`.

## Common commands

```text
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p gorce
cargo run -p xtask
```

The current binaries are smoke-test placeholders. Do not treat their output
as a stable runtime interface.

## Change shape

Prefer small, vertical changes that preserve crate boundaries. Keep protocol
types independent of transports, keep core free of I/O, and add tests next to
the contract they protect. Update an ADR when a decision changes topology,
durability, or a public compatibility surface.
