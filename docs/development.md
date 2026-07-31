# Development

## Prerequisites

Install Bun 1.3.14. TypeScript 6.0.3 and Biome 2.2.4 are committed in the
technology baseline and lockfile.

## Common commands

```text
bun install --frozen-lockfile
bun run verify:technology -- --bun=1.3.14 --typescript=6.0.3 --strict
bun run verify:architecture -- --strict
bun test
```

The Rust commands below validate only the temporary bootstrap scaffold and
remain the existing CI `checks` job; Rust is not final architecture compliance.

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

Prefer small, vertical changes that preserve the canonical TypeScript/Bun
boundaries. Add tests next to the contract they protect. Update an ADR when a
decision changes topology, durability, or a public compatibility surface.
