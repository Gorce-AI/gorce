# Development

## Prerequisites

Install Rust 1.88 or newer with `rustfmt` and `clippy`. Rust 1.88 is the
workspace MSRV. The repository's floating stable configuration is convenient
for development, while CI explicitly proves Rust 1.88.0 and retains the pinned
Rust 1.97.1 Ubuntu/macOS/Windows gate.

## Common commands

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
python3 tests/contract/test_contract.py
cargo audit --deny warnings
cargo run -p gorce
cargo run -p xtask
```

The TUI regression suite uses `TestBackend` buffers and injected surface/input
seams, so geometry, clipping/wrapping, Unicode, palette/operations,
reconnect, input, and render-failure behavior can be checked without brittle
full-screen snapshots. For a native terminal smoke, with a local daemon
available, run `cargo run -p gorce -- daemon foreground`, resize through
small/narrow/medium/wide terminals, exercise keyboard, mouse, and bracketed
paste input, then quit and confirm the terminal is restored after normal exit
and an interrupted run.

Do not treat a passing intermediate commit as releasable: the full locked
workspace gate and clean `cargo audit --deny warnings` are required.

The current binaries are smoke-test placeholders. Do not treat their output
as a stable runtime interface.

## Change shape

Prefer small, vertical changes that preserve crate boundaries. Keep protocol
types independent of transports, keep core free of I/O, and add tests next to
the contract they protect. Update an ADR when a decision changes topology,
durability, or a public compatibility surface.
