# Contributing to Gorce

Thank you for contributing. English is the project language for source code,
issues, reviews, and documentation.

## Before opening a change

1. Read the relevant architecture and ADR documents.
2. Keep changes within the crate or API boundary they belong to.
3. Add or update tests for behavior and contracts.
4. Update documentation when a public contract changes.

## Local checks

Run these commands from the repository root:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
python3 tests/contract/test_contract.py
cargo audit --deny warnings
```

Rust 1.88 is the workspace MSRV. The Ubuntu Rust 1.88.0 CI job is the
explicit MSRV gate; the pinned Rust 1.97.1 CI job runs the same locked checks
on Ubuntu, macOS, and Windows. All checks must pass, including a clean
`cargo audit --deny warnings`, before merge. Do not release or merge from an
intermediate commit with a red audit.

Do not add generated build output or secrets. Keep dependencies minimal and
justify new dependencies in the pull request.

## Pull requests

Use a focused branch and a descriptive pull request. Explain the problem,
the solution, compatibility impact, and validation performed. Pull requests
must pass CI and receive review before merge.

Contributions are accepted under the Apache License, Version 2.0, as described
in `LICENSE`.
