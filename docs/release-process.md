# Release process

Releases are currently placeholders until runtime behavior and compatibility
policies are established.

## Planned release steps

1. Confirm Rust 1.88.0 MSRV evidence on Ubuntu:
   `cargo check --workspace --all-targets --locked`,
   `cargo test --workspace --locked`, and
   `cargo clippy --workspace --all-targets --locked -- -D warnings`.
2. Confirm the pinned Rust 1.97.1 three-platform gate passes on Ubuntu, macOS,
   and Windows. Its exact commands are:
   `cargo fmt --all -- --check`, `cargo check --workspace --locked`,
   `cargo test --workspace --locked`,
   `cargo clippy --workspace --all-targets --locked -- -D warnings`, and
   `python3 tests/contract/test_contract.py`.
3. Run `cargo audit --deny warnings` and require a clean result. No audit ignore
   is permitted, and no release may be made from an intermediate commit whose
   audit is red.
4. Review the changelog and public API or storage changes.
5. Update versions together where compatibility requires it.
6. Create a signed, annotated tag from the fully green release commit.
7. Publish artifacts and checksums through the release workflow.
8. Record migration, rollback, and known-issue notes.

Release artifacts must include the applicable Apache-2.0 license and NOTICE.
No release should claim runtime guarantees that are not covered by tests.
