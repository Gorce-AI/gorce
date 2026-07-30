# Execution tooling

This repository contains verification tooling, not a production runtime. The
tooling is strict, typed TypeScript executed by Bun 1.3.14 and built with the
pinned compiler and linter versions in `package.json`.

## Commands

- `bun run verify:bootstrap -- --execution-manifest=<path>` verifies an
  externally supplied signed execution manifest and the repository snapshot.
- `bun run qa:task -- --task=03 --all --evidence=<path>` dispatches complete
  Task 3 QA against an evidence directory.
- `bun run verify:plan-compliance` verifies the pinned plan policy. Supplying
  `--execution-manifest=<path>` adds detached-input verification.
- `bun run docs:verify` checks the public documentation contract.
- `bun run verify:evidence -- --evidence=<path>` validates the evidence
  envelope and, when present, its external manifest materials.

Every command fails closed, returns a non-zero exit status on an incomplete or
invalid state, and accepts `--json` for machine-readable output. Private
manifests, signatures, keys, transcripts, and tool metadata remain outside the
repository; `.gitignore` and the repository scanner reject their staging.

The detached signature covers the exact canonical JSON bytes of the manifest.
The verifier checks the Ed25519 public-key binding, approved plan SHA, 41-task
graph, command owners, uniqueness, and acyclicity before reporting success.
