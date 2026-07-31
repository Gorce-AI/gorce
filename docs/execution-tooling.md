# Execution tooling

This repository contains verification tooling, not a production runtime. The
tooling is strict, typed TypeScript executed by Bun 1.3.14 and built with the
pinned compiler and linter versions in `package.json`.

Task 6 freezes the public architecture rules and their digests:

- `bun run verify:technology -- --bun=1.3.14 --typescript=6.0.3 --strict`
- `bun run verify:architecture -- --strict`
- `bun run architecture:hash-rules -- --technology=architecture/typescript-bun-baseline.v1.yaml --studio=architecture/studio-host-gate.v1.yaml --evidence=<path>`
- `bun run verify:architecture:ecosystem -- --published-only --technology-baseline=<digest> --core-inventory-ban=studio,jetbrains`

The ecosystem verifier uses clean hermetic sibling fixtures for F2. It is
fail-closed and must not be run as a happy-path check against this repository's
temporary Cargo scaffold. F2 requires exact set equality for the plan cases and
the Cargo/Node/Deno/non-Bun runtime overlays; each fixture establishes clean
Git trees and the three documented repository identities.

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
- `bun run qa:task -- --task=F2 --all --fixture=tests/qa/final/f2-architecture.yaml --evidence=<path>` runs every clean and negative F2 fixture.

Every command fails closed, returns a non-zero exit status on an incomplete or
invalid state, and accepts `--json` for machine-readable output. Private
manifests, signatures, keys, transcripts, and tool metadata remain outside the
repository; `.gitignore` and the repository scanner reject their staging.

Repository integrity retains a 250-line limit for ordinary TypeScript source.
The six Task 6 canonical-parser/verifier modules have a justified bounded
600-line allowance so their executable strict validation cannot be hidden from
the integrity scan; regression tests cover both limits.

The detached signature covers the exact canonical JSON bytes of the manifest.
The verifier checks the Ed25519 public-key binding, approved plan SHA, 41-task
graph, command owners, uniqueness, and acyclicity before reporting success.
