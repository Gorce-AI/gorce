# Execution tooling

This repository contains strict S2 semantic-core verification and historical S1
native-packaging tooling, not a production runtime. The tooling is typed
TypeScript executed by Bun 1.3.14 and built with the pinned compiler and linter
versions in `package.json`.

The S2 semantic authority is `@gorce-ai/core`: immutable Session and WorkRun
events, replay, expected-version conflict handling, and this effect lifecycle:

```text
planned -> attempted -> confirmed | failed | unknown -> reconciled | compensated
```

Result affinity checks 13 independent fields covering roots, targets, execution,
streams, digests, and workspace revision. Durable storage is S3 scope; TUI,
terminal, renderer, and input behavior are S4 scope.

Task 6 freezes the public architecture rules and their digests:

- `bun run verify:technology -- --bun=1.3.14 --typescript=6.0.3 --strict`
- `bun run verify:architecture -- --strict`
- `bun run verify:s2 -- --evidence="$RUNNER_TEMP/gorce-s2-evidence/semantic-core.json"` emits the S2 semantic-core evidence record.
- `bun run test:mutation -- --evidence="$RUNNER_TEMP/gorce-s2-evidence/mutation.json"` runs real mutations against the S2 semantic-law tests and requires at least 90% killed targets.
- `bun run typecheck` (no-emit project-reference graph)
- `bun run build:native -- --target=<target> --outfile="$RUNNER_TEMP/gorce-s1-evidence/native/<artifact>" --evidence="$RUNNER_TEMP/gorce-s1-evidence/native/build.json"` and `bun run verify:native -- --target=<target> --builder-bun=1.3.14 --artifact="$RUNNER_TEMP/gorce-s1-evidence/native/<artifact>" --evidence="$RUNNER_TEMP/gorce-s1-evidence/native/hello.json"`
- `bun run verify:reproducible -- --target=<target> --evidence="$RUNNER_TEMP/gorce-s1-evidence/reproducibility.json"`
- `bun run verify:native:index -- --input="$RUNNER_TEMP/gorce-s1-evidence/native" --output="$RUNNER_TEMP/gorce-s1-evidence/native-index.json"`
- `bun run audit` (`bun audit`)
- `bun run architecture:hash-rules -- --technology=architecture/typescript-bun-baseline.v1.yaml --studio=architecture/studio-host-gate.v1.yaml --evidence=<path>`
- `bun run verify:architecture:ecosystem -- --published-only --technology-baseline=<digest> --core-inventory-ban=studio,jetbrains`

The ecosystem command emits `verdict=APPROVED` only for a validated clean
three-repository ecosystem; every failure emits `verdict=CHANGES_REQUESTED`
and retains a non-zero exit status.

The ecosystem verifier uses clean hermetic sibling fixtures for F2. It is
fail-closed and is independent of the active S1 workspace. F2 requires exact
set equality for the plan cases and the Cargo/Node/Deno/non-Bun runtime overlays; each fixture establishes clean
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
invalid state, accepts `--json` for machine-readable output, and writes
acceptance evidence outside the checkout by default. Private
manifests, signatures, keys, transcripts, and tool metadata remain outside the
repository; `.gitignore` and the repository scanner reject their staging.

Repository integrity retains a 250-line limit for ordinary TypeScript source.
The bounded Task 6 canonical-parser/verifier modules have a justified
600-line allowance so their executable strict validation cannot be hidden from
the integrity scan; regression tests cover both limits.

The detached signature covers the exact canonical JSON bytes of the manifest.
The verifier checks the Ed25519 public-key binding, approved plan SHA, 41-task
graph, command owners, uniqueness, and acyclicity before reporting success.
