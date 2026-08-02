# Gorce

Gorce Core is the S2 TypeScript/Bun core-first preview workspace. S1 provides
the private core/TUI-harness graph and native packaging baseline; S2 now
provides the executable semantic core. Durable storage (S3) and the headless
TUI (S4) remain explicitly deferred.

## Repository layout

- `architecture/` — canonical technology baseline and Studio host decision rule.
- `src/` — TypeScript verification, cutover, and packaging tooling.
- `packages/core/` — private TypeScript core package.
- `packages/tui-harness/` — private reusable hello harness package.
- `apps/tui-harness/` — private argument-free Bun executable app.
- `docs/` — architecture, operations, security, and decision records.

See `docs/architecture.md` for the authoritative S2 TypeScript/Bun boundary.

## Status

S2 is a development semantic-core preview. `@gorce-ai/core` is the sole
semantic authority for independent Session and WorkRun roots. Commands use
expected versions and emit immutable versioned events. Effects follow the
only legal lifecycle:

```text
planned -> attempted -> confirmed | failed | unknown -> reconciled | compensated
```

`unknown` means dispatched-but-unconfirmed work. Result affinity independently
binds these 13 fields: `session_id`, `work_run_id`, `effect_id`,
`target_authority`, `target_id`, `target_version`, `execution_ref`,
`stream_generation`, `input_digest`, `contract_digest`, `route_digest`,
`workspace_id`, and `workspace_revision`.

S2 makes no storage/fsync, terminal/TUI, renderer, daemon, transport, provider,
release, candidate, or operational-TUI claim. S3 durable storage and S4 TUI
work are downstream phases.

## Development

The foundation gate uses Bun 1.3.14, TypeScript 6.0.3, and Biome 2.2.4:

```text
bun install --frozen-lockfile
bun run verify:technology -- --bun=1.3.14 --typescript=6.0.3 --strict
bun run verify:architecture -- --strict
mkdir -p "$RUNNER_TEMP/gorce-s1-evidence/native"
bun run build:native -- --target=bun-darwin-arm64 --outfile="$RUNNER_TEMP/gorce-s1-evidence/native/gorce-tui-harness" --evidence="$RUNNER_TEMP/gorce-s1-evidence/native/build.json"
bun run verify:native -- --target=bun-darwin-arm64 --builder-bun=1.3.14 --artifact="$RUNNER_TEMP/gorce-s1-evidence/native/gorce-tui-harness" --evidence="$RUNNER_TEMP/gorce-s1-evidence/native/hello.json"
bun run verify:reproducible -- --target=bun-darwin-arm64 --evidence="$RUNNER_TEMP/gorce-s1-evidence/reproducibility.json"
bun run verify:native:index -- --input="$RUNNER_TEMP/gorce-s1-evidence/native" --output="$RUNNER_TEMP/gorce-s1-evidence/native-index.json"
bun run verify:s2 -- --evidence="$RUNNER_TEMP/gorce-s2-evidence/semantic-core.json"
bun run test:mutation -- --evidence="$RUNNER_TEMP/gorce-s2-evidence/mutation.json"
```

The active S2 quality gate is Bun-only:

```text
bun run lint
bun run typecheck
bun test
bun run audit
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

All command output is human-readable by default and supports `--json`. S2
verification and mutation evidence are source-bound and fail closed. S1
cutover/native schemas remain historical evidence; cross-built binaries are
never treated as native validation.

## License

Gorce is licensed under the Apache License, Version 2.0. See `LICENSE` and
`NOTICE`.
