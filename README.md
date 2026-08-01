# Gorce

Gorce Core is the S1 TypeScript/Bun core-first preview workspace. S1 provides
the private core/TUI-harness graph and a deterministic native hello artifact;
semantic core and operational TUI work are explicitly deferred.

## Repository layout

- `architecture/` — canonical technology baseline and Studio host decision rule.
- `src/` — TypeScript verification, cutover, and packaging tooling.
- `packages/core/` — private TypeScript core package.
- `packages/tui-harness/` — private reusable hello harness package.
- `apps/tui-harness/` — private argument-free Bun executable app.
- `docs/` — architecture, operations, security, and decision records.

See `docs/architecture.md` for the authoritative S1 TypeScript/Bun boundary.

## Status

S1 is a development core-first packaging preview. It makes no terminal
regression, release, candidate, daemon, storage, provider, or operational-TUI
claim.

## Development

The foundation gate uses Bun 1.3.14, TypeScript 6.0.3, and Biome 2.2.4:

```text
bun install --frozen-lockfile
bun run verify:technology -- --bun=1.3.14 --typescript=6.0.3 --strict
bun run verify:architecture -- --strict
mkdir -p "$RUNNER_TEMP/gorce-s1-evidence/native"
bun run verify:s1-cutover -- --evidence="$RUNNER_TEMP/gorce-s1-evidence/cutover.json"
bun run build:native -- --target=bun-darwin-arm64 --outfile="$RUNNER_TEMP/gorce-s1-evidence/native/gorce-tui-harness" --evidence="$RUNNER_TEMP/gorce-s1-evidence/native/build.json"
bun run verify:native -- --target=bun-darwin-arm64 --builder-bun=1.3.14 --artifact="$RUNNER_TEMP/gorce-s1-evidence/native/gorce-tui-harness" --evidence="$RUNNER_TEMP/gorce-s1-evidence/native/hello.json"
bun run verify:reproducible -- --target=bun-darwin-arm64 --evidence="$RUNNER_TEMP/gorce-s1-evidence/reproducibility.json"
bun run verify:native:index -- --input="$RUNNER_TEMP/gorce-s1-evidence/native" --output="$RUNNER_TEMP/gorce-s1-evidence/native-index.json"
bun run test:mutation
```

The active S1 quality gate is Bun-only:

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

All command output is human-readable by default and supports `--json`. S1
verification emits fail-closed cutover, native-hello, reproducibility, and
native-evidence-index JSON. Cross-built binaries are never treated as native
validation; native evidence records the runner OS and architecture.

## License

Gorce is licensed under the Apache License, Version 2.0. See `LICENSE` and
`NOTICE`.
