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

The S1 commands below are the active Bun-only development gate. The compiled
hello artifact is a packaging check only and is not a release qualification.

```text
bun install --frozen-lockfile
mkdir -p "$RUNNER_TEMP/gorce-s1-evidence/native"
bun run verify:s1-cutover -- --evidence="$RUNNER_TEMP/gorce-s1-evidence/cutover.json"
bun run lint
bun run typecheck
bun test
bun run build:native -- --target=bun-darwin-arm64 --outfile="$RUNNER_TEMP/gorce-s1-evidence/native/gorce-tui-harness" --evidence="$RUNNER_TEMP/gorce-s1-evidence/native/build.json"
bun run verify:native -- --target=bun-darwin-arm64 --builder-bun=1.3.14 --artifact="$RUNNER_TEMP/gorce-s1-evidence/native/gorce-tui-harness" --evidence="$RUNNER_TEMP/gorce-s1-evidence/native/hello.json"
bun run verify:reproducible -- --target=bun-darwin-arm64 --evidence="$RUNNER_TEMP/gorce-s1-evidence/reproducibility.json"
bun run verify:native:index -- --input="$RUNNER_TEMP/gorce-s1-evidence/native" --output="$RUNNER_TEMP/gorce-s1-evidence/native-index.json"
bun run test:mutation
bun run audit
```

The current binaries are smoke-test placeholders. Do not treat their output
as a stable runtime interface.

## Change shape

Prefer small, vertical changes that preserve the canonical TypeScript/Bun
boundaries. Add tests next to the contract they protect. Update an ADR when a
decision changes topology, durability, or a public compatibility surface.
