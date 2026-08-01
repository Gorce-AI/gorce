# Contributing to Gorce

Thank you for contributing. English is the project language for source code,
issues, reviews, and documentation.

## Before opening a change

1. Read the relevant architecture and ADR documents.
2. Keep changes within the approved S1 TypeScript/Bun workspace boundary.
3. Add or update tests for behavior and contracts.
4. Update documentation when a public contract changes.

## Local checks

Run these commands from the repository root:

```text
bun install --frozen-lockfile
bun run verify:technology -- --bun=1.3.14 --typescript=6.0.3 --strict
bun run verify:architecture -- --strict
bun test
```

The active S1 quality gate is Bun-only:

```text
bun install --frozen-lockfile
bun run verify:s1-cutover
bun run test:mutation
bun run lint
bun run typecheck
bun test
bun run audit
```

Do not add generated build output or secrets. Keep dependencies minimal and
justify new dependencies in the pull request.

## Pull requests

Use a focused branch and a descriptive pull request. Explain the problem,
the solution, compatibility impact, and validation performed. Pull requests
must pass CI and receive review before merge.

Contributions are accepted under the Apache License, Version 2.0, as described
in `LICENSE`.
