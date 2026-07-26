# Architecture

Gorce is a local-first system with explicit boundaries between the daemon,
agent, storage, protocol, and client layers. The v0.1 repository contains
contracts only; runtime execution is deliberately deferred.

## Boundaries

- `gorce-protocol` owns versioned wire-level types and identifiers.
- `gorce-core` owns domain concepts and invariants independent of I/O.
- `gorce-store` owns filesystem layout, persistence, and recovery contracts.
- `gorce-agent` owns coordination between domain operations and storage.
- `gorce-daemon` owns process lifecycle and the local API boundary.
- `gorce-sdk` owns client-facing API access without daemon internals.
- `gorce-tui` owns terminal presentation and user interaction.
- `gorce` is the user-facing executable and composition root.

Dependencies should point toward stable foundations. Domain code must not
depend on the daemon, TUI, or CLI. I/O and process concerns remain at the
edges.

## Runtime shape

The daemon will be the single owner of mutable state and will expose a local,
versioned API. Agents will perform operations through core and store contracts.
Clients will use the SDK rather than reaching into daemon internals.

## Compatibility

Protocol and storage formats are public compatibility surfaces. Changes require
an explicit versioning decision, migration or recovery behavior, and tests.
See `api-versioning.md`, `storage-format.md`, and the related ADRs.
