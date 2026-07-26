# ADR 0002: Use filesystem-first storage

- Status: Accepted
- Date: 2026-07-26

## Context

The first product milestone prioritizes local ownership, inspectability,
portability, and recovery over centralized infrastructure.

## Decision

The filesystem is the durable source of truth. The storage crate defines an
explicit format, atomic publication rules, and rebuildable derived indexes.
Database or remote-service dependencies are not part of the initial runtime.

## Consequences

Users can copy and back up a storage root directly. Concurrency, locking,
crash recovery, and format migration require deliberate implementation and
failure testing.
