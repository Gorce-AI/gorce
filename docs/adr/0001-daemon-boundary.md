# ADR 0001: Keep the daemon as an explicit process boundary

- Status: Accepted
- Date: 2026-07-26

## Context

Gorce needs one owner for mutable state and a stable local API without coupling
clients to storage or process internals.

## Decision

The daemon owns process lifecycle, API transport, request validation, and
composition of agents. The SDK and TUI communicate through public contracts;
they do not depend on daemon implementation details.

## Consequences

The boundary improves isolation and enables multiple clients. It adds explicit
serialization and lifecycle concerns that must be tested when runtime work
begins.
