# Storage format

The storage design is filesystem-first. The directory is the primary durable
artifact and should remain inspectable, copyable, and recoverable without a
running daemon.

## Planned layout

```text
<root>/
  format-version
  objects/
  indexes/
  journal/
  snapshots/
  locks/
```

The exact record encoding is not implemented in v0.1. Each future format must
define canonical encoding, atomic write rules, checksums, permissions, and
recovery behavior before it is released.

## Invariants

- Writes are staged and atomically published where the platform permits.
- A committed record is self-describing and verifiable.
- Derived indexes can be rebuilt from durable objects.
- A failed write cannot silently appear as a successful commit.
- Format changes are explicit and never inferred from application versions.

## Compatibility

`format-version` identifies the on-disk format. Readers may support multiple
versions, but writers must emit one canonical version. Incompatible changes
require migration tooling or a documented export and restore path.
