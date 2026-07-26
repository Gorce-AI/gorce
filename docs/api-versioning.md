# API versioning

The API is versioned independently from the Rust crate versions and storage
format. The initial public API namespace is `/v1` when non-health endpoints are
introduced. The unversioned `/health` endpoint is a liveness contract and may
remain stable across API versions.

## Rules

- Additive response fields are compatible unless clients opt into strict
  decoding.
- Removing, renaming, or changing the meaning of a field is breaking.
- Breaking changes require a new major API version and a migration note.
- Error codes are stable identifiers; messages are for humans.
- Every request should have a traceable request identifier once runtime exists.

OpenAPI is the source of truth for HTTP shape. JSON Schemas under
`api/schemas` are reusable payload contracts and should be updated with the
OpenAPI document in the same change.
