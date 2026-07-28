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

## Provider ABI boundary

`gorce.provider/v1` is frozen. The Phase 0 official-CLI adapter design does not
reinterpret V1 nullable authentication fields, add a CLI-session method to V1,
or change its wire methods, schemas, approval tuple, or secret-delivery
contract.

A future V2 may introduce one explicit tagged authentication binding:
`none`, `host_secret`, or `official_cli_session`. This is a versioned concept,
not a shipped V2 schema. `official_cli_session` names a future closed host
policy and has no credential class, delivery kind, or secret-delivery field. V2
must not silently translate a V1 field combination into that binding. General provider
execution remains disabled until a separate admissions redesign and review. Any
future daemon-owned OAuth/token lifecycle belongs only to `host_secret`;
`official_cli_session` delegates vendor authentication to the external official
CLI and never enters that Gorce OAuth path. Exact V2 wire shape and auth
semantics require a later human compatibility gate.

See `adr/0007-provider-runtime-official-cli-adapters.md` for the Phase 0
official-CLI, credential, cache, diagnostic, and login stop lines.
