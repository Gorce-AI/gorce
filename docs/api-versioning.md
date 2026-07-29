# API versioning

The API is versioned independently from the Rust crate versions and storage
format. The initial public API namespace is `/v1` when non-health endpoints are
introduced. The unversioned `/health` endpoint is a liveness contract and may
remain stable across API versions.

> **Phase 1 status — representation-only V2 lane.** The narrow
> representation-only V2 schema/auth contract is the current Phase 1 V2
> contract. All V1 behavior remains frozen. Existing V1 core policy,
> source/archive verification, and durable authority remain current; only V2
> integration into those systems is deferred. Runtime execution, provider
> runtime, daemon/public APIs,
> cache/materialization, CLI policy/version/argv/env/cwd,
> login/status/diagnostics, budgets, and TUI surfaces remain deferred. This
> lane does not provide runtime authorization or execute CLI adapters.

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

`gorce.provider/v1` is frozen. The historical Phase 0 official-CLI adapter
design does not reinterpret V1 nullable authentication fields, add a CLI-session
method to V1, or change its wire methods, schemas, approval tuple, or
secret-delivery contract.

The narrow representation-only V2 schema/auth contract is the current Phase 1
V2 contract and uses one explicit tagged authentication binding: `none`,
`host_secret`, or `official_cli_session`. This is a representation contract,
not runtime authorization or credential delivery. `official_cli_session` names a
deferred closed host policy and has no credential class, delivery kind, or
secret-delivery field. The V2 representation must not silently translate a V1
field combination into that binding. V2 integration into existing
source/archive verification and approval/lease policy, runtime execution, and
exact CLI policy values remains deferred. Any future daemon-owned OAuth/token
lifecycle belongs only to `host_secret`; `official_cli_session` delegates
vendor authentication to the external official CLI and never enters that Gorce
OAuth path. Runtime auth semantics require a later human compatibility gate.

See `adr/0007-provider-runtime-official-cli-adapters.md` for the historical
Phase 0 official-CLI, credential, cache, diagnostic, and login stop lines and
the current representation-only V2 boundary.
