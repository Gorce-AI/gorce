# ADR 0005: Bounded Phase 2 provider installation and hosting

- Status: Accepted target architecture
- Date: 2026-07-28
- Scope: Phase 2 provider-install V1 and daemon-owned provider host

## Context

Phase 1 freezes `gorce.provider/v1`, pure `gorce-core::provider` approval and
lease policy, the signed `.gorce-provider` archive verifier, schemas, and the
deterministic mock conformance package. It deliberately does not implement a
daemon registry, package host, protected credential persistence, or OAuth
exchange.

Phase 2 needs a bounded installation and execution authority without silently
turning a community package into an official or sandboxed package. The Oracle
preflight therefore requires an explicit user install decision, an immutable
source pin, durable daemon ownership, and a host-mediated OAuth lifecycle. This
ADR freezes that target and supersedes the Phase 1 signed-archive launch sketch
for the Phase 2 provider-install V1 path.

## Decision

### 1. Explicit unsigned Git source installation

The only V1 provider source is an explicitly user-initiated install from a
canonical, pinned Git URL. The daemon resolves that URL to an immutable full
commit and computes a content digest over the exact source snapshot it will
materialize. The durable install record contains, at minimum:

```text
canonical_git_url
resolved_immutable_commit
resolved_source_content_digest
```

The commit and content digest are both checked before a source is accepted and
before it is launched. Branches, moving tags, or an unpinned revision are not
an install authority. Re-resolution is a new explicit install or upgrade
decision, not an implicit update.

This path is intentionally unsigned. V1 does not require or consume a
publisher signature, an official signature, a marketplace listing, or an
official publisher identity. A direct HTTPS archive URL is not a V1 source,
and a local filesystem path is not a V1 source. Git transport and the explicit
immutable pin are the complete source authority for this target policy.

### 2. Durable daemon-global provider data

Installed provider records, resolved source snapshots, materialized files,
content digests, install state, and protected OAuth state live under one durable
daemon-global provider data root. The root is independent of a project,
workstream, workspace, current directory, or individual invocation. It is not
selected by a provider package or by a model-generated path.

The daemon owns recovery of this root. An install is either durably committed
with its immutable source record and materialized snapshot or remains absent;
partial installs, uncommitted metadata, and a directory that merely happens to
exist are not launch authority.

### 3. Verified-source materialization and process lifecycle

The host resolves and verifies the pinned Git source in a private staging
location. Only after commit identity, content digest, manifest/package
constraints, and executable binding pass does it materialize the verified
source files into the daemon-global provider root. The final materialized
directory and its metadata become visible through an atomic commit/rename
operation; failures leave no partially committed provider available for launch.

Each invocation starts one fresh provider process from the committed verified
source and tears that process down after the invocation. V1 does not pool,
reuse, or keep a provider process resident across invocations. The daemon owns
timeouts, cancellation, exit status, cleanup, and recovery around that fresh
process while preserving the `gorce.provider/v1` protocol boundary.

### 4. Daemon-owned OAuth

OAuth is a daemon responsibility, not provider-source authority. The daemon
owns the loopback listener, exact callback registration, state, PKCE verifier,
authorization-code exchange, access-token and refresh-token storage, refresh,
expiry/revocation handling, and crash/restart recovery. Callback acceptance is
bound to the daemon-created state and PKCE transaction and is restricted to the
daemon's loopback policy; a provider process does not receive a callback
listener or a refresh token.

Transient authorization state is recoverable and idempotent: incomplete flows
are expired or cancelled safely, durable refresh state is recovered by the
daemon, and a restarted daemon cannot accept an unrelated callback. A provider
receives only the scoped access credential required for its authorized
invocation through the existing host binding. These are Phase 2 host policies;
the Phase 1 ABI and pure policy remain free of network OAuth exchange,
persistence, and process supervision.

### 5. Trust model and non-sandbox boundary

An explicitly installed package is trusted as a same-user package for the
requested source pin. That trust is not sandboxing. The provider process runs
with the user's authority and may read user-accessible data or copy a
credential delivered to it. A fresh process, a daemon-global root, immutable
source verification, and loopback OAuth mediation do not create an untrusted
package mode or a security sandbox. A future sandbox/proxy model requires a
separate decision and real platform enforcement.

## Relationship to Phase 1

The Phase 1 `verify_provider_archive` implementation and opaque
`VerifiedProviderArchive` remain the current signed-package implementation and
its conformance evidence. They are not the source authority for the target
Phase 2 provider-install V1 path. Phase 2 supersedes that signed-archive launch
model with the explicit unsigned Git pin, resolved commit, content digest,
atomic materialization, fresh-process rule, and daemon-owned OAuth policy above.
The separately versioned provider ABI and the Phase 1 pure approval/lease
contracts remain the protocol and policy foundations unless a later ADR changes
them.

## Phase boundary and consequences

This ADR does not add a marketplace, publisher reputation, official signing,
direct archive downloads, local-path installation, a sandbox, a provider
process pool, or provider-owned OAuth callbacks. It also does not implement the
Phase 2 host; it freezes the authority and recovery rules that implementation
must satisfy.

The design makes user intent and immutable source identity auditable without
claiming publisher authenticity. It centralizes persistence and recovery in the
daemon, prevents partial source trees from becoming launchable, limits process
lifetime to one invocation, and keeps OAuth secrets outside provider source.
The tradeoff is that an explicitly installed same-user package remains fully
trusted and that Git availability and the pinned source digest become part of
the install/recovery contract.
