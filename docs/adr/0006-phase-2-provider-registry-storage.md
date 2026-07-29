# ADR 0006: Phase 2 daemon-global provider registry storage

- Status: Accepted; storage-only contract frozen
- Date: 2026-07-28
- Scope: Durable provider approval registry and daemon-global data root only

## Context

ADR 0005 freezes the resolver-owned pinned-Git source proof. A later install
and host implementation needs a durable daemon-owned place to retain the exact
approval derived from that opaque proof, without turning a project directory,
provider package, or model-supplied path into authority. The Oracle-approved
Phase 2 slice is storage-only: it defines the registry/install root and its
crash, concurrency, and durability contract, but does not resolve or fetch Git
sources and does not launch providers.

## Decision

### 1. Daemon-global storage boundary

The daemon owns one `provider_data_root` for its installation and configured
identity. It is durable, daemon-global, and independent of projects,
workspaces, repositories, current directories, and individual invocations. A
provider, source manifest, client, or model cannot select, relocate, or widen
this root. The root is private to the daemon identity and is created only as a
directory with the platform's required owner/access checks.

This slice stores provider approval metadata only. It does not store a cloned
Git tree, a materialized source snapshot, an executable, a credential, OAuth
state, or a process handle. The registry is metadata authority for an
explicitly approved source; it is not source transport or source content.

### 2. Fixed layout, format marker, and lock

The root has this fixed layout:

```text
provider_data_root/
├── FORMAT
├── LOCK
└── registry.json
```

`FORMAT` is an immutable UTF-8 text marker whose complete contents are exactly
`gorce.provider-data/v1\n`. `LOCK` is a zero-length regular sentinel. The OS
lock held on an open `LOCK` descriptor is the authority; its contents, a PID,
or a timestamp are not a lock protocol. `registry.json` is the sole
authoritative registry document. A publication candidate may briefly exist as
an implementation-private same-directory temporary file, but it is never
authority and is not a second registry.

Root creation is performed under the lock and publishes `FORMAT` and an empty
valid registry together. An existing root with a valid `FORMAT` but a missing,
partial, or invalid `registry.json` is a recovery failure, not an empty
registry. There is no automatic format migration, directory scan, or fallback
to a newly initialized root.

### 3. Strict registry document

`registry.json` is canonical UTF-8 JSON with no duplicate keys, unknown fields,
noncanonical values, or trailing data. Its fixed top-level shape is:

```json
{
  "format": "gorce.provider/registry/v1",
  "generation": 0,
  "entries": [
    {
      "provider_id": "provider-id",
      "approval_id": "sha256-<64 lower-case hex characters>",
      "approval": { "...": "exact source approval record" }
    }
  ]
}
```

`generation` is an unsigned 64-bit value. It starts at zero and increases by
exactly one for every successful publication. `entries` is bounded to 256
records and the complete canonical document is bounded to 1 MiB. Entries are
sorted by lower-case `provider_id`, contain no duplicate provider or approval
IDs, and the entry `provider_id` must equal the embedded approval's provider
ID. Empty `entries` is valid only for a fully valid, durably published initial
document.

The registry has no source paths, materialization paths, executable paths,
credentials, OAuth state, lifecycle claims, or caller-supplied authority
booleans. It contains approval records and their stable IDs only.

### 4. Source approval records and `approval_id`

An approval entry is accepted only when it is the strict storage projection of
`ProviderApprovalTuple::from_verified_source` for one opaque
`VerifiedProviderSource`. Storage does not reconstruct approval from a URL,
manifest, digest, executable, capability list, or caller-provided ID. Its
canonical source record is:

```text
record_format: "gorce.provider/source-approval/v1"
provider_id
package_digest                 # the source content digest
manifest_digest
publisher_fingerprint: null
executable_sha256
capabilities                   # the complete exact capability set
source_identity:
  canonical_git_url
  commit_hash_algorithm
  resolved_commit
  source_content_digest_algorithm
```

`package_digest` is the 64-character lower-case source content digest; the
archive/content accessor aliases from the shared approval policy are not
separate storage values. `source_identity` is mandatory for this source record,
and `publisher_fingerprint` is explicitly null. No publisher, Ed25519,
official-signature, or marketplace claim may be added. The capability object
must preserve the complete approved auth policies, tool IDs and policies,
credential classes, origins, side effects, and tool-credential bindings; sets
are serialized in deterministic sorted order.

`approval_id` is not caller input. It is
`sha256-` followed by lower-case SHA-256 of the canonical UTF-8 JSON bytes of
the approval record without `approval_id`. Canonical JSON uses sorted object
keys, deterministic array ordering where the record represents a set, compact
separators, and no alternate numeric spellings. Recomputing the ID, checking
all digest lengths and lowercase forms, checking the source identity, and
checking the null publisher field are mandatory on both write and recovery.
Changing any source content, manifest, executable, capability, URL, commit,
hash algorithm, or source-digest algorithm produces a different approval ID
and requires a new explicit approval record.

There is at most one current entry for a provider ID. Replacing it is an
explicit generation-changing registry publication; it is never an implicit
upgrade, merge, or approval inheritance.

### 5. Bounded locking, publication, concurrency, and poisoning

Every registry read, recovery, and write obtains the root lock. Mutations hold
the exclusive `LOCK` descriptor from the read/validate phase through
publication. Lock acquisition has a bounded wait and returns a typed
contention failure; stale lock contents are not trusted and a lock is never
stolen or deleted by timeout. Where shared reads are supported they still use
the same sentinel and recovery rules; recovery and publication are exclusive.

A mutation carries the generation it read. Under the lock it must still match
the current document, otherwise it fails with a conflict and retries only by
re-reading a bounded number of times. There is no last-writer-wins update and
no unbounded retry loop.

Publication is a single-document transaction:

1. read and strictly validate `registry.json` and the expected generation;
2. construct the complete next document in memory within the byte and record
   bounds;
3. write one same-directory temporary file with restrictive permissions;
4. flush the complete temporary file and validate its bytes again;
5. atomically replace `registry.json` without a cross-filesystem move; and
6. perform the platform-specific directory-entry durability step before
   reporting the result.

Before replacement, every failure leaves the previous valid registry as the
only authority. A temporary file, stale temporary file, malformed candidate,
duplicate record, mismatched `approval_id`, or oversized document is rejected,
never merged, and never loaded as a fallback. Candidate cleanup is bounded and
under the lock. A malformed or internally inconsistent authoritative registry
poisons the root: recovery reports unavailable and refuses reads that would
authorize a provider, writes, repair-by-reset, and silent record dropping.

### 6. Fail-closed recovery and durability limits

Startup and every post-publication reload validate the root directory, exact
`FORMAT`, lockability, registry size, canonical JSON, generation, ordering,
record bounds, approval IDs, and all approval fields. Only a fully valid
registry is exposed. A missing or unreadable `FORMAT`, missing registry,
truncated replacement, unsupported future format, invalid permissions, failed
lock acquisition, or failed validation leaves the registry unavailable; the
daemon does not synthesize an empty document or infer authority from any
temporary or neighboring file.

On Unix-like systems, durable publication flushes the temporary file, performs
the atomic replacement, and synchronizes the opened root directory entry. On
Windows, publication uses platform-specific handle-relative atomic replacement
and file write-through/flush semantics; Unix directory `fsync` semantics are
not claimed for a Windows directory. The result reports that platform limit
explicitly. A failed file flush or replacement is not a commit. If a platform
reports directory-entry durability as best effort or the result is indeterminate
after replacement, the previous/current valid document remains the only
usable authority and the next recovery must revalidate it; a post-crash missing
or malformed registry fails closed rather than recreating identity.

No filesystem contract promises power-loss durability beyond the guarantees
the platform and filesystem actually provide. The storage API must not label a
best-effort Windows directory-entry result as Unix-equivalent durability.

## Relationship to ADR 0007

`provider_data_root` remains the sole durable approval authority. The
provider-runtime design in ADR 0007 introduces a separate future
`provider_cache_root` for bounded materialized adapter launch artifacts; it
must never be a child or replacement of this registry root. A cache entry is
usable only after revalidation against the opaque source proof, the exact
approval record, and its `approval_id`. The cache stores no approval authority,
credentials, OAuth state, or arbitrary caller-selected executable. This ADR
does not authorize cache creation, materialization, provider launch, or CLI
execution. Any future daemon-owned OAuth/token lifecycle associated with this
storage remains limited to V2 `host_secret`; `official_cli_session` is external
CLI-owned and its vendor session is never stored in this registry or cache.

## Consequences and phase boundary

The registry gives the daemon one inspectable, bounded, atomically published
record of explicit source approval. Exact approval IDs prevent changed source
identity or capabilities from inheriting an old record, while strict recovery
prevents corruption from becoming an empty or weakened approval set. The
tradeoff is that a damaged root is intentionally unavailable until an explicit
operator recovery/migration decision; automatic repair is not authority.

This ADR does **not** implement Git network transport, clone/fetch, ref
resolution, source materialization, executable launch, process supervision,
credential storage or delivery, OAuth state/exchange/callback/token handling,
the provider host/broker, daemon install or provider routes, SDK/client models,
or TUI surfaces. It does not add a registry API, an install UI, a package
cache, or an untrusted/sandboxed provider mode. Those remain separate decisions
after this storage-only contract.
