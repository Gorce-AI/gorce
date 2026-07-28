# ADR 0005: Narrow Phase 2 pinned-Git provider source proof

- Status: Accepted; narrow source-proof slice implemented
- Date: 2026-07-28
- Scope: Phase 2 provider source identity and verification only

## Context

Phase 1 freezes `gorce.provider/v1`, pure `gorce-core::provider` approval and
lease policy, the signed `.gorce-provider` archive verifier, schemas, and the
deterministic mock conformance package. Phase 1 deliberately does not provide
provider runtime integration.

The implemented Phase 2 slice defines a bounded proof for an explicitly pinned
Git source. It proves the identity and contents of one snapshot supplied by a
resolver, without treating source proof as a registry, installer, host, or
sandbox. The proof is intentionally unsigned: it does not establish a
publisher or official identity. The source schema, neutral source-manifest
schema, shared source fixtures, and provider parity fixtures are part of the
Rust/Python contract evidence for this boundary.

## Decision

### 1. Pinned Git source identity

`PinnedGitSource` is the only source identity accepted by the Phase 2 proof.
It contains:

```text
canonical_git_url
commit_hash_algorithm       # sha1 or sha256
resolved_commit             # full lower-case commit hash
```

The URL must be an ASCII canonical HTTPS URL identifying a non-root repository
path. It has no user information, query, fragment, encoded authority,
backslash, whitespace, or noncanonical host/port spelling. A commit is exactly
40 lower-case hexadecimal characters for `sha1` or 64 for `sha256`. An
abbreviated commit, branch, tag, moving ref, local path, or direct archive URL
is not an immutable source identity. This validation describes the source
proof input; it does not fetch Git data.

### 2. Resolver-owned snapshot and opaque proof

The resolver owns one `ResolverOwnedGitSnapshot` containing the pinned source,
the resolver-declared source content digest, the exact source manifest bytes,
the resolver-supplied `manifest_mode` Git regular mode for `manifest.json`, and
resolver-owned entries. Its fields are private, its resolver constructor is
crate-private, and
`ResolverSourceEntry` plus its constructors/accessors are crate-private. Only
resolver code can mint the snapshot, entries, manifest mode, or declared digest
supplied to `verify_provider_source`; callers cannot assemble a proof from
independently supplied source parts. No Git clone, fetch, ref resolution, or
network transport is performed by this proof.

`VerifiedProviderSource` is an opaque, resolver-owned, verifier-produced,
`#[non_exhaustive]` authority artifact. Its fields are private and it has no
public constructor; consumers receive read-only views of the source identity,
content digest, manifest bytes/digest, verified files, capabilities, executable
path, and executable bytes. The resolver-owned snapshot is the sole source of those
proof inputs, so a consumer cannot combine independently supplied manifest,
file, executable, or digest values into authority.

### 3. Exact source binding

The proof parses a neutral source manifest with no `publisher` or detached
signature field and validates it with the source-only manifest contract. The
source-only file table carries per-file `mode` fields; these are resolver-bound
source fields and are not fields of the strict signed-archive manifest. The
verifier extracts and matches them to the resolver entries before validating
the neutral manifest view. Its exact UTF-8 bytes receive a SHA-256
`manifest_digest`. The source content digest uses the fixed algorithm
identifier `sha256:gorce.provider/source-content/v1`; it hashes a separate
`manifest.json` record using the resolver-supplied regular Git mode, followed
by all source-file records in sorted path order. Each record binds the path,
Unix mode, byte length, and exact bytes. The resolver-declared digest must equal
the verifier-computed digest.

The source file set is bounded to 128 files, each file to 64 MiB, the total
source payload to 256 MiB, and the manifest to 256 KiB. `manifest.json` is a
separate resolver-supplied envelope record and must have a regular Git/Unix
file mode; that mode is source-content-digest-bound. Every source entry must
also be a regular file with an explicit regular Unix mode. Symlinks, Gitlinks,
directories, special entries, and missing modes are rejected. Paths are safe
ASCII relative paths: no leading root, empty/dot/dot-dot segments, backslash,
colon, controls or non-printable bytes, Windows-invalid characters, trailing
dots, or Windows reserved devices. `manifest.json` and `signature.json` are
reserved, and source paths must be unique under case folding as well as by
exact spelling.

The source-only manifest file table must exactly equal the resolved source file
set. Every source file's path, size, SHA-256, and resolver-bound regular Unix
mode must match its source-only manifest entry. A source-file mode-only change
is therefore both manifest-bound and digest-sensitive; changing the separate
`manifest.json` Git mode likewise changes the source content digest. The
manifest executable path must identify that exact file and its SHA-256 must
match both the file-table entry and the verified executable bytes exposed by
the proof.
The executable is proof data for a future host; this ADR does not launch it.

### 4. Source approval identity and trust

`ProviderApprovalTuple::from_verified_source` derives approval only from one
`VerifiedProviderSource`. The full source approval identity contains:

```text
provider_id
package_digest / content_digest / archive_digest   # source content digest
manifest_digest
executable_sha256
capabilities
source_identity:
  canonical_git_url
  commit_hash_algorithm
  resolved_commit
  source_content_digest_algorithm
publisher_fingerprint = absent
```

The `archive_digest` and `package_digest()` accessors are compatibility names
for the source content digest; the source proof is not an archive. Approval
comparison checks every source identity member as well as the content digest,
manifest, executable, and capability set.

The source variant sets `publisher_fingerprint` to absent. It consumes no
Ed25519 signature, publisher signature, official signature, marketplace
identity, or publisher-authentication claim. Publisher metadata that remains
in the source manifest is impossible: the neutral source contract omits
publisher and signature authority, and the verifier rejects a publisher key if
one is supplied. Changed source content, manifest, mode, executable,
capability, URL, commit, hash algorithm, or source-digest algorithm bindings
require a new proof and approval comparison.

The shared `source-fixtures.json` positive, negative, and multibyte UTF-8
byte-bound cases execute across the three contract layers: Rust's source
verifier, the source JSON Schemas, and Python's semantic contract checks. The
UTF-8 byte-bound case is deliberately beyond a character-count `maxLength`
prefilter; Rust and Python enforce the authoritative 256 KiB byte bound.
Provider parity fixtures keep the surrounding source semantics aligned across
implementations.

This is a trusted-after-explicit-approval model, not sandboxing. Future host
integration may execute an approved same-user package with the user's
authority; the source proof itself does not create a sandbox or make provider
code safe to receive secrets.

## Relationship to Phase 1

`verify_provider_archive` and opaque `VerifiedProviderArchive` remain the
implemented signed-archive verifier and its Phase 1 regression/conformance
path. They retain the signed ZIP, exact manifest, regular-file, file-table, and
executable binding checks needed by those archive tests. The strict signed
manifest file table has no source-only `mode` field, and the signed path still
requires its publisher metadata/signature and rejects such source-only fields;
the source path instead binds per-file modes plus the separate `manifest.json`
Git mode and does neither publisher verification nor detached-signature
verification. That verifier is not
the Phase 2 source authority and is not a current launch path. The Phase 2
source proof is unsigned and uses the resolver-owned snapshot and source
content digest described above.

The separately versioned provider ABI and the pure approval/lease contracts
remain shared foundations. The source proof does not change the ABI wire
methods or add runtime I/O.

## Phase boundary and consequences

This ADR implements only source identity, snapshot verification, opaque proof
views, and source-based approval derivation. It does **not** implement Git
network transport, clone/fetch or ref resolution, a provider registry, daemon
provider persistence or recovery, source materialization, executable launch,
process supervision, daemon routes, or OAuth callback/exchange/token
persistence. It also does not add direct archive or local-path installation,
publisher signing, a marketplace, or a sandbox.

The proof makes the resolver-supplied source identity and exact bytes
auditable, while deliberately making no publisher-authenticity claim. A later
installation/hosting decision must separately define transport trust, durable
storage, atomic materialization, process lifecycle, explicit user approval
surfaces, and daemon-owned OAuth.
