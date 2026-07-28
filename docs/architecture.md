# Architecture

Gorce is a local-first system with explicit boundaries between the daemon,
agent, storage, protocol, provider, and client layers. The Phase 1 provider
implementation supplies contracts and pure policy, and the narrow Phase 2
provider-source proof supplies resolver-snapshot verification. Provider daemon
runtime integration remains deferred.

## Boundaries

- `gorce-protocol` owns daemon-client wire types and identifiers.
- `gorce-provider-abi` owns the separately versioned `gorce.provider/v1`
  package, manifest, JSON-RPC, schema, signing, and invocation types.
- `gorce-core` owns provider approval, capability, lifecycle, and authorized
  invocation lease policy independent of I/O.
- `gorce-store` owns filesystem layout, persistence, and recovery contracts.
- `gorce-agent` owns coordination between domain operations and storage.
- `gorce-daemon` owns process lifecycle and the daemon API boundary.
- `gorce-sdk` owns client-facing API access without daemon internals.
- `gorce-tui` owns terminal presentation and user interaction.
- `gorce` is the user-facing executable and composition root.

Dependencies point toward stable foundations. Provider ABI and domain policy do
not depend on daemon, SDK, TUI, or CLI implementation details.

## Community-provider boundary

Phase 1 establishes the canonical provider ABI, pure provider policy, manifest
and schema examples, deterministic mock conformance, and normative docs. The
narrow Phase 2 source-proof slice frozen in ADR 0005 verifies one resolver-owned
snapshot. A future installed provider will cross the still-planned runtime
boundary:

```text
explicit Git source pin and approval -> daemon-global provider_data_root registry -> future package host/broker -> provider process
```

The package host/broker is planned and is not present in this repository. The
implemented source proof accepts only an unsigned `PinnedGitSource`: a
canonical HTTPS Git URL, a full lower-case immutable commit, its `sha1` or
`sha256` hash algorithm, and a resolver-declared source content digest. Moving
refs, direct HTTPS archive URLs, local filesystem paths, publisher/official
signatures, and marketplace listings are not source authority. The proof does
not perform Git network transport or resolve a ref; it consumes one
`ResolverOwnedGitSnapshot` supplied by resolver code.

`verify_provider_source` accepts only the resolver-owned
`ResolverOwnedGitSnapshot`; its fields, resolver constructor, and
`ResolverSourceEntry` construction/access are sealed to resolver code. The
snapshot separately supplies `manifest_mode`, the Git regular mode for
`manifest.json`; the verifier requires that mode, binds it into the
source-content digest, and
checks the exact source manifest bytes and digest, exact file table,
regular-file Unix modes, safe relative paths, case-fold collisions, per-file
hashes and sizes, and executable path/hash/bytes binding. It returns the
opaque, resolver-owned, verifier-produced `VerifiedProviderSource`, whose
private fields cannot be constructed by downstream crates. The source content
digest uses `sha256:gorce.provider/source-content/v1` over the separate
`manifest.json` path/mode/length/content record and sorted source-file
path/mode/length/content records. Source approval carries the source content
digest plus the full canonical URL/commit/hash-algorithm and
source-content-digest-algorithm identity, and has no publisher fingerprint or
signature.

The source manifest is neutral with respect to publisher and
detached-signature authority, but its source-only package file table declares a
resolver-bound regular Unix `mode` for each file. Those source-only mode fields
are distinct from the strict signed-archive manifest fields: the signed
manifest file table rejects `mode`, while the source verifier extracts and
matches source modes before validating the neutral manifest view. A resolver
entry's mode must match its exact source manifest file-table mode; mode-only
substitutions fail verification and change the content digest. The separate
resolver-supplied `manifest.json` Git mode is also required to be regular and
digest-bound.

`source.schema.json`, `source-manifest.schema.json`, and the shared
`source-fixtures.json` positive, negative, and UTF-8 byte-bound cases execute
across Rust source verification, JSON Schema validation, and Python semantic
contract checks. Provider parity fixtures continue to cross-check the shared
path, URL, and validation semantics. These fixtures are proof evidence, not
Git transport or provider-host implementation.

ADR 0006 freezes the storage-only registry/install-root contract. The daemon
global `provider_data_root` is independent of projects and invocations and has
the fixed `FORMAT`, `LOCK`, and `registry.json` layout. The registry is a
bounded canonical document whose entries are strict source approval records
with content-derived `approval_id` values. It is atomically replaced under the
root lock with generation checks, bounded temporary candidates, poisoning
protection, and fail-closed recovery. Platform file/directory durability
limits are reported explicitly; Windows does not claim Unix directory-fsync
equivalence.

The storage contract now has a narrow runtime implementation in the daemon and
store-writer crates. There is no provider registry API or install route, Git
transport, source materialization, executable launch, process lifecycle,
protected credential persistence, or daemon-owned OAuth in this repository. The
storage root contains approval metadata only; it does not contain a cloned
source tree or executable.

The current Phase 1 `verify_provider_archive(archive_bytes)` implementation
still verifies the bounded signed ZIP, exact manifest bytes, regular-file ZIP
modes, file table, and executable hash. That signed-archive path is retained
only as Phase 1 implementation/conformance regression evidence, not as the
Phase 2 source authority or a current launch path. The archive limit is 16 MiB
with at most 130 entries, and uncompressed archive content is bounded to
268,701,696 bytes. Its strict signed-manifest file fields, publisher/signature
requirement, and rejection of source-only manifest file modes are unchanged.

`VerifiedProviderArchive` is an opaque, verifier-produced `#[non_exhaustive]`
authority artifact: its fields are private, it has no public constructor, and
downstream crates can consume it only through read-only getter views
(`package()`, `manifest()`, `archive_digest()`, `signed_manifest()`,
`signature()`, `executable_path()`, and `executable_bytes()`). Archive paths are
ASCII, printable, forward-slash relative paths. In addition to POSIX traversal,
leading-root, backslash, colon, and Windows-invalid character rejection,
validation rejects drive-relative/absolute paths, UNC and alternate-data-stream
forms, Windows reserved devices including `CON`, `CONIN$`, `CONOUT$`, `PRN`,
`AUX`, `NUL`, `CLOCK$`, `COM1`-`COM9`, and `LPT1`-`LPT9`, trailing-dot/whitespace
components, and case-fold collisions. The manifest and archive reserve
`manifest.json` and `signature.json` case-insensitively; every ZIP entry must be a regular file,
and Unix symlink, directory, and other non-regular modes are rejected before
file binding.

The deterministic mock host exercises the Phase 1 archive views rather than
constructing authority data: it verifies the archive, compares the running
executable with `executable_bytes()`, clones the verified `manifest()`, obtains
the archive digest from the verified package view, writes only the verified
executable bytes to its test path, and then spawns that file. The conformance
test uses the same read-only getters. This bounded test harness is not the
production package host/broker and does not implement Git source transport or
the Phase 2 source proof's future launch path.

The eventual Phase 2 trust boundary is explicit installation of a same-user
package, not sandboxing. A provider would run with the user's authority and
could read accessible user data or copy a delivered credential. Source
immutability does not create an untrusted package mode or a sandbox; that would
require a separate decision and real platform enforcement.

The provider process will speak `gorce.provider/v1` over strict LF-NDJSON, not
`gorce-protocol`. Exactly one `gorce.initialize` request comes first with the
exact `gorce.provider/v1` version range and positive host limits no greater than
the ABI maxima; lower negotiated values remain in force. The only V1 methods are
`gorce.initialize`, `tool.invoke`, `operation.cancel`, and `gorce.shutdown`.
Frames are at most 65,536 bytes including LF, JSON depth is at most 16,
aggregate JSON members at most 256, request IDs are host-generated ASCII
strings at most 64 bytes, and `max_timeout_ms` is at most 120,000. A usable host
ID is retained before parameter validation: invalid parameters return a
correlated `-32602` response, other codec errors return `-32700`, and an
unusable ID terminates rather than receiving a fabricated response. After
initialization, every response—including malformed-frame errors, worker
terminal results/errors, cancellation, timeout, busy, and shutdown responses—
is encoded under the negotiated `HostLimits`; no response falls back to the
ABI maximum.

Runtime tool descriptors and capabilities must exactly match the approved
manifest. Host-derived tool IDs use
`gorce.provider/v1/tool/{package_digest}/{provider_id}/{tool_name}`. For a
signed archive `package_digest` is the archive digest; for the source proof it
is the source content digest. A `tool.invoke` may carry a copyable API-key or
access-token delivery only when the host-authoritative `AuthorizedInvocation`
binds the approved package,
tool, invocation, auth method, credential class, delivery kind, and deadline;
the invocation auth method/class must match the tool's manifest binding, and a
credentialed tool cannot omit delivery. V1 has no credential-redeem method and
never delivers a refresh token.

OAuth declarations are public-client Authorization Code with PKCE S256 only.
Canonical URL parsing, literal HTTPS, explicit canonical origins, callback
restrictions, DNS policy, state, verifier, exchange, refresh, and token
lifecycle are host-owned. OAuth hosts are lower-case canonical DNS labels or
canonical IP literals. IPv4 hosts use exactly four decimal octets in `0..=255`
without leading zeroes. Noncanonical decimal, hexadecimal, octal-like,
short-form, and mixed numeric IPv4 spellings—including bare hexadecimal-prefix
forms such as `0x` and `0X`, case variants such as `0X7F`, and spellings `127`,
`127.1`, `0x7f`, `0177`, and `0x7f.1`—are
rejected. Canonical DNS names, canonical dotted-decimal IPv4 literals, and
canonical IPv6 hosts remain accepted. IPv6 hosts are valid lower-case
hexadecimal bracketed literals without dotted embedded IPv4. Rust, JSON Schema,
and Python use the same rule. Authorities reject percent-encoded or
backslash-normalized text; explicit ports are non-zero decimal u16 values
without leading zeroes, and explicit `:443` is noncanonical while `:80` is
accepted.
Local schemas and runtime metadata are validated for
exact equivalence with the approved manifest; `tool.invoke` input is an object
and Rust/schema/Python validation share that object-only contract. JSON Schema
lengths count Unicode scalar characters; manifest/local-runtime text and
local-schema metadata use character limits, while encoded schemas, ASCII
IDs/paths, property names, secrets, reasons, and errors use explicit UTF-8 byte
bounds. Rust and Python enforce the same local-schema rules for boolean
`additionalProperties`, metadata/property-name C0/C1 controls including
U+0085, and limits,
duplicate/unknown `required` names, unique bounded enums, finite numeric
keywords, and non-inverted bounds. JSON Schema expresses the structural and
character checks where possible; Python adds the byte and cross-field semantic
checks. RPC secret/reason/error `maxLength` values are character prefilters for
Rust's authoritative byte limits. Secret-bearing request/result DTOs and
diagnostics redact raw values. The out-of-process boundary is not a sandbox.

The nullable auth fields are presence-sensitive across the wire. The manifest
tool declaration, initialize-result tool descriptor, and invocation all require
their `auth_method_id`/`credential_class`/`delivery_kind` members to be present;
explicit `null` is valid intentional absence, while omission is malformed. An
uncredentialed invocation carries all three as explicit `null`; a credentialed
invocation carries all three matching values; pure lease policy rejects an
all-null binding for a credential-required tool. Numeric equality uses JSON Schema
mathematical equality, so `1` equals `1.0` for `const`, enum membership and
duplicates, integer classification, and numeric bounds in Rust and Python.
Integer-valued decimal numbers such as `1.0` are accepted for integer schema
keywords and bounds, while fractional values are rejected. Accepted
integer-valued decimal bounds participate in minimum/maximum inversion checks.
Rust-aligned bounds also apply to wire numerics: u64-valued deadlines and
expirations are limited to `0..=18,446,744,073,709,551,615`, i32 error codes to
`-2,147,483,648..=2,147,483,647`, and each version component is an unsigned
decimal u64 value.

The active mock cancellation contract correlates a terminal `-32012` error to
the original invocation request, then correlates the successful cancellation
result to the cancel request. Natural completion correlates its result to the
original request; deadline expiry returns `-32010`, and no-active/mismatched
cancellation returns `-32012`. Pending state clears after each terminal path.
The `abnormal` fixture exits the provider process with status 101 without a
JSON-RPC response. The conformance harness captures stderr, performs a bounded
two-second poll/reap (killing on timeout), and asserts the non-success/no-response
path. An uncorrelatable oversized frame terminates without a fabricated
response. stderr is diagnostics-only and must not contain raw secrets; the
harness checks the abnormal-exit stderr stream for the secret sentinel.
Expired invocations/deliveries are denied; `Expired` is a lease-denial reason,
not a provider lifecycle state. `Revoked` is terminal with direct transitions
from Approved, Starting, Ready, Invoking, Stopping, Stopped, and Failed;
Installed must pass through Approved. Invoking and Stopping retain their drain
paths but may also be revoked directly, and Revoked has no outgoing transition.
Lease issuance is lifecycle-authorized only in Approved, Starting, Ready, and
Invoking; Installed, Stopping, Stopped, Failed, and Revoked are denied. The
pure policy does not perform transitions, process cancellation, or approval
invalidation; that host integration is not implemented here.

## Runtime status and stop lines

The ABI crate, pure core policy, narrow resolver-snapshot source proof, and
storage-only provider registry are implemented. No Git network transport or
resolver, source materialization, executable launch, package host/broker,
provider process supervisor, protected provider credential persistence,
daemon provider/install route, or daemon-owned OAuth exists in this repository.
The provider ABI and source proof do not perform I/O, OAuth exchange,
persistence, or secret storage. The mock conformance harness does perform
bounded test-process reap and stderr capture solely to prove Phase 1
abnormal-exit behavior; that is not a production provider supervisor.

ADR 0005 records the narrow Phase 2 source-proof boundary and ADR 0006 records
the storage-only daemon-global registry boundary. Git transport, source
materialization, executable launch/process lifecycle, credentials/OAuth,
provider host/broker integration, daemon install/provider routes, scoped lease
issuance, and authorization integration remain future work. Phase 3 is the
first phase for authenticated daemon routes, SDK/client models, authoring
surfaces, and public-boundary integration evidence. These stop lines do not
claim a sandbox or an untrusted package mode.

## Compatibility

The provider ABI and daemon protocol are separate public compatibility surfaces.
Changes require an explicit versioning decision, migration or recovery
behavior, and tests. See `api-versioning.md`, `adr/0004-community-provider-abi-v1.md`,
`adr/0005-phase-2-provider-install-and-host.md`,
`adr/0006-phase-2-provider-registry-storage.md`, and `threat-model.md`.
