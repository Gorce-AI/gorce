# ADR 0004: Define the community provider ABI v1 and trust boundary

- Status: Accepted
- Date: 2026-07-28

## Context

Gorce needs an installable provider contract without embedding
provider-specific API code in the daemon. The Phase 1 implementation freezes a
signed package proof, a small local JSON-RPC surface, tool and schema
validation, and host-authorized secret delivery. The provider ABI is a public
contract, but the package host/broker and daemon integration remain later-phase
work.

The canonical ABI identifier is `gorce.provider/v1`. It is independent of the
daemon-client `gorce-protocol` and must not become a second spelling of that
client protocol.

## Decision

### 1. Package proof and approval identity

A provider is distributed as a `.gorce-provider` ZIP archive. The archive is
bounded before extraction:

- archive bytes are at most `MAX_ARCHIVE_BYTES = 16,777,216` (16 MiB);
- it has 1 through `MAX_ARCHIVE_ENTRIES = 130` entries, including the two
  reserved envelope entries;
- every ZIP entry, including `manifest.json` and `signature.json`, must be a
  regular file; directories and every other non-regular Unix entry type are
  rejected;
- each entry is at most `MAX_FILE_SIZE_BYTES = 67,108,864` (64 MiB); and
- total uncompressed payload is at most
  `MAX_ARCHIVE_UNCOMPRESSED_BYTES = 268,701,696` bytes
  (`4 * 67,108,864 + 262,144 + 4,096`).

Paths are safe cross-platform relative paths. They are ASCII, use forward slash
segments only, and reject leading `/`, empty/`.`/`..` segments, NUL/control
bytes, backslash and Windows separators, `:`, and Windows-invalid filename
characters `< > " | ? *`. This rejects drive-relative and drive-absolute forms
such as `C:provider` and `C:/provider`, UNC forms, and alternate-data-stream
forms such as `provider:stream` and `provider::$DATA`. `manifest.json` and
`signature.json` are case-insensitively reserved envelope entries
(`RESERVED_ARCHIVE_ENTRIES = 2`). The manifest file table describes the
remaining archive files and has at most `MAX_FILE_TABLE_ENTRIES = 128` entries;
those two envelope entries cannot be declared in that table. Windows reserved
device components (`CON`, `CONIN$`, `CONOUT$`, `PRN`, `AUX`, `NUL`, `CLOCK$`,
`COM1`-`COM9`, and `LPT1`-`LPT9`), trailing-dot components, and whitespace are
rejected. Manifest
paths and archive entry names use ASCII case-folding for collision detection,
so names that differ only by case are not distinct package files. ZIP entries
must also declare an explicit regular-file Unix mode; missing-mode, symlink,
directory, and other non-regular modes are rejected before file binding.

The host computes `archive_digest` as lower-case SHA-256 over the immutable raw
archive bytes. The digest is not a field in the manifest, so it is not
self-referential. The manifest is retained as exact UTF-8 bytes and is bounded
by `MAX_MANIFEST_BYTES = 262,144` (256 KiB). A detached `signature.json` uses
Ed25519 and signs those exact manifest bytes. The signed manifest contains the
file table (`path`, `size`, `sha256`) and the executable entrypoint (`path`,
`sha256`). The executable entry must appear in the file table with the same
SHA-256. The publisher fingerprint is lower-case SHA-256 of the Ed25519 public
key.

The sole launch-authorizing verifier is `verify_provider_archive(archive_bytes)`.
It reads the manifest, signature, file table, and executable from the same raw
archive bytes; it accepts no split manifest/file/executable inputs and no
caller-supplied digest. `ProviderApprovalTuple::from_verified_archive` derives
approval only from the returned `VerifiedProviderArchive` artifact and checks
that its signed manifest, archive digest, executable path, and executable hash
are internally consistent.

`VerifiedProviderArchive` is an opaque, verifier-produced authority artifact:
its fields are private, it has no public constructor, and it is
`#[non_exhaustive]`, so downstream crates cannot construct it by struct literal.
Consumers receive read-only getter views only:
`package()`, `manifest()`, `archive_digest()`, `signed_manifest()`,
`signature()`, `executable_path()`, and `executable_bytes()`. The complete
package proof is therefore the host-computed archive digest, the detached
Ed25519 signature over the exact manifest bytes, the validated manifest file
table, and the executable bytes extracted from that archive. A process may be
spawned only from the executable whose hash was verified by that proof. Phase 1
conformance verifies the archive first, compares the running mock executable to
the read-only `executable_bytes()` view, and spawns only those verified bytes;
an independent executable and hash input do not establish package identity.

The implemented approval identity is `ProviderApprovalTuple` with these exact
fields:

```text
provider_id
archive_digest
manifest_digest
publisher_fingerprint
executable_sha256
capabilities
```

`manifest_digest` is lower-case SHA-256 of the exact signed manifest bytes.
`capabilities` is the exact `ProviderCapabilitySet` containing:

```text
auth_method_ids
auth_policies
tool_ids
tool_policies
credential_classes
network_origins
side_effects
tool_credentials
```

Approval comparison is exact for every field. A changed archive, manifest,
publisher key, executable, authentication policy, tool policy, origin,
side-effect declaration, credential class, or delivery binding requires new
approval. A valid signature without a matching approval tuple is not launch
authorization.

### 2. Trust model

V1 is **trusted-after-explicit-approval**. The approval policy must state:

> A trusted package executes as the user and can copy a delivered access token
> or API key.

The signed archive, process boundary, approval tuple, scoped delivery, and
schema checks are not malicious-package isolation. A trusted provider can copy
a secret after delivery and can use its user-level process permissions. A
future untrusted mode requires real cross-platform sandboxing and/or a
host-mediated HTTP proxy; it is not implied by this ABI.

### 3. Wire contract and protocol separation

The provider process speaks strict JSON-RPC 2.0 over LF-terminated NDJSON on
local stdin/stdout. The provider runtime contract is `gorce.provider/v1`,
separate from `gorce-protocol`. Neither contract is reused as the other, and
daemon clients do not receive provider-process messages or secrets.

Every frame is exactly one JSON object followed by one LF. Missing LF, CR,
blank lines, multiple frames, malformed JSON, non-object JSON, JSON-RPC
batches, unknown fields, and messages in the wrong sequence are rejected.
stdout is protocol-only. stderr is diagnostics-only and must be secret-safe:
raw request parameters, tool input/output, API keys, access tokens, refresh
tokens, and secret-delivery values must never be written there. The conformance
harness captures the provider's stderr during abnormal operation and verifies
that the secret sentinel is absent. Request and response diagnostics are
separate from the wire
contract and must not expose raw parameters or secret delivery.

The implemented hard limits are:

| Constant | Value |
| --- | ---: |
| `MAX_FRAME_BYTES` / `max_frame_bytes` | 65,536 bytes, including LF |
| `MAX_JSON_DEPTH` / `max_json_depth` | 16 |
| `MAX_JSON_MEMBERS` / `max_members` | 256 aggregate members |
| `MAX_REQUEST_ID_BYTES` / `MAX_ID_BYTES` | 64 bytes |
| `MAX_TOOL_ID_BYTES` | 256 bytes |
| `MAX_TIMEOUT_MS` / `max_timeout_ms` | 120,000 ms |
| `MAX_SECRET_BYTES` | 4,096 bytes |
| `MAX_REASON_BYTES` | 512 bytes |

`HostLimits` carries all four host-enforced limit fields in the initialization
request. Each is positive and no greater than its listed hard limit; lower
positive negotiated values are valid and remain in force. The host chooses and
enforces the values in both directions; the provider cannot raise, renegotiate,
or weaken them. Request IDs are non-empty host-generated ASCII
strings matching `[A-Za-z0-9._:-]+` and are at most 64 bytes. The provider
echoes the ID on a valid request; it does not generate or select request IDs.
If a frame has no usable request ID, the provider does not fabricate a
correlation; the current mock terminates instead of authorizing an operation.

Responses contain exactly one of `result` or `error`, never both or neither.
All request and response objects use `jsonrpc: "2.0"`, a bounded ID, and strict
unknown-field rejection. Secret-bearing DTOs redact their values in `Debug`:
request params, response result/error details, tool input/output, and
`ScopedSecretDelivery.value` never appear raw in diagnostics. Error messages are
non-empty, control-free, and at most 512 bytes.

After successful initialization, every response is encoded and checked with the
same negotiated `HostLimits`, including initialization, correlated malformed
parameter/limit errors, cancellation terminal messages, timeout errors,
abnormal-operation errors, busy errors, and shutdown. A response cannot fall
back to the ABI maximum after the host selects a smaller limit. Before limits
are negotiated, a response uses the hard ABI limits.

For a syntactically valid JSON object with a usable host ID but invalid request
parameters or limits, the provider returns a correlated response with that
same ID: `-32602` for invalid parameters and `-32700` for other codec errors.
Semantically invalid but well-shaped tool/invocation data returns `-32002`,
while a sequence violation returns `-32020`.
An unusable or unrecoverable ID is not fabricated: the provider terminates
without authorizing an uncorrelated operation.

### 4. First request, version, and method set

There is exactly one `gorce.initialize` request, and it is the first request.
Its params are exactly:

```text
version_range: {
  minimum: "gorce.provider/v1",
  maximum: "gorce.provider/v1"
}
limits: {
  max_frame_bytes,
  max_json_depth,
  max_members,
  max_timeout_ms
}
```

V1 accepts only the exact version range above; the provider cannot select a
different ABI version. A successful initialization result contains exactly
`abi_version`, `provider_id`, `package_digest`, `tools`, and `capabilities`.
Its tool descriptors and runtime capability metadata must exactly equal the
approved manifest-derived values, including digest-bound tool IDs, schemas,
side effects, auth method IDs, credential classes, and origins.

The V1 method set is exactly:

- `gorce.initialize` — the one required first request;
- `tool.invoke` — invoke one approved tool;
- `operation.cancel` — cancel an operation; and
- `gorce.shutdown` — request provider shutdown.

There is no credential-redeem method, handle redemption RPC, or
package-controlled credential exchange in V1. Known-method requests before
initialization or duplicate initialization receive the correlated sequence
error `-32020`; successful `gorce.shutdown` ends the mock process.

### 5. Host-derived tools and schema equivalence

The manifest declares a package-local tool `name`, description, input schema,
output schema, side effects, `auth_method_id`, `credential_class`, and network
origins. Those two credential fields are both null for an uncredentialed tool
or both present for a credentialed tool. The package never supplies an
authority-bearing tool ID. The host derives the canonical ID with:

```text
gorce.provider/v1/tool/{archive_digest}/{provider_id}/{tool_name}
```

The digest is the installed archive's 64-character lower-case SHA-256. Provider
and tool identifiers are lower-case ASCII identifiers, each at most 64 bytes;
the complete tool ID is bounded by 256 bytes. A forged, undeclared, or
digest-mismatched tool ID is rejected.

V1 local schemas are JSON objects using only these keywords:
`type`, `title`, `description`, `properties`, `required`, `items`,
`additionalProperties`, `enum`, `const`, `minLength`, `maxLength`, `minimum`,
`maximum`, `minItems`, and `maxItems`. References, combinators, formats,
patterns, remote loading, and runtime metadata are not schema keywords.
The canonical RPC schema requires `tool.invoke.params.input` to be a JSON
object, and Rust validation must enforce that same object-only input contract
before applying the selected local schema. A local schema itself is also an
object; non-object roots and non-object tool inputs are invalid.

Schema and runtime limits are:

| Constant | Value |
| --- | ---: |
| `MAX_SCHEMA_BYTES` | 32,768 bytes |
| `MAX_SCHEMA_DEPTH` | 16 |
| `MAX_SCHEMA_NODES` | 256 |
| `MAX_SCHEMA_PROPERTIES` | 64 |
| `MAX_SCHEMA_ENUM_ITEMS` | 32 |
| `MAX_RUNTIME_STRING_BYTES` (runtime character bound) | 4,096 Unicode scalar characters |
| `MAX_RUNTIME_MEMBERS` | 256 aggregate members |

Property names are non-empty, control-free, and at most 128 UTF-8 bytes.
`title` and `description` metadata are non-empty, control-free, and at most
4,096 Unicode scalar characters. `minLength`/`maxLength` are non-negative
integers bounded by 4,096; `minItems`/`maxItems` are bounded by 256; numeric
keywords must be finite and have non-inverted bounds. `enum` is a unique,
non-empty array of at most 32 values. `required` is an array of at most 64
unique, non-empty names, and every name must be declared in `properties`.
`additionalProperties`, when present, must be boolean; omitted and `true`
permit extra runtime properties, while `false` rejects them. Rust and Python
apply the same rules, including duplicate/unknown `required` names and enum
uniqueness. JSON Schema expresses the keyword types, bounds, counts,
character/control rules (including C0/C1 controls such as U+0085), and boolean
`additionalProperties`; semantic checks
cover the UTF-8 property-name bound, encoded-schema byte bound, duplicate or
unknown required names, and inverted numeric bounds that JSON Schema cannot
state locally. Integer-valued JSON numbers with decimal notation, such as
`1.0`, are accepted for integer-valued schema keywords and bounds; fractional
values such as `1.5` are rejected, and accepted integer-valued decimal bounds
participate in minimum/maximum inversion checks.

The exact length units are deliberate. Archive bytes, exact signed-manifest
bytes, frames, encoded schemas, ASCII identifiers, ASCII paths, property names,
secrets, reasons, and errors use UTF-8 or raw byte limits as applicable.
Manifest user text, local-runtime JSON strings, local-schema text metadata, and
JSON Schema `minLength`/`maxLength` use Unicode scalar-character counts. ASCII
IDs and paths make their character and byte limits equivalent. RPC secret,
reason, and error fields use Rust UTF-8 byte limits (`4,096` or `512`) with
C0/C1 control rejection, including U+0085; their JSON Schema `maxLength` values are character
prefilters, and Python applies the authoritative UTF-8 byte semantic checks.
`MAX_RUNTIME_STRING_BYTES` is the historical name for the 4,096-character
local-runtime bound. Manifest scopes and other general manifest text likewise
use character counts, while ASCII-only URLs make their byte bounds equivalent.

Rust-aligned numeric bounds are explicit: u64-valued deadlines, expirations, and
other u64 fields accept `0..=18,446,744,073,709,551,615`; i32-valued error codes
accept `-2,147,483,648..=2,147,483,647`. Each semantic-version major, minor,
and patch component is an unsigned decimal u64 component, so overflow, signs,
and malformed components are rejected.

The host validates schema keywords and canonical runtime metadata against the
approved manifest. `InitializeResult` requires exact tool-set equality and
exact `RuntimeCapabilities` equality; a missing, extra, or altered declaration
is rejected. Tool input is validated before invocation and `ToolResult.output`
is validated against the approved output schema before publication. A provider
result is data only and cannot mint a daemon action or result evidence. The JSON
Schema fixtures, Rust validators, and Python contract checks are cross-tested
for the same required fields, object roots, local keywords, path/device rules,
length units, controls, uniqueness rules, and cross-field auth/delivery
constraints.

JSON value equality follows JSON Schema numeric equality rather than Rust or
Python representation equality: `1` and `1.0` are the same number. This applies
to `const`, enum membership, enum/`uniqueItems` duplicate detection, integer
classification, and `minimum`/`maximum` comparisons. Rust and Python use the
same canonical numeric comparison, while the JSON Schema validator supplies the
corresponding standard numeric semantics. Thus an integer-valued decimal such
as `1.0` remains valid wherever an integer schema keyword or bound is required,
while a fraction is invalid; integer-valued decimal bounds participate in the
same minimum/maximum inversion checks as integer notation.

### 6. Manifest and authentication validation

The manifest format is exactly `gorce.provider/v1`. It permits only these
authentication method kinds:

1. `api_key`; and
2. `oauth_authorization_code_pkce`.

There may be 1 through 8 authentication methods and 1 through 64 tools. IDs,
credential classes, and capability lists are bounded lower-case ASCII
identifiers; capability lists contain no duplicates and must equal their
declared authentication methods/classes. Each credential class maps to exactly
one authentication method. Identifier and credential-class strings are at most
64 ASCII bytes, general manifest text is at most 512 Unicode scalar characters,
authentication method
and credential-class lists contain at most 8 values, other bounded lists contain
at most 64 values, URLs are ASCII and at most 2,048 characters/bytes, and scopes
are at most 128 Unicode scalar characters. Package paths are at most 256 ASCII
bytes. Side effects are explicit and
non-duplicated: `none`, `network_read`, `network_write`, or `local_write`.

OAuth declarations are public-client Authorization Code with PKCE S256 only:
`client_type` is `public`, `grant_type` is `authorization_code`,
`pkce_method` is `S256`, and `callback` is `host_managed`. Client secrets,
device grants, implicit grants, password grants, discovery documents, custom
callbacks, and package-controlled refresh logic are not V1 fields or flows.

Every OAuth endpoint and declared network origin is parsed as a canonical URL.
Only ASCII, literal `https://` URLs without whitespace, user information,
query, or fragment are accepted. Hostnames are lower-case canonical DNS labels
or canonical IP literals. An IPv4 host is accepted only as exactly four decimal
octets in `0..=255` with no leading zero. Noncanonical decimal, hexadecimal,
octal-like, short-form, and mixed numeric IPv4 spellings—including bare
hexadecimal-prefix forms such as `0x` and `0X`, case variants such as `0X7F`,
and spellings `127`, `127.1`, `0x7f`, `0177`, and `0x7f.1`—are rejected.
Canonical DNS names,
canonical dotted-decimal
IPv4 literals, and canonical IPv6 literals remain accepted. IPv6 literals must
be valid bracketed, lower-case hexadecimal hosts without dotted embedded
IPv4 notation. Rust, the manifest JSON Schema, and Python apply these same
host rules. The authority cannot contain percent-encoded or backslash-normalized
text; explicit ports are non-zero decimal u16 values without leading zeroes,
and explicit `:443` is noncanonical while `:80` is accepted. URL paths use only
`A-Za-z0-9._~!$&'()*+,;=:@%/-`. Origin declarations are canonical origins with
no path, do not
spell the default HTTPS port `:443`, and must exactly match an explicitly
approved canonical origin. OAuth state, verifier, callback,
authorization-code exchange, refresh persistence/execution, token lifecycle,
and origin/DNS policy are host-owned. This ABI only validates declarations; it
does not implement network OAuth exchange or callbacks.

### 7. Authorized invocation and secret delivery

`tool.invoke` carries `ToolInvokeParams`:

```text
invocation: {
  package_digest,
  tool_id,
  invocation_id,
  auth_method_id,
  credential_class,
  delivery_kind,
  deadline_unix_ms
}
input
secret_delivery?
```

`auth_method_id`, `credential_class`, and `delivery_kind` are nullable in the
wire type, but their JSON members are required. An explicit `null` is the
intentional nullable value; an omitted member is malformed and is rejected by
Rust deserialization as well as the schema. For an uncredentialed tool all
three are explicitly `null`; for a credentialed tool all three carry matching
values. The pure policy rejects an all-null binding for a credential-required
tool. The same presence-versus-explicit-null rule applies to the manifest
tool declaration and the initialize-result tool descriptor for
`auth_method_id` and `credential_class`.

`package_digest` is exactly 64 lower-case hexadecimal bytes. `invocation_id`,
`auth_method_id`, and `credential_class` are bounded ASCII IDs of at most 64
bytes; `tool_id` is bounded to 256 bytes. The same 64-byte invocation-ID bound
applies to `operation.cancel`.

The host-authoritative `AuthorizedInvocation` binds the approved archive
digest, digest-bound tool ID, invocation ID, auth method ID, credential class,
delivery kind, and deadline. The core approval and lease policy uses that
binding; no caller-supplied approval boolean authorizes delivery. The archive,
tool, credential, and deadline must match approval and the installed manifest.
For a credentialed tool, the invocation auth method ID must equal the tool's
manifest `auth_method_id`, and that auth method's credential class must equal the
tool and invocation class.

A credentialed tool must receive a matching `secret_delivery`; a tool without a
credential class must not receive any credential fields or delivery. Delivery
kind is exactly `api_key` for API-key auth or `access_token` for OAuth auth.
The delivery contains the matching credential class, a non-empty copyable value
of at most 4,096 bytes with no control characters, and a positive expiry no
later than the invocation deadline. It is carried only in `tool.invoke`, never
contains a refresh token, and cannot be redeemed through another RPC. An
expired invocation deadline, archive/tool/auth/class/kind mismatch, unapproved
tool, or delivery absence is denied.

The pure `gorce-core::provider` policy also requires the invocation deadline to
be in the future and within the host-supplied maximum lifetime, and requires
the exact approved archive and capability binding. It performs no I/O,
process management, OAuth exchange, persistence, or secret storage.

Lease decisions reject `LeaseDenial::Expired` when the invocation deadline is
at or before the supplied host time, or when a delivered secret's expiry is at
or before that time. `Expired` is not a `ProviderLifecycle` state; it is only a
lease-denial reason. The policy also rejects `LeaseDenial::LifetimeTooLong`
when the invocation exceeds the host-supplied maximum lifetime, and rejects
scope mismatches for the archive, tool, auth method, credential class, delivery
kind, or delivery deadline. Expired delivery may not issue a lease.

The lifecycle transition table makes `Revoked` terminal. Direct transitions to
`Revoked` exist from `Approved`, `Starting`, `Ready`, `Invoking`, `Stopping`,
`Stopped`, and `Failed`; `Installed` must first transition to `Approved`.
`Invoking` and `Stopping` retain their normal drain paths, but may also be
revoked directly. `Revoked` has no outgoing transition. Lease issuance is
lifecycle-authorized only: `decide_lease` permits `Approved`, `Starting`,
`Ready`, and `Invoking`, denies `Installed`, `Stopping`, `Stopped`, and `Failed`,
and explicitly denies `Revoked`. It does not transition state, cancel
processes, or invalidate approvals. The future host/broker must perform those
lifecycle actions and discard the approval tuple on revocation; that
integration is outside this Phase 1 implementation.

### 8. Cancellation, deadlines, and process failure

`deadline_unix_ms` is an absolute deadline. A provider rejects an expired
invocation with JSON-RPC error code `-32010`. `operation.cancel` carries an
`invocation_id` and an optional reason bounded to 512 bytes. The deterministic
conformance provider keeps a pending invocation active concurrently with the
read loop. Cancellation must match the active invocation ID; a mismatch or no
active invocation returns `-32012`. A matching cancellation sets the flag,
joins the worker, and emits two correlated terminal messages: the original
`tool.invoke` request receives error `-32012`, then the cancel request receives
`{"cancelled":true}`. Pending state is cleared. While it is pending, another
non-cancel operation receives the busy error `-32011`.

Natural pending completion emits a successful `ToolResult` using the original
`tool.invoke` request ID and clears pending state. The host-side timeout limit is
bounded by 120,000 ms; the mock emits error `-32010` with the original request
ID when the deadline expires, then remains usable for a later invocation. The
`abnormal` fixture causes the provider process to exit with status 101 without
emitting a JSON-RPC response. The conformance harness captures stderr, polls
`try_wait` for at most two seconds, kills and reaps on timeout, asserts the
non-success/no-response path, and checks that the secret sentinel is absent.
Oversized or otherwise uncorrelatable frames terminate the mock without a
fabricated response. Phase 1 conformance therefore exercises active cancel,
correlated terminal results, bounded reads, timeout cleanup/reuse, actual
abnormal process exit, bounded reap, and stderr non-disclosure. The package
host that owns production process supervision is Phase 2 work, not a Phase 1
daemon runtime.

## Consequences and phase boundary

The ABI has one canonical version and method vocabulary, bounded framing, exact
runtime declarations, and a package proof that binds the spawned executable to
the signed archive. Host-derived IDs and authoritative invocation binding keep
provider data separate from daemon authority. Redacted diagnostics reduce
accidental disclosure but do not make a trusted package safe from intentional
copying.

Phase 1 owns the separately versioned ABI, pure provider policy, manifest and
schema examples, deterministic mock conformance, and these normative docs. It
does not add the daemon provider registry/routes, package host/broker,
protected credential persistence, network OAuth exchange/callback code,
SDK/TUI surfaces, sandbox claims or an untrusted package mode, model RPC, or
concrete vendor adapters.

Phase 2 is the first phase for the package registry and host/broker,
credential/OAuth state machine, protected persistence, process timeout/kill
policy, scoped lease issuance, and authorization integration. Phase 3 is the
first phase for authenticated daemon routes, SDK/client models, authoring
surfaces, and public-boundary integration evidence. No phase boundary implies
that the trusted-after-approval provider is sandboxed.
