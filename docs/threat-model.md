# Threat model

## Assets

- User data in the storage root.
- Daemon-client authorization material.
- `.gorce-provider` archive bytes, archive digest, exact manifest bytes,
  detached signature, publisher fingerprint, file table, and executable hash.
- Provider API keys, OAuth state/verifiers, access tokens, and refresh tokens.
- Approved provider capability sets, tool schemas, invocation bindings, and
  operation deadlines.
- Integrity of the storage format and indexes.
- Release artifacts, dependencies, and source supply chain.

## Trust boundaries

- The daemon process and its configured filesystem root.
- Daemon clients and the separate provider-process ABI.
- Package archive verification and explicit approval.
- The future daemon-owned package host/broker and the provider process it
  launches. This is planned for Phase 2, not a current runtime component.
- Future host-delivered secrets and the trusted provider process that receives
  them.
- Phase 2 pinned Git source resolution, immutable content digest, and the
  daemon-global provider data root.
- Phase 2 daemon-owned loopback OAuth state, callback, refresh, and recovery.
- Build and release automation.

## Threats

- An unauthorized local or remote daemon client reads or changes data.
- Path traversal, duplicate entries, archive expansion, or symlink-like archive
  behavior escapes the intended package or storage root.
- A changed archive, manifest, publisher, executable, capability, tool policy,
  or schema inherits an old approval.
- A moving Git ref, changed resolved commit, content-digest mismatch, partial
  materialization, or project-local source path becomes launch authority.
- A circular or independently computed archive digest fails to prove that the
  spawned executable belongs to the signed archive.
- An attacker sends oversized, malformed, CR-terminated, unterminated, out of
  sequence, batched, or unknown-field JSON-RPC frames to exhaust resources or
  bypass validation.
- A provider forges a request ID, tool ID, package digest, invocation, auth
  method, credential class, delivery kind, or deadline.
- Runtime tools, capabilities, schemas, side effects, or origins differ from
  the approved manifest.
- A caller-supplied authorization claim or absent/mismatched delivery releases
  a secret to the wrong operation.
- A trusted provider copies or exfiltrates a delivered API key or access token.
- An explicitly installed same-user package is mistaken for a sandbox or an
  official/publisher-authenticated package.
- A noncanonical, non-HTTPS, unapproved, or DNS-confused OAuth endpoint or
  origin causes credential disclosure or authorization confusion.
- OAuth state, PKCE verifier, authorization code, access token, refresh token,
  or API key leaks through protocol diagnostics, `Debug`, events, SDK/TUI
  models, logs, or result data.
- A pending operation ignores cancellation, exceeds its deadline, leaves a
  child unreaped, or turns abnormal child exit into a successful result.
- A compromised dependency or release workflow ships malicious code.
- Crash recovery loses, duplicates, or partially publishes a record.

## Mitigations and gaps

The implemented ABI rejects unsafe relative paths and duplicate archive entries,
directories and every other non-regular ZIP entry, oversized entries, oversized
total payload, and archives over 16 MiB. Cross-platform path confinement
rejects non-ASCII, leading `/`, empty/dot segments, backslashes, colons,
whitespace, trailing-dot components, NUL/control bytes, Windows-invalid
`< > " | ? *` characters, and Windows reserved devices including `CON`,
`CONIN$`, `CONOUT$`, `PRN`, `AUX`, `NUL`, `CLOCK$`, `COM1`-`COM9`, and
`LPT1`-`LPT9`. It therefore covers POSIX traversal, drive, UNC, and
alternate-data-stream forms. Manifest and archive paths collide under ASCII
case-folding; `manifest.json` and `signature.json` are case-insensitively
reserved envelope entries, and every ZIP entry must declare an explicit regular Unix file
mode; missing-mode, symlink, directory, and other non-regular entries are
rejected before file binding. The
archive has at most 130 entries: 128 manifest file-table
entries plus reserved `manifest.json` and `signature.json`. Uncompressed archive
content is bounded to 268,701,696 bytes. The sole launch-authorizing path
verifies raw archive bytes with `verify_provider_archive`, and approval is
derived only from its opaque `VerifiedProviderArchive` artifact. Its fields are
private, it is `#[non_exhaustive]`, and downstream crates can only use its
read-only getters (`package()`, `manifest()`, `archive_digest()`,
`signed_manifest()`, `signature()`, `executable_path()`, and
`executable_bytes()`); they cannot forge it by struct literal. The verifier
computes the lower-case SHA-256 archive digest, reads the exact manifest and
detached signature from that archive, verifies the Ed25519 signature and
publisher fingerprint, checks the file table, and exposes the verified
executable bytes through that getter view. The manifest is bounded to 256 KiB
and does not contain the archive digest.

The approval record is an exact `ProviderApprovalTuple`: provider ID, archive
digest, manifest digest, publisher fingerprint, executable SHA-256, and the
complete capability set. The capability set includes authentication policies,
digest-bound tool IDs and policies, credential classes, origins, side effects,
and tool credential bindings. A changed member requires renewed approval.

The signed-archive controls above describe the current Phase 1 implementation.
The bounded Phase 2 target in ADR 0005 supersedes that launch authority for
provider-install V1: installation must be explicitly requested from a pinned
canonical Git URL, resolved to an immutable full commit and source content
digest. V1 has no publisher or official signature, marketplace, direct HTTPS
archive, or local-path source authority. The daemon stores the immutable record
and verified source snapshot in a durable daemon-global provider data root,
materializes it through staging and an atomic commit, and never launches a
partially materialized source. It starts one fresh provider process per
invocation rather than pooling or reusing processes.

The Phase 2 daemon owns loopback OAuth PKCE, callback/state validation,
authorization-code exchange, refresh-token storage, expiry/revocation handling,
and crash/restart recovery. An explicitly installed same-user package remains
trusted user code, not a sandbox or an official publisher package; process
freshness, source immutability, and OAuth mediation do not provide sandboxing.

The wire boundary is strict `gorce.provider/v1` JSON-RPC 2.0 LF-NDJSON. There
is exactly one first `gorce.initialize` request, followed only by
`tool.invoke`, `operation.cancel`, and `gorce.shutdown`. Host-generated ASCII
IDs are bounded to 64 bytes; frames to 65,536 bytes including LF; JSON depth to
16; aggregate members to 256; and host timeout to 120,000 ms. Initialization
may negotiate any positive values no greater than those maxima, including lower
values, and those values remain enforced afterward. Responses contain
exactly one result or error. Unknown fields, invalid sequencing, CR, batches,
and limit violations fail closed. Every response after initialization is
encoded and checked under the negotiated `HostLimits`, including worker
terminal messages and malformed-frame, cancel, timeout, busy, and shutdown
errors; no response falls back to the ABI maximum.

The host-derived tool ID includes the installed archive digest. Each manifest
tool binds both an auth method ID and credential class, or binds neither;
credential classes map one-to-one to declared auth methods. Initialization
runtime descriptors and capabilities must exactly match the approved manifest;
credential-required tools cannot use an all-null
`auth_method_id`/`credential_class`/`delivery_kind` binding, and pure lease
policy rejects that binding;
`tool.invoke` input is object-only in both the schema and Rust contract, and
tool input/output are validated against bounded local schemas. Rust and Python
enforce the same V1 keyword set, 32 KiB encoded-schema byte bound, depth 16,
256 nodes, 64 properties/required names, 32 unique enum items, boolean-only
`additionalProperties`, non-empty control-free metadata, UTF-8-byte property
names, unique known `required` names, finite numeric keywords, non-inverted
bounds, and C0/C1 control rejection including U+0085. Local runtime strings are
limited to 4,096 Unicode scalar characters
and runtime aggregate JSON members to 256. JSON Schema expresses structural,
character, control, and enum checks where possible; Python semantic checks add
the byte and cross-field rules that JSON Schema cannot express. Manifest text,
local-schema metadata, and schema `minLength`/`maxLength` use Unicode scalar
characters. Encoded schemas, ASCII IDs/paths, property names, secrets, reasons,
and errors use explicit UTF-8 byte limits. RPC `maxLength` values for secrets,
reasons, and errors are character prefilters for Rust/Python byte checks. No
remote schema loading or authority-bearing provider result is permitted.

JSON equality uses the JSON Schema mathematical numeric rule: `1` and `1.0`
compare equal for `const`, enum membership, duplicate/`uniqueItems` detection,
integer classification, and numeric bounds. The Rust and Python semantic
validators use the same canonical comparison as the JSON Schema contract.
Integer-valued decimal numbers such as `1.0` are accepted for integer schema
keywords and bounds; fractional values are rejected. Accepted integer-valued
decimal bounds participate in minimum/maximum inversion checks.
Rust-aligned bounds also apply to wire numerics: u64-valued deadlines and
expirations are limited to `0..=18,446,744,073,709,551,615`, i32 error codes to
`-2,147,483,648..=2,147,483,647`, and each version component is an unsigned
decimal u64 value.

The nullable authentication fields are required members, not optional members:
`auth_method_id`, `credential_class`, and `delivery_kind` must be present in an
invocation, and the first two must be present in manifest and initialize-result
tool declarations. Explicit `null` represents intentional absence; omission is
rejected by Rust deserialization and by the schemas. Uncredentialed invocations
use three explicit `null` values, while credentialed invocations use three
matching non-null values.

The future host/broker owns OAuth state, PKCE verifier, callback, exchange,
refresh, token lifecycle, canonical URL parsing, literal HTTPS/origin policy,
and DNS policy. OAuth host validation is canonical and shared by Rust, JSON
Schema, and Python: lower-case DNS labels or canonical IP literals are allowed;
IPv4 hosts use exactly four decimal octets in `0..=255` without leading zeroes.
Noncanonical decimal, hexadecimal, octal-like, short-form, and mixed numeric
IPv4 spellings—including bare hexadecimal-prefix forms such as `0x` and `0X`,
case variants such as `0X7F`, and spellings `127`, `127.1`, `0x7f`, `0177`, and
`0x7f.1`—are
rejected. Canonical
DNS names, canonical dotted-decimal IPv4 literals, and canonical IPv6 literals
remain accepted. IPv6 must be a valid lower-case hexadecimal bracketed literal
without dotted embedded IPv4. Authorities reject percent-encoded or
backslash-normalized text; explicit ports are non-zero decimal u16 values
without leading zeroes, and explicit `:443` is noncanonical while `:80` is
accepted. It may put an API
key or access token in `tool.invoke` only when
the host-authoritative `AuthorizedInvocation` matches package/archive digest,
digest-bound tool, invocation ID, auth method ID, credential class, delivery
kind, and deadline. Credentialed tools require a matching delivery; uncredentialed
tools reject credential fields. Delivery values are copyable, at most 4,096
bytes, expire no later than the invocation deadline, and never contain a
refresh token. V1 has no credential-redeem method.

Secret-bearing request/response DTOs redact params, results, errors, tool
values, and delivery values in `Debug` and diagnostics. stdout is protocol-only;
stderr is diagnostics-only and must not contain raw credentials, params,
delivery values, or the sentinel secret. The abnormal-operation conformance
path captures stderr and checks that the sentinel is absent. Raw credentials
never cross the daemon-client protocol, public events, SDK/TUI models,
diagnostics, logs, or provider result data. This protects disclosure through
the host's boundaries but cannot stop a trusted package from copying a secret
after it is delivered.

For a usable host ID retained from a syntactically valid frame, invalid params
produce a correlated `-32602` response and other codec failures produce a
correlated `-32700` response. Semantic tool/invocation rejection is `-32002`
and sequence rejection is `-32020`. An unusable ID terminates rather than
receiving a fabricated response. Responses always contain exactly one result or
error, and error messages are non-empty, control-free, and at most 512 bytes.

The ABI and pure `gorce-core::provider` policy validate deadlines, deny expired
invocations and expired deliveries, deny over-lifetime lease requests, enforce
invocation/auth-method/class/delivery binding, and reject mismatched
approval/capability/delivery inputs. `Expired` is a lease-denial reason, not a
provider lifecycle state. `Revoked` is terminal with direct transitions from
Approved, Starting, Ready, Invoking, Stopping, Stopped, and Failed; Installed
reaches it through Approved. Invoking and Stopping drain normally but may also
be revoked directly, and Revoked has no outgoing transition. Lease issuance is
lifecycle-authorized only in Approved, Starting, Ready, and Invoking; Installed,
Stopping, Stopped, Failed, and Revoked are denied. The pure policy does not
transition state, cancel processes, or invalidate the approval tuple; that host
integration is not implemented in Phase 1. The mock
matches cancellation to the active invocation, emits the original request's
terminal `-32012` error followed by the cancel request's correlated success,
returns `-32011` while busy, returns `-32012` for no active/mismatched cancel,
returns `-32010` on deadline. The `abnormal` fixture instead exits the provider
process with status 101 without a JSON-RPC response; it does not synthesize a
`-32013` response. It clears pending state after natural completion or
cancellation and remains usable after timeout. Oversized uncorrelatable frames
terminate without a response. The conformance harness captures stderr, polls
`try_wait` for at most two seconds, kills and reaps on timeout, asserts the
non-success/no-response path, and checks sentinel non-disclosure. This is test
harness supervision; the package host/process supervisor is not implemented
yet.

Phase 1 stops before the registry, package host/broker, protected credential
persistence, network OAuth exchange/callback, daemon provider routes, SDK/TUI
surfaces, authoring surfaces, or integration evidence. Those are Phase 2/3
boundaries. The trusted-after-approval model is explicitly not a sandbox; an
untrusted package mode requires separate cross-platform sandboxing and/or a
host-mediated HTTP proxy review.
