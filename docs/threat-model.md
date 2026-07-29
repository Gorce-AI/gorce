# Threat model

> **Phase 1 status — representation-only V2 lane.** The narrow
> representation-only V2 schema/auth contract is the current Phase 1 V2
> contract. All V1 behavior remains frozen. Existing V1 core policy,
> source/archive verification, and durable authority remain current; only V2
> integration into those systems is deferred. Runtime execution, provider
> runtime, daemon/public APIs,
> cache/materialization, CLI policy/version/argv/env/cwd,
> login/status/diagnostics, budgets, and TUI remain deferred. This lane does
> not provide runtime authorization or execute CLI adapters.

## Assets

- User data in the storage root.
- Daemon-client authorization material.
- `.gorce-provider` archive bytes, archive digest, exact manifest bytes,
  detached signature, publisher fingerprint, file table, and executable hash.
- Resolver-supplied pinned Git source identity, commit hash algorithm and full
  commit, exact neutral source manifest bytes, resolver-supplied `manifest_mode`
  regular Git mode for `manifest.json`, resolver-owned entries and modes, source
  content digest, manifest digest, full source approval identity, and opaque
  `VerifiedProviderSource` proof views.
- Provider API keys, OAuth state/verifiers, access tokens, and refresh tokens.
- Approved provider capability sets, tool schemas, invocation bindings, and
  operation deadlines.
- Daemon-global `provider_data_root`, its fixed `FORMAT` and `LOCK`, canonical
  `registry.json`, generation, strict source approval records, `approval_id`
  values, publication candidates, and durability results.
- Future adapter package identity, closed CLI policy, separate
  `provider_cache_root`, revalidated launch bytes, bounded diagnostics, and
  coarse CLI availability/authentication status. Official CLI credential
  stores and profiles remain vendor-owned opaque assets that Gorce must not
  read.
- Integrity of the storage format and indexes.
- Release artifacts, dependencies, and source supply chain.

## Trust boundaries

- The daemon process and its configured filesystem root.
- Daemon clients and the separate provider-process ABI.
- Package archive/source verification and explicit approval policy.
- The future daemon-owned package host/broker and the provider process it
  launches. This is not a current runtime component.
- Future host-delivered secrets and the trusted provider process that receives
  them.
- The sealed resolver-to-verifier boundary for a Phase 2 pinned Git source
  snapshot, entries, and declared digest; Git transport and source resolution
  are not current runtime components.
- The daemon-global provider registry storage boundary defined by ADR 0006; its
  narrow storage implementation is current, while an install route is not.
- Future source materialization and, only for a later V2 `host_secret` path,
  daemon-owned loopback OAuth state, callback, refresh, and recovery.
- `official_cli_session` is explicitly outside that OAuth boundary: its vendor
  session remains owned and opaque to the external official CLI.
- The future daemon-private adapter-to-official-CLI boundary. The adapter and
  official CLI run as trusted same-user code; this boundary is not a sandbox.
- The future separate provider cache root and its revalidation boundary; cache
  bytes cannot become approval authority.
- Build and release automation.

## Threats

- An unauthorized local or remote daemon client reads or changes data.
- Path traversal, duplicate entries, archive expansion, or symlink-like archive
  behavior escapes the intended package or storage root.
- A changed archive/source snapshot, neutral manifest, source mode, executable,
  capability, tool policy, or schema inherits an old approval.
- A moving Git ref, abbreviated or changed resolved commit, content-digest
  mismatch, substituted manifest/file/executable, unsafe source path, case
  collision, partial materialization, or project-local source path becomes
  launch authority.
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
- An explicitly approved same-user package is mistaken for a sandbox or an
  official/publisher-authenticated package; an unsigned source proof is
  mistaken for publisher authenticity.
- A noncanonical, non-HTTPS, unapproved, or DNS-confused OAuth endpoint or
  origin causes credential disclosure or authorization confusion.
- OAuth state, PKCE verifier, authorization code, access token, refresh token,
  or API key leaks through protocol diagnostics, `Debug`, events, SDK/TUI
  models, logs, or result data.
- A pending operation ignores cancellation, exceeds its deadline, leaves a
  child unreaped, or turns abnormal child exit into a successful result.
- A compromised dependency or release workflow ships malicious code.
- Crash recovery loses, duplicates, or partially publishes a record.
- A caller or provider poisons the registry with a forged approval record,
  mismatched `approval_id`, unknown field, duplicate provider, stale generation,
  or source approval that was not derived from `VerifiedProviderSource`.
- A stale lock, concurrent writer, temporary candidate, partial replacement,
  or platform durability gap loses an approved record or makes an uncommitted
  record appear authoritative.
- V1/V2 authentication confusion treats a V1 nullable binding as an official
  CLI session, or a client supplies an unknown V2 auth tag.
- A Gorce adapter is mistaken for an official vendor provider, or Gorce reads,
  copies, parses, injects, refreshes, or deletes vendor CLI credentials.
- A caller supplies an arbitrary CLI executable, flag, environment, profile,
  repository, working directory, prompt, or session and escapes the closed
  diagnostic policy.
- A cache path or launch byte is trusted without the opaque source-to-approval
  chain, or a pooled process retains a prior diagnostic's authority.
- Operator login occurs before source approval, materialization, supervision,
  fake-CLI, redaction, consent, and admissions gates are complete.

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
content is bounded to 268,701,696 bytes. The Phase 1 archive regression path
verifies raw archive bytes with `verify_provider_archive`, and archive approval
is derived only from its opaque `VerifiedProviderArchive` artifact. Its fields
are private, it is `#[non_exhaustive]`, and downstream crates can only use its
read-only getters (`package()`, `manifest()`, `archive_digest()`,
`signed_manifest()`, `signature()`, `executable_path()`, and
`executable_bytes()`); they cannot forge it by struct literal. The verifier
computes the lower-case SHA-256 archive digest, reads the exact manifest and
detached signature from that archive, verifies the Ed25519 signature and
publisher fingerprint, checks the file table, and exposes the verified
executable bytes through that getter view. The manifest is bounded to 256 KiB
and does not contain the archive digest. This is the current frozen V1
source/archive-verification path, not V2 integration or a provider launch
authority. Its publisher/signature requirement remains mandatory for signed
archives; source manifests use the separate neutral contract and source-bound
modes.

The signed-archive approval record is an exact `ProviderApprovalTuple`:
provider ID, archive digest, manifest digest, publisher fingerprint, executable
SHA-256, and the complete capability set. The capability set includes
authentication policies, digest-bound tool IDs and policies, credential
classes, origins, side effects, and tool credential bindings. A changed member
requires renewed approval; the unsigned source variant omits publisher identity,
uses its source content digest as the package digest, and compares its full
source identity separately.

The narrow Phase 2 source proof in ADR 0005 validates a `PinnedGitSource` with
a canonical ASCII HTTPS Git URL, `sha1` or `sha256` commit hash algorithm, and
a full lower-case immutable commit. This current source/archive verification is
not Git transport, provider hosting, or V2 runtime integration.
Query/fragment/userinfo, encoded or backslash-normalized authorities,
noncanonical hosts/ports, moving refs, abbreviated commits, local paths, and
direct archive URLs are rejected. The proof does not perform Git network
transport, clone/fetch, or ref resolution.

Only resolver code can construct the sealed `ResolverOwnedGitSnapshot`, its
`ResolverSourceEntry` values, its `manifest_mode` Git mode for `manifest.json`,
or the declared source digest. The verifier returns the opaque, resolver-owned,
`#[non_exhaustive]` `VerifiedProviderSource` only after checking that snapshot.
The neutral source manifest has no publisher or detached-signature authority;
its source-only file table does carry per-file modes, while a publisher key is
rejected rather than treated as optional source identity.

Source entries are bounded to 128 files, 64 MiB each, and 256 MiB total. The
separate `manifest.json` envelope entry must have the resolver-supplied regular
Git mode, which is included in the `sha256:gorce.provider/source-content/v1`
digest. Every source entry must be a regular file with an explicit regular
Unix mode. Symlinks, Gitlinks, directories, special entries, unsafe paths,
reserved envelope names, and case-fold collisions are rejected. Per-file path,
size, SHA-256, and source-only mode values must exactly match the source
manifest file table. Those mode fields are not signed-archive manifest fields:
the strict signed archive manifest rejects them. Source-file mode-only
substitutions are rejected and alter the source digest; changing the separate
`manifest.json` Git mode also changes it. The manifest executable path, size,
hash, and bytes must bind to that exact file.

Source approval uses the source content digest as the package/content digest
(the shared `archive_digest` slot), plus provider ID, exact manifest digest,
executable SHA-256, complete capabilities, and the full source identity:
canonical URL, commit hash algorithm, full commit, and source-content digest
algorithm. `publisher_fingerprint` is absent; no publisher or official
signature is verified.

The source schema, neutral source-manifest schema, and shared
`source-fixtures.json` positive, negative, and UTF-8 byte-bound cases execute
across Rust source verification, JSON Schema validation, and Python semantic
contract checks. Provider parity fixtures are additional cross-checks for this
current source contract. They do not provide Git transport or host
implementation.

The source proof is not an installer or host. Provider staging/materialization,
executable launch, process supervision, daemon routes, and OAuth callback,
exchange, and token state are not implemented. The narrow provider registry
storage and recovery boundary is implemented. A future explicitly approved
same-user package remains trusted user code, not a sandbox or an official
publisher package.

ADR 0006 defines the storage-only registry boundary that follows this proof.
The daemon-global `provider_data_root` has only the fixed `FORMAT`, `LOCK`, and
`registry.json` authority files in this slice. The bounded canonical registry
stores strict source approval records and content-derived `approval_id` values;
it stores no source tree, executable, credential, or OAuth state. Every read,
recovery, and mutation uses the root lock and generation check. A complete
same-directory candidate is flushed and atomically replaced, and temporary,
oversized, malformed, mismatched, or duplicate records are never authority.
Missing, truncated, unsupported, or invalid registry state fails closed rather
than becoming an empty registry or being repaired by dropping records. Unix
directory synchronization and Windows write-through/atomic-replacement limits
are reported separately; Windows does not claim Unix directory-fsync
equivalence. This storage contract is a current runtime implementation, but it
does not provide installation, source transport, or provider hosting.

ADR 0007 preserves the user-approved provider-runtime Phase 0 architectural
boundary and its historical stop lines; it is not runtime evidence. The
current Phase 1 lane implements only the representation-only V2 schema/auth
contract. V1 remains frozen. The explicit `none`, `host_secret`, and
`official_cli_session` tags are representation, not runtime authorization or
credential delivery. The official-CLI tag names a deferred closed host policy
and has no credential class or secret delivery. Gorce must not own vendor OAuth,
tokens, refresh, credential parsing, files, or profiles. Codex and Claude Code
remain external official CLIs described for future Gorce adapter packages, not
official vendor providers or current executions.

The future authority chain is opaque verified source -> source approval and
`approval_id` -> separately revalidated `provider_cache_root` bytes ->
daemon-private one-shot adapter host -> later-approved official CLI policy.
Registry and cache roots remain separate. Setup is intended to require a later
closed pinned-Git binary-bundle catalog, exact identity, and human approval; the
concrete pins, bundle mapping, and cache/platform values are not approved in
Phase 0. No arbitrary executable or source build is authority. A
trusted-same-user warning is mandatory because the
adapter/CLI may access same-user files and credentials; the non-reading rule is
not sandboxing.

The only future public scope before a separate admissions redesign is approved
setup/materialization, coarse CLI availability/authentication status, and one
diagnostic connection test under later-approved prompt and budget values. A
single bounded adapter process is contained and reaped per diagnostic; no
pooling, arbitrary prompt/tool/repo, or general execution is admitted. Closed
Codex/Claude policies must later record versions, argv, environment, cwd,
structured output, budgets, redaction, cancellation, and auth-failure mapping
per ADR 0007's normative signoff record; these values are not yet approved.
Claude `--bare`, `claude setup-token`, and
environment OAuth tokens are excluded. Fake-CLI behavior evidence is required.
No operator login is permitted until the later V2, authority, materialization,
platform/process, fake-CLI, diagnostic, redaction, consent, and admissions gates
pass.

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

The host-derived tool ID includes the installed package digest: an archive
digest on the Phase 1 path or a source content digest on the source-proof path.
Each manifest tool binds both an auth method ID and credential class, or binds neither;
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

For a future V2 `host_secret` path only, the host/broker may own OAuth state,
PKCE verifier, callback, exchange, refresh, token lifecycle, canonical URL
parsing, literal HTTPS/origin policy, and DNS policy. `official_cli_session`
never uses this Gorce OAuth path: the external official CLI owns its vendor
session and Gorce does not parse or store it. OAuth host validation is canonical
and shared by Rust, JSON
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
the host-authoritative `AuthorizedInvocation` matches the package digest,
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

The narrow Phase 2 implementation includes resolver-snapshot source-proof
verification and the storage-only approval registry contract. The current Phase
1 V2 scope is representation-only; V2 integration with source/archive
verification, approval/lease policy, and durable authority, plus CLI adapters,
provider cache/materialization, Git network transport, executable
launch/process lifecycle, protected credentials, OAuth exchange/callback/token
state, package host/broker, daemon install or provider routes,
login/status/diagnostics, budgets, SDK/TUI/client surfaces, authoring surfaces,
and integration evidence remain deferred Phase 2/3 boundaries. No operator
login is permitted at this phase. The
trusted-after-approval model is explicitly not a sandbox; an untrusted package
mode requires separate cross-platform sandboxing and/or a host-mediated HTTP
proxy review.
