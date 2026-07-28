# ADR 0007: Phase 0 provider runtime and official CLI adapters

- Status: User-approved architectural boundary; Phase 0 Oracle documentation
  gate pending
- Date: 2026-07-28
- Scope: Provider-runtime boundaries, official CLI adapter policy, and phase
  stop lines only

## Context

ADR 0004 freezes the `gorce.provider/v1` ABI, ADR 0005 freezes the pinned-Git
source proof, and ADR 0006 freezes the daemon-global approval registry. Codex
and Claude Code are not new vendor providers owned by Gorce. They are possible
Gorce adapter packages which may invoke the user's separately installed
official CLIs after later approval gates.

The user approved the Phase 0 architectural boundary only. The Phase 0 slice is
documentation only and still requires the Oracle documentation gate. Concrete
catalog pins, supported version ranges, command policies, cache/platform
choices, diagnostic limits, and warning copy are deliberately not approved by
this ADR. It must prevent a runtime implementation from accidentally adding
vendor OAuth, token handling, broad provider execution, cache authority, or a
sandbox claim before those decisions are separately reviewed.

## Decision

### 1. V1 remains frozen; V2 uses tagged authentication

`gorce.provider/v1` is frozen. This ADR does not reinterpret its nullable
authentication fields, add an official-CLI auth method to V1, or change its
wire methods, approval tuple, secret-delivery rules, or schema contracts.

A future separately versioned V2 may replace ambiguous nullable combinations
with one explicit tagged authentication binding:

```text
none
host_secret
official_cli_session
```

The tags are a V2 concept, not an implemented V2 schema. `none` carries no
credential. `host_secret` is a future host-mediated secret contract and is not
a vendor OAuth or token-parsing path. `official_cli_session` names a future
closed host CLI policy; it has no credential class, delivery kind, or
secret-delivery field. A V2 implementation must reject unknown tags and must
not silently translate a V1 field combination into an official CLI session.

Gorce does not own Codex or Claude Code OAuth, access tokens, refresh tokens,
credential files, profile contents, token injection, vendor HTTP/API calls,
token refresh, or vendor credential parsing. The official CLI owns its login,
session storage, refresh, and logout behavior. Gorce may later invoke an
official CLI as the same operator, but it must not read, copy, seed, inspect,
or delete the CLI's credential material. `codex login`, `claude auth login`,
`claude setup-token`, and environment-provided vendor OAuth tokens are
prohibited until the later gates in this ADR are complete.

### 2. Adapter identity, trust, and authority

The package identity is a Gorce adapter identity, not an official vendor
provider identity. A Codex or Claude adapter may declare that it invokes the
corresponding official CLI, but it must not claim vendor publication,
vendor-signature authority, vendor OAuth authority, or an official provider
ABI identity. The official CLI remains an external same-user executable.

The only future authority chain is:

```text
PinnedGit source proof
  -> opaque VerifiedProviderSource
  -> ProviderApprovalTuple / durable approval_id in provider_data_root
  -> revalidated materialized adapter bytes in provider_cache_root
  -> daemon-private one-shot adapter host
  -> later-approved closed CLI policy and external CLI process
```

Every arrow is an authority check, not a caller-supplied path or manifest
field. A cache path, executable path, CLI name, or policy name supplied by a
client cannot replace the opaque proof, durable approval, or revalidation
step. `provider_data_root` from ADR 0006 remains the durable approval registry;
`provider_cache_root` is a separate daemon-private root for future bounded
materialized launch artifacts. Cache contents are not approval authority and
must be revalidated against the approved source/bundle and approval ID before
launch. Phase 0 does not create either cache contents or a launch path.

The intended source input is a later closed catalog of pinned Git binary
bundles, not an arbitrary source build. The catalog membership, concrete pins,
bundle-to-adapter mapping, and any publisher/authenticity treatment are
deferred to the closed-setup human gate. The bundle is unsigned with respect
to publisher authenticity unless a later decision adds that authority. Its
source proof, exact content identity, human approval, and future cache
revalidation are required before an adapter can be materialized. A human must
approve the source/bundle, adapter policy, and intended diagnostic use;
approval is never inferred from installation, availability, or a manifest
field.

### 3. Trusted same-user boundary

An adapter and the official CLI run as the operator's same-user code. This is
trusted-after-explicit-consent, not sandboxing. The process may access files,
network authority, and CLI credentials already accessible to that operator even
when Gorce never reads those credentials. Gorce's non-reading policy is a
handling boundary, not a security boundary.

Every future consent surface must state plainly that the adapter can act as the
operator and may access same-user files and credentials. No document in this
ADR may describe an adapter, official CLI, process boundary, cache, or
redaction layer as an untrusted-provider sandbox.

### 4. One-shot diagnostic-only hosting

The first host is one adapter process per diagnostic request. It must use a
daemon-private process boundary with process-tree containment/reaping,
bounded lifetime, cancellation/timeout handling, and output capture. The
platform mechanisms, containment assumptions, and exact limits are deferred
to the one-shot-host human gate. It does not pool providers, retain an
asynchronous session, or make cancellation a reason to add session pooling.

The process is diagnostic-only. Its input is a later-fixed policy-defined
connection test, not an arbitrary user prompt, tool invocation, repository
command, or provider session. Its stdout/stderr are bounded and redacted before
any daemon projection; exit status is authoritative for failure, malformed
output is not success, and raw CLI output, prompts, arguments, environment values, and
credential material are never exposed as public authority. The diagnostic
policy must later fix its prompt/input, time, output, turns, and any
vendor-spend bounds before launch; Phase 0 approves no concrete budget or
prompt.

General provider execution is disabled. No public or daemon-client operation
may invoke an arbitrary adapter, arbitrary CLI arguments, arbitrary working
directory, arbitrary repository, or arbitrary tool until a separate admissions
redesign defines principals, consent, capabilities, leases, budgets,
redaction, cancellation, and recovery. A diagnostic result is bounded data,
not a provider result authority and not an execution admission.

### 5. Closed CLI policies

Each official CLI must eventually have a named, versioned, closed host policy.
The policy must fix the supported executable/version allowlist, executable
verification, exact argv, environment allowlist and ambient-secret scrubbing,
isolated working directory, allowed output mode, timeout/turn/spend bounds,
cancellation and authentication-failure mapping, and redaction rules.
Client-supplied flags, environment additions, executable paths, profile paths,
and working directories are not policy inputs. None of those concrete values
is frozen by Phase 0; the later fake-CLI policy gate must approve them before a
live diagnostic is considered.

The following are candidate command families, not approved policy values:

- **Codex:** `codex exec --json` is the candidate noninteractive diagnostic
  family. `codex login status` is a candidate coarse status probe and
  `codex logout` is the candidate future logout mechanism; Gorce never edits
  Codex credential files or profiles. Saved official CLI authentication remains
  external and opaque. Exact flags, version range, environment, cwd, parsing,
  and bounds require the later fake-CLI policy gate.
- **Claude Code:** headless `claude -p` is the candidate diagnostic family,
  with structured JSON/JSONL output to be selected later. `claude auth status`
  is a candidate coarse status probe and `claude auth logout` is the candidate
  future logout mechanism. `--bare`, `claude setup-token`, environment OAuth
  tokens, arbitrary flags, and ambient Anthropic/cloud credentials are excluded
  from the first slice. Exact versions, argv, environment, cwd, output mode,
  and bounds require the later fake-CLI policy gate; the subprocess scrub
  setting remains defense in depth, not the primary boundary.

These are policy requirements, not claims that either adapter or CLI
integration exists. Supported versions must be explicitly listed at the later
gate; "latest" is not a supported version policy.

### 6. Closed setup, status, and diagnostic scope

Before a separate public-admission decision, the only future public controls
are:

1. **Setup:** select a later-approved cataloged pinned binary bundle, show its exact source
   identity and trusted-same-user warning, obtain human approval, and later
   materialize only through the opaque authority chain. Setup does not log in.
2. **Status:** report only coarse adapter availability, verified executable
   version, and official CLI authentication presence/status. It does not expose
   profile contents, account tokens, credential paths, or vendor session data.
3. **Diagnostic:** run the later-approved, budgeted one-shot connection test
   under the closed CLI policy and return a bounded, redacted result.

No public general invocation, arbitrary prompt, tool execution, provider
session, raw CLI output, credential view, OAuth flow, or login control is part
of this scope. A later logout control, if admitted, must call the official CLI
logout command and must never delete credential files directly.

### 7. Deferred decisions and signoff record

The following values are deliberately unresolved. This table is normative:
each row requires explicit human signoff and its named evidence gate before the
related implementation phase may begin. The user boundary approval is not
signoff for any value in the table, and no value may be inferred from the
candidate command families above.

| Deferred decision | Later value that must be recorded | Required gate |
| --- | --- | --- |
| Binary-bundle catalog | Exact repository URLs, full pins/digests, allowed adapter/platform bundle mapping, and publisher/unsigned-source treatment | Closed setup and source-approval gate |
| V2 tagged authentication | Exact V2 wire/schema shape, versioning, `host_secret` semantics, and closed `official_cli_session` policy identifiers with forbidden fields | V2 parity and compatibility gate |
| CLI support | Exact Codex/Claude executable identity and supported version ranges | Fake-CLI policy gate |
| Process invocation | Exact argv/flags, environment allowlist/scrubbing, cwd/profile handling, output mode, and auth/error mapping | Fake-CLI policy and one-shot-host gates |
| Cache and containment | `provider_cache_root` layout/permissions, materialization/revalidation rules, platform assumptions, process-tree containment, and reap behavior | Cache/authority and one-shot-host gates |
| Diagnostic contract | Exact prompt/input, time/turn/output/spend limits, cancellation behavior, redaction, and coarse result mapping | Diagnostic policy and supervised-diagnostic gates |
| Consent warning | Exact trusted-same-user warning copy, approval interaction, and status/login/logout presentation | Human consent and designer-reviewed UX gate |
| Public admissions | Principals, capabilities, leases, budgets, recovery, and any general execution API | Separate admissions redesign gate |

The `host_secret` row is the only possible future Gorce-owned OAuth/token
lifecycle path. It must remain absent from `official_cli_session`: that tag
delegates authentication to the external official CLI and never causes Gorce
to parse, store, refresh, or exchange vendor credentials. No row authorizes
operator login by itself.

### 8. Login gate and phase acceptance

No operator login is requested or permitted in Phase 0. Login remains blocked
until all of the following receive separate review and approval:

- the signed-off versioned V2 tagged-auth policy and compatibility evidence;
- sealed source authority, human approval, fail-closed materialization, and
  separate registry/cache-root integrity;
- signed-off platform/process-containment details and daemon-private one-shot
  supervision, timeout, cancellation, and reaping;
- fake-CLI proof for the recorded argv, environment, cwd, output parsing,
  cancellation, authentication failures, bounds, and no-secret behavior;
- bounded/redacted daemon projection and the closed setup/status/diagnostic
  consent UX, including the approved trusted-same-user warning copy; and
- a later admission redesign if any capability beyond fixed diagnostics is
  proposed.

Phase 0 user acceptance covers only the architectural boundary and this
deferred-decision record. The Phase 0 Oracle documentation gate is still
pending. Phase 0 stops before V2 code, CLI process execution, cache
materialization, vendor authentication, public routes, SDK/TUI provider
surfaces, or general execution. A later phase must pass its named signoff gate
and real-execution gate; Phase 0 documentation is not runtime evidence.

## Consequences and stop lines

This ADR preserves V1 compatibility and keeps vendor credentials outside
Gorce's authority. It makes a future adapter reviewable as a closed policy and
keeps diagnostic evidence separate from general execution authority. The cost
is deliberate: no live provider login, broad invocation, or public result
surface can be added by convenience or by reusing nullable V1 fields.

This ADR does **not** implement a V2 ABI, a provider runtime, a CLI adapter, a
cache, source materialization, Git transport, provider launch, process
supervision, credentials, OAuth, login/status routes, SDK/TUI models, or a
general admissions system. It does not make Codex or Claude Code official
Gorce providers and does not create a sandbox. Those are later, separately
approved decisions.
