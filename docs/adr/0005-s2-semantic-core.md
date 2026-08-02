# ADR 0005: S2 semantic core authority

## Status

Accepted for the Core Preview S2 phase.

## Decision

`@gorce-ai/core` is the sole S2 semantic authority. Session and WorkRun are
independent aggregate roots. Commands carry an expected version, reducers
emit either one versioned event or a fail-closed zero-event result, and replay
accepts only the correct root with contiguous revisions.

Effects have one legal lifecycle:

```text
planned -> attempted -> confirmed | failed | unknown -> reconciled | compensated
```

`unknown` represents dispatched-but-unconfirmed work. Every result independently
matches 13 affinity fields: `session_id`, `work_run_id`, `effect_id`,
`target_authority`, `target_id`, `target_version`, `execution_ref`,
`stream_generation`, `input_digest`, `contract_digest`, `route_digest`,
`workspace_id`, and `workspace_revision`. Clock and identifier seams are
injectable so semantic-law tests and mutation runs are deterministic.

## Scope boundary

S2 semantic core exists and is source-bound/evidence-gated, but this phase does
not claim S3 durable storage/recovery/fsync/CAS, S4 UI/TUI/terminal behavior,
providers, transports, plugins, or release qualification. S1 schemas, receipts,
and the historical `NOT_APPLICABLE` mutation record remain preserved evidence;
the active mutation gate targets both Session/WorkRun reducers and direct
affinity validation.
