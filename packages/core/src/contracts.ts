export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue }
export type AggregateRoot = "session" | "work-run"
export type SemanticVersion = 1
import { immutableCopy } from "./immutability.js"
export { deepFreeze, immutableBatch, immutableCopy, immutableHistory } from "./immutability.js"
export interface SemanticClock {
  readonly now: () => string
}
export interface SemanticIdFactory {
  readonly next: (kind: string) => string
}

export interface SemanticSeams {
  readonly clock: SemanticClock
  readonly ids: SemanticIdFactory
}

export interface CommandEnvelope<Root extends AggregateRoot, Command> {
  readonly schema: "gorce.s2.command/v1"
  readonly version: SemanticVersion
  readonly command_id: string
  readonly root: Root
  readonly aggregate_id: string
  readonly expected_version: number
  readonly issued_at: string
  readonly command: Command
}

export const assertVersionedEnvelope = (
  schema: string,
  version: number,
  expectedSchema: string,
): void => {
  if (schema !== expectedSchema || version !== 1) throw new Error("S2_ENVELOPE_VERSION")
}

export interface EventEnvelope<Root extends AggregateRoot, Event> {
  readonly schema: "gorce.s2.event/v1"
  readonly version: SemanticVersion
  readonly event_id: string
  readonly root: Root
  readonly aggregate_id: string
  readonly revision: number
  readonly occurred_at: string
  readonly event: Event
}

export interface EffectEnvelope {
  readonly schema: "gorce.s2.effect/v1"
  readonly version: SemanticVersion
  readonly effect_id: string
  readonly root: "work-run"
  readonly session_id: string
  readonly work_run_id: string
  readonly target_authority: string
  readonly target_id: string
  readonly target_version: number
  readonly execution_ref: string
  readonly stream_generation: number
  readonly input_digest: string
  readonly contract_digest: string
  readonly route_digest: string
  readonly workspace_id: string
  readonly workspace_revision: number
  readonly kind: string
  readonly payload: JsonValue
  readonly requested_at: string
}

export interface EffectConfirmed {
  readonly status: "confirmed"
  readonly value: JsonValue
}

export interface EffectFailed {
  readonly status: "failed"
  readonly reason: string
}

export type EffectRejected = EffectFailed

export interface EffectUnknown {
  readonly status: "unknown"
  readonly reason: string
}

export type EffectOutcome = EffectConfirmed | EffectFailed | EffectUnknown

export interface ResultAffinity {
  readonly session_id: string
  readonly work_run_id: string
  readonly effect_id: string
  readonly target_authority: string
  readonly target_id: string
  readonly target_version: number
  readonly execution_ref: string
  readonly stream_generation: number
  readonly input_digest: string
  readonly contract_digest: string
  readonly route_digest: string
  readonly workspace_id: string
  readonly workspace_revision: number
}

export interface EffectResultEnvelope {
  readonly schema: "gorce.s2.result/v1"
  readonly version: SemanticVersion
  readonly result_id: string
  readonly root: "work-run"
  readonly session_id: string
  readonly work_run_id: string
  readonly effect_id: string
  readonly target_authority: string
  readonly target_id: string
  readonly target_version: number
  readonly execution_ref: string
  readonly stream_generation: number
  readonly input_digest: string
  readonly contract_digest: string
  readonly route_digest: string
  readonly workspace_id: string
  readonly workspace_revision: number
  readonly completed_at: string
  readonly outcome: EffectOutcome
}

export type AffinityValidation =
  | {
      readonly ok: true
    }
  | {
      readonly ok: false
      readonly errors: readonly string[]
    }

export const resultAffinityFields = [
  "session_id",
  "work_run_id",
  "effect_id",
  "target_authority",
  "target_id",
  "target_version",
  "execution_ref",
  "stream_generation",
  "input_digest",
  "contract_digest",
  "route_digest",
  "workspace_id",
  "workspace_revision",
] as const

export type ResultAffinityField = (typeof resultAffinityFields)[number]

export const validateResultAffinity = (
  result: ResultAffinity,
  expected: ResultAffinity,
): AffinityValidation => {
  const errors: string[] = []
  for (const field of resultAffinityFields)
    if (result[field] !== expected[field]) errors.push(`${field} mismatch`)
  return errors.length === 0 ? { ok: true } : { ok: false, errors }
}

export const assertResultAffinity = (result: ResultAffinity, expected: ResultAffinity): void => {
  const validation = validateResultAffinity(result, expected)
  if (!validation.ok) throw new Error(`S2_RESULT_AFFINITY: ${validation.errors.join(", ")}`)
}

export const deterministicSeams = (
  timestamps: readonly string[],
  ids: readonly string[],
): SemanticSeams => {
  let timestampIndex = 0
  let idIndex = 0
  return {
    clock: {
      now: () => {
        const value = timestamps[timestampIndex]
        if (value === undefined) throw new Error("S2_CLOCK_EXHAUSTED")
        timestampIndex += 1
        return value
      },
    },
    ids: {
      next: (_kind: string) => {
        const value = ids[idIndex]
        if (value === undefined) throw new Error("S2_ID_FACTORY_EXHAUSTED")
        idIndex += 1
        return value
      },
    },
  }
}

export const createCommandEnvelope = <Root extends AggregateRoot, Command>(
  seams: SemanticSeams,
  root: Root,
  aggregateId: string,
  expectedVersion: number,
  command: Command,
): CommandEnvelope<Root, Command> =>
  immutableCopy({
    schema: "gorce.s2.command/v1",
    version: 1,
    command_id: seams.ids.next("command"),
    root,
    aggregate_id: aggregateId,
    expected_version: expectedVersion,
    issued_at: seams.clock.now(),
    command,
  })

export const createEffectEnvelope = (
  seams: SemanticSeams,
  affinity: ResultAffinity,
  kind: string,
  payload: JsonValue,
): EffectEnvelope =>
  immutableCopy({
    schema: "gorce.s2.effect/v1",
    version: 1,
    ...affinity,
    root: "work-run",
    kind,
    payload,
    requested_at: seams.clock.now(),
  })

export const createEffectResultEnvelope = (
  seams: SemanticSeams,
  affinity: ResultAffinity,
  outcome: EffectOutcome,
): EffectResultEnvelope =>
  immutableCopy({
    schema: "gorce.s2.result/v1",
    version: 1,
    result_id: seams.ids.next("result"),
    root: "work-run",
    ...affinity,
    completed_at: seams.clock.now(),
    outcome,
  })
