import type {
  CommandEnvelope,
  EffectEnvelope,
  EffectOutcome,
  EffectResultEnvelope,
  EventEnvelope,
  SemanticSeams,
} from "./contracts.js"
import { immutableBatch, immutableCopy, validateResultAffinity } from "./contracts.js"
import {
  applyWorkRunEvent,
  effectAffinity,
  findEffect,
  transitionError,
  validateEffectAuthority,
} from "./work-run-events.js"

export { applyWorkRunEvent } from "./work-run-events.js"

export type WorkRunStatus = "new" | "running" | "completed" | "failed"
export type EffectState =
  | "planned"
  | "attempted"
  | "confirmed"
  | "failed"
  | "unknown"
  | "reconciled"
  | "compensated"

export interface WorkRunEffect {
  readonly effect: EffectEnvelope
  readonly status: EffectState
  readonly attempts: number
  readonly outcome?: EffectOutcome
  readonly resolution_reason?: string
}
export interface WorkRunState {
  readonly root: "work-run"
  readonly work_run_id: string
  readonly session_id: string
  readonly version: number
  readonly status: WorkRunStatus
  readonly effects: readonly WorkRunEffect[]
}
export type WorkRunCommand =
  | { readonly type: "work-run.start"; readonly session_id: string }
  | { readonly type: "work-run.complete" }
  | { readonly type: "work-run.fail"; readonly reason: string }
  | { readonly type: "work-run.plan-effect"; readonly effect: EffectEnvelope }
  | {
      readonly type: "work-run.attempt-effect"
      readonly effect_id: string
      readonly execution_ref: string
    }
  | { readonly type: "work-run.resolve-effect"; readonly result: EffectResultEnvelope }
  | {
      readonly type: "work-run.reconcile-effect"
      readonly effect_id: string
      readonly reason: string
    }
  | {
      readonly type: "work-run.compensate-effect"
      readonly effect_id: string
      readonly reason: string
    }
export type WorkRunEvent =
  | { readonly type: "work-run.started"; readonly session_id: string }
  | { readonly type: "work-run.completed" }
  | { readonly type: "work-run.failed"; readonly reason: string }
  | { readonly type: "work-run.effect-planned"; readonly effect: EffectEnvelope }
  | {
      readonly type: "work-run.effect-attempted"
      readonly effect_id: string
      readonly execution_ref: string
    }
  | { readonly type: "work-run.effect-resolved"; readonly result: EffectResultEnvelope }
  | {
      readonly type: "work-run.effect-reconciled"
      readonly effect_id: string
      readonly reason: string
    }
  | {
      readonly type: "work-run.effect-compensated"
      readonly effect_id: string
      readonly reason: string
    }
export type WorkRunCommandEnvelope = CommandEnvelope<"work-run", WorkRunCommand>
export type WorkRunEventEnvelope = EventEnvelope<"work-run", WorkRunEvent>
export interface WorkRunDispatchSuccess {
  readonly ok: true
  readonly state: WorkRunState
  readonly events: readonly [WorkRunEventEnvelope]
}
export interface WorkRunDispatchFailure {
  readonly ok: false
  readonly state: WorkRunState
  readonly events: readonly []
  readonly error: string
}
export type WorkRunDispatchResult = WorkRunDispatchSuccess | WorkRunDispatchFailure

export const initialWorkRunState = (workRunId: string, sessionId = ""): WorkRunState =>
  immutableCopy({
    root: "work-run",
    work_run_id: workRunId,
    session_id: sessionId,
    version: 0,
    status: "new",
    effects: [],
  })

const eventEnvelope = (
  state: WorkRunState,
  envelope: WorkRunCommandEnvelope,
  event: WorkRunEvent,
  seams?: SemanticSeams,
): WorkRunEventEnvelope =>
  immutableCopy({
    schema: "gorce.s2.event/v1",
    version: 1,
    event_id: seams?.ids.next("event") ?? `${envelope.command_id}:event`,
    root: "work-run",
    aggregate_id: state.work_run_id,
    revision: state.version + 1,
    occurred_at: envelope.issued_at,
    event,
  })

const failure = (state: WorkRunState, error: string): WorkRunDispatchFailure => ({
  ok: false,
  state,
  events: immutableBatch([] as const),
  error,
})

export const dispatchWorkRun = (
  state: WorkRunState,
  envelope: WorkRunCommandEnvelope,
  seams?: SemanticSeams,
): WorkRunDispatchResult => {
  if (envelope.schema !== "gorce.s2.command/v1" || envelope.version !== 1)
    return failure(state, "S2_COMMAND_ENVELOPE")
  if (envelope.expected_version !== state.version) return failure(state, "S2_EXPECTED_VERSION")
  if (envelope.root !== "work-run" || envelope.aggregate_id !== state.work_run_id)
    return failure(state, "S2_WORK_RUN_AUTHORITY")
  const command = envelope.command
  let error: string | undefined
  const current =
    "effect_id" in command
      ? findEffect(state, command.effect_id)
      : "result" in command
        ? findEffect(state, command.result.effect_id)
        : undefined
  if (command.type === "work-run.start") {
    if (
      state.status !== "new" ||
      (state.session_id !== "" && state.session_id !== command.session_id)
    )
      error = "S2_WORK_RUN_START_TRANSITION"
  } else if (command.type === "work-run.complete") {
    if (state.status !== "running") error = "S2_WORK_RUN_COMPLETE_TRANSITION"
  } else if (command.type === "work-run.fail") {
    if (state.status !== "running") error = "S2_WORK_RUN_FAIL_TRANSITION"
  } else if (command.type === "work-run.plan-effect") {
    if (state.status !== "running") error = "S2_EFFECT_PLAN_TRANSITION"
    else {
      try {
        validateEffectAuthority(state, command.effect)
      } catch (reason: unknown) {
        error = reason instanceof Error ? reason.message : "S2_EFFECT_AUTHORITY"
      }
    }
  } else if (command.type === "work-run.attempt-effect") {
    if (current === undefined) error = "S2_EFFECT_NOT_FOUND"
    else if (current.status !== "planned") error = transitionError(current.status, "attempt")
    else if (current.effect.execution_ref !== command.execution_ref)
      error = "S2_EFFECT_EXECUTION_REF"
  } else if (command.type === "work-run.resolve-effect") {
    if (command.result.schema !== "gorce.s2.result/v1" || command.result.version !== 1)
      error = "S2_RESULT_ENVELOPE"
    else if (current === undefined) error = "S2_EFFECT_NOT_FOUND"
    else if (current.status !== "attempted") error = transitionError(current.status, "resolve")
    else {
      const affinity = validateResultAffinity(command.result, effectAffinity(current.effect))
      if (!affinity.ok) error = `S2_RESULT_AFFINITY: ${affinity.errors.join(", ")}`
    }
  } else if (command.type === "work-run.reconcile-effect") {
    if (current === undefined) error = "S2_EFFECT_NOT_FOUND"
    else if (current.status !== "confirmed" && current.status !== "unknown")
      error = transitionError(current.status, "reconcile")
  } else if (current === undefined) error = "S2_EFFECT_NOT_FOUND"
  else if (current.status !== "failed" && current.status !== "unknown")
    error = transitionError(current.status, "compensate")
  if (error !== undefined) return failure(state, error)
  const event: WorkRunEvent =
    command.type === "work-run.start"
      ? { type: "work-run.started", session_id: command.session_id }
      : command.type === "work-run.complete"
        ? { type: "work-run.completed" }
        : command.type === "work-run.fail"
          ? { type: "work-run.failed", reason: command.reason }
          : command.type === "work-run.plan-effect"
            ? { type: "work-run.effect-planned", effect: command.effect }
            : command.type === "work-run.attempt-effect"
              ? {
                  type: "work-run.effect-attempted",
                  effect_id: command.effect_id,
                  execution_ref: command.execution_ref,
                }
              : command.type === "work-run.resolve-effect"
                ? { type: "work-run.effect-resolved", result: command.result }
                : command.type === "work-run.reconcile-effect"
                  ? {
                      type: "work-run.effect-reconciled",
                      effect_id: command.effect_id,
                      reason: command.reason,
                    }
                  : {
                      type: "work-run.effect-compensated",
                      effect_id: command.effect_id,
                      reason: command.reason,
                    }
  const value = eventEnvelope(state, envelope, event, seams)
  return {
    ok: true,
    state: applyWorkRunEvent(state, value),
    events: immutableBatch([value] as const),
  }
}
