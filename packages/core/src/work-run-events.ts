import type { EffectEnvelope, ResultAffinity } from "./contracts.js"
import { assertResultAffinity, assertVersionedEnvelope, immutableCopy } from "./contracts.js"
import type { WorkRunEffect, WorkRunEventEnvelope, WorkRunState } from "./work-run.js"

export const findEffect = (state: WorkRunState, effectId: string): WorkRunEffect | undefined =>
  state.effects.find((entry) => entry.effect.effect_id === effectId)

export const effectAffinity = (effect: EffectEnvelope): ResultAffinity => ({ ...effect })

const freezeState = (state: WorkRunState): WorkRunState => immutableCopy(state)

export const transitionError = (status: WorkRunEffect["status"], action: string): string =>
  `S2_EFFECT_TRANSITION_${status.toUpperCase()}_${action.toUpperCase()}`

export const validateEffectAuthority = (state: WorkRunState, effect: EffectEnvelope): void => {
  assertVersionedEnvelope(effect.schema, effect.version, "gorce.s2.effect/v1")
  if (
    effect.root !== "work-run" ||
    effect.session_id !== state.session_id ||
    effect.work_run_id !== state.work_run_id ||
    findEffect(state, effect.effect_id) !== undefined
  )
    throw new Error("S2_EFFECT_AUTHORITY")
}

const updateEffect = (
  state: WorkRunState,
  effectId: string,
  update: (effect: WorkRunEffect) => WorkRunEffect,
): WorkRunState =>
  freezeState({
    ...state,
    effects: state.effects.map((effect) =>
      effect.effect.effect_id === effectId ? immutableCopy(update(effect)) : effect,
    ),
  })

export const applyWorkRunEvent = (
  state: WorkRunState,
  envelope: WorkRunEventEnvelope,
): WorkRunState => {
  assertVersionedEnvelope(envelope.schema, envelope.version, "gorce.s2.event/v1")
  if (envelope.root !== "work-run") throw new Error("S2_WORK_RUN_ROOT")
  if (envelope.aggregate_id !== state.work_run_id) throw new Error("S2_WORK_RUN_AUTHORITY")
  if (envelope.revision !== state.version + 1) throw new Error("S2_WORK_RUN_REVISION")
  const event = envelope.event
  if (event.type === "work-run.started") {
    if (
      state.status !== "new" ||
      (state.session_id !== "" && state.session_id !== event.session_id)
    )
      throw new Error("S2_WORK_RUN_START_TRANSITION")
    return freezeState({
      ...state,
      version: envelope.revision,
      status: "running",
      session_id: event.session_id,
    })
  }
  if (event.type === "work-run.completed") {
    if (state.status !== "running") throw new Error("S2_WORK_RUN_COMPLETE_TRANSITION")
    return freezeState({ ...state, version: envelope.revision, status: "completed" })
  }
  if (event.type === "work-run.failed") {
    if (state.status !== "running") throw new Error("S2_WORK_RUN_FAIL_TRANSITION")
    return freezeState({ ...state, version: envelope.revision, status: "failed" })
  }
  if (event.type === "work-run.effect-planned") {
    if (state.status !== "running") throw new Error("S2_EFFECT_PLAN_TRANSITION")
    validateEffectAuthority(state, event.effect)
    return freezeState({
      ...state,
      version: envelope.revision,
      effects: [...state.effects, { effect: event.effect, status: "planned", attempts: 0 }],
    })
  }
  const eventEffectId =
    event.type === "work-run.effect-resolved"
      ? event.result.effect_id
      : "effect_id" in event
        ? event.effect_id
        : ""
  const current = findEffect(state, eventEffectId)
  if (event.type === "work-run.effect-attempted") {
    if (current === undefined || current.status !== "planned")
      throw new Error(current ? transitionError(current.status, "attempt") : "S2_EFFECT_NOT_FOUND")
    if (current.effect.execution_ref !== event.execution_ref)
      throw new Error("S2_EFFECT_EXECUTION_REF")
    return updateEffect({ ...state, version: envelope.revision }, event.effect_id, (effect) => ({
      ...effect,
      status: "attempted",
      attempts: effect.attempts + 1,
    }))
  }
  if (event.type === "work-run.effect-resolved") {
    assertVersionedEnvelope(event.result.schema, event.result.version, "gorce.s2.result/v1")
    if (current === undefined || current.status !== "attempted")
      throw new Error(current ? transitionError(current.status, "resolve") : "S2_EFFECT_NOT_FOUND")
    assertResultAffinity(event.result, effectAffinity(current.effect))
    return updateEffect(
      { ...state, version: envelope.revision },
      event.result.effect_id,
      (effect) => ({
        ...effect,
        status: event.result.outcome.status,
        outcome: event.result.outcome,
      }),
    )
  }
  if (current === undefined) throw new Error("S2_EFFECT_NOT_FOUND")
  if (event.type === "work-run.effect-reconciled") {
    if (current.status !== "confirmed" && current.status !== "unknown")
      throw new Error(transitionError(current.status, "reconcile"))
    return updateEffect({ ...state, version: envelope.revision }, event.effect_id, (effect) => ({
      ...effect,
      status: "reconciled",
      resolution_reason: event.reason,
    }))
  }
  if (current.status !== "failed" && current.status !== "unknown")
    throw new Error(transitionError(current.status, "compensate"))
  return updateEffect({ ...state, version: envelope.revision }, event.effect_id, (effect) => ({
    ...effect,
    status: "compensated",
    resolution_reason: event.reason,
  }))
}
