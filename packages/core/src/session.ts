import {
  assertVersionedEnvelope,
  immutableBatch,
  immutableCopy,
  type CommandEnvelope,
  type EventEnvelope,
  type SemanticSeams,
} from "./contracts.js"

export type SessionStatus = "new" | "active" | "closed"

export interface SessionState {
  readonly root: "session"
  readonly session_id: string
  readonly version: number
  readonly status: SessionStatus
  readonly label: string | null
}

export type SessionCommand =
  | { readonly type: "session.start"; readonly label: string }
  | { readonly type: "session.close"; readonly reason: string }

export type SessionEvent =
  | { readonly type: "session.started"; readonly label: string }
  | { readonly type: "session.closed"; readonly reason: string }

export type SessionCommandEnvelope = CommandEnvelope<"session", SessionCommand>
export type SessionEventEnvelope = EventEnvelope<"session", SessionEvent>

export interface SessionDispatchSuccess {
  readonly ok: true
  readonly state: SessionState
  readonly events: readonly [SessionEventEnvelope]
}

export interface SessionDispatchFailure {
  readonly ok: false
  readonly state: SessionState
  readonly events: readonly []
  readonly error: string
}

export type SessionDispatchResult = SessionDispatchSuccess | SessionDispatchFailure

const freezeState = (state: SessionState): SessionState => immutableCopy(state)

export const initialSessionState = (sessionId: string): SessionState =>
  freezeState({
    root: "session",
    session_id: sessionId,
    version: 0,
    status: "new",
    label: null,
  })

const nextEventId = (envelope: SessionCommandEnvelope, seams?: SemanticSeams): string =>
  seams?.ids.next("event") ?? `${envelope.command_id}:event`

const eventEnvelope = (
  state: SessionState,
  envelope: SessionCommandEnvelope,
  event: SessionEvent,
  seams?: SemanticSeams,
): SessionEventEnvelope =>
  immutableCopy({
    schema: "gorce.s2.event/v1",
    version: 1,
    event_id: nextEventId(envelope, seams),
    root: "session",
    aggregate_id: state.session_id,
    revision: state.version + 1,
    occurred_at: envelope.issued_at,
    event,
  })

export const applySessionEvent = (
  state: SessionState,
  envelope: SessionEventEnvelope,
): SessionState => {
  assertVersionedEnvelope(envelope.schema, envelope.version, "gorce.s2.event/v1")
  if (envelope.root !== "session") throw new Error("S2_SESSION_ROOT")
  if (envelope.aggregate_id !== state.session_id) throw new Error("S2_SESSION_AUTHORITY")
  if (envelope.revision !== state.version + 1) throw new Error("S2_SESSION_REVISION")
  if (envelope.event.type === "session.started") {
    if (state.status !== "new") throw new Error("S2_SESSION_START_TRANSITION")
    return freezeState({
      ...state,
      version: envelope.revision,
      status: "active",
      label: envelope.event.label,
    })
  }
  if (state.status !== "active") throw new Error("S2_SESSION_CLOSE_TRANSITION")
  if (envelope.event.type !== "session.closed") throw new Error("S2_SESSION_EVENT")
  return freezeState({ ...state, version: envelope.revision, status: "closed" })
}

export const dispatchSession = (
  state: SessionState,
  envelope: SessionCommandEnvelope,
  seams?: SemanticSeams,
): SessionDispatchResult => {
  if (envelope.schema !== "gorce.s2.command/v1" || envelope.version !== 1)
    return { ok: false, state, events: immutableBatch([] as const), error: "S2_COMMAND_ENVELOPE" }
  if (envelope.expected_version !== state.version)
    return { ok: false, state, events: immutableBatch([] as const), error: "S2_EXPECTED_VERSION" }
  if (envelope.root !== "session" || envelope.aggregate_id !== state.session_id)
    return { ok: false, state, events: immutableBatch([] as const), error: "S2_SESSION_AUTHORITY" }
  if (envelope.command.type === "session.start") {
    if (state.status !== "new")
      return {
        ok: false,
        state,
        events: immutableBatch([] as const),
        error: "S2_SESSION_START_TRANSITION",
      }
  } else if (state.status !== "active") {
    return {
      ok: false,
      state,
      events: immutableBatch([] as const),
      error: "S2_SESSION_CLOSE_TRANSITION",
    }
  }
  const event: SessionEvent =
    envelope.command.type === "session.start"
      ? { type: "session.started", label: envelope.command.label }
      : { type: "session.closed", reason: envelope.command.reason }
  const eventEnvelopeValue = eventEnvelope(state, envelope, event, seams)
  return {
    ok: true,
    state: applySessionEvent(state, eventEnvelopeValue),
    events: immutableBatch([eventEnvelopeValue] as const),
  }
}
