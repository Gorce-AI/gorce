import {
  applySessionEvent,
  initialSessionState,
  type SessionEventEnvelope,
  type SessionState,
} from "./session.js"
import { assertVersionedEnvelope, immutableHistory } from "./contracts.js"
import {
  applyWorkRunEvent,
  initialWorkRunState,
  type WorkRunEventEnvelope,
  type WorkRunState,
} from "./work-run.js"

export const replaySession = (
  sessionId: string,
  events: readonly SessionEventEnvelope[],
): SessionState => {
  let state = initialSessionState(sessionId)
  for (const event of immutableHistory(events)) {
    assertVersionedEnvelope(event.schema, event.version, "gorce.s2.event/v1")
    if (event.root !== "session" || event.aggregate_id !== sessionId)
      throw new Error("S2_REPLAY_WRONG_ROOT")
    if (event.revision !== state.version + 1) throw new Error("S2_REPLAY_NON_CONTIGUOUS")
    state = applySessionEvent(state, event)
  }
  return state
}

export const replayWorkRun = (
  workRunId: string,
  sessionId: string,
  events: readonly WorkRunEventEnvelope[],
): WorkRunState => {
  let state = initialWorkRunState(workRunId, sessionId)
  for (const event of immutableHistory(events)) {
    assertVersionedEnvelope(event.schema, event.version, "gorce.s2.event/v1")
    if (event.root !== "work-run" || event.aggregate_id !== workRunId)
      throw new Error("S2_REPLAY_WRONG_ROOT")
    if (event.revision !== state.version + 1) throw new Error("S2_REPLAY_NON_CONTIGUOUS")
    state = applyWorkRunEvent(state, event)
  }
  return state
}
