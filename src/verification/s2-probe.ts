import {
  createEffectEnvelope,
  createEffectResultEnvelope,
  deterministicSeams,
  dispatchSession,
  dispatchWorkRun,
  initialSessionState,
  initialWorkRunState,
  replaySession,
  type ResultAffinity,
} from "@gorce-ai/core"

export const probeS2Behavior = (): boolean => {
  const base: ResultAffinity = {
    session_id: "probe-session",
    work_run_id: "run-1",
    effect_id: "effect-1",
    target_authority: "probe",
    target_id: "target",
    target_version: 1,
    execution_ref: "execution",
    stream_generation: 1,
    input_digest: "input",
    contract_digest: "contract",
    route_digest: "route",
    workspace_id: "workspace",
    workspace_revision: 1,
  }
  const effect = createEffectEnvelope(deterministicSeams(["t1"], []), base, "probe", {
    nested: true,
  })
  const command = (
    id: string,
    version: number,
    command: Parameters<typeof dispatchWorkRun>[1]["command"],
  ) => ({
    schema: "gorce.s2.command/v1" as const,
    version: 1 as const,
    command_id: id,
    root: "work-run" as const,
    aggregate_id: "run-1",
    expected_version: version,
    issued_at: `t${version}`,
    command,
  })
  const start = dispatchWorkRun(
    initialWorkRunState("run-1"),
    command("start", 0, { type: "work-run.start", session_id: "probe-session" }),
  )
  if (!start.ok) return false
  const planned = dispatchWorkRun(
    start.state,
    command("plan", 1, { type: "work-run.plan-effect", effect }),
  )
  if (!planned.ok) return false
  const attempted = dispatchWorkRun(
    planned.state,
    command("attempt", 2, {
      type: "work-run.attempt-effect",
      effect_id: "effect-1",
      execution_ref: "execution",
    }),
  )
  if (!attempted.ok) return false
  const result = createEffectResultEnvelope(deterministicSeams(["t3"], ["result"]), base, {
    status: "unknown",
    reason: "probe-timeout",
  })
  const resolved = dispatchWorkRun(
    attempted.state,
    command("resolve", 3, { type: "work-run.resolve-effect", result }),
  )
  if (!resolved.ok) return false
  const reconciled = dispatchWorkRun(
    resolved.state,
    command("reconcile", 4, {
      type: "work-run.reconcile-effect",
      effect_id: "effect-1",
      reason: "probe-reconciled",
    }),
  )
  const stale = dispatchWorkRun(
    resolved.state,
    command("stale", 3, {
      type: "work-run.reconcile-effect",
      effect_id: "effect-1",
      reason: "stale",
    }),
  )
  const sessionStart = dispatchSession(initialSessionState("probe-session"), {
    schema: "gorce.s2.command/v1",
    version: 1,
    command_id: "session-start",
    root: "session",
    aggregate_id: "probe-session",
    expected_version: 0,
    issued_at: "t0",
    command: { type: "session.start", label: "probe" },
  })
  if (!sessionStart.ok) return false
  const sessionClose = dispatchSession(sessionStart.state, {
    schema: "gorce.s2.command/v1",
    version: 1,
    command_id: "session-close",
    root: "session",
    aggregate_id: "probe-session",
    expected_version: 1,
    issued_at: "t1",
    command: { type: "session.close", reason: "probe" },
  })
  const sessionStale = dispatchSession(sessionStart.state, {
    schema: "gorce.s2.command/v1",
    version: 1,
    command_id: "session-stale",
    root: "session",
    aggregate_id: "probe-session",
    expected_version: 0,
    issued_at: "t1",
    command: { type: "session.close", reason: "stale" },
  })
  const sessionHistory = sessionClose.ok ? [...sessionStart.events, ...sessionClose.events] : []
  return (
    reconciled.ok &&
    reconciled.state.effects[0]?.status === "reconciled" &&
    !stale.ok &&
    stale.events.length === 0 &&
    Object.isFrozen(effect.payload) &&
    sessionClose.ok &&
    sessionClose.state.status === "closed" &&
    !sessionStale.ok &&
    sessionStale.events.length === 0 &&
    replaySession("probe-session", sessionHistory).status === "closed"
  )
}
