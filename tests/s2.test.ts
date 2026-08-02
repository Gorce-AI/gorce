import { describe, expect, test } from "bun:test"
import {
  createCommandEnvelope,
  createEffectEnvelope,
  createEffectResultEnvelope,
  deepFreeze,
  deterministicSeams,
  dispatchSession,
  dispatchWorkRun,
  initialSessionState,
  initialWorkRunState,
  replaySession,
  replayWorkRun,
  resultAffinityFields,
  validateResultAffinity,
  type EffectOutcome,
  type EffectResultEnvelope,
  type JsonValue,
  type ResultAffinity,
  type WorkRunCommand,
  type WorkRunCommandEnvelope,
  type WorkRunEventEnvelope,
  type WorkRunState,
} from "@gorce-ai/core"
import type { SessionCommandEnvelope } from "@gorce-ai/core"

const affinity = (overrides: Partial<ResultAffinity> = {}): ResultAffinity => ({
  session_id: "session-1",
  work_run_id: "run-1",
  effect_id: "effect-1",
  target_authority: "local-core",
  target_id: "target-1",
  target_version: 7,
  execution_ref: "exec-1",
  stream_generation: 3,
  input_digest: "input-digest",
  contract_digest: "contract-digest",
  route_digest: "route-digest",
  workspace_id: "workspace-1",
  workspace_revision: 11,
  ...overrides,
})

const sessionCommand = (
  id: string,
  aggregateId: string,
  expectedVersion: number,
  command: SessionCommandEnvelope["command"],
): SessionCommandEnvelope => ({
  schema: "gorce.s2.command/v1",
  version: 1,
  command_id: id,
  root: "session",
  aggregate_id: aggregateId,
  expected_version: expectedVersion,
  issued_at: "2026-08-02T00:00:00.000Z",
  command,
})

const workRunCommand = (
  id: string,
  expectedVersion: number,
  command: WorkRunCommand,
): WorkRunCommandEnvelope => ({
  schema: "gorce.s2.command/v1",
  version: 1,
  command_id: id,
  root: "work-run",
  aggregate_id: "run-1",
  expected_version: expectedVersion,
  issued_at: "2026-08-02T00:00:00.000Z",
  command,
})

const succeed = (result: ReturnType<typeof dispatchWorkRun>): WorkRunState => {
  if (!result.ok) throw new Error(result.error)
  return result.state
}

const startedWorkRun = (): WorkRunState =>
  succeed(
    dispatchWorkRun(
      initialWorkRunState("run-1"),
      workRunCommand("start", 0, { type: "work-run.start", session_id: "session-1" }),
    ),
  )

const effectFor = (payload: unknown = null) =>
  createEffectEnvelope(
    deterministicSeams(["2026-08-02T00:00:00.000Z"], []),
    affinity(),
    "demo",
    payload as JsonValue,
  )

const resultFor = (
  effect: ReturnType<typeof effectFor>,
  outcome: EffectOutcome,
  resultId = "result-1",
): EffectResultEnvelope =>
  createEffectResultEnvelope(
    deterministicSeams(["2026-08-02T00:00:01.000Z"], [resultId]),
    affinity({
      session_id: effect.session_id,
      work_run_id: effect.work_run_id,
      effect_id: effect.effect_id,
      target_authority: effect.target_authority,
      target_id: effect.target_id,
      target_version: effect.target_version,
      execution_ref: effect.execution_ref,
      stream_generation: effect.stream_generation,
      input_digest: effect.input_digest,
      contract_digest: effect.contract_digest,
      route_digest: effect.route_digest,
      workspace_id: effect.workspace_id,
      workspace_revision: effect.workspace_revision,
    }),
    outcome,
  )

const plannedWorkRun = (payload: unknown = null): WorkRunState => {
  const state = startedWorkRun()
  return succeed(
    dispatchWorkRun(
      state,
      workRunCommand("plan", 1, { type: "work-run.plan-effect", effect: effectFor(payload) }),
    ),
  )
}

const attemptedWorkRun = (payload: unknown = null): WorkRunState =>
  succeed(
    dispatchWorkRun(
      plannedWorkRun(payload),
      workRunCommand("attempt", 2, {
        type: "work-run.attempt-effect",
        effect_id: "effect-1",
        execution_ref: "exec-1",
      }),
    ),
  )

const resolvedWorkRun = (outcome: EffectOutcome): WorkRunState =>
  succeed(
    dispatchWorkRun(
      attemptedWorkRun(),
      workRunCommand("resolve", 3, {
        type: "work-run.resolve-effect",
        result: resultFor(effectFor(), outcome),
      }),
    ),
  )

describe("S2 semantic laws", () => {
  test("WorkRun stale-version law emits zero events and preserves state for every stale version", () => {
    const state = startedWorkRun()
    const staleVersions = [-1, 0, 2, 10_000]
    const observations = staleVersions.map((expectedVersion) => {
      const result = dispatchWorkRun(
        state,
        workRunCommand(`stale-${expectedVersion}`, expectedVersion, { type: "work-run.complete" }),
      )
      return {
        expectedVersion,
        ok: result.ok,
        events: result.events.length,
        same: result.state === state,
      }
    })
    expect(observations).toEqual(
      staleVersions.map((expectedVersion) => ({
        expectedVersion,
        ok: false,
        events: 0,
        same: true,
      })),
    )
  })

  test("Session laws cover stale versions, authority, transitions, and replay rejection", () => {
    const initial = initialSessionState("session-1")
    const staleVersions = [-1, 1, 99]
    const stale = staleVersions.map((expectedVersion) => {
      const result = dispatchSession(
        initial,
        sessionCommand(`stale-${expectedVersion}`, "session-1", expectedVersion, {
          type: "session.close",
          reason: "stale",
        }),
      )
      return {
        expectedVersion,
        ok: result.ok,
        events: result.events.length,
        same: result.state === initial,
      }
    })
    const authority = dispatchSession(
      initial,
      sessionCommand("authority", "other-session", 0, { type: "session.start", label: "wrong" }),
    )
    const closeNew = dispatchSession(
      initial,
      sessionCommand("close-new", "session-1", 0, { type: "session.close", reason: "illegal" }),
    )
    const started = dispatchSession(
      initial,
      sessionCommand("start", "session-1", 0, { type: "session.start", label: "demo" }),
    )
    if (!started.ok) throw new Error(started.error)
    const startAgain = dispatchSession(
      started.state,
      sessionCommand("start-again", "session-1", 1, { type: "session.start", label: "again" }),
    )
    const closed = dispatchSession(
      started.state,
      sessionCommand("close", "session-1", 1, { type: "session.close", reason: "done" }),
    )
    if (!closed.ok) throw new Error(closed.error)
    const closeAgain = dispatchSession(
      closed.state,
      sessionCommand("close-again", "session-1", 2, { type: "session.close", reason: "again" }),
    )
    const history = [...started.events, ...closed.events]
    const first = history[0]
    const second = history[1]
    if (first === undefined || second === undefined) throw new Error("session history incomplete")
    const wrongRoot = { ...first, root: "work-run" } as never
    const gap = { ...second, revision: 9 }
    expect({
      stale,
      authority: {
        ok: authority.ok,
        events: authority.events.length,
        same: authority.state === initial,
      },
      closeNew: closeNew.ok,
      startAgain: startAgain.ok,
      closed: closed.state.status,
      closeAgain: closeAgain.ok,
      replay: replaySession("session-1", history),
      historyFrozen: Object.isFrozen(started.events) && Object.isFrozen(closed.events),
    }).toEqual({
      stale: staleVersions.map((expectedVersion) => ({
        expectedVersion,
        ok: false,
        events: 0,
        same: true,
      })),
      authority: { ok: false, events: 0, same: true },
      closeNew: false,
      startAgain: false,
      closed: "closed",
      closeAgain: false,
      replay: closed.state,
      historyFrozen: true,
    })
    expect(() => replaySession("session-1", [wrongRoot])).toThrow("S2_REPLAY_WRONG_ROOT")
    expect(() => replaySession("session-1", [gap])).toThrow("S2_REPLAY_NON_CONTIGUOUS")
  })

  test("effect transition table accepts only planned-attempted-terminal-final transitions", () => {
    const cases = [
      { outcome: { status: "confirmed", value: null } as const, final: "reconciled" as const },
      { outcome: { status: "failed", reason: "rejected" } as const, final: "compensated" as const },
      { outcome: { status: "unknown", reason: "timeout" } as const, final: "reconciled" as const },
    ]
    const traces = cases.map(({ outcome, final }) => {
      const planned = plannedWorkRun()
      const attempted = attemptedWorkRun()
      const resolved = resolvedWorkRun(outcome)
      const finalState =
        final === "reconciled"
          ? succeed(
              dispatchWorkRun(
                resolved,
                workRunCommand("reconcile", 4, {
                  type: "work-run.reconcile-effect",
                  effect_id: "effect-1",
                  reason: "authority confirmed terminal state",
                }),
              ),
            )
          : succeed(
              dispatchWorkRun(
                resolved,
                workRunCommand("compensate", 4, {
                  type: "work-run.compensate-effect",
                  effect_id: "effect-1",
                  reason: "compensation required",
                }),
              ),
            )
      const illegal = [
        dispatchWorkRun(
          planned,
          workRunCommand("resolve-before-attempt", 2, {
            type: "work-run.resolve-effect",
            result: resultFor(effectFor(), outcome),
          }),
        ).ok,
        dispatchWorkRun(
          attempted,
          workRunCommand("attempt-twice", 3, {
            type: "work-run.attempt-effect",
            effect_id: "effect-1",
            execution_ref: "exec-1",
          }),
        ).ok,
        dispatchWorkRun(
          resolved,
          workRunCommand("resolve-twice", 4, {
            type: "work-run.resolve-effect",
            result: resultFor(effectFor(), outcome, "result-twice"),
          }),
        ).ok,
        dispatchWorkRun(
          planned,
          workRunCommand("reconcile-planned", 2, {
            type: "work-run.reconcile-effect",
            effect_id: "effect-1",
            reason: "illegal",
          }),
        ).ok,
        dispatchWorkRun(
          attempted,
          workRunCommand("compensate-attempted", 3, {
            type: "work-run.compensate-effect",
            effect_id: "effect-1",
            reason: "illegal",
          }),
        ).ok,
      ]
      const terminalActions = [
        dispatchWorkRun(
          resolved,
          workRunCommand("reconcile-matrix", 4, {
            type: "work-run.reconcile-effect",
            effect_id: "effect-1",
            reason: "matrix",
          }),
        ).ok,
        dispatchWorkRun(
          resolved,
          workRunCommand("compensate-matrix", 4, {
            type: "work-run.compensate-effect",
            effect_id: "effect-1",
            reason: "matrix",
          }),
        ).ok,
      ]
      return {
        statuses: [
          planned.effects[0]?.status,
          attempted.effects[0]?.status,
          resolved.effects[0]?.status,
          finalState.effects[0]?.status,
        ],
        illegal,
        terminalActions,
      }
    })
    expect(traces).toEqual([
      {
        statuses: ["planned", "attempted", "confirmed", "reconciled"],
        illegal: [false, false, false, false, false],
        terminalActions: [true, false],
      },
      {
        statuses: ["planned", "attempted", "failed", "compensated"],
        illegal: [false, false, false, false, false],
        terminalActions: [false, true],
      },
      {
        statuses: ["planned", "attempted", "unknown", "reconciled"],
        illegal: [false, false, false, false, false],
        terminalActions: [true, true],
      },
    ])
    const unknown = resolvedWorkRun({ status: "unknown", reason: "timeout" })
    const compensated = dispatchWorkRun(
      unknown,
      workRunCommand("compensate-unknown", 4, {
        type: "work-run.compensate-effect",
        effect_id: "effect-1",
        reason: "unknown work compensated",
      }),
    )
    expect(compensated.ok && compensated.state.effects[0]?.status).toBe("compensated")
  })

  test("WorkRun complete and fail transitions require a running root", () => {
    const completed = dispatchWorkRun(
      startedWorkRun(),
      workRunCommand("complete", 1, { type: "work-run.complete" }),
    )
    const failed = dispatchWorkRun(
      startedWorkRun(),
      workRunCommand("fail", 1, { type: "work-run.fail", reason: "law" }),
    )
    const illegalComplete = dispatchWorkRun(
      initialWorkRunState("run-1"),
      workRunCommand("complete-new", 0, { type: "work-run.complete" }),
    )
    expect({
      completed: completed.ok && completed.state.status,
      failed: failed.ok && failed.state.status,
      illegalComplete: illegalComplete.ok,
    }).toEqual({ completed: "completed", failed: "failed", illegalComplete: false })
  })

  test("every result affinity field independently rejects a mismatch", () => {
    const expected = affinity()
    const attempted = attemptedWorkRun()
    const observations = resultAffinityFields.map((field) => {
      const value = typeof expected[field] === "number" ? (expected[field] as number) + 1 : "wrong"
      const result = {
        ...resultFor(effectFor(), { status: "confirmed", value: null }),
        ...expected,
        [field]: value,
      }
      const direct = validateResultAffinity(result, expected)
      const rejected = dispatchWorkRun(
        attempted,
        workRunCommand(`mismatch-${field}`, 3, { type: "work-run.resolve-effect", result }),
      )
      return {
        field,
        rejected: !rejected.ok,
        mentionsField: !direct.ok && direct.errors.includes(`${field} mismatch`),
      }
    })
    expect(observations).toEqual(
      resultAffinityFields.map((field) => ({ field, rejected: true, mentionsField: true })),
    )
  })

  test("WorkRun replay rejects wrong roots, gaps, versions, and preserves nested history", () => {
    const started = dispatchWorkRun(
      initialWorkRunState("run-1"),
      workRunCommand("start", 0, { type: "work-run.start", session_id: "session-1" }),
    )
    if (!started.ok) throw new Error(started.error)
    const planned = dispatchWorkRun(
      started.state,
      workRunCommand("plan", 1, {
        type: "work-run.plan-effect",
        effect: effectFor({ nested: { value: 1 } }),
      }),
    )
    if (!planned.ok) throw new Error(planned.error)
    const attempted = dispatchWorkRun(
      planned.state,
      workRunCommand("attempt", 2, {
        type: "work-run.attempt-effect",
        effect_id: "effect-1",
        execution_ref: "exec-1",
      }),
    )
    if (!attempted.ok) throw new Error(attempted.error)
    const resolved = dispatchWorkRun(
      attempted.state,
      workRunCommand("resolve", 3, {
        type: "work-run.resolve-effect",
        result: resultFor(effectFor({ nested: { value: 1 } }), {
          status: "confirmed",
          value: { nested: { ok: true } },
        }),
      }),
    )
    if (!resolved.ok) throw new Error(resolved.error)
    const events = [...started.events, ...planned.events, ...attempted.events, ...resolved.events]
    const returnedBatch = planned.events as unknown as WorkRunEventEnvelope[]
    const batchMutations = [
      (() => {
        try {
          returnedBatch.pop()
          return "mutated"
        } catch {
          return "frozen"
        }
      })(),
      (() => {
        try {
          returnedBatch[0] = events[0] as WorkRunEventEnvelope
          return "mutated"
        } catch {
          return "frozen"
        }
      })(),
    ]
    expect(replayWorkRun("run-1", "session-1", events)).toEqual(resolved.state)
    const firstEvent = events[0]
    const secondEvent = events[1]
    if (firstEvent === undefined || secondEvent === undefined) throw new Error("history incomplete")
    const rootEvent = { ...firstEvent, root: "session" } as never
    const gapEvent = { ...secondEvent, revision: 9 }
    const versionEvent = { ...firstEvent, version: 2 } as never
    expect(() => replayWorkRun("run-1", "session-1", [rootEvent])).toThrow("S2_REPLAY_WRONG_ROOT")
    expect(() => replayWorkRun("run-1", "session-1", [gapEvent])).toThrow(
      "S2_REPLAY_NON_CONTIGUOUS",
    )
    expect(() => replayWorkRun("run-1", "session-1", [versionEvent])).toThrow("S2_ENVELOPE_VERSION")
    const eventPayload = events[0]?.event
    const statePayload = resolved.state.effects[0]?.effect.payload
    expect({
      eventFrozen: Object.isFrozen(eventPayload),
      batchFrozen: Object.isFrozen(planned.events),
      batchMutations,
      nestedFrozen: Object.isFrozen((statePayload as { nested: object }).nested),
      replayEqual: replayWorkRun("run-1", "session-1", events),
    }).toEqual({
      eventFrozen: true,
      batchFrozen: true,
      batchMutations: ["frozen", "frozen"],
      nestedFrozen: true,
      replayEqual: resolved.state,
    })
  })

  test("nested command/result bodies and histories cannot mutate semantic state", () => {
    const payload = { nested: { value: 1 }, list: [{ value: 2 }] }
    const effect = effectFor(payload)
    const planned = dispatchWorkRun(
      startedWorkRun(),
      workRunCommand("plan", 1, { type: "work-run.plan-effect", effect }),
    )
    if (!planned.ok) throw new Error(planned.error)
    payload.nested.value = 9
    const firstItem = payload.list[0]
    if (firstItem === undefined) throw new Error("payload list incomplete")
    firstItem.value = 9
    const stored = planned.state.effects[0]?.effect.payload as {
      nested: { value: number }
      list: readonly [{ value: number }]
    }
    expect(stored).toEqual({ nested: { value: 1 }, list: [{ value: 2 }] })
    expect(
      Object.isFrozen(stored) && Object.isFrozen(stored.nested) && Object.isFrozen(stored.list),
    ).toBe(true)
    const commandBody = { nested: { command: true } }
    const command = createCommandEnvelope(
      deterministicSeams(["command-time"], ["command-id"]),
      "work-run",
      "run-1",
      0,
      commandBody,
    )
    const resolved = resolvedWorkRun({ status: "confirmed", value: { nested: { ok: true } } })
    const outcome = resolved.effects[0]?.outcome
    const result = deepFreeze({ outcome: { value: { nested: { ok: true } } } })
    expect({
      commandNestedFrozen:
        Object.isFrozen(command.command) && Object.isFrozen(command.command.nested),
      eventNestedFrozen: Object.isFrozen(
        (planned.events[0]?.event as { effect: { payload: object } }).effect.payload,
      ),
      resultNestedFrozen:
        outcome !== undefined && Object.isFrozen((outcome as { value: object }).value),
      helperNestedFrozen: Object.isFrozen(result.outcome.value),
    }).toEqual({
      commandNestedFrozen: true,
      eventNestedFrozen: true,
      resultNestedFrozen: true,
      helperNestedFrozen: true,
    })
  })

  test("Session and WorkRun never synchronously mutate one another", () => {
    const session = initialSessionState("session-1")
    const run = startedWorkRun()
    const afterSession = dispatchSession(
      session,
      sessionCommand("session-start", "session-1", 0, { type: "session.start", label: "demo" }),
    )
    expect({
      workRunSession: run.session_id,
      sessionVersion: session.version,
      workRunVersion: run.version,
      sessionStarted: afterSession.ok,
    }).toEqual({
      workRunSession: "session-1",
      sessionVersion: 0,
      workRunVersion: 1,
      sessionStarted: true,
    })
  })

  test("injected clock and IDs are deterministic", () => {
    const seams = deterministicSeams(["t1", "t2", "t3"], ["command-1", "result-1"])
    const envelope = createCommandEnvelope(seams, "session", "session-1", 0, {
      type: "session.start",
      label: "demo",
    })
    const effect = createEffectEnvelope(seams, affinity(), "demo", null)
    const result = createEffectResultEnvelope(seams, affinity(), {
      status: "confirmed",
      value: null,
    })
    expect({
      command: envelope.command_id,
      issued: envelope.issued_at,
      requested: effect.requested_at,
      result: result.result_id,
      completed: result.completed_at,
    }).toEqual({
      command: "command-1",
      issued: "t1",
      requested: "t2",
      result: "result-1",
      completed: "t3",
    })
  })
})
