export const s2MutationCategories = [
  "reducers",
  "policy",
  "compatibility",
  "persistence",
  "reconciliation",
] as const

export type S2MutationCategory = (typeof s2MutationCategories)[number]

export interface S2MutationTarget {
  readonly id: string
  readonly category: S2MutationCategory
  readonly path: string
  readonly needle: string
  readonly replacement: string
}

const affinityComparatorNeedle =
  "if (result[field] !== expected[field]) errors.push(" +
  "`" +
  String.fromCharCode(36) +
  "{field} mismatch" +
  "`)"

export const s2MutationTargets: readonly S2MutationTarget[] = [
  {
    id: "session-expected-version",
    category: "policy",
    path: "packages/core/src/session.ts",
    needle: "if (envelope.expected_version !== state.version)",
    replacement: "if (envelope.expected_version === state.version)",
  },
  {
    id: "session-authority",
    category: "reducers",
    path: "packages/core/src/session.ts",
    needle: 'if (envelope.root !== "session" || envelope.aggregate_id !== state.session_id)',
    replacement: 'if (envelope.root === "session" || envelope.aggregate_id === state.session_id)',
  },
  {
    id: "session-close-transition",
    category: "reducers",
    path: "packages/core/src/session.ts",
    needle: 'else if (state.status !== "active")',
    replacement: 'else if (state.status === "active")',
  },
  {
    id: "session-event-batch-freeze",
    category: "reducers",
    path: "packages/core/src/session.ts",
    needle: "events: immutableBatch([eventEnvelopeValue] as const)",
    replacement: "events: [eventEnvelopeValue]",
  },
  {
    id: "direct-affinity-comparator",
    category: "compatibility",
    path: "packages/core/src/contracts.ts",
    needle: affinityComparatorNeedle,
    replacement: affinityComparatorNeedle.replace("!==", "==="),
  },
  {
    id: "work-run-expected-version",
    category: "policy",
    path: "packages/core/src/work-run.ts",
    needle:
      'if (envelope.expected_version !== state.version) return failure(state, "S2_EXPECTED_VERSION")',
    replacement:
      'if (envelope.expected_version === state.version) return failure(state, "S2_EXPECTED_VERSION")',
  },
  {
    id: "work-run-event-batch-freeze",
    category: "reducers",
    path: "packages/core/src/work-run.ts",
    needle: "events: immutableBatch([value] as const)",
    replacement: "events: [value]",
  },
  {
    id: "planned-state",
    category: "reducers",
    path: "packages/core/src/work-run-events.ts",
    needle: 'effects: [...state.effects, { effect: event.effect, status: "planned", attempts: 0 }]',
    replacement:
      'effects: [...state.effects, { effect: event.effect, status: "attempted", attempts: 0 }]',
  },
  {
    id: "attempt-transition",
    category: "reducers",
    path: "packages/core/src/work-run-events.ts",
    needle: 'if (current === undefined || current.status !== "planned")',
    replacement: 'if (current === undefined || current.status === "planned")',
  },
  {
    id: "resolve-transition",
    category: "reconciliation",
    path: "packages/core/src/work-run-events.ts",
    needle: 'if (current === undefined || current.status !== "attempted")',
    replacement: 'if (current === undefined || current.status === "attempted")',
  },
  {
    id: "result-affinity-policy",
    category: "compatibility",
    path: "packages/core/src/work-run.ts",
    needle: `if (!affinity.ok) error = \`S2_RESULT_AFFINITY: \${affinity.errors.join(", ")}\``,
    replacement: 'if (affinity.ok) error = "S2_RESULT_AFFINITY"',
  },
  {
    id: "reconcile-transition",
    category: "reconciliation",
    path: "packages/core/src/work-run.ts",
    needle: 'else if (current.status !== "confirmed" && current.status !== "unknown")',
    replacement: 'else if (current.status === "confirmed" || current.status === "unknown")',
  },
  {
    id: "compensate-transition",
    category: "reconciliation",
    path: "packages/core/src/work-run.ts",
    needle: 'else if (current.status !== "failed" && current.status !== "unknown")',
    replacement: 'else if (current.status === "failed" || current.status === "unknown")',
  },
  {
    id: "unknown-outcome",
    category: "reconciliation",
    path: "packages/core/src/work-run-events.ts",
    needle: "status: event.result.outcome.status,",
    replacement: 'status: "confirmed",',
  },
  {
    id: "work-run-replay-root",
    category: "persistence",
    path: "packages/core/src/replay.ts",
    needle: 'if (event.root !== "work-run" || event.aggregate_id !== workRunId)',
    replacement: 'if (event.root === "work-run" || event.aggregate_id === workRunId)',
  },
  {
    id: "work-run-replay-revision",
    category: "persistence",
    path: "packages/core/src/replay.ts",
    needle:
      'if (event.revision !== state.version + 1) throw new Error("S2_REPLAY_NON_CONTIGUOUS")\n    state = applyWorkRunEvent(state, event)',
    replacement:
      'if (event.revision === state.version + 1) throw new Error("S2_REPLAY_NON_CONTIGUOUS")\n    state = applyWorkRunEvent(state, event)',
  },
  {
    id: "effect-execution-reference",
    category: "compatibility",
    path: "packages/core/src/work-run-events.ts",
    needle:
      'if (current.effect.execution_ref !== event.execution_ref)\n      throw new Error("S2_EFFECT_EXECUTION_REF")',
    replacement:
      'if (current.effect.execution_ref === event.execution_ref)\n      throw new Error("S2_EFFECT_EXECUTION_REF")',
  },
  {
    id: "deep-copy-payload",
    category: "reducers",
    path: "packages/core/src/immutability.ts",
    needle: "export const immutableCopy = <T>(value: T): T => deepFreeze(structuredClone(value))",
    replacement: "export const immutableCopy = <T>(value: T): T => deepFreeze(value)",
  },
] as const

export const s2MutationFixtures: readonly S2MutationTarget[] = [
  {
    id: "fixture-killed",
    category: "policy",
    path: "packages/core/src/work-run.ts",
    needle:
      'if (envelope.expected_version !== state.version) return failure(state, "S2_EXPECTED_VERSION")',
    replacement:
      'if (envelope.expected_version === state.version) return failure(state, "S2_EXPECTED_VERSION")',
  },
  {
    id: "fixture-survived",
    category: "policy",
    path: "packages/core/src/work-run.ts",
    needle:
      'if (envelope.expected_version !== state.version) return failure(state, "S2_EXPECTED_VERSION")',
    replacement:
      'if (!(envelope.expected_version === state.version)) return failure(state, "S2_EXPECTED_VERSION")',
  },
] as const
