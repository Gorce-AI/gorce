import { createHash } from "node:crypto"
import {
  APPROVED_BLOCKER_GRAPH,
  APPROVED_COMMAND_OWNERS,
  APPROVED_GRAPH_SHA256,
  APPROVED_OWNER_SHA256,
  APPROVED_PLAN_SHA256,
  APPROVED_TASK_COUNT,
  REQUIRED_CORE_COMMANDS,
} from "./expected.js"
import type {
  BlockerEntry,
  CheckResult,
  CommandOwner,
  ExecutionManifest,
  TaskId,
  VerificationReport,
} from "./types.js"

const result = (checks: readonly CheckResult[], errors: readonly string[]): VerificationReport => ({
  schema: "gorce.verification-result/v1",
  command: "manifest-structure",
  ok: errors.length === 0,
  checks,
  errors,
})

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value)

const valueAt = (record: Record<string, unknown>, key: string): unknown => record[key]

const isTaskId = (value: unknown): value is TaskId =>
  (typeof value === "number" && Number.isInteger(value) && value > 0) ||
  value === "F1" ||
  value === "F2" ||
  value === "F3" ||
  value === "F4" ||
  value === "F5" ||
  value === "F6"

const canonical = (value: unknown): string => JSON.stringify(value) ?? ""

const readTaskIdList = (value: unknown): TaskId[] | null => {
  if (!Array.isArray(value) || !value.every(isTaskId)) return null
  return [...value]
}

const readGraph = (value: unknown): BlockerEntry[] | null => {
  if (!Array.isArray(value)) return null
  const graph: BlockerEntry[] = []
  for (const entry of value) {
    if (!isRecord(entry)) return null
    const task = valueAt(entry, "task")
    if (!isTaskId(task)) return null
    const blockedBy = readTaskIdList(valueAt(entry, "blocked_by"))
    if (blockedBy === null) return null
    graph.push({ task, blocked_by: blockedBy })
  }
  return graph
}

const readOwners = (value: unknown): CommandOwner[] | null => {
  if (!Array.isArray(value)) return null
  const owners: CommandOwner[] = []
  for (const entry of value) {
    if (!isRecord(entry)) return null
    const command = valueAt(entry, "command")
    const implementedBy = valueAt(entry, "implemented_by")
    const ownerName = valueAt(entry, "owner")
    if (
      typeof command !== "string" ||
      typeof implementedBy !== "number" ||
      !Number.isInteger(implementedBy) ||
      typeof ownerName !== "string"
    ) {
      return null
    }
    owners.push({
      command,
      implemented_by: implementedBy,
      owner: ownerName,
    })
  }
  return owners
}

const hasDuplicate = (values: readonly string[]): boolean => new Set(values).size !== values.length

const isAcyclic = (graph: readonly BlockerEntry[]): boolean => {
  const state = new Map<string, "open" | "closed">()
  const edges = new Map<string, readonly TaskId[]>()
  for (const entry of graph) edges.set(String(entry.task), entry.blocked_by)

  const visit = (task: TaskId): boolean => {
    const key = String(task)
    if (state.get(key) === "open") return false
    if (state.get(key) === "closed") return true
    state.set(key, "open")
    const blockers = edges.get(key) ?? []
    for (const blocker of blockers) {
      if (!edges.has(String(blocker)) || !visit(blocker)) return false
    }
    state.set(key, "closed")
    return true
  }

  return graph.every((entry) => visit(entry.task))
}

const isExact = (actual: unknown, expected: unknown): boolean =>
  canonical(actual) === canonical(expected)

export const validateManifest = (input: unknown): VerificationReport => {
  const checks: CheckResult[] = []
  const errors: string[] = []
  if (!isRecord(input)) {
    return result(
      [{ name: "manifest-object", status: "failed" }],
      ["manifest payload is not an object"],
    )
  }

  const check = (name: string, valid: boolean, detail: string): void => {
    checks.push({ name, status: valid ? "passed" : "failed", ...(valid ? {} : { detail }) })
    if (!valid) errors.push(detail)
  }

  check(
    "schema",
    valueAt(input, "schema") === "gorce.execution-manifest/v1",
    "manifest schema is invalid",
  )
  check(
    "approved-plan-sha",
    valueAt(input, "plan_sha256") === APPROVED_PLAN_SHA256,
    "approved plan SHA mismatch",
  )
  check(
    "task-count",
    valueAt(input, "task_count") === APPROVED_TASK_COUNT,
    "manifest task count is not 41",
  )

  const graph = readGraph(valueAt(input, "blocker_graph"))
  check("graph-shape", graph !== null, "manifest blocker graph is malformed")
  if (graph !== null) {
    const ids = graph.map((entry) => String(entry.task))
    check("unique-task-ids", !hasDuplicate(ids), "manifest contains duplicate task IDs")
    check(
      "acyclic-graph",
      isAcyclic(graph),
      "manifest blocker graph is cyclic or references an unknown task",
    )
    check(
      "approved-graph",
      isExact(graph, APPROVED_BLOCKER_GRAPH),
      "manifest blocker graph does not match the approved execution data",
    )
    const graphSha = createHash("sha256").update(canonical(graph)).digest("hex")
    check(
      "graph-sha",
      valueAt(input, "blocker_graph_sha256") === graphSha && graphSha === APPROVED_GRAPH_SHA256,
      "blocker graph SHA mismatch",
    )
  }

  const owners = readOwners(valueAt(input, "command_owners"))
  check("owner-shape", owners !== null, "manifest command owners are malformed")
  if (owners !== null) {
    check(
      "unique-commands",
      !hasDuplicate(owners.map((entry) => entry.command)),
      "manifest contains duplicate command owners",
    )
    check(
      "owned-verifiers",
      REQUIRED_CORE_COMMANDS.every((command) =>
        owners.some((entry) => entry.command === command && entry.owner === "Core"),
      ),
      "manifest contains an unowned verifier command",
    )
    check(
      "approved-command-owners",
      isExact(owners, APPROVED_COMMAND_OWNERS),
      "manifest command owners does not match the approved execution data",
    )
    const ownerSha = createHash("sha256").update(canonical(owners)).digest("hex")
    check("owner-sha", ownerSha === APPROVED_OWNER_SHA256, "command owner SHA mismatch")
  }

  check(
    "owner-gates",
    Array.isArray(valueAt(input, "owner_gates")),
    "manifest owner gates are malformed",
  )
  check(
    "task-41-owners",
    isExact(valueAt(input, "task_41_command_owner_tasks"), [3, 4, 5, 26]),
    "manifest task 41 command owners are invalid",
  )
  check(
    "signer",
    valueAt(input, "signer_identity") === "lead",
    "manifest signer identity is invalid",
  )
  check(
    "signature-name",
    valueAt(input, "signature") === "execution-manifest.sig",
    "manifest signature name is invalid",
  )

  return result(checks, errors)
}

export const isExecutionManifest = (input: unknown): input is ExecutionManifest =>
  validateManifest(input).ok
