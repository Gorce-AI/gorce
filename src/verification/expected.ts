import type { BlockerEntry, CommandOwner, TaskId } from "./types.js"

export const APPROVED_PLAN_SHA256 =
  "41e1e866c7670cd204c257c551b30d1642c603c67ff1b7f3d3794625459ee764"
export const APPROVED_GRAPH_SHA256 =
  "65e5be39146dc3a0ddec90c4939e3869f9c908b029b23fcdc149c83ad2fc082a"
export const APPROVED_OWNER_SHA256 =
  "a3b0e182ec0683ae790cc31269d7e991d51d4e5ac982fd4d657e6f8498e7e45f"
export const APPROVED_TASK_COUNT = 41

const edge = (task: TaskId, blocked_by: readonly TaskId[]): BlockerEntry => ({
  task,
  blocked_by,
})

export const APPROVED_BLOCKER_GRAPH: readonly BlockerEntry[] = [
  edge(1, []),
  edge(2, [1]),
  edge(3, [1]),
  edge(4, [1]),
  edge(5, [1]),
  edge(6, [2, 3]),
  edge(7, [6]),
  edge(8, [2, 6, 7]),
  edge(9, [6, 7, 8]),
  edge(10, [9]),
  edge(11, [8, 10]),
  edge(12, [7, 10]),
  edge(13, [7, 10]),
  edge(14, [7, 10, 13]),
  edge(15, [8, 11, 12, 13, 14]),
  edge(16, [6, 7, 8]),
  edge(17, [11, 13, 14, 15, 16]),
  edge(18, [7, 15, 16, 17]),
  edge(19, [8, 11, 13, 14, 15, 16, 17]),
  edge(20, [13, 14, 15, 17, 19]),
  edge(21, [6, 10, 11, 15, 16]),
  edge(22, [15, 16, 17, 18, 19, 20, 21]),
  edge(23, [4, 11]),
  edge(24, [5, 11]),
  edge(25, [12, 15, 17, 18, 19, 20, 21, 22]),
  edge(26, [17, 18, 19, 20, 21, 22, 23, 24, 25]),
  edge(27, [2, 8, 11, 12, 15, 19, 25, 26]),
  edge(28, [23, 24, 27]),
  edge(29, [25, 26, 27, 28]),
  edge(30, [29]),
  edge(31, [23, 30]),
  edge(32, [24, 30]),
  edge(33, [30, 31, 32]),
  edge(34, [30, 33]),
  edge(35, [31, 34]),
  edge(36, [32, 34]),
  edge(37, [35, 36]),
  edge(38, [30, 37]),
  edge(39, [35, 37]),
  edge(40, [36, 37]),
  edge(41, [37, 38, 39, 40]),
  edge("F1", [41]),
  edge("F2", [41]),
  edge("F3", [41]),
  edge("F4", [41]),
  edge("F5", [41]),
  edge("F6", [41]),
]

const owner = (command: string, implemented_by: number, name: string): CommandOwner => ({
  command,
  implemented_by,
  owner: name,
})

export const APPROVED_COMMAND_OWNERS: readonly CommandOwner[] = [
  owner("topology-gate.ts", 1, "Private Bun tool"),
  owner("verify:governance", 2, ".github"),
  owner("qa:task", 3, "Core"),
  owner("verify:plan-compliance", 3, "Core"),
  owner("core docs:verify", 3, "Core"),
  owner("Studio QA/docs/candidate/index wrappers", 4, "Studio"),
  owner("JetBrains QA/docs/candidate/index wrappers", 5, "JetBrains"),
  owner("verify:technology", 6, "Core"),
  owner("verify:architecture", 6, "Core"),
  owner("F2 verifier", 6, "Core"),
  owner("Contract/compatibility validators", 8, "Core"),
  owner("verify:security", 25, "Core"),
  owner("verify:real-qa", 25, "Core"),
  owner("quality:full", 26, "Core"),
  owner("benchmark:compare", 26, "Core"),
  owner("verify:final-scope", 26, "Core"),
  owner("Consumer/release/support-set/F5 tools", 27, "Core"),
  owner("Launcher evaluator/qualifier", 33, "Core"),
]

export const REQUIRED_CORE_COMMANDS = [
  "qa:task",
  "verify:plan-compliance",
  "core docs:verify",
] as const
