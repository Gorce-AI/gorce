import { createHash } from "node:crypto"
import { execFileSync } from "node:child_process"
import { readFile } from "node:fs/promises"
import { join } from "node:path"
import {
  classifyMutation,
  copyMutationSandbox,
  disposeMutationSandbox,
} from "./mutation-s2-sandbox.js"
import {
  s2MutationCategories,
  s2MutationFixtures,
  s2MutationTargets,
  type S2MutationCategory,
} from "./mutation-s2-targets.js"

export { s2MutationCategories, s2MutationTargets } from "./mutation-s2-targets.js"
export type { S2MutationCategory, S2MutationTarget } from "./mutation-s2-targets.js"
export const s2MutationCommand = "bun run test:mutation" as const
export const s2MutationThreshold = 0.9 as const
export const s2MutationTestPath = "tests/s2.test.ts" as const
export const s2MutationDefinitionsPath = "src/verification/mutation-s2-targets.ts" as const
export const s2MutationRunnerPath = "src/verification/mutation-s2.ts" as const
export const s2MutationRunnerSupportPath = "src/verification/mutation-s2-sandbox.ts" as const
export const s2MutationTimeoutMs = 15_000 as const
export type S2MutationOutcome = "killed" | "survived" | "timeout" | "infrastructure" | "type-error"
export interface S2MutationTargetEvidence {
  readonly id: string
  readonly category: S2MutationCategory
  readonly path: string
  readonly outcome: S2MutationOutcome
}
export interface S2MutationFixtureEvidence {
  readonly id: string
  readonly expected: "killed" | "survived"
  readonly outcome: S2MutationOutcome
}
export interface S2SourceDigest {
  readonly path: string
  readonly sha256: string
}
export interface S2MutationEvidence {
  readonly schema: "gorce.s2.mutation-gate/v2"
  readonly verdict: "APPROVED" | "CHANGES_REQUESTED"
  readonly command: typeof s2MutationCommand
  readonly threshold: typeof s2MutationThreshold
  readonly critical_target_categories: typeof s2MutationCategories
  readonly source_commit: string
  readonly source_inventory: readonly S2SourceDigest[]
  readonly mutation_definitions: S2SourceDigest
  readonly runner: S2SourceDigest
  readonly runner_support: S2SourceDigest
  readonly semantic_tests: S2SourceDigest
  readonly targets: readonly S2MutationTargetEvidence[]
  readonly fixtures: readonly S2MutationFixtureEvidence[]
  readonly score: number
  readonly execution: "isolated-temporary-copy"
  readonly coverage_claim: "all declared S2 critical reducer targets"
  readonly reason: string
}

const sha256 = (source: string): string => createHash("sha256").update(source).digest("hex")
const digestFile = async (root: string, path: string): Promise<S2SourceDigest> => ({
  path,
  sha256: sha256(await readFile(join(root, path), "utf8")),
})
const sourceCommit = (root: string): string => {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim()
  } catch {
    return ""
  }
}
export const runS2Mutation = async (root: string): Promise<S2MutationEvidence> => {
  const sandbox = await copyMutationSandbox(root)
  try {
    const typescript = join(root, "node_modules/typescript/bin/tsc")
    const typecheck = await classifyMutation(
      sandbox,
      {
        id: "baseline-typecheck",
        category: "policy",
        path: "packages/core/src/work-run.ts",
        needle: "export const dispatchWorkRun",
        replacement: "export const dispatchWorkRun",
      },
      typescript,
      s2MutationTestPath,
      s2MutationTimeoutMs,
    )
    if (typecheck !== "survived")
      throw new Error("S2_MUTATION_BASELINE: typecheck/test baseline failed")
    const targets: S2MutationTargetEvidence[] = []
    for (const target of s2MutationTargets)
      targets.push({
        id: target.id,
        category: target.category,
        path: target.path,
        outcome: await classifyMutation(
          sandbox,
          target,
          typescript,
          s2MutationTestPath,
          s2MutationTimeoutMs,
        ),
      })
    const fixtures: S2MutationFixtureEvidence[] = []
    for (const fixture of s2MutationFixtures)
      fixtures.push({
        id: fixture.id,
        expected: fixture.id === "fixture-killed" ? "killed" : "survived",
        outcome: await classifyMutation(
          sandbox,
          fixture,
          typescript,
          s2MutationTestPath,
          s2MutationTimeoutMs,
        ),
      })
    const killed = targets.filter((target) => target.outcome === "killed").length
    const score = targets.length === 0 ? 0 : killed / targets.length
    const sourceInventory = await Promise.all(
      [
        "packages/core/src/contracts.ts",
        "packages/core/src/immutability.ts",
        "packages/core/src/replay.ts",
        "packages/core/src/session.ts",
        "packages/core/src/work-run.ts",
        "packages/core/src/work-run-events.ts",
      ].map((path) => digestFile(root, path)),
    )
    const definitions = await digestFile(root, s2MutationDefinitionsPath)
    const runner = await digestFile(root, s2MutationRunnerPath)
    const runnerSupport = await digestFile(root, s2MutationRunnerSupportPath)
    const tests = await digestFile(root, s2MutationTestPath)
    const fixturesPass =
      fixtures.some((item) => item.id === "fixture-killed" && item.outcome === "killed") &&
      fixtures.some((item) => item.id === "fixture-survived" && item.outcome === "survived")
    const targetOutcomesPass =
      targets.length > 0 && targets.every((target) => target.outcome === "killed")
    const verdict =
      score >= s2MutationThreshold && targetOutcomesPass && fixturesPass
        ? "APPROVED"
        : "CHANGES_REQUESTED"
    return {
      schema: "gorce.s2.mutation-gate/v2",
      verdict,
      command: s2MutationCommand,
      threshold: s2MutationThreshold,
      critical_target_categories: s2MutationCategories,
      source_commit: sourceCommit(root),
      source_inventory: sourceInventory,
      mutation_definitions: definitions,
      runner,
      runner_support: runnerSupport,
      semantic_tests: tests,
      targets,
      fixtures,
      score,
      execution: "isolated-temporary-copy",
      coverage_claim: "all declared S2 critical reducer targets",
      reason:
        verdict === "APPROVED"
          ? "isolated runner killed all declared critical mutants and qualified killed/survived fixtures"
          : "mutation score, target count, or fixture qualification is below the S2 gate",
    }
  } finally {
    await disposeMutationSandbox(sandbox)
  }
}
