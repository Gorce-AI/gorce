import { readdir, readFile } from "node:fs/promises"
import { createHash } from "node:crypto"
import { join, relative } from "node:path"
import { currentTask6BaselineSha256 } from "./s1-native.js"

export const mutationCommand = "bun run test:mutation" as const
export const mutationReason = "S1_NO_CRITICAL_MUTATION_TARGETS" as const
export const criticalMutationCategories = [
  "reducers",
  "policy",
  "compatibility",
  "persistence",
  "reconciliation",
] as const
export const s1ProductionInventory = [
  "apps/tui-harness/src/main.ts",
  "packages/core/src/index.ts",
  "packages/tui-harness/src/index.ts",
] as const
export const s1ProductionInventoryDigests = {
  "apps/tui-harness/src/main.ts":
    "29c53d27381512c86e8be1cecaac20c0b8d0040eddfc61b05db1601c05b2ea71",
  "packages/core/src/index.ts": "49bf731dd3c0a7d53c074e02f8304eb62d07536dbfa680a43ab2748f53711695",
  "packages/tui-harness/src/index.ts":
    "2f90c0b1e80f6a5d85cd7e15745c32c8015518a26817057b15d12846e6956920",
} as const

const semanticTarget =
  /\b(?:Session|WorkRun|reducer|replay|storage|recovery|conflict|provider|WebSocket|PTY|render|stdin|input)\b/i

const sourceFiles = async (root: string): Promise<readonly string[]> => {
  const files: string[] = []
  const visit = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isDirectory()) await visit(path)
      else if (entry.isFile()) files.push(relative(root, path))
    }
  }
  for (const directory of ["packages/core/src", "packages/tui-harness/src", "apps/tui-harness/src"])
    await visit(join(root, directory))
  return files.sort()
}

export interface MutationApplicability {
  readonly applicable: boolean
  readonly inventory: readonly string[]
  readonly digests: Readonly<Record<string, string>>
  readonly reason: string
}

export const inspectMutationApplicability = async (
  root: string,
): Promise<MutationApplicability> => {
  const inventory = await sourceFiles(root)
  const sources = await Promise.all(inventory.map((path) => readFile(join(root, path), "utf8")))
  const digests = Object.fromEntries(
    inventory.map((path, index) => [
      path,
      createHash("sha256")
        .update(sources[index] ?? "")
        .digest("hex"),
    ]),
  )
  if (
    JSON.stringify(inventory) !== JSON.stringify(s1ProductionInventory) ||
    JSON.stringify(digests) !== JSON.stringify(s1ProductionInventoryDigests)
  )
    return {
      applicable: false,
      inventory,
      digests,
      reason:
        "S1 mutation N/A invalidated; exact allowed S1 source content changed and a real non-vacuous >=90% mutation runner is required",
    }
  if (sources.some((source) => semanticTarget.test(source)))
    return {
      applicable: false,
      inventory,
      digests,
      reason:
        "S1 mutation N/A invalidated; a real non-vacuous >=90% mutation runner is required for the semantic target",
    }
  return { applicable: true, inventory, digests, reason: mutationReason }
}

export interface MutationEvidence {
  readonly schema: "gorce.s1.mutation-gate/v1"
  readonly verdict: "NOT_APPLICABLE"
  readonly baseline_sha256: string
  readonly command: typeof mutationCommand
  readonly critical_target_categories: typeof criticalMutationCategories
  readonly production_inventory: typeof s1ProductionInventory
  readonly production_source_digests: typeof s1ProductionInventoryDigests
  readonly targets: readonly []
  readonly score: null
  readonly runner: null
  readonly coverage_claim: null
  readonly reason: typeof mutationReason
}

export const mutationEvidence = (root: string): MutationEvidence => ({
  schema: "gorce.s1.mutation-gate/v1",
  verdict: "NOT_APPLICABLE",
  baseline_sha256: currentTask6BaselineSha256(root),
  command: mutationCommand,
  critical_target_categories: criticalMutationCategories,
  production_inventory: s1ProductionInventory,
  production_source_digests: s1ProductionInventoryDigests,
  targets: [],
  score: null,
  runner: null,
  coverage_claim: null,
  reason: mutationReason,
})
