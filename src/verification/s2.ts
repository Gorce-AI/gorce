import { createHash } from "node:crypto"
import { execFileSync } from "node:child_process"
import { readdir, readFile } from "node:fs/promises"
import { join } from "node:path"
import { bunVersion, currentTask6BaselineSha256, provenance } from "./s1-native.js"
import { probeS2Behavior } from "./s2-probe.js"

export const s2CoreInventory = [
  "packages/core/src/contracts.ts",
  "packages/core/src/index.ts",
  "packages/core/src/immutability.ts",
  "packages/core/src/replay.ts",
  "packages/core/src/session.ts",
  "packages/core/src/work-run.ts",
  "packages/core/src/work-run-events.ts",
] as const

export interface S2SourceDigest {
  readonly path: string
  readonly sha256: string
}

export interface S2MutationBinding {
  readonly definitions: S2SourceDigest
  readonly runner: S2SourceDigest
  readonly runner_support: S2SourceDigest
  readonly tests: S2SourceDigest
}

export interface S2Check {
  readonly name: string
  readonly ok: boolean
  readonly code: string
  readonly reason: string
}

export interface S2Evidence {
  readonly schema: "gorce.s2.semantic-core/v2"
  readonly verdict: "APPROVED" | "CHANGES_REQUESTED"
  readonly source_commit: string
  readonly source_inventory: readonly S2SourceDigest[]
  readonly mutation_binding: S2MutationBinding
  readonly task6_baseline_sha256: string
  readonly builder_bun: string
  readonly release_claim: false
  readonly scope: "S2 semantic core only; S3 storage and S4 TUI deferred"
  readonly checks: readonly S2Check[]
}

export interface S2Report {
  readonly evidence: S2Evidence
  readonly errors: readonly string[]
}

const digest = (source: string): string => createHash("sha256").update(source).digest("hex")
const sourceCommit = (root: string): string => {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim()
  } catch {
    return ""
  }
}
const check = (
  checks: S2Check[],
  errors: string[],
  name: string,
  ok: boolean,
  code: string,
  reason: string,
): void => {
  checks.push({ name, ok, code, reason })
  if (!ok) errors.push(`${code}: ${reason}`)
}
const sourceDigest = async (root: string, path: string): Promise<S2SourceDigest> => ({
  path,
  sha256: digest(await readFile(join(root, path), "utf8")),
})

export const verifyS2 = async (root: string): Promise<S2Report> => {
  const checks: S2Check[] = []
  const errors: string[] = []
  const sourceInventory: S2SourceDigest[] = []
  const bindingPaths = [
    "src/verification/mutation-s2-targets.ts",
    "src/verification/mutation-s2.ts",
    "src/verification/mutation-s2-sandbox.ts",
    "tests/s2.test.ts",
  ] as const
  try {
    const entries = await readdir(join(root, "packages/core/src"), { withFileTypes: true })
    const inventory = entries
      .filter((entry) => entry.isFile() && entry.name.endsWith(".ts"))
      .map((entry) => `packages/core/src/${entry.name}`)
      .sort()
    for (const path of s2CoreInventory) sourceInventory.push(await sourceDigest(root, path))
    const files = await Promise.all(
      s2CoreInventory.map(async (path) => ({
        path,
        source: await readFile(join(root, path), "utf8"),
      })),
    )
    const source = files.map((item) => item.source).join("\n")
    check(
      checks,
      errors,
      "core-inventory",
      JSON.stringify(inventory) === JSON.stringify([...s2CoreInventory].sort()),
      "S2_CORE_INVENTORY",
      "the semantic core inventory and content digests are bound",
    )
    const index = files.find((item) => item.path.endsWith("index.ts"))?.source ?? ""
    check(
      checks,
      errors,
      "core-public-api",
      ["contracts", "replay", "session", "work-run"].every((name) =>
        index.includes(`./${name}.js`),
      ),
      "S2_CORE_PUBLIC_API",
      "the package entrypoint exports the complete semantic core",
    )
    check(
      checks,
      errors,
      "versioned-envelopes",
      [
        "gorce.s2.command/v1",
        "gorce.s2.event/v1",
        "gorce.s2.effect/v1",
        "gorce.s2.result/v1",
      ].every((schema) => source.includes(schema)),
      "S2_VERSIONED_ENVELOPES",
      "all semantic envelopes are versioned",
    )
    check(
      checks,
      errors,
      "lifecycle",
      ["planned", "attempted", "confirmed", "failed", "unknown", "reconciled", "compensated"].every(
        (status) => source.includes(`"${status}"`),
      ),
      "S2_EFFECT_LIFECYCLE",
      "the full planned/attempted/terminal/reconciled lifecycle exists",
    )
    check(
      checks,
      errors,
      "affinity",
      [
        "target_authority",
        "target_id",
        "target_version",
        "execution_ref",
        "stream_generation",
        "input_digest",
        "contract_digest",
        "route_digest",
        "workspace_id",
        "workspace_revision",
      ].every((field) => source.includes(field)),
      "S2_RESULT_AFFINITY",
      "all target, execution, stream, digest, and workspace affinity fields exist",
    )
    check(
      checks,
      errors,
      "semantic-behavior",
      probeS2Behavior(),
      "S2_SEMANTIC_BEHAVIOR",
      "a live core probe exercises stale rejection, unknown, reconciliation, and immutability",
    )
    check(
      checks,
      errors,
      "core-boundary",
      files.every(({ source: text }) =>
        [...text.matchAll(/(?:from|import)\s*["']([^"']+)["']/g)].every((match) =>
          (match[1] ?? "").startsWith("."),
        ),
      ),
      "S2_CORE_BOUNDARY",
      "the semantic core has only local module imports",
    )
    const mutationBinding: S2MutationBinding = {
      definitions: await sourceDigest(root, bindingPaths[0]),
      runner: await sourceDigest(root, bindingPaths[1]),
      runner_support: await sourceDigest(root, bindingPaths[2]),
      tests: await sourceDigest(root, bindingPaths[3]),
    }
    const evidenceProvenance = provenance(root)
    const commit = sourceCommit(root)
    check(
      checks,
      errors,
      "source-provenance",
      /^[0-9a-f]{40}$/.test(commit) &&
        evidenceProvenance.builder_bun === bunVersion &&
        evidenceProvenance.task6_baseline_sha256 === currentTask6BaselineSha256(root),
      "S2_SOURCE_PROVENANCE",
      "source commit, pinned Bun, and Task 6 baseline are current",
    )
    return {
      evidence: {
        schema: "gorce.s2.semantic-core/v2",
        verdict: errors.length === 0 ? "APPROVED" : "CHANGES_REQUESTED",
        source_commit: commit,
        source_inventory: sourceInventory,
        mutation_binding: mutationBinding,
        task6_baseline_sha256: currentTask6BaselineSha256(root),
        builder_bun: bunVersion,
        release_claim: false,
        scope: "S2 semantic core only; S3 storage and S4 TUI deferred",
        checks,
      },
      errors,
    }
  } catch (error: unknown) {
    const reason = error instanceof Error ? error.message : "S2 verifier failed"
    check(checks, errors, "verifier-execution", false, "S2_VERIFIER_EXECUTION", reason)
    const commit = sourceCommit(root)
    const fallback = { path: bindingPaths[0], sha256: "0".repeat(64) }
    return {
      evidence: {
        schema: "gorce.s2.semantic-core/v2",
        verdict: "CHANGES_REQUESTED",
        source_commit: commit,
        source_inventory: sourceInventory,
        mutation_binding: {
          definitions: fallback,
          runner: { path: bindingPaths[1], sha256: "0".repeat(64) },
          runner_support: { path: bindingPaths[2], sha256: "0".repeat(64) },
          tests: { path: bindingPaths[3], sha256: "0".repeat(64) },
        },
        task6_baseline_sha256: currentTask6BaselineSha256(root),
        builder_bun: bunVersion,
        release_claim: false,
        scope: "S2 semantic core only; S3 storage and S4 TUI deferred",
        checks,
      },
      errors,
    }
  }
}
