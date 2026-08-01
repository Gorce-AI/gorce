// biome-ignore-all lint/complexity/useLiteralKeys: Cutover manifests are validated through JSON keys.
import { createHash } from "node:crypto"
import { readFile, readdir } from "node:fs/promises"
import { join } from "node:path"
import {
  bunVersion,
  currentTask6BaselineSha256,
  provenance,
  task6BaselineSha256,
} from "./s1-native.js"
import { checkS1Cutover } from "./s1-cutover.js"
import { inspectMutationApplicability } from "./mutation.js"
export interface S1Check {
  readonly name: string
  readonly ok: boolean
  readonly code: string
  readonly reason: string
}
export interface S1Evidence {
  readonly schema: "gorce.s1.cutover/v1"
  readonly verdict: "APPROVED" | "CHANGES_REQUESTED"
  readonly workspace_manifest_sha256: string
  readonly source_commit: string
  readonly task6_baseline_sha256: string
  readonly builder_bun: string
  readonly release_claim: false
  readonly scope: string
  readonly checks: readonly S1Check[]
}
export interface S1Report {
  readonly evidence: S1Evidence
  readonly errors: readonly string[]
}
export const validateS1Provenance = (
  runtimeVersion: string,
  baselineDigest: string,
  actualBaselineDigest: string,
): readonly string[] => {
  const errors: string[] = []
  if (runtimeVersion !== bunVersion) errors.push(`Bun runtime must be ${bunVersion}`)
  if (baselineDigest !== actualBaselineDigest) errors.push("Task 6 baseline digest is not current")
  if (baselineDigest !== task6BaselineSha256)
    errors.push("Task 6 baseline digest is not the approved baseline")
  return errors
}
const packagePaths = ["packages/core", "packages/tui-harness", "apps/tui-harness"] as const
const json = async (path: string): Promise<Record<string, unknown>> => {
  const value: unknown = JSON.parse(await readFile(path, "utf8"))
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error(`${path}: JSON object required`)
  return value as Record<string, unknown>
}

const object = (value: unknown): Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}

const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map((item) => canonical(item)).join(",")}]`
  if (typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`)
      .join(",")}}`
  }
  return JSON.stringify(value)
}

const exactObject = (actual: unknown, expected: Record<string, unknown>): boolean =>
  canonical(actual) === canonical(expected)

const check = (
  checks: S1Check[],
  errors: string[],
  name: string,
  ok: boolean,
  code: string,
  reason: string,
): void => {
  checks.push({ name, ok, code, reason })
  if (!ok) errors.push(`${code}: ${reason}`)
}

const checkWorkspace = async (root: string, checks: S1Check[], errors: string[]): Promise<void> => {
  const manifest = await json(join(root, "package.json"))
  const workspaces = manifest["workspaces"]
  check(
    checks,
    errors,
    "workspace-root-manifest",
    manifest["private"] === true &&
      manifest["version"] === "0.0.0" &&
      manifest["type"] === "module" &&
      manifest["packageManager"] === "bun@1.3.14" &&
      Object.keys(object(manifest["dependencies"])).length === 0,
    "S1_WORKSPACE_ROOT",
    "the root workspace must be private, Bun-pinned, ESM, and dependency-free",
  )
  check(
    checks,
    errors,
    "workspace-patterns",
    JSON.stringify(workspaces) === JSON.stringify(["packages/*", "apps/*"]),
    "S1_WORKSPACE_PATTERNS",
    "workspace patterns must be exactly packages/* and apps/*",
  )
  const packageEntries = await readdir(join(root, "packages"))
  const appEntries = await readdir(join(root, "apps"))
  check(
    checks,
    errors,
    "workspace-layout",
    JSON.stringify(packageEntries.sort()) === JSON.stringify(["core", "tui-harness"]) &&
      JSON.stringify(appEntries.sort()) === JSON.stringify(["tui-harness"]),
    "S1_WORKSPACE_LAYOUT",
    "the workspace must contain exactly core, tui-harness, and the tui-harness app",
  )
  const expected: Record<string, Record<string, unknown>> = {
    "packages/core": {
      name: "@gorce-ai/core",
      version: "0.0.0",
      private: true,
      type: "module",
      dependencies: {},
      exports: { ".": "./src/index.ts" },
      types: "./src/index.ts",
    },
    "packages/tui-harness": {
      name: "@gorce-ai/tui-harness",
      version: "0.0.0",
      private: true,
      type: "module",
      dependencies: { "@gorce-ai/core": "workspace:*" },
      exports: { ".": "./src/index.ts" },
      types: "./src/index.ts",
    },
    "apps/tui-harness": {
      name: "@gorce-ai/gorce-tui-harness",
      version: "0.0.0",
      private: true,
      type: "module",
      dependencies: { "@gorce-ai/tui-harness": "workspace:*" },
      bin: { "gorce-tui-harness": "./src/main.ts" },
    },
  }
  for (const path of packagePaths) {
    const actual = await json(join(root, `${path}/package.json`))
    const expectedManifest = expected[path] ?? {}
    const dependencies = object(actual["dependencies"])
    const known: Record<string, unknown> = { ...actual, dependencies }
    check(
      checks,
      errors,
      `package:${path}`,
      exactObject(known, expectedManifest),
      "S1_PACKAGE_MANIFEST",
      `${path}/package.json must match the approved private package contract`,
    )
  }
  const importRules: Record<string, readonly string[]> = {
    "packages/core": [],
    "packages/tui-harness": ["@gorce-ai/core"],
    "apps/tui-harness": ["@gorce-ai/tui-harness"],
  }
  for (const path of packagePaths) {
    const sourcePath = path === "apps/tui-harness" ? `${path}/src/main.ts` : `${path}/src/index.ts`
    const source = await readFile(join(root, sourcePath), "utf8")
    const imports = [...source.matchAll(/(?:from|import)\s*["']([^"']+)["']/g)].map(
      (match) => match[1] ?? "",
    )
    check(
      checks,
      errors,
      `imports:${path}`,
      imports.every((name) => importRules[path]?.includes(name) === true),
      "S1_DEPENDENCY_DIRECTION",
      `${path} imports must follow the exact app -> harness -> core direction`,
    )
  }
}

export const verifyS1 = async (root: string): Promise<S1Report> => {
  const checks: S1Check[] = []
  const errors: string[] = []
  let manifestHash = "0".repeat(64)
  try {
    const manifest = await readFile(join(root, "package.json"))
    manifestHash = createHash("sha256").update(manifest).digest("hex")
    await checkWorkspace(root, checks, errors)
    await checkS1Cutover(root, checks, errors)
    const evidenceProvenance = provenance(root)
    const provenanceErrors = validateS1Provenance(
      evidenceProvenance.builder_bun,
      evidenceProvenance.task6_baseline_sha256,
      currentTask6BaselineSha256(root),
    )
    check(
      checks,
      errors,
      "s1-provenance",
      provenanceErrors.length === 0 && /^[0-9a-f]{40}$/.test(evidenceProvenance.source_commit),
      "S1_PROVENANCE",
      provenanceErrors.length === 0
        ? "source commit, Bun runtime, and Task 6 baseline are current"
        : provenanceErrors.join("; "),
    )
    const mutation = await inspectMutationApplicability(root)
    check(
      checks,
      errors,
      "mutation-gate-applicability",
      mutation.applicable,
      "S1_MUTATION_APPLICABILITY",
      mutation.reason,
    )
  } catch (error: unknown) {
    const reason =
      error instanceof Error ? error.message : "S1 verifier failed before a stable result"
    check(checks, errors, "verifier-execution", false, "S1_VERIFIER_EXECUTION", reason)
  }
  return {
    evidence: {
      schema: "gorce.s1.cutover/v1",
      verdict: errors.length === 0 ? "APPROVED" : "CHANGES_REQUESTED",
      workspace_manifest_sha256: manifestHash,
      ...provenance(root),
      checks,
    },
    errors,
  }
}
