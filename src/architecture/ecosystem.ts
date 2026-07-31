import { readdir, readFile } from "node:fs/promises"
import { basename, join, relative, resolve } from "node:path"
import { readCanonicalYaml } from "./yaml.js"
import {
  TECHNOLOGY_BASELINE_SCHEMA,
  BUN_VERSION,
  BIOME_VERSION,
  PACKAGE_MANAGER_DECLARATION,
  TYPESCRIPT_VERSION,
} from "./rules.js"
import type { CheckResult, VerificationReport } from "../verification/types.js"

export interface EcosystemVerificationOptions {
  readonly coreRoot: string
  readonly studioRoot: string
  readonly jetbrainsRoot: string
  readonly technologyBaseline: string
  readonly coreInventoryBan: readonly string[]
  readonly publishedOnly: boolean
}

const ignoredDirectories = new Set([
  ".git",
  ".omo",
  "node_modules",
  "dist",
  "target",
  "docs",
  "tests",
  "architecture",
])
const alternateLocks = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lockb",
])
const verifierFiles = new Set([
  "src/architecture/ecosystem.ts",
  "src/commands/verify-architecture.ts",
  "src/commands/verify-architecture-ecosystem.ts",
  "src/verification/f2.ts",
])

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value)

const addCheck = (
  checks: CheckResult[],
  errors: string[],
  name: string,
  ok: boolean,
  detail: string,
): void => {
  checks.push({ name, status: ok ? "passed" : "failed", ...(ok ? {} : { detail }) })
  if (!ok) errors.push(`${name}: ${detail}`)
}

const walk = async (root: string): Promise<readonly string[]> => {
  const files: string[] = []
  const visit = async (directory: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true })
    for (const entry of entries) {
      const path = join(directory, entry.name)
      if (entry.isSymbolicLink()) throw new Error(`symlink is not allowed: ${relative(root, path)}`)
      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) await visit(path)
      } else if (
        entry.isFile() &&
        !ignoredDirectories.has(entry.name) &&
        !verifierFiles.has(relative(root, path))
      ) {
        files.push(path)
      }
    }
  }
  await visit(root)
  return files
}

const readJson = async (path: string): Promise<Record<string, unknown>> => {
  const value: unknown = JSON.parse(await readFile(path, "utf8"))
  if (!isRecord(value)) throw new Error(`${path}: JSON root must be an object`)
  return value
}

const packageManager = (manifest: Record<string, unknown>): string | null =>
  typeof manifest["packageManager"] === "string" ? (manifest["packageManager"] as string) : null

const collectProductionText = async (
  root: string,
): Promise<readonly { readonly path: string; readonly text: string }[]> => {
  const files = await walk(root)
  return Promise.all(files.map(async (path) => ({ path, text: await readFile(path, "utf8") })))
}

const checkRequiredLayout = async (
  options: EcosystemVerificationOptions,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  const roots = [options.coreRoot, options.studioRoot, options.jetbrainsRoot]
  let rootsExist = true
  for (const root of roots) {
    try {
      const entries = await readdir(root)
      if (entries.length === 0) rootsExist = false
    } catch {
      rootsExist = false
    }
  }
  const coreParent = resolve(options.coreRoot, "..")
  const siblingNames =
    basename(options.coreRoot) === "gorce" &&
    basename(options.studioRoot) === "gorce-studio" &&
    basename(options.jetbrainsRoot) === "gorce-jetbrains" &&
    resolve(options.studioRoot, "..") === coreParent &&
    resolve(options.jetbrainsRoot, "..") === coreParent
  addCheck(
    checks,
    errors,
    "sibling-layout",
    rootsExist && siblingNames,
    "core, Studio, and JetBrains must be existing sovereign siblings",
  )
  if (!rootsExist || !siblingNames) return
  try {
    await readJson(join(options.coreRoot, "package.json"))
    await readJson(join(options.studioRoot, "package.json"))
    await readFile(join(options.jetbrainsRoot, "build.gradle.kts"), "utf8")
    addCheck(checks, errors, "sovereign-manifests", true, "")
  } catch (error: unknown) {
    addCheck(
      checks,
      errors,
      "sovereign-manifests",
      false,
      error instanceof Error ? error.message : "required sibling manifest is missing",
    )
  }
}

const checkTechnology = async (
  options: EcosystemVerificationOptions,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  try {
    const baselinePath = join(options.coreRoot, "architecture/typescript-bun-baseline.v1.yaml")
    const baseline = await readCanonicalYaml(baselinePath, TECHNOLOGY_BASELINE_SCHEMA)
    addCheck(
      checks,
      errors,
      "technology-baseline-digest",
      baseline.sha256 === options.technologyBaseline,
      "technology baseline digest mismatch",
    )
    const corePackage = await readJson(join(options.coreRoot, "package.json"))
    const studioPackage = await readJson(join(options.studioRoot, "package.json"))
    const exactCore =
      packageManager(corePackage) === PACKAGE_MANAGER_DECLARATION &&
      packageManager(studioPackage) === PACKAGE_MANAGER_DECLARATION &&
      corePackage["type"] === "module" &&
      studioPackage["type"] === "module"
    const coreDev = isRecord(corePackage["devDependencies"]) ? corePackage["devDependencies"] : {}
    const studioDev = isRecord(studioPackage["devDependencies"])
      ? studioPackage["devDependencies"]
      : {}
    const versions =
      coreDev["typescript"] === TYPESCRIPT_VERSION &&
      coreDev["@biomejs/biome"] === BIOME_VERSION &&
      studioDev["typescript"] === TYPESCRIPT_VERSION &&
      studioDev["@biomejs/biome"] === BIOME_VERSION
    addCheck(
      checks,
      errors,
      "technology-versions",
      exactCore && versions,
      `Bun ${BUN_VERSION}, TypeScript ${TYPESCRIPT_VERSION}, and Biome ${BIOME_VERSION} are required in core and Studio`,
    )
    const rootEntries = await readdir(options.coreRoot)
    const studioEntries = await readdir(options.studioRoot)
    const badLocks = [...rootEntries, ...studioEntries].filter((entry) => alternateLocks.has(entry))
    addCheck(
      checks,
      errors,
      "sibling-lock-policy",
      badLocks.length === 0,
      `alternate package-manager locks are forbidden: ${badLocks.join(", ")}`,
    )
  } catch (error: unknown) {
    addCheck(
      checks,
      errors,
      "technology-baseline",
      false,
      error instanceof Error ? error.message : "cannot verify technology baseline",
    )
  }
}

const checkCoreInventoryAndTunneling = async (
  options: EcosystemVerificationOptions,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  try {
    const files = await collectProductionText(options.coreRoot)
    const violations: string[] = []
    for (const { path, text } of files) {
      const relativePath = relative(options.coreRoot, path)
      const lowerPath = relativePath.toLowerCase()
      if (/(^|[/_-])(studio|jetbrains)([/_.-]|$)|gorce-(studio|jetbrains)/i.test(relativePath)) {
        violations.push(`${relativePath}: product inventory in core`)
        continue
      }
      if (
        ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"].includes(relativePath) ||
        relativePath.startsWith("crates/")
      )
        continue
      if (
        /gorce-(studio|jetbrains)|@gorce-ai\/(studio|jetbrains)|(?:file|git|workspace):|compositeBuild|includeBuild/i.test(
          text,
        )
      ) {
        violations.push(`${relativePath}: source tunneling or package inversion`)
      }
      if (
        lowerPath.startsWith("src/") &&
        /from\s+["'][^"']*(studio|jetbrains)[^"']*["']/i.test(text)
      ) {
        violations.push(`${relativePath}: source imports a product repository`)
      }
    }
    const banned = options.coreInventoryBan.map((value) => value.toLowerCase())
    const explicitInventory = files.filter(({ path }) =>
      banned.some((name) => relativePathContains(path, options.coreRoot, name)),
    )
    violations.push(
      ...explicitInventory.map(
        ({ path }) => `${relative(options.coreRoot, path)}: explicitly banned inventory`,
      ),
    )
    addCheck(
      checks,
      errors,
      "core-inventory-and-tunneling",
      violations.length === 0,
      violations.join("; "),
    )
  } catch (error: unknown) {
    addCheck(
      checks,
      errors,
      "core-inventory-and-tunneling",
      false,
      error instanceof Error ? error.message : "cannot scan core production tree",
    )
  }
}

const relativePathContains = (path: string, root: string, name: string): boolean =>
  relative(root, path)
    .toLowerCase()
    .split(/[\\/_.-]+/)
    .includes(name)

const checkEntrypointsAndHostOwnership = async (
  options: EcosystemVerificationOptions,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  try {
    const manifest = await readJson(join(options.coreRoot, "package.json"))
    const alternateEntrypointKeys = ["main", "module", "browser", "bin", "exports"].filter((key) =>
      Object.hasOwn(manifest, key),
    )
    addCheck(
      checks,
      errors,
      "core-entrypoint",
      alternateEntrypointKeys.length === 0,
      "core must not introduce an alternate entrypoint during the foundation task",
    )
    const files = await collectProductionText(options.coreRoot)
    const displaced = files.filter(({ path }) =>
      /(?:jetbrains|kotlin|gradle|host-code)/i.test(relative(options.coreRoot, path)),
    )
    addCheck(
      checks,
      errors,
      "jetbrains-host-ownership",
      displaced.length === 0,
      displaced.map(({ path }) => relative(options.coreRoot, path)).join(", "),
    )
  } catch (error: unknown) {
    addCheck(
      checks,
      errors,
      "core-entrypoint",
      false,
      error instanceof Error ? error.message : "cannot verify core entrypoint",
    )
  }
}

const checkPublishedOnly = async (
  options: EcosystemVerificationOptions,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  if (!options.publishedOnly) {
    addCheck(
      checks,
      errors,
      "published-only",
      false,
      "--published-only is required; source checkouts are never accepted",
    )
    return
  }
  try {
    const files = [
      ...(await collectProductionText(options.studioRoot)),
      ...(await collectProductionText(options.jetbrainsRoot)),
    ]
    const sourceReferences = files.filter(({ text }) =>
      /(?:file|git|workspace):|\.\.\/gorce(?:["'/]|$)|includeBuild/i.test(text),
    )
    addCheck(
      checks,
      errors,
      "published-artifacts-only",
      sourceReferences.length === 0,
      "siblings must consume published immutable artifacts only",
    )
  } catch (error: unknown) {
    addCheck(
      checks,
      errors,
      "published-artifacts-only",
      false,
      error instanceof Error ? error.message : "cannot inspect sibling artifacts",
    )
  }
}

export const verifyEcosystem = async (
  options: EcosystemVerificationOptions,
): Promise<VerificationReport> => {
  const checks: CheckResult[] = []
  const errors: string[] = []
  await checkRequiredLayout(options, checks, errors)
  if (checks.find((item) => item.name === "sibling-layout")?.status === "passed") {
    await checkTechnology(options, checks, errors)
    await checkCoreInventoryAndTunneling(options, checks, errors)
    await checkEntrypointsAndHostOwnership(options, checks, errors)
    await checkPublishedOnly(options, checks, errors)
  }
  return {
    schema: "gorce.verification-result/v1",
    command: "verify:architecture:ecosystem",
    ok: errors.length === 0,
    checks,
    errors,
  }
}
