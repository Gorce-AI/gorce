// biome-ignore-all lint/complexity/useLiteralKeys: JSON manifests are accessed by structural keys.

import { execFileSync } from "node:child_process"
import { readdir, readFile, realpath } from "node:fs/promises"
import { basename, join, relative, resolve } from "node:path"
import { readCanonicalYaml } from "./yaml.js"
import {
  TECHNOLOGY_BASELINE_SCHEMA,
  BUN_VERSION,
  BIOME_VERSION,
  PACKAGE_MANAGER_DECLARATION,
  TYPESCRIPT_VERSION,
} from "./rules.js"
import {
  codeExtensions,
  collectManifests,
  collectProductionFiles,
  gradleSourceCall,
  importSpecifications,
  isRecord,
  isSiblingPackage,
  manifestDependencyEntries,
  relativeImportEscapesRoot,
  relativePathContains,
  runtimeFinding,
  isSourceDependency,
} from "./ecosystem-structural.js"
import type { CheckResult, VerificationReport } from "../verification/types.js"

export interface EcosystemVerificationOptions {
  readonly coreRoot: string
  readonly studioRoot: string
  readonly jetbrainsRoot: string
  readonly technologyBaseline: string
  readonly coreInventoryBan: readonly string[]
  readonly publishedOnly: boolean
}

const alternateLocks = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lockb",
])

const addCheck = (
  checks: CheckResult[],
  errors: string[],
  name: string,
  ok: boolean,
  detail: string,
  failureCode = `ECO_${name.replaceAll("-", "_").toUpperCase()}`,
): void => {
  checks.push({ name, status: ok ? "passed" : "failed", ...(ok ? {} : { detail }) })
  if (!ok) errors.push(`${failureCode}: ${detail}`)
}

const readJson = async (path: string): Promise<Record<string, unknown>> => {
  const value: unknown = JSON.parse(await readFile(path, "utf8"))
  if (!isRecord(value)) throw new Error(`${path}: JSON root must be an object`)
  return value
}

const packageManager = (manifest: Record<string, unknown>): string | null =>
  typeof manifest["packageManager"] === "string" ? (manifest["packageManager"] as string) : null

const repositoryIdentity = (origin: string): string =>
  origin
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/^ssh:\/\//i, "")
    .replace(/^[^@]+@/, "")
    .replace(":", "/")
    .replace(/\.git$/, "")
    .replace(/\/$/, "")
    .toLowerCase()

const gitOutput = (root: string, args: readonly string[]): string =>
  execFileSync("git", ["-C", root, ...args], { encoding: "utf8" }).trim()

const checkGitTrees = async (
  options: EcosystemVerificationOptions,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  const repositories = [
    { name: "core", root: options.coreRoot, identity: "github.com/gorce-ai/gorce" },
    { name: "studio", root: options.studioRoot, identity: "github.com/gorce-ai/gorce-studio" },
    {
      name: "jetbrains",
      root: options.jetbrainsRoot,
      identity: "github.com/gorce-ai/gorce-jetbrains",
    },
  ] as const
  for (const repository of repositories) {
    try {
      const topLevel = resolve(gitOutput(repository.root, ["rev-parse", "--show-toplevel"]))
      const status = gitOutput(repository.root, ["status", "--porcelain", "--untracked-files=all"])
      const origin = repositoryIdentity(gitOutput(repository.root, ["remote", "get-url", "origin"]))
      const expectedRoot = resolve(await realpath(repository.root))
      addCheck(
        checks,
        errors,
        `git-clean:${repository.name}`,
        topLevel === expectedRoot && status.length === 0,
        "repository must be a clean Git tree",
        "ECO_DIRTY_REPOSITORY",
      )
      addCheck(
        checks,
        errors,
        `git-identity:${repository.name}`,
        origin === repository.identity,
        `repository origin must identify ${repository.identity}`,
        "ECO_REPOSITORY_IDENTITY",
      )
    } catch {
      addCheck(
        checks,
        errors,
        `git-clean:${repository.name}`,
        false,
        "repository must be an existing Git tree with an origin identity",
        "ECO_REPOSITORY_IDENTITY",
      )
    }
  }
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
      if ((await readdir(root)).length === 0) rootsExist = false
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
    "ECO_SIBLING_LAYOUT",
  )
  if (!rootsExist || !siblingNames) return
  try {
    await readJson(join(options.coreRoot, "package.json"))
    await readJson(join(options.studioRoot, "package.json"))
    await readFile(join(options.jetbrainsRoot, "build.gradle.kts"), "utf8")
    addCheck(checks, errors, "sovereign-manifests", true, "", "ECO_SOVEREIGN_MANIFESTS")
  } catch (error: unknown) {
    addCheck(
      checks,
      errors,
      "sovereign-manifests",
      false,
      error instanceof Error ? error.message : "required sibling manifest is missing",
      "ECO_SOVEREIGN_MANIFESTS",
    )
  }
}

const checkTechnology = async (
  options: EcosystemVerificationOptions,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  try {
    const baseline = await readCanonicalYaml(
      join(options.coreRoot, "architecture/typescript-bun-baseline.v1.yaml"),
      TECHNOLOGY_BASELINE_SCHEMA,
    )
    addCheck(
      checks,
      errors,
      "technology-baseline-digest",
      baseline.sha256 === options.technologyBaseline,
      "technology baseline digest mismatch",
      "ECO_TECHNOLOGY_BASELINE_DIGEST",
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
      "ECO_TECHNOLOGY_VERSION",
    )
    const badLocks = [
      ...(await readdir(options.coreRoot)),
      ...(await readdir(options.studioRoot)),
    ].filter((entry) => alternateLocks.has(entry))
    addCheck(
      checks,
      errors,
      "sibling-lock-policy",
      badLocks.length === 0,
      `alternate package-manager locks are forbidden: ${badLocks.join(", ")}`,
      "ECO_ALTERNATE_PACKAGE_MANAGER",
    )
    const lockPresence = await Promise.all(
      [join(options.coreRoot, "bun.lock"), join(options.studioRoot, "bun.lock")].map(
        async (path) => {
          try {
            await readFile(path)
            return true
          } catch {
            return false
          }
        },
      ),
    )
    addCheck(
      checks,
      errors,
      "committed-bun-locks",
      lockPresence.every(Boolean),
      "core and Studio must each have a committed bun.lock",
      "ECO_LOCKFILE_POLICY",
    )
  } catch (error: unknown) {
    addCheck(
      checks,
      errors,
      "technology-baseline",
      false,
      error instanceof Error ? error.message : "cannot verify technology baseline",
      "ECO_TECHNOLOGY_BASELINE",
    )
  }
}

const checkCoreInventoryAndTunneling = async (
  options: EcosystemVerificationOptions,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  try {
    const files = await collectProductionFiles(options.coreRoot)
    const manifests = collectManifests(files, options.coreRoot)
    const violations = new Map<string, string>()
    const violate = (code: string, reason: string): void => {
      violations.set(code, reason)
    }
    for (const file of files) {
      const pathName = relative(options.coreRoot, file.path)
      const canonicalRule = pathName.startsWith("architecture/")
      if (!canonicalRule && /(?:jetbrains.*host|host-code|kotlin|gradle)/i.test(pathName))
        violate(
          "ECO_JETBRAINS_HOST_DISPLACEMENT",
          "JetBrains host code must remain in the JetBrains repository",
        )
      else if (
        !canonicalRule &&
        /(^|[/_-])(studio|jetbrains)([/_.-]|$)|gorce-(studio|jetbrains)/i.test(pathName)
      )
        violate(
          "ECO_CORE_PRODUCT_INVENTORY",
          "core must not contain Studio or JetBrains production inventory",
        )
      const extension = file.path.slice(file.path.lastIndexOf(".")).toLowerCase()
      if (codeExtensions.has(extension)) {
        for (const spec of importSpecifications(file.text)) {
          if (isSiblingPackage(spec))
            violate(
              "ECO_CORE_PACKAGE_INVERSION",
              "core must not depend on Studio or JetBrains packages",
            )
          else if (relativeImportEscapesRoot(file.path, options.coreRoot, spec))
            violate(
              "ECO_SOURCE_TUNNELING",
              "core must not tunnel to a sibling source tree or unpublished dependency",
            )
        }
      }
    }
    const runtime = await runtimeFinding(files, manifests, options.coreRoot)
    if (runtime !== null)
      violate(
        "ECO_NON_BUN_RUNTIME",
        "core ecosystem trees must use Bun rather than Cargo, Node, Deno, or another runtime",
      )
    for (const manifest of manifests) {
      const dependencies = manifestDependencyEntries(manifest)
      if (dependencies.some(({ name }) => isSiblingPackage(name)))
        violate(
          "ECO_CORE_PACKAGE_INVERSION",
          "core must not depend on Studio or JetBrains packages",
        )
      if (dependencies.some(({ spec }) => isSourceDependency(spec)))
        violate(
          "ECO_SOURCE_TUNNELING",
          "core must not tunnel to a sibling source tree or unpublished dependency",
        )
    }
    const banned = options.coreInventoryBan.map((value) => value.toLowerCase())
    const explicitInventory = files.filter(({ path }) => {
      const pathName = relative(options.coreRoot, path)
      return (
        !pathName.startsWith("architecture/") &&
        banned.some((name) => relativePathContains(path, options.coreRoot, name))
      )
    })
    if (explicitInventory.length > 0)
      violate(
        "ECO_CORE_PRODUCT_INVENTORY",
        "core must not contain Studio or JetBrains production inventory",
      )
    const codes = [...violations.keys()]
    checks.push({
      name: "core-inventory-and-tunneling",
      status: codes.length === 0 ? "passed" : "failed",
      ...(codes.length === 0 ? {} : { detail: codes.join(", ") }),
    })
    if (codes.length > 0) errors.push(...codes.map((code) => `${code}: ${violations.get(code)}`))
  } catch (error: unknown) {
    addCheck(
      checks,
      errors,
      "core-inventory-and-tunneling",
      false,
      error instanceof Error ? error.message : "cannot scan core production tree",
      "ECO_CORE_BOUNDARY",
    )
  }
}

const checkEntrypointsAndHostOwnership = async (
  options: EcosystemVerificationOptions,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  try {
    const manifest = await readJson(join(options.coreRoot, "package.json"))
    const alternate = ["main", "module", "browser"].filter((key) => Object.hasOwn(manifest, key))
    addCheck(
      checks,
      errors,
      "core-entrypoint",
      alternate.length === 0,
      "core must not introduce a Node or non-Bun alternate entrypoint; Bun exports and bin are permitted",
      "ECO_ALTERNATE_CORE_ENTRYPOINT",
    )
    const files = await collectProductionFiles(options.coreRoot)
    const displaced = files.filter(({ path }) =>
      /(?:jetbrains|kotlin|gradle|host-code)/i.test(relative(options.coreRoot, path)),
    )
    addCheck(
      checks,
      errors,
      "jetbrains-host-ownership",
      displaced.length === 0,
      displaced.length === 0 ? "" : "JetBrains host code must remain in the JetBrains repository",
      "ECO_JETBRAINS_HOST_DISPLACEMENT",
    )
  } catch (error: unknown) {
    addCheck(
      checks,
      errors,
      "core-entrypoint",
      false,
      error instanceof Error ? error.message : "cannot verify core entrypoint",
      "ECO_CORE_ENTRYPOINT",
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
    let sourceReference = false
    for (const root of [options.studioRoot, options.jetbrainsRoot]) {
      const files = await collectProductionFiles(root)
      const manifests = collectManifests(files, root)
      sourceReference ||= manifests.some((manifest) =>
        manifestDependencyEntries(manifest).some(({ spec }) => isSourceDependency(spec)),
      )
      sourceReference ||= files.some((file) => {
        if (codeExtensions.has(file.path.slice(file.path.lastIndexOf(".")).toLowerCase()))
          return importSpecifications(file.text).some((spec) =>
            relativeImportEscapesRoot(file.path, root, spec),
          )
        return /\.gradle(?:\.kts)?$/i.test(file.path) && gradleSourceCall(file.text)
      })
    }
    addCheck(
      checks,
      errors,
      "published-artifacts-only",
      !sourceReference,
      "siblings must consume published immutable artifacts only",
      "ECO_PUBLISHED_SOURCE_TUNNELING",
    )
  } catch (error: unknown) {
    addCheck(
      checks,
      errors,
      "published-artifacts-only",
      false,
      error instanceof Error ? error.message : "cannot inspect sibling artifacts",
      "ECO_PUBLISHED_SOURCE_TUNNELING",
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
    await checkGitTrees(options, checks, errors)
    await checkTechnology(options, checks, errors)
    await checkCoreInventoryAndTunneling(options, checks, errors)
    await checkEntrypointsAndHostOwnership(options, checks, errors)
    await checkPublishedOnly(options, checks, errors)
  }
  return {
    schema: "gorce.verification-result/v1",
    command: "verify:architecture:ecosystem",
    ok: errors.length === 0,
    verdict: errors.length === 0 ? "APPROVED" : "CHANGES_REQUESTED",
    checks,
    errors,
  }
}
