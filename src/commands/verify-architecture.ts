import { readdir, readFile } from "node:fs/promises"
import { join, relative, resolve } from "node:path"
import { emit, failed, flag, parseStrictCli, type StrictCliSpec } from "./cli.js"
import {
  BASELINE_SCHEMA_ID,
  STUDIO_CRITERIA,
  STUDIO_GATE_SCHEMA_ID,
  STUDIO_HOST_GATE_SCHEMA,
  TECHNOLOGY_BASELINE_SCHEMA,
} from "../architecture/rules.js"
import { validateStudioHostGate, validateTechnologyBaseline } from "../architecture/semantics.js"
import {
  readCanonicalYaml,
  type CanonicalYamlMap,
  type CanonicalYamlValue,
} from "../architecture/yaml.js"
import type { CheckResult, VerificationReport } from "../verification/types.js"

const cliSpec: StrictCliSpec = {
  flags: ["root"],
  switches: ["strict", "json"],
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
const verifierFiles = new Set([
  "src/architecture/ecosystem.ts",
  "src/commands/verify-architecture.ts",
  "src/commands/verify-architecture-ecosystem.ts",
  "src/verification/f2.ts",
])

const isRecord = (value: unknown): value is CanonicalYamlMap =>
  typeof value === "object" && value !== null && !Array.isArray(value)

const stringAt = (value: CanonicalYamlMap, key: string): string => {
  const child = value[key]
  if (typeof child !== "string") throw new Error(`${key} must be a string`)
  return child
}

const listAt = (value: CanonicalYamlMap, key: string): readonly CanonicalYamlValue[] => {
  const child = value[key]
  if (!Array.isArray(child)) throw new Error(`${key} must be a list`)
  return child
}

const booleanAt = (value: CanonicalYamlMap, key: string): boolean => {
  const child = value[key]
  if (typeof child !== "boolean") throw new Error(`${key} must be a boolean`)
  return child
}

const check = (
  checks: CheckResult[],
  errors: string[],
  name: string,
  ok: boolean,
  detail: string,
): void => {
  checks.push({ name, status: ok ? "passed" : "failed", ...(ok ? {} : { detail }) })
  if (!ok) errors.push(`${name}: ${detail}`)
}

const report = (checks: readonly CheckResult[], errors: readonly string[]): VerificationReport => ({
  schema: "gorce.verification-result/v1",
  command: "verify:architecture",
  ok: errors.length === 0,
  checks,
  errors,
})

const walkProductionFiles = async (root: string): Promise<readonly string[]> => {
  const result: string[] = []
  const visit = async (directory: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true })
    for (const entry of entries) {
      if (entry.isSymbolicLink())
        throw new Error(
          `symlink in production tree: ${relative(root, join(directory, entry.name))}`,
        )
      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) await visit(join(directory, entry.name))
      } else if (entry.isFile()) {
        const path = join(directory, entry.name)
        if (!ignoredDirectories.has(entry.name) && !verifierFiles.has(relative(root, path)))
          result.push(path)
      }
    }
  }
  await visit(root)
  return result
}

const verifyRules = async (
  root: string,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  try {
    const baseline = await readCanonicalYaml(
      join(root, "architecture/typescript-bun-baseline.v1.yaml"),
      TECHNOLOGY_BASELINE_SCHEMA,
    )
    check(
      checks,
      errors,
      "technology-rule",
      baseline.value["schema"] === BASELINE_SCHEMA_ID,
      BASELINE_SCHEMA_ID,
    )
    const semanticErrors = validateTechnologyBaseline(baseline.value)
    check(
      checks,
      errors,
      "technology-rule-semantics",
      semanticErrors.length === 0,
      semanticErrors.join("; "),
    )
  } catch (error: unknown) {
    check(
      checks,
      errors,
      "technology-rule",
      false,
      error instanceof Error ? error.message : "invalid technology rule",
    )
  }
  try {
    const gate = await readCanonicalYaml(
      join(root, "architecture/studio-host-gate.v1.yaml"),
      STUDIO_HOST_GATE_SCHEMA,
    )
    const procedure = gate.value["decision_procedure"]
    const validProcedure =
      isRecord(procedure) &&
      stringAt(gate.value, "schema") === STUDIO_GATE_SCHEMA_ID &&
      stringAt(gate.value, "kind") === "normative-task-31-decision-procedure" &&
      stringAt(procedure, "phase") === "Task 31" &&
      stringAt(procedure, "source_pin") ===
        "Pin latest stable Code-OSS and its exact source commit." &&
      stringAt(procedure, "extension_proof") ===
        "Build a TypeScript extension proof against published contracts." &&
      stringAt(procedure, "extension_api_requirement") ===
        "Every criterion must have a documented stable extension API." &&
      stringAt(procedure, "all_criteria_with_stable_api") === "extension-distribution" &&
      stringAt(procedure, "otherwise") === "fork-required" &&
      booleanAt(procedure, "subjective_override") === false &&
      listAt(procedure, "criteria").length === STUDIO_CRITERIA.length &&
      listAt(procedure, "criteria").every((item, index) => item === STUDIO_CRITERIA[index])
    check(
      checks,
      errors,
      "studio-host-rule",
      validProcedure,
      "the normative Task-31 procedure and all eight criteria are required",
    )
    const semanticErrors = validateStudioHostGate(gate.value, gate.text)
    check(
      checks,
      errors,
      "studio-host-rule-semantics",
      semanticErrors.length === 0,
      semanticErrors.join("; "),
    )
    check(
      checks,
      errors,
      "studio-host-rule-no-outcome",
      !/code-oss[^\n]*\b\d+\.\d+|\b[0-9a-f]{40,64}\b|evaluated[_ -]?outcome|result:/i.test(
        gate.text,
      ),
      "the gate must not contain a Code-OSS version, commit digest, or evaluated result",
    )
  } catch (error: unknown) {
    check(
      checks,
      errors,
      "studio-host-rule",
      false,
      error instanceof Error ? error.message : "invalid Studio host rule",
    )
  }
}

const verifyProductionBoundaries = async (
  root: string,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  try {
    const files = await walkProductionFiles(root)
    const violations: string[] = []
    for (const path of files) {
      const relativePath = relative(root, path)
      const lowerPath = relativePath.toLowerCase()
      if (/(^|[/_-])(studio|jetbrains)([/_.-]|$)|gorce-(studio|jetbrains)/i.test(relativePath)) {
        violations.push(`${relativePath}: product inventory/source path`)
        continue
      }
      if (
        ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"].includes(relativePath) ||
        relativePath.startsWith("crates/")
      )
        continue
      const text = await readFile(path, "utf8")
      if (
        /gorce-(studio|jetbrains)|@gorce-ai\/(studio|jetbrains)|(?:file|git|workspace):|compositeBuild|includeBuild/i.test(
          text,
        )
      ) {
        violations.push(`${relativePath}: product inventory or source tunneling`)
      }
      if (
        lowerPath.startsWith("src/") &&
        /from\s+["'][^"']*(studio|jetbrains)[^"']*["']/i.test(text)
      ) {
        violations.push(`${relativePath}: source imports a product repository`)
      }
    }
    check(
      checks,
      errors,
      "production-boundaries",
      violations.length === 0,
      violations.length === 0 ? "" : violations.join("; "),
    )
  } catch (error: unknown) {
    check(
      checks,
      errors,
      "production-boundaries",
      false,
      error instanceof Error ? error.message : "cannot scan production roots",
    )
  }
}

const verifyRustScaffoldDocumentation = async (
  root: string,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  try {
    const architecture = await readFile(join(root, "docs/architecture.md"), "utf8")
    const documented =
      /temporary Rust scaffold/i.test(architecture) &&
      /superseded by the TypeScript\/Bun target/i.test(architecture) &&
      /not final compliance/i.test(architecture)
    check(
      checks,
      errors,
      "rust-scaffold-disclosure",
      documented,
      "Rust must be documented as a temporary scaffold superseded by the TypeScript/Bun target, not final compliance",
    )
  } catch (error: unknown) {
    check(
      checks,
      errors,
      "rust-scaffold-disclosure",
      false,
      error instanceof Error ? error.message : "cannot read architecture documentation",
    )
  }
}

const main = async (): Promise<void> => {
  const parsed = parseStrictCli(process.argv.slice(2), cliSpec)
  if (!parsed.ok) {
    emit(failed("verify:architecture", parsed.error), process.argv.includes("--json"))
    return
  }
  if (!parsed.options.switches.has("strict")) {
    emit(failed("verify:architecture", "--strict is required"), parsed.options.switches.has("json"))
    return
  }
  const root = resolve(flag(parsed.options, "root") ?? process.cwd())
  const checks: CheckResult[] = []
  const errors: string[] = []
  await verifyRules(root, checks, errors)
  await verifyProductionBoundaries(root, checks, errors)
  await verifyRustScaffoldDocumentation(root, checks, errors)
  emit(report(checks, errors), parsed.options.switches.has("json"))
}

main().catch((error: unknown) => {
  emit(
    failed(
      "verify:architecture",
      error instanceof Error ? error.message : "unexpected architecture verification failure",
    ),
    process.argv.includes("--json"),
  )
})
