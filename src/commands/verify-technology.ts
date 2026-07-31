import { readFile, readdir } from "node:fs/promises"
import { join, resolve } from "node:path"
import { emit, failed, flag, parseStrictCli, type StrictCliSpec } from "./cli.js"
import {
  BASELINE_SCHEMA_ID,
  BIOME_VERSION,
  BUN_VERSION,
  PACKAGE_MANAGER_DECLARATION,
  REQUIRED_COMPILER_OPTIONS,
  TECHNOLOGY_BASELINE_SCHEMA,
  TYPESCRIPT_VERSION,
} from "../architecture/rules.js"
import {
  readCanonicalYaml,
  type CanonicalYamlMap,
  type CanonicalYamlValue,
} from "../architecture/yaml.js"
import type { CheckResult, VerificationReport } from "../verification/types.js"

const cliSpec: StrictCliSpec = {
  flags: ["bun", "typescript", "root"],
  switches: ["strict", "json"],
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value)

const loadJson = async (path: string): Promise<Record<string, unknown>> => {
  const value: unknown = JSON.parse(await readFile(path, "utf8"))
  if (!isRecord(value)) throw new Error(`${path}: JSON root must be an object`)
  return value
}

const mapAt = (value: CanonicalYamlMap, key: string): CanonicalYamlMap => {
  const child = value[key]
  if (typeof child !== "object" || child === null || Array.isArray(child)) {
    throw new Error(`baseline.${key} must be a mapping`)
  }
  return child as CanonicalYamlMap
}

const stringAt = (value: CanonicalYamlMap, key: string): string => {
  const child = value[key]
  if (typeof child !== "string") throw new Error(`baseline.${key} must be a string`)
  return child
}

const booleanAt = (value: CanonicalYamlMap, key: string): boolean => {
  const child = value[key]
  if (typeof child !== "boolean") throw new Error(`baseline.${key} must be a boolean`)
  return child
}

const listAt = (value: CanonicalYamlMap, key: string): readonly CanonicalYamlValue[] => {
  const child = value[key]
  if (!Array.isArray(child)) throw new Error(`baseline.${key} must be a list`)
  return child
}

const makeReport = (
  checks: readonly CheckResult[],
  errors: readonly string[],
): VerificationReport => ({
  schema: "gorce.verification-result/v1",
  command: "verify:technology",
  ok: errors.length === 0,
  checks,
  errors,
})

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

const bytesEqual = (left: Uint8Array | null, right: Uint8Array | null): boolean => {
  if (left === null || right === null || left.length !== right.length) return false
  return left.every((byte, index) => byte === right[index])
}

const readBytes = async (path: string): Promise<Uint8Array | null> => {
  try {
    return new Uint8Array(await Bun.file(path).arrayBuffer())
  } catch {
    return null
  }
}

const run = async (
  cwd: string,
  command: string[],
): Promise<{ readonly status: number; readonly output: string }> => {
  const processHandle = Bun.spawn(command, { cwd, stdout: "pipe", stderr: "pipe" })
  const [status, stdout, stderr] = await Promise.all([
    processHandle.exited,
    new Response(processHandle.stdout).text(),
    new Response(processHandle.stderr).text(),
  ])
  return { status, output: `${stdout}${stderr}` }
}

const verifyBaselineValues = (
  baseline: CanonicalYamlMap,
  checks: CheckResult[],
  errors: string[],
): void => {
  check(
    checks,
    errors,
    "baseline-schema",
    stringAt(baseline, "schema") === BASELINE_SCHEMA_ID,
    BASELINE_SCHEMA_ID,
  )
  check(
    checks,
    errors,
    "baseline-versions",
    (() => {
      const versions = mapAt(baseline, "versions")
      return (
        stringAt(versions, "bun") === BUN_VERSION &&
        stringAt(versions, "typescript") === TYPESCRIPT_VERSION &&
        stringAt(versions, "biome") === BIOME_VERSION
      )
    })(),
    `Bun ${BUN_VERSION}, TypeScript ${TYPESCRIPT_VERSION}, and Biome ${BIOME_VERSION} are required`,
  )
  check(
    checks,
    errors,
    "baseline-package-policy",
    (() => {
      const pkg = mapAt(baseline, "package")
      return (
        stringAt(pkg, "manager") === "Bun" &&
        stringAt(pkg, "declaration") === PACKAGE_MANAGER_DECLARATION &&
        stringAt(pkg, "lockfile") === "bun.lock" &&
        booleanAt(pkg, "frozen_lockfile")
      )
    })(),
    "Bun, bun@1.3.14, committed bun.lock, and frozen installs are required",
  )
  check(
    checks,
    errors,
    "baseline-module-policy",
    (() => {
      const module = mapAt(baseline, "module")
      return stringAt(module, "format") === "ESM-only" && booleanAt(module, "project_references")
    })(),
    "ESM-only modules and TypeScript project references are required",
  )
  check(
    checks,
    errors,
    "baseline-compiler-policy",
    (() => {
      const options = mapAt(baseline, "compiler_options")
      return Object.entries(REQUIRED_COMPILER_OPTIONS).every(
        ([key, expected]) => options[key] === expected,
      )
    })(),
    "the approved TypeScript compiler flags must be enabled exactly",
  )
  const policy = mapAt(baseline, "policy")
  check(
    checks,
    errors,
    "baseline-policy",
    booleanAt(policy, "explicit_any") === false &&
      booleanAt(policy, "unchecked_ts_ignore") === false &&
      booleanAt(policy, "unvalidated_external_input") === false &&
      booleanAt(policy, "untyped_error_channel") === false &&
      booleanAt(policy, "exhaustive_discriminated_unions") === true &&
      stringAt(policy, "external_data_boundary") === "branded or schema-derived types",
    "the approved type-safety and boundary policy is required",
  )
  const commands = mapAt(baseline, "commands")
  const requiredCommands: Readonly<Record<string, string>> = {
    install: "bun install --frozen-lockfile",
    lint: "bun run lint",
    typecheck: "bun run typecheck",
    test: "bun test",
    mutation: "bun run test:mutation",
    build: "bun run build",
    reproducibility: "bun run verify:reproducible",
  }
  check(
    checks,
    errors,
    "baseline-commands",
    Object.entries(requiredCommands).every(([key, value]) => stringAt(commands, key) === value),
    "the approved required command set is required",
  )
  const quality = mapAt(baseline, "quality")
  check(
    checks,
    errors,
    "baseline-quality",
    stringAt(quality, "lint_warnings") === "zero" &&
      stringAt(quality, "typecheck_emit") === "project references with no emit and zero errors" &&
      stringAt(quality, "test_scope") === "unit, property, integration, and contract tests" &&
      stringAt(quality, "critical_mutation_score_minimum") === "90%" &&
      stringAt(quality, "build_implementation") === "Bun bundling/compilation only" &&
      stringAt(quality, "release_toolchain") === "TypeScript with Bun",
    "the approved quality and mutation policy is required",
  )
  const validation = mapAt(baseline, "native_validation")
  const targetValues = [
    "macOS 14/15: aarch64",
    "macOS 14/15: x86_64",
    "Ubuntu 22.04/24.04 glibc: aarch64",
    "Ubuntu 22.04/24.04 glibc: x86_64",
    "Windows 11: ARM64",
    "Windows 11: x86_64",
  ]
  check(
    checks,
    errors,
    "baseline-native-validation",
    booleanAt(validation, "required") &&
      listAt(validation, "targets").every((item, index) => item === targetValues[index]) &&
      listAt(validation, "targets").length === targetValues.length &&
      stringAt(validation, "rule") ===
        "Every listed target requires native validation before release.",
    "the native validation target rule and all target identities are required",
  )
}

const verifyPackage = async (
  root: string,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  let packageJson: Record<string, unknown>
  try {
    packageJson = await loadJson(join(root, "package.json"))
  } catch (error: unknown) {
    check(
      checks,
      errors,
      "package-config",
      false,
      error instanceof Error ? error.message : "cannot read package.json",
    )
    return
  }
  check(
    checks,
    errors,
    "package-manager",
    packageJson["packageManager"] === PACKAGE_MANAGER_DECLARATION,
    PACKAGE_MANAGER_DECLARATION,
  )
  check(checks, errors, "esm", packageJson["type"] === "module", `package.json type must be module`)
  const engines = isRecord(packageJson["engines"]) ? packageJson["engines"] : {}
  check(
    checks,
    errors,
    "bun-engine",
    engines["bun"] === BUN_VERSION,
    `engines.bun must be ${BUN_VERSION}`,
  )
  const devDependencies = isRecord(packageJson["devDependencies"])
    ? packageJson["devDependencies"]
    : {}
  check(
    checks,
    errors,
    "pinned-development-tools",
    devDependencies["typescript"] === TYPESCRIPT_VERSION &&
      devDependencies["@biomejs/biome"] === BIOME_VERSION,
    `TypeScript ${TYPESCRIPT_VERSION} and Biome ${BIOME_VERSION} are required`,
  )
  const lockPath = join(root, "bun.lock")
  check(
    checks,
    errors,
    "committed-bun-lock",
    (await readBytes(lockPath)) !== null,
    "bun.lock is required",
  )
  const entries = await readdir(root)
  const alternateLocks = entries.filter((entry) =>
    [
      "package-lock.json",
      "npm-shrinkwrap.json",
      "pnpm-lock.yaml",
      "yarn.lock",
      "bun.lockb",
    ].includes(entry),
  )
  check(
    checks,
    errors,
    "alternate-lockfiles",
    alternateLocks.length === 0,
    `alternate lockfiles are forbidden: ${alternateLocks.join(", ")}`,
  )
}

const verifyCompiler = async (
  root: string,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  try {
    const options = await loadJson(join(root, "tsconfig.options.json"))
    const compilerOptions = isRecord(options["compilerOptions"]) ? options["compilerOptions"] : {}
    const optionsMatch = Object.entries(REQUIRED_COMPILER_OPTIONS).every(
      ([key, expected]) => compilerOptions[key] === expected,
    )
    check(
      checks,
      errors,
      "compiler-options",
      optionsMatch,
      "approved compiler options are required",
    )

    const rootConfig = await loadJson(join(root, "tsconfig.json"))
    const references = Array.isArray(rootConfig["references"]) ? rootConfig["references"] : []
    const referencePaths = references.filter(isRecord).map((reference) => reference["path"])
    check(
      checks,
      errors,
      "project-references",
      referencePaths.includes("./tsconfig.source.json") &&
        referencePaths.includes("./tsconfig.test.json"),
      "bootstrap tooling must use source and test project references",
    )
    const sourceConfig = await loadJson(join(root, "tsconfig.source.json"))
    check(
      checks,
      errors,
      "source-esm",
      sourceConfig["extends"] === "./tsconfig.options.json",
      "source must extend the approved options",
    )
  } catch (error: unknown) {
    check(
      checks,
      errors,
      "compiler-config",
      false,
      error instanceof Error ? error.message : "cannot read TypeScript configuration",
    )
  }
}

const verifyFrozenInstall = async (
  root: string,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  const packageBefore = await readBytes(join(root, "package.json"))
  const lockBefore = await readBytes(join(root, "bun.lock"))
  if (packageBefore === null || lockBefore === null) {
    check(
      checks,
      errors,
      "frozen-install",
      false,
      "package.json and bun.lock are required before install",
    )
    return
  }
  const result = await run(root, [process.execPath, "install", "--frozen-lockfile"])
  const packageAfter = await readBytes(join(root, "package.json"))
  const lockAfter = await readBytes(join(root, "bun.lock"))
  check(
    checks,
    errors,
    "frozen-install",
    result.status === 0 &&
      bytesEqual(packageBefore, packageAfter) &&
      bytesEqual(lockBefore, lockAfter),
    result.status === 0
      ? "frozen install mutated package metadata or lockfile"
      : `frozen install failed: ${result.output.trim()}`,
  )
}

const verifyRuntime = async (
  root: string,
  expectedBun: string,
  expectedTypeScript: string,
  checks: CheckResult[],
  errors: string[],
): Promise<void> => {
  check(
    checks,
    errors,
    "bun-request",
    expectedBun === BUN_VERSION,
    `--bun must equal ${BUN_VERSION}`,
  )
  check(
    checks,
    errors,
    "typescript-request",
    expectedTypeScript === TYPESCRIPT_VERSION,
    `--typescript must equal ${TYPESCRIPT_VERSION}`,
  )
  check(
    checks,
    errors,
    "bun-runtime",
    Bun.version === BUN_VERSION,
    `running Bun must be ${BUN_VERSION}`,
  )
  const result = await run(root, [process.execPath, "node_modules/typescript/bin/tsc", "--version"])
  check(
    checks,
    errors,
    "typescript-runtime",
    result.status === 0 && result.output.trim() === `Version ${TYPESCRIPT_VERSION}`,
    `running TypeScript must be ${TYPESCRIPT_VERSION}`,
  )
}

const main = async (): Promise<void> => {
  const parsed = parseStrictCli(process.argv.slice(2), cliSpec)
  if (!parsed.ok) {
    emit(failed("verify:technology", parsed.error), process.argv.includes("--json"))
    return
  }
  const expectedBun = flag(parsed.options, "bun")
  const expectedTypeScript = flag(parsed.options, "typescript")
  if (
    expectedBun === undefined ||
    expectedTypeScript === undefined ||
    !parsed.options.switches.has("strict")
  ) {
    emit(
      failed("verify:technology", "--bun, --typescript, and --strict are required"),
      parsed.options.switches.has("json"),
    )
    return
  }
  const root = resolve(flag(parsed.options, "root") ?? process.cwd())
  const checks: CheckResult[] = []
  const errors: string[] = []
  try {
    const baseline = await readCanonicalYaml(
      join(root, "architecture/typescript-bun-baseline.v1.yaml"),
      TECHNOLOGY_BASELINE_SCHEMA,
    )
    verifyBaselineValues(baseline.value, checks, errors)
  } catch (error: unknown) {
    check(
      checks,
      errors,
      "baseline-canonical-yaml",
      false,
      error instanceof Error ? error.message : "cannot read baseline",
    )
  }
  await verifyRuntime(root, expectedBun, expectedTypeScript, checks, errors)
  await verifyPackage(root, checks, errors)
  await verifyCompiler(root, checks, errors)
  await verifyFrozenInstall(root, checks, errors)
  emit(makeReport(checks, errors), parsed.options.switches.has("json"))
}

main().catch((error: unknown) => {
  emit(
    failed(
      "verify:technology",
      error instanceof Error ? error.message : "unexpected technology verification failure",
    ),
    process.argv.includes("--json"),
  )
})
