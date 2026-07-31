import {
  BASELINE_SCHEMA_ID,
  BIOME_VERSION,
  BUN_VERSION,
  PACKAGE_MANAGER_DECLARATION,
  REQUIRED_COMPILER_OPTIONS,
  STUDIO_CRITERIA,
  STUDIO_GATE_SCHEMA_ID,
  TYPESCRIPT_VERSION,
} from "./rules.js"
import type { CanonicalYamlMap, CanonicalYamlValue } from "./yaml.js"

const mapAt = (value: CanonicalYamlMap, key: string): CanonicalYamlMap | null => {
  const child = value[key]
  return typeof child === "object" && child !== null && !Array.isArray(child)
    ? (child as CanonicalYamlMap)
    : null
}

const stringAt = (value: CanonicalYamlMap, key: string): string | null => {
  const child = value[key]
  return typeof child === "string" ? child : null
}

const booleanAt = (value: CanonicalYamlMap, key: string): boolean | null => {
  const child = value[key]
  return typeof child === "boolean" ? child : null
}

const listAt = (value: CanonicalYamlMap, key: string): readonly CanonicalYamlValue[] | null => {
  const child = value[key]
  return Array.isArray(child) ? child : null
}

const exactStrings = (
  value: CanonicalYamlMap,
  expected: Readonly<Record<string, string>>,
): boolean =>
  Object.entries(expected).every(([key, expectedValue]) => stringAt(value, key) === expectedValue)

export const validateTechnologyBaseline = (value: CanonicalYamlMap): readonly string[] => {
  const errors: string[] = []
  if (stringAt(value, "schema") !== BASELINE_SCHEMA_ID)
    errors.push("schema must be the approved technology baseline")
  if (stringAt(value, "technology") !== "TypeScript on Bun")
    errors.push("technology must be TypeScript on Bun")

  const versions = mapAt(value, "versions")
  if (
    versions === null ||
    !exactStrings(versions, {
      bun: BUN_VERSION,
      typescript: TYPESCRIPT_VERSION,
      biome: BIOME_VERSION,
    })
  ) {
    errors.push(
      `versions must pin Bun ${BUN_VERSION}, TypeScript ${TYPESCRIPT_VERSION}, and Biome ${BIOME_VERSION}`,
    )
  }

  const packagePolicy = mapAt(value, "package")
  if (
    packagePolicy === null ||
    stringAt(packagePolicy, "manager") !== "Bun" ||
    stringAt(packagePolicy, "declaration") !== PACKAGE_MANAGER_DECLARATION ||
    stringAt(packagePolicy, "lockfile") !== "bun.lock" ||
    booleanAt(packagePolicy, "frozen_lockfile") !== true
  ) {
    errors.push("package policy must require Bun, bun@1.3.14, bun.lock, and frozen installs")
  }

  const dependencyFreeze = mapAt(value, "dependency_freeze")
  if (
    dependencyFreeze === null ||
    stringAt(dependencyFreeze, "direct_and_transitive") !==
      "All direct and transitive package versions are frozen by bun.lock." ||
    stringAt(dependencyFreeze, "lockfile_authority") !== "bun.lock"
  ) {
    errors.push("direct and transitive dependencies must be frozen by bun.lock")
  }

  const sovereignTooling = mapAt(value, "sovereign_tooling")
  if (
    sovereignTooling === null ||
    stringAt(sovereignTooling, "jetbrains_pins") !==
      "JetBrains separately pins its Gradle wrapper, Kotlin plugin, and JetBrains Platform versions in its sovereign repository."
  ) {
    errors.push("JetBrains Gradle, Kotlin, and Platform pins must remain sovereign")
  }

  const module = mapAt(value, "module")
  if (
    module === null ||
    stringAt(module, "format") !== "ESM-only" ||
    booleanAt(module, "project_references") !== true
  ) {
    errors.push("module policy must require ESM-only source and project references")
  }

  const compilerOptions = mapAt(value, "compiler_options")
  if (
    compilerOptions === null ||
    Object.entries(REQUIRED_COMPILER_OPTIONS).some(
      ([key, expected]) => compilerOptions[key] !== expected,
    )
  ) {
    errors.push("compiler options do not match the approved strict baseline")
  }

  const policy = mapAt(value, "policy")
  if (
    policy === null ||
    booleanAt(policy, "explicit_any") !== false ||
    booleanAt(policy, "unchecked_ts_ignore") !== false ||
    booleanAt(policy, "unvalidated_external_input") !== false ||
    booleanAt(policy, "untyped_error_channel") !== false ||
    booleanAt(policy, "exhaustive_discriminated_unions") !== true ||
    stringAt(policy, "external_data_boundary") !== "branded or schema-derived types"
  ) {
    errors.push("type-safety and boundary policy does not match the approved baseline")
  }

  const commands = mapAt(value, "commands")
  const expectedCommands = {
    install: "bun install --frozen-lockfile",
    lint: "bun run lint",
    typecheck: "bun run typecheck",
    test: "bun test",
    mutation: "bun run test:mutation",
    build: "bun run build",
    reproducibility: "bun run verify:reproducible",
  }
  if (commands === null || !exactStrings(commands, expectedCommands))
    errors.push("required commands do not match the approved baseline")

  const quality = mapAt(value, "quality")
  const expectedQuality = {
    lint_warnings: "zero",
    typecheck_emit: "project references with no emit and zero errors",
    test_scope: "unit, property, integration, and contract tests",
    critical_mutation_score_minimum: "90%",
    build_implementation: "Bun bundling/compilation only",
    release_toolchain: "TypeScript with Bun",
  }
  if (quality === null || !exactStrings(quality, expectedQuality))
    errors.push("quality policy does not match the approved baseline")

  const nativeValidation = mapAt(value, "native_validation")
  const targets = [
    "macOS 14/15: aarch64",
    "macOS 14/15: x86_64",
    "Ubuntu 22.04/24.04 glibc: aarch64",
    "Ubuntu 22.04/24.04 glibc: x86_64",
    "Windows 11: ARM64",
    "Windows 11: x86_64",
  ]
  const actualTargets = nativeValidation === null ? null : listAt(nativeValidation, "targets")
  if (
    nativeValidation === null ||
    booleanAt(nativeValidation, "required") !== true ||
    actualTargets === null ||
    actualTargets.length !== targets.length ||
    actualTargets.some((target, index) => target !== targets[index]) ||
    stringAt(nativeValidation, "rule") !==
      "Every listed target requires native validation before release."
  ) {
    errors.push("native validation targets do not match the approved target rule")
  }

  const projectValidation = mapAt(value, "project_validation")
  if (
    projectValidation === null ||
    stringAt(projectValidation, "disclaimer") !==
      "These are Gorce project validation targets, not claims about Bun's official OS-version support guarantees." ||
    stringAt(projectValidation, "build_and_test") !==
      "Each target is built and tested on a pinned native runner." ||
    stringAt(projectValidation, "cross_produced_artifacts") !==
      "Cross-produced artifacts do not satisfy target acceptance."
  ) {
    errors.push(
      "project validation must require pinned-native build and test, not cross-produced artifacts",
    )
  }
  return errors
}

export const validateStudioHostGate = (
  value: CanonicalYamlMap,
  text: string,
): readonly string[] => {
  const errors: string[] = []
  if (stringAt(value, "schema") !== STUDIO_GATE_SCHEMA_ID)
    errors.push("schema must be the approved Studio host gate")
  if (stringAt(value, "kind") !== "normative-task-31-decision-procedure")
    errors.push("Studio host gate must be normative")
  const procedure = mapAt(value, "decision_procedure")
  const criteria = procedure === null ? null : listAt(procedure, "criteria")
  if (
    procedure === null ||
    stringAt(procedure, "phase") !== "Task 31" ||
    stringAt(procedure, "source_pin") !==
      "Pin latest stable Code-OSS and its exact source commit." ||
    stringAt(procedure, "extension_proof") !==
      "Build a TypeScript extension proof against published contracts." ||
    criteria === null ||
    criteria.length !== STUDIO_CRITERIA.length ||
    criteria.some((criterion, index) => criterion !== STUDIO_CRITERIA[index]) ||
    stringAt(procedure, "extension_api_requirement") !==
      "Every criterion must have a documented stable extension API." ||
    stringAt(procedure, "all_criteria_with_stable_api") !== "extension-distribution" ||
    stringAt(procedure, "otherwise") !== "fork-required" ||
    booleanAt(procedure, "subjective_override") !== false
  ) {
    errors.push(
      "Studio host gate criteria, API requirement, and deterministic decisions are invalid",
    )
  }
  if (/code-oss[^\n]*\b\d+\.\d+|\b[0-9a-f]{40,64}\b|evaluated[_ -]?outcome|result:/i.test(text)) {
    errors.push(
      "Studio host gate must contain no evaluated outcome, version, commit digest, or result",
    )
  }
  return errors
}
