import { boolean, list, map, string, type CanonicalYamlSchema } from "./yaml.js"

const baselineSchema = map([
  ["schema", string()],
  ["technology", string()],
  [
    "versions",
    map([
      ["bun", string()],
      ["typescript", string()],
      ["biome", string()],
    ]),
  ],
  [
    "package",
    map([
      ["manager", string()],
      ["declaration", string()],
      ["lockfile", string()],
      ["frozen_lockfile", boolean()],
    ]),
  ],
  [
    "dependency_freeze",
    map([
      ["direct_and_transitive", string()],
      ["lockfile_authority", string()],
    ]),
  ],
  ["sovereign_tooling", map([["jetbrains_pins", string()]])],
  [
    "module",
    map([
      ["format", string()],
      ["project_references", boolean()],
    ]),
  ],
  [
    "compiler_options",
    map([
      ["strict", boolean()],
      ["noUncheckedIndexedAccess", boolean()],
      ["exactOptionalPropertyTypes", boolean()],
      ["noImplicitOverride", boolean()],
      ["useUnknownInCatchVariables", boolean()],
      ["noPropertyAccessFromIndexSignature", boolean()],
      ["noFallthroughCasesInSwitch", boolean()],
      ["noUnusedLocals", boolean()],
      ["noUnusedParameters", boolean()],
      ["allowUnreachableCode", boolean()],
      ["allowUnusedLabels", boolean()],
    ]),
  ],
  [
    "policy",
    map([
      ["explicit_any", boolean()],
      ["unchecked_ts_ignore", boolean()],
      ["unvalidated_external_input", boolean()],
      ["untyped_error_channel", boolean()],
      ["exhaustive_discriminated_unions", boolean()],
      ["external_data_boundary", string()],
    ]),
  ],
  [
    "commands",
    map([
      ["install", string()],
      ["lint", string()],
      ["typecheck", string()],
      ["test", string()],
      ["mutation", string()],
      ["build", string()],
      ["reproducibility", string()],
    ]),
  ],
  [
    "quality",
    map([
      ["lint_warnings", string()],
      ["typecheck_emit", string()],
      ["test_scope", string()],
      ["critical_mutation_score_minimum", string()],
      ["build_implementation", string()],
      ["release_toolchain", string()],
    ]),
  ],
  [
    "native_validation",
    map([
      ["required", boolean()],
      ["targets", list(string())],
      ["rule", string()],
    ]),
  ],
  [
    "project_validation",
    map([
      ["disclaimer", string()],
      ["build_and_test", string()],
      ["cross_produced_artifacts", string()],
    ]),
  ],
])

const studioGateSchema = map([
  ["schema", string()],
  ["kind", string()],
  [
    "decision_procedure",
    map([
      ["phase", string()],
      ["source_pin", string()],
      ["extension_proof", string()],
      ["criteria", list(string())],
      ["extension_api_requirement", string()],
      ["all_criteria_with_stable_api", string()],
      ["otherwise", string()],
      ["subjective_override", boolean()],
    ]),
  ],
])

export const TECHNOLOGY_BASELINE_SCHEMA: CanonicalYamlSchema = baselineSchema
export const STUDIO_HOST_GATE_SCHEMA: CanonicalYamlSchema = studioGateSchema

export const BASELINE_SCHEMA_ID = "gorce.architecture.typescript-bun-baseline/v1"
export const STUDIO_GATE_SCHEMA_ID = "gorce.architecture.studio-host-gate/v1"
export const BUN_VERSION = "1.3.14"
export const TYPESCRIPT_VERSION = "6.0.3"
export const BIOME_VERSION = "2.2.4"
export const PACKAGE_MANAGER_DECLARATION = "bun@1.3.14"

export const REQUIRED_COMPILER_OPTIONS = {
  strict: true,
  noUncheckedIndexedAccess: true,
  exactOptionalPropertyTypes: true,
  noImplicitOverride: true,
  useUnknownInCatchVariables: true,
  noPropertyAccessFromIndexSignature: true,
  noFallthroughCasesInSwitch: true,
  noUnusedLocals: true,
  noUnusedParameters: true,
  allowUnreachableCode: false,
  allowUnusedLabels: false,
} as const

export const STUDIO_CRITERIA = [
  "independent identity/trademark-safe branding",
  "independent update channel",
  "product-owned telemetry defaults",
  "product-owned marketplace policy",
  "bundled default plugins",
  "daemon lifecycle before extension activation",
  "workbench-level Activity",
  "workbench-level permission/bypass visibility",
] as const
