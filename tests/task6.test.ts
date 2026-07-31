// biome-ignore-all lint/complexity/useLiteralKeys: The test exercises JSON Schema keyword names.

import { describe, expect, test } from "bun:test"
import { copyFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { parseStrictCli } from "../src/commands/cli.js"
import { createF2Fixture, runF2FixtureManifest } from "../src/verification/f2.js"
import { STUDIO_HOST_GATE_SCHEMA, TECHNOLOGY_BASELINE_SCHEMA } from "../src/architecture/rules.js"
import { verifyEcosystem } from "../src/architecture/ecosystem.js"
import {
  validateStudioHostGate,
  validateTechnologyBaseline,
} from "../src/architecture/semantics.js"
import { parseCanonicalYaml, readCanonicalYaml } from "../src/architecture/yaml.js"

type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { readonly [key: string]: JsonValue }
type JsonSchema = { readonly [key: string]: JsonValue }

const isJsonRecord = (value: JsonValue): value is { readonly [key: string]: JsonValue } =>
  typeof value === "object" && value !== null && !Array.isArray(value)

const jsonEqual = (left: JsonValue, right: JsonValue): boolean =>
  JSON.stringify(left) === JSON.stringify(right)

const schemaTypeMatches = (value: JsonValue, type: JsonValue): boolean => {
  if (typeof type !== "string") return false
  if (type === "object") return isJsonRecord(value)
  if (type === "array") return Array.isArray(value)
  if (type === "integer") return typeof value === "number" && Number.isInteger(value)
  return typeof value === type
}

const schemaValid = (value: JsonValue, schema: JsonSchema, root: JsonSchema): boolean => {
  if (typeof schema["$ref"] === "string") {
    const ref = schema["$ref"]
    if (
      ref !== "#/$defs/case" &&
      ref !== "#/$defs/approved-case" &&
      ref !== "#/$defs/complete-case-set" &&
      ref !== "#/$defs/complete-approved-case-set"
    )
      return false
    const name = ref.slice("#/$defs/".length)
    const defs = root["$defs"] ?? null
    const definition = isJsonRecord(defs) ? (defs[name] ?? null) : null
    if (!isJsonRecord(definition)) return false
    return schemaValid(value, definition, root)
  }
  if (schema["type"] !== undefined && !schemaTypeMatches(value, schema["type"])) return false
  if (schema["const"] !== undefined && !jsonEqual(value, schema["const"])) return false
  if (Array.isArray(schema["enum"]) && !schema["enum"].some((item) => jsonEqual(value, item)))
    return false
  if (
    typeof schema["pattern"] === "string" &&
    (typeof value !== "string" || !new RegExp(schema["pattern"]).test(value))
  )
    return false
  if (
    typeof schema["minLength"] === "number" &&
    (typeof value !== "string" || value.length < schema["minLength"])
  )
    return false
  if (
    typeof schema["minimum"] === "number" &&
    (typeof value !== "number" || value < schema["minimum"])
  )
    return false
  if (
    typeof schema["minItems"] === "number" &&
    (!Array.isArray(value) || value.length < schema["minItems"])
  )
    return false
  if (
    typeof schema["maxItems"] === "number" &&
    (!Array.isArray(value) || value.length > schema["maxItems"])
  )
    return false
  if (schema["uniqueItems"] === true && Array.isArray(value)) {
    const serialized = value.map((item) => JSON.stringify(item))
    if (new Set(serialized).size !== serialized.length) return false
  }
  if (Array.isArray(schema["required"]) && isJsonRecord(value)) {
    if (schema["required"].some((key) => typeof key !== "string" || !Object.hasOwn(value, key)))
      return false
  }
  if (schema["additionalProperties"] === false && isJsonRecord(value)) {
    const properties = isJsonRecord(schema["properties"] ?? null)
      ? (schema["properties"] as JsonSchema)
      : {}
    if (Object.keys(value).some((key) => !Object.hasOwn(properties, key))) return false
  }
  if (isJsonRecord(schema["properties"] ?? null) && isJsonRecord(value)) {
    for (const [key, child] of Object.entries(schema["properties"] as JsonSchema)) {
      if (
        Object.hasOwn(value, key) &&
        isJsonRecord(child) &&
        !schemaValid(value[key] ?? null, child, root)
      )
        return false
    }
  }
  if (isJsonRecord(schema["items"] ?? null) && Array.isArray(value)) {
    if (value.some((item) => !schemaValid(item, schema["items"] as JsonSchema, root))) return false
  }
  if (isJsonRecord(schema["contains"] ?? null) && Array.isArray(value)) {
    const matches = value.filter((item) =>
      schemaValid(item, schema["contains"] as JsonSchema, root),
    ).length
    const minimum = typeof schema["minContains"] === "number" ? schema["minContains"] : 1
    const maximum =
      typeof schema["maxContains"] === "number" ? schema["maxContains"] : Number.POSITIVE_INFINITY
    if (matches < minimum || matches > maximum) return false
  }
  if (
    Array.isArray(schema["allOf"]) &&
    schema["allOf"].some((child) => !isJsonRecord(child) || !schemaValid(value, child, root))
  )
    return false
  if (
    Array.isArray(schema["anyOf"]) &&
    !schema["anyOf"].some((child) => isJsonRecord(child) && schemaValid(value, child, root))
  )
    return false
  if (
    Array.isArray(schema["oneOf"]) &&
    schema["oneOf"].filter((child) => isJsonRecord(child) && schemaValid(value, child, root))
      .length !== 1
  )
    return false
  if (isJsonRecord(schema["not"] ?? null) && schemaValid(value, schema["not"] as JsonSchema, root))
    return false
  if (isJsonRecord(schema["if"] ?? null)) {
    if (
      schemaValid(value, schema["if"] as JsonSchema, root) &&
      isJsonRecord(schema["then"] ?? null) &&
      !schemaValid(value, schema["then"] as JsonSchema, root)
    )
      return false
  }
  return true
}

const validateF2EvidenceSchema = (value: JsonValue, schema: JsonValue): boolean =>
  isJsonRecord(schema) && schemaValid(value, schema, schema)

describe("Task 6 canonical architecture rules", () => {
  test("reads both public rules as canonical UTF-8 YAML", async () => {
    const baseline = await readCanonicalYaml(
      "architecture/typescript-bun-baseline.v1.yaml",
      TECHNOLOGY_BASELINE_SCHEMA,
    )
    const gate = await readCanonicalYaml(
      "architecture/studio-host-gate.v1.yaml",
      STUDIO_HOST_GATE_SCHEMA,
    )
    expect(baseline.sha256).toMatch(/^[0-9a-f]{64}$/)
    expect(gate.sha256).toMatch(/^[0-9a-f]{64}$/)
    expect(baseline.text.startsWith("\uFEFF")).toBe(false)
    expect(gate.text.startsWith("\uFEFF")).toBe(false)
  })

  test("rejects comments, aliases, duplicate keys, and unknown keys", () => {
    const schema = {
      kind: "map" as const,
      keys: { schema: { kind: "string" as const } },
      order: ["schema"],
    }
    expect(() => parseCanonicalYaml('schema: "ok"\n# no comments\n', schema)).toThrow()
    expect(() => parseCanonicalYaml('schema: "ok"\nschema: "again"\n', schema)).toThrow()
    expect(() => parseCanonicalYaml('unknown: "no"\n', schema)).toThrow()
    expect(() => parseCanonicalYaml('schema: "ok"\n', schema)).not.toThrow()
  })

  test("semantic validation rejects altered versions and Studio criteria", async () => {
    const baseline = await readCanonicalYaml(
      "architecture/typescript-bun-baseline.v1.yaml",
      TECHNOLOGY_BASELINE_SCHEMA,
    )
    const gate = await readCanonicalYaml(
      "architecture/studio-host-gate.v1.yaml",
      STUDIO_HOST_GATE_SCHEMA,
    )
    const alteredBaseline = await readCanonicalYaml(
      "architecture/typescript-bun-baseline.v1.yaml",
      TECHNOLOGY_BASELINE_SCHEMA,
    )
    const alteredBaselineText = alteredBaseline.text.replace('bun: "1.3.14"', 'bun: "1.3.13"')
    const alteredGateText = gate.text.replace('"independent update channel"', '"altered criterion"')
    const alteredBaselineValue = parseCanonicalYaml(alteredBaselineText, TECHNOLOGY_BASELINE_SCHEMA)
    const alteredGateValue = parseCanonicalYaml(alteredGateText, STUDIO_HOST_GATE_SCHEMA)
    expect(validateTechnologyBaseline(baseline.value)).toEqual([])
    expect(validateStudioHostGate(gate.value, gate.text)).toEqual([])
    expect(validateTechnologyBaseline(alteredBaselineValue).length).toBeGreaterThan(0)
    expect(validateStudioHostGate(alteredGateValue, alteredGateText).length).toBeGreaterThan(0)
  })
})

describe("Task 6 strict command arguments", () => {
  test("rejects unknown, duplicate, and positional options", () => {
    const spec = { flags: ["value"], switches: ["strict"] }
    expect(parseStrictCli(["--unknown"], spec).ok).toBe(false)
    expect(parseStrictCli(["--value=one", "--value=two"], spec).ok).toBe(false)
    expect(parseStrictCli(["positional"], spec).ok).toBe(false)
    expect(parseStrictCli(["--value=one", "--strict"], spec).ok).toBe(true)
  })
})

describe("F2 architecture fixtures", () => {
  test(
    "approves the clean fixture and rejects every specified overlay",
    async () => {
      const directory = await mkdtemp(join(tmpdir(), "gorce-task-06-"))
      try {
        const evidence = join(directory, "final-architecture.json")
        const report = await runF2FixtureManifest("tests/qa/final/f2-architecture.yaml", evidence)
        expect(report.ok).toBe(true)
        const payload = JSON.parse(await readFile(evidence, "utf8")) as {
          readonly schema: string
          readonly verdict: string
          readonly cases: readonly {
            readonly kind: string
            readonly id: string
            readonly ok: boolean
            readonly expected_code: string
            readonly expected_reason: string
            readonly observed_code: string
            readonly observed_reason: string
            readonly error_count: number
          }[]
        }
        expect(payload).toMatchObject({ schema: "gorce.f2-verdict/v1", verdict: "APPROVED" })
        expect(payload.cases).toHaveLength(22)
        expect(payload.cases.filter((item) => item.kind === "runtime-overlay")).toHaveLength(4)
        expect(
          payload.cases.filter((item) => item.kind === "published-source-overlay"),
        ).toHaveLength(9)
        expect(payload.cases.every((item) => item.ok)).toBe(true)
        expect(
          payload.cases.every(
            (item) =>
              item.observed_code === item.expected_code &&
              item.observed_reason === item.expected_reason,
          ),
        ).toBe(true)
        expect(payload.cases.find((item) => item.id === "clean")).toMatchObject({
          observed_code: "NONE",
          error_count: 0,
        })
        const schema = JSON.parse(
          await readFile("tests/qa/final/f2-verdict.schema.json", "utf8"),
        ) as JsonValue
        expect(validateF2EvidenceSchema(payload as unknown as JsonValue, schema)).toBe(true)
        const approvedWithFailure = structuredClone(payload) as unknown as {
          verdict: string
          cases: { ok: boolean; error_count: number }[]
        }
        const failedCase = approvedWithFailure.cases[0]
        if (failedCase === undefined) throw new Error("approved evidence has no first case")
        failedCase.ok = false
        failedCase.error_count = 1
        expect(validateF2EvidenceSchema(approvedWithFailure as unknown as JsonValue, schema)).toBe(
          false,
        )
        const approvedWithMismatch = structuredClone(payload) as unknown as {
          cases: { observed_code: string }[]
        }
        const mismatchedCase = approvedWithMismatch.cases[0]
        if (mismatchedCase === undefined) throw new Error("approved evidence has no first case")
        mismatchedCase.observed_code = "ECO_MUTATED"
        expect(validateF2EvidenceSchema(approvedWithMismatch as unknown as JsonValue, schema)).toBe(
          false,
        )
        const missingCase = structuredClone(payload) as unknown as { cases: unknown[] }
        missingCase.cases.pop()
        expect(validateF2EvidenceSchema(missingCase as unknown as JsonValue, schema)).toBe(false)
        const duplicateCase = structuredClone(payload) as unknown as { cases: unknown[] }
        duplicateCase.cases[21] = duplicateCase.cases[0]
        expect(validateF2EvidenceSchema(duplicateCase as unknown as JsonValue, schema)).toBe(false)
        const changesRequested = structuredClone(payload) as unknown as {
          verdict: string
          cases: { ok: boolean; error_count: number }[]
        }
        changesRequested.verdict = "CHANGES_REQUESTED"
        const requestedCase = changesRequested.cases[0]
        if (requestedCase === undefined) throw new Error("approved evidence has no first case")
        requestedCase.ok = false
        requestedCase.error_count = 1
        expect(validateF2EvidenceSchema(changesRequested as unknown as JsonValue, schema)).toBe(
          true,
        )
      } finally {
        await rm(directory, { recursive: true, force: true })
      }
    },
    { timeout: 30000 },
  )

  test("incomplete F2 manifests atomically emit CHANGES_REQUESTED", async () => {
    const directory = await mkdtemp(join(tmpdir(), "gorce-task-06-"))
    try {
      const manifest = join(directory, "incomplete.yaml")
      const evidence = join(directory, "final-architecture.json")
      await writeFile(
        manifest,
        'schema: "gorce.qa.f2-architecture/v1"\ncases:\n  - "clean"\nruntime_overlays:\n  - "alternate-cargo-runtime"\n',
      )
      const report = await runF2FixtureManifest(manifest, evidence)
      expect(report.ok).toBe(false)
      const payload = JSON.parse(await readFile(evidence, "utf8")) as {
        readonly verdict: string
        readonly fatal_code?: string
      }
      expect(payload.verdict).toBe("CHANGES_REQUESTED")
      expect(payload.fatal_code).toBe("F2_MANIFEST_CASE_SET")
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })

  test(
    "ecosystem CLI emits an exact verdict for real clean and failing trees",
    async () => {
      const clean = await createF2Fixture("clean")
      const failing = await createF2Fixture("alternate-node-runtime")
      const runCli = async (
        fixture: typeof clean,
      ): Promise<{ readonly exitCode: number; readonly verdict: string }> => {
        const processHandle = Bun.spawn(
          [
            process.execPath,
            join(process.cwd(), "src/commands/verify-architecture-ecosystem.ts"),
            "--published-only",
            `--technology-baseline=${fixture.technologyBaseline}`,
            "--core-inventory-ban=studio,jetbrains",
            `--core=${fixture.coreRoot}`,
            `--studio=${fixture.studioRoot}`,
            `--jetbrains=${fixture.jetbrainsRoot}`,
            "--json",
          ],
          { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" },
        )
        const [exitCode, stdout] = await Promise.all([
          processHandle.exited,
          new Response(processHandle.stdout).text(),
          new Response(processHandle.stderr).text(),
        ])
        const payload = JSON.parse(stdout) as { readonly verdict: string }
        return { exitCode, verdict: payload.verdict }
      }
      try {
        await expect(runCli(clean)).resolves.toEqual({ exitCode: 0, verdict: "APPROVED" })
        await expect(runCli(failing)).resolves.toEqual({
          exitCode: 1,
          verdict: "CHANGES_REQUESTED",
        })
      } finally {
        await rm(clean.root, { recursive: true, force: true })
        await rm(failing.root, { recursive: true, force: true })
      }
    },
    { timeout: 30000 },
  )

  test(
    "structurally rejects Git, workspace, and protocol source specifications",
    async () => {
      const fixtureNames = [
        "published-github-protocol-source",
        "published-git-ssh-source",
        "published-git-url-source",
        "published-workspace-source",
      ]
      for (const name of fixtureNames) {
        const fixture = await createF2Fixture(name)
        try {
          const report = await verifyEcosystem({
            coreRoot: fixture.coreRoot,
            studioRoot: fixture.studioRoot,
            jetbrainsRoot: fixture.jetbrainsRoot,
            technologyBaseline: fixture.technologyBaseline,
            coreInventoryBan: ["studio", "jetbrains"],
            publishedOnly: true,
          })
          expect(report.ok).toBe(false)
          expect(report.errors[0]).toBe(
            "ECO_PUBLISHED_SOURCE_TUNNELING: siblings must consume published immutable artifacts only",
          )
        } finally {
          await rm(fixture.root, { recursive: true, force: true })
        }
      }
    },
    { timeout: 30000 },
  )

  test(
    "does not hide real imports in detector paths and accepts Bun shebang bins",
    async () => {
      const detector = await createF2Fixture("detector-real-import")
      try {
        const report = await verifyEcosystem({
          coreRoot: detector.coreRoot,
          studioRoot: detector.studioRoot,
          jetbrainsRoot: detector.jetbrainsRoot,
          technologyBaseline: detector.technologyBaseline,
          coreInventoryBan: ["studio", "jetbrains"],
          publishedOnly: true,
        })
        expect(report.errors[0]).toBe(
          "ECO_CORE_PACKAGE_INVERSION: core must not depend on Studio or JetBrains packages",
        )
      } finally {
        await rm(detector.root, { recursive: true, force: true })
      }

      for (const name of ["bun-shebang-bin", "bun-js-shebang-bin"]) {
        const fixture = await createF2Fixture(name)
        try {
          const report = await verifyEcosystem({
            coreRoot: fixture.coreRoot,
            studioRoot: fixture.studioRoot,
            jetbrainsRoot: fixture.jetbrainsRoot,
            technologyBaseline: fixture.technologyBaseline,
            coreInventoryBan: ["studio", "jetbrains"],
            publishedOnly: true,
          })
          expect(report.ok).toBe(true)
        } finally {
          await rm(fixture.root, { recursive: true, force: true })
        }
      }
    },
    { timeout: 30000 },
  )

  test(
    "tokenizes script options before rejecting a Node runtime",
    async () => {
      const fixture = await createF2Fixture("alternate-node-script")
      try {
        const report = await verifyEcosystem({
          coreRoot: fixture.coreRoot,
          studioRoot: fixture.studioRoot,
          jetbrainsRoot: fixture.jetbrainsRoot,
          technologyBaseline: fixture.technologyBaseline,
          coreInventoryBan: ["studio", "jetbrains"],
          publishedOnly: true,
        })
        expect(report.errors[0]).toBe(
          "ECO_NON_BUN_RUNTIME: core ecosystem trees must use Bun rather than Cargo, Node, Deno, or another runtime",
        )
      } finally {
        await rm(fixture.root, { recursive: true, force: true })
      }
    },
    { timeout: 30000 },
  )

  test("hashing altered canonical rules writes no digest evidence", async () => {
    const directory = await mkdtemp(join(tmpdir(), "gorce-task-06-"))
    try {
      const baseline = join(directory, "baseline.yaml")
      const studio = join(directory, "studio.yaml")
      const validBaseline = join(directory, "valid-baseline.yaml")
      const alteredStudio = join(directory, "altered-studio.yaml")
      const evidence = join(directory, "digests.json")
      const studioEvidence = join(directory, "studio-digests.json")
      const baselineText = await readFile("architecture/typescript-bun-baseline.v1.yaml", "utf8")
      await writeFile(baseline, baselineText.replace('bun: "1.3.14"', 'bun: "1.3.13"'))
      await copyFile("architecture/studio-host-gate.v1.yaml", studio)
      await copyFile("architecture/typescript-bun-baseline.v1.yaml", validBaseline)
      const studioText = await readFile(studio, "utf8")
      await writeFile(
        alteredStudio,
        studioText.replace('"independent update channel"', '"altered criterion"'),
      )
      const runHash = async (
        technology: string,
        studioRule: string,
        output: string,
      ): Promise<number> => {
        const processHandle = Bun.spawn(
          [
            process.execPath,
            join(process.cwd(), "src/commands/hash-rules.ts"),
            `--technology=${technology}`,
            `--studio=${studioRule}`,
            `--evidence=${output}`,
          ],
          { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" },
        )
        const [exitCode] = await Promise.all([
          processHandle.exited,
          new Response(processHandle.stdout).text(),
          new Response(processHandle.stderr).text(),
        ])
        return exitCode
      }
      expect(await runHash(baseline, studio, evidence)).not.toBe(0)
      expect(await runHash(validBaseline, alteredStudio, studioEvidence)).not.toBe(0)
      expect(await Bun.file(evidence).exists()).toBe(false)
      expect(await Bun.file(studioEvidence).exists()).toBe(false)
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })
})
