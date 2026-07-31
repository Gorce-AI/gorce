import { describe, expect, test } from "bun:test"
import { copyFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { parseStrictCli } from "../src/commands/cli.js"
import { runF2FixtureManifest } from "../src/verification/f2.js"
import { STUDIO_HOST_GATE_SCHEMA, TECHNOLOGY_BASELINE_SCHEMA } from "../src/architecture/rules.js"
import {
  validateStudioHostGate,
  validateTechnologyBaseline,
} from "../src/architecture/semantics.js"
import { parseCanonicalYaml, readCanonicalYaml } from "../src/architecture/yaml.js"

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
            readonly observed_code: string
            readonly error_count: number
          }[]
        }
        expect(payload).toMatchObject({ schema: "gorce.f2-verdict/v1", verdict: "APPROVED" })
        expect(payload.cases).toHaveLength(13)
        expect(payload.cases.filter((item) => item.kind === "runtime-overlay")).toHaveLength(4)
        expect(payload.cases.every((item) => item.ok)).toBe(true)
        expect(payload.cases.find((item) => item.id === "clean")).toMatchObject({
          observed_code: "NONE",
          error_count: 0,
        })
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
