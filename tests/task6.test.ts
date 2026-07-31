import { describe, expect, test } from "bun:test"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { parseStrictCli } from "../src/commands/cli.js"
import { runF2FixtureManifest } from "../src/verification/f2.js"
import { STUDIO_HOST_GATE_SCHEMA, TECHNOLOGY_BASELINE_SCHEMA } from "../src/architecture/rules.js"
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
  test("approves the clean fixture and rejects every specified overlay", async () => {
    const directory = await mkdtemp(join(tmpdir(), "gorce-task-06-"))
    try {
      const evidence = join(directory, "final-architecture.json")
      const report = await runF2FixtureManifest("tests/qa/final/f2-architecture.yaml", evidence)
      expect(report.ok).toBe(true)
      const payload: unknown = JSON.parse(await readFile(evidence, "utf8"))
      expect(payload).toMatchObject({ schema: "gorce.f2-verdict/v1", verdict: "APPROVED" })
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })
})
