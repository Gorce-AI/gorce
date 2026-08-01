import { describe, expect, test } from "bun:test"
import { copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises"
import { dirname, join } from "node:path"
import { tmpdir } from "node:os"
import { validateJsonSchema } from "../src/verification/json-schema.js"
import { validateNativeLaneSet } from "../src/verification/native-index.js"
import { scanProductionTree } from "../src/verification/production.js"
import { schemaErrors } from "../src/verification/s1-evidence.js"
import {
  copiedArtifactPath,
  currentTask6BaselineSha256,
  nativeArtifactName,
} from "../src/verification/s1-native.js"
import { inspectMutationApplicability, mutationEvidence } from "../src/verification/mutation.js"
import { validateS1Provenance } from "../src/verification/s1.js"
import type { JsonValue } from "../src/verification/json-schema.js"
import { generatedOutputs, validateProjectReferenceGraph } from "../src/verification/typecheck.js"

const copyFixture = async (root: string): Promise<void> => {
  const paths = [
    "tsconfig.json",
    "tsconfig.source.json",
    "tsconfig.test.json",
    "packages/core/tsconfig.json",
    "packages/tui-harness/tsconfig.json",
    "apps/tui-harness/tsconfig.json",
    "packages/core/package.json",
    "packages/tui-harness/package.json",
    "apps/tui-harness/package.json",
  ]
  for (const path of paths) {
    const destination = join(root, path)
    await mkdir(dirname(destination), { recursive: true })
    await copyFile(path, destination)
  }
}

const nativeRecord = (target: string, os: "linux" | "darwin" | "win32", arch: "x64" | "arm64") => ({
  schema: "gorce.s1.native-hello/v1",
  target,
  source_commit: "a".repeat(40),
  task6_baseline_sha256: "67b95cadb3ec9a711992007d2df420d984d97cfb9da94b033567e9b7987365a2",
  builder_bun: "1.3.14",
  release_claim: false,
  scope: "S1 native validation only; not release qualified",
  runner_os: os,
  runner_arch: arch,
  artifact: `external-${target}`,
  artifact_sha256: "b".repeat(64),
  copied_outside_source: true,
  exit_code: 0,
  stderr: "",
  stdout:
    '{"schema":"gorce.s1.hello/v1","hello":"gorce-tui-harness","package":"@gorce-ai/tui-harness","core":"@gorce-ai/core","ok":true}',
  payload: {
    schema: "gorce.s1.hello/v1",
    hello: "gorce-tui-harness",
    package: "@gorce-ai/tui-harness",
    core: "@gorce-ai/core",
    ok: true,
  },
  native_execution: true,
})

describe("S1 Oracle blocker regressions", () => {
  test("rejects API, Cargo, Rust, and non-Bun production artifacts but permits historical docs", async () => {
    const root = await mkdtemp(join(tmpdir(), "gorce-s1-production-"))
    try {
      await mkdir(join(root, "api/schemas"), { recursive: true })
      await writeFile(join(root, "api/schemas/health.schema.json"), "{}\n")
      expect((await scanProductionTree(root)).length).toBeGreaterThan(0)
      await rm(join(root, "api"), { recursive: true, force: true })
      await mkdir(join(root, "docs"), { recursive: true })
      await writeFile(join(root, "docs/adr.md"), "Historical Cargo and Rust decision\n")
      await writeFile(join(root, "Cargo.toml"), "[workspace]\n")
      expect((await scanProductionTree(root)).some((item) => item.includes("Cargo.toml"))).toBe(
        true,
      )
      await mkdir(join(root, "src/architecture"), { recursive: true })
      await writeFile(
        join(root, "src/architecture/ecosystem.ts"),
        'Bun.spawn(["go", "run", "tool.go"])\n',
      )
      expect(
        (await scanProductionTree(root)).some((item) => item.includes("executable invocation")),
      ).toBe(true)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  test("rejects missing, broken, and cyclic project reference graphs and output", async () => {
    const root = await mkdtemp(join(tmpdir(), "gorce-s1-graph-"))
    try {
      await copyFixture(root)
      expect(await validateProjectReferenceGraph(root)).toEqual([])
      await writeFile(
        join(root, "packages/tui-harness/tsconfig.json"),
        JSON.stringify({
          extends: "../../tsconfig.options.json",
          references: [{ path: "../missing" }],
        }),
      )
      expect((await validateProjectReferenceGraph(root)).length).toBeGreaterThan(0)
      await copyFixture(root)
      await writeFile(
        join(root, "packages/core/tsconfig.json"),
        JSON.stringify({
          extends: "../../tsconfig.options.json",
          references: [{ path: "../tui-harness" }],
          include: ["src/**/*.ts"],
        }),
      )
      expect(
        (await validateProjectReferenceGraph(root)).some((item) => item.includes("cycle")),
      ).toBe(true)
      await mkdir(join(root, "dist"), { recursive: true })
      expect((await generatedOutputs(root)).some((item) => item === "dist")).toBe(true)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  test("schema-validates mutated native evidence and requires the exact native lane set", async () => {
    const records = [
      nativeRecord("bun-linux-x64", "linux", "x64"),
      nativeRecord("bun-darwin-arm64", "darwin", "arm64"),
      nativeRecord("bun-windows-x64", "win32", "x64"),
    ]
    expect(validateNativeLaneSet(records)).toEqual([])
    const duplicate = records.map((record) => ({ ...record }))
    const third = duplicate[2]
    if (third === undefined) throw new Error("native fixture is incomplete")
    duplicate[2] = { ...third, target: "bun-linux-x64" }
    expect(validateNativeLaneSet(duplicate)).not.toEqual([])
    const schema = JSON.parse(await Bun.file("tests/qa/s1-native-hello.schema.json").text())
    const first = records[0]
    if (first === undefined) throw new Error("native fixture is incomplete")
    expect(validateJsonSchema(first, schema, schema)).toEqual([])
    expect(
      validateJsonSchema({ ...first, release_claim: true }, schema, schema).length,
    ).toBeGreaterThan(0)
    const index = {
      schema: "gorce.s1.native-index/v1",
      source_commit: first.source_commit,
      task6_baseline_sha256: first.task6_baseline_sha256,
      builder_bun: first.builder_bun,
      release_claim: false,
      scope: first.scope,
      entries: records.map((record, index) => ({ name: `lane-${index}`, ...record })),
      aggregate: "native-hello-only",
    }
    expect(await schemaErrors(process.cwd(), "s1-native-index.schema.json", index)).toEqual([])
    expect(
      await schemaErrors(process.cwd(), "s1-native-index.schema.json", {
        ...index,
        entries: records,
      }),
    ).not.toEqual([])
  })

  test("preserves the Windows executable suffix through copied native execution", () => {
    expect(nativeArtifactName("bun-windows-x64")).toBe("gorce-tui-harness-bun-windows-x64.exe")
    expect(copiedArtifactPath("external-gorce-native", "bun-windows-x64")).toEndWith(".exe")
  })

  test("binds the N/A mutation gate to the exact inventory and current baseline", async () => {
    const evidence = mutationEvidence(process.cwd())
    expect(
      await schemaErrors(
        process.cwd(),
        "s1-mutation-gate.schema.json",
        evidence as unknown as JsonValue,
      ),
    ).toEqual([])
    expect(evidence.baseline_sha256).toBe(currentTask6BaselineSha256(process.cwd()))
    expect(
      validateS1Provenance("1.3.13", evidence.baseline_sha256, evidence.baseline_sha256),
    ).not.toEqual([])
    expect(validateS1Provenance("1.3.14", "0".repeat(64), evidence.baseline_sha256)).not.toEqual([])

    const root = await mkdtemp(join(tmpdir(), "gorce-s1-mutation-"))
    try {
      for (const path of [
        "packages/core/src/index.ts",
        "packages/tui-harness/src/index.ts",
        "apps/tui-harness/src/main.ts",
      ]) {
        const destination = join(root, path)
        await mkdir(dirname(destination), { recursive: true })
        await copyFile(path, destination)
      }
      expect((await inspectMutationApplicability(root)).applicable).toBe(true)
      for (const behavior of [
        "policy compatibility",
        "commands events effects",
        "state transition",
        "persistence",
        "reconciliation",
      ]) {
        await writeFile(
          join(root, "packages/core/src/index.ts"),
          `export const injected = ${JSON.stringify(behavior)}\n`,
        )
        expect((await inspectMutationApplicability(root)).applicable).toBe(false)
        await copyFile("packages/core/src/index.ts", join(root, "packages/core/src/index.ts"))
      }
      await writeFile(join(root, "packages/core/src/extra.ts"), "export const extra = true\n")
      expect((await inspectMutationApplicability(root)).applicable).toBe(false)
      await rm(join(root, "packages/core/src/extra.ts"))
      await writeFile(join(root, "packages/core/src/index.ts"), "export const storage = true\n")
      expect((await inspectMutationApplicability(root)).applicable).toBe(false)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })
})
