import { describe, expect, test } from "bun:test"
import { readFile } from "node:fs/promises"
import { join } from "node:path"
import { verifyS1 } from "../src/verification/s1.js"

describe("S1 core-first Bun cutover", () => {
  test("verifies the exact private workspace graph", async () => {
    const result = await verifyS1(process.cwd())
    expect(result.errors).toEqual([])
    expect(result.evidence.verdict).toBe("APPROVED")
    expect(result.evidence.checks.every((item) => item.ok)).toBe(true)
  })

  test("keeps the hello payload semantic-free and deterministic", () => {
    expect({
      schema: "gorce.s1.hello/v1",
      hello: "gorce-tui-harness",
      package: "@gorce-ai/tui-harness",
      core: "@gorce-ai/core",
      ok: true,
    }).toEqual({
      schema: "gorce.s1.hello/v1",
      hello: "gorce-tui-harness",
      package: "@gorce-ai/tui-harness",
      core: "@gorce-ai/core",
      ok: true,
    })
  })

  test("runs the source executable without arguments", async () => {
    const processHandle = Bun.spawn(
      [process.execPath, join(process.cwd(), "apps/tui-harness/src/main.ts")],
      {
        cwd: process.cwd(),
        stdout: "pipe",
        stderr: "pipe",
      },
    )
    const [exitCode, stdout, stderr] = await Promise.all([
      processHandle.exited,
      new Response(processHandle.stdout).text(),
      new Response(processHandle.stderr).text(),
    ])
    expect(exitCode).toBe(0)
    expect(stderr).toBe("")
    expect(JSON.parse(stdout)).toEqual({
      schema: "gorce.s1.hello/v1",
      hello: "gorce-tui-harness",
      package: "@gorce-ai/tui-harness",
      core: "@gorce-ai/core",
      ok: true,
    })
  })

  test("keeps the S1 evidence contract present", async () => {
    const schema = JSON.parse(await readFile("tests/qa/s1-cutover.schema.json", "utf8")) as {
      readonly $id: string
      readonly properties: Record<string, unknown>
    }
    expect(schema.$id).toBe("https://gorce.ai/schemas/s1-cutover.v1.json")
    expect(Object.hasOwn(schema.properties, "verdict")).toBe(true)
    expect(Object.hasOwn(schema.properties, "checks")).toBe(true)
  })
})
