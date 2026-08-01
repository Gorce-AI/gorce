import { mkdir, rename, unlink, writeFile } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import { emit, failed, flag, parseStrictCli, type StrictCliSpec } from "./cli.js"
import { verifyS1 } from "../verification/s1.js"
import { defaultExternalEvidencePath, externalPath } from "../verification/s1-native.js"
import { schemaErrors } from "../verification/s1-evidence.js"
import type { JsonValue } from "../verification/json-schema.js"

const cliSpec: StrictCliSpec = {
  flags: ["root", "evidence"],
  switches: ["strict", "json"],
}

const atomicWrite = async (path: string, value: unknown): Promise<void> => {
  await mkdir(dirname(path), { recursive: true })
  const temporary = `${path}.tmp-${process.pid}`
  await unlink(temporary).catch(() => undefined)
  try {
    await writeFile(temporary, `${JSON.stringify(value)}\n`, { flag: "wx" })
    await rename(temporary, path)
  } catch (error: unknown) {
    await unlink(temporary).catch(() => undefined)
    throw error
  }
}

const main = async (): Promise<void> => {
  const parsed = parseStrictCli(process.argv.slice(2), cliSpec)
  if (!parsed.ok) {
    emit(failed("verify:s1", parsed.error), process.argv.includes("--json"))
    process.exitCode = 1
    return
  }
  if (!parsed.options.switches.has("strict")) {
    emit(failed("verify:s1", "--strict is required"), parsed.options.switches.has("json"))
    process.exitCode = 1
    return
  }
  const root = resolve(flag(parsed.options, "root") ?? process.cwd())
  const evidencePath =
    flag(parsed.options, "evidence") ?? defaultExternalEvidencePath("cutover.json")
  try {
    const result = await verifyS1(root)
    const output = externalPath(root, evidencePath, "S1 evidence")
    const schemaFailures = await schemaErrors(
      root,
      "s1-cutover.schema.json",
      result.evidence as unknown as JsonValue,
    )
    if (schemaFailures.length > 0)
      throw new Error(`S1 evidence schema failure: ${schemaFailures.join("; ")}`)
    await atomicWrite(output, result.evidence)
    emit(
      {
        schema: "gorce.verification-result/v1",
        command: "verify:s1",
        ok: result.errors.length === 0,
        verdict: result.evidence.verdict,
        checks: result.evidence.checks.map((item) => ({
          name: item.name,
          status: item.ok ? "passed" : "failed",
          ...(item.ok ? {} : { detail: `${item.code}: ${item.reason}` }),
        })),
        errors: result.errors,
      },
      parsed.options.switches.has("json"),
    )
    process.exitCode = result.errors.length === 0 ? 0 : 1
  } catch (error: unknown) {
    emit(
      failed(
        "verify:s1",
        error instanceof Error ? error.message : "unexpected S1 verification failure",
      ),
      parsed.options.switches.has("json"),
    )
    process.exitCode = 1
  }
}

main().catch((error: unknown) => {
  emit(
    failed(
      "verify:s1",
      error instanceof Error ? error.message : "unexpected S1 verification failure",
    ),
    process.argv.includes("--json"),
  )
  process.exitCode = 1
})
