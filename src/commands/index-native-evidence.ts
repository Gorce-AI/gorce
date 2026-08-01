// biome-ignore-all lint/complexity/useLiteralKeys: Native evidence is validated through JSON keys.

import { readdir, readFile } from "node:fs/promises"
import { join } from "node:path"
import { emit, failed, flag, parseStrictCli, type StrictCliSpec } from "./cli.js"
import { atomicJson, externalPath } from "../verification/s1-native.js"
import { schemaErrors } from "../verification/s1-evidence.js"
import { validateNativeLaneSet } from "../verification/native-index.js"
import type { JsonValue } from "../verification/json-schema.js"

const cliSpec: StrictCliSpec = { flags: ["input", "output"], switches: ["json"] }

const main = async (): Promise<void> => {
  const parsed = parseStrictCli(process.argv.slice(2), cliSpec)
  if (!parsed.ok) {
    emit(failed("verify:native:index", parsed.error), process.argv.includes("--json"))
    process.exitCode = 1
    return
  }
  const inputOption = flag(parsed.options, "input")
  const outputOption = flag(parsed.options, "output")
  if (inputOption === undefined || outputOption === undefined) {
    emit(
      failed("verify:native:index", "--input and --output are required external paths"),
      parsed.options.switches.has("json"),
    )
    process.exitCode = 1
    return
  }
  try {
    const root = process.cwd()
    const input = externalPath(root, inputOption, "native evidence input")
    const output = externalPath(root, outputOption, "native index output")
    const entries: Record<string, unknown>[] = []
    for (const name of (await readdir(input)).filter((item) => item.endsWith(".json")).sort()) {
      const value: unknown = JSON.parse(await readFile(join(input, name), "utf8"))
      if (typeof value !== "object" || value === null || Array.isArray(value))
        throw new Error(`S1_NATIVE_INDEX: invalid native hello evidence ${name}`)
      const record = value as Record<string, unknown>
      const schemaName =
        record["schema"] === "gorce.s1.native-build/v1"
          ? "s1-native-build.schema.json"
          : "s1-native-hello.schema.json"
      const failures = await schemaErrors(root, schemaName, record as unknown as JsonValue)
      if (failures.length > 0)
        throw new Error(
          `S1_NATIVE_INDEX: invalid native hello evidence ${name}: ${failures.join("; ")}`,
        )
      if (record["schema"] === "gorce.s1.native-build/v1") continue
      if (record["schema"] !== "gorce.s1.native-hello/v1")
        throw new Error(`S1_NATIVE_INDEX: unsupported evidence schema ${name}`)
      entries.push({ name, ...record })
    }
    const laneFailures = validateNativeLaneSet(entries)
    if (laneFailures.length > 0) throw new Error(`S1_NATIVE_INDEX: ${laneFailures.join("; ")}`)
    const first = entries[0]
    if (first === undefined) throw new Error("S1_NATIVE_INDEX: no native hello evidence found")
    const evidence = {
      schema: "gorce.s1.native-index/v1",
      source_commit: first["source_commit"],
      task6_baseline_sha256: first["task6_baseline_sha256"],
      builder_bun: first["builder_bun"],
      release_claim: first["release_claim"],
      scope: first["scope"],
      entries,
      aggregate: "native-hello-only",
    }
    const schemaFailures = await schemaErrors(
      root,
      "s1-native-index.schema.json",
      evidence as unknown as JsonValue,
    )
    if (schemaFailures.length > 0)
      throw new Error(`S1_NATIVE_INDEX: schema failure: ${schemaFailures.join("; ")}`)
    await atomicJson(output, evidence)
    emit(
      {
        schema: "gorce.verification-result/v1",
        command: "verify:native:index",
        ok: true,
        checks: [{ name: "native-index", status: "passed", detail: JSON.stringify(evidence) }],
        errors: [],
      },
      parsed.options.switches.has("json"),
    )
  } catch (error: unknown) {
    emit(
      failed(
        "verify:native:index",
        error instanceof Error ? error.message : "native evidence indexing failed",
      ),
      parsed.options.switches.has("json"),
    )
    process.exitCode = 1
  }
}

main().catch((error: unknown) => {
  emit(
    failed(
      "verify:native:index",
      error instanceof Error ? error.message : "native evidence indexing failed",
    ),
    process.argv.includes("--json"),
  )
  process.exitCode = 1
})
