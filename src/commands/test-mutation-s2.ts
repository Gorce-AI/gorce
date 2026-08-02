import { atomicJson, defaultExternalEvidencePath, externalPath } from "../verification/s1-native.js"
import { schemaErrors } from "../verification/s1-evidence.js"
import type { JsonValue } from "../verification/json-schema.js"
import { runS2Mutation } from "../verification/mutation-s2.js"
import { emit, failed, flag, parseStrictCli, type StrictCliSpec } from "./cli.js"

const cliSpec: StrictCliSpec = { flags: ["evidence"], switches: ["json"] }

const main = async (): Promise<void> => {
  const parsed = parseStrictCli(process.argv.slice(2), cliSpec)
  if (!parsed.ok) {
    emit(failed("test:mutation", parsed.error), process.argv.includes("--json"))
    process.exitCode = 1
    return
  }
  try {
    const root = process.cwd()
    const evidence = await runS2Mutation(root)
    const failures = await schemaErrors(
      root,
      "s2-mutation-gate.schema.json",
      evidence as unknown as JsonValue,
    )
    if (failures.length > 0) throw new Error(`S2_MUTATION_SCHEMA: ${failures.join("; ")}`)
    if (evidence.verdict !== "APPROVED") throw new Error(`S2_MUTATION_SCORE: ${evidence.reason}`)
    const output = externalPath(
      root,
      flag(parsed.options, "evidence") ?? defaultExternalEvidencePath("s2-mutation-gate.json"),
      "S2 mutation evidence",
    )
    await atomicJson(output, evidence)
    emit(
      {
        schema: "gorce.verification-result/v1",
        command: "test:mutation",
        ok: true,
        verdict: evidence.verdict,
        checks: [{ name: "s2-mutation-gate", status: "passed", detail: JSON.stringify(evidence) }],
        errors: [],
      },
      parsed.options.switches.has("json"),
    )
  } catch (error: unknown) {
    emit(
      failed("test:mutation", error instanceof Error ? error.message : "S2 mutation gate failed"),
      parsed.options.switches.has("json"),
    )
    process.exitCode = 1
  }
}

main().catch((error: unknown) => {
  emit(
    failed("test:mutation", error instanceof Error ? error.message : "S2 mutation gate failed"),
    process.argv.includes("--json"),
  )
  process.exitCode = 1
})
