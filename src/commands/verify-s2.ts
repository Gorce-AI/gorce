import { atomicJson, defaultExternalEvidencePath, externalPath } from "../verification/s1-native.js"
import { schemaErrors } from "../verification/s1-evidence.js"
import type { JsonValue } from "../verification/json-schema.js"
import { emit, failed, flag, parseStrictCli, type StrictCliSpec } from "./cli.js"
import { verifyS2 } from "../verification/s2.js"

const cliSpec: StrictCliSpec = { flags: ["evidence"], switches: ["json", "strict"] }

const main = async (): Promise<void> => {
  const parsed = parseStrictCli(process.argv.slice(2), cliSpec)
  if (!parsed.ok) {
    emit(failed("verify:s2", parsed.error), process.argv.includes("--json"))
    process.exitCode = 1
    return
  }
  try {
    const root = process.cwd()
    const report = await verifyS2(root)
    const failures = await schemaErrors(
      root,
      "s2-semantic-core.schema.json",
      report.evidence as unknown as JsonValue,
    )
    const errors = [...report.errors, ...failures.map((failure) => `S2_SCHEMA: ${failure}`)]
    const evidenceOption = flag(parsed.options, "evidence")
    const output = externalPath(
      root,
      evidenceOption ?? defaultExternalEvidencePath("s2-semantic-core.json"),
      "S2 evidence",
    )
    await atomicJson(output, report.evidence)
    emit(
      {
        schema: "gorce.verification-result/v1",
        command: "verify:s2",
        ok: errors.length === 0,
        verdict: errors.length === 0 ? "APPROVED" : "CHANGES_REQUESTED",
        checks: report.evidence.checks.map((item) => ({
          name: item.name,
          status: item.ok ? "passed" : "failed",
          detail: item.reason,
        })),
        errors,
      },
      parsed.options.switches.has("json"),
    )
    if (parsed.options.switches.has("strict") && errors.length > 0) process.exitCode = 1
  } catch (error: unknown) {
    emit(
      failed("verify:s2", error instanceof Error ? error.message : "S2 verification failed"),
      parsed.options.switches.has("json"),
    )
    process.exitCode = 1
  }
}

main().catch((error: unknown) => {
  emit(
    failed("verify:s2", error instanceof Error ? error.message : "S2 verification failed"),
    process.argv.includes("--json"),
  )
  process.exitCode = 1
})
