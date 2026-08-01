import {
  atomicJson,
  currentTask6BaselineSha256,
  defaultExternalEvidencePath,
  externalPath,
} from "../verification/s1-native.js"
import { inspectMutationApplicability, mutationEvidence } from "../verification/mutation.js"
import { schemaErrors } from "../verification/s1-evidence.js"
import type { JsonValue } from "../verification/json-schema.js"
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
    const applicability = await inspectMutationApplicability(root)
    if (!applicability.applicable)
      throw new Error(`S1_MUTATION_APPLICABILITY: ${applicability.reason}`)
    const evidence = mutationEvidence(root)
    const failures = await schemaErrors(
      root,
      "s1-mutation-gate.schema.json",
      evidence as unknown as JsonValue,
    )
    if (evidence.baseline_sha256 !== currentTask6BaselineSha256(root))
      throw new Error("S1_MUTATION_BASELINE: evidence baseline digest is not current")
    if (failures.length > 0) throw new Error(`S1_MUTATION_SCHEMA: ${failures.join("; ")}`)
    const evidenceOption = flag(parsed.options, "evidence")
    const output = externalPath(
      root,
      evidenceOption ?? defaultExternalEvidencePath("mutation-gate.json"),
      "mutation evidence",
    )
    await atomicJson(output, evidence)
    emit(
      {
        schema: "gorce.verification-result/v1",
        command: "test:mutation",
        ok: true,
        verdict: "NOT_APPLICABLE",
        checks: [{ name: "mutation-gate", status: "passed", detail: JSON.stringify(evidence) }],
        errors: [],
      },
      parsed.options.switches.has("json"),
    )
  } catch (error: unknown) {
    emit(
      failed("test:mutation", error instanceof Error ? error.message : "mutation gate failed"),
      parsed.options.switches.has("json"),
    )
    process.exitCode = 1
  }
}

main().catch((error: unknown) => {
  emit(
    failed("test:mutation", error instanceof Error ? error.message : "mutation gate failed"),
    process.argv.includes("--json"),
  )
  process.exitCode = 1
})
