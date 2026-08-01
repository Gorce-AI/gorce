import { mkdtemp, rm } from "node:fs/promises"
import { join, resolve } from "node:path"
import { tmpdir } from "node:os"
import { emit, failed, flag, parseStrictCli, type StrictCliSpec } from "./cli.js"
import {
  atomicJson,
  bunVersion,
  defaultExternalEvidencePath,
  externalPath,
  hostTarget,
  nativeArtifactName,
  nativeTargets,
  provenance,
  sha256,
} from "../verification/s1-native.js"
import { schemaErrors } from "../verification/s1-evidence.js"
import type { JsonValue } from "../verification/json-schema.js"

const cliSpec: StrictCliSpec = { flags: ["target", "evidence"], switches: ["json"] }

const main = async (): Promise<void> => {
  const parsed = parseStrictCli(process.argv.slice(2), cliSpec)
  if (!parsed.ok) {
    emit(failed("verify:reproducible", parsed.error), process.argv.includes("--json"))
    process.exitCode = 1
    return
  }
  const evidencePath = flag(parsed.options, "evidence")
  const target = flag(parsed.options, "target") ?? hostTarget()
  if (!nativeTargets.includes(target as (typeof nativeTargets)[number])) {
    emit(
      failed("verify:reproducible", `unsupported S1 native target: ${target}`),
      parsed.options.switches.has("json"),
    )
    process.exitCode = 1
    return
  }
  if (Bun.version !== bunVersion) {
    emit(
      failed("verify:reproducible", `Bun ${bunVersion} is required, found ${Bun.version}`),
      parsed.options.switches.has("json"),
    )
    process.exitCode = 1
    return
  }
  const root = process.cwd()
  const outputEvidencePath = externalPath(
    root,
    evidencePath ?? defaultExternalEvidencePath("reproducibility.json"),
    "reproducibility evidence",
  )
  const temporaryRoot = await mkdtemp(join(tmpdir(), "gorce-s1-reproducible-"))
  try {
    const output = join(temporaryRoot, nativeArtifactName(target))
    const results: number[] = []
    const digests: string[] = []
    for (const _run of [1, 2]) {
      const processHandle = Bun.spawn(
        [
          process.execPath,
          "build",
          "--compile",
          `--target=${target}`,
          resolve(root, "apps/tui-harness/src/main.ts"),
          "--outfile",
          output,
        ],
        { cwd: root, stdout: "pipe", stderr: "pipe" },
      )
      const exitCode = await processHandle.exited
      results.push(exitCode)
      if (exitCode === 0) digests.push(await sha256(output))
    }
    const match =
      results.length === 2 &&
      results.every((code) => code === 0) &&
      digests.length === 2 &&
      digests[0] === digests[1]
    const evidence = {
      schema: "gorce.s1.reproducibility/v1",
      target,
      ...provenance(root),
      exit_codes: results,
      digests,
      match,
    }
    const schemaFailures = await schemaErrors(
      root,
      "s1-reproducibility.schema.json",
      evidence as unknown as JsonValue,
    )
    await atomicJson(outputEvidencePath, evidence)
    const valid = match && schemaFailures.length === 0
    emit(
      {
        schema: "gorce.verification-result/v1",
        command: "verify:reproducible",
        ok: valid,
        checks: [
          {
            name: "reproducible-build",
            status: valid ? "passed" : "failed",
            detail: JSON.stringify(evidence),
          },
        ],
        errors: valid
          ? []
          : ["S1_REPRODUCIBILITY: paired native build digests differ", ...schemaFailures],
      },
      parsed.options.switches.has("json"),
    )
    process.exitCode = valid ? 0 : 1
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true })
  }
}

main().catch((error: unknown) => {
  emit(
    failed(
      "verify:reproducible",
      error instanceof Error ? error.message : "reproducibility verification failed",
    ),
    process.argv.includes("--json"),
  )
  process.exitCode = 1
})
