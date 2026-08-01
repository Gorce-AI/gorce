import { mkdir } from "node:fs/promises"
import { dirname, join, resolve } from "node:path"
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

const cliSpec: StrictCliSpec = { flags: ["target", "outfile", "evidence"], switches: ["json"] }

const main = async (): Promise<void> => {
  const parsed = parseStrictCli(process.argv.slice(2), cliSpec)
  if (!parsed.ok) {
    emit(failed("build:native", parsed.error), process.argv.includes("--json"))
    process.exitCode = 1
    return
  }
  const root = process.cwd()
  const target = flag(parsed.options, "target") ?? hostTarget()
  const outfileOption = flag(parsed.options, "outfile")
  const evidenceOption = flag(parsed.options, "evidence")
  if (!nativeTargets.includes(target as (typeof nativeTargets)[number])) {
    emit(
      failed("build:native", `unsupported S1 native target: ${target}`),
      parsed.options.switches.has("json"),
    )
    process.exitCode = 1
    return
  }
  if (Bun.version !== bunVersion) {
    emit(
      failed("build:native", `Bun ${bunVersion} is required, found ${Bun.version}`),
      parsed.options.switches.has("json"),
    )
    process.exitCode = 1
    return
  }
  const outfile = externalPath(
    root,
    outfileOption ?? defaultExternalEvidencePath(join("native", nativeArtifactName(target))),
    "native artifact",
  )
  const evidencePath = externalPath(
    root,
    evidenceOption ?? defaultExternalEvidencePath(join("native", `build-${target}.json`)),
    "native build evidence",
  )
  await mkdir(dirname(outfile), { recursive: true })
  const processHandle = Bun.spawn(
    [
      process.execPath,
      "build",
      "--compile",
      `--target=${target}`,
      resolve(root, "apps/tui-harness/src/main.ts"),
      "--outfile",
      outfile,
    ],
    { cwd: root, stdout: "pipe", stderr: "pipe" },
  )
  const [exitCode, stdout, stderr] = await Promise.all([
    processHandle.exited,
    new Response(processHandle.stdout).text(),
    new Response(processHandle.stderr).text(),
  ])
  if (exitCode !== 0) {
    emit(failed("build:native", `${stdout}${stderr}`.trim()), parsed.options.switches.has("json"))
    process.exitCode = 1
    return
  }
  const evidence = {
    schema: "gorce.s1.native-build/v1",
    target,
    ...provenance(root),
    source: "apps/tui-harness/src/main.ts",
    artifact: outfile,
    artifact_sha256: await sha256(outfile),
    exit_code: exitCode,
  }
  const failures = await schemaErrors(
    root,
    "s1-native-build.schema.json",
    evidence as unknown as JsonValue,
  )
  await atomicJson(evidencePath, evidence)
  emit(
    {
      schema: "gorce.verification-result/v1",
      command: "build:native",
      ok: failures.length === 0,
      checks: [
        {
          name: "native-build",
          status: failures.length === 0 ? "passed" : "failed",
          detail: JSON.stringify(evidence),
        },
      ],
      errors: failures,
    },
    parsed.options.switches.has("json"),
  )
  process.exitCode = failures.length === 0 ? 0 : 1
}

main().catch((error: unknown) => {
  emit(
    failed("build:native", error instanceof Error ? error.message : "native build failed"),
    process.argv.includes("--json"),
  )
  process.exitCode = 1
})
