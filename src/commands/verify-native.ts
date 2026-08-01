// biome-ignore-all lint/complexity/useLiteralKeys: Native hello payloads are validated through JSON keys.

import { cp, mkdtemp, rm } from "node:fs/promises"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { emit, failed, flag, parseStrictCli, type StrictCliSpec } from "./cli.js"
import {
  atomicJson,
  bunVersion,
  copiedArtifactPath,
  ensureExecutable,
  externalPath,
  helloSchema,
  hostTarget,
  nativeTargets,
  provenance,
  runnerTarget,
  sha256,
} from "../verification/s1-native.js"
import { schemaErrors } from "../verification/s1-evidence.js"
import type { JsonValue } from "../verification/json-schema.js"

const cliSpec: StrictCliSpec = {
  flags: ["artifact", "evidence", "target", "builder-bun"],
  switches: ["json"],
}

const main = async (): Promise<void> => {
  const parsed = parseStrictCli(process.argv.slice(2), cliSpec)
  if (!parsed.ok) {
    emit(failed("verify:native", parsed.error), process.argv.includes("--json"))
    process.exitCode = 1
    return
  }
  const artifact = flag(parsed.options, "artifact")
  const evidencePath = flag(parsed.options, "evidence")
  const targetOption = flag(parsed.options, "target")
  const builderBun = flag(parsed.options, "builder-bun")
  if (
    artifact === undefined ||
    evidencePath === undefined ||
    targetOption === undefined ||
    builderBun === undefined
  ) {
    emit(
      failed("verify:native", "--artifact, --evidence, --target, and --builder-bun are required"),
      parsed.options.switches.has("json"),
    )
    process.exitCode = 1
    return
  }
  const target = targetOption
  if (!nativeTargets.includes(target as (typeof nativeTargets)[number])) {
    emit(
      failed("verify:native", `unsupported S1 native target: ${target}`),
      parsed.options.switches.has("json"),
    )
    process.exitCode = 1
    return
  }
  const outputEvidencePath = externalPath(process.cwd(), evidencePath, "native hello evidence")
  const artifactPath = externalPath(process.cwd(), artifact, "native artifact")
  const temporaryRoot = await mkdtemp(join(tmpdir(), "gorce-s1-native-run-"))
  const copied = copiedArtifactPath(temporaryRoot, target)
  try {
    await cp(artifactPath, copied)
    await ensureExecutable(copied)
    const processHandle = Bun.spawn([copied], {
      cwd: temporaryRoot,
      stdout: "pipe",
      stderr: "pipe",
    })
    const [exitCode, stdout, stderr] = await Promise.all([
      processHandle.exited,
      new Response(processHandle.stdout).text(),
      new Response(processHandle.stderr).text(),
    ])
    const output = stdout.trim()
    let payload: Record<string, unknown> | null = null
    try {
      const value: unknown = JSON.parse(output)
      if (typeof value === "object" && value !== null && !Array.isArray(value))
        payload = value as Record<string, unknown>
    } catch {
      payload = null
    }
    const semanticValid =
      exitCode === 0 &&
      stderr.trim().length === 0 &&
      payload !== null &&
      payload["schema"] === helloSchema &&
      payload["hello"] === "gorce-tui-harness" &&
      payload["ok"] === true &&
      target === hostTarget() &&
      target === runnerTarget(process.platform, process.arch) &&
      builderBun === bunVersion &&
      Bun.version === bunVersion &&
      copied.endsWith(target.includes("windows") ? ".exe" : "")
    const evidence = {
      schema: "gorce.s1.native-hello/v1",
      target,
      ...provenance(process.cwd()),
      builder_bun: builderBun,
      runner_os: process.platform,
      runner_arch: process.arch,
      artifact: artifactPath,
      artifact_sha256: await sha256(artifactPath),
      copied_outside_source: true,
      exit_code: exitCode,
      stderr: stderr.trim(),
      stdout: output,
      payload,
      native_execution: semanticValid,
    }
    const schemaFailures = await schemaErrors(
      process.cwd(),
      "s1-native-hello.schema.json",
      evidence as unknown as JsonValue,
    )
    const valid = semanticValid && schemaFailures.length === 0
    await atomicJson(outputEvidencePath, { ...evidence, native_execution: valid })
    emit(
      {
        schema: "gorce.verification-result/v1",
        command: "verify:native",
        ok: valid,
        checks: [
          {
            name: "native-hello",
            status: valid ? "passed" : "failed",
            detail: JSON.stringify(evidence),
          },
        ],
        errors: valid ? [] : ["S1_NATIVE_HELLO: native hello output is invalid", ...schemaFailures],
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
      "verify:native",
      error instanceof Error ? error.message : "native hello verification failed",
    ),
    process.argv.includes("--json"),
  )
  process.exitCode = 1
})
