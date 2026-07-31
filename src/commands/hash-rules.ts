import { mkdir, rename, unlink, writeFile } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import { emit, failed, flag, parseStrictCli, type StrictCliSpec } from "./cli.js"
import { STUDIO_HOST_GATE_SCHEMA, TECHNOLOGY_BASELINE_SCHEMA } from "../architecture/rules.js"
import { readCanonicalYaml } from "../architecture/yaml.js"
import type { VerificationReport } from "../verification/types.js"

const cliSpec: StrictCliSpec = {
  flags: ["technology", "studio", "evidence"],
  switches: ["json"],
}

const writeAtomic = async (path: string, content: string): Promise<void> => {
  await mkdir(dirname(path), { recursive: true })
  const temporary = `${path}.tmp-${process.pid}`
  try {
    await writeFile(temporary, content, { encoding: "utf8", flag: "wx" })
    await rename(temporary, path)
  } catch (error: unknown) {
    await unlink(temporary).catch(() => undefined)
    throw error
  }
}

const main = async (): Promise<void> => {
  const parsed = parseStrictCli(process.argv.slice(2), cliSpec)
  if (!parsed.ok) {
    emit(failed("architecture:hash-rules", parsed.error), process.argv.includes("--json"))
    return
  }
  const technology = flag(parsed.options, "technology")
  const studio = flag(parsed.options, "studio")
  const evidence = flag(parsed.options, "evidence")
  if (technology === undefined || studio === undefined || evidence === undefined) {
    emit(
      failed("architecture:hash-rules", "--technology, --studio, and --evidence are required"),
      parsed.options.switches.has("json"),
    )
    return
  }
  try {
    const technologyRule = await readCanonicalYaml(resolve(technology), TECHNOLOGY_BASELINE_SCHEMA)
    const studioRule = await readCanonicalYaml(resolve(studio), STUDIO_HOST_GATE_SCHEMA)
    const output = `${JSON.stringify({
      schema: "gorce.architecture-rule-digests/v1",
      technology_sha256: technologyRule.sha256,
      studio_sha256: studioRule.sha256,
    })}\n`
    await writeAtomic(resolve(evidence), output)
    const report: VerificationReport = {
      schema: "gorce.verification-result/v1",
      command: "architecture:hash-rules",
      ok: true,
      checks: [
        { name: "technology-rule", status: "passed", detail: technologyRule.sha256 },
        { name: "studio-host-rule", status: "passed", detail: studioRule.sha256 },
        { name: "deterministic-evidence", status: "passed" },
      ],
      errors: [],
    }
    emit(report, parsed.options.switches.has("json"))
  } catch (error: unknown) {
    emit(
      failed(
        "architecture:hash-rules",
        error instanceof Error ? error.message : "cannot hash architecture rules",
      ),
      parsed.options.switches.has("json"),
    )
  }
}

main().catch((error: unknown) => {
  emit(
    failed(
      "architecture:hash-rules",
      error instanceof Error ? error.message : "unexpected rule hashing failure",
    ),
    process.argv.includes("--json"),
  )
})
