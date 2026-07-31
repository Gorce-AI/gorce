import { combineReports } from "../verification/combine.js"
import { verifyEvidenceDirectory } from "../verification/evidence.js"
import { verifyManifestFile } from "../verification/manifest-file.js"
import { scanRepository } from "../verification/repository.js"
import { runF2FixtureManifest } from "../verification/f2.js"
import type { ManifestFileOptions } from "../verification/manifest-file.js"
import { emit, failed, flag, hasSwitch, parseStrictCli, type StrictCliSpec } from "./cli.js"

const cliSpec: StrictCliSpec = {
  flags: ["task", "evidence", "fixture", "execution-manifest", "public-key"],
  switches: ["all", "json"],
}

const main = async (): Promise<void> => {
  const parsed = parseStrictCli(process.argv.slice(2), cliSpec)
  if (!parsed.ok) {
    emit(failed("qa:task", parsed.error), process.argv.includes("--json"))
    return
  }
  const options = parsed.options
  const task = flag(options, "task")
  const evidencePath = flag(options, "evidence")
  if (task === "F2") {
    const fixture = flag(options, "fixture")
    if (!hasSwitch(options, "all") || fixture === undefined || evidencePath === undefined) {
      emit(
        failed("qa:task:F2", "--task=F2 requires --all, --fixture, and --evidence"),
        hasSwitch(options, "json"),
      )
      return
    }
    const report = await runF2FixtureManifest(fixture, evidencePath)
    emit(report, hasSwitch(options, "json"))
    return
  }
  if (task !== "03") {
    emit(failed("qa:task", "--task=03 is required"), hasSwitch(options, "json"))
    return
  }
  if (!hasSwitch(options, "all")) {
    emit(failed("qa:task", "--all is required for complete task QA"), hasSwitch(options, "json"))
    return
  }
  if (evidencePath === undefined || evidencePath.length === 0) {
    emit(failed("qa:task", "--evidence is required"), hasSwitch(options, "json"))
    return
  }

  const evidence = await verifyEvidenceDirectory(evidencePath)
  const repository = scanRepository(process.cwd())
  const manifestPath = flag(options, "execution-manifest")
  const publicKeyPath = flag(options, "public-key")
  const manifestOptions: ManifestFileOptions | null =
    manifestPath === undefined
      ? null
      : publicKeyPath === undefined
        ? { manifestPath }
        : { manifestPath, publicKeyPath }
  const manifest = manifestOptions === null ? null : await verifyManifestFile(manifestOptions)
  const reports = manifest === null ? [evidence, repository] : [evidence, repository, manifest]
  emit(combineReports("qa:task", reports), hasSwitch(options, "json"))
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "unexpected QA failure"
  emit(failed("qa:task", message), process.argv.includes("--json"))
})
