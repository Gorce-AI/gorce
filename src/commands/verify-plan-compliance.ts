import { combineReports } from "../verification/combine.js"
import { verifyManifestFile } from "../verification/manifest-file.js"
import { verifyPlanPolicy } from "../verification/plan.js"
import type { ManifestFileOptions } from "../verification/manifest-file.js"
import { emit, flag, hasSwitch, parseCli } from "./cli.js"

const main = async (): Promise<void> => {
  const options = parseCli(process.argv.slice(2))
  const policy = verifyPlanPolicy()
  const manifestPath = flag(options, "execution-manifest")
  const publicKeyPath = flag(options, "public-key")
  const manifestOptions: ManifestFileOptions | null =
    manifestPath === undefined
      ? null
      : publicKeyPath === undefined
        ? { manifestPath }
        : { manifestPath, publicKeyPath }
  const manifest = manifestOptions === null ? null : await verifyManifestFile(manifestOptions)
  emit(
    manifest === null
      ? { ...policy, command: "verify:plan-compliance" }
      : combineReports("verify:plan-compliance", [policy, manifest]),
    hasSwitch(options, "json"),
  )
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "unexpected verification failure"
  emit(
    {
      schema: "gorce.verification-result/v1",
      command: "verify:plan-compliance",
      ok: false,
      checks: [{ name: "execution", status: "failed", detail: message }],
      errors: [message],
    },
    process.argv.includes("--json"),
  )
})
