import { existsSync, readdirSync, statSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { combineReports } from "./combine.js"
import { verifyManifestFile } from "./manifest-file.js"
import type { CheckResult, VerificationReport } from "./types.js"

const failure = (detail: string): VerificationReport => ({
  schema: "gorce.verification-result/v1",
  command: "verify:evidence",
  ok: false,
  checks: [{ name: "evidence-directory", status: "failed", detail }],
  errors: [detail],
})

export const verifyEvidenceDirectory = async (directory: string): Promise<VerificationReport> => {
  if (!existsSync(directory) || !statSync(directory).isDirectory())
    return failure("evidence directory is missing")
  const entries = readdirSync(directory)
  if (entries.length === 0) return failure("evidence directory is empty")

  const checks: CheckResult[] = [
    { name: "evidence-directory", status: "passed" },
    { name: "evidence-nonempty", status: "passed" },
  ]
  const errors: string[] = []
  const indexPath = join(directory, "evidence.json")
  if (existsSync(indexPath)) {
    try {
      const index: unknown = JSON.parse(readFileSync(indexPath, "utf8"))
      const isValid =
        typeof index === "object" &&
        index !== null &&
        !Array.isArray(index) &&
        "schema" in index &&
        index.schema === "gorce.task-evidence/v1" &&
        "task" in index &&
        index.task === "03"
      checks.push({
        name: "evidence-schema",
        status: isValid ? "passed" : "failed",
        ...(isValid ? {} : { detail: "evidence schema or task is invalid" }),
      })
      if (!isValid) errors.push("evidence schema or task is invalid")
    } catch {
      checks.push({
        name: "evidence-schema",
        status: "failed",
        detail: "evidence index is malformed JSON",
      })
      errors.push("evidence index is malformed JSON")
    }
  }

  const manifestPath = join(directory, "execution-manifest.json")
  if (existsSync(manifestPath)) {
    const manifest = await verifyManifestFile({ manifestPath })
    return combineReports("verify:evidence", [
      {
        schema: "gorce.verification-result/v1",
        command: "verify:evidence",
        ok: errors.length === 0,
        checks,
        errors,
      },
      manifest,
    ])
  }
  return {
    schema: "gorce.verification-result/v1",
    command: "verify:evidence",
    ok: errors.length === 0,
    checks,
    errors,
  }
}
