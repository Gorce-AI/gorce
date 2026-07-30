import type { CheckResult, VerificationReport } from "./types.js"

export const combineReports = (
  command: string,
  reports: readonly VerificationReport[],
): VerificationReport => {
  const checks: CheckResult[] = []
  const errors: string[] = []
  for (const report of reports) {
    checks.push(...report.checks)
    errors.push(...report.errors)
  }
  return {
    schema: "gorce.verification-result/v1",
    command,
    ok: errors.length === 0,
    checks,
    errors,
  }
}
