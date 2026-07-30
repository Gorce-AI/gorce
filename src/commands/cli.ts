import type { CheckResult, VerificationReport } from "../verification/types.js"

export interface CliOptions {
  readonly flags: ReadonlyMap<string, string>
  readonly switches: ReadonlySet<string>
}

export const parseCli = (args: readonly string[]): CliOptions => {
  const flags = new Map<string, string>()
  const switches = new Set<string>()
  for (const argument of args) {
    if (!argument.startsWith("--")) continue
    const value = argument.slice(2)
    const separator = value.indexOf("=")
    if (separator === -1) switches.add(value)
    else flags.set(value.slice(0, separator), value.slice(separator + 1))
  }
  return { flags, switches }
}

export const flag = (options: CliOptions, name: string): string | undefined =>
  options.flags.get(name)

export const hasSwitch = (options: CliOptions, name: string): boolean => options.switches.has(name)

export const failed = (command: string, detail: string): VerificationReport => ({
  schema: "gorce.verification-result/v1",
  command,
  ok: false,
  checks: [{ name: "arguments", status: "failed", detail }],
  errors: [detail],
})

const human = (report: VerificationReport): string => {
  const lines = [`${report.ok ? "PASS" : "FAIL"} ${report.command}`]
  for (const check of report.checks) {
    const suffix = check.detail === undefined ? "" : `: ${check.detail}`
    lines.push(`- ${check.status.toUpperCase()} ${check.name}${suffix}`)
  }
  return lines.join("\n")
}

export const emit = (report: VerificationReport, json: boolean): void => {
  process.stdout.write(`${json ? JSON.stringify(report) : human(report)}\n`)
  if (!report.ok) process.exitCode = 1
}

export const pass = (command: string, name: string): VerificationReport => ({
  schema: "gorce.verification-result/v1",
  command,
  ok: true,
  checks: [{ name, status: "passed" } satisfies CheckResult],
  errors: [],
})
