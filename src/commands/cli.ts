import type { CheckResult, VerificationReport } from "../verification/types.js"

export interface CliOptions {
  readonly flags: ReadonlyMap<string, string>
  readonly switches: ReadonlySet<string>
}

export interface StrictCliSpec {
  readonly flags: readonly string[]
  readonly switches: readonly string[]
}

export type StrictCliResult =
  | { readonly ok: true; readonly options: CliOptions }
  | { readonly ok: false; readonly error: string }

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

export const parseStrictCli = (args: readonly string[], spec: StrictCliSpec): StrictCliResult => {
  const flags = new Map<string, string>()
  const switches = new Set<string>()
  const allowedFlags = new Set(spec.flags)
  const allowedSwitches = new Set(spec.switches)
  for (const argument of args) {
    if (!argument.startsWith("--") || argument === "--") {
      return { ok: false, error: `positional argument is not allowed: ${argument}` }
    }
    const value = argument.slice(2)
    const separator = value.indexOf("=")
    if (separator === -1) {
      if (!allowedSwitches.has(value)) return { ok: false, error: `unknown option --${value}` }
      if (switches.has(value)) return { ok: false, error: `duplicate option --${value}` }
      switches.add(value)
      continue
    }
    const name = value.slice(0, separator)
    const flagValue = value.slice(separator + 1)
    if (!allowedFlags.has(name)) return { ok: false, error: `unknown option --${name}` }
    if (flagValue.length === 0) return { ok: false, error: `empty value for --${name}` }
    if (flags.has(name)) return { ok: false, error: `duplicate option --${name}` }
    flags.set(name, flagValue)
  }
  return { ok: true, options: { flags, switches } }
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
