// biome-ignore-all lint/complexity/useLiteralKeys: Native evidence is validated through JSON keys.

import { nativeTargets, runnerTarget, type NativeTarget } from "./s1-native.js"
import { validProvenance } from "./s1-evidence.js"

export const validateNativeLaneSet = (
  records: readonly Record<string, unknown>[],
): readonly string[] => {
  const errors: string[] = []
  const targets = records.map((record) => record["target"])
  const targetSet = new Set(targets)
  if (records.length !== nativeTargets.length)
    errors.push("exactly three native hello lanes are required")
  if (targetSet.size !== records.length) errors.push("native hello lanes must have unique targets")
  for (const target of nativeTargets) {
    if (!targetSet.has(target)) errors.push(`missing native lane ${target}`)
  }
  const sourceCommits = new Set<string>()
  for (const record of records) {
    if (record["schema"] !== "gorce.s1.native-hello/v1")
      errors.push("native index contains a non-hello document")
    if (record["native_execution"] !== true)
      errors.push("native index contains a non-native execution")
    if (!validProvenance(record)) errors.push("native evidence provenance is not S1-bound")
    const source = record["source_commit"]
    if (typeof source === "string") sourceCommits.add(source)
    const os = record["runner_os"]
    const architecture = record["runner_arch"]
    if (
      typeof record["target"] !== "string" ||
      typeof os !== "string" ||
      typeof architecture !== "string" ||
      record["target"] !== runnerTarget(os, architecture)
    )
      errors.push("native target does not correspond to its runner host")
  }
  if (sourceCommits.size !== 1) errors.push("all native lanes must bind one source commit")
  return [...new Set(errors)]
}

export const nativeTarget = (value: unknown): value is NativeTarget =>
  typeof value === "string" && nativeTargets.includes(value as NativeTarget)
