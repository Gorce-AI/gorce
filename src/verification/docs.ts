import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"
import type { CheckResult, VerificationReport } from "./types.js"

const requiredDocuments = [
  "README.md",
  "LICENSE",
  "docs/development.md",
  "docs/execution-tooling.md",
  "docs/architecture.md",
  "docs/adr/0001-daemon-boundary.md",
  "docs/adr/0002-filesystem-first-storage.md",
  "docs/adr/0003-repository-topology.md",
  "docs/adr/0004-s1-cutover.md",
  "docs/adr/0005-s2-semantic-core.md",
] as const

export const verifyDocs = (root: string): VerificationReport => {
  const checks: CheckResult[] = []
  const errors: string[] = []
  for (const document of requiredDocuments) {
    const present = existsSync(join(root, document))
    checks.push({
      name: `document:${document}`,
      status: present ? "passed" : "failed",
      ...(present ? {} : { detail: `required document is missing: ${document}` }),
    })
    if (!present) errors.push(`required document is missing: ${document}`)
  }

  const toolingPath = join(root, "docs/execution-tooling.md")
  if (existsSync(toolingPath)) {
    const text = readFileSync(toolingPath, "utf8")
    const complete = [
      "verify:bootstrap",
      "qa:task",
      "verify:plan-compliance",
      "docs:verify",
      "verify:s2",
      "test:mutation",
      "build:native",
      "verify:native",
      "verify:reproducible",
      "bun audit",
    ].every((term) => text.includes(term))
    checks.push({
      name: "tooling-documentation",
      status: complete ? "passed" : "failed",
      ...(complete ? {} : { detail: "execution tooling documentation is incomplete" }),
    })
    if (!complete) errors.push("execution tooling documentation is incomplete")
  }

  return {
    schema: "gorce.verification-result/v1",
    command: "docs:verify",
    ok: errors.length === 0,
    checks,
    errors,
  }
}
