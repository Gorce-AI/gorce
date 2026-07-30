import { execFileSync } from "node:child_process"
import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"
import type { CheckResult, RepositorySnapshot, VerificationReport } from "./types.js"

const PRIVATE_NAME =
  /(^|\/)(\.omo|approved-plan(?:\.md)?|execution-manifest(?:\.[^/]+)?|adversarialverify[^/]*|doneclaim[^/]*|tool-recovery[^/]*|receipts)(\/|$)|\.(?:key|pem|sig)$/i
const PRIVATE_ROOTS = ["Users", "home", "private", "var/folders", "tmp"]
const ABSOLUTE_PRIVATE_PATH = new RegExp(
  `(?:^|[\\s"'\`=])\\/(?:${PRIVATE_ROOTS.join("|")})\\/[^\\s"'\`]+`,
  "i",
)
const privateKeyHeader = (kind: string): string =>
  ["-----BEGIN", ...(kind.length === 0 ? [] : [kind]), "PRIVATE KEY-----"].join(" ")
const PRIVATE_KEY_HEADERS = ["", "RSA", "EC", "OPENSSH"].map(privateKeyHeader)
const CREDENTIAL = new RegExp(
  `(${PRIVATE_KEY_HEADERS.join("|")}|(?:ghp|github_pat)_[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9_-]{12,}|xox[baprs]-[A-Za-z0-9-]{12,}|(?:authorization|password|token|secret)\\s*[:=]\\s*[^\\s]+)`,
  "i",
)

const makeReport = (
  checks: readonly CheckResult[],
  errors: readonly string[],
): VerificationReport => ({
  schema: "gorce.verification-result/v1",
  command: "repository-integrity",
  ok: errors.length === 0,
  checks,
  errors,
})

const check = (
  checks: CheckResult[],
  errors: string[],
  name: string,
  valid: boolean,
  detail: string,
): void => {
  checks.push({ name, status: valid ? "passed" : "failed", ...(valid ? {} : { detail }) })
  if (!valid) errors.push(detail)
}

const runGit = (root: string, args: readonly string[]): string[] => {
  try {
    const output = execFileSync("git", [...args], { cwd: root, encoding: "utf8" })
    return output
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
  } catch {
    return []
  }
}

const pathIsPrivate = (path: string): boolean => PRIVATE_NAME.test(path)

const contentIsPrivate = (content: string): boolean =>
  ABSOLUTE_PRIVATE_PATH.test(content) || CREDENTIAL.test(content)

export const validateRepositorySnapshot = (snapshot: RepositorySnapshot): VerificationReport => {
  const checks: CheckResult[] = []
  const errors: string[] = []
  const licenseText = snapshot.licenseText
  check(
    checks,
    errors,
    "apache-license",
    typeof licenseText === "string" &&
      licenseText.includes("Apache License") &&
      licenseText.includes("Version 2.0"),
    "Apache-2.0 LICENSE is missing",
  )

  const privatePaths = snapshot.stagedPaths.filter(pathIsPrivate)
  check(
    checks,
    errors,
    "private-artifact-paths",
    privatePaths.length === 0,
    "staged private artifact or tool metadata detected",
  )

  const files = snapshot.files ?? []
  const privateContent = files.some(
    (file) => file.content !== undefined && contentIsPrivate(file.content),
  )
  check(
    checks,
    errors,
    "private-content",
    !privateContent,
    "private absolute path or credential detected in repository content",
  )

  const gitignore = files.find((file) => file.path === ".gitignore")?.content
  if (gitignore !== undefined) {
    check(
      checks,
      errors,
      "private-artifact-ignore",
      gitignore.includes(".omo/") && gitignore.includes("*.key") && gitignore.includes("*.pem"),
      "gitignore does not exclude private execution artifacts",
    )
  }

  const oversized = files.filter(
    (file) =>
      file.path.startsWith("src/") &&
      file.path.endsWith(".ts") &&
      (file.content?.split("\n").length ?? 0) >= 250,
  )
  check(
    checks,
    errors,
    "source-module-size",
    oversized.length === 0,
    "source module is 250 lines or larger",
  )
  return makeReport(checks, errors)
}

export const scanRepository = (root: string): VerificationReport => {
  const trackedPaths = runGit(root, ["ls-files"])
  const stagedPaths = runGit(root, ["diff", "--cached", "--name-only"])
  const paths = [...new Set([...trackedPaths, ...stagedPaths])]
  const files = paths.map((path) => {
    if (!existsSync(join(root, path))) return { path }
    return { path, content: readFileSync(join(root, path), "utf8") }
  })
  const licensePath = join(root, "LICENSE")
  const snapshot: RepositorySnapshot = {
    licenseText: existsSync(licensePath) ? readFileSync(licensePath, "utf8") : null,
    stagedPaths,
    files,
  }
  return validateRepositorySnapshot(snapshot)
}
