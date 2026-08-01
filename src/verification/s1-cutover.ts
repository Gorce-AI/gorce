import { access, readFile } from "node:fs/promises"
import { join } from "node:path"
import type { S1Check } from "./s1.js"
import { scanProductionTree } from "./production.js"

const retiredPaths = [
  "Cargo.toml",
  "Cargo.lock",
  "rust-toolchain.toml",
  "xtask",
  "crates",
  "api",
  ".github/workflows/release.yml",
] as const

const pathExists = async (root: string, path: string): Promise<boolean> => {
  try {
    await access(join(root, path))
    return true
  } catch {
    return false
  }
}

const check = (
  checks: S1Check[],
  errors: string[],
  name: string,
  ok: boolean,
  code: string,
  reason: string,
): void => {
  checks.push({ name, ok, code, reason })
  if (!ok) errors.push(`${code}: ${reason}`)
}

export const checkS1Cutover = async (
  root: string,
  checks: S1Check[],
  errors: string[],
): Promise<void> => {
  for (const path of retiredPaths)
    check(
      checks,
      errors,
      `retired:${path}`,
      !(await pathExists(root, path)),
      "S1_RETIRED_ARTIFACT",
      `${path} must be retired from the active Bun-only tree`,
    )
  const workflow = await readFile(join(root, ".github/workflows/ci.yml"), "utf8")
  const security = await readFile(join(root, ".github/workflows/security.yml"), "utf8")
  check(
    checks,
    errors,
    "ci-bun-only",
    !/cargo|rust|dtolnay/i.test(workflow),
    "S1_CI_TOOLCHAIN",
    "active CI must use Bun-only verification",
  )
  check(
    checks,
    errors,
    "security-bun-audit",
    /bun audit/.test(security) && !/cargo|rust/i.test(security),
    "S1_SECURITY_TOOLCHAIN",
    "active security verification must run Bun audit",
  )
  const productionViolations = await scanProductionTree(root)
  check(
    checks,
    errors,
    "production-runtime-retirement",
    productionViolations.length === 0,
    "S1_PRODUCTION_RUNTIME_RETIREMENT",
    productionViolations.length === 0
      ? "the tracked production tree is Bun-only and Rust/API-free"
      : productionViolations.join("; "),
  )
  const source = await Promise.all(
    [
      "packages/core/src/index.ts",
      "packages/tui-harness/src/index.ts",
      "apps/tui-harness/src/main.ts",
    ].map(async (path) => readFile(join(root, path), "utf8")),
  )
  check(
    checks,
    errors,
    "s1-boundary",
    !/(?:\bSession\b|\bWorkRun\b|reducer|replay|storage|daemon|transport|provider|WebSocket|PTY|render|stdin|input)/i.test(
      source.join("\n"),
    ),
    "S1_SCOPE_BOUNDARY",
    "S1 packages must not contain S2 semantics, storage, transport, or TUI rendering/input",
  )
}
