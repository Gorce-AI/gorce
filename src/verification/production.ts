import { readdir, readFile } from "node:fs/promises"
import { join, relative } from "node:path"

const ignoredDirectories = new Set([
  ".git",
  ".omo",
  "node_modules",
  "dist",
  "target",
  "docs",
  "tests",
])
const toolingTextExemptions = new Set([
  "architecture/typescript-bun-baseline.v1.yaml",
  "architecture/studio-host-gate.v1.yaml",
  "src/architecture/ecosystem.ts",
  "src/architecture/ecosystem-structural.ts",
  "src/architecture/semantics.ts",
  "src/commands/verify-architecture.ts",
  "src/verification/f2.ts",
  "src/verification/production.ts",
  "src/verification/s1.ts",
  "src/verification/s1-cutover.ts",
])
const forbiddenPath =
  /(^|\/)(api|crates|xtask)(\/|$)|(^|\/)(Cargo\.toml|Cargo\.lock|rust-toolchain(?:\.toml)?|[^/]+\.rs)$/i
export const forbiddenRuntimes = [
  "cargo",
  "rustc",
  "rustup",
  "node",
  "nodejs",
  "deno",
  "python",
  "python3",
  "java",
  "gradle",
  "mvn",
  "dotnet",
  "go",
  "ruby",
  "perl",
] as const
const forbiddenRuntimeNames = forbiddenRuntimes.join("|")
const forbiddenRuntime = new RegExp(`\\b(?:${forbiddenRuntimeNames})\\b`, "i")
const forbiddenProcess = new RegExp(
  `(?:Bun\\.)?(?:spawn|spawnSync|exec|execFile|execFileSync)\\s*\\(\\s*(?:\\[\\s*)?["'](?:${forbiddenRuntimeNames})\\b`,
  "i",
)

const withoutNodeImports = (text: string): string => text.replace(/["']node:[^"']+["']/g, "")

export const scanProductionTree = async (root: string): Promise<readonly string[]> => {
  const violations: string[] = []
  const visit = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (ignoredDirectories.has(entry.name)) continue
      const path = join(directory, entry.name)
      const relativePath = relative(root, path)
      if (entry.isSymbolicLink()) {
        violations.push(`${relativePath}: symlink in production tree`)
        continue
      }
      if (entry.isDirectory()) {
        await visit(path)
        continue
      }
      if (!entry.isFile()) continue
      if (forbiddenPath.test(relativePath)) {
        violations.push(`${relativePath}: retired Rust/API production artifact`)
        continue
      }
      if (relativePath === "bun.lock") continue
      const text = await readFile(path, "utf8")
      if (forbiddenProcess.test(text))
        violations.push(`${relativePath}: non-Bun runtime executable invocation`)
      else if (
        !toolingTextExemptions.has(relativePath) &&
        forbiddenRuntime.test(withoutNodeImports(text))
      )
        violations.push(`${relativePath}: non-Bun runtime reference`)
    }
  }
  await visit(root)
  return violations
}
