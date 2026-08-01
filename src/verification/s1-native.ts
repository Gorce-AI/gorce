import { createHash } from "node:crypto"
import { execFileSync } from "node:child_process"
import { readFileSync } from "node:fs"
import { chmod, mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path"

export const helloSchema = "gorce.s1.hello/v1" as const
export const bunVersion = "1.3.14" as const
export const task6BaselineSha256 =
  "67b95cadb3ec9a711992007d2df420d984d97cfb9da94b033567e9b7987365a2" as const
export const nonReleaseScope = "S1 native validation only; not release qualified" as const
export const nativeTargets = ["bun-linux-x64", "bun-darwin-arm64", "bun-windows-x64"] as const
export type NativeTarget = (typeof nativeTargets)[number]

export interface Provenance {
  readonly source_commit: string
  readonly task6_baseline_sha256: string
  readonly builder_bun: string
  readonly release_claim: false
  readonly scope: typeof nonReleaseScope
}

export const hostTarget = (): string => {
  const platform = process.platform === "win32" ? "windows" : process.platform
  const architecture = process.arch === "arm64" ? "arm64" : "x64"
  return `bun-${platform}-${architecture}`
}

export const runnerTarget = (os: string, architecture: string): string =>
  `bun-${os === "win32" ? "windows" : os}-${architecture === "arm64" ? "arm64" : "x64"}`

export const sourceCommit = (root: string): string => {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim()
  } catch {
    return ""
  }
}

export const currentTask6BaselineSha256 = (root: string): string => {
  try {
    return createHash("sha256")
      .update(readFileSync(join(root, "architecture/typescript-bun-baseline.v1.yaml")))
      .digest("hex")
  } catch {
    return ""
  }
}

export const provenance = (root: string, runtimeVersion = Bun.version): Provenance => ({
  source_commit: sourceCommit(root),
  task6_baseline_sha256: currentTask6BaselineSha256(root),
  builder_bun: runtimeVersion,
  release_claim: false,
  scope: nonReleaseScope,
})

export const sha256 = async (path: string): Promise<string> =>
  createHash("sha256")
    .update(await readFile(path))
    .digest("hex")

export const ensureExecutable = async (path: string): Promise<void> => {
  if (process.platform !== "win32") await chmod(path, 0o755)
}

export const atomicJson = async (path: string, value: unknown): Promise<void> => {
  await mkdir(dirname(path), { recursive: true })
  const temporary = `${path}.tmp-${process.pid}`
  await unlink(temporary).catch(() => undefined)
  try {
    await writeFile(temporary, `${JSON.stringify(value)}\n`, { flag: "wx" })
    await rename(temporary, path)
  } catch (error: unknown) {
    await unlink(temporary).catch(() => undefined)
    throw error
  }
}

export const nativeArtifactName = (target: string): string =>
  `gorce-tui-harness-${target}${target.includes("windows") ? ".exe" : ""}`

export const copiedArtifactPath = (temporaryRoot: string, target: string): string =>
  join(temporaryRoot, nativeArtifactName(target))

export const externalPath = (root: string, path: string, label: string): string => {
  const absolute = resolve(root, path)
  const rootPath = resolve(root)
  const outside = relative(rootPath, absolute)
  if (
    isAbsolute(outside) ||
    (outside.length > 0 && outside !== ".." && !outside.startsWith(`..${sep}`))
  )
    throw new Error(`${label} must be an explicit path outside the checkout`)
  return absolute
}

export const defaultExternalEvidencePath = (name: string): string =>
  join(tmpdir(), "gorce-s1-default", name)
