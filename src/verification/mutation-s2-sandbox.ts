import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { S2MutationTarget } from "./mutation-s2-targets.js"
import type { S2MutationOutcome } from "./mutation-s2.js"

interface ProcessResult {
  readonly outcome: "passed" | "failed" | "timeout" | "infrastructure"
  readonly output: string
}

const runProcess = async (
  command: readonly string[],
  cwd: string,
  timeoutMs: number,
): Promise<ProcessResult> => {
  let child: Bun.Subprocess
  try {
    child = Bun.spawn([...command], { cwd, stdout: "pipe", stderr: "pipe" })
  } catch (error: unknown) {
    return {
      outcome: "infrastructure",
      output: error instanceof Error ? error.message : "spawn failed",
    }
  }
  let timer: ReturnType<typeof setTimeout> | undefined
  const output = Promise.all([
    child.exited,
    new Response(child.stdout as ReadableStream<Uint8Array>).text(),
    new Response(child.stderr as ReadableStream<Uint8Array>).text(),
  ])
  const timeout = new Promise<readonly [number, string, string]>((resolve) => {
    timer = setTimeout(() => {
      child.kill()
      resolve([-1, "", "timeout"])
    }, timeoutMs)
  })
  const [exitCode, stdout, stderr] = await Promise.race([output, timeout])
  if (timer !== undefined) clearTimeout(timer)
  if (exitCode === -1) return { outcome: "timeout", output: stderr }
  return {
    outcome: exitCode === 0 ? "passed" : "failed",
    output: `${stdout}
${stderr}`,
  }
}

export const copyMutationSandbox = async (root: string): Promise<string> => {
  const sandbox = await mkdtemp(join(tmpdir(), "gorce-s2-mutants-"))
  for (const path of [
    "package.json",
    "bun.lock",
    "tsconfig.json",
    "tsconfig.options.json",
    "tsconfig.source.json",
    "tsconfig.test.json",
    "tsconfig.s1.noemit.json",
    "src",
    "packages",
    "apps",
    "tests",
  ])
    await cp(join(root, path), join(sandbox, path), { recursive: true })
  await mkdir(join(sandbox, "node_modules", "@gorce-ai"), { recursive: true })
  await symlink(join(root, "node_modules/@types"), join(sandbox, "node_modules/@types"), "dir")
  await symlink(join(sandbox, "packages/core"), join(sandbox, "node_modules/@gorce-ai/core"))
  return sandbox
}

export const classifyMutation = async (
  sandbox: string,
  target: S2MutationTarget,
  typescript: string,
  testPath: string,
  timeoutMs: number,
): Promise<S2MutationOutcome> => {
  const path = join(sandbox, target.path)
  const source = await readFile(path, "utf8")
  if (source.split(target.needle).length - 1 !== 1) return "infrastructure"
  await writeFile(path, source.replace(target.needle, target.replacement))
  try {
    const typecheck = await runProcess(
      [
        process.execPath,
        typescript,
        "--noEmit",
        "--pretty",
        "false",
        "--project",
        "tsconfig.s1.noemit.json",
      ],
      sandbox,
      timeoutMs,
    )
    if (typecheck.outcome === "timeout") return "timeout"
    if (typecheck.outcome === "infrastructure") return "infrastructure"
    if (typecheck.outcome !== "passed") return "type-error"
    const tests = await runProcess([process.execPath, "test", testPath], sandbox, timeoutMs)
    if (tests.outcome === "timeout") return "timeout"
    if (tests.outcome === "infrastructure") return "infrastructure"
    return tests.outcome === "passed" ? "survived" : "killed"
  } finally {
    await writeFile(path, source)
  }
}

export const disposeMutationSandbox = async (sandbox: string): Promise<void> => {
  await rm(sandbox, { recursive: true, force: true })
}
