import { execFileSync } from "node:child_process"
import { createHash } from "node:crypto"
import { mkdir, mkdtemp, readFile, rename, rm, unlink, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { map, list, readCanonicalYaml, string } from "../architecture/yaml.js"
import { verifyEcosystem } from "../architecture/ecosystem.js"
import { TECHNOLOGY_BASELINE_SCHEMA } from "../architecture/rules.js"
import type { VerificationReport } from "./types.js"

const fixtureSchema = map([
  ["schema", string()],
  ["cases", list(string())],
  ["runtime_overlays", list(string())],
])

const planCases = [
  "clean",
  "package-inversion",
  "product-inventory-in-core",
  "source-tunneling",
  "wrong-bun-version",
  "wrong-typescript-version",
  "alternate-package-manager",
  "alternate-core-entrypoint",
  "jetbrains-host-code-displacement",
] as const

const runtimeOverlayCases = [
  "alternate-cargo-runtime",
  "alternate-node-runtime",
  "alternate-deno-runtime",
  "alternate-non-bun-runtime",
] as const

interface ExpectedFailure {
  readonly code: string
  readonly reason: string
}

const expectedFailures: Readonly<Record<string, ExpectedFailure>> = {
  "package-inversion": {
    code: "ECO_CORE_PACKAGE_INVERSION",
    reason: "core must not depend on Studio or JetBrains packages",
  },
  "product-inventory-in-core": {
    code: "ECO_CORE_PRODUCT_INVENTORY",
    reason: "core must not contain Studio or JetBrains production inventory",
  },
  "source-tunneling": {
    code: "ECO_SOURCE_TUNNELING",
    reason: "core must not tunnel to a sibling source tree or unpublished dependency",
  },
  "wrong-bun-version": {
    code: "ECO_TECHNOLOGY_VERSION",
    reason: "Bun 1.3.14, TypeScript 6.0.3, and Biome 2.2.4 are required in core and Studio",
  },
  "wrong-typescript-version": {
    code: "ECO_TECHNOLOGY_VERSION",
    reason: "Bun 1.3.14, TypeScript 6.0.3, and Biome 2.2.4 are required in core and Studio",
  },
  "alternate-package-manager": {
    code: "ECO_ALTERNATE_PACKAGE_MANAGER",
    reason: "alternate package-manager locks are forbidden: pnpm-lock.yaml",
  },
  "alternate-core-entrypoint": {
    code: "ECO_ALTERNATE_CORE_ENTRYPOINT",
    reason:
      "core must not introduce a Node or non-Bun alternate entrypoint; Bun exports and bin are permitted",
  },
  "jetbrains-host-code-displacement": {
    code: "ECO_JETBRAINS_HOST_DISPLACEMENT",
    reason: "JetBrains host code must remain in the JetBrains repository",
  },
  "alternate-cargo-runtime": {
    code: "ECO_NON_BUN_RUNTIME",
    reason: "core ecosystem trees must use Bun rather than Cargo, Node, Deno, or another runtime",
  },
  "alternate-node-runtime": {
    code: "ECO_NON_BUN_RUNTIME",
    reason: "core ecosystem trees must use Bun rather than Cargo, Node, Deno, or another runtime",
  },
  "alternate-deno-runtime": {
    code: "ECO_NON_BUN_RUNTIME",
    reason: "core ecosystem trees must use Bun rather than Cargo, Node, Deno, or another runtime",
  },
  "alternate-non-bun-runtime": {
    code: "ECO_NON_BUN_RUNTIME",
    reason: "core ecosystem trees must use Bun rather than Cargo, Node, Deno, or another runtime",
  },
}

const setEquals = (actual: readonly string[], expected: readonly string[]): boolean =>
  actual.length === expected.length &&
  new Set(actual).size === actual.length &&
  expected.every((item) => actual.includes(item))

const fixturePackage = {
  name: "@gorce-ai/gorce-core-fixture",
  version: "0.0.0",
  type: "module",
  packageManager: "bun@1.3.14",
  exports: { ".": "./src/index.ts" },
  bin: { "gorce-fixture": "./src/index.ts" },
  devDependencies: { "@biomejs/biome": "2.2.4", typescript: "6.0.3" },
} as const

const studioPackage = {
  name: "@gorce-ai/gorce-studio-fixture",
  version: "0.0.0",
  type: "module",
  packageManager: "bun@1.3.14",
  exports: { ".": "./src/index.ts" },
  bin: { "gorce-studio-fixture": "./src/index.ts" },
  devDependencies: { "@biomejs/biome": "2.2.4", typescript: "6.0.3" },
} as const

const initializeRepository = (root: string, identity: string): void => {
  execFileSync("git", ["-C", root, "init", "--quiet"], { stdio: "ignore" })
  execFileSync("git", ["-C", root, "config", "user.name", "Gorce F2 Fixture"], { stdio: "ignore" })
  execFileSync("git", ["-C", root, "config", "user.email", "f2-fixture@gorce.ai"], {
    stdio: "ignore",
  })
  execFileSync(
    "git",
    ["-C", root, "remote", "add", "origin", `https://github.com/Gorce-AI/${identity}.git`],
    {
      stdio: "ignore",
    },
  )
  execFileSync("git", ["-C", root, "add", "."], { stdio: "ignore" })
  execFileSync("git", ["-C", root, "commit", "--quiet", "-m", "fixture"], { stdio: "ignore" })
}

const fixtureFiles = async (root: string, name: string): Promise<void> => {
  const core = join(root, "gorce")
  const studio = join(root, "gorce-studio")
  const jetbrains = join(root, "gorce-jetbrains")
  await Promise.all([
    mkdir(join(core, "architecture"), { recursive: true }),
    mkdir(join(core, "src"), { recursive: true }),
    mkdir(join(studio, "src"), { recursive: true }),
    mkdir(join(jetbrains, "src/main/kotlin"), { recursive: true }),
  ])
  await Promise.all([
    writeFile(join(core, "package.json"), `${JSON.stringify(fixturePackage)}\n`),
    writeFile(join(core, "bun.lock"), "lockfileVersion = 1\n"),
    writeFile(join(core, "src/index.ts"), "export const fixture = true\n"),
    writeFile(join(studio, "package.json"), `${JSON.stringify(studioPackage)}\n`),
    writeFile(join(studio, "bun.lock"), "lockfileVersion = 1\n"),
    writeFile(join(studio, "src/index.ts"), "export const fixture = true\n"),
    writeFile(join(jetbrains, "build.gradle.kts"), 'plugins { kotlin("jvm") version "2.0.0" }\n'),
    writeFile(join(jetbrains, "src/main/kotlin/Host.kt"), "class Host\n"),
  ])
  await Promise.all([
    writeFile(
      join(core, "architecture/typescript-bun-baseline.v1.yaml"),
      await readFile(join(process.cwd(), "architecture/typescript-bun-baseline.v1.yaml")),
    ),
    writeFile(
      join(core, "architecture/studio-host-gate.v1.yaml"),
      await readFile(join(process.cwd(), "architecture/studio-host-gate.v1.yaml")),
    ),
  ])

  if (name === "package-inversion") {
    await writeFile(
      join(core, "src/inversion.ts"),
      'export const dependency = "@gorce-ai/studio"\n',
    )
  } else if (name === "product-inventory-in-core") {
    await mkdir(join(core, "studio"), { recursive: true })
    await writeFile(join(core, "studio/inventory.json"), "{}\n")
  } else if (name === "source-tunneling") {
    await writeFile(
      join(core, "package.json"),
      `${JSON.stringify({ ...fixturePackage, dependencies: { studio: "file:../gorce-studio" } })}\n`,
    )
  } else if (name === "wrong-bun-version") {
    await writeFile(
      join(core, "package.json"),
      `${JSON.stringify({ ...fixturePackage, packageManager: "bun@1.3.13" })}\n`,
    )
  } else if (name === "wrong-typescript-version") {
    await writeFile(
      join(core, "package.json"),
      `${JSON.stringify({ ...fixturePackage, devDependencies: { ...fixturePackage.devDependencies, typescript: "5.9.0" } })}\n`,
    )
  } else if (name === "alternate-package-manager") {
    await writeFile(join(core, "pnpm-lock.yaml"), "lockfileVersion: 9\n")
  } else if (name === "alternate-core-entrypoint") {
    await writeFile(
      join(core, "package.json"),
      `${JSON.stringify({ ...fixturePackage, main: "dist/index.js" })}\n`,
    )
  } else if (name === "jetbrains-host-code-displacement") {
    await writeFile(join(core, "src/jetbrains-host.ts"), "export const misplaced = true\n")
  } else if (name === "alternate-cargo-runtime") {
    await mkdir(join(core, "crates/gorce/src"), { recursive: true })
    await writeFile(join(core, "Cargo.toml"), '[workspace]\nmembers = ["crates/gorce"]\n')
    await writeFile(join(core, "Cargo.lock"), "version = 3\n")
    await writeFile(join(core, "rust-toolchain.toml"), '[toolchain]\nchannel = "stable"\n')
  } else if (name === "alternate-node-runtime") {
    await writeFile(join(core, "node-runtime.mjs"), 'console.log("node")\n')
  } else if (name === "alternate-deno-runtime") {
    await writeFile(join(core, "deno.json"), "{}\n")
  } else if (name === "alternate-non-bun-runtime") {
    await writeFile(join(core, "python-runtime.py"), 'print("python")\n')
  }

  initializeRepository(core, "gorce")
  initializeRepository(studio, "gorce-studio")
  initializeRepository(jetbrains, "gorce-jetbrains")
}

export interface F2VerdictEvidence {
  readonly schema: "gorce.f2-verdict/v1"
  readonly verdict: "APPROVED" | "CHANGES_REQUESTED"
  readonly fixture_manifest_sha256: string
  readonly cases: readonly {
    readonly kind: "plan" | "runtime-overlay"
    readonly id: string
    readonly expected_code: string
    readonly expected_reason: string
    readonly observed_code: string
    readonly observed_reason: string
    readonly ok: boolean
    readonly error_count: number
  }[]
  readonly fatal_code?: string
  readonly fatal_reason?: string
}

const atomicWriteEvidence = async (path: string, evidence: F2VerdictEvidence): Promise<void> => {
  await mkdir(dirname(path), { recursive: true })
  const temporary = `${path}.tmp-${process.pid}`
  await unlink(temporary).catch(() => undefined)
  try {
    await writeFile(temporary, `${JSON.stringify(evidence)}\n`, { encoding: "utf8", flag: "wx" })
    await rename(temporary, path)
  } catch (error: unknown) {
    await unlink(temporary).catch(() => undefined)
    throw error
  }
}

const errorParts = (
  report: VerificationReport,
): { readonly code: string; readonly reason: string } => {
  const error = report.errors[0] ?? "F2_EXECUTION_ERROR: verifier returned no stable failure reason"
  const separator = error.indexOf(": ")
  return separator < 1
    ? { code: "F2_EXECUTION_ERROR", reason: error }
    : { code: error.slice(0, separator), reason: error.slice(separator + 2) }
}

const expectedFor = (name: string): ExpectedFailure =>
  name === "clean"
    ? { code: "NONE", reason: "clean sovereign sibling trees are approved" }
    : (expectedFailures[name] ?? {
        code: "F2_MANIFEST_ERROR",
        reason: "fixture is not plan-mandated",
      })

const runCase = async (
  fixtureRoot: string,
  name: string,
  kind: "plan" | "runtime-overlay",
): Promise<F2VerdictEvidence["cases"][number]> => {
  const expected = expectedFor(name)
  try {
    await fixtureFiles(fixtureRoot, name)
    const baseline = await readCanonicalYaml(
      join(fixtureRoot, "gorce/architecture/typescript-bun-baseline.v1.yaml"),
      TECHNOLOGY_BASELINE_SCHEMA,
    )
    const report = await verifyEcosystem({
      coreRoot: join(fixtureRoot, "gorce"),
      studioRoot: join(fixtureRoot, "gorce-studio"),
      jetbrainsRoot: join(fixtureRoot, "gorce-jetbrains"),
      technologyBaseline: baseline.sha256,
      coreInventoryBan: ["studio", "jetbrains"],
      publishedOnly: true,
    })
    const observed = report.ok
      ? { code: "NONE", reason: "clean sovereign sibling trees are approved" }
      : errorParts(report)
    const expectedClean = name === "clean"
    const ok = expectedClean
      ? report.ok && observed.code === expected.code
      : !report.ok &&
        report.errors.some((error) => error === `${expected.code}: ${expected.reason}`)
    return {
      kind,
      id: name,
      expected_code: expected.code,
      expected_reason: expected.reason,
      observed_code: observed.code,
      observed_reason: observed.reason,
      ok,
      error_count: report.errors.length,
    }
  } catch (error: unknown) {
    return {
      kind,
      id: name,
      expected_code: expected.code,
      expected_reason: expected.reason,
      observed_code: "F2_FIXTURE_EXECUTION_ERROR",
      observed_reason: "fixture execution failed before a stable verdict",
      ok: false,
      error_count: error instanceof Error ? 1 : 1,
    }
  }
}

const reportFromCases = (
  cases: readonly F2VerdictEvidence["cases"][number][],
): VerificationReport => {
  const errors = cases.filter((item) => !item.ok).map((item) => `F2_CASE_MISMATCH: ${item.id}`)
  return {
    schema: "gorce.verification-result/v1",
    command: "qa:task:F2",
    ok: errors.length === 0,
    checks: cases.map((item) => ({
      name: `fixture:${item.id}`,
      status: item.ok ? "passed" : "failed",
      ...(item.ok ? {} : { detail: `${item.observed_code}: ${item.observed_reason}` }),
    })),
    errors,
  }
}

export const runF2FixtureManifest = async (
  manifestPath: string,
  evidencePath: string,
): Promise<VerificationReport> => {
  let manifestBytes = new Uint8Array(0)
  let manifestHash = "0".repeat(64)
  const results: Array<F2VerdictEvidence["cases"][number]> = []
  try {
    manifestBytes = new Uint8Array(await Bun.file(manifestPath).arrayBuffer())
    manifestHash = createHash("sha256").update(manifestBytes).digest("hex")
    const manifest = await readCanonicalYaml(manifestPath, fixtureSchema)
    if (manifest.value["schema"] !== "gorce.qa.f2-architecture/v1")
      throw new Error("F2_MANIFEST_SCHEMA: invalid F2 fixture manifest schema")
    const rawCases = manifest.value["cases"]
    const rawRuntimeOverlays = manifest.value["runtime_overlays"]
    if (!Array.isArray(rawCases) || !Array.isArray(rawRuntimeOverlays))
      throw new Error("F2_MANIFEST_CASE_SET: F2 fixture case lists are required")
    const cases = rawCases.filter((item): item is string => typeof item === "string")
    const runtimeOverlays = rawRuntimeOverlays.filter(
      (item): item is string => typeof item === "string",
    )
    if (!setEquals(cases, planCases) || !setEquals(runtimeOverlays, runtimeOverlayCases)) {
      throw new Error(
        "F2_MANIFEST_CASE_SET: fixture cases must exactly and uniquely match the approved plan and runtime overlay sets",
      )
    }
    for (const name of cases) {
      const fixtureRoot = await mkdtemp(join(tmpdir(), "gorce-f2-"))
      try {
        results.push(await runCase(fixtureRoot, name, "plan"))
      } finally {
        await rm(fixtureRoot, { recursive: true, force: true })
      }
    }
    for (const name of runtimeOverlays) {
      const fixtureRoot = await mkdtemp(join(tmpdir(), "gorce-f2-"))
      try {
        results.push(await runCase(fixtureRoot, name, "runtime-overlay"))
      } finally {
        await rm(fixtureRoot, { recursive: true, force: true })
      }
    }
    const verdict: F2VerdictEvidence["verdict"] = results.every((item) => item.ok)
      ? "APPROVED"
      : "CHANGES_REQUESTED"
    await atomicWriteEvidence(evidencePath, {
      schema: "gorce.f2-verdict/v1",
      verdict,
      fixture_manifest_sha256: manifestHash,
      cases: results,
    })
    return reportFromCases(results)
  } catch (error: unknown) {
    const reason =
      error instanceof Error ? error.message : "F2 fixture execution failed before a stable verdict"
    const separator = reason.indexOf(": ")
    const code = separator > 0 ? reason.slice(0, separator) : "F2_EXECUTION_ERROR"
    const stableReason =
      separator > 0
        ? reason.slice(separator + 2)
        : "fixture execution failed before a stable verdict"
    await atomicWriteEvidence(evidencePath, {
      schema: "gorce.f2-verdict/v1",
      verdict: "CHANGES_REQUESTED",
      fixture_manifest_sha256: manifestHash,
      cases: results,
      fatal_code: code,
      fatal_reason: stableReason,
    })
    return {
      schema: "gorce.verification-result/v1",
      command: "qa:task:F2",
      ok: false,
      checks: [{ name: "fixture-manifest", status: "failed", detail: `${code}: ${stableReason}` }],
      errors: [`${code}: ${stableReason}`],
    }
  }
}
