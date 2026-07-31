import { createHash } from "node:crypto"
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { dirname, join } from "node:path"
import { tmpdir } from "node:os"
import { readCanonicalYaml, map, string, list } from "../architecture/yaml.js"
import { verifyEcosystem } from "../architecture/ecosystem.js"
import { TECHNOLOGY_BASELINE_SCHEMA } from "../architecture/rules.js"
import type { CheckResult, VerificationReport } from "./types.js"

const fixtureSchema = map([
  ["schema", string()],
  ["cases", list(string())],
])

const expectedFailureCases = new Set([
  "package-inversion",
  "product-inventory-in-core",
  "source-tunneling",
  "wrong-bun-version",
  "wrong-typescript-version",
  "alternate-package-manager",
  "alternate-core-entrypoint",
  "jetbrains-host-code-displacement",
])

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
  const packageJson = {
    name: "@gorce-ai/gorce-core-fixture",
    version: "0.0.0",
    type: "module",
    packageManager: "bun@1.3.14",
    devDependencies: { "@biomejs/biome": "2.2.4", typescript: "6.0.3" },
  }
  const studioPackageJson = {
    name: "@gorce-ai/gorce-studio-fixture",
    version: "0.0.0",
    type: "module",
    packageManager: "bun@1.3.14",
    devDependencies: { "@biomejs/biome": "2.2.4", typescript: "6.0.3" },
  }
  await Promise.all([
    writeFile(join(core, "package.json"), `${JSON.stringify(packageJson)}\n`),
    writeFile(join(core, "bun.lock"), "lockfileVersion = 1\n"),
    writeFile(join(core, "src/index.ts"), "export const fixture = true\n"),
    writeFile(join(studio, "package.json"), `${JSON.stringify(studioPackageJson)}\n`),
    writeFile(join(studio, "bun.lock"), "lockfileVersion = 1\n"),
    writeFile(join(studio, "src/index.ts"), "export const fixture = true\n"),
    writeFile(join(jetbrains, "build.gradle.kts"), 'plugins { kotlin("jvm") version "2.0.0" }\n'),
    writeFile(join(jetbrains, "src/main/kotlin/Host.kt"), "class Host\n"),
  ])
  await writeFile(
    join(core, "architecture/typescript-bun-baseline.v1.yaml"),
    await readFile(join(process.cwd(), "architecture/typescript-bun-baseline.v1.yaml")),
  )
  await writeFile(
    join(core, "architecture/studio-host-gate.v1.yaml"),
    await readFile(join(process.cwd(), "architecture/studio-host-gate.v1.yaml")),
  )

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
      `${JSON.stringify({ ...packageJson, dependencies: { studio: "file:../gorce-studio" } })}\n`,
    )
  } else if (name === "wrong-bun-version") {
    await writeFile(
      join(core, "package.json"),
      `${JSON.stringify({ ...packageJson, packageManager: "bun@1.3.13" })}\n`,
    )
  } else if (name === "wrong-typescript-version") {
    await writeFile(
      join(core, "package.json"),
      `${JSON.stringify({ ...packageJson, devDependencies: { ...packageJson.devDependencies, typescript: "5.9.0" } })}\n`,
    )
  } else if (name === "alternate-package-manager") {
    await writeFile(join(core, "pnpm-lock.yaml"), "lockfileVersion: 9\n")
  } else if (name === "alternate-core-entrypoint") {
    await writeFile(
      join(core, "package.json"),
      `${JSON.stringify({ ...packageJson, main: "dist/index.js" })}\n`,
    )
  } else if (name === "jetbrains-host-code-displacement") {
    await writeFile(join(core, "src/jetbrains-host.ts"), "export const misplaced = true\n")
  }
}

const observedVerdict = (report: VerificationReport): "APPROVED" | "CHANGES_REQUESTED" =>
  report.ok ? "APPROVED" : "CHANGES_REQUESTED"

export interface F2VerdictEvidence {
  readonly schema: "gorce.f2-verdict/v1"
  readonly verdict: "APPROVED" | "CHANGES_REQUESTED"
  readonly fixture_manifest_sha256: string
  readonly cases: readonly {
    readonly id: string
    readonly expected: "APPROVED" | "CHANGES_REQUESTED"
    readonly observed: "APPROVED" | "CHANGES_REQUESTED"
    readonly ok: boolean
    readonly error_count: number
  }[]
}

const writeEvidence = async (path: string, evidence: F2VerdictEvidence): Promise<void> => {
  await mkdir(dirname(path), { recursive: true })
  await writeFile(path, `${JSON.stringify(evidence)}\n`, "utf8")
}

export const runF2FixtureManifest = async (
  manifestPath: string,
  evidencePath: string,
): Promise<VerificationReport> => {
  const manifestBytes = new Uint8Array(await Bun.file(manifestPath).arrayBuffer())
  const manifest = await readCanonicalYaml(manifestPath, fixtureSchema)
  if (manifest.value["schema"] !== "gorce.qa.f2-architecture/v1")
    throw new Error("invalid F2 fixture manifest schema")
  const rawCases = manifest.value["cases"]
  if (!Array.isArray(rawCases)) throw new Error("F2 fixture cases must be a list")
  const cases = rawCases.filter((item): item is string => typeof item === "string")
  if (cases.length !== rawCases.length || cases.length === 0 || !cases.includes("clean"))
    throw new Error("F2 fixtures must include clean")
  for (const name of cases) {
    if (name !== "clean" && !expectedFailureCases.has(name))
      throw new Error(`unknown F2 fixture ${name}`)
  }

  const results: Array<F2VerdictEvidence["cases"][number]> = []
  try {
    for (const name of cases) {
      const fixtureRoot = await mkdtemp(join(tmpdir(), "gorce-f2-"))
      try {
        await fixtureFiles(fixtureRoot, name)
        const baseline = await readCanonicalYaml(
          join(fixtureRoot, "gorce/architecture/typescript-bun-baseline.v1.yaml"),
          TECHNOLOGY_BASELINE_SCHEMA,
        )
        const result = await verifyEcosystem({
          coreRoot: join(fixtureRoot, "gorce"),
          studioRoot: join(fixtureRoot, "gorce-studio"),
          jetbrainsRoot: join(fixtureRoot, "gorce-jetbrains"),
          technologyBaseline: baseline.sha256,
          coreInventoryBan: ["studio", "jetbrains"],
          publishedOnly: true,
        })
        const expected = name === "clean" ? "APPROVED" : "CHANGES_REQUESTED"
        const observed = observedVerdict(result)
        results.push({
          id: name,
          expected,
          observed,
          ok: expected === observed,
          error_count: result.errors.length,
        })
      } finally {
        await rm(fixtureRoot, { recursive: true, force: true })
      }
    }
  } finally {
    const verdict = results.every((item) => item.ok) ? "APPROVED" : "CHANGES_REQUESTED"
    await writeEvidence(evidencePath, {
      schema: "gorce.f2-verdict/v1",
      verdict,
      fixture_manifest_sha256: createHash("sha256").update(manifestBytes).digest("hex"),
      cases: results,
    })
  }
  const checks: CheckResult[] = results.map((item) => ({
    name: `fixture:${item.id}`,
    status: item.ok ? "passed" : "failed",
    ...(item.ok ? {} : { detail: `expected ${item.expected}, observed ${item.observed}` }),
  }))
  const errors = results
    .filter((item) => !item.ok)
    .map((item) => `fixture:${item.id}: expected ${item.expected}, observed ${item.observed}`)
  return {
    schema: "gorce.verification-result/v1",
    command: "qa:task:F2",
    ok: errors.length === 0,
    checks,
    errors,
  }
}
