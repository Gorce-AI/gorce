import { describe, expect, test } from "bun:test"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { validateManifest } from "../src/verification/manifest.js"
import { verifyManifestFile } from "../src/verification/manifest-file.js"
import {
  APPROVED_BLOCKER_GRAPH,
  APPROVED_COMMAND_OWNERS,
  APPROVED_PLAN_SHA256,
} from "../src/verification/expected.js"
import {
  SOURCE_MODULE_MAX_LINES,
  TASK6_VERIFIER_MAX_LINES,
  validateRepositorySnapshot,
} from "../src/verification/repository.js"

const validManifest = (): Record<string, unknown> => ({
  schema: "gorce.execution-manifest/v1",
  plan_sha256: APPROVED_PLAN_SHA256,
  task_count: 41,
  blocker_graph: APPROVED_BLOCKER_GRAPH,
  blocker_graph_sha256: "65e5be39146dc3a0ddec90c4939e3869f9c908b029b23fcdc149c83ad2fc082a",
  command_owners: APPROVED_COMMAND_OWNERS,
  owner_gates: [],
  task_41_command_owner_tasks: [3, 4, 5, 26],
  signer_identity: "lead",
  signature: "execution-manifest.sig",
})

describe("execution manifest structural gate", () => {
  test("rejects a wrong approved plan SHA", () => {
    const manifest = validManifest()
    Object.assign(manifest, { plan_sha256: "0".repeat(64) })
    expect(validateManifest(manifest).ok).toBe(false)
  })

  test("rejects an altered blocker graph", () => {
    const manifest = validManifest()
    Object.assign(manifest, { blocker_graph: [...APPROVED_BLOCKER_GRAPH.slice(0, -1)] })
    expect(validateManifest(manifest).ok).toBe(false)
  })

  test("rejects duplicate task IDs", () => {
    const manifest = validManifest()
    Object.assign(manifest, {
      blocker_graph: [...APPROVED_BLOCKER_GRAPH, { task: 1, blocked_by: [] }],
    })
    expect(validateManifest(manifest).ok).toBe(false)
  })

  test("rejects an unowned verifier command", () => {
    const manifest = validManifest()
    Object.assign(manifest, {
      command_owners: APPROVED_COMMAND_OWNERS.filter((entry) => entry.command !== "qa:task"),
    })
    expect(validateManifest(manifest).ok).toBe(false)
  })

  test("rejects malformed manifest input", () => {
    expect(validateManifest({ schema: "not-a-manifest" }).ok).toBe(false)
  })
})

describe("detached input and repository gates", () => {
  test("rejects a missing signature", async () => {
    const directory = await mkdtemp(join(tmpdir(), "gorce-task-03-"))
    try {
      const manifestPath = join(directory, "execution-manifest.json")
      await writeFile(manifestPath, "{}")
      const result = await verifyManifestFile({
        manifestPath,
      })
      expect(result.ok).toBe(false)
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })

  test("rejects a bad signature", async () => {
    const directory = await mkdtemp(join(tmpdir(), "gorce-task-03-"))
    try {
      const manifestPath = join(directory, "execution-manifest.json")
      await writeFile(manifestPath, "{}")
      await writeFile(join(directory, "execution-manifest.sig"), new Uint8Array(64))
      await writeFile(join(directory, "execution-manifest.ed25519.pub"), "not a public key")
      const result = await verifyManifestFile({ manifestPath })
      expect(result.ok).toBe(false)
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })

  test("rejects a staged private artifact", () => {
    const result = validateRepositorySnapshot({
      licenseText: "Apache License, Version 2.0",
      stagedPaths: [".omo/secret"],
    })
    expect(result.ok).toBe(false)
  })

  test("rejects a missing license", () => {
    const result = validateRepositorySnapshot({ licenseText: null, stagedPaths: [] })
    expect(result.ok).toBe(false)
  })

  test("keeps the ordinary source limit while allowing bounded Task 6 verifiers", () => {
    const ordinary = validateRepositorySnapshot({
      licenseText: "Apache License, Version 2.0",
      stagedPaths: [],
      files: [
        {
          path: "src/ordinary.ts",
          content: Array(SOURCE_MODULE_MAX_LINES).fill("line").join("\n"),
        },
      ],
    })
    expect(ordinary.errors).toContain(
      `source module exceeds its applicable limit (${SOURCE_MODULE_MAX_LINES} lines; Task 6 verifier modules ${TASK6_VERIFIER_MAX_LINES})`,
    )
    const verifier = validateRepositorySnapshot({
      licenseText: "Apache License, Version 2.0",
      stagedPaths: [],
      files: [
        {
          path: "src/commands/verify-technology.ts",
          content: Array(TASK6_VERIFIER_MAX_LINES - 1)
            .fill("line")
            .join("\n"),
        },
      ],
    })
    expect(verifier.ok).toBe(true)
  })

  test("does not mistake Task 6 evidence paths for credentials", () => {
    const result = validateRepositorySnapshot({
      licenseText: "Apache License, Version 2.0",
      stagedPaths: [],
      files: [
        {
          path: ".github/workflows/ci.yml",
          content: 'path: "$RUNNER_TEMP/gorce-evidence/task-06-rule-digests.json"',
        },
      ],
    })
    expect(result.ok).toBe(true)
  })
})
