// biome-ignore-all lint/complexity/useLiteralKeys: TypeScript config keys are validated as JSON.

import { readdir, readFile } from "node:fs/promises"
import { join, relative, resolve, sep } from "node:path"

export const EXPECTED_PROJECT_REFERENCES = {
  ".": [
    "./tsconfig.source.json",
    "./tsconfig.test.json",
    "./packages/core",
    "./packages/tui-harness",
    "./apps/tui-harness",
  ],
  "packages/core": [],
  "packages/tui-harness": ["../core"],
  "apps/tui-harness": ["../../packages/tui-harness"],
  "tsconfig.source.json": [],
  "tsconfig.test.json": [],
} as const

const GENERATED = /(^|\/)(dist|\.tsbuildinfo$)|\.(?:js|mjs|cjs|d\.ts|map|tsbuildinfo)$/i
const ignored = new Set([".git", ".omo", "node_modules"])

export const generatedOutputs = async (root: string): Promise<readonly string[]> => {
  const outputs: string[] = []
  const visit = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (ignored.has(entry.name)) continue
      const path = join(directory, entry.name)
      const relativePath = relative(root, path)
      if (entry.isDirectory()) {
        if (entry.name === "dist") outputs.push(relativePath)
        else await visit(path)
      } else if (entry.isFile() && GENERATED.test(relativePath)) outputs.push(relativePath)
    }
  }
  await visit(root)
  return outputs
}

type JsonObject = Record<string, unknown>
const readJson = async (path: string): Promise<JsonObject> => {
  const value: unknown = JSON.parse(await readFile(path, "utf8"))
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error(`${path}: object required`)
  return value as JsonObject
}

const references = (config: JsonObject): string[] => {
  const values = config["references"]
  if (!Array.isArray(values)) return []
  return values.flatMap((value) => {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return []
    const path = (value as JsonObject)["path"]
    return typeof path === "string" ? [path] : []
  })
}

const equal = (actual: readonly string[], expected: readonly string[]): boolean =>
  actual.length === expected.length && actual.every((item, index) => item === expected[index])

const expectedIncludes: Readonly<Record<string, readonly string[]>> = {
  "tsconfig.source.json": ["src/**/*.ts"],
  "tsconfig.test.json": ["src/**/*.ts", "tests/**/*.ts"],
  "packages/core": ["src/**/*.ts"],
  "packages/tui-harness": ["src/**/*.ts"],
  "apps/tui-harness": ["src/**/*.ts"],
}

const graphChild = (root: string, key: string, reference: string): string => {
  const base = key === "." || key.endsWith(".json") ? root : join(root, key)
  return relative(root, resolve(base, reference)).split(sep).join("/")
}

export const validateProjectReferenceGraph = async (root: string): Promise<readonly string[]> => {
  const errors: string[] = []
  const configs = new Map<string, JsonObject>()
  for (const key of Object.keys(EXPECTED_PROJECT_REFERENCES)) {
    const path = key === "." ? "tsconfig.json" : key.includes("/") ? `${key}/tsconfig.json` : key
    try {
      configs.set(key, await readJson(join(root, path)))
    } catch (error: unknown) {
      errors.push(error instanceof Error ? error.message : `${path}: unreadable`)
    }
  }
  for (const [key, expected] of Object.entries(EXPECTED_PROJECT_REFERENCES)) {
    const config = configs.get(key)
    if (config === undefined) continue
    const actual = references(config)
    if (!equal(actual, expected))
      errors.push(`${key}: references must be exactly ${JSON.stringify(expected)}`)
    if (key !== "." && actual.some((item, index) => item === actual[index - 1]))
      errors.push(`${key}: duplicate reference`)
    const includes = config["include"]
    if (
      key !== "." &&
      (!Array.isArray(includes) ||
        !equal(
          includes.filter((item): item is string => typeof item === "string"),
          expectedIncludes[key] ?? [],
        ))
    )
      errors.push(`${key}: include set must be exact`)
  }
  const rootConfig = configs.get(".")
  if (rootConfig !== undefined && JSON.stringify(rootConfig["files"]) !== "[]")
    errors.push(".: root project must have an empty files list")
  const packageContracts = [
    ["packages/core", []],
    ["packages/tui-harness", ["@gorce-ai/core"]],
    ["apps/tui-harness", ["@gorce-ai/tui-harness"]],
  ] as const
  for (const [path, dependencyNames] of packageContracts) {
    try {
      const manifest = await readJson(join(root, path, "package.json"))
      const dependencies = manifest["dependencies"]
      const actual =
        typeof dependencies === "object" && dependencies !== null && !Array.isArray(dependencies)
          ? Object.keys(dependencies as JsonObject)
          : []
      const dependencyMap =
        typeof dependencies === "object" && dependencies !== null && !Array.isArray(dependencies)
          ? (dependencies as JsonObject)
          : {}
      if (
        !equal(actual, dependencyNames) ||
        dependencyNames.some((name) => dependencyMap[name] !== "workspace:*")
      )
        errors.push(`${path}: dependencies disagree with the reference graph`)
    } catch (error: unknown) {
      errors.push(error instanceof Error ? error.message : `${path}/package.json: unreadable`)
    }
  }
  const graph = new Map<string, string[]>()
  for (const [key, config] of configs) {
    const actual = references(config)
    graph.set(
      key,
      actual.map((reference) => graphChild(root, key, reference)),
    )
  }
  const visiting = new Set<string>()
  const visited = new Set<string>()
  const visit = (key: string): void => {
    if (visiting.has(key)) {
      errors.push(`project reference cycle detected at ${key}`)
      return
    }
    if (visited.has(key)) return
    visiting.add(key)
    for (const child of graph.get(key) ?? []) {
      if (!graph.has(child)) errors.push(`${key}: missing graph child ${child}`)
      else visit(child)
    }
    visiting.delete(key)
    visited.add(key)
  }
  visit(".")
  return [...new Set(errors)]
}
