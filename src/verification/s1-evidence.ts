// biome-ignore-all lint/complexity/useLiteralKeys: Evidence provenance uses JSON contract keys.

import { readFile } from "node:fs/promises"
import { join } from "node:path"
import { parseJsonSchema, validateJsonSchema, type JsonValue } from "./json-schema.js"
import {
  currentTask6BaselineSha256,
  nativeTargets,
  nonReleaseScope,
  bunVersion,
} from "./s1-native.js"

export const readS1Schema = async (
  root: string,
  name: string,
): Promise<Record<string, JsonValue>> =>
  parseJsonSchema(await readFile(join(root, "tests/qa", name), "utf8"))

export const schemaErrors = async (
  root: string,
  name: string,
  value: JsonValue,
): Promise<readonly string[]> => {
  const schema = await readS1Schema(root, name)
  return validateJsonSchema(value, schema, schema)
}

export const validProvenance = (value: Record<string, unknown>, root = process.cwd()): boolean =>
  typeof value["source_commit"] === "string" &&
  /^[0-9a-f]{40}$/.test(value["source_commit"]) &&
  value["task6_baseline_sha256"] === currentTask6BaselineSha256(root) &&
  value["builder_bun"] === Bun.version &&
  value["builder_bun"] === bunVersion &&
  value["release_claim"] === false &&
  value["scope"] === nonReleaseScope

export const expectedNativeTargets = (): readonly string[] => nativeTargets
