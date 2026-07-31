import { createHash } from "node:crypto"

export type CanonicalYamlValue = string | boolean | CanonicalYamlMap | readonly CanonicalYamlValue[]

export interface CanonicalYamlMap {
  readonly [key: string]: CanonicalYamlValue
}

export type CanonicalYamlSchema =
  | { readonly kind: "string" }
  | { readonly kind: "boolean" }
  | {
      readonly kind: "map"
      readonly keys: Readonly<Record<string, CanonicalYamlSchema>>
      readonly order: readonly string[]
    }
  | { readonly kind: "list"; readonly item: CanonicalYamlSchema }

interface SourceLine {
  readonly indent: number
  readonly content: string
}

export interface CanonicalYamlDocument {
  readonly value: CanonicalYamlMap
  readonly text: string
  readonly bytes: Uint8Array
  readonly sha256: string
}

const stringSchema: CanonicalYamlSchema = { kind: "string" }
const booleanSchema: CanonicalYamlSchema = { kind: "boolean" }

const isMap = (value: CanonicalYamlValue): value is CanonicalYamlMap =>
  typeof value === "object" && value !== null && !Array.isArray(value)

const scalar = (source: string, lineNumber: number): string | boolean => {
  if (source.startsWith('"')) {
    if (!source.endsWith('"')) throw new Error(`line ${lineNumber}: malformed quoted string`)
    let value: unknown
    try {
      value = JSON.parse(source)
    } catch {
      throw new Error(`line ${lineNumber}: malformed quoted string`)
    }
    if (typeof value !== "string" || JSON.stringify(value) !== source) {
      throw new Error(`line ${lineNumber}: strings must use canonical double quotes`)
    }
    return value
  }
  if (source === "true") return true
  if (source === "false") return false
  throw new Error(`line ${lineNumber}: only canonical strings and booleans are allowed`)
}

const sourceLines = (text: string): readonly SourceLine[] => {
  if (text.length === 0) throw new Error("YAML is empty")
  if (text.charCodeAt(0) === 0xfeff) throw new Error("YAML must be BOM-free UTF-8")
  if (text.includes("\r")) throw new Error("YAML must use LF line endings")
  if (!text.endsWith("\n")) throw new Error("YAML must end with a final newline")

  const rawLines = text.slice(0, -1).split("\n")
  if (rawLines.length === 0) throw new Error("YAML is empty")
  return rawLines.map((line, index) => {
    if (line.length === 0) throw new Error(`line ${index + 1}: blank lines are not canonical`)
    if (line.endsWith(" ") || line.endsWith("\t")) {
      throw new Error(`line ${index + 1}: trailing whitespace is not canonical`)
    }
    const match = /^( *)?(.*)$/.exec(line)
    if (match === null) throw new Error(`line ${index + 1}: malformed line`)
    const spaces = match[1]?.length ?? 0
    if (spaces % 2 !== 0 || match[2] === undefined || match[2].length === 0) {
      throw new Error(`line ${index + 1}: indentation must use two-space levels`)
    }
    if (match[2].includes("#") || /(^|[ :])([&*!])/.test(match[2])) {
      throw new Error(`line ${index + 1}: comments, aliases, and tags are forbidden`)
    }
    return { indent: spaces, content: match[2] as string }
  })
}

const parseBlock = (
  lines: readonly SourceLine[],
  start: number,
  indent: number,
): { readonly value: CanonicalYamlValue; readonly next: number } => {
  const first = lines[start]
  if (first === undefined || first.indent !== indent)
    throw new Error(`line ${start + 1}: invalid indentation`)
  if (first.content.startsWith("- ")) {
    const values: CanonicalYamlValue[] = []
    let index = start
    while (index < lines.length) {
      const line = lines[index]
      if (line === undefined || line.indent !== indent) break
      if (!line.content.startsWith("- ")) throw new Error(`line ${index + 1}: mixed map and list`)
      values.push(scalar(line.content.slice(2), index + 1))
      index += 1
    }
    return { value: values, next: index }
  }

  const result: Record<string, CanonicalYamlValue> = {}
  let index = start
  while (index < lines.length) {
    const line = lines[index]
    if (line === undefined || line.indent !== indent) break
    if (line.content.startsWith("- ")) throw new Error(`line ${index + 1}: mixed map and list`)
    const separator = line.content.indexOf(":")
    if (separator < 1 || !/^[A-Za-z][A-Za-z0-9_]*$/.test(line.content.slice(0, separator))) {
      throw new Error(`line ${index + 1}: malformed mapping key`)
    }
    const key = line.content.slice(0, separator)
    if (Object.hasOwn(result, key)) throw new Error(`line ${index + 1}: duplicate key ${key}`)
    const remainder = line.content.slice(separator + 1)
    if (remainder.length > 0) {
      if (!remainder.startsWith(" "))
        throw new Error(`line ${index + 1}: mapping needs a space after ':'`)
      result[key] = scalar(remainder.slice(1), index + 1)
      index += 1
      continue
    }
    const child = lines[index + 1]
    if (child === undefined || child.indent !== indent + 2) {
      throw new Error(`line ${index + 1}: empty mappings are not canonical`)
    }
    const parsed = parseBlock(lines, index + 1, indent + 2)
    result[key] = parsed.value
    index = parsed.next
  }
  return { value: result, next: index }
}

const validateSchema = (
  value: CanonicalYamlValue,
  schema: CanonicalYamlSchema,
  path: string,
): void => {
  if (schema.kind === "string") {
    if (typeof value !== "string") throw new Error(`${path}: expected a string`)
    return
  }
  if (schema.kind === "boolean") {
    if (typeof value !== "boolean") throw new Error(`${path}: expected a boolean`)
    return
  }
  if (schema.kind === "list") {
    if (!Array.isArray(value)) throw new Error(`${path}: expected a list`)
    for (const [index, item] of value.entries())
      validateSchema(item, schema.item, `${path}[${index}]`)
    return
  }
  if (!isMap(value)) throw new Error(`${path}: expected a mapping`)
  const actualKeys = Object.keys(value)
  const expectedKeys = schema.order
  if (actualKeys.some((key) => !Object.hasOwn(schema.keys, key))) {
    const unknown = actualKeys.find((key) => !Object.hasOwn(schema.keys, key))
    throw new Error(`${path}: unknown key ${unknown ?? "<unknown>"}`)
  }
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new Error(`${path}: keys must use the canonical schema order`)
  }
  for (const key of expectedKeys) {
    const child = value[key]
    const childSchema = schema.keys[key]
    if (child === undefined || childSchema === undefined)
      throw new Error(`${path}: missing key ${key}`)
    validateSchema(child, childSchema, `${path}.${key}`)
  }
}

const render = (value: CanonicalYamlValue, indent: number): string => {
  const prefix = " ".repeat(indent)
  if (typeof value === "string") return JSON.stringify(value)
  if (typeof value === "boolean") return value ? "true" : "false"
  if (Array.isArray(value))
    return value.map((item) => `${prefix}- ${render(item, indent + 2)}`).join("\n")
  return Object.entries(value)
    .map(([key, child]) => {
      if (typeof child === "object" && child !== null) {
        return `${prefix}${key}:\n${render(child, indent + 2)}`
      }
      return `${prefix}${key}: ${render(child, indent + 2)}`
    })
    .join("\n")
}

export const parseCanonicalYaml = (text: string, schema: CanonicalYamlSchema): CanonicalYamlMap => {
  const lines = sourceLines(text)
  const parsed = parseBlock(lines, 0, 0)
  if (parsed.next !== lines.length)
    throw new Error(`line ${parsed.next + 1}: trailing YAML content`)
  if (!isMap(parsed.value)) throw new Error("YAML root must be a mapping")
  validateSchema(parsed.value, schema, "$")
  const canonical = `${render(parsed.value, 0)}\n`
  if (canonical !== text) throw new Error("YAML is not canonical")
  return parsed.value
}

export const readCanonicalYaml = async (
  path: string,
  schema: CanonicalYamlSchema,
): Promise<CanonicalYamlDocument> => {
  const bytes = new Uint8Array(await Bun.file(path).arrayBuffer())
  let text: string
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes)
  } catch {
    throw new Error(`${path}: expected valid UTF-8`)
  }
  const value = parseCanonicalYaml(text, schema)
  const sha256 = createHash("sha256").update(bytes).digest("hex")
  return { value, text, bytes, sha256 }
}

export const string = (): CanonicalYamlSchema => stringSchema
export const boolean = (): CanonicalYamlSchema => booleanSchema
export const list = (item: CanonicalYamlSchema): CanonicalYamlSchema => ({ kind: "list", item })
export const map = (
  entries: ReadonlyArray<readonly [string, CanonicalYamlSchema]>,
): CanonicalYamlSchema => ({
  kind: "map",
  keys: Object.fromEntries(entries),
  order: entries.map(([key]) => key),
})
