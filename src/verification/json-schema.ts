// biome-ignore-all lint/complexity/useLiteralKeys: JSON Schema keywords are dynamic contract keys.

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { readonly [key: string]: JsonValue }

type JsonSchema = { readonly [key: string]: JsonValue }

const isRecord = (value: unknown): value is { readonly [key: string]: JsonValue } =>
  typeof value === "object" && value !== null && !Array.isArray(value)

const equal = (left: JsonValue, right: JsonValue): boolean =>
  JSON.stringify(left) === JSON.stringify(right)

const typeMatches = (value: JsonValue, type: JsonValue): boolean => {
  if (typeof type !== "string") return false
  if (type === "object") return isRecord(value)
  if (type === "array") return Array.isArray(value)
  if (type === "integer") return typeof value === "number" && Number.isInteger(value)
  if (type === "null") return value === null
  return typeof value === type
}

const resolveRef = (schema: JsonSchema, root: JsonSchema): JsonSchema | null => {
  const reference = schema["$ref"]
  if (typeof reference !== "string" || !reference.startsWith("#/$defs/")) return null
  const defs = root["$defs"]
  if (!isRecord(defs)) return null
  const definition = defs[reference.slice("#/$defs/".length)]
  return isRecord(definition) ? definition : null
}

export const validateJsonSchema = (
  value: JsonValue,
  schema: JsonSchema,
  root: JsonSchema = schema,
  path = "$",
): readonly string[] => {
  const errors: string[] = []
  const referenced = resolveRef(schema, root)
  if (schema["$ref"] !== undefined) {
    if (referenced === null) return [`${path}: unresolved schema reference`]
    return validateJsonSchema(value, referenced, root, path)
  }
  if (schema["type"] !== undefined && !typeMatches(value, schema["type"]))
    errors.push(`${path}: type mismatch`)
  if (schema["const"] !== undefined && !equal(value, schema["const"]))
    errors.push(`${path}: const mismatch`)
  const enumeration = schema["enum"]
  if (Array.isArray(enumeration) && !enumeration.some((item) => equal(value, item)))
    errors.push(`${path}: enum mismatch`)
  if (
    typeof schema["pattern"] === "string" &&
    (typeof value !== "string" || !new RegExp(schema["pattern"]).test(value))
  )
    errors.push(`${path}: pattern mismatch`)
  if (
    typeof schema["minLength"] === "number" &&
    (typeof value !== "string" || value.length < schema["minLength"])
  )
    errors.push(`${path}: minLength violation`)
  if (
    typeof schema["minimum"] === "number" &&
    (typeof value !== "number" || value < schema["minimum"])
  )
    errors.push(`${path}: minimum violation`)
  if (Array.isArray(value)) {
    if (typeof schema["minItems"] === "number" && value.length < schema["minItems"])
      errors.push(`${path}: minItems violation`)
    if (typeof schema["maxItems"] === "number" && value.length > schema["maxItems"])
      errors.push(`${path}: maxItems violation`)
    if (schema["uniqueItems"] === true) {
      const serialized = value.map((item) => JSON.stringify(item))
      if (new Set(serialized).size !== serialized.length) errors.push(`${path}: duplicate items`)
    }
    const prefixItems = schema["prefixItems"]
    if (Array.isArray(prefixItems)) {
      for (const [index, itemSchema] of prefixItems.entries()) {
        if (isRecord(itemSchema) && value[index] !== undefined)
          errors.push(
            ...validateJsonSchema(value[index] ?? null, itemSchema, root, `${path}[${index}]`),
          )
      }
    }
    const itemSchema = schema["items"]
    if (isRecord(itemSchema)) {
      for (const [index] of value.entries())
        errors.push(
          ...validateJsonSchema(value[index] ?? null, itemSchema, root, `${path}[${index}]`),
        )
    }
    const contains = schema["contains"]
    if (isRecord(contains)) {
      const matches = value.filter(
        (item) => validateJsonSchema(item, contains, root).length === 0,
      ).length
      const minimum = typeof schema["minContains"] === "number" ? schema["minContains"] : 1
      const maximum = typeof schema["maxContains"] === "number" ? schema["maxContains"] : Infinity
      if (matches < minimum || matches > maximum) errors.push(`${path}: contains violation`)
    }
  }
  if (isRecord(value)) {
    const required = schema["required"]
    if (Array.isArray(required)) {
      for (const key of required) {
        if (typeof key === "string" && !Object.hasOwn(value, key))
          errors.push(`${path}: missing ${key}`)
      }
    }
    const properties = schema["properties"]
    if (isRecord(properties)) {
      for (const [key, child] of Object.entries(properties)) {
        if (Object.hasOwn(value, key) && isRecord(child))
          errors.push(...validateJsonSchema(value[key] ?? null, child, root, `${path}.${key}`))
      }
      if (schema["additionalProperties"] === false) {
        for (const key of Object.keys(value)) {
          if (!Object.hasOwn(properties, key)) errors.push(`${path}: unexpected ${key}`)
        }
      }
    }
  }
  const allOf = schema["allOf"]
  if (Array.isArray(allOf)) {
    for (const child of allOf) {
      if (isRecord(child)) errors.push(...validateJsonSchema(value, child, root, path))
    }
  }
  const anyOf = schema["anyOf"]
  if (
    Array.isArray(anyOf) &&
    !anyOf.some((child) => isRecord(child) && validateJsonSchema(value, child, root).length === 0)
  )
    errors.push(`${path}: anyOf violation`)
  const oneOf = schema["oneOf"]
  if (
    Array.isArray(oneOf) &&
    oneOf.filter((child) => isRecord(child) && validateJsonSchema(value, child, root).length === 0)
      .length !== 1
  )
    errors.push(`${path}: oneOf violation`)
  const not = schema["not"]
  if (isRecord(not) && validateJsonSchema(value, not, root).length === 0)
    errors.push(`${path}: not violation`)
  const conditional = schema["if"]
  if (isRecord(conditional) && validateJsonSchema(value, conditional, root).length === 0) {
    const then = schema["then"]
    if (isRecord(then)) errors.push(...validateJsonSchema(value, then, root, path))
  }
  return errors
}

export const parseJsonSchema = (text: string): JsonSchema => {
  const value = JSON.parse(text) as JsonValue
  if (!isRecord(value)) throw new Error("JSON Schema root must be an object")
  return value
}
