export const deepFreeze = <T>(value: T): T => {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value
  for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child)
  return Object.freeze(value)
}

export const immutableCopy = <T>(value: T): T => deepFreeze(structuredClone(value))

export const immutableHistory = <T>(events: readonly T[]): readonly T[] =>
  immutableCopy([...events])

export const immutableBatch = <T extends readonly unknown[]>(events: T): Readonly<T> =>
  immutableCopy([...events]) as Readonly<T>
