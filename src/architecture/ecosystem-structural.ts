// biome-ignore-all lint/complexity/useLiteralKeys: JSON manifests are accessed by structural keys.

import { readdir, readFile } from "node:fs/promises"
import { basename, dirname, extname, join, relative, resolve, sep } from "node:path"

export interface ProductionFile {
  readonly path: string
  readonly text: string
}

export interface JsonManifest {
  readonly path: string
  readonly root: string
  readonly value: Record<string, unknown>
}

interface LexToken {
  readonly kind: "word" | "string" | "punct"
  readonly value: string
}

export interface RuntimeFinding {
  readonly runtime: string
  readonly path: string
}

export const codeExtensions = new Set([
  ".cjs",
  ".cts",
  ".js",
  ".jsx",
  ".mjs",
  ".mts",
  ".ts",
  ".tsx",
])

const ignoredDirectories = new Set([".git", ".omo", "node_modules", "dist", "target"])
const dependencySections = new Set([
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
  "resolutions",
  "overrides",
])
const runtimeNames = new Map([
  ["bun", "bun"],
  ["bunx", "bun"],
  ["node", "node"],
  ["nodejs", "node"],
  ["deno", "deno"],
  ["python", "python"],
  ["python2", "python"],
  ["python3", "python"],
  ["cargo", "cargo"],
  ["rustc", "cargo"],
  ["go", "go"],
])

export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value)

const walk = async (root: string): Promise<readonly string[]> => {
  const files: string[] = []
  const visit = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isSymbolicLink()) throw new Error(`symlink is not allowed: ${relative(root, path)}`)
      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) await visit(path)
      } else if (entry.isFile()) files.push(path)
    }
  }
  await visit(root)
  return files
}

export const collectProductionFiles = async (root: string): Promise<readonly ProductionFile[]> =>
  Promise.all(
    (await walk(root)).map(async (path) => ({ path, text: await readFile(path, "utf8") })),
  )

export const collectManifests = (
  files: readonly ProductionFile[],
  root: string,
): readonly JsonManifest[] =>
  files
    .filter(({ path }) => basename(path) === "package.json")
    .map(({ path, text }) => {
      const value: unknown = JSON.parse(text)
      if (!isRecord(value)) throw new Error(`${path}: JSON root must be an object`)
      return { path, root, value }
    })

const unescapeString = (text: string): string =>
  text.replace(/\\([\\"'`nrt])/g, (_match, character: string) =>
    character === "n" ? "\n" : character === "r" ? "\r" : character === "t" ? "\t" : character,
  )

const tokenize = (text: string): readonly LexToken[] => {
  const tokens: LexToken[] = []
  let index = 0
  while (index < text.length) {
    const character = text[index] ?? ""
    if (/\s/.test(character)) {
      index += 1
      continue
    }
    if (text.startsWith("//", index)) {
      const end = text.indexOf("\n", index + 2)
      index = end < 0 ? text.length : end + 1
      continue
    }
    if (text.startsWith("/*", index)) {
      const end = text.indexOf("*/", index + 2)
      index = end < 0 ? text.length : end + 2
      continue
    }
    if (character === "#" && (index === 0 || text[index - 1] === "\n")) {
      const end = text.indexOf("\n", index + 1)
      index = end < 0 ? text.length : end + 1
      continue
    }
    if (character === '"' || character === "'" || character === "`") {
      const quote = character
      let end = index + 1
      let value = ""
      while (end < text.length) {
        if ((text[end] ?? "") === "\\" && end + 1 < text.length) {
          value += text.slice(end, end + 2)
          end += 2
          continue
        }
        if ((text[end] ?? "") === quote) break
        value += text[end] ?? ""
        end += 1
      }
      tokens.push({ kind: "string", value: unescapeString(value) })
      index = end < text.length ? end + 1 : end
      continue
    }
    if ("(){}[];,:".includes(character)) {
      tokens.push({ kind: "punct", value: character })
      index += 1
      continue
    }
    let end = index + 1
    while (
      end < text.length &&
      !/\s/.test(text[end] ?? "") &&
      !"(){}[];,:\"'`".includes(text[end] ?? "") &&
      !text.startsWith("//", end) &&
      !text.startsWith("/*", end)
    )
      end += 1
    tokens.push({ kind: "word", value: text.slice(index, end) })
    index = end
  }
  return tokens
}

const shellTokenize = (text: string): readonly string[] => {
  const tokens: string[] = []
  let current = ""
  let quote: string | null = null
  const flush = (): void => {
    if (current.length > 0) tokens.push(current)
    current = ""
  }
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index] ?? ""
    if (quote !== null) {
      if (character === "\\" && index + 1 < text.length) {
        current += text[index + 1] ?? ""
        index += 1
      } else if (character === quote) quote = null
      else current += character
      continue
    }
    if (character === '"' || character === "'") quote = character
    else if (/\s/.test(character)) flush()
    else if (character === ";" || character === "(" || character === ")") {
      flush()
      tokens.push(character)
    } else if (character === "&" || character === "|") {
      flush()
      if (text[index + 1] === character) index += 1
      tokens.push(character)
    } else current += character
  }
  flush()
  return tokens
}

const commandRuntime = (tokens: readonly string[]): string | null => {
  let index = 0
  while (index < tokens.length) {
    const item = tokens[index]
    if (item === undefined) break
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(item) || item.startsWith("-")) {
      index += 1
      continue
    }
    if (basename(item).toLowerCase() === "env") {
      index += 1
      while (
        index < tokens.length &&
        ((tokens[index] ?? "").startsWith("-") ||
          /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[index] ?? ""))
      )
        index += 1
      continue
    }
    if (item === "command" || item === "exec" || item === "sudo") {
      index += 1
      continue
    }
    const name = basename(item).toLowerCase()
    if (name === "npx" || name === "corepack") {
      index += 1
      continue
    }
    if (["npm", "pnpm", "yarn"].includes(name)) {
      index += 1
      if (["exec", "dlx", "run"].includes(tokens[index] ?? "")) index += 1
      continue
    }
    return runtimeNames.get(name) ?? null
  }
  return null
}

const scriptRuntime = (text: string): RuntimeFinding | null => {
  let command: string[] = []
  const inspect = (): RuntimeFinding | null => {
    const runtime = commandRuntime(command)
    return runtime !== null && runtime !== "bun" ? { runtime, path: "script" } : null
  }
  for (const token of shellTokenize(text)) {
    if ([";", "(", ")", "&", "|"].includes(token)) {
      const finding = inspect()
      if (finding !== null) return finding
      command = []
    } else command.push(token)
  }
  return inspect()
}

const shebangRuntime = (text: string): string | null => {
  const firstLine = text.split(/\r?\n/, 1)[0] ?? ""
  if (!firstLine.startsWith("#!")) return null
  return commandRuntime(shellTokenize(firstLine.slice(2)))
}

const runtimeFromManifest = (manifest: JsonManifest): RuntimeFinding | null => {
  const engines = isRecord(manifest.value["engines"]) ? manifest.value["engines"] : {}
  for (const key of ["node", "deno", "python", "cargo", "go"])
    if (Object.hasOwn(engines, key)) return { runtime: key, path: manifest.path }
  for (const key of ["scripts", "tasks"]) {
    const scripts = isRecord(manifest.value[key]) ? manifest.value[key] : {}
    for (const value of Object.values(scripts)) {
      if (typeof value !== "string") continue
      const finding = scriptRuntime(value)
      if (finding !== null) return { runtime: finding.runtime, path: manifest.path }
    }
  }
  return null
}

const targetStrings = (value: unknown): readonly string[] => {
  if (typeof value === "string") return [value]
  if (Array.isArray(value)) return value.flatMap((item) => targetStrings(item))
  if (isRecord(value)) return Object.values(value).flatMap((item) => targetStrings(item))
  return []
}

const targetPath = (root: string, value: string): string | null => {
  if (!value.startsWith(".") && !value.startsWith("/")) return null
  const resolved = resolve(root, value)
  return resolved === root || resolved.startsWith(`${root}${sep}`) ? resolved : null
}

const targetRuntime = async (
  manifest: JsonManifest,
  value: unknown,
  executable: boolean,
): Promise<RuntimeFinding | null> => {
  for (const target of targetStrings(value)) {
    const path = targetPath(manifest.root, target)
    if (path === null) {
      if (target.startsWith(".") || target.startsWith("/"))
        return { runtime: "unresolved", path: resolve(manifest.root, target) }
      continue
    }
    let text: string
    try {
      text = await readFile(path, "utf8")
    } catch {
      return { runtime: "unresolved", path }
    }
    const shebang = shebangRuntime(text)
    if (shebang !== null && shebang !== "bun") return { runtime: shebang, path }
    const extension = extname(path).toLowerCase()
    if ([".py", ".rb", ".rs", ".go"].includes(extension))
      return { runtime: extension.slice(1), path }
    if (executable && [".js", ".jsx", ".mjs", ".cjs"].includes(extension) && shebang !== "bun")
      return { runtime: "ambiguous-javascript-bin", path }
  }
  return null
}

const runtimeFromManifestTargets = async (
  manifest: JsonManifest,
): Promise<RuntimeFinding | null> => {
  const binFinding = await targetRuntime(manifest, manifest.value["bin"], true)
  if (binFinding !== null) return binFinding
  return targetRuntime(manifest, manifest.value["exports"], false)
}

const languageRuntime = (file: ProductionFile, root: string): RuntimeFinding | null => {
  const path = relative(root, file.path)
  const extension = extname(path).toLowerCase()
  if ([".py", ".rb", ".rs", ".go"].includes(extension))
    return { runtime: extension.slice(1), path: file.path }
  const name = basename(path).toLowerCase()
  if (name === "cargo.toml" && /^\s*\[(?:package|workspace|dependencies)\]/m.test(file.text))
    return { runtime: "cargo", path: file.path }
  if (name === "cargo.lock" && /^\s*version\s*=\s*\d+/m.test(file.text))
    return { runtime: "cargo", path: file.path }
  if (name === "rust-toolchain.toml" && /^\s*\[toolchain\]/m.test(file.text))
    return { runtime: "cargo", path: file.path }
  if (name === "go.mod" && /^\s*module\s+/m.test(file.text))
    return { runtime: "go", path: file.path }
  if (
    (name === "deno.json" || name === "deno.jsonc") &&
    /["'](?:tasks|imports|compilerOptions)["']\s*:/.test(file.text)
  )
    return { runtime: "deno", path: file.path }
  const shebang = shebangRuntime(file.text)
  return shebang !== null && shebang !== "bun" ? { runtime: shebang, path: file.path } : null
}

export const runtimeFinding = async (
  files: readonly ProductionFile[],
  manifests: readonly JsonManifest[],
  root: string,
): Promise<RuntimeFinding | null> => {
  for (const file of files) {
    const finding = languageRuntime(file, root)
    if (finding !== null) return finding
  }
  for (const manifest of manifests) {
    const finding = runtimeFromManifest(manifest) ?? (await runtimeFromManifestTargets(manifest))
    if (finding !== null) return finding
  }
  return null
}

const sourceDependencySpec = (value: string): boolean => {
  const spec = value.trim()
  return (
    /^(?:link|file|workspace):/i.test(spec) ||
    /^(?:\.\.?[\\/]|[\\/]|~[\\/])/.test(spec) ||
    /^(?:git\+|git:|git@|ssh:\/\/|github:)/i.test(spec) ||
    /^(?:https?:\/\/|ssh:\/\/)[^\s]+(?:\.git(?:[#?].*)?|\/[^\s]*)$/i.test(spec) ||
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:[#?].*)?$/.test(spec)
  )
}

export const manifestDependencyEntries = (
  manifest: JsonManifest,
): readonly { readonly name: string; readonly spec: string }[] => {
  const entries: { name: string; spec: string }[] = []
  for (const section of dependencySections) {
    const value = manifest.value[section]
    if (!isRecord(value)) continue
    for (const [name, spec] of Object.entries(value))
      if (typeof spec === "string") entries.push({ name, spec })
  }
  return entries
}

export const isSourceDependency = (value: string): boolean => sourceDependencySpec(value)

export const isSiblingPackage = (name: string): boolean =>
  /^@gorce-ai\/(?:studio|jetbrains)$/i.test(name) || /^gorce-(?:studio|jetbrains)$/i.test(name)

export const importSpecifications = (text: string): readonly string[] => {
  const tokens = tokenize(text)
  const specs: string[] = []
  for (let index = 0; index < tokens.length; index += 1) {
    const lexeme = tokens[index]
    if (lexeme === undefined || lexeme.kind !== "word") continue
    if (lexeme.value === "import" || lexeme.value === "require") {
      if (tokens[index + 1]?.value === "(" && tokens[index + 2]?.kind === "string")
        specs.push(tokens[index + 2]?.value ?? "")
      else if (lexeme.value === "import" && tokens[index + 1]?.kind === "string")
        specs.push(tokens[index + 1]?.value ?? "")
      else if (lexeme.value === "import") {
        for (let cursor = index + 1; cursor < tokens.length; cursor += 1) {
          const current = tokens[cursor]
          if (current?.value === ";") break
          if (current?.value === "from" && tokens[cursor + 1]?.kind === "string") {
            specs.push(tokens[cursor + 1]?.value ?? "")
            break
          }
        }
      }
      continue
    }
    if (lexeme.value === "export") {
      for (let cursor = index + 1; cursor < tokens.length; cursor += 1) {
        const current = tokens[cursor]
        if (current?.value === ";") break
        if (current?.value === "from" && tokens[cursor + 1]?.kind === "string") {
          specs.push(tokens[cursor + 1]?.value ?? "")
          break
        }
      }
    }
  }
  return specs
}

export const relativeImportEscapesRoot = (file: string, root: string, spec: string): boolean => {
  if (spec.startsWith("/")) return true
  if (!spec.startsWith(".")) return false
  const resolved = resolve(dirname(file), spec)
  return !(resolved === root || resolved.startsWith(`${root}${sep}`))
}

export const gradleSourceCall = (text: string): boolean => {
  const tokens = tokenize(text)
  return tokens.some(
    (token, index) =>
      token !== undefined &&
      token.kind === "word" &&
      ["files", "project", "includeBuild"].includes(token.value) &&
      tokens[index + 1]?.value === "(",
  )
}

export const relativePathContains = (path: string, root: string, name: string): boolean =>
  relative(root, path)
    .toLowerCase()
    .split(/[\\/_.-]+/)
    .includes(name)
