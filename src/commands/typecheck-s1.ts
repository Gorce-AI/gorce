import { generatedOutputs, validateProjectReferenceGraph } from "../verification/typecheck.js"

const root = JSON.parse(await Bun.file("tsconfig.json").text()) as {
  readonly references?: readonly { readonly path?: string }[]
}
const references = root.references?.map((item) => item.path) ?? []
const expected = [
  "./tsconfig.source.json",
  "./tsconfig.test.json",
  "./packages/core",
  "./packages/tui-harness",
  "./apps/tui-harness",
]
if (JSON.stringify(references) !== JSON.stringify(expected)) {
  console.error("S1_TYPECHECK: root project references do not match the approved graph")
  process.exit(1)
}

const noEmitConfig = JSON.parse(await Bun.file("tsconfig.s1.noemit.json").text()) as {
  readonly compilerOptions?: { readonly noEmit?: boolean; readonly incremental?: boolean }
}
if (
  noEmitConfig.compilerOptions?.noEmit !== true ||
  noEmitConfig.compilerOptions?.incremental !== false
) {
  console.error("S1_TYPECHECK: no-emit config must set noEmit=true and incremental=false")
  process.exit(1)
}

const graphErrors = await validateProjectReferenceGraph(process.cwd())
if (graphErrors.length > 0) {
  console.error(`S1_TYPECHECK: invalid project reference graph\n${graphErrors.join("\n")}`)
  process.exit(1)
}

const before = await generatedOutputs(process.cwd())
if (before.length > 0) {
  console.error(`S1_TYPECHECK: generated output exists before typecheck\n${before.join("\n")}`)
  process.exit(1)
}

const processHandle = Bun.spawn(
  [
    process.execPath,
    "node_modules/typescript/bin/tsc",
    "--noEmit",
    "--incremental",
    "false",
    "--pretty",
    "false",
    "--project",
    "tsconfig.s1.noemit.json",
  ],
  { stdout: "inherit", stderr: "inherit" },
)
const exitCode = await processHandle.exited
if (exitCode !== 0) {
  console.error(`S1_TYPECHECK: no-emit graph failed with exit code ${exitCode}`)
  process.exit(exitCode)
}

const after = await generatedOutputs(process.cwd())
if (after.length > 0) {
  console.error(`S1_TYPECHECK: generated output was created by typecheck\n${after.join("\n")}`)
  process.exit(1)
}
