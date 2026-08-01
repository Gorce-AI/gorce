import { helloPayload } from "@gorce-ai/tui-harness"

const args = Bun.argv.slice(2)
if (args.length !== 0) {
  console.error(
    JSON.stringify({
      schema: "gorce.s1.hello-error/v1",
      error: "S1_ARGUMENTS_FORBIDDEN",
      reason: "gorce-tui-harness accepts no arguments",
    }),
  )
  process.exit(2)
}

console.log(JSON.stringify(helloPayload()))
