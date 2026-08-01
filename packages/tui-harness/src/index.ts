import { CORE_PACKAGE_NAME } from "@gorce-ai/core"

export const TUI_HARNESS_PACKAGE_NAME = "@gorce-ai/tui-harness" as const

export const helloPayload = (): {
  readonly schema: "gorce.s1.hello/v1"
  readonly hello: "gorce-tui-harness"
  readonly package: "@gorce-ai/tui-harness"
  readonly core: "@gorce-ai/core"
  readonly ok: true
} => ({
  schema: "gorce.s1.hello/v1",
  hello: "gorce-tui-harness",
  package: TUI_HARNESS_PACKAGE_NAME,
  core: CORE_PACKAGE_NAME,
  ok: true,
})
