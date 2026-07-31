import { join, resolve } from "node:path"
import { verifyEcosystem } from "../architecture/ecosystem.js"
import { emit, failed, flag, parseStrictCli, type StrictCliSpec } from "./cli.js"

const cliSpec: StrictCliSpec = {
  flags: ["technology-baseline", "core-inventory-ban", "core", "studio", "jetbrains"],
  switches: ["published-only", "json"],
}

const main = async (): Promise<void> => {
  const parsed = parseStrictCli(process.argv.slice(2), cliSpec)
  if (!parsed.ok) {
    emit(failed("verify:architecture:ecosystem", parsed.error), process.argv.includes("--json"))
    return
  }
  const digest = flag(parsed.options, "technology-baseline")
  const inventory = flag(parsed.options, "core-inventory-ban")
  if (
    digest === undefined ||
    inventory === undefined ||
    !parsed.options.switches.has("published-only")
  ) {
    emit(
      failed(
        "verify:architecture:ecosystem",
        "--published-only, --technology-baseline, and --core-inventory-ban are required",
      ),
      parsed.options.switches.has("json"),
    )
    return
  }
  if (!/^[0-9a-f]{64}$/.test(digest)) {
    emit(
      failed(
        "verify:architecture:ecosystem",
        "--technology-baseline must be a lowercase SHA-256 digest",
      ),
      parsed.options.switches.has("json"),
    )
    return
  }
  const coreRoot = resolve(flag(parsed.options, "core") ?? process.cwd())
  const parent = resolve(coreRoot, "..")
  const studioRoot = resolve(flag(parsed.options, "studio") ?? join(parent, "gorce-studio"))
  const jetbrainsRoot = resolve(flag(parsed.options, "jetbrains") ?? join(parent, "gorce-jetbrains"))
  const coreInventoryBan = inventory.split(",")
  if (
    coreInventoryBan.some((entry) => !["studio", "jetbrains"].includes(entry)) ||
    new Set(coreInventoryBan).size !== coreInventoryBan.length
  ) {
    emit(
      failed(
        "verify:architecture:ecosystem",
        "--core-inventory-ban may contain studio and jetbrains exactly once",
      ),
      parsed.options.switches.has("json"),
    )
    return
  }
  try {
    const report = await verifyEcosystem({
      coreRoot,
      studioRoot,
      jetbrainsRoot,
      technologyBaseline: digest,
      coreInventoryBan,
      publishedOnly: true,
    })
    emit(report, parsed.options.switches.has("json"))
  } catch (error: unknown) {
    emit(
      failed(
        "verify:architecture:ecosystem",
        error instanceof Error ? error.message : "unexpected ecosystem verification failure",
      ),
      parsed.options.switches.has("json"),
    )
  }
}

main().catch((error: unknown) => {
  emit(
    failed(
      "verify:architecture:ecosystem",
      error instanceof Error ? error.message : "unexpected ecosystem verification failure",
    ),
    process.argv.includes("--json"),
  )
})
