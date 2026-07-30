import { verifyEvidenceDirectory } from "../verification/evidence.js"
import { emit, failed, flag, hasSwitch, parseCli } from "./cli.js"

const main = async (): Promise<void> => {
  const options = parseCli(process.argv.slice(2))
  const directory = flag(options, "evidence")
  if (directory === undefined || directory.length === 0) {
    emit(failed("verify:evidence", "--evidence is required"), hasSwitch(options, "json"))
    return
  }
  emit(await verifyEvidenceDirectory(directory), hasSwitch(options, "json"))
}

main().catch((error: unknown) => {
  const message =
    error instanceof Error ? error.message : "unexpected evidence verification failure"
  emit(failed("verify:evidence", message), process.argv.includes("--json"))
})
