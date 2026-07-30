import { combineReports } from "../verification/combine.js"
import { verifyDocs } from "../verification/docs.js"
import { verifyManifestFile } from "../verification/manifest-file.js"
import { scanRepository } from "../verification/repository.js"
import { emit, failed, flag, hasSwitch, parseCli } from "./cli.js"

const main = async (): Promise<void> => {
  const options = parseCli(process.argv.slice(2))
  const manifestPath = flag(options, "execution-manifest")
  if (manifestPath === undefined || manifestPath.length === 0) {
    emit(failed("verify:bootstrap", "--execution-manifest is required"), hasSwitch(options, "json"))
    return
  }
  const keyPath = flag(options, "public-key")
  const signaturePath = flag(options, "signature")
  const manifest = await verifyManifestFile({
    manifestPath,
    ...(keyPath === undefined ? {} : { publicKeyPath: keyPath }),
    ...(signaturePath === undefined ? {} : { signaturePath }),
  })
  const repository = scanRepository(process.cwd())
  const docs = verifyDocs(process.cwd())
  emit(combineReports("verify:bootstrap", [manifest, repository, docs]), hasSwitch(options, "json"))
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "unexpected verification failure"
  emit(failed("verify:bootstrap", message), process.argv.includes("--json"))
})
