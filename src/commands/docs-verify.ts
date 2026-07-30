import { verifyDocs } from "../verification/docs.js"
import { emit, hasSwitch, parseCli } from "./cli.js"

const options = parseCli(process.argv.slice(2))
emit(verifyDocs(process.cwd()), hasSwitch(options, "json"))
