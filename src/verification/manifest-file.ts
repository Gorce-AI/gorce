import { createPublicKey, verify } from "node:crypto"
import { basename, dirname, join } from "node:path"
import { validateManifest } from "./manifest.js"
import type { CheckResult, VerificationReport } from "./types.js"

export interface ManifestFileOptions {
  readonly manifestPath: string
  readonly publicKeyPath?: string
  readonly signaturePath?: string
}

const report = (checks: readonly CheckResult[], errors: readonly string[]): VerificationReport => ({
  schema: "gorce.verification-result/v1",
  command: "verify:bootstrap",
  ok: errors.length === 0,
  checks,
  errors,
})

const failure = (name: string, detail: string): VerificationReport =>
  report([{ name, status: "failed", detail }], [detail])

const errorText = (error: unknown): string =>
  error instanceof Error ? error.message : "unknown error"

const withCheck = (
  checks: CheckResult[],
  errors: string[],
  name: string,
  valid: boolean,
  detail: string,
): void => {
  checks.push({ name, status: valid ? "passed" : "failed", ...(valid ? {} : { detail }) })
  if (!valid) errors.push(detail)
}

export const verifyManifestFile = async (
  options: ManifestFileOptions,
): Promise<VerificationReport> => {
  const manifestFile = Bun.file(options.manifestPath)
  if (!(await manifestFile.exists()))
    return failure("manifest-file", "execution manifest is missing")

  const signaturePath =
    options.signaturePath ?? join(dirname(options.manifestPath), "execution-manifest.sig")
  const publicKeyPath =
    options.publicKeyPath ?? join(dirname(options.manifestPath), "execution-manifest.ed25519.pub")
  const signatureFile = Bun.file(signaturePath)
  const publicKeyFile = Bun.file(publicKeyPath)
  if (!(await signatureFile.exists()))
    return failure("signature-file", "execution manifest signature is missing")
  if (!(await publicKeyFile.exists()))
    return failure("public-key-file", "execution manifest public key is missing")

  const payload = new Uint8Array(await manifestFile.arrayBuffer())
  const signature = new Uint8Array(await signatureFile.arrayBuffer())
  const publicKey = await publicKeyFile.text()
  const checks: CheckResult[] = []
  const errors: string[] = []

  let parsed: unknown
  let payloadText: string
  try {
    payloadText = new TextDecoder().decode(payload)
    parsed = JSON.parse(payloadText) as unknown
  } catch {
    return failure("manifest-json", "manifest payload is malformed JSON")
  }
  const canonicalPayload = JSON.stringify(parsed)
  withCheck(
    checks,
    errors,
    "canonical-payload",
    canonicalPayload === payloadText,
    "manifest payload is not canonical JSON",
  )

  let signatureValid = false
  try {
    const key = createPublicKey(publicKey)
    const isEd25519PublicKey =
      publicKey.includes("-----BEGIN PUBLIC KEY-----") &&
      publicKey.includes("-----END PUBLIC KEY-----") &&
      key.asymmetricKeyType === "ed25519"
    withCheck(
      checks,
      errors,
      "ed25519-public-key",
      isEd25519PublicKey,
      "public key is not an Ed25519 public key",
    )
    signatureValid =
      isEd25519PublicKey && signature.length === 64 && verify(null, payload, key, signature)
  } catch (error) {
    checks.push({ name: "ed25519-signature", status: "failed", detail: "public key is invalid" })
    errors.push(`public key is invalid: ${errorText(error)}`)
  }
  if (checks.every((check) => check.name !== "ed25519-signature")) {
    withCheck(
      checks,
      errors,
      "ed25519-signature",
      signatureValid,
      "Ed25519 signature verification failed",
    )
  }

  const structural = validateManifest(parsed)
  checks.push(...structural.checks)
  errors.push(...structural.errors)
  withCheck(
    checks,
    errors,
    "signature-filename",
    basename(signaturePath) === "execution-manifest.sig",
    "signature file name is not approved",
  )
  return report(checks, errors)
}
