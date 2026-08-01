export type TaskId = number | "F1" | "F2" | "F3" | "F4" | "F5" | "F6"

export interface BlockerEntry {
  readonly task: TaskId
  readonly blocked_by: readonly TaskId[]
}

export interface CommandOwner {
  readonly command: string
  readonly implemented_by: number
  readonly owner: string
}

export interface ExecutionManifest {
  readonly schema: string
  readonly plan_sha256: string
  readonly task_count: number
  readonly blocker_graph: readonly BlockerEntry[]
  readonly blocker_graph_sha256: string
  readonly command_owners: readonly CommandOwner[]
  readonly owner_gates: readonly unknown[]
  readonly task_41_command_owner_tasks: readonly number[]
  readonly signer_identity: string
  readonly signature: string
}

export type CheckStatus = "passed" | "failed"

export interface CheckResult {
  readonly name: string
  readonly status: CheckStatus
  readonly detail?: string
}

export interface VerificationReport {
  readonly schema: "gorce.verification-result/v1"
  readonly command: string
  readonly ok: boolean
  readonly verdict?: "APPROVED" | "CHANGES_REQUESTED" | "NOT_APPLICABLE"
  readonly checks: readonly CheckResult[]
  readonly errors: readonly string[]
}

export interface RepositoryFileSnapshot {
  readonly path: string
  readonly content?: string
}

export interface RepositorySnapshot {
  readonly licenseText: string | null
  readonly stagedPaths: readonly string[]
  readonly files?: readonly RepositoryFileSnapshot[]
}
