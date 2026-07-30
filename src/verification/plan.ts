import {
  APPROVED_BLOCKER_GRAPH,
  APPROVED_COMMAND_OWNERS,
  APPROVED_PLAN_SHA256,
} from "./expected.js"
import { validateManifest } from "./manifest.js"
import type { VerificationReport } from "./types.js"

export const verifyPlanPolicy = (): VerificationReport =>
  validateManifest({
    schema: "gorce.execution-manifest/v1",
    plan_sha256: APPROVED_PLAN_SHA256,
    task_count: 41,
    blocker_graph: APPROVED_BLOCKER_GRAPH,
    blocker_graph_sha256: "65e5be39146dc3a0ddec90c4939e3869f9c908b029b23fcdc149c83ad2fc082a",
    command_owners: APPROVED_COMMAND_OWNERS,
    owner_gates: [],
    task_41_command_owner_tasks: [3, 4, 5, 26],
    signer_identity: "lead",
    signature: "execution-manifest.sig",
  })
