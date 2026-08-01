# Threat model

## S1 assets

- Integrity of the private workspace graph and canonical architecture bytes.
- Native hello artifacts and their reproducibility/native-runner evidence.
- Dependency and build-tool supply-chain inputs.

## S1 trust boundaries

- Workspace package imports must flow app -> harness -> core.
- Native artifacts are copied outside the source tree before execution.
- CI and local verification use the pinned Bun toolchain only.

## S1 threats

- A package imports outside the approved workspace direction.
- A cross-built artifact is incorrectly reported as native execution.
- Non-reproducible compilation or an altered canonical rule is accepted.
- A compromised dependency or build tool enters the workspace.

## Mitigations and gaps

The S1 cutover verifier, no-emit project-reference check, copied-outside-source
runner, paired SHA-256 build check, native evidence index, frozen install, and
Bun audit are the active mitigations. Runtime authentication, storage, daemon,
transport, provider, and release hardening are outside S1.
