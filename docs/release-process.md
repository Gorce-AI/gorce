# Release process

Releases are currently placeholders until runtime behavior and compatibility
policies are established.

## Planned release steps

1. Confirm the workspace checks and security checks pass.
2. Review the changelog and public API or storage changes.
3. Update versions together where compatibility requires it.
4. Create a signed, annotated tag from the release commit.
5. Publish artifacts and checksums through the release workflow.
6. Record migration, rollback, and known-issue notes.

Release artifacts must include the applicable Apache-2.0 license and NOTICE.
No release should claim runtime guarantees that are not covered by tests.
