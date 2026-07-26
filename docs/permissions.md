# Permissions

Gorce should follow least privilege. The daemon must not require privileges
that are unnecessary for its configured storage root or local API.

## Planned policy

- Store data under an explicitly configured user-owned directory.
- Refuse unsafe roots and unexpected symlinks where they could escape the
  configured boundary.
- Create files with restrictive permissions before writing sensitive content.
- Keep API access local by default; remote exposure must be an explicit choice.
- Separate read, write, administrative, and recovery operations.
- Never log credentials, tokens, private keys, or complete sensitive records.

The concrete authorization model is not implemented in v0.1. Any future
permission change must document threat assumptions and migration impact.
