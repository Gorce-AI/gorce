# Threat model

## Assets

- User data in the storage root.
- Credentials and local API authorization material.
- Integrity of the storage format and indexes.
- Release artifacts and source supply chain.

## Trust boundaries

- The daemon process and its configured filesystem root.
- Local API clients and any explicitly enabled remote clients.
- Agent operations crossing from API input into storage.
- Build and release automation.

## Threats

- A local or remote unauthorized client reads or changes data.
- Path traversal or symlink handling escapes the storage root.
- Crash recovery loses, duplicates, or partially publishes a record.
- A compromised dependency or release workflow ships malicious code.
- Sensitive data leaks through logs, diagnostics, or backups.

## Mitigations and gaps

Least privilege, local-by-default exposure, canonical paths, atomic commits,
checksums, rebuildable indexes, dependency auditing, and redacted logging are
planned mitigations. Authentication, authorization, format implementation,
and operational hardening are open work and must be reviewed before runtime
release.
