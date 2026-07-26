# Recovery

Recovery must preserve user data over process availability. The filesystem is
the durable source of truth; indexes and caches are rebuildable.

## Planned recovery sequence

1. Acquire the storage lock and verify the format version.
2. Check journal and commit markers for incomplete operations.
3. Complete or roll back only operations with a valid marker and checksum.
4. Validate durable objects.
5. Rebuild derived indexes when they are missing or inconsistent.
6. Report unrecoverable records without deleting them automatically.

Recovery should be deterministic, observable, and safe to retry. Destructive
repair requires an explicit operator action and a backup or export path.

The recovery implementation and failure-injection tests are future work.
