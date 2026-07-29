# Contract tests

Run the dependency-free harness from the repository root:

```text
python3 -m unittest discover -s tests/contract -p 'test_*.py'
```

The harness checks JSON Schema 2020-12 documents, their embedded examples, the
daemon-only canonical event batch, closed authority command request/commit/error
contracts, header-only principal-scoped idempotency, forged daemon-field
rejection, opaque public cursors, resynchronization examples, the paginated
public event page, unknown-field rejection, and the `KEEP` promotion fixture.
OpenAPI version, bearer/idempotency requirements, `Last-Event-ID`, read-only
events, and the absence of a raw EventBatch writer are also checked as contract
smoke tests.
