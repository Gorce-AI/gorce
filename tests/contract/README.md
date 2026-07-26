# Contract tests

Run the dependency-free harness from the repository root:

```text
python3 -m unittest discover -s tests/contract -p 'test_*.py'
```

The harness checks JSON Schema 2020-12 documents, their embedded examples, the
canonical persisted event batch, its negative fixtures, the paginated public event
page, unknown-field rejection, and the `KEEP` promotion fixture. OpenAPI version
and `/v0` references are also checked as contract smoke tests.
