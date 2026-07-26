import json
import re
import unittest
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = ROOT / "api" / "schemas"
EXAMPLE_DIR = ROOT / "api" / "examples"
NEGATIVE_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
MAX_EVENT_COUNT = 1024
MAX_EVENT_DATA_BYTES = 1_048_576
MAX_TOTAL_EVENT_DATA_BYTES = 8 * 1_048_576
MAX_REFERENCED_BLOBS = 1024
SCHEMAS_BY_ID = {
    json.loads(path.read_text())["$id"]: json.loads(path.read_text())
    for path in SCHEMA_DIR.glob("*.schema.json")
}


class SchemaViolation(AssertionError):
    pass


def validate(value, schema, path="$", root=None):
    if root is None:
        root = schema
    if "$ref" in schema:
        target = SCHEMAS_BY_ID.get(schema["$ref"])
        if target is None:
            raise SchemaViolation(f"{path}: unresolved schema reference {schema['$ref']}")
        validate(value, target, path, root)
        return

    expected = schema.get("type")
    if expected is not None:
        expected_types = expected if isinstance(expected, list) else [expected]
        if not any(_is_type(value, item) for item in expected_types):
            raise SchemaViolation(f"{path}: expected {expected}, got {type(value).__name__}")

    if "enum" in schema and value not in schema["enum"]:
        raise SchemaViolation(f"{path}: {value!r} is not in enum")
    if "const" in schema and value != schema["const"]:
        raise SchemaViolation(f"{path}: {value!r} is not {schema['const']!r}")

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise SchemaViolation(f"{path}: string is too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise SchemaViolation(f"{path}: string is too long")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise SchemaViolation(f"{path}: string does not match pattern")
        _validate_format(value, schema.get("format"), path)

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise SchemaViolation(f"{path}: number is below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise SchemaViolation(f"{path}: number is above maximum")

    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                raise SchemaViolation(f"{path}: missing {name}")
        if schema.get("additionalProperties") is False:
            unknown = set(value) - set(schema.get("properties", {}))
            if unknown:
                raise SchemaViolation(f"{path}: unknown properties {sorted(unknown)}")
        for name, child in schema.get("properties", {}).items():
            if name in value:
                validate(value[name], child, f"{path}.{name}", root)

    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise SchemaViolation(f"{path}: too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise SchemaViolation(f"{path}: too many items")
        if "items" in schema:
            for index, item in enumerate(value):
                validate(item, schema["items"], f"{path}[{index}]", root)

    for keyword in ("allOf", "anyOf", "oneOf"):
        if keyword in schema:
            matches = 0
            for option in schema[keyword]:
                try:
                    validate(value, option, path, root)
                except SchemaViolation:
                    continue
                matches += 1
            if keyword == "allOf" and matches != len(schema[keyword]):
                raise SchemaViolation(f"{path}: allOf failed")
            if keyword == "anyOf" and matches == 0:
                raise SchemaViolation(f"{path}: anyOf failed")
            if keyword == "oneOf" and matches != 1:
                raise SchemaViolation(f"{path}: oneOf failed")

    condition = schema.get("if")
    if condition is not None:
        try:
            validate(value, condition, path, root)
        except SchemaViolation:
            branch = schema.get("else")
        else:
            branch = schema.get("then")
        if branch is not None:
            validate(value, branch, path, root)


def _is_type(value, expected):
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, True)


def _validate_format(value, format_name, path):
    if format_name == "uuid" and re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[89abAB0-9][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
        value,
    ) is None:
        raise SchemaViolation(f"{path}: invalid UUID")
    if format_name == "date-time":
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise SchemaViolation(f"{path}: invalid date-time") from error
        if parsed.tzinfo is None:
            raise SchemaViolation(f"{path}: date-time must include a timezone")
    if format_name == "uri" and not urlparse(value).scheme:
        raise SchemaViolation(f"{path}: invalid URI")


def validate_event_batch_contract(value):
    """Apply canonical constraints that JSON Schema cannot express dynamically."""
    events = value["events"]
    if not events:
        raise SchemaViolation("$.events: canonical batches require at least one event")
    if len(events) > MAX_EVENT_COUNT:
        raise SchemaViolation("$.events: too many events")
    for expected, event in enumerate(events):
        if event["ordinal"] != expected:
            raise SchemaViolation(
                f"$.events[{expected}].ordinal: expected {expected}, got {event['ordinal']}"
            )
        data_size = len(
            json.dumps(event["data"], ensure_ascii=False, separators=(",", ":"))
            .encode("utf-8")
        )
        if data_size > MAX_EVENT_DATA_BYTES:
            raise SchemaViolation(f"$.events[{expected}].data: serialized data is too large")
        if event["schema_version"] < 1:
            raise SchemaViolation(f"$.events[{expected}].schema_version: must be at least 1")
    total_data_size = sum(
        len(json.dumps(event["data"], ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        for event in events
    )
    if total_data_size > MAX_TOTAL_EVENT_DATA_BYTES:
        raise SchemaViolation("$.events: total serialized data is too large")

    references = value["referenced_blobs"]
    if len(references) > MAX_REFERENCED_BLOBS:
        raise SchemaViolation("$.referenced_blobs: too many references")
    digests = set()
    for index, reference in enumerate(references):
        digest = reference["digest"]
        if digest in digests:
            raise SchemaViolation(f"$.referenced_blobs[{index}]: duplicate digest")
        digests.add(digest)


class ContractTest(unittest.TestCase):
    def test_every_schema_is_json_schema_2020_12(self):
        schemas = sorted(SCHEMA_DIR.glob("*.schema.json"))
        self.assertGreater(len(schemas), 1)
        for path in schemas:
            document = json.loads(path.read_text())
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertIn("$id", document)

    def test_schema_examples(self):
        for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
            schema = json.loads(path.read_text())
            for index, example in enumerate(schema.get("examples", [])):
                with self.subTest(schema=path.name, example=index):
                    validate(example, schema)
                    if path.name == "event-batch.schema.json":
                        validate_event_batch_contract(example)

    def test_checked_in_golden_examples(self):
        cases = {
            "project.json": "project.schema.json",
            "event-batch.json": "event-batch.schema.json",
            "public-event-page.json": "public-event-batch.schema.json",
            "promotion-keep.json": "promotion-mapping.schema.json",
            "plan-revision.json": "plan-revision.schema.json",
            "typed-error.json": "error.schema.json",
            "message.json": "message.schema.json",
        }
        for example_name, schema_name in cases.items():
            with self.subTest(example=example_name):
                example = json.loads((EXAMPLE_DIR / example_name).read_text())
                schema = json.loads((SCHEMA_DIR / schema_name).read_text())
                validate(example, schema)
                if schema_name == "event-batch.schema.json":
                    validate_event_batch_contract(example)

    def test_canonical_negative_fixtures_fail_schema_or_semantic_validation(self):
        schema = json.loads((SCHEMA_DIR / "event-batch.schema.json").read_text())
        fixtures = sorted(NEGATIVE_FIXTURE_DIR.glob("event-batch-*.json"))
        self.assertEqual(len(fixtures), 8)
        for path in fixtures:
            with self.subTest(fixture=path.name):
                value = json.loads(path.read_text())
                with self.assertRaises(SchemaViolation):
                    validate(value, schema)
                    validate_event_batch_contract(value)

    def test_canonical_and_public_event_formats_are_not_interchangeable(self):
        canonical = json.loads((EXAMPLE_DIR / "event-batch.json").read_text())
        public = json.loads((EXAMPLE_DIR / "public-event-page.json").read_text())
        canonical_schema = json.loads((SCHEMA_DIR / "event-batch.schema.json").read_text())
        public_schema = json.loads((SCHEMA_DIR / "public-event-batch.schema.json").read_text())

        validate(canonical, canonical_schema)
        validate(public, public_schema)
        with self.assertRaises(SchemaViolation):
            validate(canonical, public_schema)
        with self.assertRaises(SchemaViolation):
            validate(public, canonical_schema)

    def test_unknown_fields_fail_for_closed_contract_objects(self):
        project = json.loads((EXAMPLE_DIR / "project.json").read_text())
        project["unexpected"] = True
        schema = json.loads((SCHEMA_DIR / "project.schema.json").read_text())
        with self.assertRaises(SchemaViolation):
            validate(project, schema)

    def test_unfinished_promotion_is_explicit_keep(self):
        fixture = json.loads((EXAMPLE_DIR / "promotion-keep.json").read_text())
        schema = json.loads((SCHEMA_DIR / "promotion-mapping.schema.json").read_text())
        validate(fixture, schema)
        self.assertEqual(fixture["disposition"], "KEEP")
        self.assertIn("task_id", fixture)

    def test_uuidv7_schema_is_explicit_not_global(self):
        schema = json.loads((SCHEMA_DIR / "uuidv7.schema.json").read_text())
        validate("018f0f5e-7b12-7abc-8def-0123456789ab", schema)
        with self.assertRaises(SchemaViolation):
            validate("018f0f5e-7b12-4abc-8def-0123456789ab", schema)

    def test_openapi_is_versioned_and_references_v0(self):
        document = (ROOT / "api" / "openapi" / "openapi.yaml").read_text()
        self.assertIn("openapi: 3.1.0", document)
        self.assertIn("  /v0/health:", document)
        self.assertIn("/v0/projects/{project_id}/events:", document)
        self.assertIn("event-batch.schema.json", document)
        self.assertIn("public-event-batch.schema.json", document)
        self.assertIn("public-event-cursor.schema.json", document)
        self.assertIn("idempotency_key", document)
        self.assertIn("same key with a different payload", document)
        self.assertIn("referenced_blobs", document)


if __name__ == "__main__":
    unittest.main()
