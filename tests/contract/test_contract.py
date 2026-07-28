import json
import ipaddress
import math
import os
import re
import shutil
import subprocess
import unittest
import unicodedata
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = ROOT / "api" / "schemas"
EXAMPLE_DIR = ROOT / "api" / "examples"
PROVIDER_SCHEMA_DIR = ROOT / "api" / "provider-abi" / "v1"
NEGATIVE_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
MAX_EVENT_COUNT = 1024
MAX_EVENT_DATA_BYTES = 1_048_576
MAX_TOTAL_EVENT_DATA_BYTES = 8 * 1_048_576
MAX_REFERENCED_BLOBS = 1024
MAX_U64 = 2**64 - 1
MIN_I32 = -(2**31)
MAX_I32 = 2**31 - 1
SCHEMAS_BY_ID = {
    json.loads(path.read_text())["$id"]: json.loads(path.read_text())
    for path in SCHEMA_DIR.glob("*.schema.json")
}
SCHEMAS_BY_ID.update(
    {
        json.loads(path.read_text())["$id"]: json.loads(path.read_text())
        for path in PROVIDER_SCHEMA_DIR.glob("*.schema.json")
    }
)


class SchemaViolation(AssertionError):
    pass


def validate(value, schema, path="$", root=None):
    if root is None:
        root = schema
    if "$ref" in schema:
        reference = schema["$ref"]
        if reference.startswith("#/"):
            target = root
            for part in reference[2:].split("/"):
                target = target.get(part)
                if target is None:
                    break
        else:
            target = SCHEMAS_BY_ID.get(reference)
        if target is None:
            raise SchemaViolation(f"{path}: unresolved schema reference {schema['$ref']}")
        validate(value, target, path, root)
        return

    expected = schema.get("type")
    if expected is not None:
        expected_types = expected if isinstance(expected, list) else [expected]
        if not any(_is_type(value, item) for item in expected_types):
            raise SchemaViolation(f"{path}: expected {expected}, got {type(value).__name__}")

    if "enum" in schema and not any(_json_equal(value, candidate) for candidate in schema["enum"]):
        raise SchemaViolation(f"{path}: {value!r} is not in enum")
    if "const" in schema and not _json_equal(value, schema["const"]):
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
        if "maxProperties" in schema and len(value) > schema["maxProperties"]:
            raise SchemaViolation(f"{path}: too many properties")
        if "propertyNames" in schema:
            for name in value:
                validate(name, schema["propertyNames"], f"{path}.{name}", root)
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
        if schema.get("uniqueItems"):
            if any(
                _json_equal(item, other)
                for index, item in enumerate(value)
                for other in value[index + 1 :]
            ):
                raise SchemaViolation(f"{path}: items are not unique")
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
        "integer": _json_schema_integer(value) is not None,
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


def validate_provider_manifest_contract(value):
    version = value["version"].split(".")
    try:
        version_values = [int(component) for component in version]
    except ValueError as error:
        raise SchemaViolation("provider version is not numeric") from error
    if len(version) != 3 or any(
        not component
        or not component.isascii()
        or not component.isdecimal()
        or component_value < 0
        or component_value > MAX_U64
        for component, component_value in zip(version, version_values)
    ):
        raise SchemaViolation("provider version components exceed u64")
    files = value["package"]["files"]
    executable = value["package"]["executable"]
    paths = {entry["path"].lower() for entry in files}
    if len(paths) != len(files):
        raise SchemaViolation("provider package file paths must be unique")
    if sum(entry["size"] for entry in files) > 4 * 64 * 1024 * 1024:
        raise SchemaViolation("provider package payload exceeds the bounded total")
    for entry in files:
        path = entry["path"]
        parts = path.split("/")
        if path.lower() in {"manifest.json", "signature.json"}:
            raise SchemaViolation("provider package metadata paths are archive-reserved")
        if (
            path.startswith("/")
            or not path.isascii()
            or any(not ("!" <= char <= "~") for char in path)
            or "\\" in path
            or any(char in path for char in ':<>"|?*')
            or "" in parts
            or any(part in {".", ".."} for part in parts)
            or any(part.endswith(".") or provider_windows_reserved_component(part) for part in parts)
        ):
            raise SchemaViolation("provider package paths must be safe relative paths")
    if executable["path"].lower() not in paths:
        raise SchemaViolation("provider executable must be in the file table")
    executable_file = next((entry for entry in files if entry["path"] == executable["path"]), None)
    if executable_file is None:
        raise SchemaViolation("provider executable path case must match its file entry")
    if executable_file["sha256"] != executable["sha256"]:
        raise SchemaViolation("provider executable hash must match its file entry")
    auth_ids = {method["id"] for method in value["auth_methods"]}
    if len(auth_ids) != len(value["auth_methods"]):
        raise SchemaViolation("provider auth method IDs must be unique")
    credential_classes = [method["credential_class"] for method in value["auth_methods"]]
    if len(set(credential_classes)) != len(credential_classes):
        raise SchemaViolation("provider credential classes must map one-to-one to auth methods")
    if auth_ids != set(value["capabilities"]["auth_method_ids"]):
        raise SchemaViolation("provider auth capability set must equal declarations")
    if set(credential_classes) != set(value["capabilities"]["credential_classes"]):
        raise SchemaViolation("provider credential capability set must equal declarations")
    auth_by_id = {method["id"]: method for method in value["auth_methods"]}
    for method in value["auth_methods"]:
        if method["kind"] == "oauth_authorization_code_pkce":
            for endpoint in (method["authorization_endpoint"], method["token_endpoint"]):
                validate_provider_https_url(endpoint, allow_path=True)
            for origin in method["approved_origins"]:
                validate_provider_https_url(origin, allow_path=False)
            approved = set(method["approved_origins"])
            for endpoint in (method["authorization_endpoint"], method["token_endpoint"]):
                parsed = urlparse(endpoint)
                host = parsed.hostname or ""
                if ":" in host:
                    host = f"[{host}]"
                origin = f"https://{host}"
                if parsed.port is not None:
                    origin += f":{parsed.port}"
                if origin not in approved:
                    raise SchemaViolation("provider OAuth endpoint origin is not approved")
    for origin in value["capabilities"]["network_origins"]:
        validate_provider_https_url(origin, allow_path=False)
    for tool in value["tools"]:
        if sum(existing["name"] == tool["name"] for existing in value["tools"]) != 1:
            raise SchemaViolation("provider tool names must be unique")
        if tool["credential_class"] is None:
            if tool["auth_method_id"] is not None:
                raise SchemaViolation("credential-free provider tools cannot bind auth")
        else:
            if tool["auth_method_id"] is None or tool["auth_method_id"] not in auth_by_id:
                raise SchemaViolation("provider tool auth method is not declared")
            if auth_by_id[tool["auth_method_id"]]["credential_class"] != tool["credential_class"]:
                raise SchemaViolation("provider tool auth/class binding does not match")
            if tool["credential_class"] not in set(value["capabilities"]["credential_classes"]):
                raise SchemaViolation("provider tool credential class is not approved")
        if len(tool["side_effects"]) != len(set(tool["side_effects"])):
            raise SchemaViolation("provider tool side effects must be unique")
        validate_provider_local_schema(tool["input_schema"])
        if tool["input_schema"].get("type") != "object":
            raise SchemaViolation("provider input schemas must describe JSON objects")
        validate_provider_local_schema(tool["output_schema"])
        if not set(tool["network_origins"]).issubset(set(value["capabilities"]["network_origins"])):
            raise SchemaViolation("provider tool origin is not approved")


def validate_provider_local_schema(schema, depth=0, nodes=None):
    if nodes is None:
        nodes = [0]
    if depth == 0:
        try:
            encoded = json.dumps(
                schema, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise SchemaViolation("provider local schemas must be JSON") from error
        if len(encoded) > 32 * 1024:
            raise SchemaViolation("provider local schema exceeds its byte bound")
    nodes[0] += 1
    if depth > 16 or nodes[0] > 256 or not isinstance(schema, dict):
        raise SchemaViolation("provider local schemas must be bounded objects")
    allowed = {
        "type", "title", "description", "properties", "required", "items", "additionalProperties",
        "enum", "const", "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems",
    }
    if set(schema) - allowed:
        raise SchemaViolation("provider local schema contains an unsupported keyword")
    if "type" in schema and (
        not isinstance(schema["type"], str)
        or schema["type"] not in {
            "object", "array", "string", "integer", "number", "boolean", "null"
        }
    ):
        raise SchemaViolation("provider local schema contains an unknown type")
    for name in ("title", "description"):
        if name in schema:
            text = schema[name]
            if (
                not isinstance(text, str)
                or not text
                or len(text) > 4096
                or any(unicodedata.category(char) == "Cc" for char in text)
            ):
                raise SchemaViolation("provider local schema text metadata is invalid")
    properties = schema.get("properties", {})
    if not isinstance(properties, dict) or len(properties) > 64:
        raise SchemaViolation("provider local schema properties are bounded objects")
    for name in properties:
        if (
            not name
            or len(name.encode("utf-8")) > 128
            or any(unicodedata.category(char) == "Cc" for char in name)
        ):
            raise SchemaViolation("provider local schema property names are invalid")
    required = schema.get("required", [])
    if not isinstance(required, list) or len(required) > 64:
        raise SchemaViolation("provider local schema required names are invalid")
    if any(
        not isinstance(name, str) or not name or name not in properties for name in required
    ) or len(set(required)) != len(required):
        raise SchemaViolation("provider local schema required names are invalid")
    if "additionalProperties" in schema and not isinstance(schema["additionalProperties"], bool):
        raise SchemaViolation("provider local schema additionalProperties must be boolean")
    if "enum" in schema:
        values = schema["enum"]
        if (
            not isinstance(values, list)
            or not values
            or len(values) > 32
            or any(_json_equal(value, other) for index, value in enumerate(values) for other in values[index + 1 :])
        ):
            raise SchemaViolation("provider local schema enum is invalid")
    integer_bounds = {}
    for keyword, maximum in (
        ("minLength", 4096),
        ("maxLength", 4096),
        ("minItems", 256),
        ("maxItems", 256),
    ):
        integer_value = _json_schema_integer(schema[keyword]) if keyword in schema else None
        if keyword in schema and (
            integer_value is None or not 0 <= integer_value <= maximum
        ):
            raise SchemaViolation(f"provider local schema {keyword} is invalid")
        if keyword in schema:
            integer_bounds[keyword] = integer_value
    for keyword in ("minimum", "maximum"):
        if keyword in schema and not _is_finite_json_number(schema[keyword]):
            raise SchemaViolation(f"provider local schema {keyword} is invalid")
    if (
        "minLength" in integer_bounds
        and "maxLength" in integer_bounds
        and integer_bounds["minLength"] > integer_bounds["maxLength"]
    ) or (
        "minItems" in integer_bounds
        and "maxItems" in integer_bounds
        and integer_bounds["minItems"] > integer_bounds["maxItems"]
    ) or (
        "minimum" in schema
        and "maximum" in schema
        and schema["minimum"] > schema["maximum"]
    ):
        raise SchemaViolation("provider local schema has inverted bounds")
    for child in properties.values():
        validate_provider_local_schema(child, depth + 1, nodes)
    if "items" in schema:
        validate_provider_local_schema(schema["items"], depth + 1, nodes)


def _is_finite_json_number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return isinstance(value, int) or math.isfinite(value)


def _json_schema_integer(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return None
        return int(value)
    return value


def _json_equal(left, right):
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if isinstance(left, (int, float)) and not isinstance(left, bool):
        return (
            isinstance(right, (int, float))
            and not isinstance(right, bool)
            and left == right
        )
    if isinstance(left, dict) or isinstance(right, dict):
        return (
            isinstance(left, dict)
            and isinstance(right, dict)
            and left.keys() == right.keys()
            and all(_json_equal(left[key], right[key]) for key in left)
        )
    if isinstance(left, list) or isinstance(right, list):
        return (
            isinstance(left, list)
            and isinstance(right, list)
            and len(left) == len(right)
            and all(_json_equal(item, other) for item, other in zip(left, right))
        )
    return type(left) is type(right) and left == right


def validate_provider_https_url(value, allow_path):
    try:
        parsed = urlparse(value)
    except ValueError as error:
        raise SchemaViolation("provider URL is not canonical HTTPS syntax") from error
    try:
        port = parsed.port
    except ValueError as error:
        raise SchemaViolation("provider URL has an invalid port") from error
    host = parsed.hostname or ""
    authority = value.removeprefix("https://").split("/", 1)[0]
    if "%" in authority or "\\" in authority:
        raise SchemaViolation("provider URL authority must not contain encoded or backslash-normalized text")
    raw_host = (
        authority[1:].split("]", 1)[0]
        if authority.startswith("[")
        else authority.split(":", 1)[0]
    )
    explicit_port = None
    if authority.startswith("["):
        closing = authority.find("]")
        if closing >= 0 and authority[closing + 1 :].startswith(":"):
            explicit_port = authority[closing + 2 :]
    elif authority.count(":") == 1:
        explicit_port = authority.rsplit(":", 1)[1]
    if explicit_port is not None and (
        not explicit_port
        or not explicit_port.isascii()
        or not explicit_port.isdecimal()
        or (len(explicit_port) > 1 and explicit_port.startswith("0"))
        or explicit_port == "0"
        or int(explicit_port) > 65535
    ):
        raise SchemaViolation("provider URL port must be a canonical non-zero decimal number")
    if (
        not value.isascii()
        or parsed.scheme != "https"
        or not host
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or raw_host != raw_host.lower()
        or port == 443
        or (not allow_path and parsed.path not in ("", "/"))
        or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~!$&'()*+,;=:@%/-" for char in parsed.path)
    ):
        raise SchemaViolation("provider URL is not canonical HTTPS syntax")
    if ":" in host:
        if not parsed.netloc.startswith("["):
            raise SchemaViolation("provider URL has a non-canonical IPv6 host")
        if "." in host:
            raise SchemaViolation("provider URL IPv6 host must use hexadecimal notation")
        try:
            ipaddress.IPv6Address(host)
        except ValueError as error:
            raise SchemaViolation("provider URL has an invalid IPv6 host") from error
    elif _is_whatwg_numeric_host(host):
        if not _is_canonical_ipv4_host(host):
            raise SchemaViolation("provider URL has an invalid IPv4 host")
    elif any(
        not label
        or label.startswith("-")
        or label.endswith("-")
        or not all(char.isascii() and (char.islower() or char.isdigit() or char == "-") for char in label)
        for label in host.split(".")
    ):
        raise SchemaViolation("provider URL has an invalid DNS host")


def _is_whatwg_numeric_component(component):
    if component.startswith("0x"):
        return all(char in "0123456789abcdef" for char in component[2:])
    return bool(component) and component.isdigit()


def _is_whatwg_numeric_host(host):
    return bool(host) and all(
        _is_whatwg_numeric_component(component) for component in host.split(".")
    )


def _is_canonical_ipv4_host(host):
    components = host.split(".")
    return len(components) == 4 and all(
        component
        and (len(component) == 1 or not component.startswith("0"))
        and component.isdigit()
        and 0 <= int(component) <= 255
        for component in components
    )


def provider_windows_reserved_component(component):
    stem = component.split(".", 1)[0].lower()
    return stem in {"con", "conin$", "conout$", "prn", "aux", "nul", "clock$"} or (
        len(stem) == 4 and stem[:3] in {"com", "lpt"} and stem[3] in "123456789"
    )


def validate_provider_rpc_contract(value):
    if not isinstance(value.get("id"), str) or not 1 <= len(value["id"]) <= 64:
        raise SchemaViolation("provider RPC IDs must be bounded strings")
    if "method" in value:
        if value["method"] == "gorce.initialize":
            limits = value["params"]["limits"]
            maximums = {
                "max_frame_bytes": 65536,
                "max_json_depth": 16,
                "max_members": 256,
                "max_timeout_ms": 120000,
            }
            if any(
                name not in limits or not 1 <= limits[name] <= maximum
                for name, maximum in maximums.items()
            ):
                raise SchemaViolation("provider initialize limits are outside ABI bounds")
        if value["method"] == "tool.invoke":
            invocation = value["params"]["invocation"]
            if (
                isinstance(invocation["deadline_unix_ms"], bool)
                or not isinstance(invocation["deadline_unix_ms"], int)
                or not (
                1 <= invocation["deadline_unix_ms"] <= MAX_U64
                )
            ):
                raise SchemaViolation("provider invocation deadline exceeds u64")
            if not invocation["tool_id"].startswith(
                "gorce.provider/v1/tool/" + invocation["package_digest"] + "/"
            ):
                raise SchemaViolation("provider tool identity is not digest-bound")
            fields = (
                invocation["auth_method_id"],
                invocation["credential_class"],
                invocation["delivery_kind"],
            )
            if any(field is not None for field in fields) and not all(field is not None for field in fields):
                raise SchemaViolation("provider invocation credentials must be all present or absent")
            delivery = value["params"].get("secret_delivery")
            if any(field is not None for field in fields):
                if not isinstance(delivery, dict):
                    raise SchemaViolation("credentialed invocation requires delivery")
                if delivery["credential_class"] != invocation["credential_class"]:
                    raise SchemaViolation("provider delivery class is not invocation-bound")
                if delivery["kind"] != invocation["delivery_kind"]:
                    raise SchemaViolation("provider delivery kind is not invocation-bound")
                if delivery["expires_at_unix_ms"] > invocation["deadline_unix_ms"]:
                    raise SchemaViolation("provider delivery exceeds invocation deadline")
                if (
                    isinstance(delivery["expires_at_unix_ms"], bool)
                    or not isinstance(delivery["expires_at_unix_ms"], int)
                    or not (
                    1 <= delivery["expires_at_unix_ms"] <= MAX_U64
                    )
                ):
                    raise SchemaViolation("provider delivery expiry exceeds u64")
                validate_provider_byte_string(delivery["value"], 4096, "secret delivery")
            elif delivery is not None:
                raise SchemaViolation("credential-free invocation cannot deliver a secret")
        for reason in (value.get("params", {}).get("reason"),) if value["method"] == "operation.cancel" else ():
            if reason is not None:
                validate_provider_byte_string(reason, 512, "cancel reason")
        if value["method"] == "gorce.shutdown":
            reason = value["params"].get("reason")
            if reason is not None:
                validate_provider_byte_string(reason, 512, "shutdown reason")
    else:
        if ("result" in value) == ("error" in value):
            raise SchemaViolation("provider responses require exactly one result or error")
        if "error" in value:
            error = value["error"]
            if (
                isinstance(error.get("code"), bool)
                or not isinstance(error.get("code"), int)
                or not (
                MIN_I32 <= error["code"] <= MAX_I32
                )
            ):
                raise SchemaViolation("provider error code exceeds i32")
            if not isinstance(error.get("message"), str) or not 1 <= len(error["message"]) <= 512:
                raise SchemaViolation("provider error messages are bounded")
            validate_provider_byte_string(error["message"], 512, "error message")


def validate_provider_byte_string(value, maximum, label):
    if (
        len(value.encode("utf-8")) > maximum
        or any(unicodedata.category(char) == "Cc" for char in value)
    ):
        raise SchemaViolation(f"{label} exceeds its UTF-8 byte bound or contains control text")


def validate_provider_signed_package_contract(value):
    if len(value["manifest"].encode("utf-8")) > 256 * 1024:
        raise SchemaViolation("signed package manifest exceeds its UTF-8 byte bound")


class ContractTest(unittest.TestCase):
    def test_daemon_writer_surface_is_private_and_contained(self):
        source = (ROOT / "crates" / "gorce-daemon" / "src" / "lib.rs").read_text()
        self.assertNotIn("pub struct ProjectRegistry", source)
        self.assertNotIn("pub struct ProjectHandle", source)
        self.assertNotIn("pub struct ProjectCommandService", source)
        self.assertNotIn("pub fn registry", source)
        self.assertIn("pub struct ProjectReadFacade", source)
        self.assertNotIn("PowerShell", source)
        self.assertNotIn("powershell.exe", source)
        self.assertIn("#![forbid(unsafe_code)]", source)
        self.assertNotIn("CreateFileW", source)
        platform_source = (
            ROOT / "crates" / "gorce-platform-security" / "src" / "lib.rs"
        ).read_text()
        self.assertIn("#![forbid(unsafe_code)]", platform_source)
        self.assertNotIn("unsafe {", platform_source)
        self.assertIn("pub struct SecureRuntime", platform_source)
        self.assertIn("pub struct PrivateFile", platform_source)
        enclave_source = (
            ROOT / "crates" / "gorce-platform-security-win" / "src" / "lib.rs"
        ).read_text()
        self.assertIn("CreateFileW", enclave_source)
        self.assertIn("NtCreateFile", enclave_source)
        self.assertIn("#![deny(unsafe_op_in_unsafe_fn)]", enclave_source)
        public_error = source[source.index("pub enum DaemonError") : source.index("impl fmt::Display")]
        self.assertNotIn("ProjectStoreWriter", public_error)
        self.assertNotIn("WriterStoreError", public_error)

        metadata = json.loads(
            subprocess.check_output(
                [
                    shutil.which("cargo") or "/opt/homebrew/opt/rustup/bin/cargo",
                    "metadata",
                    "--format-version",
                    "1",
                    "--locked",
                    "--no-deps",
                ],
                cwd=ROOT,
                text=True,
            )
        )
        owners = [
            package["name"]
            for package in metadata["packages"]
            if any(
                dependency["name"] == "gorce-store-writer"
                for dependency in package["dependencies"]
            )
        ]
        self.assertEqual(owners, ["gorce-daemon"])
        platform_owners = [
            package["name"]
            for package in metadata["packages"]
            if any(
                dependency["name"] == "gorce-platform-security"
                for dependency in package["dependencies"]
            )
        ]
        self.assertEqual(platform_owners, ["gorce-daemon", "gorce-store-writer"])
        windows_owners = [
            package["name"]
            for package in metadata["packages"]
            if any(
                dependency["name"] == "gorce-platform-security-win"
                for dependency in package["dependencies"]
            )
        ]
        self.assertEqual(windows_owners, ["gorce-platform-security"])

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
            "command-request.json": "command-request.schema.json",
            "command-commit.json": "command-commit.schema.json",
            "command-error.json": "command-error.schema.json",
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
                schema_failed = False
                try:
                    validate(value, schema)
                except SchemaViolation:
                    schema_failed = True
                semantic_failed = False
                try:
                    validate_event_batch_contract(value)
                except SchemaViolation:
                    semantic_failed = True
                self.assertTrue(schema_failed or semantic_failed)

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
        self.assertIn("  /v0/projects/{project_id}/commands:", document)
        self.assertIn("/v0/projects/{project_id}/events:", document)
        self.assertIn("/v0/events/stream:", document)
        self.assertIn("event-batch.schema.json", document)
        self.assertIn("command-request.schema.json", document)
        self.assertIn("command-commit.schema.json", document)
        self.assertIn("command-error.schema.json", document)
        self.assertIn("authority.profile_register", (SCHEMA_DIR / "command-request.schema.json").read_text())
        self.assertIn("authority.operator_bind", (SCHEMA_DIR / "command-request.schema.json").read_text())
        self.assertIn("authority.admission_create", (SCHEMA_DIR / "command-request.schema.json").read_text())
        self.assertIn("public-event-batch.schema.json", document)
        self.assertIn("public-event-cursor.schema.json", document)
        self.assertIn("Idempotency-Key", document)
        self.assertIn("X-Gorce-Protocol-Version", document)
        self.assertIn("CommandRequestError", document)
        self.assertIn("oneOf:", document)
        self.assertIn("../schemas/error.schema.json", document)
        self.assertIn("command request", document)
        self.assertIn("bearerAuth", document)
        self.assertIn("X-Gorce-Token", document)
        self.assertIn("Last-Event-ID", document)
        self.assertIn("resync_required", document)
        self.assertIn("HTTP 405", document)

    def test_command_request_rejects_forged_daemon_fields(self):
        value = json.loads((EXAMPLE_DIR / "command-request.json").read_text())
        schema = json.loads((SCHEMA_DIR / "command-request.schema.json").read_text())
        validate(value, schema)
        for field in (
            "actor",
            "committed_at",
            "batch_id",
            "batch_sequence",
            "events",
            "referenced_blobs",
            "idempotency_key",
        ):
            forged = json.loads(json.dumps(value))
            forged[field] = {} if field in {"actor", "events", "referenced_blobs"} else "forged"
            with self.subTest(field=field):
                with self.assertRaises(SchemaViolation):
                    validate(forged, schema)
        forged_admission = {
            "version": "gorce.command/v1",
            "command": {
                "kind": "authority.admission_create",
                "arguments": {
                    "operator_id": "018f0f5e-7b12-7abc-8def-0123456789ab",
                    "run_id": "018f0f5e-7b12-7abd-8def-0123456789ab",
                    "profile_id": "forged",
                    "grant": {},
                    "actor": {},
                },
            },
        }
        with self.assertRaises(SchemaViolation):
            validate(forged_admission, schema)

    def test_command_contract_has_header_only_idempotency(self):
        value = json.loads((EXAMPLE_DIR / "command-request.json").read_text())
        self.assertNotIn("idempotency_key", value)
        self.assertNotIn("Idempotency-Key", value)
        document = (ROOT / "api" / "openapi" / "openapi.yaml").read_text()
        header = document.split("    IdempotencyKey:", 1)[1].split("    EventLimit:", 1)[0]
        self.assertIn("name: Idempotency-Key", header)
        self.assertIn("in: header", header)
        self.assertIn("required: true", header)
        self.assertIn("minLength: 1", header)
        self.assertIn("maxLength: 256", header)

    def test_command_commit_has_daemon_identity_and_opaque_cursors(self):
        value = json.loads((EXAMPLE_DIR / "command-commit.json").read_text())
        schema = json.loads((SCHEMA_DIR / "command-commit.schema.json").read_text())
        validate(value, schema)
        self.assertIn("project_id", value)
        self.assertIn("batch_id", value)
        self.assertIn("batch_sequence", value)
        self.assertIn("public_cursors", value)
        self.assertIn("result", value)
        self.assertIn("evidence_refs", value)
        self.assertTrue(all(cursor.startswith("g1-") for cursor in value["public_cursors"]))

    def test_cursor_contract_is_opaque_and_query_header_semantics_match(self):
        cursor_schema = json.loads((SCHEMA_DIR / "public-event-cursor.schema.json").read_text())
        validate("g1-0-0", cursor_schema)
        validate("g1-100-2", cursor_schema)
        with self.assertRaises(SchemaViolation):
            validate("eyJzZXF1ZW5jZSI6MX0", cursor_schema)
        self.assertIn("must not parse it", cursor_schema["description"])
        self.assertIn("numeric contiguity", cursor_schema["description"])
        document = (ROOT / "api" / "openapi" / "openapi.yaml").read_text()
        self.assertIn("opaque resume cursor", document)
        self.assertIn("Last-Event-ID", document)

    def test_events_are_read_only_and_have_no_raw_batch_writer(self):
        document = (ROOT / "api" / "openapi" / "openapi.yaml").read_text()
        events_path = document.split("  /v0/projects/{project_id}/events:", 1)[1].split(
            "  /v0/projects/{project_id}/commands:", 1
        )[0]
        self.assertNotIn("    post:", events_path)
        self.assertEqual(document.count("    post:"), 1)
        self.assertNotIn("event-batches", document)
        self.assertNotIn("requestBodies:", document)
        self.assertNotIn("/v0/projects/{project_id}/tasks:", document)
        self.assertIn("x-daemon-only: true", document)

    def test_provider_abi_schemas_and_examples_are_loaded_and_cross_checked(self):
        schemas = sorted(PROVIDER_SCHEMA_DIR.glob("*.schema.json"))
        self.assertGreaterEqual(len(schemas), 4)
        for path in schemas:
            schema = json.loads(path.read_text())
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertIn("$id", schema)
            for example in schema.get("examples", []):
                with self.subTest(schema=path.name):
                    validate(example, schema)
                    if path.name == "manifest.schema.json":
                        validate_provider_manifest_contract(example)
                    if path.name == "rpc.schema.json":
                        validate_provider_rpc_contract(example)
                    if path.name == "signed-package.schema.json":
                        validate_provider_signed_package_contract(example)

    def test_shared_provider_fixtures_pass_schema_and_semantic_contracts(self):
        fixtures = json.loads(
            (PROVIDER_SCHEMA_DIR / "provider-abi-fixtures.json").read_text()
        )
        rpc_schema = json.loads((PROVIDER_SCHEMA_DIR / "rpc.schema.json").read_text())
        manifest_schema = json.loads((PROVIDER_SCHEMA_DIR / "manifest.schema.json").read_text())
        schemas = {"manifest": manifest_schema, "response": rpc_schema}
        for fixture in fixtures["positive"]:
            with self.subTest(kind=fixture["kind"], polarity="positive"):
                validate(fixture["value"], schemas[fixture["kind"]])
                if fixture["kind"] == "manifest":
                    validate_provider_manifest_contract(fixture["value"])
                else:
                    validate_provider_rpc_contract(fixture["value"])
        for fixture in fixtures["negative"]:
            with self.subTest(reason=fixture["reason"], polarity="negative"):
                schema_failed = False
                try:
                    validate(fixture["value"], schemas[fixture["kind"]])
                except SchemaViolation:
                    schema_failed = True
                semantic_failed = False
                try:
                    if fixture["kind"] == "manifest":
                        validate_provider_manifest_contract(fixture["value"])
                    else:
                        validate_provider_rpc_contract(fixture["value"])
                except SchemaViolation:
                    semantic_failed = True
                self.assertTrue(schema_failed or semantic_failed)

    def test_provider_paths_oauth_urls_input_type_and_character_limits_match_rust(self):
        schema = json.loads((PROVIDER_SCHEMA_DIR / "manifest.schema.json").read_text())
        base = json.loads((PROVIDER_SCHEMA_DIR / "examples" / "manifest.json").read_text())
        for unsafe in (
            "C:provider", "C:/provider", "//server/share/provider", "provider:stream", "provider?name",
            "CON", "CONIN$", "CONOUT$.txt", "nul.txt", "clock$", "dir/name.", "dir/name ", "dir/name*",
        ):
            value = json.loads(json.dumps(base))
            value["package"]["files"][0]["path"] = unsafe
            value["package"]["executable"]["path"] = unsafe
            with self.subTest(path=unsafe), self.assertRaises(SchemaViolation):
                validate(value, schema)

        invalid_input = json.loads(json.dumps(base))
        invalid_input["tools"][0]["input_schema"] = {"type": "array"}
        with self.assertRaises(SchemaViolation):
            validate(invalid_input, schema)

        oauth = json.loads(json.dumps(base))
        oauth["auth_methods"] = [{
            "kind": "oauth_authorization_code_pkce", "id": "search_oauth", "credential_class": "search-oauth",
            "label": "Search OAuth", "client_type": "public", "client_id": "public-client",
            "authorization_endpoint": "https://example.com:8443/authorize", "token_endpoint": "https://example.com:8443/token",
            "approved_origins": ["https://example.com:8443"], "scopes": ["search.read"],
            "callback": "host_managed", "grant_type": "authorization_code", "pkce_method": "S256",
        }]
        oauth["capabilities"] = {"auth_method_ids": ["search_oauth"], "credential_classes": ["search-oauth"], "network_origins": []}
        oauth["tools"][0]["auth_method_id"] = "search_oauth"
        oauth["tools"][0]["credential_class"] = "search-oauth"
        validate(oauth, schema)
        validate_provider_manifest_contract(oauth)
        invalid_oauth = json.loads(json.dumps(oauth))
        invalid_oauth["auth_methods"][0]["authorization_endpoint"] = "https://EXAMPLE.com/authorize"
        with self.assertRaises(SchemaViolation):
            validate(invalid_oauth, schema)

        parity = json.loads((PROVIDER_SCHEMA_DIR / "provider-parity-fixtures.json").read_text())
        for reserved in parity["reserved_archive_paths"]:
            value = json.loads(json.dumps(base))
            value["package"]["files"][0]["path"] = reserved
            value["package"]["executable"]["path"] = reserved
            with self.subTest(path=reserved):
                with self.assertRaises(SchemaViolation):
                    validate(value, schema)
                with self.assertRaises(SchemaViolation):
                    validate_provider_manifest_contract(value)

        for fixture in parity["oauth_urls"]:
            schema_name = "httpsUrl" if fixture["allow_path"] else "httpsOrigin"
            schema_valid = True
            try:
                validate(fixture["url"], schema["$defs"][schema_name])
            except SchemaViolation:
                schema_valid = False
            semantic_valid = True
            try:
                validate_provider_https_url(fixture["url"], fixture["allow_path"])
            except SchemaViolation:
                semantic_valid = False
            with self.subTest(url=fixture["url"]):
                self.assertEqual(schema_valid, fixture["valid"])
                self.assertEqual(semantic_valid, fixture["valid"])

        unicode_name = json.loads(json.dumps(base))
        unicode_name["display_name"] = "é" * 512
        validate(unicode_name, schema)
        unicode_name["display_name"] += "é"
        with self.assertRaises(SchemaViolation):
            validate(unicode_name, schema)
        unicode_name["display_name"] = "\u0085"
        with self.assertRaises(SchemaViolation):
            validate(unicode_name, schema)

    def test_provider_required_nullable_fields_must_be_present_or_explicitly_null(self):
        parity = json.loads((PROVIDER_SCHEMA_DIR / "provider-parity-fixtures.json").read_text())
        manifest_schema = json.loads((PROVIDER_SCHEMA_DIR / "manifest.schema.json").read_text())
        manifest = json.loads((PROVIDER_SCHEMA_DIR / "examples" / "manifest.json").read_text())
        for field in parity["required_nullable_fields"][:2]:
            missing = json.loads(json.dumps(manifest))
            missing["tools"][0].pop(field)
            with self.assertRaises(SchemaViolation):
                validate(missing, manifest_schema)

        explicit_null = json.loads(json.dumps(manifest))
        explicit_null["tools"][0]["auth_method_id"] = None
        explicit_null["tools"][0]["credential_class"] = None
        validate(explicit_null, manifest_schema)
        validate_provider_manifest_contract(explicit_null)

        rpc_schema = json.loads((PROVIDER_SCHEMA_DIR / "rpc.schema.json").read_text())
        invoke = json.loads((PROVIDER_SCHEMA_DIR / "examples" / "tool-invoke.json").read_text())
        for field in parity["required_nullable_fields"]:
            missing = json.loads(json.dumps(invoke))
            missing["params"]["invocation"].pop(field)
            with self.assertRaises(SchemaViolation):
                validate(missing, rpc_schema)

        explicit_null = json.loads(json.dumps(invoke))
        explicit_null["params"]["invocation"]["auth_method_id"] = None
        explicit_null["params"]["invocation"]["credential_class"] = None
        explicit_null["params"]["invocation"]["delivery_kind"] = None
        explicit_null["params"].pop("secret_delivery")
        validate(explicit_null, rpc_schema)
        validate_provider_rpc_contract(explicit_null)

        initialize_schema = json.loads(
            (PROVIDER_SCHEMA_DIR / "initialize-result.schema.json").read_text()
        )
        initialize = json.loads(json.dumps(initialize_schema["examples"][0]))
        for field in parity["required_nullable_fields"][:2]:
            missing = json.loads(json.dumps(initialize))
            missing["tools"][0].pop(field)
            with self.assertRaises(SchemaViolation):
                validate(missing, initialize_schema)
        initialize["tools"][0]["auth_method_id"] = None
        initialize["tools"][0]["credential_class"] = None
        validate(initialize, initialize_schema)

    def test_provider_numeric_bounds_match_rust_and_schema(self):
        parity = json.loads((PROVIDER_SCHEMA_DIR / "provider-parity-fixtures.json").read_text())
        manifest_schema = json.loads((PROVIDER_SCHEMA_DIR / "manifest.schema.json").read_text())
        manifest = json.loads((PROVIDER_SCHEMA_DIR / "examples" / "manifest.json").read_text())
        rpc_schema = json.loads((PROVIDER_SCHEMA_DIR / "rpc.schema.json").read_text())
        invoke = json.loads((PROVIDER_SCHEMA_DIR / "examples" / "tool-invoke.json").read_text())
        for fixture in parity["numeric_bounds"]:
            kind = fixture["kind"]
            if kind == "version":
                value = json.loads(json.dumps(manifest))
                value["version"] = fixture["value"]
                schema = manifest_schema
                semantic = validate_provider_manifest_contract
            elif kind in {"deadline", "expiration"}:
                value = json.loads(json.dumps(invoke))
                if kind == "deadline":
                    value["params"]["invocation"]["deadline_unix_ms"] = fixture["value"]
                else:
                    value["params"]["invocation"]["deadline_unix_ms"] = fixture["value"]
                    value["params"]["secret_delivery"]["expires_at_unix_ms"] = fixture["value"]
                schema = rpc_schema
                semantic = validate_provider_rpc_contract
            else:
                value = {
                    "jsonrpc": "2.0",
                    "id": "numeric-code",
                    "error": {"code": fixture["value"], "message": "error"},
                }
                schema = rpc_schema
                semantic = validate_provider_rpc_contract
            schema_valid = True
            try:
                validate(value, schema)
            except SchemaViolation:
                schema_valid = False
            semantic_valid = True
            try:
                semantic(value)
            except SchemaViolation:
                semantic_valid = False
            with self.subTest(kind=kind, value=fixture["value"]):
                self.assertEqual(schema_valid, fixture["valid"])
                self.assertEqual(semantic_valid, fixture["valid"])

    def test_provider_local_schema_adversarial_fixtures_match_python_semantics(self):
        fixtures = json.loads(
            (PROVIDER_SCHEMA_DIR / "local-schema-fixtures.json").read_text()
        )
        for fixture in fixtures["positive"]:
            with self.subTest(name=fixture["name"], polarity="positive"):
                validate_provider_local_schema(fixture["schema"])
        for fixture in fixtures["negative"]:
            with self.subTest(name=fixture["name"], polarity="negative"):
                with self.assertRaises(SchemaViolation):
                    validate_provider_local_schema(fixture["schema"])
        for fixture in fixtures["numeric_cases"]:
            with self.subTest(name=fixture["name"], polarity="numeric"):
                schema_valid = True
                try:
                    validate_provider_local_schema(fixture["schema"])
                    if "value" in fixture:
                        validate(fixture["value"], fixture["schema"])
                except SchemaViolation:
                    schema_valid = False
                self.assertEqual(schema_valid, fixture["valid"])

        manifest_schema = json.loads((PROVIDER_SCHEMA_DIR / "manifest.schema.json").read_text())
        base = json.loads((PROVIDER_SCHEMA_DIR / "examples" / "manifest.json").read_text())
        expressible = {
            "additionalProperties must be boolean",
            "metadata rejects U+0085",
            "property names reject U+0085",
            "enum must be non-empty",
            "enum values must be unique",
            "integer keyword rejects boolean",
            "numeric keyword rejects string",
        }
        for fixture in fixtures["negative"]:
            if fixture["name"] not in expressible:
                continue
            value = json.loads(json.dumps(base))
            value["tools"][0]["input_schema"] = fixture["schema"]
            with self.subTest(name=fixture["name"], polarity="json-schema"):
                with self.assertRaises(SchemaViolation):
                    validate(value, manifest_schema)

        byte_boundary = json.loads(json.dumps(base))
        byte_boundary["tools"][0]["input_schema"] = {
            "type": "object",
            "properties": {"é" * 64: {"type": "string"}},
        }
        validate(byte_boundary, manifest_schema)
        validate_provider_manifest_contract(byte_boundary)
        byte_boundary["tools"][0]["input_schema"]["properties"]["é" * 65] = {
            "type": "string"
        }
        with self.assertRaises(SchemaViolation):
            validate_provider_manifest_contract(byte_boundary)

    def test_provider_rpc_utf8_byte_bounds_are_checked_semantically(self):
        schema = json.loads((PROVIDER_SCHEMA_DIR / "rpc.schema.json").read_text())
        response = {"jsonrpc": "2.0", "id": "unicode-error", "error": {"code": -1, "message": "é" * 256}}
        validate(response, schema)
        validate_provider_rpc_contract(response)
        response["error"]["message"] += "é"
        validate(response, schema)
        with self.assertRaises(SchemaViolation):
            validate_provider_rpc_contract(response)
        response["error"]["message"] = "\u0085"
        with self.assertRaises(SchemaViolation):
            validate(response, schema)
        with self.assertRaises(SchemaViolation):
            validate_provider_rpc_contract(response)

        initialize = json.loads((PROVIDER_SCHEMA_DIR / "examples" / "initialize.json").read_text())
        initialize["params"]["limits"] = {
            "max_frame_bytes": 1024, "max_json_depth": 4, "max_members": 8, "max_timeout_ms": 1000
        }
        validate(initialize, schema)
        validate_provider_rpc_contract(initialize)

    def test_provider_signed_package_manifest_utf8_byte_bound_is_semantic(self):
        schema = json.loads((PROVIDER_SCHEMA_DIR / "signed-package.schema.json").read_text())
        value = json.loads(json.dumps(schema["examples"][0]))
        value["manifest"] = "é" * (256 * 1024 // 2)
        validate(value, schema)
        validate_provider_signed_package_contract(value)
        value["manifest"] += "é"
        validate(value, schema)
        with self.assertRaises(SchemaViolation):
            validate_provider_signed_package_contract(value)

    def test_provider_abi_examples_have_canonical_methods_and_no_redeem_surface(self):
        expected = {
            "initialize.json": "gorce.initialize",
            "tool-invoke.json": "tool.invoke",
            "operation-cancel.json": "operation.cancel",
        }
        for filename, method in expected.items():
            value = json.loads((PROVIDER_SCHEMA_DIR / "examples" / filename).read_text())
            self.assertEqual(value["method"], method)
            self.assertIsInstance(value["id"], str)
            self.assertLessEqual(len(value["id"].encode("ascii")), 64)
        provider_text = "\n".join(path.read_text() for path in PROVIDER_SCHEMA_DIR.rglob("*.json"))
        self.assertNotIn("credentials/redeem", provider_text)
        self.assertNotIn("tools/invoke", provider_text)

    def test_provider_rust_and_spawned_mock_contracts_are_exercised(self):
        cargo = shutil.which("cargo") or "/opt/homebrew/opt/rustup/bin/cargo"
        subprocess.check_call(
            [cargo, "test", "--locked", "-p", "gorce-provider-abi", "-p", "mock-web-search"],
            cwd=ROOT,
            env={
                **os.environ,
                "PATH": "/opt/homebrew/opt/rustup/bin:" + os.environ.get("PATH", ""),
            },
        )


if __name__ == "__main__":
    unittest.main()
