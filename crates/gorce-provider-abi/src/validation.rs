use std::cmp::Ordering;
use std::fmt;

use serde_json::Value;

pub const MAX_SCHEMA_BYTES: usize = 32 * 1024;
pub const MAX_SCHEMA_DEPTH: usize = 16;
pub const MAX_SCHEMA_NODES: usize = 256;
pub const MAX_SCHEMA_PROPERTIES: usize = 64;
pub const MAX_SCHEMA_ENUM_ITEMS: usize = 32;
pub const MAX_RUNTIME_STRING_BYTES: usize = 4 * 1024;
pub const MAX_RUNTIME_MEMBERS: usize = 256;

pub type ValidationResult<T> = Result<T, ValidationError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub field: String,
    pub reason: String,
}

impl ValidationError {
    pub(crate) fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid {}: {}", self.field, self.reason)
    }
}

impl std::error::Error for ValidationError {}

pub fn validate_local_schema(schema: &Value, field: &str) -> ValidationResult<()> {
    let encoded =
        serde_json::to_vec(schema).map_err(|_| ValidationError::new(field, "not JSON"))?;
    if encoded.len() > MAX_SCHEMA_BYTES {
        return Err(ValidationError::new(
            field,
            "schema exceeds the local size bound",
        ));
    }
    let mut nodes = 0;
    validate_schema_node(schema, field, 0, &mut nodes)
}

fn validate_schema_node(
    schema: &Value,
    field: &str,
    depth: usize,
    nodes: &mut usize,
) -> ValidationResult<()> {
    *nodes += 1;
    if depth > MAX_SCHEMA_DEPTH || *nodes > MAX_SCHEMA_NODES {
        return Err(ValidationError::new(
            field,
            "schema is too deep or has too many nodes",
        ));
    }
    let object = schema
        .as_object()
        .ok_or_else(|| ValidationError::new(field, "schema must be a JSON object"))?;
    // This is the complete v1 local keyword set. References, combinators,
    // formats, patterns, and remote/runtime metadata are intentionally not ABI keywords.
    let allowed = [
        "type",
        "title",
        "description",
        "properties",
        "required",
        "items",
        "additionalProperties",
        "enum",
        "const",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "minItems",
        "maxItems",
    ];
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(ValidationError::new(
            field,
            "schema keyword is not allowed in local v1 schemas",
        ));
    }
    let schema_type = object.get("type").and_then(Value::as_str);
    if object.contains_key("type")
        && !matches!(
            schema_type,
            Some("object" | "array" | "string" | "integer" | "number" | "boolean" | "null")
        )
    {
        return Err(ValidationError::new(field, "schema type is not supported"));
    }
    for metadata_key in ["title", "description"] {
        if let Some(value) = object.get(metadata_key) {
            if value.as_str().map_or(true, |text| {
                text.is_empty()
                    || text.chars().count() > MAX_RUNTIME_STRING_BYTES
                    || text.chars().any(char::is_control)
            }) {
                return Err(ValidationError::new(
                    field,
                    "schema text metadata is invalid",
                ));
            }
        }
    }
    if let Some(properties) = object.get("properties") {
        let properties = properties
            .as_object()
            .ok_or_else(|| ValidationError::new(field, "properties must be an object"))?;
        if properties.len() > MAX_SCHEMA_PROPERTIES {
            return Err(ValidationError::new(field, "too many schema properties"));
        }
        for (name, child) in properties {
            if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                return Err(ValidationError::new(
                    field,
                    "schema property name is invalid",
                ));
            }
            validate_schema_node(
                child,
                &format!("{field}.properties.{name}"),
                depth + 1,
                nodes,
            )?;
        }
    }
    if let Some(items) = object.get("items") {
        validate_schema_node(items, &format!("{field}.items"), depth + 1, nodes)?;
    }
    if let Some(required) = object.get("required") {
        let required = required
            .as_array()
            .ok_or_else(|| ValidationError::new(field, "required must be an array"))?;
        if required.len() > MAX_SCHEMA_PROPERTIES {
            return Err(ValidationError::new(field, "required has too many names"));
        }
        let properties = object.get("properties").and_then(Value::as_object);
        let mut names = std::collections::BTreeSet::new();
        for name in required {
            let name = name
                .as_str()
                .ok_or_else(|| ValidationError::new(field, "required names must be strings"))?;
            if name.is_empty()
                || !names.insert(name)
                || properties.map_or(true, |properties| !properties.contains_key(name))
            {
                return Err(ValidationError::new(
                    field,
                    "required contains an invalid or unknown name",
                ));
            }
        }
    }
    if let Some(additional) = object.get("additionalProperties") {
        if !additional.is_boolean() {
            return Err(ValidationError::new(
                field,
                "additionalProperties must be boolean",
            ));
        }
    }
    if let Some(values) = object.get("enum") {
        let values = values
            .as_array()
            .filter(|values| !values.is_empty() && values.len() <= MAX_SCHEMA_ENUM_ITEMS)
            .ok_or_else(|| ValidationError::new(field, "enum must be a bounded array"))?;
        if values.iter().enumerate().any(|(index, value)| {
            values[index + 1..]
                .iter()
                .any(|other| json_schema_equal(value, other))
        }) {
            return Err(ValidationError::new(field, "enum must be a bounded array"));
        }
    }
    validate_integer_keyword(object, "minLength", field, MAX_RUNTIME_STRING_BYTES as u64)?;
    validate_integer_keyword(object, "maxLength", field, MAX_RUNTIME_STRING_BYTES as u64)?;
    validate_integer_keyword(object, "minItems", field, MAX_RUNTIME_MEMBERS as u64)?;
    validate_integer_keyword(object, "maxItems", field, MAX_RUNTIME_MEMBERS as u64)?;
    if let (Some(min), Some(max)) = (
        object.get("minLength").and_then(json_schema_integer),
        object.get("maxLength").and_then(json_schema_integer),
    ) {
        if min > max {
            return Err(ValidationError::new(field, "minLength exceeds maxLength"));
        }
    }
    if let (Some(min), Some(max)) = (
        object.get("minItems").and_then(json_schema_integer),
        object.get("maxItems").and_then(json_schema_integer),
    ) {
        if min > max {
            return Err(ValidationError::new(field, "minItems exceeds maxItems"));
        }
    }
    validate_number_keyword(object, "minimum", field)?;
    validate_number_keyword(object, "maximum", field)?;
    if let (Some(min), Some(max)) = (
        object.get("minimum").and_then(Value::as_number),
        object.get("maximum").and_then(Value::as_number),
    ) {
        if compare_json_numbers(min, max) == Some(Ordering::Greater) {
            return Err(ValidationError::new(field, "minimum exceeds maximum"));
        }
    }
    Ok(())
}

fn validate_integer_keyword(
    object: &serde_json::Map<String, Value>,
    keyword: &str,
    field: &str,
    maximum: u64,
) -> ValidationResult<()> {
    if let Some(value) = object.get(keyword) {
        if json_schema_integer(value).map_or(true, |value| value > maximum) {
            return Err(ValidationError::new(
                field,
                format!("{keyword} is invalid or oversized"),
            ));
        }
    }
    Ok(())
}

fn validate_number_keyword(
    object: &serde_json::Map<String, Value>,
    keyword: &str,
    field: &str,
) -> ValidationResult<()> {
    if let Some(value) = object.get(keyword) {
        if value.as_f64().map_or(true, |value| !value.is_finite()) {
            return Err(ValidationError::new(
                field,
                format!("{keyword} must be finite"),
            ));
        }
    }
    Ok(())
}

fn json_schema_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => {
            compare_json_numbers(left, right) == Some(Ordering::Equal)
        }
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| json_schema_equal(left, right))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right
                        .get(key)
                        .is_some_and(|other| json_schema_equal(value, other))
                })
        }
        _ => left == right,
    }
}

fn canonical_number(number: &serde_json::Number) -> Option<(bool, String, i64)> {
    let raw = number.to_string();
    let (negative, unsigned) = raw
        .strip_prefix('-')
        .map_or((false, raw.as_str()), |value| (true, value));
    let (mantissa, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or((unsigned, 0), |(mantissa, exponent)| {
            (mantissa, exponent.parse::<i64>().unwrap_or(i64::MIN))
        });
    if exponent == i64::MIN {
        return None;
    }
    let (whole, fraction) = mantissa
        .split_once('.')
        .map_or((mantissa, ""), |parts| parts);
    let mut digits = String::with_capacity(whole.len() + fraction.len());
    digits.push_str(whole);
    digits.push_str(fraction);
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Some((false, "0".to_owned(), 0));
    }
    let trailing_zeroes = digits
        .bytes()
        .rev()
        .take_while(|byte| *byte == b'0')
        .count();
    let end = digits.len() - trailing_zeroes;
    let digits = digits[..end].to_owned();
    let power = exponent
        .checked_sub(fraction.len() as i64)?
        .checked_add(trailing_zeroes as i64)?;
    Some((negative, digits, power))
}

fn compare_json_numbers(left: &serde_json::Number, right: &serde_json::Number) -> Option<Ordering> {
    let (left_negative, left_digits, left_power) = canonical_number(left)?;
    let (right_negative, right_digits, right_power) = canonical_number(right)?;
    let left_zero = left_digits == "0";
    let right_zero = right_digits == "0";
    if left_zero && right_zero {
        return Some(Ordering::Equal);
    }
    if left_negative != right_negative {
        return Some(if left_negative {
            Ordering::Less
        } else {
            Ordering::Greater
        });
    }
    let left_magnitude = (left_digits.len() as i64).checked_add(left_power)?;
    let right_magnitude = (right_digits.len() as i64).checked_add(right_power)?;
    let magnitude = left_magnitude.cmp(&right_magnitude).then_with(|| {
        let width = left_digits.len().max(right_digits.len());
        (0..width)
            .map(|index| {
                left_digits
                    .as_bytes()
                    .get(index)
                    .copied()
                    .unwrap_or(b'0')
                    .cmp(&right_digits.as_bytes().get(index).copied().unwrap_or(b'0'))
            })
            .find(|ordering| *ordering != Ordering::Equal)
            .unwrap_or(Ordering::Equal)
    });
    Some(if left_negative {
        magnitude.reverse()
    } else {
        magnitude
    })
}

fn is_json_integer(number: &serde_json::Number) -> bool {
    canonical_number(number).is_some_and(|(_, _, power)| power >= 0)
}

fn json_schema_integer(value: &Value) -> Option<u64> {
    let number = value.as_number()?;
    let (negative, digits, power) = canonical_number(number)?;
    if negative || !(0..=20).contains(&power) {
        return None;
    }
    let mut digits = digits;
    digits.extend(std::iter::repeat('0').take(power as usize));
    digits.parse().ok()
}

pub fn validate_json_value(schema: &Value, value: &Value) -> ValidationResult<()> {
    validate_local_schema(schema, "schema")?;
    let mut members = 0;
    validate_runtime_structure(value, 0, &mut members)?;
    validate_value(schema, value, "value")
}

fn validate_runtime_structure(
    value: &Value,
    depth: usize,
    members: &mut usize,
) -> ValidationResult<()> {
    if depth > crate::MAX_JSON_DEPTH {
        return Err(ValidationError::new("value", "runtime JSON is too deep"));
    }
    match value {
        Value::String(text) if text.chars().count() > MAX_RUNTIME_STRING_BYTES => {
            Err(ValidationError::new("value", "runtime string is oversized"))
        }
        Value::Array(values) => {
            *members += values.len();
            if *members > crate::MAX_JSON_MEMBERS {
                return Err(ValidationError::new(
                    "value",
                    "runtime JSON has too many members",
                ));
            }
            for child in values {
                validate_runtime_structure(child, depth + 1, members)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            *members += values.len();
            if *members > crate::MAX_JSON_MEMBERS {
                return Err(ValidationError::new(
                    "value",
                    "runtime JSON has too many members",
                ));
            }
            for child in values.values() {
                validate_runtime_structure(child, depth + 1, members)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_value(schema: &Value, value: &Value, field: &str) -> ValidationResult<()> {
    let object = schema.as_object().expect("validated schema object");
    if let Some(expected) = object.get("type").and_then(Value::as_str) {
        let matches = match expected {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.as_number().is_some_and(is_json_integer),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => false,
        };
        if !matches {
            return Err(ValidationError::new(field, format!("expected {expected}")));
        }
    }
    if let Some(enum_values) = object.get("enum").and_then(Value::as_array) {
        if !enum_values
            .iter()
            .any(|candidate| json_schema_equal(candidate, value))
        {
            return Err(ValidationError::new(field, "value is not in enum"));
        }
    }
    if let Some(constant) = object.get("const") {
        if !json_schema_equal(constant, value) {
            return Err(ValidationError::new(field, "value does not match const"));
        }
    }
    if let Some(text) = value.as_str() {
        let length = text.chars().count() as u64;
        if object
            .get("minLength")
            .and_then(json_schema_integer)
            .is_some_and(|min| length < min)
            || object
                .get("maxLength")
                .and_then(json_schema_integer)
                .is_some_and(|max| length > max)
        {
            return Err(ValidationError::new(
                field,
                "string length is outside bounds",
            ));
        }
    }
    if let Value::Number(number) = value {
        if object
            .get("minimum")
            .and_then(Value::as_number)
            .is_some_and(|min| compare_json_numbers(number, min) == Some(Ordering::Less))
            || object
                .get("maximum")
                .and_then(Value::as_number)
                .is_some_and(|max| compare_json_numbers(number, max) == Some(Ordering::Greater))
        {
            return Err(ValidationError::new(field, "number is outside bounds"));
        }
    }
    if let Some(array) = value.as_array() {
        if object
            .get("minItems")
            .and_then(json_schema_integer)
            .is_some_and(|min| (array.len() as u64) < min)
            || object
                .get("maxItems")
                .and_then(json_schema_integer)
                .is_some_and(|max| (array.len() as u64) > max)
        {
            return Err(ValidationError::new(
                field,
                "array length is outside bounds",
            ));
        }
        if let Some(items) = object.get("items") {
            for (index, child) in array.iter().enumerate() {
                validate_value(items, child, &format!("{field}[{index}]"))?;
            }
        }
    }
    if let Some(map) = value.as_object() {
        let properties = object.get("properties").and_then(Value::as_object);
        if let Some(required) = object.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                if !map.contains_key(name) {
                    return Err(ValidationError::new(
                        field,
                        format!("missing property {name}"),
                    ));
                }
            }
        }
        for (name, child) in map {
            if let Some(property_schema) = properties.and_then(|props| props.get(name)) {
                validate_value(property_schema, child, &format!("{field}.{name}"))?;
            } else if object.get("additionalProperties").and_then(Value::as_bool) == Some(false) {
                return Err(ValidationError::new(
                    field,
                    format!("unknown property {name}"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn local_schema_checks_type_and_character_constraints() {
        let schema = json!({"type": "string", "minLength": 2, "maxLength": 3});
        assert!(validate_json_value(&schema, &json!("éé")).is_ok());
        assert!(validate_json_value(&schema, &json!("é")).is_err());
        assert!(validate_json_value(&schema, &json!("éééé")).is_err());
        assert!(validate_json_value(&schema, &json!(3)).is_err());

        let invalid_schema = json!({"type": "array", "items": {"type": "string"}});
        assert!(validate_json_value(&invalid_schema, &json!(["ok"])).is_ok());
        assert!(validate_json_value(&invalid_schema, &json!([3])).is_err());
        assert!(validate_local_schema(&json!({"type": "bogus"}), "schema").is_err());
        assert!(
            validate_local_schema(&json!({"type": "string", "title": "\u{0085}"}), "schema")
                .is_err()
        );
        let property_name_at_byte_bound = "é".repeat(64);
        let property_name_over_byte_bound = "é".repeat(65);
        let mut schema_at_byte_bound = json!({"type": "object", "properties": {}});
        schema_at_byte_bound["properties"]
            .as_object_mut()
            .unwrap()
            .insert(property_name_at_byte_bound, json!({"type": "string"}));
        let mut schema_over_byte_bound = json!({"type": "object", "properties": {}});
        schema_over_byte_bound["properties"]
            .as_object_mut()
            .unwrap()
            .insert(property_name_over_byte_bound, json!({"type": "string"}));
        assert!(validate_local_schema(&schema_at_byte_bound, "schema").is_ok());
        assert!(validate_local_schema(&schema_over_byte_bound, "schema").is_err());
    }

    #[test]
    fn local_schema_shared_adversarial_fixtures_match_rust_contract() {
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../api/provider-abi/v1/local-schema-fixtures.json"
        ))
        .unwrap();
        for fixture in fixtures["positive"].as_array().unwrap() {
            validate_local_schema(&fixture["schema"], "schema").unwrap();
        }
        for fixture in fixtures["negative"].as_array().unwrap() {
            assert!(
                validate_local_schema(&fixture["schema"], "schema").is_err(),
                "fixture unexpectedly passed: {}",
                fixture["name"]
            );
        }
        for fixture in fixtures["numeric_cases"].as_array().unwrap() {
            let valid = validate_json_value(&fixture["schema"], &fixture["value"]).is_ok();
            assert_eq!(
                valid,
                fixture["valid"].as_bool().unwrap(),
                "{}",
                fixture["name"]
            );
        }
    }
}
